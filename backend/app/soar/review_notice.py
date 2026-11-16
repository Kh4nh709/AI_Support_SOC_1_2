"""The body n8n pushes to `POST /webhook/soar-notices`, read and stored (spec 2026-11-16 §2, "Contract A").

`parse(body) -> Notice` reads the bytes and either returns the ticket or raises `NoticeRejected` carrying EVERY fault
(`[{"field", "reason"}]`, the `400`'s body). `apply(conn, notice) -> Applied` stores it by the upsert table of the spec and
writes the one `soar.review_received` event. The route (`web/routers/webhook_soar_notices.py`) does the rest: the key, the
address, the size, the thread.

**What is read.** `schema_version` "1.x" (another major is `unsupported_version`); required `schema_version`, `event`
(`created|updated|reminder`), `kind` (`review|notice`), `id`, `sent_at`, `status`; for a review also `action.type` and
`buttons`; every other field may be null or absent and an unknown one is ignored (it stays in `raw`). A review's id is 8
characters of `[A-HJ-NP-Z2-9]`, a notice's is `N` and 12 of `[A-Za-z0-9_-]`. A review is never `info` and a notice always is.
`processing` is the web's own and a `400` from n8n (`reserved`). `severity` null or absent is `info`, `simulated` `false`,
`remind_every_minutes` 0. A timestamp carries an offset (`no_offset` otherwise) and is kept in UTC, years 2000 to 2099. `score`
is a finite number or null, stored rounded half up to an integer. Texts are capped by characters: `title` 200, the others
2,000. `case.number` and `remind_every_minutes` are whole numbers inside their columns. At most 20 buttons.

Beyond the contract, three limits that keep the rest of the system working, each a `body` fault: no NUL character anywhere
(`jsonb` refuses it, and stored it would be a 500), no number too large for a float, and no nesting past `MAX_DEPTH` levels
(the detail route serves `raw`, and the serialiser gives up, a 500, a little under 250 levels: `admin_audit.py` has the same
cap for the same reason).

A fault names the field and the kind of fault, never the value: nothing the sender wrote is repeated in the answer.

**What is stored** (`apply`, one transaction, the row locked `FOR UPDATE`):

| case | answer | stored |
| --- | --- | --- |
| no row with this `id` | `201 {id, created: true}` | the row, `last_sent_at = sent_at`, `raw` = the body as sent |
| a row, `sent_at` older than `last_sent_at` | `200 {id, created: false, ignored: true, reason: "stale"}` | nothing |
| a row in `undone`, `false_positive` or `expired`, and the body says `open` | `200 {..., ignored: true, reason: "terminal"}` | nothing |
| otherwise | `200 {id, created: false}` | every field of the body replaces the stored one (but `decided_by`, `decided_at`, `result`: null or absent keeps the stored value); `raw`, `last_sent_at`, `updated_at` |

An update that lands on a row the web holds (`processing`) is applied, since n8n is the authority: the lock columns are
cleared, and the decision request in flight finds its compare-and-set no longer matches (`soar/reviews.py`). An `updated`
or `reminder` for an unknown id creates the row. `created_at` of the body is n8n's time of the ticket; absent, the first
`sent_at` stands in, and an update that omits it keeps the stored one. The fields the web owns (`last_error`) are not
touched. The record of a decision (`decided_by`, `decided_at`, `result`) is kept when a push leaves it null or out: the web writes it on a
press, and n8n's next push may not carry it; a non-null value replaces it. Every request that parsed writes one event, whatever the outcome; a body that did not parse writes none.

Everything in the body is data: it is stored as text and JSON, and reaches SQL only as a bound parameter.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb

from app.audit.events import write_event

EVENTS = ("created", "updated", "reminder")
KINDS = ("review", "notice")
#: What n8n may send. `processing` is the web's own (migration 025) and is refused with its own reason.
STATUSES = ("open", "kept", "undone", "false_positive", "expired", "info")
#: The states a ticket does not come back from by itself: a body saying `open` for one of these is ignored.
TERMINAL_STATUSES = ("undone", "false_positive", "expired")
SEVERITIES = ("info", "warning", "error")
ACTION_TYPES = (
    "block_ip",
    "sinkhole_domain",
    "isolate_host",
    "disable_user",
    "disable_xp_cmdshell",
    "kill_process",
)
ACTION_VIAS = ("pfsense", "wazuh")
DECISIONS = ("keep", "undo", "fp")

TITLE_MAX = 200
TEXT_MAX = 2000
BUTTONS_MAX = 20
#: A body is read at most this many containers deep (module docstring).
MAX_DEPTH = 32
#: Years of a timestamp, in UTC: as the lab's windows (`lab/runs.py`), a time near year 1 or 9999 has no portable form.
YEAR_MIN, YEAR_MAX = 2000, 2099
_INT32 = (-(2**31), 2**31 - 1)
_INT64_MAX = 2**63 - 1
_TIMESTAMP_MAX_LENGTH = 64

REQUIRED = "required"
INVALID_TYPE = "invalid_type"
INVALID_VALUE = "invalid_value"
TOO_LONG = "too_long"
NO_OFFSET = "no_offset"
UNSUPPORTED_VERSION = "unsupported_version"
RESERVED = "reserved"

_VERSION_1 = re.compile(r"1\.[0-9]{1,6}")
_VERSION_ANY = re.compile(r"[0-9]+\.[0-9]+")
_REVIEW_ID = re.compile(r"[A-HJ-NP-Z2-9]{8}")
_NOTICE_ID = re.compile(r"N[A-Za-z0-9_-]{12}")


class NoticeRejected(Exception):
    """The body is not one this contract accepts. `faults` is the whole list, in field order, as the `400` serves it."""

    def __init__(self, faults: list[dict[str, str]]) -> None:
        super().__init__(f"{len(faults)} fault(s)")
        self.faults = faults


@dataclass(frozen=True)
class Notice:
    """A parsed ticket. `columns` holds the table's columns the body fills, by name (`created_at` is `None` when the body
    gave none: the first `sent_at` stands in where the row is made). `raw` is the parsed body, whole, as sent.
    """

    id: str
    event: str
    kind: str
    status: str
    sent_at: datetime
    columns: dict[str, Any]
    raw: Any


@dataclass(frozen=True)
class Applied:
    """What `apply` did: `outcome` is `created`, `updated` or `ignored` (then `reason` is `stale` or `terminal`)."""

    id: str
    outcome: Literal["created", "updated", "ignored"]
    reason: str | None = None

    def body(self) -> dict[str, Any]:
        """The answer of the route (spec §2)."""
        if self.outcome == "created":
            return {"id": self.id, "created": True}
        if self.outcome == "ignored":
            return {"id": self.id, "created": False, "ignored": True, "reason": self.reason}
        return {"id": self.id, "created": False}


# ── reading the body ────────────────────────────────────────────────────────────────────────


def _reject_constant(name: str) -> Any:
    raise ValueError(name)  # NaN, Infinity, -Infinity: not JSON, and not storable


def _tree_fault(root: Any) -> str | None:
    """`invalid` for a NUL character (in a key or a text) or a number that is not finite, `too_deep` for a body nested past
    `MAX_DEPTH`; `None` when the tree is storable. Iterative: a hostile depth must not reach the interpreter's own limit.
    """
    stack: list[tuple[Any, int]] = [(root, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > MAX_DEPTH:
            return "too_deep"
        children = node.items() if isinstance(node, dict) else enumerate(node)
        for key, child in children:
            if isinstance(node, dict) and "\x00" in key:
                return "invalid"
            if isinstance(child, str):
                if "\x00" in child:
                    return "invalid"
            elif isinstance(child, float):
                if not math.isfinite(child):
                    return "invalid"
            elif isinstance(child, dict | list):
                stack.append((child, depth + 1))
    return None


def _load(body: bytes) -> dict[str, Any]:
    """The body as a JSON object, or `NoticeRejected` with the one `body` fault."""

    def reject(reason: str) -> NoticeRejected:
        return NoticeRejected([{"field": "body", "reason": reason}])

    try:
        doc = json.loads(body.decode("utf-8"), parse_constant=_reject_constant)
    except RecursionError:
        raise reject("too_deep") from None
    except ValueError:  # JSONDecodeError and UnicodeDecodeError both, and a number too long to read
        raise reject("invalid") from None
    if not isinstance(doc, dict):
        raise reject("invalid")
    problem = _tree_fault(doc)
    if problem is not None:
        raise reject(problem)
    return doc


class _Reader:
    """The checks of one body, collecting every fault instead of stopping at the first."""

    def __init__(self) -> None:
        self.faults: list[dict[str, str]] = []

    def fault(self, field: str, reason: str) -> None:
        self.faults.append({"field": field, "reason": reason})

    def text(
        self, source: dict[str, Any], key: str, *, field: str | None = None, cap: int = TEXT_MAX
    ) -> str | None:
        """An optional text, at most `cap` characters; a fault makes it `None`."""
        value = source.get(key)
        if value is None:
            return None
        if not isinstance(value, str):
            self.fault(field or key, INVALID_TYPE)
            return None
        if len(value) > cap:
            self.fault(field or key, TOO_LONG)
            return None
        return value

    def choice(
        self,
        source: dict[str, Any],
        key: str,
        allowed: tuple[str, ...],
        *,
        field: str | None = None,
        required: bool = False,
    ) -> str | None:
        """A text that is one of `allowed`; absent or null is a fault only when `required`."""
        value = source.get(key)
        name = field or key
        if value is None:
            if required:
                self.fault(name, REQUIRED)
            return None
        if not isinstance(value, str):
            self.fault(name, INVALID_TYPE)
            return None
        if value not in allowed:
            self.fault(name, INVALID_VALUE)
            return None
        return value

    def instant(
        self, source: dict[str, Any], key: str, *, required: bool = False
    ) -> datetime | None:
        """A timestamp with an offset, in UTC; absent or null is a fault only when `required`."""
        value = source.get(key)
        if value is None:
            if required:
                self.fault(key, REQUIRED)
            return None
        if not isinstance(value, str):
            self.fault(key, INVALID_TYPE)
            return None
        moment, reason = _read_instant(value)
        if reason is not None:
            self.fault(key, reason)
        return moment

    def whole(
        self, source: dict[str, Any], key: str, *, field: str | None = None, low: int, high: int
    ) -> int | None:
        """A whole number from `low` to `high` (`30.0` is 30); absent or null is `None`."""
        value = source.get(key)
        name = field or key
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int | float):
            self.fault(name, INVALID_TYPE)
            return None
        if isinstance(value, float):
            if not math.isfinite(value) or not value.is_integer():
                self.fault(name, INVALID_VALUE)
                return None
            value = int(value)
        if not low <= value <= high:
            self.fault(name, INVALID_VALUE)
            return None
        return value

    def block(self, source: dict[str, Any], key: str) -> dict[str, Any] | None:
        """The object under `key`: `{}` when absent or null; `None` (and a fault) when it is not an object."""
        value = source.get(key)
        if value is None:
            return {}
        if not isinstance(value, dict):
            self.fault(key, INVALID_TYPE)
            return None
        return value


def _read_instant(text: str) -> tuple[datetime | None, str | None]:
    """`(UTC moment, None)` or `(None, reason)`."""
    if len(text) > _TIMESTAMP_MAX_LENGTH:
        return None, INVALID_VALUE
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None, INVALID_VALUE
    if moment.utcoffset() is None:
        return None, NO_OFFSET
    try:
        utc = moment.astimezone(UTC)
    except (OverflowError, ValueError):
        return None, INVALID_VALUE
    if not YEAR_MIN <= utc.year <= YEAR_MAX:
        return None, INVALID_VALUE
    return utc, None


def _read_version(doc: dict[str, Any], reader: _Reader) -> None:
    value = doc.get("schema_version")
    if value is None:
        reader.fault("schema_version", REQUIRED)
    elif not isinstance(value, str):
        reader.fault("schema_version", INVALID_TYPE)
    elif _VERSION_1.fullmatch(value):
        return
    elif _VERSION_ANY.fullmatch(value):
        reader.fault("schema_version", UNSUPPORTED_VERSION)
    else:
        reader.fault("schema_version", INVALID_VALUE)


def _read_id(doc: dict[str, Any], kind: str | None, reader: _Reader) -> str | None:
    value = doc.get("id")
    if value is None:
        reader.fault("id", REQUIRED)
        return None
    if not isinstance(value, str):
        reader.fault("id", INVALID_TYPE)
        return None
    if kind is None:
        return value  # the kind is already a fault: the shape of the id cannot be judged
    pattern = _REVIEW_ID if kind == "review" else _NOTICE_ID
    if not pattern.fullmatch(value):
        reader.fault("id", INVALID_VALUE)
        return None
    return value


def _read_status(doc: dict[str, Any], kind: str | None, reader: _Reader) -> str | None:
    value = doc.get("status")
    if value is None:
        reader.fault("status", REQUIRED)
        return None
    if not isinstance(value, str):
        reader.fault("status", INVALID_TYPE)
        return None
    if value == "processing":
        reader.fault("status", RESERVED)
        return None
    if value not in STATUSES:
        reader.fault("status", INVALID_VALUE)
        return None
    if kind is not None and (value == "info") != (kind == "notice"):
        reader.fault("status", INVALID_VALUE)  # a notice is info and nothing else is
        return None
    return value


def _read_score(doc: dict[str, Any], reader: _Reader) -> int | None:
    value = doc.get("score")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        reader.fault("score", INVALID_TYPE)
        return None
    if isinstance(value, float):
        if not math.isfinite(value) or not _INT32[0] - 1 <= value <= _INT32[1] + 1:
            reader.fault("score", INVALID_VALUE)
            return None
        value = math.floor(value + 0.5)  # half up: 49.5 is 50, -0.5 is 0
    if not _INT32[0] <= value <= _INT32[1]:
        reader.fault("score", INVALID_VALUE)
        return None
    return value


def _read_buttons(doc: dict[str, Any], kind: str | None, reader: _Reader) -> list[dict[str, str]]:
    value = doc.get("buttons")
    if value is None:
        if kind == "review":
            reader.fault("buttons", REQUIRED)
        return []
    if not isinstance(value, list):
        reader.fault("buttons", INVALID_TYPE)
        return []
    if len(value) > BUTTONS_MAX:
        reader.fault("buttons", INVALID_VALUE)
        return []
    buttons: list[dict[str, str]] = []
    for index, item in enumerate(value):
        where = f"buttons[{index}]"
        if not isinstance(item, dict):
            reader.fault(where, INVALID_TYPE)
            continue
        decision = reader.choice(
            item, "decision", DECISIONS, field=f"{where}.decision", required=True
        )
        label = item.get("label")
        if label is None:
            reader.fault(f"{where}.label", REQUIRED)
        elif not isinstance(label, str):
            reader.fault(f"{where}.label", INVALID_TYPE)
        elif len(label) > TEXT_MAX:
            reader.fault(f"{where}.label", TOO_LONG)
        elif decision is not None:
            buttons.append({"decision": decision, "label": label})
    return buttons


def parse(body: bytes) -> Notice:
    """The ticket in `body`, or `NoticeRejected` listing every fault. Never touches a database."""
    doc = _load(body)
    reader = _Reader()

    _read_version(doc, reader)
    event = reader.choice(doc, "event", EVENTS, required=True)
    kind = reader.choice(doc, "kind", KINDS, required=True)
    id_ = _read_id(doc, kind, reader)
    sent_at = reader.instant(doc, "sent_at", required=True)
    status = _read_status(doc, kind, reader)
    severity = reader.choice(doc, "severity", SEVERITIES) or "info"
    title = reader.text(doc, "title", cap=TITLE_MAX)

    simulated = doc.get("simulated")
    if simulated is None:
        simulated = False
    elif not isinstance(simulated, bool):
        reader.fault("simulated", INVALID_TYPE)
        simulated = False

    case = reader.block(doc, "case")
    case_id = case_number = None
    if case is not None:
        case_id = reader.text(case, "id", field="case.id")
        case_number = reader.whole(case, "number", field="case.number", low=0, high=_INT64_MAX)

    action = reader.block(doc, "action")
    action_type = action_text = action_target = action_via = action_agent = None
    if action is not None:
        action_type = reader.choice(action, "type", ACTION_TYPES, field="action.type")
        if action.get("type") is None and kind == "review":
            reader.fault("action.type", REQUIRED)
        action_text = reader.text(action, "text", field="action.text")
        action_target = reader.text(action, "target", field="action.target")
        action_via = reader.choice(action, "via", ACTION_VIAS, field="action.via")
        action_agent = reader.text(action, "agent", field="action.agent")

    host = reader.text(doc, "host")
    agent_id = reader.text(doc, "agent_id")
    user_name = reader.text(doc, "user")
    src_ip = reader.text(doc, "src_ip")
    domain = reader.text(doc, "domain")

    scenario = reader.block(doc, "scenario")
    scenario_id = scenario_name = None
    if scenario is not None:
        scenario_id = reader.text(scenario, "id", field="scenario.id")
        scenario_name = reader.text(scenario, "name", field="scenario.name")

    score = _read_score(doc, reader)
    note = reader.text(doc, "note")
    created_at = reader.instant(doc, "created_at")
    auto_expire_at = reader.instant(doc, "auto_expire_at")
    remind_every_minutes = reader.whole(doc, "remind_every_minutes", low=0, high=_INT32[1])
    next_remind_at = reader.instant(doc, "next_remind_at")
    decided_by = reader.text(doc, "decided_by")
    decided_at = reader.instant(doc, "decided_at")
    result = reader.text(doc, "result")
    buttons = _read_buttons(doc, kind, reader)

    if reader.faults:
        raise NoticeRejected(reader.faults)
    assert id_ is not None and event is not None and kind is not None  # for the type checker
    assert status is not None and sent_at is not None
    return Notice(
        id=id_,
        event=event,
        kind=kind,
        status=status,
        sent_at=sent_at,
        columns={
            "kind": kind,
            "status": status,
            "severity": severity,
            "title": title,
            "simulated": simulated,
            "case_id": case_id,
            "case_number": case_number,
            "action_type": action_type,
            "action_text": action_text,
            "action_target": action_target,
            "action_via": action_via,
            "action_agent": action_agent,
            "host": host,
            "agent_id": agent_id,
            "user_name": user_name,
            "src_ip": src_ip,
            "domain": domain,
            "scenario_id": scenario_id,
            "scenario_name": scenario_name,
            "score": score,
            "note": note,
            "buttons": buttons,
            "created_at": created_at,
            "auto_expire_at": auto_expire_at,
            "remind_every_minutes": remind_every_minutes or 0,
            "next_remind_at": next_remind_at,
            "decided_by": decided_by,
            "decided_at": decided_at,
            "result": result,
        },
        raw=doc,
    )


# ── storing it ──────────────────────────────────────────────────────────────────────────────

#: The columns a body fills, in the order they are written. `created_at` is separate: it keeps the stored value when the
#: body of an update omits it.
_BODY_COLUMNS = tuple(
    name
    for name in (
        "kind",
        "status",
        "severity",
        "title",
        "simulated",
        "case_id",
        "case_number",
        "action_type",
        "action_text",
        "action_target",
        "action_via",
        "action_agent",
        "host",
        "agent_id",
        "user_name",
        "src_ip",
        "domain",
        "scenario_id",
        "scenario_name",
        "score",
        "note",
        "buttons",
        "auto_expire_at",
        "remind_every_minutes",
        "next_remind_at",
        "decided_by",
        "decided_at",
        "result",
    )
)


def _params(notice: Notice) -> dict[str, Any]:
    values = {name: notice.columns[name] for name in _BODY_COLUMNS}
    values["buttons"] = Jsonb(notice.columns["buttons"])
    values["created_at"] = notice.columns["created_at"]
    values["id"] = notice.id
    values["sent_at"] = notice.sent_at
    values["raw"] = Jsonb(notice.raw)
    return values


def _insert(conn: psycopg.Connection, notice: Notice) -> bool:
    """Make the row; `False` when another request made it first (nothing is written then)."""
    columns = sql.SQL(", ").join(sql.Identifier(name) for name in _BODY_COLUMNS)
    marks = sql.SQL(", ").join(sql.Placeholder(name) for name in _BODY_COLUMNS)
    statement = sql.SQL(
        "INSERT INTO soar_reviews (id, {columns}, created_at, last_sent_at, raw) "
        "VALUES (%(id)s, {marks}, COALESCE(%(created_at)s, %(sent_at)s), %(sent_at)s, %(raw)s) "
        "ON CONFLICT (id) DO NOTHING RETURNING id"
    ).format(columns=columns, marks=marks)
    return conn.execute(statement, _params(notice)).fetchone() is not None


#: The record of a decision. A push that carries one replaces it; a push that leaves it null or out keeps the stored one, so that
#: n8n's next `updated` or `reminder` cannot erase who decided, when and with what result (the web writes them on a press).
_KEPT_WHEN_NULL = ("decided_by", "decided_at", "result")


def _update(conn: psycopg.Connection, notice: Notice) -> None:
    """Every field of the body replaces the stored one, except the three of `_KEPT_WHEN_NULL`, which a null or an absent field
    leaves as it is; the lock is released: n8n is the authority."""
    assignments = sql.SQL(", ").join(
        (
            sql.SQL("{name} = COALESCE({value}, {name})").format(
                name=sql.Identifier(column), value=sql.Placeholder(column)
            )
            if column in _KEPT_WHEN_NULL
            else sql.SQL("{} = {}").format(sql.Identifier(column), sql.Placeholder(column))
        )
        for column in _BODY_COLUMNS
    )
    statement = sql.SQL(
        "UPDATE soar_reviews SET {assignments}, created_at = COALESCE(%(created_at)s, created_at), "
        "raw = %(raw)s, last_sent_at = %(sent_at)s, locked_by = NULL, locked_at = NULL, "
        "prev_status = NULL, updated_at = now() WHERE id = %(id)s"
    ).format(assignments=assignments)
    conn.execute(statement, _params(notice))


def _lock_row(conn: psycopg.Connection, review_id: str) -> tuple[str, datetime] | None:
    """`(status, last_sent_at)` of the ticket, its row locked until the transaction ends; `None` when there is none."""
    row = conn.execute(
        "SELECT status, last_sent_at FROM soar_reviews WHERE id = %s FOR UPDATE", (review_id,)
    ).fetchone()
    return None if row is None else (row[0], row[1])


def apply(conn: psycopg.Connection, notice: Notice) -> Applied:
    """Store `notice` by the table of the module docstring and write its audit event. The caller commits."""
    row = _lock_row(conn, notice.id)
    if row is None and _insert(conn, notice):
        applied = Applied(notice.id, "created")
    else:
        if row is None:  # another request made it between our look and our insert: it is there now
            row = _lock_row(conn, notice.id)
        assert row is not None
        stored_status, last_sent_at = row
        if notice.sent_at < last_sent_at:
            applied = Applied(notice.id, "ignored", "stale")
        elif stored_status in TERMINAL_STATUSES and notice.status == "open":
            applied = Applied(notice.id, "ignored", "terminal")
        else:
            _update(conn, notice)
            applied = Applied(notice.id, "updated")
    write_event(
        conn,
        "soar.review_received",
        notice.id,
        "system",
        payload={
            "event": notice.event,
            "kind": notice.kind,
            "outcome": applied.outcome,
            "reason": applied.reason,
            "status": notice.status,
            "sent_at": notice.sent_at.isoformat(),
        },
    )
    return applied
