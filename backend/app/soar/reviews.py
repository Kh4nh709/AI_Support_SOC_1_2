"""The SOAR review tickets as the web serves and decides them (SR-T1, spec 2026-11-16 §3 to §5).

What `review_notice.py` stores from n8n's pushes, this module reads for the analysts' page (`list_reviews`, `count_reviews`,
`get_detail`) and changes when a person presses a button (`decide`). `web/routers/soar_reviews.py` binds both to HTTP.

**The served object** (`serve`): the ticket's columns by the names of spec §4 (`status` is the effective one, `user_name` the
`user` n8n sent), the times as ISO 8601 with offset `+00:00` whatever zone the database session is in, and two fields computed for
THIS caller: `allowed_decisions` (valid for the state AND allowed for the role) and `strong_warning` (an isolation, or a host that
is a domain controller). The effective status: a `processing` row whose `locked_at` is older than `LOCK_STALE_SECONDS` is served
with the status it had before the lock and with `locked_by` / `locked_at` null; a read never writes, so the lock is released by
the next press, not by looking.

**The decisions** (`valid_decisions`): an `open` review takes the decisions of its `buttons`; a `kept` one takes `undo` only, and
never for a `kill_process` (a killed process cannot be brought back); anything else, a notice included, takes none.

**The press** (`decide`), in order, each step in the spec's words:

1. the ticket is read (`NotFound`); one that is held (`locked`) or whose state does not fit (`invalid_state`) is `Refused` with the
   ticket as it is, after writing its audit event and committing it (commit before raise: the request's connection rolls back on
   an exception);
2. n8n must be configured (`NotConfigured`), before anything is locked;
3. the lock, ONE `UPDATE` whose `WHERE` is the state just validated, or a lock older than two minutes on that state: `prev_status`
   is kept when the row was already `processing` (a stale lock), else it is the state it had. No row matched: the ticket changed in
   between, and the answer is `Refused` again. Then COMMIT: the lock is visible to everyone and no transaction is open during the call;
4. the call to n8n (`infra/n8n_approval.py`; it never raises);
5. the finish, a compare-and-set on `(id, status = 'processing', locked_by, locked_at)`, so it matches only the lock THIS press took:
   `ok` takes the status n8n gave, its `result`, who decided and when, and clears `last_error`; `failed` and `unavailable` put the
   state back and keep the reason in `last_error`; `conflict` takes the status n8n says when it is one a ticket can have, else puts
   the state back. If it matches nothing, n8n's own `updated` push got there first (it clears the lock): nothing is written, and
   the answer carries the ticket as it now is;
6. one `soar.review_decided` event, whatever the outcome, and the ticket as it now is.

`soar/` imports `infra` and `audit` only; the caller's identity arrives as plain values (`Person`), never as `web`'s `Claims`.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx
import psycopg

from app.audit.events import write_event
from app.infra import n8n_approval
from app.infra.config import Config

#: A lock older than this is taken to be abandoned (a call ends well before: `N8N_APPROVAL_TIMEOUT_SECONDS` is at most 100).
LOCK_STALE_SECONDS = 120
_STALE_AFTER = f"interval '{LOCK_STALE_SECONDS} seconds'"

#: The states a ticket can be in, as served (the effective status).
STATUSES = ("open", "kept", "undone", "false_positive", "expired", "info", "processing")
#: What a `conflict` answer may put the ticket in (n8n's own five).
CONFLICT_STATUSES = ("open", "kept", "undone", "false_positive", "expired")
KINDS = ("review", "notice")
ACTION_TYPES = (
    "block_ip",
    "sinkhole_domain",
    "isolate_host",
    "disable_user",
    "disable_xp_cmdshell",
    "kill_process",
)

PAGE_SIZE_DEFAULT = 50
PAGE_SIZE_MAX = 200
#: `q` is at most this many characters.
Q_MAX_LENGTH = 100
HISTORY_MAX = 200
RELATED_MAX = 50
_INT64_MAX = 2**63 - 1

#: What the person is told when a press failed or was refused and n8n gave no text of its own.
FAILED_TEXT = "n8n báo thao tác không thành công. Phiếu giữ nguyên trạng thái."
CONFLICT_TEXT = "Phiếu đã được xử lý ở nơi khác. Đã cập nhật theo trạng thái của n8n."


class NotFound(Exception):
    """No ticket has this id."""


class NotConfigured(Exception):
    """`N8N_APPROVAL_URL` or `N8N_APPROVAL_SECRET` is empty: nothing was locked."""


class Refused(Exception):
    """The press was refused (`reason` is `locked` or `invalid_state`); `review` is the ticket as it is, as served to the caller."""

    def __init__(self, reason: str, review: dict[str, Any]) -> None:
        super().__init__(reason)
        self.reason = reason
        self.review = review


@dataclass(frozen=True)
class Person:
    """Who presses: the `users` row's id and name, the role (`tier1`, `tier2`, `admin`) and the audit actor role it maps to
    (`analyst` or `admin`: the audit CHECKs know four roles, not three)."""

    user_id: str
    username: str
    role: str
    actor_role: str


@dataclass(frozen=True)
class Decided:
    """The answer of a press that reached n8n: `outcome` is `ok`, `failed`, `unavailable` or `conflict`."""

    outcome: str
    message: str | None
    review: dict[str, Any]


# ── what is served ──────────────────────────────────────────────────────────────────────────

#: The columns of the served object, in spec §4's order, as the SELECT below gives them; `allowed_decisions` and
#: `strong_warning` are computed.
_SERVED_NAMES = (
    "id", "kind", "status", "severity", "title", "simulated", "case_id", "case_number",
    "action_type", "action_text", "action_target", "action_via", "action_agent",
    "host", "agent_id", "user_name", "src_ip", "domain", "scenario_id", "scenario_name", "score", "note",
    "buttons", "created_at", "auto_expire_at", "remind_every_minutes", "next_remind_at",
    "decided_by", "decided_at", "result", "last_error", "locked_by", "locked_at", "last_sent_at", "updated_at",
)  # fmt: skip
_TIME_NAMES = (
    "created_at", "auto_expire_at", "next_remind_at", "decided_at", "locked_at", "last_sent_at", "updated_at",
)  # fmt: skip

#: The table with the effective status worked out: a stale lock is served as the state the row had.
_BASE = f"""
  SELECT t.*,
         CASE WHEN t.status = 'processing' AND t.locked_at < now() - {_STALE_AFTER}
              THEN t.prev_status ELSE t.status END AS eff_status,
         (t.status = 'processing' AND t.locked_at >= now() - {_STALE_AFTER}) AS locked
    FROM soar_reviews t
"""
_SERVED_SQL = """
  r.id, r.kind, r.eff_status, r.severity, r.title, r.simulated, r.case_id, r.case_number,
  r.action_type, r.action_text, r.action_target, r.action_via, r.action_agent,
  r.host, r.agent_id, r.user_name, r.src_ip, r.domain, r.scenario_id, r.scenario_name, r.score, r.note,
  r.buttons, r.created_at, r.auto_expire_at, r.remind_every_minutes, r.next_remind_at,
  r.decided_by, r.decided_at, r.result, r.last_error,
  CASE WHEN r.locked THEN r.locked_by END, CASE WHEN r.locked THEN r.locked_at END,
  r.last_sent_at, r.updated_at
"""


def _iso(moment: datetime | None) -> str | None:
    return None if moment is None else moment.astimezone(UTC).isoformat()


def valid_decisions(
    kind: str, status: str, action_type: str | None, buttons: list[dict]
) -> list[str]:
    """The decisions the state allows, whoever asks (module docstring)."""
    if kind != "review":
        return []
    if status == "open":
        found: list[str] = []
        for button in buttons:
            if button.get("decision") not in found:
                found.append(button["decision"])
        return found
    if status == "kept" and action_type != "kill_process":
        return ["undo"]
    return []


def roles_for(decision: str, cfg: Config) -> list[str]:
    """The roles the configuration allows `decision` to."""
    return {
        "keep": cfg.SOAR_ROLES_KEEP,
        "undo": cfg.SOAR_ROLES_UNDO,
        "fp": cfg.SOAR_ROLES_FP,
    }[decision]


def roles_for_any(cfg: Config) -> list[str]:
    """Every role that is allowed some decision, in the order the lists give them."""
    found: list[str] = []
    for decision in ("keep", "undo", "fp"):
        for role in roles_for(decision, cfg):
            if role not in found:
                found.append(role)
    return found


def strong_warning(action_type: str | None, host: str | None, cfg: Config) -> bool:
    """An isolation, or a host that is a domain controller (`SOAR_AD_HOSTS`, compared without case)."""
    if action_type == "isolate_host":
        return True
    return host is not None and host.casefold() in {name.casefold() for name in cfg.SOAR_AD_HOSTS}


def serve(row: tuple, role: str, cfg: Config) -> dict[str, Any]:
    """The ticket as the API serves it to a caller of `role`."""
    review = dict(zip(_SERVED_NAMES, row, strict=True))
    for name in _TIME_NAMES:
        review[name] = _iso(review[name])
    review["allowed_decisions"] = [
        decision
        for decision in valid_decisions(
            review["kind"], review["status"], review["action_type"], review["buttons"]
        )
        if role in roles_for(decision, cfg)
    ]
    review["strong_warning"] = strong_warning(review["action_type"], review["host"], cfg)
    return review


def _fetch_row(conn: psycopg.Connection, review_id: str) -> tuple | None:
    return conn.execute(
        f"SELECT {_SERVED_SQL} FROM ({_BASE}) r WHERE r.id = %s", (review_id,)
    ).fetchone()


def get_review(
    conn: psycopg.Connection, review_id: str, role: str, cfg: Config
) -> dict[str, Any] | None:
    row = _fetch_row(conn, review_id)
    return None if row is None else serve(row, role, cfg)


# ── the list and the count ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Filters:
    """The list's filters, all optional and ANDed. `statuses` is the effective status."""

    statuses: tuple[str, ...] | None = None
    kind: str | None = None
    action_type: str | None = None
    case_number: int | None = None
    created_from: datetime | None = None  # inclusive
    created_to: datetime | None = None  # exclusive
    q: str | None = None


def _like(text: str) -> str:
    r"""`text` as the middle of a `LIKE` pattern that matches it literally: `\`, `%` and `_` are escaped (`ESCAPE '\'`)."""
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


#: The columns `q` is looked for in, when it is not a case number.
_Q_COLUMNS = ("src_ip", "host", "action_target", "user_name", "domain")


def _where(filters: Filters) -> tuple[str, dict[str, Any]]:
    """The `WHERE` of the list and the count: fixed fragments, every value a bound parameter."""
    clauses: list[str] = []
    params: dict[str, Any] = {}
    if filters.statuses is not None:
        clauses.append("r.eff_status = ANY(%(statuses)s)")
        params["statuses"] = list(filters.statuses)
    if filters.kind is not None:
        clauses.append("r.kind = %(kind)s")
        params["kind"] = filters.kind
    if filters.action_type is not None:
        clauses.append("r.action_type = %(action_type)s")
        params["action_type"] = filters.action_type
    if filters.case_number is not None:
        clauses.append("r.case_number = %(case_number)s")
        params["case_number"] = filters.case_number
    if filters.created_from is not None:
        clauses.append("r.created_at >= %(created_from)s")
        params["created_from"] = filters.created_from
    if filters.created_to is not None:
        clauses.append("r.created_at < %(created_to)s")
        params["created_to"] = filters.created_to
    q = (filters.q or "").strip()
    if q:
        if re.fullmatch(r"[0-9]{1,18}", q):  # a case number; ASCII digits only, and inside a bigint
            clauses.append("r.case_number = %(q_number)s")
            params["q_number"] = int(q)
        else:
            clauses.append(
                "("
                + " OR ".join(f"r.{name} ILIKE %(q_like)s ESCAPE '\\'" for name in _Q_COLUMNS)
                + ")"
            )
            params["q_like"] = _like(q)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def list_reviews(
    conn: psycopg.Connection,
    filters: Filters,
    *,
    page: int,
    page_size: int,
    role: str,
    cfg: Config,
) -> tuple[list[dict[str, Any]], int]:
    """`(rows, total)`: one page of the tickets, newest `created_at` first (then `id`). `page_size` is clamped to
    `PAGE_SIZE_MAX`."""
    page_size = min(page_size, PAGE_SIZE_MAX)
    where, params = _where(filters)
    records = conn.execute(
        f"SELECT {_SERVED_SQL} FROM ({_BASE}) r{where} "
        "ORDER BY r.created_at DESC, r.id LIMIT %(limit)s OFFSET %(offset)s",
        {**params, "limit": page_size, "offset": (page - 1) * page_size},
    ).fetchall()
    total = conn.execute(f"SELECT count(*) FROM ({_BASE}) r{where}", params).fetchone()[0]
    return [serve(record, role, cfg) for record in records], total


def count_reviews(conn: psycopg.Connection, statuses: tuple[str, ...]) -> tuple[int, str | None]:
    """`(count, latest created_at)` over the REVIEWS (never the notices) in these effective states."""
    count, latest = conn.execute(
        f"SELECT count(*), max(r.created_at) FROM ({_BASE}) r "
        "WHERE r.kind = 'review' AND r.eff_status = ANY(%s)",
        (list(statuses),),
    ).fetchone()
    return count, _iso(latest)


# ── the detail ──────────────────────────────────────────────────────────────────────────────


def _history(conn: psycopg.Connection, review_id: str) -> list[dict[str, Any]]:
    """The audit events of this ticket, oldest first, at most `HISTORY_MAX`. `actor` is the person's username (null for the
    system); `actor_role` is `tier1`, `tier2` or `admin` (the role of the user as the `users` row has it now: the audit CHECKs
    know only `analyst` and `admin`, and both analyst tiers are `analyst` there) or `system`. A person whose row is gone keeps
    the audit's own word, `analyst` or `admin`."""
    records = conn.execute(
        "SELECT a.created_at, a.event_type, u.username, "
        "CASE WHEN a.actor_role IN ('analyst', 'admin') THEN COALESCE(u.role, a.actor_role) ELSE a.actor_role END, "
        "a.payload "
        "FROM audit_events a "
        "LEFT JOIN users u ON a.actor_role IN ('analyst', 'admin') AND u.user_id = a.actor_id "
        "WHERE a.subject_id = %s AND a.event_type IN ('soar.review_received', 'soar.review_decided') "
        "ORDER BY a.audit_id LIMIT %s",
        (review_id, HISTORY_MAX),
    ).fetchall()
    return [
        {
            "at": _iso(at),
            "event": event,
            "actor": actor,
            "actor_role": actor_role,
            "payload": payload,
        }
        for at, event, actor, actor_role, payload in records
    ]


#: The alerts of a SOAR case: `alerts.raw_payload -> enrichment -> case -> case_number` (the alert page's SOAR view reads the same
#: place). Compared as text, so a number and a text of the same digits are the same case. A filtered scan, run only for the detail.
_CASE_OF_ALERT = "raw_payload #>> '{enrichment,case,case_number}'"


def _related_alerts(conn: psycopg.Connection, case_number: int) -> tuple[list[dict[str, Any]], int]:
    """The alerts of the same SOAR case, newest first, at most `RELATED_MAX`, and how many there are. The fields are the
    queue row's, none of ①'s (the blind arm sees nothing new)."""
    number = str(case_number)
    records = conn.execute(
        "SELECT alert_id, alert_time, agent_name, description, severity, status, occurrence_count "
        f"FROM alerts WHERE {_CASE_OF_ALERT} = %s ORDER BY alert_time DESC, alert_id LIMIT %s",
        (number, RELATED_MAX),
    ).fetchall()
    total = conn.execute(
        f"SELECT count(*) FROM alerts WHERE {_CASE_OF_ALERT} = %s", (number,)
    ).fetchone()[0]
    rows = [
        {
            "alert_id": alert_id,
            "alert_time": _iso(alert_time),
            "agent_name": agent_name,
            "description": description,
            "severity": severity,
            "status": status,
            "occurrence_count": occurrence_count,
        }
        for alert_id, alert_time, agent_name, description, severity, status, occurrence_count in records
    ]
    return rows, total


def get_detail(
    conn: psycopg.Connection, review_id: str, role: str, cfg: Config
) -> dict[str, Any] | None:
    """The ticket plus `raw` (the last body n8n sent), `history`, `related_alerts` and `related_total`; `None` for an
    unknown id."""
    review = get_review(conn, review_id, role, cfg)
    if review is None:
        return None
    (raw,) = conn.execute("SELECT raw FROM soar_reviews WHERE id = %s", (review_id,)).fetchone()
    review["raw"] = raw
    review["history"] = _history(conn, review_id)
    if review["case_number"] is None:
        review["related_alerts"], review["related_total"] = [], 0
    else:
        review["related_alerts"], review["related_total"] = _related_alerts(
            conn, review["case_number"]
        )
    return review


# ── a person presses a button ───────────────────────────────────────────────────────────────

_LOCK_SQL = f"""
UPDATE soar_reviews
   SET prev_status = CASE WHEN status = 'processing' THEN prev_status ELSE status END,
       status = 'processing', locked_by = %(user)s, locked_at = now(), updated_at = now()
 WHERE id = %(id)s
   AND (status = %(status)s
        OR (status = 'processing' AND locked_at < now() - {_STALE_AFTER} AND prev_status = %(status)s))
RETURNING locked_at
"""

#: The finish: a compare-and-set on the lock this press took. Each variant sets what its outcome says and releases the lock.
_FINISH_WHERE = "WHERE id = %(id)s AND status = 'processing' AND locked_by = %(user)s AND locked_at = %(locked_at)s"
_FINISH_OK_SQL = (
    "UPDATE soar_reviews SET status = %(status)s, result = %(result)s, decided_by = %(user)s, decided_at = now(), "
    "last_error = NULL, locked_by = NULL, locked_at = NULL, prev_status = NULL, updated_at = now() "
    + _FINISH_WHERE
)
_FINISH_BACK_SQL = (
    "UPDATE soar_reviews SET status = prev_status, last_error = %(error)s, "
    "locked_by = NULL, locked_at = NULL, prev_status = NULL, updated_at = now() " + _FINISH_WHERE
)
_FINISH_CONFLICT_SQL = (
    "UPDATE soar_reviews SET status = COALESCE(%(status)s, prev_status), result = COALESCE(%(result)s, result), "
    "last_error = NULL, locked_by = NULL, locked_at = NULL, prev_status = NULL, updated_at = now() "
    + _FINISH_WHERE
)


def _record(
    conn: psycopg.Connection,
    person: Person,
    review_id: str,
    decision: str,
    note: str | None,
    outcome: str,
    status_before: str,
    status_after: str,
    message: str | None,
) -> None:
    write_event(
        conn,
        "soar.review_decided",
        review_id,
        person.actor_role,
        actor_id=person.user_id,
        payload={
            "decision": decision,
            "note": note,
            "outcome": outcome,
            "status_before": status_before,
            "status_after": status_after,
            "message": message,
        },
    )


def _refuse(
    conn: psycopg.Connection,
    person: Person,
    cfg: Config,
    review_id: str,
    decision: str,
    note: str | None,
    reason: str,
) -> Refused:
    """Write the event of a refused press, commit it, and return the exception to raise: the request's connection rolls back
    on any exception, so the event would be lost if it were not committed first."""
    row = _fetch_row(conn, review_id)
    assert row is not None  # tickets are never deleted
    review = serve(row, person.role, cfg)
    _record(
        conn, person, review_id, decision, note, reason, review["status"], review["status"], None
    )
    conn.commit()
    return Refused(reason, review)


def decide(
    conn: psycopg.Connection,
    review_id: str,
    person: Person,
    decision: str,
    note: str | None,
    cfg: Config,
    client_factory: Callable[[], httpx.Client] | None = None,
) -> Decided:
    """Carry out `decision` on `review_id` for `person` (the module docstring has the steps). The role check and the body's
    validation are the caller's; the ticket, the lock, n8n and the finish are here. Raises `NotFound`, `NotConfigured`
    (nothing locked) or `Refused` (its event written and committed). On any other raise the connection's owner rolls back.
    """
    row = _fetch_row(conn, review_id)
    if row is None:
        raise NotFound(review_id)
    review = serve(row, person.role, cfg)
    status_before = review["status"]
    if status_before == "processing":
        raise _refuse(conn, person, cfg, review_id, decision, note, "locked")
    if decision not in valid_decisions(
        review["kind"], status_before, review["action_type"], review["buttons"]
    ):
        raise _refuse(conn, person, cfg, review_id, decision, note, "invalid_state")
    if not n8n_approval.is_configured(cfg):
        raise NotConfigured

    locked = conn.execute(
        _LOCK_SQL, {"id": review_id, "user": person.username, "status": status_before}
    ).fetchone()
    if (
        locked is None
    ):  # the ticket changed between the look and the lock: whoever got there first is right
        now = _fetch_row(conn, review_id)
        reason = "locked" if now is not None and now[2] == "processing" else "invalid_state"
        raise _refuse(conn, person, cfg, review_id, decision, note, reason)
    (locked_at,) = locked
    conn.commit()  # the lock is visible, and no transaction is open while n8n is asked

    answer = n8n_approval.call(
        cfg,
        review_id=review_id,
        decision=decision,
        user=person.username,
        user_role=person.role,
        note=note,
        client_factory=client_factory,
    )

    key = {"id": review_id, "user": person.username, "locked_at": locked_at}
    message: str | None
    if answer.outcome == "ok":
        message = answer.message
        conn.execute(_FINISH_OK_SQL, {**key, "status": answer.status, "result": answer.result})
    elif answer.outcome == "failed":
        message = answer.message or answer.result or FAILED_TEXT
        conn.execute(_FINISH_BACK_SQL, {**key, "error": message})
    elif answer.outcome == "conflict":
        message = answer.message or CONFLICT_TEXT
        status = answer.status if answer.status in CONFLICT_STATUSES else None
        conn.execute(_FINISH_CONFLICT_SQL, {**key, "status": status, "result": answer.result})
    else:  # unavailable
        message = answer.message
        conn.execute(_FINISH_BACK_SQL, {**key, "error": message})

    # Whether the compare-and-set matched or n8n's own push got there first, the answer is the ticket as it now is.
    final = _fetch_row(conn, review_id)
    assert final is not None
    served = serve(final, person.role, cfg)
    _record(
        conn,
        person,
        review_id,
        decision,
        note,
        answer.outcome,
        status_before,
        served["status"],
        message,
    )
    conn.commit()
    return Decided(answer.outcome, message, served)
