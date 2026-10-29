"""The webhook intake path — `receive()` is `POST /webhook/alerts`'s business
logic (context pack §6.4, architecture §3.1, DEC-040).

Pure by the import rule (infra imports nothing from the app — G1, context pack
§4): this module knows the `intake`/`rejected_alerts` tables and nothing about
HTTP. `web/routers/webhook.py` turns its exceptions into status codes, exactly
as `web/deps.py` does for `infra/auth.py` (P4-tasks.md planning decision 2).

G9: `raw_text` is `body.decode("utf-8")`, unchanged — never `json.dumps` of the
parsed object, which would reorder nothing in this Python version but is still
not the received document.

DEC-035's trap: a webhook row is inserted with `via='webhook'`, never the
puller's private, `pull`-specific `_insert_alert` (`via='pull'`) — `via='pull'`
on an envelope-free (bare) body would make `soar.pipeline._derive_source`
read it as `source='replay'` instead of `'wazuh'`. `is_heartbeat` is public
and reused (P4-tasks.md planning decision 13); `_update_heartbeat` and
`_replay_sort_key` are same-package private helpers, reused rather than
duplicated (design note 1c/1d of the task card).

DEC-207 (item 2, amended in fix round 1): with `PULL_ENABLED=false` an accepted alert stamps
`source_heartbeat` (`saw_alert=True`), so the `heartbeat` health check stays green on a stream
that arrives by the webhook only. With the pull on nothing is stamped here, as before.
"""

from __future__ import annotations

import dataclasses
import json
import re
from typing import Literal

import psycopg
from psycopg.types.json import Jsonb

from app.infra.config import Config
from app.infra.ids import is_alert_id
from app.infra.jobs import enqueue
from app.infra.puller import _replay_sort_key, _update_heartbeat, is_heartbeat

# "≤ 4 KB" — design note 1b: the excerpt stored for a body that could not even
# be parsed as JSON (so there is no smaller structured thing to store instead).
_REJECTED_BODY_EXCERPT_CHARS = 4096

# A character no Postgres text or jsonb value can hold: NUL, or a surrogate code point on its own.
_UNSTORABLE_RE = re.compile("[\x00\ud800-\udfff]")


class PayloadTooLarge(Exception):
    """`body` exceeds `cfg.MAX_PAYLOAD_BYTES` — checked before any parse."""


class Rejected(Exception):
    """`reason` ∈ not_json | not_an_object | id | rule.id | timestamp — the route names the
    missing field, never an exception message (phase-1 §Xử lý lỗi, G-15). `id` also covers an id
    that is present but not ①'s `alert_id` shape (DEC-211 R6): the answer is the same, so the
    response bytes did not change. `timestamp` (INT-T02 fix round 1) is the one new value: the
    body is the existing `{"missing": <reason>}`, and it covers a timestamp that is absent or that
    no sort key can be made from. `not_json` (fix round 2) also covers a body that is not strict UTF-8
    (UTF-16/32, a BOM) and a JSON string or key holding a NUL or a lone surrogate."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class Duplicate(Exception):
    """The same `(manager_id, source_alert_id)` was already received."""


@dataclasses.dataclass(frozen=True)
class Receipt:
    kind: Literal["heartbeat", "alert"]
    intake_id: int | None


def _body_excerpt(body: bytes) -> str:
    """The first characters of a body that is not an alert, decoded leniently, to be stored as a
    `jsonb` string in `rejected_alerts`. A NUL character is replaced (by U+FFFD, so nothing shifts):
    a body in UTF-16-LE or UTF-32-LE without a BOM, or with a raw NUL byte, decodes to text full of
    them, and neither a `text` nor a `jsonb` column can hold one (INT-T02 fix round 2)."""
    text = body.decode("utf-8", errors="replace").replace("\x00", "�")
    return text[:_REJECTED_BODY_EXCERPT_CHARS]


def _has_unstorable_text(value: object) -> bool:
    """Whether a string or an object key anywhere inside the parsed JSON `value` is one Postgres
    cannot store: a NUL (`"\\u0000"` is valid JSON, but `intake.raw_payload` is `raw_text::jsonb` and
    jsonb refuses it, as the text columns do) or a lone surrogate (`"\\ud800"`, which `jsonb` refuses
    and UTF-8 cannot encode; a surrogate PAIR has already become one character). Iterative: the
    parser took a document as deep as the interpreter allows, and a recursive walk would not."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if _UNSTORABLE_RE.search(item):
                return True
        elif isinstance(item, dict):
            for key, child in item.items():
                if _UNSTORABLE_RE.search(key):
                    return True
                stack.append(child)
        elif isinstance(item, list):
            stack.extend(item)
    return False


def _manager_id(alert_obj: dict) -> str:
    """The same derivation as `puller._manager_id`: `manager.name`, or
    `'default'` when absent."""
    manager = alert_obj.get("manager")
    return (manager if isinstance(manager, dict) else {}).get("name") or "default"


def _sort_key_of(timestamp: object) -> int | None:
    """The epoch-millis sort key of an alert's `timestamp` (`puller._replay_sort_key`, the one the
    pull and the replay use), or `None` when there is none to make: the key is absent or null, the
    value is not text (a number, a list, an object: none is the ISO text Wazuh and the SOAR send), or
    the text is not an ISO date-time the key can be taken from (including an offset or a year the
    conversion cannot represent)."""
    if not isinstance(timestamp, str):
        return None
    try:
        return _replay_sort_key(timestamp)
    except (ValueError, OverflowError, OSError):
        return None


def _insert_rejected(
    conn: psycopg.Connection, source_ip: str, reason: str, raw_payload: object
) -> None:
    conn.execute(
        "INSERT INTO rejected_alerts (raw_payload, reason, source_ip) VALUES (%s, %s, %s)",
        (Jsonb(raw_payload), reason, source_ip),
    )


def receive(conn: psycopg.Connection, body: bytes, source_ip: str, cfg: Config) -> Receipt:
    """Design note 1's ordering — nothing earlier than the size check reads
    `body`. Raises `PayloadTooLarge` / `Rejected` / `Duplicate` on every
    non-201 outcome; the route maps each to its status code."""
    if len(body) > cfg.MAX_PAYLOAD_BYTES:
        raise PayloadTooLarge(
            f"body is {len(body)} bytes, exceeds MAX_PAYLOAD_BYTES={cfg.MAX_PAYLOAD_BYTES}"
        )

    # INT-T02 fix round 2 (the Director's ruling): decode strictly as UTF-8 FIRST, then parse the text.
    # `json.loads(bytes)` would guess UTF-8, UTF-16 or UTF-32 (and take encoded surrogates), so a UTF-16/32
    # body parsed and failed later at `body.decode("utf-8")` (a 500), and a UTF-8 BOM gave a 201 the
    # pipeline's `json.loads(raw_text)` could not read. RFC 8259 §8.1: JSON on a network is UTF-8. A body
    # that is not strict UTF-8 (a BOM included: `json.loads(str)` refuses it) is `not_json`. The text
    # decoded here is `raw_text` below, the very `body.decode("utf-8")` of G9, so a valid body is stored
    # exactly as it was.
    try:
        raw_text = body.decode("utf-8")
        doc = json.loads(raw_text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        _insert_rejected(conn, source_ip, "not_json", {"body": _body_excerpt(body)})
        raise Rejected("not_json") from None
    # A NUL, or a lone surrogate, inside a JSON string or key is valid JSON that `raw_text::jsonb` (the
    # generated `intake.raw_payload`) refuses: a 500 and no `rejected_alerts` row. It is `not_json` too,
    # and what is stored is the excerpt, never the document (which the jsonb column could not hold).
    if _has_unstorable_text(doc):
        _insert_rejected(conn, source_ip, "not_json", {"body": _body_excerpt(body)})
        raise Rejected("not_json")
    if not isinstance(doc, dict):
        _insert_rejected(conn, source_ip, "not_an_object", {"body": _body_excerpt(body)})
        raise Rejected("not_an_object")

    # Structural, not shape-counting (same rule as `wazuh_parser.parse_wazuh_alert`):
    # a `_source` key present means the alert is `_source`, else the object itself is.
    alert_obj = doc["_source"] if isinstance(doc.get("_source"), dict) else doc
    # DEC-211 R6 item A (INT-T02): the id must be ①'s exact `alert_id` shape (`app.infra.ids`), the
    # Wazuh `<epoch>.<n>` or the SOAR `gl-<ULID>-<uuid>`. An empty, absent, non-string or off-pattern
    # id is one case with one answer (the reason `id`, a rejected row, the route's 400): an id ① could
    # never render would otherwise be accepted, stored, and fail much later in the pipeline.
    if not is_alert_id(alert_obj.get("id")):
        _insert_rejected(conn, source_ip, "id", doc)
        raise Rejected("id")
    rule = alert_obj.get("rule")
    if not isinstance(rule, dict) or not rule.get("id"):
        _insert_rejected(conn, source_ip, "rule.id", doc)
        raise Rejected("rule.id")

    # INT-T02 fix round 1, F2 (the Director's ruling): the same for a `timestamp` the sort key cannot
    # be made from. It used to raise (`KeyError`, `ValueError`) out of `_replay_sort_key`: a 500, with
    # no `rejected_alerts` row, as `Conn` rolls back, so the alert was dropped without a trace. Judged
    # after the id and the rule, in their style, before anything is written.
    sort_key = _sort_key_of(alert_obj.get("timestamp"))
    if sort_key is None:
        _insert_rejected(conn, source_ip, "timestamp", doc)
        raise Rejected("timestamp")

    manager_id = _manager_id(alert_obj)
    source_alert_id = alert_obj["id"]

    # Normalised for the heartbeat check only (never for storage — G9):
    # `is_heartbeat` reads `doc["_source"]["rule"]["id"]`, and a webhook body
    # may arrive bare or already wrapped as an indexer hit.
    hit = doc if "_source" in doc else {"_source": doc}
    if is_heartbeat(hit):
        conn.execute(
            """
            INSERT INTO intake
                (manager_id, source_alert_id, raw_text, sort_key, via, outcome, processed_at)
            VALUES (%s, %s, %s, %s, 'webhook', 'heartbeat', now())
            ON CONFLICT (manager_id, source_alert_id) DO NOTHING
            """,
            (manager_id, source_alert_id, raw_text, sort_key),
        )
        _update_heartbeat(conn, saw_alert=False)
        return Receipt(kind="heartbeat", intake_id=None)

    row = conn.execute(
        """
        INSERT INTO intake (manager_id, source_alert_id, raw_text, sort_key, via)
        VALUES (%s, %s, %s, %s, 'webhook')
        ON CONFLICT (manager_id, source_alert_id) DO NOTHING
        RETURNING intake_id
        """,
        (manager_id, source_alert_id, raw_text, sort_key),
    ).fetchone()
    if row is None:
        raise Duplicate()
    intake_id = row[0]
    enqueue(conn, "pipeline", str(intake_id))
    # DEC-207 item 2, as amended in fix round 1: with `PULL_ENABLED=false` an accepted alert is
    # proof the source is alive. The puller no longer moves `source_heartbeat`, and without this
    # stamp the `heartbeat` health check would report a lost source on a stream that is flowing.
    # Same helper, same row, same two columns the puller writes for a pulled alert. With the
    # pull on (the default) nothing is stamped here, exactly as before DEC-207: a pull that died
    # still turns the alarm red beside a webhook that keeps receiving. After the conflict check
    # above, on purpose: a `Duplicate` (409) proves nothing new and stamps nothing.
    if not cfg.PULL_ENABLED:
        _update_heartbeat(conn, saw_alert=True)
    return Receipt(kind="alert", intake_id=intake_id)
