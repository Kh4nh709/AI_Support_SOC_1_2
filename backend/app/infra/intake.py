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
"""

from __future__ import annotations

import dataclasses
import json
from typing import Literal

import psycopg
from psycopg.types.json import Jsonb

from app.infra.config import Config
from app.infra.jobs import enqueue
from app.infra.puller import _replay_sort_key, _update_heartbeat, is_heartbeat

# "≤ 4 KB" — design note 1b: the excerpt stored for a body that could not even
# be parsed as JSON (so there is no smaller structured thing to store instead).
_REJECTED_BODY_EXCERPT_CHARS = 4096


class PayloadTooLarge(Exception):
    """`body` exceeds `cfg.MAX_PAYLOAD_BYTES` — checked before any parse."""


class Rejected(Exception):
    """`reason` ∈ not_json | not_an_object | id | rule.id — the route names the
    missing field, never an exception message (phase-1 §Xử lý lỗi, G-15)."""

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
    return body.decode("utf-8", errors="replace")[:_REJECTED_BODY_EXCERPT_CHARS]


def _manager_id(alert_obj: dict) -> str:
    """The same derivation as `puller._manager_id`: `manager.name`, or
    `'default'` when absent."""
    manager = alert_obj.get("manager")
    return (manager if isinstance(manager, dict) else {}).get("name") or "default"


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

    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        _insert_rejected(conn, source_ip, "not_json", {"body": _body_excerpt(body)})
        raise Rejected("not_json") from None
    if not isinstance(doc, dict):
        _insert_rejected(conn, source_ip, "not_an_object", {"body": _body_excerpt(body)})
        raise Rejected("not_an_object")

    # Structural, not shape-counting (same rule as `wazuh_parser.parse_wazuh_alert`):
    # a `_source` key present means the alert is `_source`, else the object itself is.
    alert_obj = doc["_source"] if isinstance(doc.get("_source"), dict) else doc
    if not alert_obj.get("id"):
        _insert_rejected(conn, source_ip, "id", doc)
        raise Rejected("id")
    rule = alert_obj.get("rule")
    if not isinstance(rule, dict) or not rule.get("id"):
        _insert_rejected(conn, source_ip, "rule.id", doc)
        raise Rejected("rule.id")

    raw_text = body.decode("utf-8")
    manager_id = _manager_id(alert_obj)
    source_alert_id = alert_obj["id"]
    sort_key = _replay_sort_key(str(alert_obj["timestamp"]))

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
    return Receipt(kind="alert", intake_id=intake_id)
