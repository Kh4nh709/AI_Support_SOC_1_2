"""The bodies n8n pushes to `POST /webhook/soar-notices` (spec 2026-11-16 §2), and the rows they become (SR-T1).

Every function returns a fresh document, so a test may edit what it gets. `review(**over)` is the `block_ip` review of
the spec's example; `kill_process(**over)` the review whose buttons are keep / false positive; `notice(**over)` an
information line. `over` replaces top-level keys; a key set to `MISSING` is removed (an absent field is not a null one).
`edit(doc, "action.type", value)` sets a dotted path or, given `MISSING`, removes it.

`new_id()` and `new_notice_id()` make ids of the contract's alphabets, fresh per call, so a test never meets another's row
in a database that outlives it.
"""

from __future__ import annotations

import copy
import random
from datetime import UTC, datetime, timedelta
from typing import Any

from psycopg.types.json import Jsonb

MISSING = object()

#: The alphabet of a review's 8-character id (spec §2): no `I`, no `O`, no `0`, no `1`.
ID_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_rng = random.SystemRandom()

#: The instant the example bodies are written at: one hour before it is `created_at`.
T0 = datetime(2026, 11, 13, 14, 40, 5, 123000, tzinfo=UTC)


def new_id() -> str:
    return "".join(_rng.choice(ID_ALPHABET) for _ in range(8))


def new_notice_id() -> str:
    return "N" + "".join(_rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(12))


def iso(moment: datetime, offset_hours: int = 7) -> str:
    """`moment` as n8n writes it: with the local offset (+07:00), milliseconds."""
    local = moment.astimezone(UTC) + timedelta(hours=offset_hours)
    return (
        local.strftime("%Y-%m-%dT%H:%M:%S.")
        + f"{local.microsecond // 1000:03d}+{offset_hours:02d}:00"
    )


def review(**over: Any) -> dict[str, Any]:
    """The spec's example: a `block_ip` review, open, with its two buttons."""
    doc: dict[str, Any] = {
        "schema_version": "1.0",
        "event": "created",
        "kind": "review",
        "id": new_id(),
        "sent_at": iso(T0),
        "status": "open",
        "severity": "info",
        "title": "ĐÃ TỰ XỬ LÝ",
        "simulated": False,
        "case": {"id": "~4096", "number": 65},
        "action": {
            "type": "block_ip",
            "text": "Chặn IP 79.79.78.202 trên pfSense",
            "target": "79.79.78.202",
            "via": "pfsense",
            "agent": None,
        },
        "host": "pfSense.home.arpa",
        "agent_id": "003",
        "user": None,
        "src_ip": "79.79.78.202",
        "domain": None,
        "scenario": {"id": "SC03", "name": "Quét cổng từ bên ngoài"},
        "score": 50,
        "note": "Đã chặn 79.79.78.202 trên pfSense, tự gỡ 22:40",
        "created_at": iso(T0 - timedelta(seconds=2)),
        "auto_expire_at": iso(T0 + timedelta(hours=1)),
        "remind_every_minutes": 0,
        "next_remind_at": None,
        "decided_by": None,
        "decided_at": None,
        "result": None,
        "buttons": [
            {"decision": "keep", "label": "✅ Giữ chặn"},
            {"decision": "undo", "label": "↩️ Gỡ chặn IP"},
        ],
    }
    return _apply(doc, over)


def kill_process(**over: Any) -> dict[str, Any]:
    """A review of a killed process: keep or false positive, never undo."""
    doc = review(
        action={
            "type": "kill_process",
            "text": "Kết thúc tiến trình mimikatz.exe trên WIN-DC01",
            "target": "mimikatz.exe",
            "via": "wazuh",
            "agent": "WIN-DC01",
        },
        host="WIN-DC01",
        agent_id="005",
        src_ip=None,
        case={"id": "~8192", "number": 71},
        scenario={"id": "MW03", "name": "Mã độc trên endpoint"},
        score=82,
        buttons=[
            {"decision": "keep", "label": "✅ Giữ (đã kill)"},
            {"decision": "fp", "label": "🚫 Báo nhầm"},
        ],
    )
    return _apply(doc, over)


def notice(**over: Any) -> dict[str, Any]:
    """An information line: `status` info, no buttons, no case, no action."""
    doc: dict[str, Any] = {
        "schema_version": "1.0",
        "event": "created",
        "kind": "notice",
        "id": new_notice_id(),
        "sent_at": iso(T0),
        "status": "info",
        "severity": "warning",
        "title": "SOAR TẠM DỪNG",
        "note": "pfSense không phản hồi, các hành động chặn IP được hoãn",
        "created_at": iso(T0),
        "buttons": [],
    }
    return _apply(doc, over)


def _apply(doc: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    for key, value in over.items():
        if value is MISSING:
            doc.pop(key, None)
        else:
            doc[key] = copy.deepcopy(value)
    return doc


def edit(doc: dict[str, Any], path: str, value: Any = MISSING) -> dict[str, Any]:
    """Set the dotted `path` of `doc` to `value`, or remove it when no value is given; returns `doc`."""
    *parents, leaf = path.split(".")
    node = doc
    for name in parents:
        node = node[name]
    if value is MISSING:
        node.pop(leaf, None)
    else:
        node[leaf] = value
    return doc


# ── rows, written straight into the table (a test of the API does not stand on the webhook) ─────────────────


def insert_row(conn: Any, **over: Any) -> str:
    """One `soar_reviews` row on `conn` (the caller commits); its id. `over` names columns: `buttons` and `raw` take their
    Python value, a timestamp a `datetime`. The defaults are the spec's example (`review()`), flat.
    """
    body = review()
    row: dict[str, Any] = {
        "id": body["id"],
        "kind": "review",
        "status": "open",
        "severity": "info",
        "title": body["title"],
        "simulated": False,
        "case_id": "~4096",
        "case_number": 65,
        "action_type": "block_ip",
        "action_text": body["action"]["text"],
        "action_target": "79.79.78.202",
        "action_via": "pfsense",
        "host": "pfSense.home.arpa",
        "agent_id": "003",
        "src_ip": "79.79.78.202",
        "scenario_id": "SC03",
        "scenario_name": "Quét cổng từ bên ngoài",
        "score": 50,
        "note": body["note"],
        "buttons": body["buttons"],
        "created_at": T0 - timedelta(seconds=2),
        "auto_expire_at": T0 + timedelta(hours=1),
        "last_sent_at": T0,
        "raw": body,
    }
    row.update(over)
    for name in ("buttons", "raw"):
        row[name] = Jsonb(row[name])
    names = list(row)
    conn.execute(
        f"INSERT INTO soar_reviews ({', '.join(names)}) VALUES ({', '.join('%s' for _ in names)})",
        list(row.values()),
    )
    return row["id"]
