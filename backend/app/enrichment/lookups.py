"""Look up asset criticality, identity privilege and IoC reputation from the inventory files.

Three deterministic, read-only lookups (phase-4 "Hai nửa enrichment" — the inner
half): always run, never model-decided, for every alert including auto-closed
ones. Every dict carries `"status"` in `found | not_found | skipped`
(`not_found` is a security signal, `skipped` is not — phase-4 "Ba trạng thái
kết quả").

`enrichment` may import only `infra` (context pack §4), so these return plain
dicts and never import `app.domain`: `soar/pipeline.py`, which may import both,
turns them into an `AlertContext` (P2-tasks.md planning decision 4).
"""

from __future__ import annotations

import psycopg

#: Worst-wins ordering for `lookup_ioc` (§6.2's `ioc_reputation` vocabulary).
_REPUTATION_RANK = {"malicious": 3, "suspicious": 2, "clean": 1}


def lookup_asset(conn: psycopg.Connection, agent_name: str, origin_host: str | None) -> dict:
    """`agent_name`, then `origin_host` if different (F5: "tra kiểm kê cả hai").

    `present` is G8′'s "asset not in inventory" hard block — distinct from a
    present row whose `criticality` is `unknown` (`inventory-format.md` §1).
    """
    row = _select_asset(conn, agent_name)
    if row is None and origin_host is not None and origin_host != agent_name:
        row = _select_asset(conn, origin_host)
    if row is None:
        return {
            "status": "not_found",
            "present": False,
            "criticality": "unknown",
            "owner": None,
            "role": None,
        }
    _hostname, criticality, owner, role = row
    return {
        "status": "found",
        "present": True,
        "criticality": criticality,
        "owner": owner,
        "role": role,
    }


def _select_asset(conn: psycopg.Connection, hostname: str) -> tuple | None:
    return conn.execute(
        "SELECT hostname, criticality, owner, role FROM assets WHERE hostname = %s AND active",
        (hostname,),
    ).fetchone()


def lookup_identity(conn: psycopg.Connection, username: str | None) -> dict:
    """`None` means the alert carries no such field (phase-4: "alert không có trường để tra")."""
    if username is None:
        return {"status": "skipped", "is_privileged": None}
    row = conn.execute(
        "SELECT is_privileged FROM identities WHERE username = %s AND active",
        (username,),
    ).fetchone()
    if row is None:
        return {"status": "not_found", "is_privileged": None}
    return {"status": "found", "is_privileged": row[0]}


def lookup_ioc(
    conn: psycopg.Connection,
    srcip: str,
    dstip: str,
    *,
    srcip_is_private: bool | None,
    dstip_is_private: bool | None,
) -> dict:
    """Candidates are the non-empty IPs whose private flag is not `True` (C4: a
    private IP is skipped, `''` is nothing to look up). The worst reputation
    among matching, unexpired rows wins (`malicious > suspicious > clean`).

    `reputation` alone carries the full §6.2 `ioc_reputation` vocabulary
    (`malicious | suspicious | clean | not_found | skipped`) so gate step 2 (P3)
    compares strings with no mapping; `status` stays `found | not_found | skipped`
    like the other two lookups.
    """
    candidates = [
        ip
        for ip, is_private in ((srcip, srcip_is_private), (dstip, dstip_is_private))
        if ip and is_private is not True
    ]
    if not candidates:
        return {"status": "skipped", "reputation": "skipped"}

    rows = conn.execute(
        "SELECT value, reputation FROM iocs WHERE value = ANY(%s::text[]) AND active "
        "AND expires_at > now()",
        (candidates,),
    ).fetchall()
    if not rows:
        return {"status": "not_found", "reputation": "not_found"}

    worst = max(rows, key=lambda row: _REPUTATION_RANK[row[1]])
    return {"status": "found", "reputation": worst[1]}
