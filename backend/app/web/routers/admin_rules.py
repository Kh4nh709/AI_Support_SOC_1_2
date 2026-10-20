"""`web/routers/admin_rules.py` — the admin rules API (P5-T10, P11-T06): a screen's worth of
operations over three functions `app.ingest.autoclose` already has and already tests
(`simulate`, `rule_width_report`, `reload_rules`) — this module edits none of
them. The four §6.4 operations `GET|POST|PATCH /api/admin/rules` and
`POST /api/admin/rules/simulate`, for the React rules page (`frontend/`). The Jinja page that
shared these helpers (`GET /admin/rules`, the two-step create and the toggle) was retired in
P11-T19 (spec §8, DEC-205); nothing here renders HTML.

Design note 1 (P5-T10.prompt.md): the preview is the point of the screen, so
it runs `simulate()` — same predicates `evaluate()` does, hard blocks included
— *before* anything is written, and only a second, explicit action writes the
rule. Xem trước dùng đúng vị từ của bộ máy, đã tính cả sáu chặn cứng.

P11-T06 (admin console v1.1 §5.5), both additive: `POST /api/admin/rules/simulate`
also returns `hard_block_tally` (`{matched, blocks: [{code, count}]}` when the
preview closes no cluster, else `null`), from `_hard_block_tally` below; each row of
`GET /api/admin/rules` also carries `width_threshold_pct`.

Design note 3: toggle (and create — no dedicated "rule created" audit event
exists and this card adds none) write `admin.autoclose_rule_toggled` with
`before`/`after` both explicit, then call `reload_rules()` *after* the write
so the 60 s cache never serves a state that no longer exists.

`_hard_block_tally` reuses `autoclose._parse_match`/`_rule_matches`/
`_first_hard_block`/`_asset_ctx`/`_identity_ctx`/`_ioc_ctx` read-only (design
note 2: an admin who cannot tell "my rule matches nothing" from "everything
it matches is hard-blocked" will write a worse rule) — no G8' or whitelist
logic is reimplemented here. Review round 1 (2026-09-29): it now counts a
hard block only for a row the *candidate rule's own conditions* match — a
hard-blocked row the rule would never have matched anyway is not this rule's
business, and the original version counted the whole 30-day window instead.
"""

from __future__ import annotations

import dataclasses
import json
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from psycopg.types.json import Jsonb
from pydantic import BaseModel

from app.audit.events import write_event
from app.infra.auth import Claims
from app.infra.errors import PermanentError
from app.ingest import autoclose
from app.web.deps import Cfg, Conn, require_role

router = APIRouter()

require_admin = require_role("admin")
Admin = Annotated[Claims, Depends(require_admin)]

#: The six G8' hard blocks, in their fixed order (context pack §2) — the tally
#: of an empty preview counts them, so "matches nothing" and "everything is blocked"
#: are never confused (design note 2). Codes come from `autoclose`'s own
#: constants, not spelled out again here, so a renamed code is an
#: `AttributeError` at import — loud — rather than a `KeyError`/500 the
#: first time `_first_hard_block` returns a code this dict doesn't have.
_HARD_BLOCK_ORDER: tuple[tuple[str, str], ...] = (
    (autoclose._HARD_BLOCK_CRITICAL, "Mức độ nghiêm trọng = critical"),
    (autoclose._HARD_BLOCK_NEVER_AGENT, "Agent nằm trong NEVER_AUTOCLOSE_AGENTS"),
    (autoclose._HARD_BLOCK_ASSET_HIGH, "Asset trọng yếu (asset.criticality = high)"),
    (autoclose._HARD_BLOCK_ASSET_ABSENT, "Asset không có trong kiểm kê (inventory)"),
    (autoclose._HARD_BLOCK_IDENTITY, "Danh tính đặc quyền (identity_privileged)"),
    (autoclose._HARD_BLOCK_IOC, "IoC malicious hoặc suspicious"),
)


# ---------------------------------------------------------------------------
# Shared helpers — read/write the DB directly (autoclose.py exposes no
# "list every rule" or "write a rule" function; the matching engine itself,
# `evaluate`/`_parse_match`/the whitelist, stays untouched and unreimplemented)
# ---------------------------------------------------------------------------


def _list_rules(conn: Any) -> list[dict[str, Any]]:
    """Every `autoclose_rules` row (enabled or not — the admin screen shows
    all of them, unlike `load_rules()`, which only ever returns the enabled
    ones), the width report merged in by `autoclose_rule_id`."""
    rows = conn.execute(
        "SELECT autoclose_rule_id, name, enabled, match, reason, created_by, created_at "
        "FROM autoclose_rules ORDER BY created_at ASC, autoclose_rule_id ASC"
    ).fetchall()
    width = {r["autoclose_rule_id"]: r for r in autoclose.rule_width_report(conn)}
    result: list[dict[str, Any]] = []
    for rule_id, name, enabled, match, reason, created_by, created_at in rows:
        rule_id_str = str(rule_id)
        w = width.get(rule_id_str)
        result.append(
            {
                "rule_id": rule_id_str,
                "name": name,
                "enabled": enabled,
                "match": match,
                "match_json": json.dumps(match, ensure_ascii=False),
                "reason": reason,
                "created_by": str(created_by),
                "created_at": created_at,
                "width_pct": w["pct"] if w else None,
            }
        )
    return result


def _create_rule(
    conn: Any, *, name: str, reason: str, match: list[dict[str, Any]], actor_id: str
) -> str:
    """Validate `match` through `simulate()`'s own whitelist + hard-block
    predicates (raises `PermanentError`, writing nothing, on a violation —
    design note 1), INSERT the row, write `admin.autoclose_rule_toggled`
    (`before=False`, `after=True` — no dedicated "rule created" event type
    exists and this card adds none, design note 3), then `reload_rules()`."""
    autoclose.simulate(conn, match)
    rule_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO autoclose_rules (autoclose_rule_id, name, enabled, match, reason, created_by) "
        "VALUES (%s, %s, true, %s, %s, %s)",
        (rule_id, name, Jsonb(match), reason, actor_id),
    )
    write_event(
        conn,
        "admin.autoclose_rule_toggled",
        rule_id,
        "admin",
        actor_id=actor_id,
        payload={"name": name, "before": False, "after": True},
    )
    autoclose.reload_rules(conn)
    return rule_id


def _toggle_rule(conn: Any, *, rule_id: str, enabled: bool, actor_id: str) -> str | None:
    """`UPDATE ... SET enabled` -> `admin.autoclose_rule_toggled` with
    `before`/`after` both explicit (prompts/P5.md:33) -> `reload_rules()`
    after the write (design note 3). Returns the rule's name, or `None` if
    `rule_id` does not exist."""
    row = conn.execute(
        "SELECT name, enabled FROM autoclose_rules WHERE autoclose_rule_id = %s", (rule_id,)
    ).fetchone()
    if row is None:
        return None
    name, before = row
    conn.execute(
        "UPDATE autoclose_rules SET enabled = %s WHERE autoclose_rule_id = %s", (enabled, rule_id)
    )
    write_event(
        conn,
        "admin.autoclose_rule_toggled",
        rule_id,
        "admin",
        actor_id=actor_id,
        payload={"name": name, "before": before, "after": enabled},
    )
    autoclose.reload_rules(conn)
    return name


def _hard_block_tally(
    conn: Any, cfg: Any, match: list[dict[str, Any]]
) -> tuple[int, list[tuple[str, str, int]]]:
    """When a preview matches zero clusters, tell the admin *why*: of the
    alerts THIS rule's own conditions match over the same 30-day window
    `simulate()` reads (hard blocks aside), which G8' hard block accounted
    for each one — sorted, largest first (design note 2). A row the rule
    would never have matched anyway (its conditions fail) is not counted,
    even if it happens to be hard-blocked for some other reason — counting
    the whole window regardless of the rule's own conditions was review
    round 1's finding.

    `match` must already be validated — the caller's own `simulate()` call
    (which raises `PermanentError` first) guarantees `_parse_match` here
    cannot return `None`. Reuses `simulate()`'s own predicates
    (`_parse_match`, `_rule_matches`, `_first_hard_block`) read-only; no G8'
    or whitelist logic is reimplemented here, so this can never diverge from
    the real decision.

    Returns `(matched, tally)`: `matched` is how many alerts the rule's
    conditions match at all (hard-blocked or not) — the "rule khớp N cụm"
    count the screen states before it lists what blocked them.
    """
    conditions = autoclose._parse_match(match)
    candidate = autoclose.Rule(rule_id="(tally)", name="(tally)", reason="", conditions=conditions)
    rows = conn.execute("""
        SELECT alert_id, occurrence_count, severity, agent_name, rule_id, category,
               srcip, dstip, agent_id, alert_user, decoder, dst_port, src_port, rule_level,
               asset_context, identity_context, ioc_context
        FROM alerts
        WHERE duplicate_of IS NULL
          AND status <> 'duplicate'
          AND NOT is_synthetic
          AND received_at >= now() - interval '30 days'
        """).fetchall()
    counts: dict[str, int] = {code: 0 for code, _ in _HARD_BLOCK_ORDER}
    matched = 0
    for (
        _alert_id,
        _occurrence_count,
        severity,
        agent_name,
        rule_id_val,
        category,
        srcip,
        dstip,
        agent_id,
        alert_user,
        decoder,
        dst_port,
        src_port,
        rule_level,
        asset_context,
        identity_context,
        ioc_context,
    ) in rows:
        asset_present, asset_criticality = autoclose._asset_ctx(asset_context)
        identity_privileged = autoclose._identity_ctx(identity_context)
        ioc_reputation = autoclose._ioc_ctx(ioc_context)
        field_values = {
            "rule_id": rule_id_val,
            "category": category,
            "srcip": srcip,
            "dstip": dstip,
            "agent_name": agent_name,
            "agent_id": agent_id,
            "alert_user": alert_user,
            "decoder": decoder,
            "dst_port": dst_port,
            "src_port": src_port,
            "rule_level": rule_level,
            "asset_criticality": asset_criticality,
            "identity_privileged": identity_privileged,
            "ioc_reputation": ioc_reputation,
        }
        if not autoclose._rule_matches(candidate, field_values):
            continue
        matched += 1
        blocked_by = autoclose._first_hard_block(
            severity=severity,
            agent_name=agent_name,
            asset_present=asset_present,
            asset_criticality=asset_criticality,
            identity_privileged=identity_privileged,
            ioc_reputation=ioc_reputation,
            never_autoclose_agents=cfg.NEVER_AUTOCLOSE_AGENTS,
        )
        if blocked_by is not None:
            counts[blocked_by] += 1
    tally = sorted(
        ((code, label, counts[code]) for code, label in _HARD_BLOCK_ORDER),
        key=lambda row: row[2],
        reverse=True,
    )
    return matched, tally


# ---------------------------------------------------------------------------
# §6.4 — the API operations
# ---------------------------------------------------------------------------


class SimulateIn(BaseModel):
    match: list[dict[str, Any]]


class RuleCreateIn(BaseModel):
    name: str
    reason: str
    match: list[dict[str, Any]]


class RuleToggleIn(BaseModel):
    # uuid.UUID, not str: a malformed id is a 422 from Pydantic before this
    # module ever sees it, not a 500 from the SQL layer (review round 1).
    rule_id: uuid.UUID
    enabled: bool


@router.get("/api/admin/rules")
def api_list_rules(conn: Conn, claims: Admin, cfg: Cfg) -> list[dict[str, Any]]:
    # P11-T06: the threshold the 7-day width warning ("⚠ x% > ngưỡng%") is measured
    # against travels with every row, so the UI never hard-codes it. Added here, not in
    # `_list_rules`, whose rows are the table's own.
    threshold = cfg.AUTOCLOSE_RULE_WIDTH_PCT
    return [{**row, "width_threshold_pct": threshold} for row in _list_rules(conn)]


@router.post("/api/admin/rules", status_code=201)
def api_create_rule(conn: Conn, claims: Admin, body: RuleCreateIn) -> dict[str, Any]:
    try:
        rule_id = _create_rule(
            conn, name=body.name, reason=body.reason, match=body.match, actor_id=claims.user_id
        )
    except PermanentError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"rule_id": rule_id, "name": body.name, "enabled": True}


@router.patch("/api/admin/rules")
def api_toggle_rule(conn: Conn, claims: Admin, body: RuleToggleIn) -> dict[str, Any]:
    rule_id = str(body.rule_id)
    name = _toggle_rule(conn, rule_id=rule_id, enabled=body.enabled, actor_id=claims.user_id)
    if name is None:
        raise HTTPException(status_code=404, detail="rule not found")
    return {"rule_id": rule_id, "name": name, "enabled": body.enabled}


@router.post("/api/admin/rules/simulate")
def api_simulate_rule(conn: Conn, claims: Admin, cfg: Cfg, body: SimulateIn) -> dict[str, Any]:
    # `simulate()` validates first (`PermanentError` -> 422), so a rule that fails the
    # whitelist never reaches the tally, which assumes `match` is already valid.
    try:
        stats = autoclose.simulate(conn, body.match)
    except PermanentError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    result: dict[str, Any] = dataclasses.asdict(stats)
    # P11-T06 (§5.5): when the rule closes nothing, say why: the tally as `{code, count}` in the
    # order `_hard_block_tally` returns (largest first). The Vietnamese labels stay in the UI.
    # Otherwise `null`, and nothing computed.
    result["hard_block_tally"] = None
    if stats.clusters == 0:
        matched, tally = _hard_block_tally(conn, cfg, body.match)
        result["hard_block_tally"] = {
            "matched": matched,
            "blocks": [{"code": code, "count": count} for code, _label, count in tally],
        }
    return result
