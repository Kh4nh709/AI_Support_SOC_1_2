"""Apply the G8' hard blocks, then autoclose_rules, to decide whether a cluster auto-closes.

Order, fixed (context pack §2 G8', task card design note 2 — never re-order):
`severity == "critical"` -> `agent_name in NEVER_AUTOCLOSE_AGENTS` -> `asset_criticality
== "high"` -> `not asset_present` -> `identity_privileged is True` -> `ioc_reputation in
("malicious", "suspicious")`. All six run before any rule is read. A blocked alert is
never matched; the sole exception is block 1, where a rule that *would* have matched is
still looked up so `alert.autoclose_blocked_critical` can carry its `rule_id` (phase-3
§Xu ly loi — "tin hieu rule can xem lai"). Blocks 2-6 return silently: no event type
exists for them in context pack §6.1, and inventing one is a contract change.

`evaluate()` is the pipeline's entry point; `simulate()` runs the identical hard-block +
whitelist logic over 30 days of stored clusters, reading `asset_context`/
`identity_context`/`ioc_context` back into the same shape `evaluate()` reads live from an
`AlertContext` (see `_asset_ctx`/`_identity_ctx`/`_ioc_ctx` below) — "same code path" per
design note 5. `load_rules()`/`_cached_rules()` own the fail-open contract: a query that
raises, or a rule whose `match` fails the whitelist, is dropped from the returned list
(A8) — never a matched-with-fewer-conditions rule (that would only widen it).

D8/planning decision 7 supersede phase-3's v1 design: there is no partial, held-back
slice of auto-closed alerts routed through tier 1 as a check on the rules — every
auto-closed alert gets `jobs('triage')`, written by `domain.transitions.open_alert`
(P2-T06) in the same transaction as the INSERT this module does not perform.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import logging
import time
from collections.abc import Mapping, Sequence

import psycopg

from app.audit.events import write_event
from app.domain.alert import Alert, AlertContext
from app.domain.transitions import AutocloseMatch
from app.infra import config
from app.infra.errors import PermanentError

logger = logging.getLogger(__name__)

#: phase-3 AC-C4 (60 s), not a §6.3 Config key (design note 4) — a module constant.
RULE_CACHE_TTL_S = 60

#: field -> allowed operators. Transcribed from phase-3's table plus the three v3
#: internal fields (design note 3). Three things stay out on purpose (design note 3):
#: `risk_score` and any other not-yet-enriched field; the two "is this address in a
#: private range" boolean flags parsed onto `Alert` (an address property, not a
#: security conclusion — a rule that wants a private range writes a CIDR condition
#: instead); and free-text pattern matching as a match operator (a denial-of-service
#: vector on attacker-controlled text). `grep` for the excluded names/operator finds
#: none of them below — that absence is acceptance 6, not a coincidence.
_WHITELIST: Mapping[str, frozenset[str]] = {
    "rule_id": frozenset({"eq", "in"}),
    "category": frozenset({"eq", "in"}),
    "srcip": frozenset({"eq", "in", "cidr"}),
    "dstip": frozenset({"eq", "in", "cidr"}),
    "agent_name": frozenset({"eq", "in", "prefix"}),
    "agent_id": frozenset({"eq", "in", "prefix"}),
    "alert_user": frozenset({"eq", "in"}),
    "decoder": frozenset({"eq", "in"}),
    "dst_port": frozenset({"eq", "in"}),
    "src_port": frozenset({"eq", "in"}),
    "rule_level": frozenset({"eq", "lte"}),
    "asset_criticality": frozenset({"eq", "in"}),
    "identity_privileged": frozenset({"eq"}),
    "ioc_reputation": frozenset({"eq", "in"}),
}

_HARD_BLOCK_NEVER_AGENT = "never_autoclose_agent"
_HARD_BLOCK_CRITICAL = "critical"
_HARD_BLOCK_ASSET_HIGH = "asset_high"
_HARD_BLOCK_ASSET_ABSENT = "asset_not_in_inventory"
_HARD_BLOCK_IDENTITY = "identity_privileged"
_HARD_BLOCK_IOC = "ioc_bad"


@dataclasses.dataclass(frozen=True)
class _Condition:
    field: str
    op: str
    value: object


@dataclasses.dataclass(frozen=True)
class Rule:
    """One loaded `autoclose_rules` row, `match` already parsed and validated
    against `_WHITELIST` — a broken rule is skipped once at load, not per alert
    (design note 4)."""

    rule_id: str
    name: str
    reason: str
    conditions: tuple[_Condition, ...]


@dataclasses.dataclass(frozen=True)
class AutocloseDecision:
    """`blocked_by is None and match is None` means "no rule matched — proceed
    to the queue". `blocked_by` names the hard block that fired; it is what the
    pipeline (P2-T10) logs."""

    blocked_by: str | None
    match: AutocloseMatch | None


@dataclasses.dataclass(frozen=True)
class SimulateStats:
    clusters: int
    alerts: int
    by_severity: dict[str, int]
    by_asset_criticality: dict[str, int]
    samples: list[str]


# `(monotonic_loaded_at, rules)` — module-level, TTL RULE_CACHE_TTL_S. `evaluate()`
# reads it through `_cached_rules()` whenever the caller does not pass `rules=`
# explicitly; `reload_rules()` busts it (P5's admin route calls that on rule
# add/edit/toggle so a change is live immediately rather than waiting the TTL out).
_rule_cache: tuple[float, list[Rule]] | None = None


# ---------------------------------------------------------------------------
# Whitelist parsing — load-time, so a broken rule costs one warning, not one
# warning per alert.
# ---------------------------------------------------------------------------


def _value_ok(field: str, op: str, value: object) -> bool:
    if op == "in":
        return (
            isinstance(value, list) and len(value) > 0 and all(_scalar_ok(field, v) for v in value)
        )
    if op == "cidr":
        if not isinstance(value, str):
            return False
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            return False
        return True
    if op == "prefix":
        return isinstance(value, str)
    if op == "lte":
        return isinstance(value, int) and not isinstance(value, bool)
    # eq
    return _scalar_ok(field, value)


def _scalar_ok(field: str, value: object) -> bool:
    if field in ("dst_port", "src_port", "rule_level"):
        return isinstance(value, int) and not isinstance(value, bool)
    if field == "identity_privileged":
        return isinstance(value, bool)
    return isinstance(value, str)


def _parse_match(raw: object) -> tuple[_Condition, ...] | None:
    """`raw` (the jsonb `match` column, already decoded by psycopg) -> a tuple of
    validated conditions, or `None` if it names a field/operator outside
    `_WHITELIST`, is not a list of `{field, op, value}` objects, or a value's
    shape does not fit its operator. `None` here means "skip the whole rule" —
    never "drop the bad condition and keep the rest", which would widen it
    (phase-3 §Xu ly loi)."""
    if not isinstance(raw, list):
        return None
    conditions: list[_Condition] = []
    for item in raw:
        if not isinstance(item, dict) or set(item.keys()) != {"field", "op", "value"}:
            return None
        field, op, value = item["field"], item["op"], item["value"]
        if not isinstance(field, str) or field not in _WHITELIST:
            return None
        if not isinstance(op, str) or op not in _WHITELIST[field]:
            return None
        if not _value_ok(field, op, value):
            return None
        conditions.append(_Condition(field=field, op=op, value=value))
    return tuple(conditions)


# ---------------------------------------------------------------------------
# Matching — shared by evaluate() (live) and simulate() (30-day replay).
# ---------------------------------------------------------------------------


def _condition_matches(cond: _Condition, field_values: Mapping[str, object]) -> bool:
    actual = field_values.get(cond.field)
    if cond.op == "eq":
        return actual == cond.value
    if cond.op == "in":
        return actual in cond.value
    if cond.op == "cidr":
        if not actual:
            return False
        try:
            return ipaddress.ip_address(actual) in ipaddress.ip_network(cond.value, strict=False)
        except ValueError:
            return False
    if cond.op == "prefix":
        return isinstance(actual, str) and actual.startswith(cond.value)
    if cond.op == "lte":
        return actual is not None and actual <= cond.value
    return False  # unreachable: _parse_match only ever emits whitelisted ops


def _rule_matches(rule: Rule, field_values: Mapping[str, object]) -> bool:
    """Every condition true (AND) — an empty `conditions` tuple (`match = []`)
    is vacuously true, the match-everything rule G8' is tested with."""
    return all(_condition_matches(c, field_values) for c in rule.conditions)


def _first_match(rules: Sequence[Rule], field_values: Mapping[str, object]) -> Rule | None:
    """First rule in `rules` order that matches — `rules` is assumed already
    sorted `created_at ASC, autoclose_rule_id ASC` (A3); this function does not
    sort, so passing an unsorted list is the caller's bug, not this one's."""
    for rule in rules:
        if _rule_matches(rule, field_values):
            return rule
    return None


def _alert_field_values(alert: Alert, ctx: AlertContext) -> dict[str, object]:
    return {
        "rule_id": alert.rule_id,
        "category": alert.category,
        "srcip": alert.srcip,
        "dstip": alert.dstip,
        "agent_name": alert.agent_name,
        "agent_id": alert.agent_id,
        "alert_user": alert.alert_user,
        "decoder": alert.decoder,
        "dst_port": alert.dst_port,
        "src_port": alert.src_port,
        "rule_level": alert.rule_level,
        "asset_criticality": ctx.asset_criticality,
        "identity_privileged": ctx.identity_privileged,
        "ioc_reputation": ctx.ioc_reputation,
    }


def _first_hard_block(
    *,
    severity: str,
    agent_name: str,
    asset_present: bool,
    asset_criticality: str,
    identity_privileged: bool | None,
    ioc_reputation: str,
    never_autoclose_agents: Sequence[str],
) -> str | None:
    """The six G8' checks, in the fixed order, before any rule is read."""
    if severity == "critical":
        return _HARD_BLOCK_CRITICAL
    if agent_name in never_autoclose_agents:
        return _HARD_BLOCK_NEVER_AGENT
    if asset_criticality == "high":
        return _HARD_BLOCK_ASSET_HIGH
    if not asset_present:
        return _HARD_BLOCK_ASSET_ABSENT
    if identity_privileged is True:
        return _HARD_BLOCK_IDENTITY
    if ioc_reputation in ("malicious", "suspicious"):
        return _HARD_BLOCK_IOC
    return None


# ---------------------------------------------------------------------------
# Loading and caching
# ---------------------------------------------------------------------------


def load_rules(conn: psycopg.Connection) -> list[Rule]:
    """`SELECT ... FROM autoclose_rules WHERE enabled ORDER BY created_at ASC,
    autoclose_rule_id ASC` (the index `ix_autoclose_rules_enabled` is exactly
    this order) -> parsed `Rule`s, a rule whose `match` fails the whitelist
    dropped with a warning log naming it. Does not itself catch a query-level
    failure (a dead connection, an unmigrated database) — `_cached_rules()` and
    `reload_rules()` own that half of fail-open (A8); this function's contract
    is per-rule, not per-query."""
    rows = conn.execute("""
        SELECT autoclose_rule_id, name, match, reason
        FROM autoclose_rules
        WHERE enabled
        ORDER BY created_at ASC, autoclose_rule_id ASC
        """).fetchall()
    rules: list[Rule] = []
    for rule_id, name, match, reason in rows:
        conditions = _parse_match(match)
        if conditions is None:
            logger.warning(
                "autoclose: rule %s (%r) skipped whole — match outside the whitelist: %r",
                rule_id,
                name,
                match,
            )
            continue
        rules.append(Rule(rule_id=str(rule_id), name=name, reason=reason, conditions=conditions))
    return rules


def reload_rules(conn: psycopg.Connection) -> list[Rule]:
    """Force a fresh load into the cache, bypassing and resetting the TTL.
    P5's admin route calls this after a rule is added/edited/toggled so the
    change is live immediately rather than waiting up to `RULE_CACHE_TTL_S`
    (AC-C4's documented limit otherwise)."""
    global _rule_cache
    try:
        rules = load_rules(conn)
    except Exception:
        logger.exception("autoclose: reload_rules failed — fail-open, no rule is active")
        rules = []
    _rule_cache = (time.monotonic(), rules)
    return rules


def _cached_rules(conn: psycopg.Connection) -> list[Rule]:
    if _rule_cache is not None and time.monotonic() - _rule_cache[0] < RULE_CACHE_TTL_S:
        return _rule_cache[1]
    return reload_rules(conn)


# ---------------------------------------------------------------------------
# evaluate — the pipeline's entry point
# ---------------------------------------------------------------------------


def evaluate(
    conn: psycopg.Connection,
    alert: Alert,
    ctx: AlertContext,
    *,
    rules: Sequence[Rule] | None = None,
) -> AutocloseDecision:
    """The decision "does this cluster auto-close by rule?" `rules` defaults to
    the 60 s cache; tests (and the pipeline, which loads rules before taking
    its advisory lock — P2-T10) pass an explicit list."""
    cfg = config.load()
    blocked_by = _first_hard_block(
        severity=alert.severity,
        agent_name=alert.agent_name,
        asset_present=ctx.asset_present,
        asset_criticality=ctx.asset_criticality,
        identity_privileged=ctx.identity_privileged,
        ioc_reputation=ctx.ioc_reputation,
        never_autoclose_agents=cfg.NEVER_AUTOCLOSE_AGENTS,
    )

    if blocked_by == _HARD_BLOCK_CRITICAL:
        active_rules = rules if rules is not None else _cached_rules(conn)
        would_have_matched = _first_match(active_rules, _alert_field_values(alert, ctx))
        if would_have_matched is not None:
            write_event(
                conn,
                "alert.autoclose_blocked_critical",
                alert.alert_id,
                "system",
                payload={"rule_id": would_have_matched.rule_id},
            )
        return AutocloseDecision(blocked_by=_HARD_BLOCK_CRITICAL, match=None)

    if blocked_by is not None:
        # Blocks 2-6: return silently — no audit event type exists for these in
        # context pack §6.1, and inventing one is a contract change (design note 2).
        return AutocloseDecision(blocked_by=blocked_by, match=None)

    active_rules = rules if rules is not None else _cached_rules(conn)
    matched = _first_match(active_rules, _alert_field_values(alert, ctx))
    if matched is None:
        return AutocloseDecision(blocked_by=None, match=None)
    return AutocloseDecision(
        blocked_by=None,
        match=AutocloseMatch(rule_id=matched.rule_id, name=matched.name, reason=matched.reason),
    )


# ---------------------------------------------------------------------------
# simulate — the same decision, replayed over 30 days of stored clusters
# ---------------------------------------------------------------------------

_SIMULATE_MAX_IDS_KEPT = 20


def _asset_ctx(raw: Mapping[str, object] | None) -> tuple[bool, str]:
    raw = raw or {}
    return bool(raw.get("present", False)), str(raw.get("criticality", "unknown"))


def _identity_ctx(raw: Mapping[str, object] | None) -> bool | None:
    raw = raw or {}
    return raw.get("privileged")


def _ioc_ctx(raw: Mapping[str, object] | None) -> str:
    raw = raw or {}
    return str(raw.get("reputation", "not_found"))


def simulate(conn: psycopg.Connection, match: list[dict]) -> SimulateStats:
    """Apply `match` (one candidate rule's conditions, not a stored rule id) to
    every cluster received in the last 30 days — hard blocks included, each
    alert's stored `asset_context`/`identity_context`/`ioc_context` jsonb
    rebuilt into the same field values `evaluate()` reads from a live
    `AlertContext`. Same predicates as `evaluate()` (`_first_hard_block`,
    `_condition_matches`): a rule this says would close 40 clusters must close
    exactly those 40 once enabled (design note 5).

    `asset_context`/`identity_context`/`ioc_context`'s key shape
    (`{"present","criticality","owner","role"}` / `{"privileged"}` /
    `{"reputation"}`) is this module's own reading of the three columns split
    out of `AlertContext`'s seven fields — no card pins it yet (P2-T06/T08 are
    still `todo`); flagged in the task report for the Reviewer to re-check
    once those land.
    """
    conditions = _parse_match(match)
    if conditions is None:
        raise PermanentError(f"simulate: match is outside the whitelist or malformed: {match!r}")
    candidate = Rule(rule_id="(simulate)", name="(simulate)", reason="", conditions=conditions)
    cfg = config.load()

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

    clusters = 0
    alerts_total = 0
    by_severity: dict[str, int] = {}
    by_asset_criticality: dict[str, int] = {}
    kept_ids: list[str] = []

    for (
        alert_id,
        occurrence_count,
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
        asset_present, asset_criticality = _asset_ctx(asset_context)
        identity_privileged = _identity_ctx(identity_context)
        ioc_reputation = _ioc_ctx(ioc_context)

        blocked_by = _first_hard_block(
            severity=severity,
            agent_name=agent_name,
            asset_present=asset_present,
            asset_criticality=asset_criticality,
            identity_privileged=identity_privileged,
            ioc_reputation=ioc_reputation,
            never_autoclose_agents=cfg.NEVER_AUTOCLOSE_AGENTS,
        )
        if blocked_by is not None:
            continue

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
        if not _rule_matches(candidate, field_values):
            continue

        clusters += 1
        alerts_total += occurrence_count
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_asset_criticality[asset_criticality] = by_asset_criticality.get(asset_criticality, 0) + 1
        if len(kept_ids) < _SIMULATE_MAX_IDS_KEPT:
            kept_ids.append(alert_id)

    return SimulateStats(
        clusters=clusters,
        alerts=alerts_total,
        by_severity=by_severity,
        by_asset_criticality=by_asset_criticality,
        samples=kept_ids,
    )


# ---------------------------------------------------------------------------
# Layer 2 — the width report
# ---------------------------------------------------------------------------


def rule_width_report(conn: psycopg.Connection, days: int = 7) -> list[dict]:
    """Rows of `autoclose_rules` whose share of the window's alert volume
    exceeds `Config.AUTOCLOSE_RULE_WIDTH_PCT` — **sum** `occurrence_count`,
    never count rows (M4: after clustering, a rule that closed 5,000 alerts is
    one row)."""
    cfg = config.load()
    rows = conn.execute(
        """
        WITH total AS (
            SELECT count(*)::numeric AS n
            FROM alerts
            WHERE received_at >= now() - (%(days)s * interval '1 day')
        )
        SELECT autoclose_rule_id,
               sum(occurrence_count) AS alerts_closed,
               round(100.0 * sum(occurrence_count) / NULLIF(total.n, 0), 1) AS pct
        FROM alerts, total
        WHERE status = 'auto_closed'
          AND autoclose_rule_id IS NOT NULL
          AND received_at >= now() - (%(days)s * interval '1 day')
        GROUP BY autoclose_rule_id, total.n
        HAVING sum(occurrence_count) > (%(pct)s / 100.0) * total.n
        """,
        {"days": days, "pct": cfg.AUTOCLOSE_RULE_WIDTH_PCT},
    ).fetchall()
    return [
        {"autoclose_rule_id": str(rule_id), "alerts_closed": alerts_closed, "pct": float(pct)}
        for rule_id, alerts_closed, pct in rows
    ]
