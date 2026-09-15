"""Compute the risk score from enrichment context that ranks a cluster in the Tier-1 queue.

phase-4 P4-3, formula (b) — "severity trội + trần ngữ cảnh"
(docs/phase-4-enrichment.md:134-217): severity picks the base, context can
move the score at most one band via `CONTEXT_CAP`, additive-only (never a
penalty), deterministic, capped at 100. No caller may add a threshold on this
number (E4) — it orders the Tier-1 queue and feeds a display band, nothing
else.

`ASSET` is the DEC-034 re-weighting of phase-4's asset-tier bonus onto the
DEC-004 vocabulary (`high|medium|low|unknown`, no `crown_jewel`/`normal`);
INBOX 2026-09-06 · P2-T10 carries it as the recommended default, kept because
every row of phase-4's worked table survives unchanged (the cap binds).
"""

from __future__ import annotations

from app.domain.alert import AlertContext

RISK_BASE: dict[str, int] = {"critical": 70, "high": 50, "medium": 28, "low": 10}
CONTEXT_CAP = 25
ASSET: dict[str, int] = {"high": 30, "medium": 10, "low": 0, "unknown": 0}
IOC: dict[str, int] = {"malicious": 25, "suspicious": 10, "clean": 0, "not_found": 0, "skipped": 0}


def compute_risk_score(severity: str, ctx: AlertContext, occurrence_count: int) -> tuple[int, dict]:
    """`(score, components)` — `components` is the per-addend breakdown stored
    verbatim as `alerts.risk_score_components` (B4b); `components["base"] +
    components["context_capped"] == score` always."""
    occurrence = 10 if occurrence_count >= 100 else 5 if occurrence_count >= 10 else 0
    identity = 15 if ctx.identity_privileged is True else 0
    asset = ASSET[ctx.asset_criticality]
    ioc = IOC[ctx.ioc_reputation]
    context = asset + identity + ioc + occurrence
    context_capped = min(CONTEXT_CAP, context)
    base = RISK_BASE[severity]
    score = min(100, base + context_capped)
    components = {
        "base": base,
        "asset": asset,
        "identity": identity,
        "ioc": ioc,
        "occurrence": occurrence,
        "context_capped": context_capped,
    }
    return score, components
