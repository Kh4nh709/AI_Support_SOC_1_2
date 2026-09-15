"""Tests for app.soar.risk.compute_risk_score — phase-4 P4-3, formula (b).

Pure and deterministic (no DB): every case here is phase-4's worked table
(docs/phase-4-enrichment.md:134-217), the re-weighted asset tier from DEC-034,
and the four constraints (additive-only, deterministic, capped at 100, no
threshold anywhere reads it).
"""

from __future__ import annotations

from app.domain.alert import AlertContext
from app.soar.risk import ASSET, CONTEXT_CAP, IOC, RISK_BASE, compute_risk_score


def _ctx(**overrides) -> AlertContext:
    fields = {
        "asset_present": True,
        "asset_criticality": "unknown",
        "asset_owner": None,
        "asset_role": None,
        "identity_privileged": None,
        "ioc_reputation": "skipped",
        "lookup_status": {},
    }
    fields.update(overrides)
    return AlertContext(**fields)


_BARE = _ctx()
_FULL = _ctx(
    asset_present=True,
    asset_criticality="high",
    identity_privileged=True,
    ioc_reputation="malicious",
)


# ---------------------------------------------------------------------------
# phase-4's worked table, verbatim (docs/phase-4-enrichment.md:170-206)
# ---------------------------------------------------------------------------


def test_critical_bare_is_70():
    score, _ = compute_risk_score("critical", _BARE, 1)
    assert score == 70


def test_critical_full_context_is_95():
    score, _ = compute_risk_score("critical", _FULL, 1)
    assert score == 95


def test_high_full_context_is_75_and_exceeds_critical_bare():
    score, _ = compute_risk_score("high", _FULL, 1)
    assert score == 75
    assert score > compute_risk_score("critical", _BARE, 1)[0]


def test_medium_full_context_is_53():
    score, _ = compute_risk_score("medium", _FULL, 1)
    assert score == 53


def test_low_full_context_is_35():
    score, _ = compute_risk_score("low", _FULL, 1)
    assert score == 35


def test_low_bare_is_10_not_zero():
    score, _ = compute_risk_score("low", _BARE, 1)
    assert score == 10


# ---------------------------------------------------------------------------
# E3 — not_found and skipped contribute 0 alike (additive-only, no penalty)
# ---------------------------------------------------------------------------


def test_not_found_context_scores_the_same_as_bare():
    not_found = _ctx(ioc_reputation="not_found")
    assert compute_risk_score("critical", not_found, 1) == compute_risk_score("critical", _BARE, 1)


def test_skipped_context_scores_the_same_as_bare():
    skipped = _ctx(ioc_reputation="skipped")
    assert compute_risk_score("critical", skipped, 1) == compute_risk_score("critical", _BARE, 1)


# ---------------------------------------------------------------------------
# CONTEXT_CAP binds — the failing case named by acceptance 3: with
# CONTEXT_CAP = 40, the second number becomes 100 and the third 90.
# ---------------------------------------------------------------------------


def test_context_cap_of_25_is_what_keeps_the_table_exact():
    assert CONTEXT_CAP == 25
    # Demonstrate the failing case named by the card without mutating the
    # module: replicate the formula by hand with CONTEXT_CAP=40.
    base_critical = RISK_BASE["critical"]
    base_high = RISK_BASE["high"]
    context = ASSET["high"] + 15 + IOC["malicious"]  # 30 + 15 + 25 = 70
    assert min(100, base_critical + min(40, context)) == 100
    assert min(100, base_high + min(40, context)) == 90
    # ... which is NOT what the real, shipped CONTEXT_CAP produces:
    assert compute_risk_score("critical", _FULL, 1)[0] == 95
    assert compute_risk_score("high", _FULL, 1)[0] == 75


# ---------------------------------------------------------------------------
# occurrence_count thresholds
# ---------------------------------------------------------------------------


def test_occurrence_under_10_contributes_nothing():
    low_occ = _ctx()
    score, components = compute_risk_score("low", low_occ, 9)
    assert score == 10
    assert components["occurrence"] == 0


def test_occurrence_10_to_99_contributes_5():
    score, components = compute_risk_score("low", _ctx(), 10)
    assert score == 15
    assert components["occurrence"] == 5


def test_occurrence_100_or_more_contributes_10():
    score, components = compute_risk_score("low", _ctx(), 100)
    assert score == 20
    assert components["occurrence"] == 10


# ---------------------------------------------------------------------------
# Cap at 100 — additive components can overflow CONTEXT_CAP, score never
# exceeds 100 (with today's constants the ceiling is 95: RISK_BASE["critical"]
# + CONTEXT_CAP = 70 + 25; a higher occurrence_count cannot push it further
# because context is capped before it is added to base).
# ---------------------------------------------------------------------------


def test_score_is_capped_and_a_bigger_occurrence_count_cannot_push_it_past_the_cap():
    score, _ = compute_risk_score("critical", _FULL, 1000)
    assert score == RISK_BASE["critical"] + CONTEXT_CAP == 95
    assert score <= 100


# ---------------------------------------------------------------------------
# Determinism and the components dict
# ---------------------------------------------------------------------------


def test_same_inputs_always_give_the_same_score():
    a = compute_risk_score("high", _FULL, 42)
    b = compute_risk_score("high", _FULL, 42)
    assert a == b


def test_components_sum_to_the_score():
    score, components = compute_risk_score("high", _FULL, 1)
    assert components["base"] + components["context_capped"] == score


def test_components_dict_carries_every_addend():
    _, components = compute_risk_score("medium", _FULL, 50)
    assert components["base"] == RISK_BASE["medium"]
    assert components["asset"] == ASSET["high"]
    assert components["identity"] == 15
    assert components["ioc"] == IOC["malicious"]
    assert components["occurrence"] == 5
