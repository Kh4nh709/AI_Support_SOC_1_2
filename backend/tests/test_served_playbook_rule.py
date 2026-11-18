"""DEC-219, the playbook-rule signal (the Director's ruling after the AP-T2 review). PURE: no database.

Gate step 4 evaluates the rule the MODEL cited (`structured_basis.playbook_rule_applied`, `tier1/triage.py::
_make_rule_check`), so what step 4 says about the playbook rule correlates with what the model answered: a
`rule_is_not_false_positive` in `gate_result.warnings` says the model cited a rule whose action is not
`false_positive`, which a model answering `false_positive` would not have done. For a run whose
`gate_result.rag_rule.applied` is true the Tier 1 API must therefore serve step 4 from the SYSTEM facts only:

* `Suggestion.gate.warnings` leaves out every reason the rule check can write (`verdicts.RULE_CHECK_WARNINGS`),
  and keeps any other warning;
* `held_by` (the queue row's and the alert view's) leaves out `fp_policy:playbook_rule`, next to the
  `verifier_disagrees` it already leaves out;
* `analysis.checks` step 4 is `fp_policy_facts` (warn) when a FACT field is in `missing`, else `fp_policy_ok`
  (pass) - never `fp_policy_playbook`; `check_totals` and `highlights` follow.

The stored documents are untouched, and a run the rule did NOT apply to is served exactly as before. The
helpers are `llm.verdicts`' `served_*` family, with the others. The database-backed counterpart (the real queue
statement and the real route) is in `test_analysis_db.py`.
"""

from __future__ import annotations

import ast
import copy
import pathlib

import pytest
from app.llm import verdicts
from app.tier1 import analysis, queue

from tests.test_analysis_view import (
    BASIS,
    NOW,
    RAW,
    STEPS,
    _build,
    _cand,
    _gate,
    _match,
    _rows,
    _run,
)

TP, FP = "true_positive", "false_positive"
RUN_ID = "11111111-1111-1111-1111-111111111111"
ROOT = pathlib.Path(__file__).resolve().parents[2]

APPLIED = {"threshold": 80, "best_pct": 62, "applied": True, "changed": False}
CHANGED = {**APPLIED, "changed": True}
NOT_APPLIED = {"threshold": 80, "best_pct": 91, "applied": False, "changed": False}


def _cites(rule_id):
    return {**RAW, "structured_basis": {**BASIS, "playbook_rule_applied": rule_id}}


def _changed_gate(fact_fields, **more):
    """A model `true_positive` the rule turned into `false_positive`. The model cited an escalate rule (`bf-2`),
    so step 4 wrote `rule_is_not_false_positive` and `playbook_rule` among `missing`; the verifier, sent the model's
    `true_positive`, disagreed with the verdict the run ended with."""
    missing = [*fact_fields, "playbook_rule"]
    gate = _gate(
        proposed_verdict=TP,
        final_verdict=FP,
        rag_rule=CHANGED,
        flagged_by=["step4", "step6"],
        steps={**STEPS, "3r": "changed", "4": "missing", "6": "disagree"},
        missing=missing,
        warnings=["rule_is_not_false_positive"],
        verifier_verdict="needs_review",
        proposer_raw=_cites("bf-2"),
    )
    gate.update(more)
    return gate


def _applied_gate(fact_fields, **more):
    """A model `false_positive` the rule applied to without changing anything. The model cited a false-positive
    rule that holds (`bf-1`): no playbook condition is missing and no rule-check warning was written.
    """
    gate = _gate(
        proposed_verdict=FP,
        final_verdict=FP,
        rag_rule=APPLIED,
        flagged_by=["step4"] if fact_fields else [],
        steps={**STEPS, "3r": "applied", "4": "missing" if fact_fields else "ok", "6": "agree"},
        missing=list(fact_fields),
        warnings=[],
        verifier_verdict=FP,
        proposer_raw=_cites("bf-1"),
    )
    gate.update(more)
    return gate


FACT_CASES = [(), ("severity",), ("asset_criticality", "identity_privileged")]


def _result(action):
    return {**RAW, "suggested_action": action}


def _suggestion(gate, action=FP):
    return queue._suggestion_of(RUN_ID, _result(action), gate, NOW)


def _gate_held(gate):
    """The queue statement's `gate_held` projection of a stored `gate_result` (`queue._QUEUE_SQL`)."""
    return {
        "proposed_verdict": gate.get("proposed_verdict"),
        "forced_by": gate.get("forced_by"),
        "flagged_by": gate.get("flagged_by"),
        "missing": gate.get("missing"),
        "steps": {"6": (gate.get("steps") or {}).get("6")},
        "rag_rule": {"applied": (gate.get("rag_rule") or {}).get("applied")},
    }


# ── the closed set the rule check can write ─────────────────────────────────────────────────────


def _reasons_the_rule_check_returns() -> list[str]:
    """Every string `tier1/triage.py::_make_rule_check`'s inner function returns as the reason of a failed check,
    read from its source: a new reason there must reach `verdicts.RULE_CHECK_WARNINGS` or this fails.
    """
    tree = ast.parse((ROOT / "backend" / "app" / "tier1" / "triage.py").read_text("utf-8"))
    factory = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_make_rule_check"
    )
    found = []
    for node in ast.walk(factory):
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple):
            first, second = node.value.elts
            if isinstance(first, ast.Constant) and first.value is False:
                assert isinstance(second, ast.Constant) and isinstance(second.value, str)
                found.append(second.value)
    return found


def test_the_rule_check_warnings_are_the_six_the_rule_check_can_write():
    assert verdicts.RULE_CHECK_WARNINGS == (
        "no_rule_cited",
        "no_table",
        "table_unreviewed",
        "unknown_rule",
        "rule_does_not_hold",
        "rule_is_not_false_positive",
    )
    assert _reasons_the_rule_check_returns() == list(verdicts.RULE_CHECK_WARNINGS)


# ── gate.warnings ───────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("reason", verdicts.RULE_CHECK_WARNINGS)
@pytest.mark.parametrize("rule", [APPLIED, CHANGED])
def test_for_an_applied_run_no_rule_check_reason_is_served_in_gate_warnings(reason, rule):
    gate = _changed_gate((), rag_rule=rule, warnings=[reason])
    assert _suggestion(gate).gate["warnings"] == []


def test_for_an_applied_run_every_other_warning_stays():
    gate = _changed_gate(
        (), warnings=["rule_is_not_false_positive", "some_other_warning", "no_table"]
    )
    assert _suggestion(gate).gate["warnings"] == ["some_other_warning"]
    only_other = _applied_gate((), warnings=["some_other_warning"])
    assert _suggestion(only_other).gate["warnings"] == ["some_other_warning"]


@pytest.mark.parametrize(
    "rule",
    [NOT_APPLIED, {"threshold": 0, "best_pct": None, "applied": False, "changed": False}, None],
)
def test_a_run_the_rule_did_not_apply_to_serves_its_warnings_exactly_as_stored(rule):
    stored = ["no_rule_cited", "unknown_rule", "rule_is_not_false_positive", "x"]
    gate = _gate(warnings=list(stored))
    if rule is None:
        del gate["rag_rule"]
    else:
        gate["rag_rule"] = rule
    assert _suggestion(gate, TP).gate["warnings"] == stored


@pytest.mark.parametrize("warnings", [None, [], "junk", 7, {"a": 1}])
def test_a_missing_or_garbled_warnings_value_is_served_as_it_always_was(warnings):
    plain = _gate(warnings=warnings)
    assert _suggestion(plain, TP).gate["warnings"] == (warnings or [])
    # an applied run: nothing a list could not be filtered from is served either
    applied = _changed_gate((), warnings=warnings)
    assert _suggestion(applied).gate["warnings"] == []


def test_serving_does_not_change_the_stored_document():
    gate = _changed_gate(("severity",))
    before = copy.deepcopy(gate)
    _suggestion(gate)
    verdicts.served_held_reasons(gate)
    _build(_run(gate=gate))
    assert gate == before


# ── held_by ─────────────────────────────────────────────────────────────────────────────────────


def test_for_an_applied_run_held_by_leaves_out_the_playbook_rule_and_the_verifier():
    gate = _changed_gate(("severity", "asset_criticality"))
    assert verdicts.held_reasons(gate) == [
        "fp_policy:severity",
        "fp_policy:asset_criticality",
        "fp_policy:playbook_rule",
        "verifier_disagrees",
    ]
    assert verdicts.served_held_reasons(gate) == [
        "fp_policy:severity",
        "fp_policy:asset_criticality",
    ]


def test_for_an_applied_run_that_only_failed_the_playbook_rule_held_by_is_empty():
    assert verdicts.served_held_reasons(_changed_gate(())) == []


def test_a_verifier_that_gave_no_usable_answer_is_still_served_for_an_applied_run():
    gate = _applied_gate(
        (), flagged_by=["step6"], steps={**STEPS, "3r": "applied", "4": "ok", "6": "invalid"}
    )
    assert verdicts.served_held_reasons(gate) == ["verifier_invalid"]


@pytest.mark.parametrize("rule", [NOT_APPLIED, None])
def test_a_run_the_rule_did_not_apply_to_keeps_every_held_reason(rule):
    gate = _gate(
        flagged_by=["step4", "step6"],
        missing=["severity", "playbook_rule"],
        steps={**STEPS, "4": "missing", "6": "disagree"},
    )
    if rule is None:
        del gate["rag_rule"]
    else:
        gate["rag_rule"] = rule
    assert verdicts.served_held_reasons(gate) == verdicts.held_reasons(gate)
    assert "fp_policy:playbook_rule" in verdicts.served_held_reasons(gate)


def test_the_queue_rows_projection_is_served_the_same_way():
    gate = _changed_gate(("severity",))
    assert verdicts.served_held_reasons(_gate_held(gate)) == ["fp_policy:severity"]


# ── analysis.checks, check_totals, highlights ───────────────────────────────────────────────────


def _analysis(gate, action=FP):
    run = _run(
        result={**RAW, "suggested_action": action},
        gate=gate,
        matches=[_match(0.62, "a")],
        ranked=[_cand(0.62, "a")],
    )
    return _build(run)


def test_for_an_applied_run_that_only_failed_the_playbook_rule_step_4_passes():
    built = _analysis(_changed_gate(()))
    assert _rows(built)["4"] == {"id": "4", "outcome": "pass", "detail": "fp_policy_ok"}
    assert built["check_totals"] == {"passed": 5, "applicable": 5, "warnings": 0}
    assert not [h for h in built["highlights"] if h["code"].startswith("warning_")]


def test_for_an_applied_run_with_a_fact_missing_step_4_is_the_facts_warning():
    built = _analysis(_changed_gate(("severity",)))
    assert _rows(built)["4"] == {"id": "4", "outcome": "warn", "detail": "fp_policy_facts"}
    assert built["check_totals"] == {"passed": 4, "applicable": 5, "warnings": 1}
    assert "warning_fp_policy_facts" in [h["code"] for h in built["highlights"]]


@pytest.mark.parametrize("fields", FACT_CASES)
@pytest.mark.parametrize("gate_of", [_changed_gate, _applied_gate])
def test_step_4_of_an_applied_run_is_never_the_playbook_code(fields, gate_of):
    built = _analysis(gate_of(fields))
    row = _rows(built)["4"]
    assert row["detail"] == ("fp_policy_facts" if fields else "fp_policy_ok")
    assert row["outcome"] == ("warn" if fields else "pass")
    assert "warning_fp_policy_playbook" not in [h["code"] for h in built["highlights"]]


def test_a_run_the_rule_did_not_apply_to_keeps_the_playbook_code():
    gate = _gate(
        proposed_verdict=FP,
        final_verdict=FP,
        flagged_by=["step4"],
        steps={**STEPS, "4": "missing"},
        missing=["playbook_rule"],
        warnings=["rule_is_not_false_positive"],
    )
    built = _build(_run(result={**RAW, "suggested_action": FP}, gate=gate))
    assert _rows(built)["4"] == {"id": "4", "outcome": "warn", "detail": "fp_policy_playbook"}
    assert "warning_fp_policy_playbook" in [h["code"] for h in built["highlights"]]


@pytest.mark.parametrize("missing", [None, "x", 5, [None, 3]])
def test_an_applied_run_whose_missing_is_garbled_gives_step_4_from_what_can_be_read(missing):
    built = _analysis(_changed_gate((), missing=missing))
    assert _rows(built)["4"]["detail"] == "fp_policy_ok"


# ── the pair: what the model cited must not show ────────────────────────────────────────────────


def _everything_served(gate, action=FP):
    """Everything this ruling touches, for one stored `gate_result`: `gate.warnings`, `held_by` (alert view and
    queue row), and the analysis' checks, totals and highlights."""
    built = _analysis(gate, action)
    return {
        "warnings": _suggestion(gate, action).gate["warnings"],
        "held_by": verdicts.served_held_reasons(gate),
        "queue_held_by": verdicts.served_held_reasons(_gate_held(gate)),
        "checks": built["checks"],
        "check_totals": built["check_totals"],
        "highlights": built["highlights"],
    }


@pytest.mark.parametrize("fields", FACT_CASES)
def test_a_run_the_rule_changed_and_one_it_applied_to_unchanged_are_served_identically(fields):
    """Their stored step-4 playbook outcomes differ (the first cited an escalate rule: `rule_is_not_false_positive`,
    `playbook_rule` in `missing`, step 4 flagged even with no fact missing; the second cited a false-positive rule
    that holds); the API says the same about both."""
    changed, applied = _changed_gate(fields), _applied_gate(fields)
    assert changed["warnings"] != applied["warnings"] and changed["missing"] != applied["missing"]
    assert changed["steps"]["4"] != applied["steps"]["4"] or fields

    got = _everything_served(changed)
    assert got == _everything_served(applied, FP)
    assert got["warnings"] == []
    assert got["held_by"] == got["queue_held_by"] == [f"fp_policy:{f}" for f in fields]


def test_the_whole_analysis_of_the_pair_is_equal_too():
    changed = _analysis(_changed_gate(("severity",)))
    applied = _analysis(_applied_gate(("severity",)))
    assert changed == applied


def test_the_analysis_never_names_the_rule_check_reasons_for_an_applied_run():
    built = _analysis(_changed_gate(("severity",)))
    text = repr(built)
    for reason in verdicts.RULE_CHECK_WARNINGS:
        assert reason not in text
    assert (
        analysis.CHECK_DETAILS.count("fp_policy_playbook") == 1
    )  # the code still exists for the others
