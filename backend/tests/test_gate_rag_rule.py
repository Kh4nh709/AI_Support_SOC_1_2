"""`security.gate.step3r_rag_rule` - the two-sided RAG rule (DEC-219 as changed by DEC-225, RR-T3). PURE: no
database, no socket, `security` imports only `infra`, so the gate is handed plain values (`best_pct | None`, the
`entry_side` of the single top knowledge item, `threshold`, `basis`) and everything else is the model's answer and
crafted facts.

The top item's side is `incident` (its conclusion is `confirmed_incident`) or `benign` (the four closed
conclusions). With `threshold > 0`, a number and a side the rule APPLIES unless the side is `benign` and the number
is below the threshold:

| top item | percentage >= threshold | percentage < threshold (also under the floor) |
|----------|-------------------------|-----------------------------------------------|
| incident | `true_positive`         | `false_positive`                              |
| benign   | `false_positive`        | not applied: the model's answer stands        |

Equal applies (80 at threshold 80). When the rule applies, ①'s verdict is the rule's (`rule_verdict`); `changed` is
"applied and the rule's verdict differs from the model's". It is the one step that can change the verdict
(DEC-217: the checks of steps 2, 3, 4 and 6 only flag). It is NOT a gate force: `forced` stays false and `forced_by`
stays empty on every new run, whatever the rule did; `steps["3r"]` and `gate_result.rag_rule` are its record, and
`proposed_verdict` keeps the model's own answer.
"""

from __future__ import annotations

import copy

import pytest
from app.security import gate, output_guard, wrap

from tests.fakes.llm import TRIAGE_V4_FALSE_POSITIVE, TRIAGE_V4_TRUE_POSITIVE

NONCE = wrap.new_nonce()
TP, FP = "true_positive", "false_positive"
INCIDENT, BENIGN = "incident", "benign"
SWITCH_OFF = {
    "threshold": 0,
    "best_pct": None,
    "applied": False,
    "changed": False,
    "entry_side": None,
    "rule_verdict": None,
    "basis": None,
}


def _blocks(**text_by_source: str) -> dict[str, wrap.Block]:
    return {
        source: wrap.untrusted_block(text, source, nonce=NONCE)
        for source, text in text_by_source.items()
    }


def _facts_from(structured_basis: dict, **overrides) -> dict:
    facts = {
        "severity": structured_basis["severity"],
        "ioc_reputation": structured_basis["ioc_reputation"],
        "asset_criticality": structured_basis["asset_criticality"],
        "identity_privileged": structured_basis["identity_privileged"],
        "occurrence_count": structured_basis["occurrence_count"],
    }
    facts.update(overrides)
    return facts


def _tp_blocks() -> dict[str, wrap.Block]:
    reason = TRIAGE_V4_TRUE_POSITIVE["reasons"][0]
    return _blocks(**{reason["source"]: reason["quote"] + " - trailing log context"})


def _fp_blocks() -> dict[str, wrap.Block]:
    reason = TRIAGE_V4_FALSE_POSITIVE["reasons"][0]
    return _blocks(**{reason["source"]: reason["quote"] + " (routine)"})


def _rule_check_holds(_rule_id):
    return True, None


def _rule_check_unknown_rule(rule_id):
    return (False, "no_rule_cited") if rule_id is None else (False, "unknown_rule")


def _no_findings(_blocks):
    return []


def _model_answer(answer: str) -> tuple[dict, dict, dict]:
    """`(parsed, facts, blocks)` of one model answer whose steps 2 and 3 pass, so only the rule and step 4
    can say anything about it."""
    if answer == TP:
        parsed = TRIAGE_V4_TRUE_POSITIVE
        return parsed, _facts_from(parsed["structured_basis"]), _tp_blocks()
    parsed = TRIAGE_V4_FALSE_POSITIVE
    return parsed, _facts_from(parsed["structured_basis"]), _fp_blocks()


def _through_step3r(
    answer: str,
    best_pct: int | None,
    entry_side: str | None,
    threshold: int,
    basis: str | None = "match",
) -> gate.GateState:
    parsed, facts, blocks = _model_answer(answer)
    state = gate.start(parsed, facts, blocks, repaired=False)
    gate.step2_basis(state)
    gate.step3_quotes(state)
    gate.step3r_rag_rule(state, best_pct, entry_side, threshold, basis)
    return state


def _document(state: gate.GateState) -> dict:
    return gate.gate_result(state, prompt_version="v", playbook_used_effective=None)


# ---------------------------------------------------------------------------
# the truth table - the Owner's rule of 18/11 (DEC-225)
# ---------------------------------------------------------------------------

#: (threshold, best_pct, the top item's side, basis, the model's answer)
#:   -> (applied, changed, steps["3r"], rule_verdict, the verdict after the rule).
#: Written out, not computed: the table is the specification.
TRUTH_TABLE = [
    # the switch is off: nothing applies, whatever the item
    (0, None, None, None, TP, False, False, "n/a", None, TP),
    (0, 62, INCIDENT, "match", TP, False, False, "n/a", None, TP),
    (0, 62, INCIDENT, "match", FP, False, False, "n/a", None, FP),
    (0, 95, BENIGN, "match", TP, False, False, "n/a", None, TP),
    (0, 95, BENIGN, "match", FP, False, False, "n/a", None, FP),
    # no number, or no side (the top entry's row or conclusion cannot be read): the model's verdict stays
    (80, None, INCIDENT, None, TP, False, False, "n/a", None, TP),
    (80, None, BENIGN, None, FP, False, False, "n/a", None, FP),
    (80, 90, None, "match", TP, False, False, "n/a", None, TP),
    (80, 90, None, "match", FP, False, False, "n/a", None, FP),
    (80, 40, None, "below_floor", TP, False, False, "n/a", None, TP),
    (80, None, None, None, TP, False, False, "n/a", None, TP),
    (80, None, None, None, FP, False, False, "n/a", None, FP),
    # an incident at or over the threshold: true_positive (equal applies)
    (80, 85, INCIDENT, "match", TP, True, False, "applied", TP, TP),
    (80, 85, INCIDENT, "match", FP, True, True, "changed", TP, TP),
    (80, 80, INCIDENT, "match", TP, True, False, "applied", TP, TP),
    (80, 80, INCIDENT, "match", FP, True, True, "changed", TP, TP),
    (80, 100, INCIDENT, "match", FP, True, True, "changed", TP, TP),
    # an incident under the threshold: false_positive
    (80, 79, INCIDENT, "match", TP, True, True, "changed", FP, FP),
    (80, 79, INCIDENT, "match", FP, True, False, "applied", FP, FP),
    (80, 62, INCIDENT, "match", TP, True, True, "changed", FP, FP),
    (80, 62, INCIDENT, "match", FP, True, False, "applied", FP, FP),
    (80, 0, INCIDENT, "match", TP, True, True, "changed", FP, FP),  # 0 % is a number
    # an incident under the 50 % floor (no kept match; the candidate the rerank scored): also false_positive
    (80, 47, INCIDENT, "below_floor", TP, True, True, "changed", FP, FP),
    (80, 47, INCIDENT, "below_floor", FP, True, False, "applied", FP, FP),
    (80, 0, INCIDENT, "below_floor", TP, True, True, "changed", FP, FP),
    # a benign item at or over the threshold: false_positive (equal applies)
    (80, 89, BENIGN, "match", TP, True, True, "changed", FP, FP),
    (80, 89, BENIGN, "match", FP, True, False, "applied", FP, FP),
    (80, 80, BENIGN, "match", TP, True, True, "changed", FP, FP),
    (80, 80, BENIGN, "match", FP, True, False, "applied", FP, FP),
    (80, 100, BENIGN, "match", TP, True, True, "changed", FP, FP),
    # a benign item under the threshold - also under the floor - is NOT applied: the model's answer stands
    (80, 79, BENIGN, "match", TP, False, False, "n/a", None, TP),
    (80, 79, BENIGN, "match", FP, False, False, "n/a", None, FP),
    (80, 62, BENIGN, "match", TP, False, False, "n/a", None, TP),
    (80, 47, BENIGN, "below_floor", TP, False, False, "n/a", None, TP),
    (80, 47, BENIGN, "below_floor", FP, False, False, "n/a", None, FP),
    (80, 0, BENIGN, "match", TP, False, False, "n/a", None, TP),
    # the ends of the range
    (1, 0, INCIDENT, "match", TP, True, True, "changed", FP, FP),
    (1, 1, INCIDENT, "match", FP, True, True, "changed", TP, TP),
    (1, 0, BENIGN, "match", TP, False, False, "n/a", None, TP),
    (1, 1, BENIGN, "match", TP, True, True, "changed", FP, FP),
    (100, 99, INCIDENT, "match", TP, True, True, "changed", FP, FP),
    (100, 100, INCIDENT, "match", FP, True, True, "changed", TP, TP),
    (100, 99, BENIGN, "match", TP, False, False, "n/a", None, TP),
    (100, 100, BENIGN, "match", TP, True, True, "changed", FP, FP),
]

_PARAMS = "threshold, best_pct, side, basis, answer, applied, changed, step, rule_verdict, final"


@pytest.mark.parametrize(_PARAMS, TRUTH_TABLE)
def test_the_truth_table(
    threshold, best_pct, side, basis, answer, applied, changed, step, rule_verdict, final
):
    state = _through_step3r(answer, best_pct, side, threshold, basis)

    assert state.steps["3r"] == step
    assert state.verdict == final
    assert state.proposed_verdict == answer  # the model's own answer is kept beside it
    doc = _document(state)
    assert doc["rag_rule"] == {
        "threshold": threshold,
        "best_pct": best_pct,
        "applied": applied,
        "changed": changed,
        "entry_side": side,
        "rule_verdict": rule_verdict,
        "basis": basis,
    }
    assert (doc["proposed_verdict"], doc["final_verdict"]) == (answer, final)
    # the verdicts differ exactly when the rule changed it, and that is recorded by `rag_rule`, not by a force
    assert (doc["proposed_verdict"] != doc["final_verdict"]) is changed
    assert doc["forced"] is False and doc["forced_by"] == []  # in every case, as since DEC-217
    assert doc["flagged_by"] == []  # a rule is not a failed check: it flags nothing
    assert doc["version"] == 2


@pytest.mark.parametrize(_PARAMS, TRUTH_TABLE)
def test_step7_carries_the_verdict_after_the_rule_and_the_models_reasons(
    threshold, best_pct, side, basis, answer, applied, changed, step, rule_verdict, final
):
    state = _through_step3r(answer, best_pct, side, threshold, basis)
    parsed = _model_answer(answer)[0]

    result = gate.step7_output_guard(state)

    assert result["suggested_action"] == final
    assert result["reasons"] == parsed["reasons"]  # step 3's survivors: the model's, changed or not
    assert result["confidence"] == parsed["confidence"]  # the model's confidence, never rewritten
    assert result["structured_basis"] == parsed["structured_basis"]
    assert state.steps["7"] == "ok"


def test_an_incident_at_the_threshold_turns_a_model_false_positive_into_true_positive():
    """The new direction (RR-T3): the knowledge says incident with 85 %, the model said false_positive."""
    state = _through_step3r(FP, 85, INCIDENT, 80)

    assert state.verdict == TP and state.proposed_verdict == FP
    assert state.steps["3r"] == "changed"
    assert state.rag_rule["rule_verdict"] == TP and state.rag_rule["changed"] is True


def test_the_record_carries_what_the_rule_compared():
    state = _through_step3r(TP, 62, INCIDENT, 80, "below_floor")

    assert state.rag_rule == {
        "threshold": 80,
        "best_pct": 62,
        "applied": True,
        "changed": True,
        "entry_side": INCIDENT,
        "rule_verdict": FP,
        "basis": "below_floor",
    }
    assert not hasattr(state, "forced_by")  # nothing is forced: the gate state has no such list


@pytest.mark.parametrize("side", ["other", "", "Incident", 1, True])
def test_a_side_that_is_not_one_of_the_two_is_no_side(side):
    state = _through_step3r(TP, 90, side, 80)

    assert state.steps["3r"] == "n/a" and state.verdict == TP
    assert state.rag_rule["entry_side"] is None and state.rag_rule["applied"] is False


@pytest.mark.parametrize("basis", ["other", "", "Match", 1, True])
def test_a_basis_that_is_not_one_of_the_two_is_recorded_as_null(basis):
    state = _through_step3r(TP, 90, INCIDENT, 80, basis)

    assert state.rag_rule["basis"] is None
    assert state.rag_rule["applied"] is True  # the basis is a record, the rule does not read it


@pytest.mark.parametrize("pct", [True, False, 62.0, "62", float("nan")])
def test_a_percentage_that_is_not_an_integer_is_no_number(pct):
    state = _through_step3r(TP, pct, INCIDENT, 80)

    assert state.steps["3r"] == "n/a" and state.verdict == TP
    assert state.rag_rule["best_pct"] is None and state.rag_rule["applied"] is False


def test_the_rule_does_not_change_the_reasons_that_leave_the_gate():
    good = TRIAGE_V4_TRUE_POSITIVE["reasons"][0]
    bad = {"claim": "fabricated", "quote": "nowhere in the log", "source": "rule_description"}
    parsed = dict(TRIAGE_V4_TRUE_POSITIVE, reasons=[good, bad])
    facts = _facts_from(parsed["structured_basis"])
    state = gate.start(parsed, facts, _tp_blocks(), repaired=False)
    gate.step2_basis(state)
    gate.step3_quotes(state)

    gate.step3r_rag_rule(state, 62, INCIDENT, 80, "match")
    result = gate.step7_output_guard(state)

    assert state.verdict == FP
    assert result["reasons"] == [good]  # the model's survivors, not touched by the rule
    assert state.dropped_reasons == [{"index": 1, "why": "unknown_source"}]


def test_calling_the_step_twice_gives_the_same_state():
    """The rule reads the model's own answer, not the verdict it has so far: a second call changes nothing."""
    state = _through_step3r(TP, 62, INCIDENT, 80)
    before = (state.verdict, dict(state.rag_rule), state.steps["3r"])

    gate.step3r_rag_rule(state, 62, INCIDENT, 80, "match")

    assert (state.verdict, state.rag_rule, state.steps["3r"]) == before
    assert state.steps["3r"] == "changed" and state.verdict == FP
    assert _document(state)["proposed_verdict"] == TP

    flipped = _through_step3r(FP, 90, INCIDENT, 80)
    gate.step3r_rag_rule(flipped, 90, INCIDENT, 80, "match")
    assert flipped.steps["3r"] == "changed" and flipped.verdict == TP
    assert _document(flipped)["proposed_verdict"] == FP


# ---------------------------------------------------------------------------
# the step's place - after step 3, before step 4
# ---------------------------------------------------------------------------


def test_run_steps_1_to_5_runs_the_rule_after_step_3_and_before_step_4():
    parsed, facts, blocks = _model_answer(TP)

    state = gate.run_steps_1_to_5(
        parsed,
        facts,
        blocks,
        repaired=False,
        rule_check=_rule_check_holds,
        scan=_no_findings,
        rag_best_pct=62,
        rag_entry_side=INCIDENT,
        rag_threshold=80,
        rag_basis="match",
    )

    assert list(state.steps) == ["1", "2", "3", "3r", "4", "5"]
    assert state.steps["3r"] == "changed"
    assert state.verdict == FP


def test_run_steps_1_to_5_for_a_model_false_positive_the_rule_turns_into_true_positive():
    parsed, facts, blocks = _model_answer(FP)

    state = gate.run_steps_1_to_5(
        parsed,
        facts,
        blocks,
        repaired=False,
        rule_check=_rule_check_unknown_rule,
        scan=_no_findings,
        rag_best_pct=85,
        rag_entry_side=INCIDENT,
        rag_threshold=80,
        rag_basis="match",
    )

    assert list(state.steps) == ["1", "2", "3", "3r", "4", "5"]
    assert state.steps["3r"] == "changed" and state.verdict == TP and state.proposed_verdict == FP
    # step 4 evaluates the verdict it finds: a true_positive is `n/a`, as for any other
    assert state.steps["4"] == "n/a" and state.missing == [] and state.flagged_by == []


def test_run_steps_1_to_5_without_the_rule_is_what_it_was_plus_an_n_a_step():
    parsed, facts, blocks = _model_answer(TP)

    state = gate.run_steps_1_to_5(
        parsed,
        facts,
        blocks,
        repaired=False,
        rule_check=_rule_check_holds,
        scan=_no_findings,
    )

    assert list(state.steps) == ["1", "2", "3", "3r", "4", "5"]
    assert state.steps["3r"] == "n/a"
    assert state.verdict == TP
    assert state.rag_rule == SWITCH_OFF


def test_the_restricted_mode_runs_the_rule_too_after_step_3():
    """B3's re-run (`gate_mode="steps_1_3"`): start, step 2, step 3, then the rule, then step 7."""
    parsed, facts, blocks = _model_answer(TP)
    state = gate.start(parsed, facts, blocks, repaired=False)
    gate.step2_basis(state)
    gate.step3_quotes(state)
    gate.step3r_rag_rule(state, 62, INCIDENT, 80, "match")
    result = gate.step7_output_guard(state)

    assert list(state.steps) == ["1", "2", "3", "3r", "7"]
    assert result["suggested_action"] == FP
    doc = _document(state)
    assert (doc["proposed_verdict"], doc["final_verdict"]) == (TP, FP)
    assert doc["forced"] is False and doc["forced_by"] == []


# ---------------------------------------------------------------------------
# step 4 evaluates the verdict it finds
# ---------------------------------------------------------------------------


def test_step4_evaluates_a_false_positive_the_rule_produced_like_one_the_model_gave():
    """The model said `true_positive` on an alert with a critical severity, an unknown asset and a rule that is
    not in the table; the rule makes it `false_positive`, and step 4 then raises the policy warnings it raises
    for the model's own `false_positive`."""
    parsed, facts, blocks = _model_answer(TP)
    state = gate.start(parsed, facts, blocks, repaired=False)
    gate.step2_basis(state)
    gate.step3_quotes(state)
    gate.step3r_rag_rule(state, 62, INCIDENT, 80, "match")

    gate.step4_fp_policy(state, _rule_check_unknown_rule)

    assert state.steps["4"] == "missing"
    assert state.missing == ["severity", "asset_criticality", "playbook_rule"]
    assert state.warnings == ["unknown_rule"]
    assert state.flagged_by == ["step4"]
    assert state.verdict == FP and state.proposed_verdict == TP
    doc = _document(state)
    assert doc["forced"] is False and doc["forced_by"] == []  # a flag is not a force either
    assert doc["flagged_by"] == ["step4"]


def test_step4_evaluates_a_false_positive_a_benign_item_produced_too():
    state = _through_step3r(TP, 89, BENIGN, 80)

    gate.step4_fp_policy(state, _rule_check_unknown_rule)

    assert state.verdict == FP and state.steps["3r"] == "changed"
    assert state.steps["4"] == "missing" and state.flagged_by == ["step4"]


def test_step4_is_n_a_when_the_rule_did_not_change_a_true_positive():
    state = _through_step3r(TP, 62, BENIGN, 80)  # a benign item under the threshold: not applied
    gate.step4_fp_policy(state, _rule_check_unknown_rule)

    assert state.steps["4"] == "n/a" and state.missing == [] and state.flagged_by == []


def test_step4_is_n_a_for_a_true_positive_the_rule_produced():
    """The same crafted facts and rule check that flag the model's own `false_positive` (critical severity, an
    unknown asset, a rule not in the table): once the rule says `true_positive` there is no false positive to
    check."""
    parsed, facts, blocks = _model_answer(FP)
    own = gate.start(parsed, facts, blocks, repaired=False)
    gate.step2_basis(own)
    gate.step3_quotes(own)
    gate.step4_fp_policy(own, _rule_check_unknown_rule)
    assert own.steps["4"] == "missing"

    ruled = _through_step3r(FP, 90, INCIDENT, 80)
    gate.step4_fp_policy(ruled, _rule_check_unknown_rule)

    assert ruled.verdict == TP
    assert ruled.steps["4"] == "n/a" and ruled.missing == [] and ruled.flagged_by == []


def test_step4_passes_a_rule_produced_false_positive_whose_conditions_hold():
    basis = dict(
        TRIAGE_V4_TRUE_POSITIVE["structured_basis"],
        severity="low",
        ioc_reputation="clean",
        asset_criticality="low",
        identity_privileged="false",
    )
    parsed = dict(TRIAGE_V4_TRUE_POSITIVE, structured_basis=basis)
    state = gate.start(parsed, _facts_from(basis), _tp_blocks(), repaired=False)
    gate.step2_basis(state)
    gate.step3_quotes(state)
    gate.step3r_rag_rule(state, 62, INCIDENT, 80, "match")

    gate.step4_fp_policy(state, _rule_check_holds)

    assert state.steps["4"] == "ok" and state.missing == [] and state.flagged_by == []
    assert state.verdict == FP


# ---------------------------------------------------------------------------
# the verifier: sent the model's own verdict, step 6 compares with it
# ---------------------------------------------------------------------------


def _after_1_to_5(
    answer, best_pct, threshold, side=INCIDENT, basis="match", rule_check=_rule_check_holds
) -> gate.GateState:
    parsed, facts, blocks = _model_answer(answer)
    return gate.run_steps_1_to_5(
        parsed,
        facts,
        blocks,
        repaired=False,
        rule_check=rule_check,
        scan=_no_findings,
        rag_best_pct=best_pct,
        rag_entry_side=side,
        rag_threshold=threshold,
        rag_basis=basis,
    )


def test_step6_compares_the_verifier_with_the_models_verdict_not_the_rules():
    changed = _after_1_to_5(TP, 62, 80)
    assert changed.verdict == FP and changed.proposed_verdict == TP

    agrees_with_the_model = {"agree": True, "structured_only_verdict": TP, "reason": "consistent"}
    state_a = copy.deepcopy(changed)
    gate.step6_verifier(state_a, agrees_with_the_model)
    assert state_a.steps["6"] == "agree"  # the verifier was sent `true_positive` and said so
    assert "step6" not in state_a.flagged_by
    assert state_a.verdict == FP  # step 6 never touches the verdict

    answers_the_rules_verdict = {"agree": True, "structured_only_verdict": FP, "reason": "fp"}
    state_b = copy.deepcopy(changed)
    gate.step6_verifier(state_b, answers_the_rules_verdict)
    assert state_b.steps["6"] == "disagree"  # `false_positive` is not what it was asked to check
    assert "step6" in state_b.flagged_by
    assert state_b.verdict == FP


def test_step6_for_a_true_positive_the_rule_produced_compares_with_the_models_false_positive():
    changed = _after_1_to_5(FP, 85, 80)
    assert changed.verdict == TP and changed.proposed_verdict == FP

    state_a = copy.deepcopy(changed)
    gate.step6_verifier(state_a, {"agree": True, "structured_only_verdict": FP, "reason": "fp"})
    assert state_a.steps["6"] == "agree" and "step6" not in state_a.flagged_by
    assert state_a.verdict == TP

    state_b = copy.deepcopy(changed)
    gate.step6_verifier(state_b, {"agree": True, "structured_only_verdict": TP, "reason": "tp"})
    assert state_b.steps["6"] == "disagree" and "step6" in state_b.flagged_by
    assert state_b.verdict == TP


def test_step6_for_a_run_the_rule_did_not_change_is_what_it_is_today():
    state = _after_1_to_5(TP, None, 80, side=None, basis=None)
    gate.step6_verifier(
        state, {"agree": True, "structured_only_verdict": TP, "reason": "consistent"}
    )
    assert state.steps["6"] == "agree" and state.flagged_by == []

    state = _after_1_to_5(
        FP, 62, 80
    )  # applied (an incident under the threshold), but the model said FP
    gate.step6_verifier(state, {"agree": True, "structured_only_verdict": FP, "reason": "ok"})
    assert state.steps["6"] == "agree"
    gate.step6_verifier(state, {"agree": False, "structured_only_verdict": FP, "reason": "no"})
    assert state.steps["6"] == "disagree"


def test_an_unusable_verifier_answer_still_flags_a_rule_changed_run():
    state = _after_1_to_5(TP, 62, 80)
    result = gate.finish(state, None)

    assert state.steps["6"] == "invalid" and "step6" in state.flagged_by
    assert result["suggested_action"] == FP


# ---------------------------------------------------------------------------
# gate_result
# ---------------------------------------------------------------------------

VERSION_2_KEYS = {
    "version",
    "proposed_verdict",
    "final_verdict",
    "forced",
    "forced_by",
    "flagged_by",
    "step1_errors",
    "steps",
    "hallucination_flag",
    "mismatched_fields",
    "dropped_reasons",
    "missing",
    "facts",
    "warnings",
    "verifier_verdict",
    "playbook_used_effective",
    "prompt_version",
    "proposer_raw",
}


def test_the_document_of_a_changed_run_says_everything_the_spec_lists():
    state = _after_1_to_5(TP, 62, 80, rule_check=_rule_check_unknown_rule)
    gate.step6_verifier(
        state, {"agree": True, "structured_only_verdict": TP, "reason": "consistent"}
    )

    doc = gate.gate_result(state, prompt_version="pv", playbook_used_effective="ssh_brute_force")

    assert set(doc) == VERSION_2_KEYS | {"rag_rule"}
    assert doc["version"] == 2  # a reader that does not know the keys is not affected
    assert doc["proposed_verdict"] == TP and doc["final_verdict"] == FP
    assert doc["forced"] is False and doc["forced_by"] == []  # the rule is the record, not a force
    assert doc["rag_rule"] == {
        "threshold": 80,
        "best_pct": 62,
        "applied": True,
        "changed": True,
        "entry_side": INCIDENT,
        "rule_verdict": FP,
        "basis": "match",
    }
    assert doc["steps"]["3r"] == "changed"
    assert doc["flagged_by"] == ["step4"]  # step 4 flagged the false_positive the rule produced
    assert doc["verifier_verdict"] == TP
    assert doc["proposer_raw"]["suggested_action"] == TP  # the stored model JSON is not rewritten


def test_the_document_of_a_true_positive_the_rule_produced():
    state = _after_1_to_5(FP, 85, 80, rule_check=_rule_check_unknown_rule)
    gate.step6_verifier(state, {"agree": True, "structured_only_verdict": FP, "reason": "fp"})

    doc = gate.gate_result(state, prompt_version="pv", playbook_used_effective=None)

    assert doc["proposed_verdict"] == FP and doc["final_verdict"] == TP
    assert doc["rag_rule"]["rule_verdict"] == TP and doc["rag_rule"]["changed"] is True
    assert doc["forced"] is False and doc["forced_by"] == [] and doc["flagged_by"] == []
    assert doc["steps"]["3r"] == "changed" and doc["steps"]["4"] == "n/a"
    assert doc["steps"]["6"] == "agree"


def test_with_the_switch_off_the_document_is_what_it_was_plus_the_rag_rule_key_and_step_3r():
    state = _after_1_to_5(TP, None, 0, side=None, basis=None)
    gate.step6_verifier(
        state, {"agree": True, "structured_only_verdict": TP, "reason": "consistent"}
    )

    doc = gate.gate_result(state, prompt_version="pv", playbook_used_effective=None)

    assert set(doc) == VERSION_2_KEYS | {"rag_rule"}
    assert doc["rag_rule"] == SWITCH_OFF
    assert (doc["proposed_verdict"], doc["final_verdict"]) == (TP, TP)
    assert doc["forced"] is False and doc["forced_by"] == [] and doc["flagged_by"] == []
    assert doc["steps"] == {
        "1": "ok",
        "2": "ok",
        "3": "dropped:0",
        "3r": "n/a",
        "4": "n/a",
        "5": "findings:0",
        "6": "agree",
    }


def test_a_state_that_never_ran_the_step_still_carries_the_key_with_the_switch_off_values():
    parsed, facts, blocks = _model_answer(TP)
    state = gate.start(parsed, facts, blocks, repaired=False)

    doc = gate.gate_result(state, prompt_version="v", playbook_used_effective=None)

    assert doc["rag_rule"] == SWITCH_OFF and doc["forced"] is False and doc["forced_by"] == []
    assert "3r" not in doc["steps"]


def test_the_rule_is_the_only_step_that_changes_the_verdict_and_it_leaves_flagged_by_alone():
    parsed, facts, blocks = _model_answer(TP)
    facts = {**facts, "severity": "high"}  # step 2 flags
    state = gate.start(parsed, facts, blocks, repaired=False)
    gate.step2_basis(state)
    before = list(state.flagged_by)

    gate.step3r_rag_rule(state, 62, INCIDENT, 80, "match")

    assert state.flagged_by == before == ["step2"]
    assert state.verdict == FP


def test_output_guard_still_accepts_the_two_verdicts_and_the_rule_cannot_make_needs_review():
    for answer, pct, side in ((TP, 62, INCIDENT), (FP, 90, INCIDENT), (TP, 90, BENIGN)):
        state = _through_step3r(answer, pct, side, 80)
        assert gate.step7_output_guard(state)["suggested_action"] in output_guard.SUGGESTED_ACTIONS
        assert state.verdict in {TP, FP}
