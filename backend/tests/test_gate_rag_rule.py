"""`security.gate.step3r_rag_rule` - the RAG low-match rule (DEC-219,
`docs/superpowers/specs/2026-11-15-rag-low-match-fp-rule-design.md` sections 2, 4 and 7). PURE: no database,
no socket, `security` imports only `infra`, so the gate is handed two plain integers (`best_pct | None`,
`threshold`) and everything else is the model's answer and crafted facts.

The rule APPLIES when `threshold > 0`, `best_pct is not None` and `best_pct < threshold`. When it applies and
the model answered `true_positive`, ①'s verdict becomes `false_positive` (`forced_by` gains `rag_rule`, the
step is `changed`); when it applies and the model already answered `false_positive`, the step is `applied` and
nothing else changes; otherwise `n/a`. It is the one step that can change the verdict (DEC-217: the checks of
steps 2, 3, 4 and 6 only flag).
"""

from __future__ import annotations

import copy

import pytest
from app.security import gate, output_guard, wrap

from tests.fakes.llm import TRIAGE_V2_FALSE_POSITIVE, TRIAGE_V3_TRUE_POSITIVE

NONCE = wrap.new_nonce()
TP, FP = "true_positive", "false_positive"
SWITCH_OFF = {"threshold": 0, "best_pct": None, "applied": False, "changed": False}


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
    reason = TRIAGE_V3_TRUE_POSITIVE["reasons"][0]
    return _blocks(**{reason["source"]: reason["quote"] + " - trailing log context"})


def _fp_blocks() -> dict[str, wrap.Block]:
    reason = TRIAGE_V2_FALSE_POSITIVE["reasons"][0]
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
        parsed = TRIAGE_V3_TRUE_POSITIVE
        return parsed, _facts_from(parsed["structured_basis"]), _tp_blocks()
    parsed = TRIAGE_V2_FALSE_POSITIVE
    return parsed, _facts_from(parsed["structured_basis"]), _fp_blocks()


def _through_step3r(answer: str, best_pct: int | None, threshold: int) -> gate.GateState:
    parsed, facts, blocks = _model_answer(answer)
    state = gate.start(parsed, facts, blocks, repaired=False)
    gate.step2_basis(state)
    gate.step3_quotes(state)
    gate.step3r_rag_rule(state, best_pct, threshold)
    return state


def _document(state: gate.GateState) -> dict:
    return gate.gate_result(state, prompt_version="v", playbook_used_effective=None)


# ---------------------------------------------------------------------------
# the truth table - spec section 2
# ---------------------------------------------------------------------------

#: (threshold, best_pct, the model's answer) -> (applied, changed, steps["3r"], the verdict after the rule).
#: Written out, not computed: the table is the specification.
TRUTH_TABLE = [
    # the switch is off: nothing applies, whatever the match
    (0, None, TP, False, False, "n/a", TP),
    (0, 62, TP, False, False, "n/a", TP),
    (0, 0, TP, False, False, "n/a", TP),
    (0, 62, FP, False, False, "n/a", FP),
    (0, None, FP, False, False, "n/a", FP),
    # no number (no lookup, a failed one, no match, entries dropped, RAG off): the model's verdict stays
    (80, None, TP, False, False, "n/a", TP),
    (80, None, FP, False, False, "n/a", FP),
    # below the threshold: a true_positive is replaced, a false_positive is only "applied"
    (80, 62, TP, True, True, "changed", FP),
    (80, 62, FP, True, False, "applied", FP),
    (80, 79, TP, True, True, "changed", FP),
    (80, 79, FP, True, False, "applied", FP),
    (80, 0, TP, True, True, "changed", FP),  # 0 % is a number: a match with the lowest score
    # equal: 80 is not below 80
    (80, 80, TP, False, False, "n/a", TP),
    (80, 80, FP, False, False, "n/a", FP),
    # above
    (80, 81, TP, False, False, "n/a", TP),
    (80, 100, TP, False, False, "n/a", TP),
    (80, 100, FP, False, False, "n/a", FP),
    # the ends of the range
    (1, 0, TP, True, True, "changed", FP),
    (1, 1, TP, False, False, "n/a", TP),
    (100, 99, TP, True, True, "changed", FP),
    (100, 100, TP, False, False, "n/a", TP),
]


@pytest.mark.parametrize("threshold, best_pct, answer, applied, changed, step, final", TRUTH_TABLE)
def test_the_truth_table(threshold, best_pct, answer, applied, changed, step, final):
    state = _through_step3r(answer, best_pct, threshold)

    assert state.steps["3r"] == step
    assert state.verdict == final
    assert state.proposed_verdict == answer  # the model's own answer is kept beside it
    doc = _document(state)
    assert doc["rag_rule"] == {
        "threshold": threshold,
        "best_pct": best_pct,
        "applied": applied,
        "changed": changed,
    }
    assert (doc["proposed_verdict"], doc["final_verdict"]) == (answer, final)
    assert doc["forced"] is changed  # true exactly when the rule changed the verdict
    assert doc["forced"] is (doc["proposed_verdict"] != doc["final_verdict"])
    assert doc["forced_by"] == (["rag_rule"] if changed else [])
    assert doc["flagged_by"] == []  # a rule is not a failed check: it flags nothing
    assert doc["version"] == 2


@pytest.mark.parametrize("threshold, best_pct, answer, applied, changed, step, final", TRUTH_TABLE)
def test_step7_carries_the_verdict_after_the_rule_and_the_models_reasons(
    threshold, best_pct, answer, applied, changed, step, final
):
    state = _through_step3r(answer, best_pct, threshold)
    parsed = _model_answer(answer)[0]

    result = gate.step7_output_guard(state)

    assert result["suggested_action"] == final
    assert result["reasons"] == parsed["reasons"]  # step 3's survivors: the model's, changed or not
    assert result["confidence"] == parsed["confidence"]  # the model's confidence, never rewritten
    assert result["structured_basis"] == parsed["structured_basis"]
    assert state.steps["7"] == "ok"


def test_best_pct_and_threshold_are_the_numbers_it_was_given():
    state = _through_step3r(TP, 62, 80)
    assert state.rag_rule == {"threshold": 80, "best_pct": 62, "applied": True, "changed": True}
    assert state.forced_by == ["rag_rule"]


def test_the_rule_does_not_change_the_reasons_that_leave_the_gate():
    good = TRIAGE_V3_TRUE_POSITIVE["reasons"][0]
    bad = {"claim": "fabricated", "quote": "nowhere in the log", "source": "rule_description"}
    parsed = dict(TRIAGE_V3_TRUE_POSITIVE, reasons=[good, bad])
    facts = _facts_from(parsed["structured_basis"])
    state = gate.start(parsed, facts, _tp_blocks(), repaired=False)
    gate.step2_basis(state)
    gate.step3_quotes(state)

    gate.step3r_rag_rule(state, 62, 80)
    result = gate.step7_output_guard(state)

    assert state.verdict == FP
    assert result["reasons"] == [good]  # the model's survivors, not touched by the rule
    assert state.dropped_reasons == [{"index": 1, "why": "unknown_source"}]


def test_calling_the_step_twice_gives_the_same_state():
    """The rule reads the model's own answer, not the verdict it has so far: a second call changes nothing and
    lists the rule once."""
    state = _through_step3r(TP, 62, 80)
    before = (state.verdict, list(state.forced_by), dict(state.rag_rule), state.steps["3r"])

    gate.step3r_rag_rule(state, 62, 80)

    assert (state.verdict, state.forced_by, state.rag_rule, state.steps["3r"]) == before
    assert state.forced_by == ["rag_rule"] and state.steps["3r"] == "changed"
    assert _document(state)["forced"] is True


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
        rag_threshold=80,
    )

    assert list(state.steps) == ["1", "2", "3", "3r", "4", "5"]
    assert state.steps["3r"] == "changed"
    assert state.verdict == FP


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
    assert state.verdict == TP and state.forced_by == []
    assert state.rag_rule == SWITCH_OFF


def test_the_restricted_mode_runs_the_rule_too_after_step_3():
    """B3's re-run (`gate_mode="steps_1_3"`): start, step 2, step 3, then the rule, then step 7."""
    parsed, facts, blocks = _model_answer(TP)
    state = gate.start(parsed, facts, blocks, repaired=False)
    gate.step2_basis(state)
    gate.step3_quotes(state)
    gate.step3r_rag_rule(state, 62, 80)
    result = gate.step7_output_guard(state)

    assert list(state.steps) == ["1", "2", "3", "3r", "7"]
    assert result["suggested_action"] == FP
    assert _document(state)["forced_by"] == ["rag_rule"]


# ---------------------------------------------------------------------------
# step 4 evaluates the verdict it finds - section 4
# ---------------------------------------------------------------------------


def test_step4_evaluates_a_false_positive_the_rule_produced_like_one_the_model_gave():
    """The model said `true_positive` on an alert with a critical severity, an unknown asset and a rule that is
    not in the table; the rule makes it `false_positive`, and step 4 then raises the policy warnings it raises
    for the model's own `false_positive`."""
    parsed, facts, blocks = _model_answer(TP)
    state = gate.start(parsed, facts, blocks, repaired=False)
    gate.step2_basis(state)
    gate.step3_quotes(state)
    gate.step3r_rag_rule(state, 62, 80)

    gate.step4_fp_policy(state, _rule_check_unknown_rule)

    assert state.steps["4"] == "missing"
    assert state.missing == ["severity", "asset_criticality", "playbook_rule"]
    assert state.warnings == ["unknown_rule"]
    assert state.flagged_by == ["step4"]
    assert state.verdict == FP and state.proposed_verdict == TP
    doc = _document(state)
    assert doc["forced"] is True and doc["forced_by"] == ["rag_rule"]  # a flag does not replace it
    assert doc["flagged_by"] == ["step4"]


def test_step4_is_n_a_when_the_rule_did_not_apply_to_a_true_positive():
    state = _through_step3r(TP, 90, 80)
    gate.step4_fp_policy(state, _rule_check_unknown_rule)

    assert state.steps["4"] == "n/a" and state.missing == [] and state.flagged_by == []


def test_step4_passes_a_rule_produced_false_positive_whose_conditions_hold():
    basis = dict(
        TRIAGE_V3_TRUE_POSITIVE["structured_basis"],
        severity="low",
        ioc_reputation="clean",
        asset_criticality="low",
        identity_privileged="false",
    )
    parsed = dict(TRIAGE_V3_TRUE_POSITIVE, structured_basis=basis)
    state = gate.start(parsed, _facts_from(basis), _tp_blocks(), repaired=False)
    gate.step2_basis(state)
    gate.step3_quotes(state)
    gate.step3r_rag_rule(state, 62, 80)

    gate.step4_fp_policy(state, _rule_check_holds)

    assert state.steps["4"] == "ok" and state.missing == [] and state.flagged_by == []
    assert state.verdict == FP


# ---------------------------------------------------------------------------
# the verifier - section 4: sent the model's own verdict, step 6 compares with it
# ---------------------------------------------------------------------------


def _after_1_to_5(answer, best_pct, threshold, rule_check=_rule_check_holds) -> gate.GateState:
    parsed, facts, blocks = _model_answer(answer)
    return gate.run_steps_1_to_5(
        parsed,
        facts,
        blocks,
        repaired=False,
        rule_check=rule_check,
        scan=_no_findings,
        rag_best_pct=best_pct,
        rag_threshold=threshold,
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


def test_step6_for_a_run_the_rule_did_not_change_is_what_it_is_today():
    state = _after_1_to_5(TP, None, 80)
    gate.step6_verifier(
        state, {"agree": True, "structured_only_verdict": TP, "reason": "consistent"}
    )
    assert state.steps["6"] == "agree" and state.flagged_by == []

    state = _after_1_to_5(
        FP, 62, 80, rule_check=_rule_check_holds
    )  # applied, but the model said FP
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
# gate_result - section 4
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
    assert doc["version"] == 2  # a reader that does not know the key is not affected
    assert doc["proposed_verdict"] == TP and doc["final_verdict"] == FP
    assert doc["forced"] is True and doc["forced_by"] == ["rag_rule"]
    assert doc["rag_rule"] == {"threshold": 80, "best_pct": 62, "applied": True, "changed": True}
    assert doc["steps"]["3r"] == "changed"
    assert doc["flagged_by"] == ["step4"]  # step 4 flagged the false_positive the rule produced
    assert doc["verifier_verdict"] == TP
    assert doc["proposer_raw"]["suggested_action"] == TP  # the stored model JSON is not rewritten


def test_with_the_switch_off_the_document_is_what_it_was_plus_the_rag_rule_key_and_step_3r():
    state = _after_1_to_5(TP, None, 0)
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

    gate.step3r_rag_rule(state, 62, 80)

    assert state.flagged_by == before == ["step2"]
    assert state.verdict == FP


def test_output_guard_still_accepts_the_two_verdicts_and_the_rule_cannot_make_needs_review():
    state = _through_step3r(TP, 62, 80)
    assert gate.step7_output_guard(state)["suggested_action"] in output_guard.SUGGESTED_ACTIONS
    assert state.verdict in {TP, FP}
