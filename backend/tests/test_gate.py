"""`security.gate` — the 7-step gate (P3-T08), pure functions over crafted proposer/verifier JSON.

Written against context pack §7.3 (the seven steps) and `docs/plan/tasks/P3/P3-T08.prompt.md`'s
design notes. Every branch uses one of the fakes' canned `triage_v3` payloads (`fakes/llm.py`; ①'s
verdict is `false_positive | true_positive`, P14-T01) with one field changed, per the brief's
crafted-JSON matrix. `security` may import only `infra`
(G1) — `rule_check` and the verifier's parsed JSON always arrive as plain arguments, never as a
`kb`/`llm` import.

DEC-217 (BV-T1): a failed check FLAGS the run (`state.flagged_by`), it never changes `state.verdict`,
which stays the model's own answer from `start()` to step 7. Nothing here can produce `needs_review`.
DEC-219 (RR-T1): the one exception is the RAG low-match rule (`step3r_rag_rule`, a rule, not a check): with
the switch off (its defaults, which is what every test below runs) it is `n/a` and the verdict is the model's.
Its own tests are `test_gate_rag_rule.py`.
"""

from __future__ import annotations

import copy
import itertools

import pytest
from app.security import gate, output_guard, wrap

from tests.fakes.llm import TRIAGE_V2_FALSE_POSITIVE, TRIAGE_V3_TRUE_POSITIVE

NONCE = wrap.new_nonce()


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


def _true_positive_blocks() -> dict[str, wrap.Block]:
    reason = TRIAGE_V3_TRUE_POSITIVE["reasons"][0]
    return _blocks(**{reason["source"]: reason["quote"] + " — trailing log context"})


def _fp_blocks() -> dict[str, wrap.Block]:
    reason = TRIAGE_V2_FALSE_POSITIVE["reasons"][0]
    return _blocks(**{reason["source"]: reason["quote"] + " (routine)"})


def _rule_check_holds(_rule_id):
    return True, None


def _rule_check_no_rule_cited(rule_id):
    if rule_id is None:
        return False, "no_rule_cited"
    return False, "unknown_rule"


def _no_findings(_blocks):
    return []


def _one_high_finding(_blocks):
    return [{"level": "high", "category": "instruction_override"}]


# ---------------------------------------------------------------------------
# step 1 — schema
# ---------------------------------------------------------------------------


def test_step1_first_failure_asks_repair_second_fails():
    def validate_fails(_name, _obj):
        return ["structured_basis.severity: expected one of critical|high|medium|low"]

    status, errors = gate.step1_schema(TRIAGE_V3_TRUE_POSITIVE, validate_fails, repaired=False)
    assert status == "repair"
    assert errors

    status, errors = gate.step1_schema(TRIAGE_V3_TRUE_POSITIVE, validate_fails, repaired=True)
    assert status == "failed"
    assert errors


def test_step1_passes_when_validator_reports_no_errors():
    def validate_ok(_name, _obj):
        return []

    status, errors = gate.step1_schema(TRIAGE_V3_TRUE_POSITIVE, validate_ok, repaired=False)
    assert status == "ok"
    assert errors == []


def test_step1_asks_the_validator_for_triage_v3():
    """P14-T01: the model's answer is held to `triage_v3` (`false_positive | true_positive`)."""
    asked = []

    def spy(name, _obj):
        asked.append(name)
        return []

    gate.step1_schema(TRIAGE_V3_TRUE_POSITIVE, spy, repaired=False)
    assert asked == ["triage_v3"]


def test_step1_unparsed_json_counts_as_invalid():
    def validate_never_called(_name, _obj):
        raise AssertionError("validate must not be called on parsed=None")

    status, errors = gate.step1_schema(None, validate_never_called, repaired=False)
    assert status == "repair"
    assert errors

    status, errors = gate.step1_schema(None, validate_never_called, repaired=True)
    assert status == "failed"
    assert errors


def test_start_records_repaired_flag_in_steps():
    facts = _facts_from(TRIAGE_V3_TRUE_POSITIVE["structured_basis"])
    state = gate.start(TRIAGE_V3_TRUE_POSITIVE, facts, _true_positive_blocks(), repaired=False)
    assert state.steps["1"] == "ok"

    state = gate.start(TRIAGE_V3_TRUE_POSITIVE, facts, _true_positive_blocks(), repaired=True)
    assert state.steps["1"] == "repaired"
    assert state.proposed_verdict == "true_positive"
    assert state.verdict == "true_positive"
    assert state.reasons == TRIAGE_V3_TRUE_POSITIVE["reasons"]


# ---------------------------------------------------------------------------
# step 2 — structured_basis vs DB facts
# ---------------------------------------------------------------------------


def test_step2_basis_mismatch_flags_and_keeps_the_models_verdict():
    facts = _facts_from(TRIAGE_V3_TRUE_POSITIVE["structured_basis"], severity="high")
    state = gate.start(TRIAGE_V3_TRUE_POSITIVE, facts, _true_positive_blocks(), repaired=False)

    gate.step2_basis(state)

    assert state.verdict == "true_positive"
    assert state.hallucination_flag is True
    assert state.mismatched_fields == ["severity"]
    assert state.flagged_by == ["step2"]
    assert state.steps["2"] == "mismatch"


def test_step2_string_fields_compared_case_insensitively():
    basis = dict(TRIAGE_V3_TRUE_POSITIVE["structured_basis"])
    parsed = dict(TRIAGE_V3_TRUE_POSITIVE, structured_basis=basis)
    facts = _facts_from(basis, severity="CRITICAL")  # DB facts upper-cased, still a match
    state = gate.start(parsed, facts, _true_positive_blocks(), repaired=False)

    gate.step2_basis(state)

    assert state.verdict == "true_positive"
    assert state.steps["2"] == "ok"
    assert state.hallucination_flag is False
    assert state.flagged_by == []


def test_step2_occurrence_is_integer_equal_at_build_time():
    basis = dict(
        TRIAGE_V3_TRUE_POSITIVE["structured_basis"], occurrence_count="1"
    )  # model sent a string
    parsed = dict(TRIAGE_V3_TRUE_POSITIVE, structured_basis=basis)
    facts = _facts_from(TRIAGE_V3_TRUE_POSITIVE["structured_basis"], occurrence_count=1)
    state = gate.start(parsed, facts, _true_positive_blocks(), repaired=False)

    gate.step2_basis(state)
    assert state.steps["2"] == "ok"  # int("1") == 1, not a mismatch

    facts_grown = _facts_from(TRIAGE_V3_TRUE_POSITIVE["structured_basis"], occurrence_count=2)
    state2 = gate.start(parsed, facts_grown, _true_positive_blocks(), repaired=False)
    gate.step2_basis(state2)
    assert state2.mismatched_fields == ["occurrence_count"]
    assert state2.verdict == "true_positive"
    assert state2.flagged_by == ["step2"]


def test_step2_playbook_rule_applied_is_not_compared():
    basis = dict(TRIAGE_V3_TRUE_POSITIVE["structured_basis"], playbook_rule_applied="not-in-facts")
    parsed = dict(TRIAGE_V3_TRUE_POSITIVE, structured_basis=basis)
    facts = _facts_from(
        TRIAGE_V3_TRUE_POSITIVE["structured_basis"]
    )  # facts carry no playbook_rule_applied key at all
    state = gate.start(parsed, facts, _true_positive_blocks(), repaired=False)

    gate.step2_basis(state)

    assert state.steps["2"] == "ok"
    assert state.verdict == "true_positive"


# ---------------------------------------------------------------------------
# step 3 — quote check
# ---------------------------------------------------------------------------


def test_step3_invalid_quote_dropped_survivors_kept():
    good = TRIAGE_V2_FALSE_POSITIVE["reasons"][0]
    bad = {
        "claim": "fabricated",
        "quote": "this text is nowhere in any block",
        "source": "rule_description",
    }
    parsed = dict(TRIAGE_V2_FALSE_POSITIVE, reasons=[good, bad])
    facts = _facts_from(TRIAGE_V2_FALSE_POSITIVE["structured_basis"])
    state = gate.start(parsed, facts, _fp_blocks(), repaired=False)

    gate.step3_quotes(state)

    assert state.reasons == [good]
    assert state.dropped_reasons == [{"index": 1, "why": "not_substring"}]
    assert state.steps["3"] == "dropped:1"
    assert state.verdict == "false_positive"
    assert state.flagged_by == []  # a survivor remains - step 3 does not flag


def test_step3_all_invalid_flags_and_keeps_the_models_verdict():
    bad = {"claim": "fabricated", "quote": "not anywhere", "source": "rule_description"}
    parsed = dict(TRIAGE_V2_FALSE_POSITIVE, reasons=[bad])
    facts = _facts_from(TRIAGE_V2_FALSE_POSITIVE["structured_basis"])
    state = gate.start(parsed, facts, _fp_blocks(), repaired=False)

    gate.step3_quotes(state)

    assert state.reasons == []
    assert state.verdict == "false_positive"
    assert state.flagged_by == ["step3"]
    assert state.steps["3"] == "dropped:1"


def test_step3_quote_matches_escaped_form():
    reason = {"claim": "html-ish quote", "quote": "&lt;script&gt;", "source": "context"}
    parsed = dict(TRIAGE_V2_FALSE_POSITIVE, reasons=[reason])
    facts = _facts_from(TRIAGE_V2_FALSE_POSITIVE["structured_basis"])
    blocks = _blocks(context="payload contains <script>alert(1)</script> inline")
    state = gate.start(parsed, facts, blocks, repaired=False)

    gate.step3_quotes(state)

    assert state.reasons == [reason]
    assert state.dropped_reasons == []


def test_step3_unknown_source_dropped():
    good = TRIAGE_V2_FALSE_POSITIVE["reasons"][0]
    unknown = {"claim": "typo'd source", "quote": "irrelevant", "source": "kb_playbok"}
    parsed = dict(TRIAGE_V2_FALSE_POSITIVE, reasons=[good, unknown])
    facts = _facts_from(TRIAGE_V2_FALSE_POSITIVE["structured_basis"])
    state = gate.start(parsed, facts, _fp_blocks(), repaired=False)

    gate.step3_quotes(state)

    assert state.reasons == [good]
    assert state.dropped_reasons == [{"index": 1, "why": "unknown_source"}]


def test_step3_empty_quote_dropped():
    empty = {"claim": "nothing quoted", "quote": "", "source": "rule_description"}
    parsed = dict(TRIAGE_V2_FALSE_POSITIVE, reasons=[empty])
    facts = _facts_from(TRIAGE_V2_FALSE_POSITIVE["structured_basis"])
    state = gate.start(parsed, facts, _fp_blocks(), repaired=False)

    gate.step3_quotes(state)

    assert state.dropped_reasons == [{"index": 0, "why": "empty_quote"}]
    assert state.verdict == "false_positive"
    assert state.flagged_by == ["step3"]


# ---------------------------------------------------------------------------
# step 4 — false_positive policy
# ---------------------------------------------------------------------------


def _fp_parsed_and_facts(**basis_overrides):
    basis = dict(TRIAGE_V2_FALSE_POSITIVE["structured_basis"], **basis_overrides)
    parsed = dict(TRIAGE_V2_FALSE_POSITIVE, structured_basis=basis)
    facts = _facts_from(basis)
    return parsed, facts


def test_step4_fp_without_rule_is_missing_playbook_rule():
    parsed, facts = _fp_parsed_and_facts(playbook_rule_applied=None)
    state = gate.start(parsed, facts, _fp_blocks(), repaired=False)
    gate.step2_basis(state)
    gate.step3_quotes(state)

    gate.step4_fp_policy(state, _rule_check_no_rule_cited)

    assert state.missing == ["playbook_rule"]
    assert state.verdict == "false_positive"
    assert state.flagged_by == ["step4"]
    assert state.warnings == ["no_rule_cited"]


def test_step4_fp_with_asset_unknown_is_missing():
    parsed, facts = _fp_parsed_and_facts(asset_criticality="unknown", playbook_rule_applied="sbf-1")
    state = gate.start(parsed, facts, _fp_blocks(), repaired=False)
    gate.step2_basis(state)
    gate.step3_quotes(state)

    gate.step4_fp_policy(state, _rule_check_holds)

    assert state.missing == ["asset_criticality"]
    assert state.verdict == "false_positive"
    assert state.flagged_by == ["step4"]


def test_step4_fp_with_critical_is_missing():
    parsed, facts = _fp_parsed_and_facts(severity="critical", playbook_rule_applied="sbf-1")
    state = gate.start(parsed, facts, _fp_blocks(), repaired=False)
    gate.step2_basis(state)
    gate.step3_quotes(state)

    gate.step4_fp_policy(state, _rule_check_holds)

    assert state.missing == ["severity"]
    assert state.verdict == "false_positive"
    assert state.flagged_by == ["step4"]


def test_step4_fp_with_all_conditions_survives():
    """Positive control (DEC-025) — asset is deliberately `medium`, not `low`: a step 4
    that requires asset_criticality == "low" instead of not-in-{high,unknown} would pass
    the fixture's own "low" value and prove nothing. `medium` discriminates the two."""
    parsed, facts = _fp_parsed_and_facts(asset_criticality="medium", playbook_rule_applied="sbf-1")
    state = gate.start(parsed, facts, _fp_blocks(), repaired=False)
    gate.step2_basis(state)
    gate.step3_quotes(state)

    gate.step4_fp_policy(state, _rule_check_holds)

    assert state.missing == []
    assert state.verdict == "false_positive"
    assert state.steps["4"] == "ok"
    assert state.flagged_by == []


def test_step4_missing_names_every_failed_condition():
    parsed, facts = _fp_parsed_and_facts(
        severity="critical",
        ioc_reputation="malicious",
        asset_criticality="high",
        identity_privileged="true",
        playbook_rule_applied=None,
    )
    state = gate.start(parsed, facts, _fp_blocks(), repaired=False)
    gate.step2_basis(state)
    gate.step3_quotes(state)

    gate.step4_fp_policy(state, _rule_check_no_rule_cited)

    assert state.missing == [
        "severity",
        "ioc_reputation",
        "asset_criticality",
        "identity_privileged",
        "playbook_rule",
    ]


def test_step4_not_applied_to_true_positive():
    facts = _facts_from(TRIAGE_V3_TRUE_POSITIVE["structured_basis"])
    state = gate.start(TRIAGE_V3_TRUE_POSITIVE, facts, _true_positive_blocks(), repaired=False)
    gate.step2_basis(state)
    gate.step3_quotes(state)

    gate.step4_fp_policy(state, _rule_check_no_rule_cited)

    assert state.steps["4"] == "n/a"
    assert state.verdict == "true_positive"
    assert state.missing == []
    assert state.flagged_by == []


def test_step4_is_evaluated_after_a_step2_flag():
    """DEC-217 G1: a step 2 flag no longer ends the policy check - step 4 still looks at every
    `false_positive` answer, so its `missing` and its warning are recorded beside step 2's."""
    parsed, facts = _fp_parsed_and_facts(playbook_rule_applied=None)
    facts = {**facts, "severity": "high"}  # the model said `low`: step 2 mismatch
    state = gate.start(parsed, facts, _fp_blocks(), repaired=False)
    gate.step2_basis(state)
    assert state.steps["2"] == "mismatch"

    gate.step4_fp_policy(state, _rule_check_no_rule_cited)

    assert state.steps["4"] == "missing"
    assert state.missing == ["playbook_rule"]
    assert state.warnings == ["no_rule_cited"]
    assert state.verdict == "false_positive"
    assert state.flagged_by == ["step2", "step4"]


def test_step4_is_evaluated_after_a_step3_flag():
    bad = {"claim": "fabricated", "quote": "not anywhere", "source": "rule_description"}
    parsed = dict(TRIAGE_V2_FALSE_POSITIVE, reasons=[bad])
    facts = _facts_from(TRIAGE_V2_FALSE_POSITIVE["structured_basis"])
    state = gate.start(parsed, facts, _fp_blocks(), repaired=False)
    gate.step2_basis(state)
    gate.step3_quotes(state)
    assert state.steps["3"] == "dropped:1" and state.reasons == []

    gate.step4_fp_policy(state, _rule_check_no_rule_cited)

    assert state.steps["4"] == "missing"
    assert state.missing == ["playbook_rule"]
    assert state.verdict == "false_positive"
    assert state.flagged_by == ["step3", "step4"]


def test_flagged_by_lists_the_steps_in_step_order_and_never_twice():
    parsed, facts = _fp_parsed_and_facts(playbook_rule_applied=None)
    facts = {**facts, "severity": "high"}
    bad = {"claim": "fabricated", "quote": "not anywhere", "source": "rule_description"}
    parsed = dict(parsed, reasons=[bad])
    state = gate.run_steps_1_to_5(
        parsed,
        facts,
        _fp_blocks(),
        repaired=False,
        rule_check=_rule_check_no_rule_cited,
        scan=_no_findings,
    )
    gate.step6_verifier(
        state, {"agree": False, "structured_only_verdict": "false_positive", "reason": "no"}
    )

    assert state.flagged_by == ["step2", "step3", "step4", "step6"]
    assert state.verdict == "false_positive" == state.proposed_verdict


# ---------------------------------------------------------------------------
# step 5 — detector records, never decides
# ---------------------------------------------------------------------------


def test_step5_high_finding_never_changes_verdict():
    facts = _facts_from(TRIAGE_V3_TRUE_POSITIVE["structured_basis"])
    state = gate.start(TRIAGE_V3_TRUE_POSITIVE, facts, _true_positive_blocks(), repaired=False)
    gate.step2_basis(state)
    gate.step3_quotes(state)
    gate.step4_fp_policy(state, _rule_check_no_rule_cited)

    gate.step5_detector(state, _one_high_finding)

    assert state.verdict == "true_positive"
    assert state.injection_findings == [{"level": "high", "category": "instruction_override"}]
    assert state.steps["5"] == "findings:1"


def test_step5_no_findings_recorded_as_zero():
    facts = _facts_from(TRIAGE_V3_TRUE_POSITIVE["structured_basis"])
    state = gate.start(TRIAGE_V3_TRUE_POSITIVE, facts, _true_positive_blocks(), repaired=False)

    gate.step5_detector(state, _no_findings)

    assert state.injection_findings == []
    assert state.steps["5"] == "findings:0"


# ---------------------------------------------------------------------------
# run_steps_1_to_5 — the runner
# ---------------------------------------------------------------------------


def test_run_steps_1_to_5_runs_start_through_five_in_order():
    facts = _facts_from(TRIAGE_V3_TRUE_POSITIVE["structured_basis"])
    state = gate.run_steps_1_to_5(
        TRIAGE_V3_TRUE_POSITIVE,
        facts,
        _true_positive_blocks(),
        repaired=False,
        rule_check=_rule_check_holds,
        scan=_no_findings,
    )

    # DEC-219: the RAG rule's step sits between 3 and 4; with the switch off (the defaults) it is `n/a`
    assert list(state.steps) == ["1", "2", "3", "3r", "4", "5"]
    assert state.steps["3r"] == "n/a"
    assert state.verdict == "true_positive"


# ---------------------------------------------------------------------------
# step 6 — verifier
# ---------------------------------------------------------------------------


def _state_after_1_to_5(parsed, facts, blocks, *, rule_check):
    return gate.run_steps_1_to_5(
        parsed, facts, blocks, repaired=False, rule_check=rule_check, scan=_no_findings
    )


def test_step6_disagree_flags_and_keeps_the_models_verdict():
    facts = _facts_from(TRIAGE_V3_TRUE_POSITIVE["structured_basis"])
    state = _state_after_1_to_5(
        TRIAGE_V3_TRUE_POSITIVE, facts, _true_positive_blocks(), rule_check=_rule_check_holds
    )
    assert state.verdict == "true_positive"

    gate.step6_verifier(
        state,
        {
            "agree": False,
            "structured_only_verdict": "true_positive",
            "reason": "insufficient basis",
        },
    )

    assert state.verdict == "true_positive"
    assert state.flagged_by == ["step6"]
    assert state.steps["6"] == "disagree"
    assert state.verifier_verdict == "true_positive"


def test_step6_agree_true_different_verdict_flags():
    facts = _facts_from(TRIAGE_V3_TRUE_POSITIVE["structured_basis"])
    state = _state_after_1_to_5(
        TRIAGE_V3_TRUE_POSITIVE, facts, _true_positive_blocks(), rule_check=_rule_check_holds
    )

    gate.step6_verifier(
        state, {"agree": True, "structured_only_verdict": "needs_review", "reason": "not enough"}
    )

    assert state.verdict == "true_positive"
    assert state.flagged_by == ["step6"]
    assert state.steps["6"] == "disagree"


def test_step6_invalid_flags():
    facts = _facts_from(TRIAGE_V3_TRUE_POSITIVE["structured_basis"])
    state = _state_after_1_to_5(
        TRIAGE_V3_TRUE_POSITIVE, facts, _true_positive_blocks(), rule_check=_rule_check_holds
    )

    gate.step6_verifier(state, None)

    assert state.verdict == "true_positive"
    assert state.flagged_by == ["step6"]
    assert state.steps["6"] == "invalid"
    assert state.verifier_verdict is None


def test_step6_agrees_and_matches_keeps_verdict():
    facts = _facts_from(TRIAGE_V3_TRUE_POSITIVE["structured_basis"])
    state = _state_after_1_to_5(
        TRIAGE_V3_TRUE_POSITIVE, facts, _true_positive_blocks(), rule_check=_rule_check_holds
    )

    gate.step6_verifier(
        state, {"agree": True, "structured_only_verdict": "true_positive", "reason": "consistent"}
    )

    assert state.verdict == "true_positive"
    assert state.flagged_by == []
    assert state.steps["6"] == "agree"


def test_step6_compares_against_the_models_verdict_even_after_a_step4_flag():
    """DEC-217: step 4 flags but does not change the verdict, so the verifier's prompt carried the model's
    own `false_positive` and step 6 compares its answer with that."""
    parsed, facts = _fp_parsed_and_facts(playbook_rule_applied=None)  # step 4 will flag
    state = _state_after_1_to_5(parsed, facts, _fp_blocks(), rule_check=_rule_check_no_rule_cited)
    assert state.flagged_by == ["step4"]
    assert state.verdict == "false_positive" == state.proposed_verdict

    disagree_by_flag = {
        "agree": False,
        "structured_only_verdict": "false_positive",
        "reason": "the proposer's false_positive is unsupported",
    }
    state_a = copy.deepcopy(state)
    gate.step6_verifier(state_a, disagree_by_flag)
    assert state_a.steps["6"] == "disagree"  # agree is False, regardless of the verdict match
    assert state_a.flagged_by == ["step4", "step6"]

    agree_and_matches = {
        "agree": True,
        "structured_only_verdict": "false_positive",
        "reason": "consistent with the model's verdict",
    }
    state_b = copy.deepcopy(state)
    gate.step6_verifier(state_b, agree_and_matches)
    assert state_b.steps["6"] == "agree"
    assert state_b.flagged_by == ["step4"]
    assert state_b.verdict == "false_positive"

    verifier_says_needs_review = {
        "agree": True,
        "structured_only_verdict": "needs_review",
        "reason": "not enough to say",
    }
    state_c = copy.deepcopy(state)
    gate.step6_verifier(state_c, verifier_says_needs_review)
    assert state_c.steps["6"] == "disagree"  # the verifier may still say it; it only flags
    assert state_c.verifier_verdict == "needs_review"
    assert state_c.flagged_by == ["step4", "step6"]
    assert state_c.verdict == "false_positive"


# ---------------------------------------------------------------------------
# step 7 — output_guard
# ---------------------------------------------------------------------------


def test_step7_result_carries_the_models_verdict_and_the_survivors():
    good = TRIAGE_V2_FALSE_POSITIVE["reasons"][0]
    bad = {"claim": "fabricated", "quote": "nowhere", "source": "rule_description"}
    parsed = dict(TRIAGE_V2_FALSE_POSITIVE, reasons=[good, bad])
    facts = _facts_from(TRIAGE_V2_FALSE_POSITIVE["structured_basis"], severity="high")
    state = gate.start(parsed, facts, _fp_blocks(), repaired=False)
    gate.step2_basis(state)  # a mismatch: flagged
    gate.step3_quotes(state)  # drops `bad`, keeps `good`
    assert state.flagged_by == ["step2"]

    result = gate.step7_output_guard(state)

    assert result["suggested_action"] == "false_positive"  # the model's own, flagged or not
    assert result["reasons"] == [good]
    assert state.steps["7"] == "ok"


def test_step7_refuses_needs_review_even_if_a_step_set_it():
    """DEC-217: `needs_review` can no longer leave the gate - the guard raises, whatever wrote it."""
    facts = _facts_from(TRIAGE_V3_TRUE_POSITIVE["structured_basis"])
    state = gate.start(TRIAGE_V3_TRUE_POSITIVE, facts, _true_positive_blocks(), repaired=False)
    state.verdict = "needs_review"

    with pytest.raises(output_guard.OutputGuardError, match="suggested_action: invalid"):
        gate.step7_output_guard(state)


def test_step7_raises_via_output_guard_on_violation():
    parsed = dict(TRIAGE_V3_TRUE_POSITIVE)
    facts = _facts_from(TRIAGE_V3_TRUE_POSITIVE["structured_basis"])
    state = gate.start(parsed, facts, _true_positive_blocks(), repaired=False)
    state.verdict = "maybe"  # not a real verdict — output_guard must catch this, not trust the gate

    with pytest.raises(output_guard.OutputGuardError):
        gate.step7_output_guard(state)


def test_finish_runs_step6_then_step7():
    facts = _facts_from(TRIAGE_V3_TRUE_POSITIVE["structured_basis"])
    state = _state_after_1_to_5(
        TRIAGE_V3_TRUE_POSITIVE, facts, _true_positive_blocks(), rule_check=_rule_check_holds
    )

    result = gate.finish(
        state, {"agree": True, "structured_only_verdict": "true_positive", "reason": "consistent"}
    )

    assert result["suggested_action"] == "true_positive"
    assert state.steps["6"] == "agree"
    assert state.steps["7"] == "ok"


# ---------------------------------------------------------------------------
# output_guard.enforce — the closed-set re-check, tested live and directly
# ---------------------------------------------------------------------------


def test_output_guard_refuses_needs_review():
    """DEC-217 (G1): a `needs_review` can no longer leave the gate."""
    with pytest.raises(output_guard.OutputGuardError, match="suggested_action: invalid"):
        output_guard.enforce(dict(TRIAGE_V3_TRUE_POSITIVE, suggested_action="needs_review"))


def test_output_guard_vocabulary_is_the_models_two_values():
    assert output_guard.SUGGESTED_ACTIONS == frozenset({"false_positive", "true_positive"})
    for answer in ("false_positive", "true_positive"):
        enforced = output_guard.enforce(dict(TRIAGE_V3_TRUE_POSITIVE, suggested_action=answer))
        assert enforced["suggested_action"] == answer


def test_output_guard_raises_on_closed_set_violation():
    bad = dict(TRIAGE_V3_TRUE_POSITIVE, suggested_action="maybe")

    with pytest.raises(output_guard.OutputGuardError):
        output_guard.enforce(bad)


def test_output_guard_drops_unknown_keys():
    with_extra = dict(TRIAGE_V3_TRUE_POSITIVE, unexpected_field="smuggled")

    enforced = output_guard.enforce(with_extra)

    assert "unexpected_field" not in enforced
    assert set(enforced) == {
        "suggested_action",
        "confidence",
        "structured_basis",
        "reasons",
        "playbook_used",
    }


def test_output_guard_requires_occurrence_count_int():
    basis = dict(TRIAGE_V3_TRUE_POSITIVE["structured_basis"], occurrence_count="1")
    bad = dict(TRIAGE_V3_TRUE_POSITIVE, structured_basis=basis)

    with pytest.raises(output_guard.OutputGuardError):
        output_guard.enforce(bad)


def test_output_guard_rechecks_reason_source():
    bad_reason = dict(TRIAGE_V3_TRUE_POSITIVE["reasons"][0], source="not_a_real_source")
    bad = dict(TRIAGE_V3_TRUE_POSITIVE, reasons=[bad_reason])

    with pytest.raises(output_guard.OutputGuardError):
        output_guard.enforce(bad)


def test_output_guard_never_adds_an_action_or_rewrites_text():
    enforced = output_guard.enforce(TRIAGE_V3_TRUE_POSITIVE)

    assert enforced["suggested_action"] == TRIAGE_V3_TRUE_POSITIVE["suggested_action"]
    assert enforced["reasons"][0]["claim"] == TRIAGE_V3_TRUE_POSITIVE["reasons"][0]["claim"]
    assert enforced["reasons"][0]["quote"] == TRIAGE_V3_TRUE_POSITIVE["reasons"][0]["quote"]


# ---------------------------------------------------------------------------
# gate_result
# ---------------------------------------------------------------------------


def test_gate_result_is_version_2_and_shows_the_flags_not_a_force():
    facts = _facts_from(TRIAGE_V3_TRUE_POSITIVE["structured_basis"])
    state = _state_after_1_to_5(
        TRIAGE_V3_TRUE_POSITIVE, facts, _true_positive_blocks(), rule_check=_rule_check_holds
    )
    gate.step6_verifier(
        state,
        {"agree": False, "structured_only_verdict": "true_positive", "reason": "insufficient"},
    )

    doc = gate.gate_result(
        state, prompt_version="abc123+deadbeef", playbook_used_effective="ssh_brute_force"
    )

    assert doc == {
        "version": 2,
        "proposed_verdict": "true_positive",
        "final_verdict": "true_positive",
        "forced": False,
        "forced_by": [],
        "flagged_by": ["step6"],
        # DEC-219: on every new run; the switch off (threshold 0) applies nothing
        "rag_rule": {"threshold": 0, "best_pct": None, "applied": False, "changed": False},
        "step1_errors": [],  # DEC-218: the first call was valid, so none
        "steps": state.steps,
        "hallucination_flag": False,
        "mismatched_fields": [],
        "dropped_reasons": [],
        "missing": [],
        "facts": facts,
        "warnings": [],
        "verifier_verdict": "true_positive",
        "playbook_used_effective": "ssh_brute_force",
        "prompt_version": "abc123+deadbeef",
        "proposer_raw": TRIAGE_V3_TRUE_POSITIVE,
    }


def test_gate_result_of_a_run_nothing_flagged_has_an_empty_flagged_by():
    facts = _facts_from(TRIAGE_V3_TRUE_POSITIVE["structured_basis"])
    state = _state_after_1_to_5(
        TRIAGE_V3_TRUE_POSITIVE, facts, _true_positive_blocks(), rule_check=_rule_check_holds
    )
    gate.step6_verifier(
        state, {"agree": True, "structured_only_verdict": "true_positive", "reason": "consistent"}
    )

    doc = gate.gate_result(state, prompt_version="v", playbook_used_effective=None)

    assert doc["version"] == 2
    assert doc["forced"] is False and doc["forced_by"] == [] and doc["flagged_by"] == []
    assert doc["playbook_used_effective"] is None


def test_gate_result_of_every_check_failing_still_carries_the_models_verdict_twice():
    """G1 and G2 together: all four checks fire, the verdict is the model's, and each finding is recorded."""
    parsed, facts = _fp_parsed_and_facts(playbook_rule_applied=None)
    facts = {**facts, "severity": "high"}
    bad = {"claim": "fabricated", "quote": "not anywhere", "source": "rule_description"}
    parsed = dict(parsed, reasons=[bad])
    state = gate.run_steps_1_to_5(
        parsed,
        facts,
        _fp_blocks(),
        repaired=False,
        rule_check=_rule_check_no_rule_cited,
        scan=_no_findings,
    )
    result = gate.finish(state, None)  # and the verifier's answer did not parse

    doc = gate.gate_result(state, prompt_version="v", playbook_used_effective=None)

    assert result["suggested_action"] == "false_positive" and result["reasons"] == []
    assert (doc["proposed_verdict"], doc["final_verdict"]) == ("false_positive",) * 2
    assert doc["flagged_by"] == ["step2", "step3", "step4", "step6"]
    assert doc["forced"] is False and doc["forced_by"] == []
    assert doc["hallucination_flag"] is True and doc["mismatched_fields"] == ["severity"]
    assert doc["dropped_reasons"] == [{"index": 0, "why": "not_substring"}]
    assert doc["missing"] == ["playbook_rule"] and doc["warnings"] == ["no_rule_cited"]
    assert doc["steps"]["6"] == "invalid"


# ---------------------------------------------------------------------------
# the verdict is constant — DEC-217 (it replaces DEC-025/DEC-077's "no step un-forces needs_review")
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("answer", ["false_positive", "true_positive"])
def test_no_step_changes_the_models_verdict_in_any_order(answer):
    """Every order of steps 2, 3, 4 and 6, each one failing its check: the verdict is the model's answer
    after every call, so a step can raise a warning and nothing else. A step that wrote `needs_review`
    (or the other definite answer) would break it."""
    basis = dict(TRIAGE_V2_FALSE_POSITIVE["structured_basis"], playbook_rule_applied=None)
    bad_reason = {"claim": "fabricated", "quote": "not anywhere", "source": "rule_description"}
    parsed = dict(
        TRIAGE_V2_FALSE_POSITIVE,
        suggested_action=answer,
        structured_basis=basis,
        reasons=[bad_reason],
    )
    facts = {
        **_facts_from(basis),
        "severity": "critical",
    }  # steps 2, 3 fail; for FP step 4 fails too

    steps = {
        "step2": lambda s: gate.step2_basis(s),
        "step3": lambda s: gate.step3_quotes(s),
        "step4": lambda s: gate.step4_fp_policy(s, _rule_check_no_rule_cited),
        "step6": lambda s: gate.step6_verifier(
            s, {"agree": False, "structured_only_verdict": "needs_review", "reason": "no"}
        ),
    }

    for order in itertools.permutations(steps):
        state = gate.start(parsed, facts, _fp_blocks(), repaired=False)
        for name in order:
            steps[name](state)
            assert state.verdict == answer, f"{name} (order {order}) changed the verdict"
            assert state.proposed_verdict == answer
        assert state.flagged_by  # something was flagged ...
        assert gate.step7_output_guard(state)["suggested_action"] == answer  # ... and kept
