"""`security.gate` — the 7-step gate (P3-T08), pure functions over crafted proposer/verifier JSON.

Written against context pack §7.3 (the seven steps) and `docs/plan/tasks/P3/P3-T08.prompt.md`'s
design notes. Every branch uses one of the fakes' canned `triage_v2` payloads (`fakes/llm.py`)
with one field changed, per the brief's crafted-JSON matrix. `security` may import only `infra`
(G1) — `rule_check` and the verifier's parsed JSON always arrive as plain arguments, never as a
`kb`/`llm` import.
"""

from __future__ import annotations

import copy
import itertools

import pytest
from app.security import gate, output_guard, wrap
from tests.fakes.llm import TRIAGE_V2_ESCALATE, TRIAGE_V2_FALSE_POSITIVE

NONCE = wrap.new_nonce()


def _blocks(**text_by_source: str) -> dict[str, wrap.Block]:
    return {source: wrap.untrusted_block(text, source, nonce=NONCE) for source, text in text_by_source.items()}


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


def _escalate_blocks() -> dict[str, wrap.Block]:
    reason = TRIAGE_V2_ESCALATE["reasons"][0]
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

    status, errors = gate.step1_schema(TRIAGE_V2_ESCALATE, validate_fails, repaired=False)
    assert status == "repair"
    assert errors

    status, errors = gate.step1_schema(TRIAGE_V2_ESCALATE, validate_fails, repaired=True)
    assert status == "failed"
    assert errors


def test_step1_passes_when_validator_reports_no_errors():
    def validate_ok(_name, _obj):
        return []

    status, errors = gate.step1_schema(TRIAGE_V2_ESCALATE, validate_ok, repaired=False)
    assert status == "ok"
    assert errors == []


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
    facts = _facts_from(TRIAGE_V2_ESCALATE["structured_basis"])
    state = gate.start(TRIAGE_V2_ESCALATE, facts, _escalate_blocks(), repaired=False)
    assert state.steps["1"] == "ok"

    state = gate.start(TRIAGE_V2_ESCALATE, facts, _escalate_blocks(), repaired=True)
    assert state.steps["1"] == "repaired"
    assert state.proposed_verdict == "escalate"
    assert state.verdict == "escalate"
    assert state.reasons == TRIAGE_V2_ESCALATE["reasons"]


# ---------------------------------------------------------------------------
# step 2 — structured_basis vs DB facts
# ---------------------------------------------------------------------------


def test_step2_basis_mismatch_forces_needs_review_and_flags():
    facts = _facts_from(TRIAGE_V2_ESCALATE["structured_basis"], severity="high")
    state = gate.start(TRIAGE_V2_ESCALATE, facts, _escalate_blocks(), repaired=False)

    gate.step2_basis(state)

    assert state.verdict == "needs_review"
    assert state.hallucination_flag is True
    assert state.mismatched_fields == ["severity"]
    assert state.forced_by == ["step2"]
    assert state.steps["2"] == "mismatch"


def test_step2_string_fields_compared_case_insensitively():
    basis = dict(TRIAGE_V2_ESCALATE["structured_basis"])
    parsed = dict(TRIAGE_V2_ESCALATE, structured_basis=basis)
    facts = _facts_from(basis, severity="CRITICAL")  # DB facts upper-cased, still a match
    state = gate.start(parsed, facts, _escalate_blocks(), repaired=False)

    gate.step2_basis(state)

    assert state.verdict == "escalate"
    assert state.steps["2"] == "ok"
    assert state.hallucination_flag is False


def test_step2_occurrence_is_integer_equal_at_build_time():
    basis = dict(TRIAGE_V2_ESCALATE["structured_basis"], occurrence_count="1")  # model sent a string
    parsed = dict(TRIAGE_V2_ESCALATE, structured_basis=basis)
    facts = _facts_from(TRIAGE_V2_ESCALATE["structured_basis"], occurrence_count=1)
    state = gate.start(parsed, facts, _escalate_blocks(), repaired=False)

    gate.step2_basis(state)
    assert state.steps["2"] == "ok"  # int("1") == 1, not a mismatch

    facts_grown = _facts_from(TRIAGE_V2_ESCALATE["structured_basis"], occurrence_count=2)
    state2 = gate.start(parsed, facts_grown, _escalate_blocks(), repaired=False)
    gate.step2_basis(state2)
    assert state2.mismatched_fields == ["occurrence_count"]
    assert state2.verdict == "needs_review"


def test_step2_playbook_rule_applied_is_not_compared():
    basis = dict(TRIAGE_V2_ESCALATE["structured_basis"], playbook_rule_applied="not-in-facts")
    parsed = dict(TRIAGE_V2_ESCALATE, structured_basis=basis)
    facts = _facts_from(TRIAGE_V2_ESCALATE["structured_basis"])  # facts carry no playbook_rule_applied key at all
    state = gate.start(parsed, facts, _escalate_blocks(), repaired=False)

    gate.step2_basis(state)

    assert state.steps["2"] == "ok"
    assert state.verdict == "escalate"


# ---------------------------------------------------------------------------
# step 3 — quote check
# ---------------------------------------------------------------------------


def test_step3_invalid_quote_dropped_survivors_kept():
    good = TRIAGE_V2_FALSE_POSITIVE["reasons"][0]
    bad = {"claim": "fabricated", "quote": "this text is nowhere in any block", "source": "rule_description"}
    parsed = dict(TRIAGE_V2_FALSE_POSITIVE, reasons=[good, bad])
    facts = _facts_from(TRIAGE_V2_FALSE_POSITIVE["structured_basis"])
    state = gate.start(parsed, facts, _fp_blocks(), repaired=False)

    gate.step3_quotes(state)

    assert state.reasons == [good]
    assert state.dropped_reasons == [{"index": 1, "why": "not_substring"}]
    assert state.steps["3"] == "dropped:1"
    assert state.verdict == "false_positive"  # a survivor remains — step 3 does not force


def test_step3_all_invalid_forces_needs_review():
    bad = {"claim": "fabricated", "quote": "not anywhere", "source": "rule_description"}
    parsed = dict(TRIAGE_V2_FALSE_POSITIVE, reasons=[bad])
    facts = _facts_from(TRIAGE_V2_FALSE_POSITIVE["structured_basis"])
    state = gate.start(parsed, facts, _fp_blocks(), repaired=False)

    gate.step3_quotes(state)

    assert state.reasons == []
    assert state.verdict == "needs_review"
    assert state.forced_by == ["step3"]
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
    assert state.verdict == "needs_review"


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
    assert state.verdict == "needs_review"
    assert state.forced_by == ["step4"]
    assert state.warnings == ["no_rule_cited"]


def test_step4_fp_with_asset_unknown_is_missing():
    parsed, facts = _fp_parsed_and_facts(asset_criticality="unknown", playbook_rule_applied="sbf-1")
    state = gate.start(parsed, facts, _fp_blocks(), repaired=False)
    gate.step2_basis(state)
    gate.step3_quotes(state)

    gate.step4_fp_policy(state, _rule_check_holds)

    assert state.missing == ["asset_criticality"]
    assert state.verdict == "needs_review"


def test_step4_fp_with_critical_is_missing():
    parsed, facts = _fp_parsed_and_facts(severity="critical", playbook_rule_applied="sbf-1")
    state = gate.start(parsed, facts, _fp_blocks(), repaired=False)
    gate.step2_basis(state)
    gate.step3_quotes(state)

    gate.step4_fp_policy(state, _rule_check_holds)

    assert state.missing == ["severity"]
    assert state.verdict == "needs_review"


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
    assert state.forced_by == []


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


def test_step4_not_applied_to_escalate():
    facts = _facts_from(TRIAGE_V2_ESCALATE["structured_basis"])
    state = gate.start(TRIAGE_V2_ESCALATE, facts, _escalate_blocks(), repaired=False)
    gate.step2_basis(state)
    gate.step3_quotes(state)

    gate.step4_fp_policy(state, _rule_check_no_rule_cited)

    assert state.steps["4"] == "n/a"
    assert state.verdict == "escalate"
    assert state.missing == []
    assert state.forced_by == []


# ---------------------------------------------------------------------------
# step 5 — detector records, never decides
# ---------------------------------------------------------------------------


def test_step5_high_finding_never_changes_verdict():
    facts = _facts_from(TRIAGE_V2_ESCALATE["structured_basis"])
    state = gate.start(TRIAGE_V2_ESCALATE, facts, _escalate_blocks(), repaired=False)
    gate.step2_basis(state)
    gate.step3_quotes(state)
    gate.step4_fp_policy(state, _rule_check_no_rule_cited)

    gate.step5_detector(state, _one_high_finding)

    assert state.verdict == "escalate"
    assert state.injection_findings == [{"level": "high", "category": "instruction_override"}]
    assert state.steps["5"] == "findings:1"


def test_step5_no_findings_recorded_as_zero():
    facts = _facts_from(TRIAGE_V2_ESCALATE["structured_basis"])
    state = gate.start(TRIAGE_V2_ESCALATE, facts, _escalate_blocks(), repaired=False)

    gate.step5_detector(state, _no_findings)

    assert state.injection_findings == []
    assert state.steps["5"] == "findings:0"


# ---------------------------------------------------------------------------
# run_steps_1_to_5 — the runner
# ---------------------------------------------------------------------------


def test_run_steps_1_to_5_runs_start_through_five_in_order():
    facts = _facts_from(TRIAGE_V2_ESCALATE["structured_basis"])
    state = gate.run_steps_1_to_5(
        TRIAGE_V2_ESCALATE,
        facts,
        _escalate_blocks(),
        repaired=False,
        rule_check=_rule_check_holds,
        scan=_no_findings,
    )

    assert set(state.steps) == {"1", "2", "3", "4", "5"}
    assert state.verdict == "escalate"


# ---------------------------------------------------------------------------
# step 6 — verifier
# ---------------------------------------------------------------------------


def _state_after_1_to_5(parsed, facts, blocks, *, rule_check):
    return gate.run_steps_1_to_5(
        parsed, facts, blocks, repaired=False, rule_check=rule_check, scan=_no_findings
    )


def test_step6_disagree_forces():
    facts = _facts_from(TRIAGE_V2_ESCALATE["structured_basis"])
    state = _state_after_1_to_5(
        TRIAGE_V2_ESCALATE, facts, _escalate_blocks(), rule_check=_rule_check_holds
    )
    assert state.verdict == "escalate"

    gate.step6_verifier(
        state, {"agree": False, "structured_only_verdict": "escalate", "reason": "insufficient basis"}
    )

    assert state.verdict == "needs_review"
    assert state.forced_by == ["step6"]
    assert state.steps["6"] == "disagree"
    assert state.verifier_verdict == "escalate"


def test_step6_agree_true_different_verdict_forces():
    facts = _facts_from(TRIAGE_V2_ESCALATE["structured_basis"])
    state = _state_after_1_to_5(
        TRIAGE_V2_ESCALATE, facts, _escalate_blocks(), rule_check=_rule_check_holds
    )

    gate.step6_verifier(
        state, {"agree": True, "structured_only_verdict": "needs_review", "reason": "not enough"}
    )

    assert state.verdict == "needs_review"
    assert state.forced_by == ["step6"]
    assert state.steps["6"] == "disagree"


def test_step6_invalid_forces():
    facts = _facts_from(TRIAGE_V2_ESCALATE["structured_basis"])
    state = _state_after_1_to_5(
        TRIAGE_V2_ESCALATE, facts, _escalate_blocks(), rule_check=_rule_check_holds
    )

    gate.step6_verifier(state, None)

    assert state.verdict == "needs_review"
    assert state.forced_by == ["step6"]
    assert state.steps["6"] == "invalid"


def test_step6_agrees_and_matches_keeps_verdict():
    facts = _facts_from(TRIAGE_V2_ESCALATE["structured_basis"])
    state = _state_after_1_to_5(
        TRIAGE_V2_ESCALATE, facts, _escalate_blocks(), rule_check=_rule_check_holds
    )

    gate.step6_verifier(
        state, {"agree": True, "structured_only_verdict": "escalate", "reason": "consistent"}
    )

    assert state.verdict == "escalate"
    assert state.forced_by == []
    assert state.steps["6"] == "agree"


def test_step6_compares_against_post_step4_verdict():
    parsed, facts = _fp_parsed_and_facts(playbook_rule_applied=None)  # step 4 will force needs_review
    state = _state_after_1_to_5(parsed, facts, _fp_blocks(), rule_check=_rule_check_no_rule_cited)
    assert state.verdict == "needs_review"
    assert state.proposed_verdict == "false_positive"

    disagree_with_proposer = {
        "agree": False,
        "structured_only_verdict": "needs_review",
        "reason": "proposer's false_positive is unsupported",
    }
    state_a = copy.deepcopy(state)
    gate.step6_verifier(state_a, disagree_with_proposer)
    assert state_a.steps["6"] == "disagree"  # agree is False, regardless of the verdict match

    agree_and_matches_post_step4 = {
        "agree": True,
        "structured_only_verdict": "needs_review",
        "reason": "consistent with the forced verdict",
    }
    state_b = copy.deepcopy(state)
    gate.step6_verifier(state_b, agree_and_matches_post_step4)
    assert state_b.steps["6"] == "agree"
    assert state_b.verdict == "needs_review"


# ---------------------------------------------------------------------------
# step 7 — output_guard
# ---------------------------------------------------------------------------


def test_step7_result_carries_final_verdict_and_survivors():
    good = TRIAGE_V2_FALSE_POSITIVE["reasons"][0]
    bad = {"claim": "fabricated", "quote": "nowhere", "source": "rule_description"}
    parsed = dict(TRIAGE_V2_FALSE_POSITIVE, reasons=[good, bad])
    facts = _facts_from(TRIAGE_V2_FALSE_POSITIVE["structured_basis"])
    state = gate.start(parsed, facts, _fp_blocks(), repaired=False)
    gate.step3_quotes(state)  # drops `bad`, keeps `good`
    state.verdict = "needs_review"  # simulate some earlier step forcing it
    state.forced_by.append("step2")

    result = gate.step7_output_guard(state)

    assert result["suggested_action"] == "needs_review"
    assert result["reasons"] == [good]
    assert state.steps["7"] == "ok"


def test_step7_raises_via_output_guard_on_violation():
    parsed = dict(TRIAGE_V2_ESCALATE)
    facts = _facts_from(TRIAGE_V2_ESCALATE["structured_basis"])
    state = gate.start(parsed, facts, _escalate_blocks(), repaired=False)
    state.verdict = "maybe"  # not a real verdict — output_guard must catch this, not trust the gate

    with pytest.raises(output_guard.OutputGuardError):
        gate.step7_output_guard(state)


def test_finish_runs_step6_then_step7():
    facts = _facts_from(TRIAGE_V2_ESCALATE["structured_basis"])
    state = _state_after_1_to_5(
        TRIAGE_V2_ESCALATE, facts, _escalate_blocks(), rule_check=_rule_check_holds
    )

    result = gate.finish(
        state, {"agree": True, "structured_only_verdict": "escalate", "reason": "consistent"}
    )

    assert result["suggested_action"] == "escalate"
    assert state.steps["6"] == "agree"
    assert state.steps["7"] == "ok"


# ---------------------------------------------------------------------------
# output_guard.enforce — the closed-set re-check, tested live and directly
# ---------------------------------------------------------------------------


def test_output_guard_raises_on_closed_set_violation():
    bad = dict(TRIAGE_V2_ESCALATE, suggested_action="maybe")

    with pytest.raises(output_guard.OutputGuardError):
        output_guard.enforce(bad)


def test_output_guard_drops_unknown_keys():
    with_extra = dict(TRIAGE_V2_ESCALATE, unexpected_field="smuggled")

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
    basis = dict(TRIAGE_V2_ESCALATE["structured_basis"], occurrence_count="1")
    bad = dict(TRIAGE_V2_ESCALATE, structured_basis=basis)

    with pytest.raises(output_guard.OutputGuardError):
        output_guard.enforce(bad)


def test_output_guard_rechecks_reason_source():
    bad_reason = dict(TRIAGE_V2_ESCALATE["reasons"][0], source="not_a_real_source")
    bad = dict(TRIAGE_V2_ESCALATE, reasons=[bad_reason])

    with pytest.raises(output_guard.OutputGuardError):
        output_guard.enforce(bad)


def test_output_guard_never_adds_an_action_or_rewrites_text():
    enforced = output_guard.enforce(TRIAGE_V2_ESCALATE)

    assert enforced["suggested_action"] == TRIAGE_V2_ESCALATE["suggested_action"]
    assert enforced["reasons"][0]["claim"] == TRIAGE_V2_ESCALATE["reasons"][0]["claim"]
    assert enforced["reasons"][0]["quote"] == TRIAGE_V2_ESCALATE["reasons"][0]["quote"]


# ---------------------------------------------------------------------------
# gate_result
# ---------------------------------------------------------------------------


def test_gate_result_shape_and_forced_flag():
    facts = _facts_from(TRIAGE_V2_ESCALATE["structured_basis"])
    state = _state_after_1_to_5(
        TRIAGE_V2_ESCALATE, facts, _escalate_blocks(), rule_check=_rule_check_holds
    )
    gate.step6_verifier(
        state, {"agree": False, "structured_only_verdict": "escalate", "reason": "insufficient"}
    )

    doc = gate.gate_result(state, prompt_version="abc123+deadbeef", playbook_used_effective="ssh_brute_force")

    assert doc == {
        "version": 1,
        "proposed_verdict": "escalate",
        "final_verdict": "needs_review",
        "forced": True,
        "forced_by": ["step6"],
        "steps": state.steps,
        "hallucination_flag": False,
        "mismatched_fields": [],
        "dropped_reasons": [],
        "missing": [],
        "facts": facts,
        "warnings": [],
        "verifier_verdict": "escalate",
        "playbook_used_effective": "ssh_brute_force",
        "prompt_version": "abc123+deadbeef",
        "proposer_raw": TRIAGE_V2_ESCALATE,
    }


def test_gate_result_forced_is_false_when_verdict_unchanged():
    facts = _facts_from(TRIAGE_V2_ESCALATE["structured_basis"])
    state = _state_after_1_to_5(
        TRIAGE_V2_ESCALATE, facts, _escalate_blocks(), rule_check=_rule_check_holds
    )
    gate.step6_verifier(
        state, {"agree": True, "structured_only_verdict": "escalate", "reason": "consistent"}
    )

    doc = gate.gate_result(state, prompt_version="v", playbook_used_effective=None)

    assert doc["forced"] is False
    assert doc["playbook_used_effective"] is None


# ---------------------------------------------------------------------------
# monotonicity — DEC-025/DEC-077: no step un-forces needs_review
# ---------------------------------------------------------------------------


def test_verdict_is_monotone():
    """Starting from a state already forced to needs_review, every order of the
    remaining steps must leave the verdict at needs_review — none may set it back
    to false_positive or escalate, even when every individual step's own
    admission conditions would otherwise be satisfied."""
    parsed, facts = _fp_parsed_and_facts(playbook_rule_applied="sbf-1")  # all step-4 conditions hold

    def build_forced_state():
        state = gate.start(parsed, facts, _fp_blocks(), repaired=False)
        state.verdict = "needs_review"  # simulate an earlier, unmodelled force
        state.forced_by = ["manual"]
        return state

    steps = {
        "step2": lambda s: gate.step2_basis(s),
        "step3": lambda s: gate.step3_quotes(s),
        "step4": lambda s: gate.step4_fp_policy(s, _rule_check_holds),
        "step6_agree": lambda s: gate.step6_verifier(
            s, {"agree": True, "structured_only_verdict": "needs_review", "reason": "ok"}
        ),
    }

    for order in itertools.permutations(steps):
        state = build_forced_state()
        for name in order:
            steps[name](state)
            assert state.verdict == "needs_review", f"{name} (order {order}) reverted the verdict"
        assert state.verdict not in ("false_positive", "escalate")
