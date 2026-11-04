"""P14-T03 (DEC-213): why the system held ①'s definite verdict - `llm.verdicts.held_reasons` and
`llm.verdicts.proposed_action`, the two readers of `gate_result` the alert view and the queue rows use.

No database. The reasons are a closed set, in the gate's step order (spec 4.3):

    facts_mismatch (step 2), no_verified_quote (step 3), fp_policy:<field> for each entry of step 4's
    `missing`, verifier_disagrees (step 6), verifier_invalid (step 6 when the verifier's answer was
    unusable: `steps["6"] == "invalid"`)

and nothing else ever leaves: a garbled `gate_result` gives `[]`, never an exception.
"""

from __future__ import annotations

import copy

import pytest
from app.llm import verdicts
from app.security import gate, wrap

from tests.fakes.llm import TRIAGE_V2_FALSE_POSITIVE, VERIFIER_V2_AGREE, VERIFIER_V2_DISAGREE

CLOSED = (
    "facts_mismatch",
    "no_verified_quote",
    "fp_policy:severity",
    "fp_policy:ioc_reputation",
    "fp_policy:asset_criticality",
    "fp_policy:identity_privileged",
    "fp_policy:playbook_rule",
    "verifier_disagrees",
    "verifier_invalid",
)


def test_the_closed_reasons_are_the_nine_in_step_order():
    assert verdicts.HELD_REASONS == CLOSED
    # The literal tuple and the fields step 4 can name cannot drift apart.
    assert verdicts.HELD_REASONS == (
        "facts_mismatch",
        "no_verified_quote",
        *(f"fp_policy:{field}" for field in verdicts.FP_POLICY_FIELDS),
        "verifier_disagrees",
        "verifier_invalid",
    )
    assert verdicts.FP_POLICY_FIELDS == (
        "severity",
        "ioc_reputation",
        "asset_criticality",
        "identity_privileged",
        "playbook_rule",
    )


# ── the pure reader ─────────────────────────────────────────────────────────────────────────


def test_a_step_4_gate_result_names_the_missing_field():
    gate_result = {"forced_by": ["step4"], "missing": ["asset_criticality"]}
    assert verdicts.held_reasons(gate_result) == ["fp_policy:asset_criticality"]


def test_each_forcing_step_gives_its_own_reason():
    assert verdicts.held_reasons({"forced_by": ["step2"]}) == ["facts_mismatch"]
    assert verdicts.held_reasons({"forced_by": ["step3"]}) == ["no_verified_quote"]
    assert verdicts.held_reasons({"forced_by": ["step6"]}) == ["verifier_disagrees"]


def test_step_6_with_an_unusable_verifier_answer_is_verifier_invalid_not_disagreement():
    invalid = {"forced_by": ["step6"], "steps": {"6": "invalid"}}
    assert verdicts.held_reasons(invalid) == ["verifier_invalid"]
    for other in ({"6": "disagree"}, {"6": "agree"}, {}, {"5": "findings:0"}):
        assert verdicts.held_reasons({"forced_by": ["step6"], "steps": other}) == [
            "verifier_disagrees"
        ]


def test_an_invalid_verifier_is_named_only_when_step_6_forced_the_verdict():
    # `steps["6"]` alone does not hold anything back: the verdict may have been forced before, and the
    # step only ever forces through `forced_by`.
    assert verdicts.held_reasons({"forced_by": [], "steps": {"6": "invalid"}}) == []
    assert verdicts.held_reasons({"forced_by": ["step2"], "steps": {"6": "invalid"}}) == [
        "facts_mismatch"
    ]


@pytest.mark.parametrize("steps", [None, "6", ["6"], {"6": ["invalid"]}, {6: "invalid"}, 7])
def test_a_garbled_steps_value_reads_as_a_plain_disagreement(steps):
    assert verdicts.held_reasons({"forced_by": ["step6"], "steps": steps}) == ["verifier_disagrees"]


def test_the_reasons_come_in_step_order_whatever_the_order_of_forced_by():
    gate_result = {
        "forced_by": ["step6", "step4", "step3", "step2"],
        "missing": ["identity_privileged", "playbook_rule"],
    }
    assert verdicts.held_reasons(gate_result) == [
        "facts_mismatch",
        "no_verified_quote",
        "fp_policy:identity_privileged",
        "fp_policy:playbook_rule",
        "verifier_disagrees",
    ]


def test_every_missing_entry_is_a_reason_in_the_order_of_missing():
    missing = ["severity", "ioc_reputation", "asset_criticality", "identity_privileged"]
    assert verdicts.held_reasons({"forced_by": ["step4"], "missing": missing}) == [
        f"fp_policy:{field}" for field in missing
    ]
    assert verdicts.held_reasons(
        {"forced_by": ["step4"], "missing": ["playbook_rule", "severity"]}
    ) == [
        "fp_policy:playbook_rule",
        "fp_policy:severity",
    ]


def test_a_verdict_the_gate_kept_has_no_reasons():
    kept = {"forced": False, "forced_by": [], "missing": []}
    assert verdicts.held_reasons(kept) == []


def test_only_closed_values_ever_leave():
    gate_result = {
        "forced_by": ["step4", "step9", "step3", 7, None, "step3"],
        "missing": ["asset_criticality", "<script>", "asset_criticality", 3, None, "x" * 500],
    }
    reasons = verdicts.held_reasons(gate_result)
    assert reasons == ["no_verified_quote", "fp_policy:asset_criticality"]
    assert set(reasons) <= set(verdicts.HELD_REASONS)


@pytest.mark.parametrize(
    "garbled",
    [
        None,
        {},
        [],
        "step4",
        7,
        {"forced_by": None, "missing": None},
        {"forced_by": "step4", "missing": "asset_criticality"},
        {"forced_by": {"step4": True}, "missing": {"severity": 1}},
        {"forced_by": [["step2"]], "missing": [["severity"]]},
    ],
)
def test_a_missing_or_garbled_gate_result_gives_no_reasons_and_no_exception(garbled):
    assert verdicts.held_reasons(garbled) == []


# ── the model's own answer ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("answer", ["false_positive", "true_positive"])
def test_proposed_action_is_the_models_definite_answer(answer):
    assert verdicts.proposed_action({"proposed_verdict": answer}) == answer


@pytest.mark.parametrize(
    "gate_result",
    [
        None,
        {},
        [],
        "true_positive",
        {"proposed_verdict": None},
        {"proposed_verdict": "needs_review"},
        {"proposed_verdict": "escalate"},
        {"proposed_verdict": ["true_positive"]},
        {"proposed_verdict": 1},
        {"final_verdict": "true_positive"},
    ],
)
def test_proposed_action_is_none_unless_it_is_one_the_model_may_answer(gate_result):
    assert verdicts.proposed_action(gate_result) is None


# ── against a real gate_result ──────────────────────────────────────────────────────────────


def _facts(basis: dict, **over) -> dict:
    facts = {
        k: basis[k]
        for k in (
            "severity",
            "ioc_reputation",
            "asset_criticality",
            "identity_privileged",
            "occurrence_count",
        )
    }
    facts.update(over)
    return facts


def _blocks(payload: dict, *, quote: str | None = None) -> dict[str, wrap.Block]:
    reason = payload["reasons"][0]
    return {
        reason["source"]: wrap.untrusted_block(
            (quote or reason["quote"]) + " - trailing context",
            reason["source"],
            nonce=wrap.new_nonce(),
        )
    }


#: The verifier agreeing with a ``false_positive`` that survived steps 2-4.
_VERIFIER_FP_AGREES = {**VERIFIER_V2_AGREE, "structured_only_verdict": "false_positive"}


_DEFAULT = object()


def _run(proposal: dict, *, facts: dict, blocks: dict, holds: bool = True, verifier=_DEFAULT):
    """The real gate, steps 1-7. ``verifier=None`` is a verifier whose answer did not parse."""
    state = gate.run_steps_1_to_5(
        proposal,
        facts,
        blocks,
        repaired=False,
        rule_check=lambda _rule: (holds, None),
        scan=lambda _blocks: [],
    )
    gate.finish(state, _VERIFIER_FP_AGREES if verifier is _DEFAULT else verifier)
    return gate.gate_result(state, prompt_version="pv", playbook_used_effective=None)


def test_a_high_criticality_asset_is_held_for_that_field_only():
    basis = dict(TRIAGE_V2_FALSE_POSITIVE["structured_basis"], asset_criticality="high")
    proposal = {**copy.deepcopy(TRIAGE_V2_FALSE_POSITIVE), "structured_basis": basis}
    result = _run(
        proposal,
        facts=_facts(basis),
        blocks=_blocks(proposal),
        verifier={**VERIFIER_V2_AGREE, "structured_only_verdict": "needs_review"},
    )
    assert (
        result["proposed_verdict"] == "false_positive" and result["final_verdict"] == "needs_review"
    )
    assert verdicts.held_reasons(result) == ["fp_policy:asset_criticality"]
    assert verdicts.proposed_action(result) == "false_positive"


def test_a_basis_mismatch_and_a_dropped_quote_and_a_verifier_that_disagrees_are_all_named():
    proposal = copy.deepcopy(TRIAGE_V2_FALSE_POSITIVE)
    facts = _facts(proposal["structured_basis"], severity="critical")
    blocks = _blocks(proposal, quote="a line the model never quoted")
    result = _run(proposal, facts=facts, blocks=blocks, verifier=VERIFIER_V2_DISAGREE)
    reasons = verdicts.held_reasons(result)
    assert reasons[0] == "facts_mismatch"
    assert reasons[1] == "no_verified_quote"
    assert reasons[-1] == "verifier_disagrees"
    assert set(reasons) <= set(verdicts.HELD_REASONS)


def test_a_missing_playbook_rule_is_a_reason_of_its_own():
    proposal = copy.deepcopy(TRIAGE_V2_FALSE_POSITIVE)
    result = _run(
        proposal,
        facts=_facts(proposal["structured_basis"]),
        blocks=_blocks(proposal),
        holds=False,
        verifier={**VERIFIER_V2_AGREE, "structured_only_verdict": "needs_review"},
    )
    assert "fp_policy:playbook_rule" in verdicts.held_reasons(result)


def test_a_verdict_the_gate_kept_is_not_held():
    proposal = copy.deepcopy(TRIAGE_V2_FALSE_POSITIVE)
    result = _run(proposal, facts=_facts(proposal["structured_basis"]), blocks=_blocks(proposal))
    assert result["forced"] is False
    assert verdicts.held_reasons(result) == []
    assert verdicts.proposed_action(result) == "false_positive"


def test_a_verifier_whose_answer_did_not_parse_is_verifier_invalid_from_the_real_gate():
    proposal = copy.deepcopy(TRIAGE_V2_FALSE_POSITIVE)
    result = _run(
        proposal,
        facts=_facts(proposal["structured_basis"]),
        blocks=_blocks(proposal),
        verifier=None,
    )
    assert result["steps"]["6"] == "invalid" and result["forced_by"] == ["step6"]
    assert result["final_verdict"] == "needs_review"
    assert verdicts.held_reasons(result) == ["verifier_invalid"]
    assert verdicts.proposed_action(result) == "false_positive"


def test_a_verifier_that_disagrees_is_verifier_disagrees_from_the_real_gate():
    proposal = copy.deepcopy(TRIAGE_V2_FALSE_POSITIVE)
    result = _run(
        proposal,
        facts=_facts(proposal["structured_basis"]),
        blocks=_blocks(proposal),
        verifier=VERIFIER_V2_DISAGREE,
    )
    assert result["steps"]["6"] == "disagree"
    assert verdicts.held_reasons(result) == ["verifier_disagrees"]


def test_an_invalid_verifier_after_an_earlier_force_names_both():
    proposal = copy.deepcopy(TRIAGE_V2_FALSE_POSITIVE)
    facts = _facts(proposal["structured_basis"], severity="critical")
    result = _run(proposal, facts=facts, blocks=_blocks(proposal), verifier=None)
    assert verdicts.held_reasons(result) == ["facts_mismatch", "verifier_invalid"]


# ── FP_POLICY_FIELDS against the real step 4 (every field, not two of the five) ──────────────

#: What makes each field fail step 4 (``security/gate.py``, ``step4_fp_policy``): the basis the model
#: wrote and the DB facts must agree (step 2), so the basis carries the value too.
_FAILS_STEP_4 = {
    "severity": {"severity": "critical"},
    "ioc_reputation": {"ioc_reputation": "malicious"},
    "asset_criticality": {"asset_criticality": "high"},
    "identity_privileged": {"identity_privileged": "true"},
}


def _step_4(fields: list[str]):
    """The real gate with exactly ``fields`` failing step 4 (``playbook_rule`` through the rule check)."""
    over: dict = {}
    for field in fields:
        over.update(_FAILS_STEP_4.get(field, {}))
    basis = {**TRIAGE_V2_FALSE_POSITIVE["structured_basis"], **over}
    proposal = {**copy.deepcopy(TRIAGE_V2_FALSE_POSITIVE), "structured_basis": basis}
    return _run(
        proposal,
        facts=_facts(basis),
        blocks=_blocks(proposal),
        holds="playbook_rule" not in fields,
        verifier={**VERIFIER_V2_AGREE, "structured_only_verdict": "needs_review"},
    )


@pytest.mark.parametrize("field", verdicts.FP_POLICY_FIELDS)
def test_each_field_step_4_can_name_is_a_reason_from_the_real_gate(field):
    result = _step_4([field])
    assert result["forced_by"] == ["step4"] and result["missing"] == [field]
    assert verdicts.held_reasons(result) == [f"fp_policy:{field}"]


def test_step_4_names_all_five_fields_in_the_order_of_fp_policy_fields():
    result = _step_4(list(verdicts.FP_POLICY_FIELDS))
    assert result["missing"] == list(verdicts.FP_POLICY_FIELDS)
    assert verdicts.held_reasons(result) == [f"fp_policy:{f}" for f in verdicts.FP_POLICY_FIELDS]
