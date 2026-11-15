"""`gate_result.step1_errors` — what the first call got wrong, kept when the repair round fixed it
(DEC-218, spec section 6; `gate_result` stays version 2 and gains one key). PURE.

`step1_errors` is the first call's validator messages when step 1 was `repaired`, else `[]`. They may name a
key the model invented (`reasones: unexpected key`); they are stored with the document and never put in a
prompt. The gate enforces the "else `[]`" itself: a caller that passes messages with `repaired=False` gets none.
"""

from __future__ import annotations

import pytest
from app.security import gate

from tests.fakes.llm import TRIAGE_V3_TRUE_POSITIVE
from tests.test_gate import (
    _facts_from,
    _no_findings,
    _rule_check_holds,
    _true_positive_blocks,
)

FIRST = ["reasones: unexpected key", "reasons: missing"]


def _facts() -> dict:
    return _facts_from(TRIAGE_V3_TRUE_POSITIVE["structured_basis"])


def _start(**kwargs):
    return gate.start(TRIAGE_V3_TRUE_POSITIVE, _facts(), _true_positive_blocks(), **kwargs)


def _result(state) -> dict:
    return gate.gate_result(state, prompt_version="pv", playbook_used_effective=None)


def test_a_repaired_run_carries_the_first_calls_messages():
    state = _start(repaired=True, step1_errors=FIRST)

    assert state.steps["1"] == "repaired"
    assert state.step1_errors == FIRST
    assert _result(state)["step1_errors"] == FIRST


def test_a_run_that_was_valid_at_once_carries_an_empty_list():
    state = _start(repaired=False)

    assert state.steps["1"] == "ok"
    assert state.step1_errors == []
    assert _result(state)["step1_errors"] == []


def test_messages_with_repaired_false_are_dropped_by_the_gate_itself():
    state = _start(repaired=False, step1_errors=FIRST)

    assert state.step1_errors == []
    assert _result(state)["step1_errors"] == []


def test_the_state_and_the_document_hold_their_own_lists():
    given = list(FIRST)
    state = _start(repaired=True, step1_errors=given)
    document = _result(state)

    given.append("later")
    document["step1_errors"].append("mutated")

    assert state.step1_errors == FIRST
    assert _result(state)["step1_errors"] == FIRST


def test_run_steps_1_to_5_passes_them_through():
    state = gate.run_steps_1_to_5(
        TRIAGE_V3_TRUE_POSITIVE,
        _facts(),
        _true_positive_blocks(),
        repaired=True,
        step1_errors=FIRST,
        rule_check=_rule_check_holds,
        scan=_no_findings,
    )

    assert state.step1_errors == FIRST
    assert _result(state)["step1_errors"] == FIRST


def test_run_steps_1_to_5_without_them_is_what_it_was():
    state = gate.run_steps_1_to_5(
        TRIAGE_V3_TRUE_POSITIVE,
        _facts(),
        _true_positive_blocks(),
        repaired=True,
        rule_check=_rule_check_holds,
        scan=_no_findings,
    )

    assert state.step1_errors == []


def test_the_document_is_still_version_2_and_every_other_key_is_where_it_was():
    state = _start(repaired=True, step1_errors=FIRST)
    document = _result(state)

    assert document["version"] == 2
    assert set(document) == {
        "version",
        "proposed_verdict",
        "final_verdict",
        "forced",
        "forced_by",
        "flagged_by",
        "rag_rule",  # DEC-219: on every new run
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


def test_the_messages_do_not_change_the_verdict_or_the_flags():
    with_messages = _start(repaired=True, step1_errors=FIRST)
    without = _start(repaired=True)

    for state in (with_messages, without):
        gate.step2_basis(state)
        gate.step3_quotes(state)
    assert with_messages.verdict == without.verdict
    assert with_messages.flagged_by == without.flagged_by
    assert with_messages.steps == without.steps


@pytest.mark.parametrize("step1_errors", [(), ("a: missing",), ["a: missing"]])
def test_any_sequence_is_accepted_and_stored_as_a_list(step1_errors):
    state = _start(repaired=True, step1_errors=step1_errors)

    assert isinstance(state.step1_errors, list)
    assert state.step1_errors == list(step1_errors)


def test_an_old_document_without_the_key_is_still_read_by_the_verdict_readers():
    """Version 2 documents written before this change have no `step1_errors`; nothing reads it, so they are
    read as ever (`llm.verdicts`)."""
    from app.llm import verdicts

    state = _start(repaired=True, step1_errors=FIRST)
    with_key = _result(state)
    without_key = {k: v for k, v in with_key.items() if k != "step1_errors"}

    assert verdicts.held_reasons(with_key) == verdicts.held_reasons(without_key)
    assert verdicts.proposed_action(with_key) == verdicts.proposed_action(without_key)
