"""DB tests for P14-T03 (DEC-213): the queue rows and the alert view carry ①'s own conclusion
(`proposed_action`, `gate_result.proposed_verdict`) and why the system held it (`held_by`,
`llm.verdicts.held_reasons`) - and the blind arm (DEC-101) shows neither.

The fixtures are `test_queue.py`'s: a head through the real transitions, and one `llm_runs` row
inserted in P3-T10's shape. Every test runs in the `db` fixture's transaction.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from app.domain.transitions import acknowledge, decide
from app.llm import verdicts
from app.tier1 import queue
from app.tier1.queue import get_alert_view
from app.tier1.visibility import ANALYST_HIDE, LABELING_DENYLIST

from tests.test_queue import (
    GATE,
    RESULT,
    USER_ID,
    _all_rows,
    _duplicate,
    _insert_run,
    _queued,
    _row,
    _seed_user,
    _walk_keys,
)

#: The model concluded `false_positive`; gate step 4 held it on a critical asset (P14-T03 spec 4.3).
HELD_RESULT: dict[str, Any] = {**RESULT, "suggested_action": "needs_review", "confidence": "medium"}
HELD_GATE: dict[str, Any] = {
    **GATE,
    "proposed_verdict": "false_positive",
    "final_verdict": "needs_review",
    "forced": True,
    "forced_by": ["step4"],
    "missing": ["asset_criticality"],
}
TRUE_POSITIVE_RESULT: dict[str, Any] = {**RESULT, "suggested_action": "true_positive"}
TRUE_POSITIVE_GATE: dict[str, Any] = {
    **GATE,
    "proposed_verdict": "true_positive",
    "final_verdict": "true_positive",
    "verifier_verdict": "true_positive",
}


# ── a true_positive run is shown as it is ───────────────────────────────────────────────────


@pytest.mark.db
def test_queue_row_of_a_true_positive_run(db):
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, result=TRUE_POSITIVE_RESULT, gate_result=TRUE_POSITIVE_GATE)

    row = _row(db, alert_id)

    assert row["suggested_action"] == "true_positive"
    assert row["proposed_action"] == "true_positive"
    assert row["held_by"] == []
    assert row["gate_forced"] is False


@pytest.mark.db
def test_alert_view_of_a_true_positive_run(db):
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, result=TRUE_POSITIVE_RESULT, gate_result=TRUE_POSITIVE_GATE)

    view = get_alert_view(db, alert_id)

    assert view["suggestion"]["suggested_action"] == "true_positive"
    assert view["proposed_action"] == "true_positive"
    assert view["held_by"] == []


# ── a held verdict names the model's answer and the reasons ─────────────────────────────────


@pytest.mark.db
def test_queue_row_of_a_held_verdict_names_the_models_answer_and_the_field(db):
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, result=HELD_RESULT, gate_result=HELD_GATE)

    row = _row(db, alert_id)

    assert row["suggested_action"] == "needs_review"
    assert row["proposed_action"] == "false_positive"
    assert row["held_by"] == ["fp_policy:asset_criticality"]
    assert row["gate_forced"] is True


@pytest.mark.db
def test_alert_view_of_a_held_verdict_names_the_models_answer_and_the_field(db):
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, result=HELD_RESULT, gate_result=HELD_GATE)

    view = get_alert_view(db, alert_id)

    assert view["proposed_action"] == "false_positive"
    assert view["held_by"] == ["fp_policy:asset_criticality"]
    assert view["suggestion"]["suggested_action"] == "needs_review"


@pytest.mark.db
def test_several_reasons_come_in_step_order_in_the_row_and_the_view(db):
    gate_result = {
        **HELD_GATE,
        "forced_by": ["step2", "step4", "step6"],
        "missing": ["severity", "playbook_rule"],
    }
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, result=HELD_RESULT, gate_result=gate_result)
    expected = [
        "facts_mismatch",
        "fp_policy:severity",
        "fp_policy:playbook_rule",
        "verifier_disagrees",
    ]

    assert _row(db, alert_id)["held_by"] == expected
    assert get_alert_view(db, alert_id)["held_by"] == expected


@pytest.mark.db
def test_the_row_and_the_view_agree_with_held_reasons_and_proposed_action(db):
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, result=HELD_RESULT, gate_result=HELD_GATE)

    row, view = _row(db, alert_id), get_alert_view(db, alert_id)

    for shown in (row, view):
        assert shown["held_by"] == verdicts.held_reasons(HELD_GATE)
        assert shown["proposed_action"] == verdicts.proposed_action(HELD_GATE)


# ── no run, a failed run, a garbled gate_result ─────────────────────────────────────────────


@pytest.mark.db
def test_no_run_gives_none_and_an_empty_list(db):
    alert_id = _queued(db, suggestion_visible=True)

    row, view = _row(db, alert_id), get_alert_view(db, alert_id)

    for shown in (row, view):
        assert shown["proposed_action"] is None
        assert shown["held_by"] == []


@pytest.mark.db
def test_a_failed_newest_run_is_not_replaced_by_an_older_held_one(db):
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, result=HELD_RESULT, gate_result=HELD_GATE, offset_s=0)
    _insert_run(db, alert_id, result=None, gate_result=None, stopped_by="schema", offset_s=5)

    row, view = _row(db, alert_id), get_alert_view(db, alert_id)

    for shown in (row, view):
        assert shown["proposed_action"] is None
        assert shown["held_by"] == []


@pytest.mark.db
@pytest.mark.parametrize(
    "garbled",
    [
        {},
        {"forced_by": "step4", "missing": "asset_criticality", "proposed_verdict": ["x"]},
        {"forced_by": [1, None], "missing": {"a": 1}, "proposed_verdict": "escalate"},
    ],
)
def test_a_garbled_gate_result_gives_none_and_an_empty_list(db, garbled):
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, result=HELD_RESULT, gate_result=garbled)

    row, view = _row(db, alert_id), get_alert_view(db, alert_id)

    for shown in (row, view):
        assert shown["proposed_action"] is None
        assert shown["held_by"] == []


@pytest.mark.db
def test_a_null_gate_result_gives_none_and_an_empty_list(db):
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, result=HELD_RESULT, gate_result=None)

    row, view = _row(db, alert_id), get_alert_view(db, alert_id)

    for shown in (row, view):
        assert shown["proposed_action"] is None
        assert shown["held_by"] == []


@pytest.mark.db
def test_a_duplicates_view_carries_its_heads_conclusion(db):
    head = _queued(db, suggestion_visible=True)
    duplicate = _duplicate(db, head)
    _insert_run(db, head, result=HELD_RESULT, gate_result=HELD_GATE)

    view = get_alert_view(db, duplicate)

    assert view["alert_id"] == head
    assert view["held_by"] == ["fp_policy:asset_criticality"]


@pytest.mark.db
def test_the_queue_rows_stay_one_statement(db):
    """`held_by` and `proposed_action` come out of the queue's own SELECT (a narrow `jsonb` of three gate
    keys, never the whole `gate_result` with its facts): no statement per row."""
    for _ in range(3):
        alert_id = _queued(db, suggestion_visible=True)
        _insert_run(db, alert_id, result=HELD_RESULT, gate_result=HELD_GATE)

    with _count_statements(db) as statements:
        rows = _all_rows(db)

    assert len([r for r in rows if r.get("held_by")]) == 3
    assert len([s for s in statements if "FROM llm_runs" in s]) == 1


class _count_statements:
    """Collect the text of every statement `conn.execute` runs inside the block."""

    def __init__(self, conn):
        self.conn = conn
        self.statements: list[str] = []

    def __enter__(self) -> list[str]:
        self.original = self.conn.execute

        def spy(query, *args, **kwargs):
            self.statements.append(str(query))
            return self.original(query, *args, **kwargs)

        self.conn.execute = spy
        return self.statements

    def __exit__(self, *exc) -> None:
        self.conn.execute = self.original


@pytest.mark.db
def test_the_alert_view_reads_the_newest_run_once_for_the_suggestion_and_the_held_reasons(db):
    """Fix round 1 (M2): `proposed_action` and `held_by` come out of the very row the suggestion is built
    from (`_SUGGESTION_SQL`), so "the same run" is true by construction. The view's other `llm_runs` read
    is the stop reason (`_STOPPED_BY_SQL`), so two statements, not three."""
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, result=HELD_RESULT, gate_result=HELD_GATE)

    with _count_statements(db) as statements:
        view = get_alert_view(db, alert_id)

    assert view["held_by"] == ["fp_policy:asset_criticality"]
    assert len([s for s in statements if "FROM llm_runs" in s]) == 2


@pytest.mark.db
def test_a_run_inserted_between_the_reads_cannot_pair_one_runs_suggestion_with_anothers_reasons(db):
    """A newer proposer run lands right after the suggestion row was read (READ COMMITTED lets it): the
    view must say what the run it read says - the suggestion, `proposed_action` and `held_by` of one run.
    """
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, result=HELD_RESULT, gate_result=HELD_GATE, offset_s=0)
    newer_gate = {**HELD_GATE, "proposed_verdict": "true_positive", "forced_by": ["step6"]}
    newer_gate["missing"] = []
    original = db.execute
    fired: list[bool] = []

    def spy(query, *args, **kwargs):
        answer = original(query, *args, **kwargs)
        if not fired and "FROM llm_runs" in str(query):
            fired.append(True)
            _insert_run(db, alert_id, result=HELD_RESULT, gate_result=newer_gate, offset_s=5)
        return answer

    db.execute = spy  # type: ignore[method-assign]
    try:
        view = get_alert_view(db, alert_id)
    finally:
        db.execute = original  # type: ignore[method-assign]

    assert fired
    assert view["suggestion"]["gate"]["forced_by"] == ["step4"]
    assert view["proposed_action"] == "false_positive"
    assert view["held_by"] == ["fp_policy:asset_criticality"]


# ── the blind arm (DEC-101) ─────────────────────────────────────────────────────────────────


@pytest.mark.db
def test_a_blind_undecided_row_has_neither_key(db):
    alert_id = _queued(db, suggestion_visible=False)
    _insert_run(db, alert_id, result=HELD_RESULT, gate_result=HELD_GATE)

    row = _row(db, alert_id)

    assert "proposed_action" not in row and "held_by" not in row
    for key in ANALYST_HIDE:
        assert key not in row, key
    assert "fp_policy:asset_criticality" not in json.dumps(row, default=str)


@pytest.mark.db
def test_a_blind_undecided_view_has_neither_key(db):
    alert_id = _queued(db, suggestion_visible=False)
    _insert_run(db, alert_id, result=HELD_RESULT, gate_result=HELD_GATE)

    view = get_alert_view(db, alert_id)

    assert "proposed_action" not in view and "held_by" not in view
    assert "suggestion" not in view
    assert "fp_policy:asset_criticality" not in json.dumps(view, default=str)


@pytest.mark.db
def test_a_decision_brings_the_conclusion_back_on_the_blind_arm(db):
    _seed_user(db)
    alert_id = _queued(db, suggestion_visible=False, risk_score=30)
    _insert_run(db, alert_id, result=HELD_RESULT, gate_result=HELD_GATE)
    acknowledge(db, alert_id, USER_ID)
    assert "held_by" not in get_alert_view(db, alert_id)  # still undecided, still blind

    decide(
        db,
        alert_id,
        USER_ID,
        decision="closed_benign",
        reason="benign",
        seen_occurrence_count=1,
        llm_suggestion=None,
        llm_confidence=None,
    )
    view = get_alert_view(db, alert_id)

    assert view["status"] == "closed_benign"
    assert view["proposed_action"] == "false_positive"
    assert view["held_by"] == ["fp_policy:asset_criticality"]


@pytest.mark.db
@pytest.mark.parametrize("suggestion_visible", [True, False], ids=["visible", "blind"])
def test_the_labelling_page_never_has_either_key(db, suggestion_visible):
    alert_id = _queued(db, suggestion_visible=suggestion_visible)
    _insert_run(db, alert_id, result=HELD_RESULT, gate_result=HELD_GATE)

    labelling = get_alert_view(db, alert_id, mode="labeling")

    keys = set(_walk_keys(labelling))
    assert "proposed_action" not in keys and "held_by" not in keys
    assert not keys & LABELING_DENYLIST
    assert "fp_policy" not in json.dumps(labelling, default=str)
    # the control: the analyst view of the same head has them on the visible arm
    analyst = get_alert_view(db, alert_id)
    assert ("held_by" in analyst) is suggestion_visible


def test_the_two_keys_are_hidden_on_the_blind_arm_and_from_the_labeller():
    assert {"proposed_action", "held_by"} <= ANALYST_HIDE
    assert {"proposed_action", "held_by"} <= LABELING_DENYLIST


def test_suggestion_keeps_its_shape():
    """The held reasons are a sibling read of the same run, not a new field of `Suggestion`: the shape
    P4's `decide` and the digest consume is unchanged."""
    assert set(queue.Suggestion.__dataclass_fields__) == {
        "run_id",
        "suggested_action",
        "confidence",
        "reasons",
        "gate",
        "correlated_at_analysis",
        "created_at",
    }
