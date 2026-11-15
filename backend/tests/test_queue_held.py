"""P14-T03 (DEC-213), DEC-217: the queue rows and the alert view carry ①'s own conclusion
(`proposed_action`, `gate_result.proposed_verdict`) and which checks raised a warning on it (`held_by`,
`llm.verdicts.held_reasons`) - and the blind arm (DEC-101) shows neither.

DEC-217 (BV-T1, G3): Tier 1 is served the model's verdict. A new run stores it (`gate_result` version 2,
`flagged_by`); a stored run the old gate held (version 1: `suggested_action` `needs_review`, `forced_by`)
is served as its `proposed_verdict` (`verdicts.served_action`), in the alert view (`Suggestion`) and in the
queue list's `suggested_action` column, without a new model call and without touching `llm_runs`. The
version 1 fixtures below (`HELD_RESULT`, `HELD_GATE`) are exactly such stored rows.

The fixtures are `test_queue.py`'s: a head through the real transitions, and one `llm_runs` row
inserted in P3-T10's shape. The `db` tests run in the `db` fixture's transaction; the ones without the
mark need no database (`_suggestion_of`, and the SQL of the queue's `suggested_action` column run on
an in-memory SQLite, whose `->>` is PostgreSQL's for these documents).
"""

from __future__ import annotations

import copy
import json
import sqlite3
from datetime import UTC, datetime
from typing import Any

import pytest
from app.domain.transitions import acknowledge, decide
from app.llm import verdicts
from app.tier1 import queue
from app.tier1.queue import get_alert_view
from app.tier1.visibility import ANALYST_HIDE, LABELING_DENYLIST

from tests.fakes.llm import TRIAGE_V2_FALSE_POSITIVE, VERIFIER_V2_DISAGREE
from tests.test_held_reasons import _blocks, _facts, _run
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

#: A VERSION 1 run: the model concluded `false_positive`; gate step 4 held it on a critical asset
#: (P14-T03 spec 4.3). `llm_runs` is immutable, so rows like this one stay in the database (DEC-217).
HELD_RESULT: dict[str, Any] = {**RESULT, "suggested_action": "needs_review", "confidence": "medium"}
HELD_GATE: dict[str, Any] = {
    **GATE,
    "version": 1,
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
#: A VERSION 2 run (DEC-217): step 4 flagged the model's own `false_positive`; the verdict is stored as it is.
FLAGGED_RESULT: dict[str, Any] = {
    **RESULT,
    "suggested_action": "false_positive",
    "confidence": "medium",
}
FLAGGED_GATE: dict[str, Any] = {
    **GATE,
    "version": 2,
    "proposed_verdict": "false_positive",
    "final_verdict": "false_positive",
    "forced": False,
    "forced_by": [],
    "flagged_by": ["step4"],
    "missing": ["asset_criticality"],
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

    # DEC-217: the row stores `needs_review` (version 1), Tier 1 is shown the model's own verdict
    assert row["suggested_action"] == "false_positive"
    assert row["proposed_action"] == "false_positive"
    assert row["held_by"] == ["fp_policy:asset_criticality"]
    assert row["gate_forced"] is True  # what is stored, for a version 1 row


@pytest.mark.db
def test_alert_view_of_a_held_verdict_names_the_models_answer_and_the_field(db):
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, result=HELD_RESULT, gate_result=HELD_GATE)

    view = get_alert_view(db, alert_id)

    assert view["proposed_action"] == "false_positive"
    assert view["held_by"] == ["fp_policy:asset_criticality"]
    assert view["suggestion"]["suggested_action"] == "false_positive"  # served, not the stored one
    assert view["suggestion"]["gate"]["forced"] is True  # the version 1 gate, as stored


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


# ── DEC-217 G3: a stored version 1 `needs_review` row is served as the model's own verdict ────


@pytest.mark.db
@pytest.mark.parametrize("proposed", ["false_positive", "true_positive"])
def test_a_stored_needs_review_is_served_as_its_proposed_verdict_in_the_queue_list(db, proposed):
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(
        db,
        alert_id,
        result=HELD_RESULT,
        gate_result={**HELD_GATE, "proposed_verdict": proposed},
    )

    row = _row(db, alert_id)

    assert row["suggested_action"] == proposed
    assert row["proposed_action"] == proposed


@pytest.mark.db
@pytest.mark.parametrize("proposed", ["false_positive", "true_positive"])
def test_a_stored_needs_review_is_served_as_its_proposed_verdict_in_the_alert_view(db, proposed):
    alert_id = _queued(db, suggestion_visible=True)
    gate_result = {**HELD_GATE, "proposed_verdict": proposed}
    _insert_run(db, alert_id, result=HELD_RESULT, gate_result=gate_result)

    view = get_alert_view(db, alert_id)
    suggestion = queue.latest_suggestion(db, alert_id)

    assert view["suggestion"]["suggested_action"] == proposed
    assert suggestion is not None and suggestion.suggested_action == proposed
    assert queue.latest_suggestions(db, [alert_id])[alert_id].suggested_action == proposed


@pytest.mark.db
def test_the_stored_row_is_not_touched_by_serving_it(db):
    alert_id = _queued(db, suggestion_visible=True)
    run_id = _insert_run(db, alert_id, result=HELD_RESULT, gate_result=HELD_GATE)

    _row(db, alert_id)
    get_alert_view(db, alert_id)

    stored = db.execute(
        "SELECT result->>'suggested_action', gate_result->>'final_verdict' FROM llm_runs "
        "WHERE run_id = %s",
        (run_id,),
    ).fetchone()
    assert stored == ("needs_review", "needs_review")


@pytest.mark.db
@pytest.mark.parametrize(
    "gate_result",
    [None, {}, {"proposed_verdict": "needs_review"}, {"proposed_verdict": 1}],
    ids=["null", "empty", "needs_review", "garbled"],
)
def test_a_stored_needs_review_with_no_usable_proposed_verdict_is_served_as_none(db, gate_result):
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, result=HELD_RESULT, gate_result=gate_result)

    assert _row(db, alert_id)["suggested_action"] is None
    assert get_alert_view(db, alert_id)["suggestion"]["suggested_action"] is None


@pytest.mark.db
def test_a_version_2_run_is_served_as_stored_with_its_warnings(db):
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, result=FLAGGED_RESULT, gate_result=FLAGGED_GATE)

    row, view = _row(db, alert_id), get_alert_view(db, alert_id)

    for shown in (row, view):
        assert shown["proposed_action"] == "false_positive"
        assert shown["held_by"] == ["fp_policy:asset_criticality"]  # read from `flagged_by`
    assert row["suggested_action"] == "false_positive"
    assert row["gate_forced"] is False
    assert view["suggestion"]["suggested_action"] == "false_positive"
    assert view["suggestion"]["gate"]["forced"] is False


@pytest.mark.db
def test_a_version_2_run_flagged_by_every_check_names_them_all_in_the_row_and_the_view(db):
    gate_result = {
        **FLAGGED_GATE,
        "flagged_by": ["step2", "step3", "step4", "step6"],
        "missing": ["severity", "playbook_rule"],
        "steps": {"6": "disagree"},
    }
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, result=FLAGGED_RESULT, gate_result=gate_result)
    expected = [
        "facts_mismatch",
        "no_verified_quote",
        "fp_policy:severity",
        "fp_policy:playbook_rule",
        "verifier_disagrees",
    ]

    assert _row(db, alert_id)["held_by"] == expected
    assert get_alert_view(db, alert_id)["held_by"] == expected


@pytest.mark.db
def test_a_version_1_row_still_reads_its_forced_by_in_the_queue_projection(db):
    """The queue's projection now carries `flagged_by` too; for a version 1 row that is `null`, and the
    old reasons must still come out of `forced_by`."""
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, result=HELD_RESULT, gate_result=HELD_GATE)

    assert "flagged_by" not in HELD_GATE
    assert _row(db, alert_id)["held_by"] == ["fp_policy:asset_criticality"]


# ── the same, with no database: `_suggestion_of`, and the SQL twin of `served_action` ─────────


_NOW = datetime(2026, 11, 15, 9, 0, tzinfo=UTC)


@pytest.mark.parametrize("proposed", ["false_positive", "true_positive"])
def test_suggestion_of_serves_a_stored_needs_review_as_the_proposed_verdict(proposed):
    got = queue._suggestion_of(
        "run-1", HELD_RESULT, {**HELD_GATE, "proposed_verdict": proposed}, _NOW
    )

    assert got is not None
    assert got.suggested_action == proposed
    assert got.confidence == "medium"
    # the gate as stored, version 1 included: the page's gate line is a record
    assert got.gate["forced"] is True and got.gate["forced_by"] == ["step4"]
    assert got.gate["final_verdict"] == "needs_review"


def test_suggestion_of_keeps_a_stored_definite_verdict():
    for result, gate_result in (
        (TRUE_POSITIVE_RESULT, TRUE_POSITIVE_GATE),
        (FLAGGED_RESULT, FLAGGED_GATE),
        # the stored verdict wins over a gate_result that says something else
        ({**RESULT, "suggested_action": "true_positive"}, GATE),
    ):
        got = queue._suggestion_of("run-1", result, gate_result, _NOW)
        assert got is not None and got.suggested_action == result["suggested_action"]


@pytest.mark.parametrize("gate_result", [None, {}, [], "x", {"proposed_verdict": "needs_review"}])
def test_suggestion_of_a_stored_needs_review_with_no_proposed_verdict_has_none(gate_result):
    got = queue._suggestion_of("run-1", HELD_RESULT, gate_result, _NOW)

    assert got is not None and got.suggested_action is None


def test_suggestion_of_a_failed_run_is_still_no_suggestion():
    assert queue._suggestion_of("run-1", None, HELD_GATE, _NOW) is None


#: What the queue's `suggested_action` column is for every stored/proposed pair the database can hold.
_STORED = ["false_positive", "needs_review", "true_positive", "escalate", None, 5]
_PROPOSED = ["false_positive", "true_positive", "needs_review", "escalate", None, 1]


def _sql_served(stored: Any, proposed: Any) -> str | None:
    """The queue's SQL expression for the served verdict, run on one stored/proposed pair. `r` is the
    LATERAL alias of `_QUEUE_SQL`; the two documents are JSON text, as `->>` reads them."""
    result = json.dumps({"suggested_action": stored})
    gate_result = json.dumps({"proposed_verdict": proposed})
    with sqlite3.connect(":memory:") as conn:
        return conn.execute(
            f"SELECT {queue._SERVED_ACTION_SQL} FROM (SELECT ? AS result, ? AS gate_result) r",
            (result, gate_result),
        ).fetchone()[0]


@pytest.mark.parametrize("stored", _STORED, ids=repr)
@pytest.mark.parametrize("proposed", _PROPOSED, ids=repr)
def test_the_queue_sql_serves_what_served_action_serves(stored, proposed):
    expected = verdicts.served_action({"suggested_action": stored}, {"proposed_verdict": proposed})

    assert _sql_served(stored, proposed) == expected


def test_the_queue_list_selects_the_served_verdict_not_the_stored_one():
    """The statement `list_queue` runs names the served expression for its `suggested_action` column, and
    not the bare stored value (`r.result->>'suggested_action'` alone, version 1's `needs_review` too).
    """
    statements: list[str] = []

    class _Cursor:
        def fetchall(self):
            return []

        def fetchone(self):
            return (0,)

    class _Conn:
        def execute(self, statement, params=None):
            statements.append(str(statement))
            return _Cursor()

    queue.list_queue(_Conn())  # type: ignore[arg-type]

    (listing,) = [s for s in statements if "FROM alerts a" in s and "LATERAL" in s]
    assert (
        "r.result->>'suggested_action',\n" not in listing
    )  # no bare stored value in the select list
    assert queue._SERVED_ACTION_SQL in listing


# ── step 6: a queue row and the alert view of the same run name the same reason ──────────────

#: What step 6 records (`security/gate.py`, `step6_verifier`): the verifier's answer did not parse
#: (`invalid`), or it parsed and disagreed (`disagree`). Both force `needs_review` through `step6`.
_STEP_6 = [("invalid", "verifier_invalid"), ("disagree", "verifier_disagrees")]


def _step_6_gate(outcome: str) -> dict[str, Any]:
    return {
        **GATE,
        "proposed_verdict": "false_positive",
        "final_verdict": "needs_review",
        "forced": True,
        "forced_by": ["step6"],
        "missing": [],
        "verifier_verdict": None if outcome == "invalid" else "needs_review",
        "steps": {
            "1": "ok",
            "2": "ok",
            "3": "dropped:0",
            "4": "ok",
            "5": "findings:0",
            "6": outcome,
        },
    }


@pytest.mark.db
@pytest.mark.parametrize(("outcome", "reason"), _STEP_6)
def test_a_queue_row_and_the_alert_view_of_the_same_run_agree_on_step_6(db, outcome, reason):
    """Fix round 2 (M3): the queue's gate projection carries step 6's outcome, so its `held_by` is the
    alert view's, run for run - an unusable verifier is `verifier_invalid` in both, a disagreeing one
    `verifier_disagrees` in both."""
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, result=HELD_RESULT, gate_result=_step_6_gate(outcome))

    row, view = _row(db, alert_id), get_alert_view(db, alert_id)

    assert row["held_by"] == [reason]
    assert view["held_by"] == [reason]
    assert row["proposed_action"] == view["proposed_action"] == "false_positive"


@pytest.mark.db
@pytest.mark.parametrize(("verifier", "reason"), [(None, "verifier_invalid"), (False, None)])
def test_a_real_gate_result_gives_the_row_and_the_view_the_same_held_by(db, verifier, reason):
    """The same, with the gate_result the real gate writes (`gate.finish(state, None)` for an answer that
    did not parse; a disagreeing verifier for the other), so the stored shape is the one the projection reads.
    """
    proposal = copy.deepcopy(TRIAGE_V2_FALSE_POSITIVE)
    stored = _run(
        proposal,
        facts=_facts(proposal["structured_basis"]),
        blocks=_blocks(proposal),
        verifier=None if verifier is None else VERIFIER_V2_DISAGREE,
    )
    expected = verdicts.held_reasons(stored)
    assert expected == [reason or "verifier_disagrees"]
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, result=FLAGGED_RESULT, gate_result=stored)

    row, view = _row(db, alert_id), get_alert_view(db, alert_id)

    assert row["held_by"] == view["held_by"] == expected


@pytest.mark.db
def test_the_gate_projection_of_a_queue_row_holds_step_6_and_not_the_whole_gate_result(db):
    """Only what `held_reasons` reads leaves the database: three gate keys and step 6's outcome, never
    `facts` or `proposer_raw`; and the rows are still one statement."""
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, result=HELD_RESULT, gate_result=_step_6_gate("invalid"))

    with _count_statements(db) as statements:
        rows = _all_rows(db)

    queue_statements = [s for s in statements if "FROM llm_runs" in s]
    assert len(queue_statements) == 1
    assert "'steps'" in queue_statements[0] and "'6'" in queue_statements[0]
    assert (
        "r.gate_result," not in queue_statements[0]
    )  # the column list holds no bare `gate_result`
    assert [r["held_by"] for r in rows if r["alert_id"] == alert_id] == [["verifier_invalid"]]


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
