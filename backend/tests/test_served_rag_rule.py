"""What Tier 1 is served of a run the RAG low-match rule applied to (DEC-219, as amended:
`docs/superpowers/specs/2026-11-15-rag-low-match-fp-rule-design.md` section 5). NO DATABASE.

Below the threshold `false_positive` is ①'s DEFAULT answer, so the Tier 1 API must not hand out the model's own
answer for such a run: `proposed_action` (the queue row and the alert view) and `Suggestion.gate.proposed_verdict`
return the verdict ① ended with when the stored run's `gate_result.rag_rule.applied` is true, whether or not
the model had answered `false_positive` itself. The stored `gate_result.proposed_verdict` is untouched (the admin
LLM page and the audit log show stored rows as they are), and a run the rule did not apply to is served exactly
as before. `Suggestion.gate` also gains `rag_rule`: the stored object, or `null` for a run that has none.

The database-backed counterpart, which runs the queue's SQL, is `test_served_rag_rule_db.py` (marked `db`).
Here the queue statement's rows are crafted the way PostgreSQL returns them, and the readers are the real ones.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from app.llm import verdicts
from app.tier1 import queue, visibility

TP, FP = "true_positive", "false_positive"
RUN_ID = "11111111-1111-1111-1111-111111111111"
NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)

CHANGED = {"threshold": 80, "best_pct": 62, "applied": True, "changed": True}
APPLIED_ONLY = {"threshold": 80, "best_pct": 62, "applied": True, "changed": False}
NOT_APPLIED = {"threshold": 80, "best_pct": 91, "applied": False, "changed": False}
SWITCH_OFF = {"threshold": 0, "best_pct": None, "applied": False, "changed": False}


def _result(action: str) -> dict:
    return {
        "suggested_action": action,
        "confidence": "high",
        "reasons": [{"claim": "c", "quote": "q", "source": "wazuh_raw_log"}],
    }


def _gate(*, proposed: str, final: str, rag_rule: dict | None, **more) -> dict:
    gate = {
        "version": 2,
        "proposed_verdict": proposed,
        "final_verdict": final,
        "forced": False,
        "forced_by": [],
        "flagged_by": [],
        "missing": [],
        "warnings": [],
        "facts": {"correlated_clusters": 2},
        "steps": {"6": "agree"},
        "verifier_verdict": proposed,
    }
    if rag_rule is not None:
        gate["rag_rule"] = rag_rule
    gate.update(more)
    return gate


#: A model `true_positive` the rule turned into `false_positive`; a model `false_positive` it applied to; a run
#: it did not apply to; a run with the switch off; a run from before the key existed (no `rag_rule` at all).
CHANGED_RUN = (_result(FP), _gate(proposed=TP, final=FP, rag_rule=CHANGED))
APPLIED_RUN = (_result(FP), _gate(proposed=FP, final=FP, rag_rule=APPLIED_ONLY))
NOT_APPLIED_RUN = (_result(TP), _gate(proposed=TP, final=TP, rag_rule=NOT_APPLIED))
SWITCH_OFF_RUN = (_result(TP), _gate(proposed=TP, final=TP, rag_rule=SWITCH_OFF))
OLD_RUN = (_result(TP), _gate(proposed=TP, final=TP, rag_rule=None))


# ---------------------------------------------------------------------------------------------------
# llm.verdicts: the two functions the two readers share
# ---------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "gate_result, expected",
    [
        ({"rag_rule": CHANGED}, True),
        ({"rag_rule": APPLIED_ONLY}, True),
        ({"rag_rule": NOT_APPLIED}, False),
        ({"rag_rule": SWITCH_OFF}, False),
        ({}, False),
        ({"rag_rule": None}, False),
        (
            {"rag_rule": {"applied": None}},
            False,
        ),  # the queue projection of a run that has no rag_rule
        ({"rag_rule": {"applied": "true"}}, False),  # only the JSON boolean counts
        ({"rag_rule": {"applied": 1}}, False),
        ({"rag_rule": "applied"}, False),
        ({"rag_rule": [True]}, False),
        (None, False),
        ("garbled", False),
        ([], False),
    ],
)
def test_rag_rule_applied_is_true_only_for_a_stored_applied_true(gate_result, expected):
    assert verdicts.rag_rule_applied(gate_result) is expected


@pytest.mark.parametrize(
    "gate_result, served, expected",
    [
        # the rule applied: the verdict ① ended with, whatever the model said
        (_gate(proposed=TP, final=FP, rag_rule=CHANGED), FP, FP),
        (_gate(proposed=FP, final=FP, rag_rule=APPLIED_ONLY), FP, FP),
        # the rule did not apply, or there is none: the model's own answer, as before
        (_gate(proposed=TP, final=TP, rag_rule=NOT_APPLIED), TP, TP),
        (_gate(proposed=TP, final=TP, rag_rule=SWITCH_OFF), TP, TP),
        (_gate(proposed=FP, final=FP, rag_rule=None), FP, FP),
        # no verdict served (no usable result): no verdict, not the model's
        (_gate(proposed=TP, final=FP, rag_rule=CHANGED), None, None),
        (_gate(proposed=TP, final=FP, rag_rule=CHANGED), "needs_review", None),
        # a run the old gate held (version 1): the model's own answer, as before DEC-219
        ({"proposed_verdict": FP, "final_verdict": "needs_review", "forced": True}, FP, FP),
        # nothing usable at all
        (None, FP, None),
        ({}, TP, None),
    ],
)
def test_served_proposed_action(gate_result, served, expected):
    assert verdicts.served_proposed_action(gate_result, served) == expected


def test_proposed_action_itself_is_still_the_stored_models_answer():
    """`proposed_action` is the stored record (it also feeds `served_action` for a stored `needs_review`): the
    serving rule is a new function, so the stored answer is never rewritten by reading it."""
    assert verdicts.proposed_action(_gate(proposed=TP, final=FP, rag_rule=CHANGED)) == TP


# ---------------------------------------------------------------------------------------------------
# Suggestion.gate (the alert view's suggestion)
# ---------------------------------------------------------------------------------------------------


def _suggestion(run):
    result, gate_result = run
    return queue._suggestion_of(RUN_ID, result, gate_result, NOW)


class TestSuggestionGate:
    def test_a_run_the_rule_changed_serves_the_verdict_it_ended_with_as_proposed_verdict(self):
        suggestion = _suggestion(CHANGED_RUN)

        assert suggestion.suggested_action == FP
        assert suggestion.gate["proposed_verdict"] == FP  # not `true_positive`, the model's own
        assert suggestion.gate["final_verdict"] == FP
        assert suggestion.gate["rag_rule"] == CHANGED
        assert suggestion.gate["forced"] is False and suggestion.gate["forced_by"] == []

    def test_a_run_the_rule_applied_to_without_changing_it_is_served_the_same(self):
        suggestion = _suggestion(APPLIED_RUN)

        assert suggestion.gate["proposed_verdict"] == FP and suggestion.gate["final_verdict"] == FP
        assert suggestion.gate["rag_rule"] == APPLIED_ONLY

    @pytest.mark.parametrize(
        "run, rule", [(NOT_APPLIED_RUN, NOT_APPLIED), (SWITCH_OFF_RUN, SWITCH_OFF)]
    )
    def test_a_run_the_rule_did_not_apply_to_is_served_as_before_plus_the_object(self, run, rule):
        suggestion = _suggestion(run)

        assert suggestion.gate["proposed_verdict"] == TP  # the model's own answer, unchanged
        assert suggestion.gate["final_verdict"] == TP
        assert suggestion.gate["rag_rule"] == rule

    def test_a_run_from_before_the_key_has_a_null_rag_rule(self):
        suggestion = _suggestion(OLD_RUN)

        assert suggestion.gate["rag_rule"] is None
        assert "rag_rule" in suggestion.gate  # the key is there, `null`, as the spec says
        assert suggestion.gate["proposed_verdict"] == TP

    @pytest.mark.parametrize("garbled", ["applied", 7, [True], True])
    def test_a_stored_rag_rule_that_is_not_an_object_is_null(self, garbled):
        result, gate_result = OLD_RUN
        suggestion = queue._suggestion_of(RUN_ID, result, {**gate_result, "rag_rule": garbled}, NOW)

        assert suggestion.gate["rag_rule"] is None
        assert suggestion.gate["proposed_verdict"] == TP

    def test_the_stored_gate_result_is_not_touched(self):
        result, gate_result = copy.deepcopy(CHANGED_RUN)
        before = copy.deepcopy(gate_result)

        queue._suggestion_of(RUN_ID, result, gate_result, NOW)

        assert (
            gate_result == before and gate_result["proposed_verdict"] == TP
        )  # `llm_runs` is as stored

    def test_the_reasons_are_the_models_and_the_confidence_is_not_served(self):
        suggestion = _suggestion(CHANGED_RUN)

        assert suggestion.reasons == [{"claim": "c", "quote": "q", "source": "wazuh_raw_log"}]
        assert suggestion.confidence is None  # the model's confidence in its own answer (see below)

    def test_a_version_1_run_the_old_gate_held_is_served_as_before(self):
        result = {**_result("needs_review"), "confidence": "medium"}
        gate_result = {
            "version": 1,
            "proposed_verdict": FP,
            "final_verdict": "needs_review",
            "forced": True,
            "forced_by": ["step4"],
        }

        suggestion = queue._suggestion_of(RUN_ID, result, gate_result, NOW)

        assert (
            suggestion.suggested_action == FP
        )  # DEC-217: the model's own verdict, for a stored needs_review
        assert suggestion.gate["proposed_verdict"] == FP
        assert suggestion.gate["final_verdict"] == "needs_review"
        assert suggestion.gate["forced"] is True and suggestion.gate["rag_rule"] is None


# ---------------------------------------------------------------------------------------------------
# the alert view: latest_suggestion_rag(...)[1], the `proposed_action` of `get_alert_view`
# ---------------------------------------------------------------------------------------------------


class _OneRowConn:
    """What `latest_suggestion_rag` needs of a connection: the newest proposer row as `_SUGGESTION_SQL`
    selects it."""

    def __init__(self, row):
        self._row = row

    def execute(self, _statement, _params=None):
        return SimpleNamespace(fetchone=lambda: self._row)


def _alert_view_pair(run):
    result, gate_result = run
    row = (RUN_ID, result, gate_result, NOW, [], None)
    suggestion, proposed_action, held_by, _rag = queue.latest_suggestion_rag(
        _OneRowConn(row), "a-1"
    )
    return suggestion, proposed_action, held_by


class TestAlertView:
    def test_a_changed_run_is_served_the_verdict_it_ended_with_as_proposed_action(self):
        suggestion, proposed_action, held_by = _alert_view_pair(CHANGED_RUN)

        assert proposed_action == FP
        assert suggestion.suggested_action == FP and suggestion.gate["proposed_verdict"] == FP
        assert held_by == []

    def test_a_run_the_rule_applied_to_without_changing_it_is_served_the_same(self):
        assert _alert_view_pair(APPLIED_RUN)[1] == FP

    @pytest.mark.parametrize("run", [NOT_APPLIED_RUN, SWITCH_OFF_RUN, OLD_RUN])
    def test_a_run_the_rule_did_not_apply_to_keeps_the_models_answer(self, run):
        assert _alert_view_pair(run)[1] == TP

    def test_the_held_by_warnings_are_unchanged(self):
        result, gate_result = CHANGED_RUN
        flagged = {**gate_result, "flagged_by": ["step4"], "missing": ["severity", "playbook_rule"]}

        _suggestion_unused, _proposed, held_by = _alert_view_pair((result, flagged))

        assert held_by == ["fp_policy:severity", "fp_policy:playbook_rule"]

    def test_the_proposed_action_and_the_suggestion_are_one_run(self):
        """The two values come from the row of ONE statement: a served `proposed_action` that disagreed with the
        `suggested_action` beside it would be two runs."""
        for run in (CHANGED_RUN, APPLIED_RUN):
            suggestion, proposed_action, _held = _alert_view_pair(run)
            assert (
                proposed_action
                == suggestion.suggested_action
                == suggestion.gate["proposed_verdict"]
            )


# ---------------------------------------------------------------------------------------------------
# the queue row: `list_queue`'s `proposed_action`
# ---------------------------------------------------------------------------------------------------


class _QueueConn:
    """`list_queue` over one crafted row: the list statement gives it, the count statement says 1 and the
    band-count statement says nothing. The SQL itself is the database test's."""

    def __init__(self, record):
        self._record = record

    def execute(self, statement, _params=None):
        text = str(statement)
        if "LEFT JOIN LATERAL" in text:
            return SimpleNamespace(fetchall=lambda: [self._record])
        if text.lstrip().startswith("SELECT count(*) FROM alerts"):
            return SimpleNamespace(fetchone=lambda: (1,))
        return SimpleNamespace(fetchall=list)


def _queue_row(run, *, projection: dict | None, status="queued_tier1", visible=True) -> dict:
    """The row `list_queue` returns for one head whose newest run is `run`, with `gate_held` as the statement
    projects it (`projection`)."""
    result, gate_result = run
    values = {
        "alert_id": "a-1",
        "rule_id": "5710",
        "description": "d",
        "category": "ssh_brute_force",
        "severity": "critical",
        "agent_name": "agent",
        "alert_user": None,
        "srcip": "10.0.0.1",
        "risk_score": 50,
        "occurrence_count": 1,
        "triaged_count": 1,
        "first_seen_at": NOW,
        "last_seen_at": NOW,
        "alert_time": NOW,
        "suggestion_visible": visible,
        "triage_status": "ready",
        "status": status,
        "run_id": RUN_ID,
        "suggested_action": verdicts.served_action(result, gate_result),
        "confidence": result["confidence"],
        "gate_forced": "true" if gate_result.get("forced") else "false",
        "gate_held": projection,
        "needs_retriage": False,
    }
    record = tuple(values[name] for name in queue._QUEUE_COLUMNS)
    page = queue.list_queue(_QueueConn(record))
    assert len(page.rows) == 1
    return page.rows[0]


def _projection(gate_result: dict) -> dict:
    """`gate_held` as `_QUEUE_SQL` builds it: the five keys the readers need, and (DEC-219) `rag_rule` reduced
    to its `applied` flag, which is all the served `proposed_action` needs of it."""
    rule = gate_result.get("rag_rule")
    return {
        "proposed_verdict": gate_result.get("proposed_verdict"),
        "forced_by": gate_result.get("forced_by"),
        "flagged_by": gate_result.get("flagged_by"),
        "missing": gate_result.get("missing"),
        "steps": {"6": gate_result.get("steps", {}).get("6")},
        "rag_rule": {"applied": rule.get("applied") if isinstance(rule, dict) else None},
    }


class TestQueueRow:
    def test_a_changed_run_is_served_the_verdict_it_ended_with_as_proposed_action(self):
        row = _queue_row(CHANGED_RUN, projection=_projection(CHANGED_RUN[1]))

        assert row["suggested_action"] == FP
        assert row["proposed_action"] == FP  # not `true_positive`, the model's own
        assert row["gate_forced"] is False
        assert row["held_by"] == []

    def test_a_run_the_rule_applied_to_without_changing_it_is_served_the_same(self):
        row = _queue_row(APPLIED_RUN, projection=_projection(APPLIED_RUN[1]))

        assert row["suggested_action"] == FP and row["proposed_action"] == FP

    @pytest.mark.parametrize("run", [NOT_APPLIED_RUN, SWITCH_OFF_RUN, OLD_RUN])
    def test_a_run_the_rule_did_not_apply_to_keeps_the_models_answer(self, run):
        row = _queue_row(run, projection=_projection(run[1]))

        assert row["suggested_action"] == TP and row["proposed_action"] == TP

    def test_a_row_whose_projection_has_no_rag_rule_key_at_all_is_served_as_before(self):
        projection = _projection(OLD_RUN[1])
        del projection["rag_rule"]

        assert _queue_row(OLD_RUN, projection=projection)["proposed_action"] == TP

    def test_the_queue_row_gains_no_key_of_its_own(self):
        """Spec 5: `Suggestion.gate` gains `rag_rule`; the queue row gains nothing (`gate_forced` is false for
        such a run, and `held_by` is the warnings)."""
        row = _queue_row(CHANGED_RUN, projection=_projection(CHANGED_RUN[1]))

        assert "rag_rule" not in row and "gate_held" not in row

    def test_the_blind_arm_sees_none_of_it(self):
        row = _queue_row(
            CHANGED_RUN,
            projection=_projection(CHANGED_RUN[1]),
            status="queued_tier1",
            visible=False,
        )

        for key in ("proposed_action", "suggested_action", "held_by", "gate_forced", "run_id"):
            assert key not in row
        assert "rag_rule" not in row


class TestTheQueueStatementProjectsTheFlag:
    """The statement is run by the database tests; here only what the text must say for the reader above to
    get the flag, and that the stored document is read, never written."""

    def test_the_gate_held_projection_carries_rag_rule_applied(self):
        sql = " ".join(queue._QUEUE_SQL.split())

        assert (
            "'rag_rule', jsonb_build_object('applied', r.gate_result->'rag_rule'->'applied')" in sql
        )

    def test_it_is_still_the_five_old_keys_plus_that_one(self):
        sql = " ".join(queue._QUEUE_SQL.split())
        block = sql.split("jsonb_build_object(", 1)[1].split(" END AS gate_held")[0]

        for key in ("proposed_verdict", "forced_by", "flagged_by", "missing", "steps", "rag_rule"):
            assert f"'{key}'" in block
        assert "INSERT" not in sql and "UPDATE" not in sql


# ---------------------------------------------------------------------------------------------------
# the blind arm (DEC-101): `rag_rule` is hidden wherever the suggestion is
# ---------------------------------------------------------------------------------------------------


def _view_with(suggestion) -> dict:
    return {
        "alert_id": "a-1",
        "status": "queued_tier1",
        "suggestion_visible": False,
        "suggestion": suggestion.to_dict() if suggestion is not None else None,
        "proposed_action": FP,
        "held_by": [],
        "rag": {"best_pct": 62, "not_applied": None},
    }


def _keys(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _keys(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _keys(item)


class TestBlindArmHidesRagRule:
    def test_a_blind_undecided_head_has_no_rag_rule_at_any_depth(self):
        view = _view_with(_suggestion(CHANGED_RUN))
        assert "rag_rule" in set(_keys(view))  # it is in the full view ...

        stripped = visibility.strip(
            view, status="queued_tier1", suggestion_visible=False, mode="analyst"
        )

        assert "rag_rule" not in set(_keys(stripped))  # ... and in none of the blind one
        assert "suggestion" not in stripped and "proposed_action" not in stripped

    def test_the_visible_arm_keeps_it_inside_the_suggestion(self):
        view = _view_with(_suggestion(CHANGED_RUN))

        stripped = visibility.strip(
            view, status="queued_tier1", suggestion_visible=True, mode="analyst"
        )

        assert stripped["suggestion"]["gate"]["rag_rule"] == CHANGED

    def test_a_decided_head_shows_it(self):
        view = _view_with(_suggestion(CHANGED_RUN))

        stripped = visibility.strip(
            view, status="closed_fp", suggestion_visible=False, mode="analyst"
        )

        assert stripped["suggestion"]["gate"]["rag_rule"] == CHANGED

    def test_the_labelling_page_never_has_it(self):
        view = _view_with(_suggestion(CHANGED_RUN))

        stripped = visibility.strip(
            view, status="closed_fp", suggestion_visible=True, mode="labeling"
        )

        assert "rag_rule" not in set(_keys(stripped))
        assert "gate" not in set(_keys(stripped))


# ---------------------------------------------------------------------------------------------------
# the model's confidence is not served for a run the rule applied to (the amendment's addition)
# ---------------------------------------------------------------------------------------------------
#
# `result.confidence` is the model's confidence in ITS OWN answer, not in the default verdict ① ended with, so
# the Tier 1 API serves `null` for it wherever it served it before: the alert view's `suggestion.confidence` and
# the queue row's `confidence` - the two places the verdict is served - and so what `decide` records with a
# decision. The stored `result.confidence`, the admin LLM page and the audit log are unchanged.


@pytest.mark.parametrize(
    "gate_result, expected",
    [
        (_gate(proposed=TP, final=FP, rag_rule=CHANGED), None),
        (
            _gate(proposed=FP, final=FP, rag_rule=APPLIED_ONLY),
            None,
        ),  # applied, though the model said FP itself
        (_gate(proposed=TP, final=TP, rag_rule=NOT_APPLIED), "high"),
        (_gate(proposed=TP, final=TP, rag_rule=SWITCH_OFF), "high"),
        (_gate(proposed=TP, final=TP, rag_rule=None), "high"),
        ({"proposed_verdict": FP, "forced": True, "forced_by": ["step4"]}, "high"),  # version 1
        (None, "high"),
        ({}, "high"),
    ],
)
def test_served_confidence(gate_result, expected):
    assert verdicts.served_confidence("high", gate_result) == expected


def test_served_confidence_keeps_a_missing_confidence_missing():
    assert verdicts.served_confidence(None, _gate(proposed=TP, final=TP, rag_rule=None)) is None


class TestSuggestionConfidence:
    @pytest.mark.parametrize("run", [CHANGED_RUN, APPLIED_RUN])
    def test_a_run_the_rule_applied_to_is_served_no_confidence(self, run):
        suggestion = _suggestion(run)

        assert suggestion.confidence is None
        assert suggestion.to_dict()["confidence"] is None
        assert suggestion.suggested_action == FP  # the verdict is served, its confidence is not

    @pytest.mark.parametrize("run", [NOT_APPLIED_RUN, SWITCH_OFF_RUN, OLD_RUN])
    def test_every_other_run_is_served_the_models_confidence(self, run):
        assert _suggestion(run).confidence == "high"

    def test_the_stored_result_is_not_touched(self):
        result, gate_result = copy.deepcopy(CHANGED_RUN)
        before = copy.deepcopy(result)

        queue._suggestion_of(RUN_ID, result, gate_result, NOW)

        assert result == before and result["confidence"] == "high"

    def test_the_alert_view_reader_serves_it_too(self):
        suggestion, _proposed, _held = _alert_view_pair(CHANGED_RUN)
        assert suggestion.confidence is None

        suggestion, _proposed, _held = _alert_view_pair(NOT_APPLIED_RUN)
        assert suggestion.confidence == "high"


class TestQueueRowConfidence:
    @pytest.mark.parametrize("run", [CHANGED_RUN, APPLIED_RUN])
    def test_a_run_the_rule_applied_to_is_served_no_confidence(self, run):
        row = _queue_row(run, projection=_projection(run[1]))

        assert row["confidence"] is None
        assert row["suggested_action"] == FP and row["proposed_action"] == FP

    @pytest.mark.parametrize("run", [NOT_APPLIED_RUN, SWITCH_OFF_RUN, OLD_RUN])
    def test_every_other_run_is_served_the_models_confidence(self, run):
        assert _queue_row(run, projection=_projection(run[1]))["confidence"] == "high"

    def test_the_blind_arm_still_has_no_confidence_key_at_all(self):
        row = _queue_row(
            CHANGED_RUN,
            projection=_projection(CHANGED_RUN[1]),
            status="queued_tier1",
            visible=False,
        )

        assert "confidence" not in row


class TestWhatDecideRecords:
    """`tier1/decide.py` joins ①'s latest suggestion to the decision (`llm_suggestion`, `llm_confidence`): it
    reads `queue.latest_suggestion`, so it records what Tier 1 was served - the verdict ① ended with and, for a
    run the rule applied to, no confidence."""

    def _decide(self, monkeypatch, run):
        from app.tier1 import decide as decide_module

        suggestion = _suggestion(run)
        recorded = {}
        monkeypatch.setattr(
            decide_module.queue, "latest_suggestion", lambda conn, alert_id: suggestion
        )
        monkeypatch.setattr(
            decide_module.transitions, "decide", lambda *a, **kw: recorded.update(kw)
        )
        rows = iter([(True,), (1,)])  # `suggestion_visible`, then the closed count
        conn = SimpleNamespace(
            execute=lambda *_a, **_k: SimpleNamespace(fetchone=lambda: next(rows, (1,)))
        )
        decide_module.decide(
            conn,
            "a-1",
            SimpleNamespace(user_id="u-1"),
            decision="false_positive",
            reason="as ① said",
            seen_occurrence_count=1,
        )
        return recorded

    def test_a_run_the_rule_applied_to_records_the_verdict_and_no_confidence(self, monkeypatch):
        recorded = self._decide(monkeypatch, CHANGED_RUN)

        assert recorded["llm_suggestion"] == FP
        assert recorded["llm_confidence"] is None
        assert recorded["gate_forced"] is False
        assert recorded["llm_run_id"] == RUN_ID

    def test_any_other_run_records_the_models_confidence_as_before(self, monkeypatch):
        recorded = self._decide(monkeypatch, NOT_APPLIED_RUN)

        assert recorded["llm_suggestion"] == TP and recorded["llm_confidence"] == "high"
