"""The RAG low-match rule (DEC-219, as amended) against a real PostgreSQL: the rows `run_triage_job` stores, and
what the Tier 1 readers serve for them (`docs/superpowers/specs/2026-11-15-rag-low-match-fp-rule-design.md`
sections 4, 5 and 7). Marked `db`: it needs a PostgreSQL reachable at `TEST_DATABASE_URL`, and cannot run on a
host where that DSN does not authenticate. The database-free counterparts, which run the same code over crafted
rows, are `test_tier1_rag_rule.py` (the job) and `test_served_rag_rule.py` (the readers).

What only a database can show:

* the job stores the verdict after the rule in `llm_runs.result`, the model's own answer in
  `gate_result.proposed_verdict`, `gate_result.rag_rule`, `forced` false, and writes no `llm.gate_forced`;
* `best_pct` the job read is the number the alert page shows for the same stored run: the page reads
  `rag_results.matches` through the scalar subquery of `llm_runs.rag_lookup_id`, the job through
  `_lookup_matches`, and both go through `llm.rag_view.rag_view`;
* the queue statement's `gate_held` projection carries `rag_rule.applied`, so the queue row's `proposed_action`
  is the verdict ① ended with and its `confidence` is `null` for a run the rule applied to; the alert view says
  the same in `proposed_action`, `suggestion.confidence` and `suggestion.gate.proposed_verdict`, and gains
  `suggestion.gate.rag_rule`; the stored row is untouched; `decide` records what was served;
* the blind arm sees none of it.
"""

from __future__ import annotations

import pytest
from app.tier1 import queue
from app.tier1.decide import decide
from app.tier1.queue import get_alert_view, list_queue
from app.tier1.triage import run_triage_job

from tests.fakes.llm import TRIAGE_V2_FALSE_POSITIVE, TRIAGE_V3_TRUE_POSITIVE, VERIFIER_V2_AGREE
from tests.test_decide import (
    USER_ID,
    USER_NAME,
    _active,
    _actor,
    _audit_rows,
    _seed_user,
)
from tests.test_decide import _insert_run as _decide_insert_run
from tests.test_triage_job import _enable_llm, _event_types, _job, _RecordingLLM, _seed_alert
from tests.test_triage_rag import approved, put_lookup

pytestmark = pytest.mark.db

TP, FP = "true_positive", "false_positive"
ENTRY = "# Máy quét nội bộ\n\nCảnh báo quét cổng từ máy quản trị đã được đóng là lành tính."


@pytest.fixture
def rule_on(monkeypatch) -> None:
    """The LLM on, RAG on, the rule at the trial's 80."""
    _enable_llm(monkeypatch)
    monkeypatch.setenv("RAG_ENABLED", "true")
    monkeypatch.setenv("TRIAGE_RAG_FP_BELOW_PCT", "80")


def _model(answer=TRIAGE_V3_TRUE_POSITIVE, verifier=VERIFIER_V2_AGREE) -> _RecordingLLM:
    return _RecordingLLM(responses=[answer, verifier])


def _with_lookup(db, score: float, **alert_overrides) -> str:
    """A visible-arm head with a stored `ok` lookup whose one entry matched at `score`."""
    alert_id = _seed_alert(db, suggestion_visible=True, **alert_overrides)
    put_lookup(db, alert_id, matches=[approved(db, ENTRY, "giong", score)])
    return alert_id


def _stored(db, alert_id: str) -> dict:
    row = db.execute(
        "SELECT result, gate_result, rag_lookup_id FROM llm_runs"
        " WHERE subject_id = %s AND role = 'proposer'",
        (alert_id,),
    ).fetchone()
    return {"result": row[0], "gate_result": row[1], "rag_lookup_id": row[2]}


def _queue_row(db, alert_id: str) -> dict:
    rows = [r for r in list_queue(db, page_size=200).rows if r["alert_id"] == alert_id]
    assert len(rows) == 1
    return rows[0]


def _keys(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _keys(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _keys(item)


# ── what the job stores ──────────────────────────────────────────────────────────────────────────


def test_a_true_positive_below_the_threshold_is_stored_as_false_positive(db, rule_on) -> None:
    alert_id = _with_lookup(db, 0.62)

    run_triage_job(db, _job(alert_id), adapter=_model())

    stored = _stored(db, alert_id)
    assert stored["result"]["suggested_action"] == FP
    gate_result = stored["gate_result"]
    assert gate_result["proposed_verdict"] == TP and gate_result["final_verdict"] == FP
    assert gate_result["forced"] is False and gate_result["forced_by"] == []
    assert gate_result["rag_rule"] == {
        "threshold": 80,
        "best_pct": 62,
        "applied": True,
        "changed": True,
    }
    assert gate_result["steps"]["3r"] == "changed"
    assert gate_result["proposer_raw"]["suggested_action"] == TP
    events = _event_types(db, alert_id)
    assert "triage.suggested" in events and "llm.gate_forced" not in events


def test_the_best_pct_the_job_read_is_the_number_the_page_shows(db, rule_on) -> None:
    alert_id = _seed_alert(db, suggestion_visible=True)
    matches = [approved(db, ENTRY, "giong", 0.55), approved(db, ENTRY + " (2)", "giong", 0.71)]
    put_lookup(db, alert_id, matches=matches)

    run_triage_job(db, _job(alert_id), adapter=_model())

    stored = _stored(db, alert_id)
    _suggestion, _proposed, _held, rag = queue.latest_suggestion_rag(db, alert_id)
    assert stored["gate_result"]["rag_rule"]["best_pct"] == rag["best_pct"] == 71


def test_the_switch_off_stores_what_it_did_before_plus_the_rag_rule_key(db, monkeypatch) -> None:
    _enable_llm(monkeypatch)
    monkeypatch.setenv("RAG_ENABLED", "true")
    monkeypatch.delenv("TRIAGE_RAG_FP_BELOW_PCT", raising=False)
    alert_id = _with_lookup(db, 0.62)

    run_triage_job(db, _job(alert_id), adapter=_model())

    stored = _stored(db, alert_id)
    assert stored["result"]["suggested_action"] == TP
    assert stored["gate_result"]["rag_rule"] == {
        "threshold": 0,
        "best_pct": None,
        "applied": False,
        "changed": False,
    }
    assert stored["gate_result"]["steps"]["3r"] == "n/a"
    assert stored["gate_result"]["forced"] is False and stored["gate_result"]["forced_by"] == []


def test_a_best_match_at_the_threshold_leaves_the_models_verdict(db, rule_on) -> None:
    alert_id = _with_lookup(db, 0.80)

    run_triage_job(db, _job(alert_id), adapter=_model())

    stored = _stored(db, alert_id)
    assert stored["result"]["suggested_action"] == TP
    assert stored["gate_result"]["rag_rule"]["applied"] is False


def test_a_lookup_that_kept_no_match_leaves_the_models_verdict(db, rule_on) -> None:
    alert_id = _seed_alert(db, suggestion_visible=True)
    put_lookup(db, alert_id, matches=[])

    run_triage_job(db, _job(alert_id), adapter=_model())

    stored = _stored(db, alert_id)
    assert stored["result"]["suggested_action"] == TP
    assert stored["gate_result"]["rag_rule"]["best_pct"] is None


def test_a_failed_lookup_leaves_the_models_verdict(db, rule_on) -> None:
    alert_id = _seed_alert(db, suggestion_visible=True)
    put_lookup(db, alert_id, status="failed", failure_kind="auth")

    run_triage_job(db, _job(alert_id), adapter=_model())

    stored = _stored(db, alert_id)
    assert stored["result"]["suggested_action"] == TP
    assert stored["gate_result"]["rag_rule"]["best_pct"] is None
    assert stored["rag_lookup_id"] is None


def test_no_lookup_leaves_the_models_verdict(db, rule_on) -> None:
    alert_id = _seed_alert(db, suggestion_visible=True)

    run_triage_job(db, _job(alert_id), adapter=_model())

    stored = _stored(db, alert_id)
    assert stored["result"]["suggested_action"] == TP
    assert stored["gate_result"]["rag_rule"]["best_pct"] is None


def test_rag_off_leaves_the_models_verdict_whatever_the_lookup(db, rule_on, monkeypatch) -> None:
    monkeypatch.setenv("RAG_ENABLED", "false")
    alert_id = _with_lookup(db, 0.62)

    run_triage_job(db, _job(alert_id), adapter=_model())

    stored = _stored(db, alert_id)
    assert stored["result"]["suggested_action"] == TP
    assert stored["gate_result"]["rag_rule"]["best_pct"] is None


# ── what Tier 1 is served ────────────────────────────────────────────────────────────────────────


def test_the_queue_row_serves_the_verdict_it_ended_with_and_no_confidence(db, rule_on) -> None:
    alert_id = _with_lookup(db, 0.62)
    run_triage_job(db, _job(alert_id), adapter=_model())

    row = _queue_row(db, alert_id)

    assert row["suggested_action"] == FP
    assert row["proposed_action"] == FP  # not `true_positive`, the model's own answer
    assert row["confidence"] is None
    assert row["gate_forced"] is False


def test_the_alert_view_serves_the_verdict_it_ended_with_and_no_confidence(db, rule_on) -> None:
    alert_id = _with_lookup(db, 0.62)
    run_triage_job(db, _job(alert_id), adapter=_model())

    view = get_alert_view(db, alert_id)

    assert view["proposed_action"] == FP
    suggestion = view["suggestion"]
    assert suggestion["suggested_action"] == FP and suggestion["confidence"] is None
    assert suggestion["gate"]["proposed_verdict"] == FP
    assert suggestion["gate"]["final_verdict"] == FP
    assert suggestion["gate"]["forced"] is False
    assert suggestion["gate"]["rag_rule"] == {
        "threshold": 80,
        "best_pct": 62,
        "applied": True,
        "changed": True,
    }
    assert view["rag"]["best_pct"] == 62


def test_the_stored_run_is_untouched_by_serving(db, rule_on) -> None:
    alert_id = _with_lookup(db, 0.62)
    run_triage_job(db, _job(alert_id), adapter=_model())
    before = _stored(db, alert_id)

    get_alert_view(db, alert_id)
    _queue_row(db, alert_id)

    after = _stored(db, alert_id)
    assert after == before
    assert (
        after["gate_result"]["proposed_verdict"] == TP
    )  # the model's own answer is in the stored row
    assert after["result"]["confidence"] == TRIAGE_V3_TRUE_POSITIVE["confidence"]


def test_a_run_the_rule_applied_to_without_changing_it_is_served_the_same(db, rule_on) -> None:
    alert_id = _with_lookup(db, 0.62)
    answers_fp = {**VERIFIER_V2_AGREE, "structured_only_verdict": FP}
    run_triage_job(db, _job(alert_id), adapter=_model(TRIAGE_V2_FALSE_POSITIVE, answers_fp))

    row = _queue_row(db, alert_id)
    view = get_alert_view(db, alert_id)

    assert row["proposed_action"] == FP and row["confidence"] is None
    assert view["proposed_action"] == FP and view["suggestion"]["confidence"] is None
    assert view["suggestion"]["gate"]["rag_rule"]["changed"] is False
    assert view["suggestion"]["gate"]["rag_rule"]["applied"] is True


def test_a_run_the_rule_did_not_apply_to_is_served_the_models_answer_and_confidence(
    db, rule_on
) -> None:
    alert_id = _with_lookup(db, 0.91)
    run_triage_job(db, _job(alert_id), adapter=_model())

    row = _queue_row(db, alert_id)
    view = get_alert_view(db, alert_id)

    assert row["proposed_action"] == TP
    assert row["confidence"] == TRIAGE_V3_TRUE_POSITIVE["confidence"]
    assert view["proposed_action"] == TP
    assert view["suggestion"]["confidence"] == TRIAGE_V3_TRUE_POSITIVE["confidence"]
    assert view["suggestion"]["gate"]["proposed_verdict"] == TP
    assert view["suggestion"]["gate"]["rag_rule"]["applied"] is False


def test_decide_records_the_verdict_it_ended_with_and_no_confidence(db) -> None:
    _seed_user(db, USER_ID, USER_NAME)
    head = _active(db)
    result = {
        "suggested_action": FP,
        "confidence": "high",
        "reasons": [{"claim": "c", "quote": "q", "source": "wazuh_raw_log"}],
    }
    gate_result = {
        "version": 2,
        "proposed_verdict": TP,
        "final_verdict": FP,
        "forced": False,
        "forced_by": [],
        "flagged_by": [],
        "rag_rule": {"threshold": 80, "best_pct": 62, "applied": True, "changed": True},
        "warnings": [],
        "facts": {"correlated_clusters": 2},
        "verifier_verdict": TP,
    }
    run_id = _decide_insert_run(db, head, result=result, gate_result=gate_result)

    decide(
        db,
        head,
        _actor(USER_ID),
        decision="false_positive",
        reason="as ① said",
        seen_occurrence_count=1,
    )

    (payload,) = [r[1] for r in _audit_rows(db, head) if r[0] == "tier1.decided"]
    assert payload["llm_suggestion"] == FP
    assert payload["llm_confidence"] is None  # follows what was served
    assert payload["gate_forced"] is False
    assert payload["llm_run_id"] == run_id
    stored = db.execute("SELECT result->>'confidence' FROM llm_runs WHERE run_id = %s", (run_id,))
    assert stored.fetchone()[0] == "high"  # `llm_runs` is as it was written


# ── the blind arm sees none of it ────────────────────────────────────────────────────────────────


def test_a_blind_undecided_head_shows_no_rag_rule_and_no_served_verdict(db, rule_on) -> None:
    alert_id = _seed_alert(db, suggestion_visible=False)
    put_lookup(db, alert_id, matches=[approved(db, ENTRY, "giong", 0.62)])
    run_triage_job(db, _job(alert_id), adapter=_model())

    view = get_alert_view(db, alert_id)
    row = _queue_row(db, alert_id)

    for shown in (view, row):
        assert "rag_rule" not in set(_keys(shown))
        for key in (
            "suggestion",
            "proposed_action",
            "confidence",
            "suggested_action",
            "held_by",
            "rag",
        ):
            assert key not in shown
