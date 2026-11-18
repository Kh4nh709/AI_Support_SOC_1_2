"""The two-sided RAG rule (DEC-219, as changed by DEC-225 / RR-T3) against a real PostgreSQL: the rows
`run_triage_job` stores, and what the Tier 1 readers serve for them. Marked `db`: it needs a PostgreSQL reachable at
`TEST_DATABASE_URL`, and cannot run on a host where that DSN does not authenticate. The database-free
counterparts, which run the same code over crafted rows, are `test_tier1_rag_rule.py` (the job) and
`test_served_rag_rule.py` (the readers).

The rule takes the single top knowledge item of the lookup the run's prompt held: the kept match with the highest
score (its percentage is the page's `best_pct`), else the best scored candidate of a lookup that kept none (the
page's `below_floor_pct`); its side is its entry's `conclusion` (`confirmed_incident` is an incident, the four
closed ones are benign). An incident gives `true_positive` at or over the threshold and `false_positive` under it, a
benign item gives `false_positive` at or over it and leaves the model's answer under it.

What only a database can show:

* the job stores the verdict after the rule in `llm_runs.result`, the model's own answer in
  `gate_result.proposed_verdict`, `gate_result.rag_rule` (seven keys), `forced` false, and writes no
  `llm.gate_forced`;
* the percentage the job read is the number the alert page shows for the same stored run, and the entry's
  conclusion is read from `knowledge_entries` by id whatever the entry's status;
* the queue statement's `gate_held` projection carries `rag_rule.applied`, so the queue row's `proposed_action` is
  the verdict ① ended with and its `confidence` is `null` for a run the rule applied to - in both directions - and
  the alert view says the same; the stored row is untouched; `decide` records what was served;
* Tier 1 is not told that a rule exists: no `rag_rule` anywhere in the alert view or the queue row, no 3r check
  row in the analysis, a DEC-219 document still reads;
* the blind arm sees none of it.
"""

from __future__ import annotations

import json
import uuid

import pytest
from app.infra import config
from app.tier1 import queue
from app.tier1.decide import decide
from app.tier1.queue import get_alert_view, list_queue
from app.tier1.triage import EvalSwitches, evaluate_alert, run_triage_job

from tests.fakes.llm import TRIAGE_V4_FALSE_POSITIVE, TRIAGE_V4_TRUE_POSITIVE, VERIFIER_V2_AGREE
from tests.rag_data import add_entry
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
from tests.test_triage_rag import approved, history_json, put_lookup

pytestmark = pytest.mark.db

TP, FP = "true_positive", "false_positive"
ENTRY = "# Máy quét nội bộ\n\nCảnh báo quét cổng từ máy quản trị đã được đóng là lành tính."
INCIDENT, BENIGN = "confirmed_incident", "closed_fp"
ANSWERS_FP = {**VERIFIER_V2_AGREE, "structured_only_verdict": FP}


@pytest.fixture
def rule_on(monkeypatch) -> None:
    """The LLM on, RAG on, the rule at the trial's 80."""
    _enable_llm(monkeypatch)
    monkeypatch.setenv("RAG_ENABLED", "true")
    monkeypatch.setenv("TRIAGE_RAG_FP_BELOW_PCT", "80")


def _model(answer=TRIAGE_V4_TRUE_POSITIVE, verifier=VERIFIER_V2_AGREE) -> _RecordingLLM:
    return _RecordingLLM(responses=[answer, verifier])


def _model_fp(verifier=ANSWERS_FP) -> _RecordingLLM:
    """A model that answers `false_positive` (its verifier agrees with that)."""
    return _model(TRIAGE_V4_FALSE_POSITIVE, verifier)


def _with_lookup(db, score: float, conclusion: str = INCIDENT, **alert_overrides) -> str:
    """A visible-arm head with a stored `ok` lookup whose one entry (of `conclusion`) matched at `score`."""
    alert_id = _seed_alert(db, suggestion_visible=True, **alert_overrides)
    put_lookup(db, alert_id, matches=[approved(db, ENTRY, "giong", score, conclusion)])
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


def _rule(
    pct,
    side,
    *,
    verdict,
    changed,
    applied=True,
    basis="match",
    threshold=80,
) -> dict:
    return {
        "threshold": threshold,
        "best_pct": pct,
        "applied": applied,
        "changed": changed,
        "entry_side": side,
        "rule_verdict": verdict,
        "basis": basis,
    }


# ── what the job stores ──────────────────────────────────────────────────────────────────────────


def test_an_incident_below_the_threshold_turns_a_model_true_positive_into_false_positive(
    db, rule_on
) -> None:
    alert_id = _with_lookup(db, 0.62)

    run_triage_job(db, _job(alert_id), adapter=_model())

    stored = _stored(db, alert_id)
    assert stored["result"]["suggested_action"] == FP
    gate_result = stored["gate_result"]
    assert gate_result["proposed_verdict"] == TP and gate_result["final_verdict"] == FP
    assert gate_result["forced"] is False and gate_result["forced_by"] == []
    assert gate_result["rag_rule"] == _rule(62, "incident", verdict=FP, changed=True)
    assert gate_result["steps"]["3r"] == "changed"
    assert gate_result["proposer_raw"]["suggested_action"] == TP
    events = _event_types(db, alert_id)
    assert "triage.suggested" in events and "llm.gate_forced" not in events


def test_an_incident_at_85_percent_turns_a_model_false_positive_into_true_positive(
    db, rule_on
) -> None:
    alert_id = _with_lookup(db, 0.85)

    run_triage_job(db, _job(alert_id), adapter=_model_fp())

    stored = _stored(db, alert_id)
    assert stored["result"]["suggested_action"] == TP
    gate_result = stored["gate_result"]
    assert gate_result["proposed_verdict"] == FP and gate_result["final_verdict"] == TP
    assert gate_result["forced"] is False and gate_result["forced_by"] == []
    assert gate_result["rag_rule"] == _rule(85, "incident", verdict=TP, changed=True)
    assert gate_result["steps"]["3r"] == "changed"
    assert (
        gate_result["steps"]["4"] == "n/a"
    )  # a true_positive: there is no false positive to check
    assert gate_result["proposer_raw"]["suggested_action"] == FP
    events = _event_types(db, alert_id)
    assert "triage.suggested" in events and "llm.gate_forced" not in events


def test_an_incident_exactly_at_the_threshold_applies(db, rule_on) -> None:
    alert_id = _with_lookup(db, 0.80)

    run_triage_job(db, _job(alert_id), adapter=_model_fp())

    stored = _stored(db, alert_id)
    assert stored["result"]["suggested_action"] == TP  # 80 at threshold 80 applies
    assert stored["gate_result"]["rag_rule"]["applied"] is True


def test_an_incident_with_a_model_true_positive_is_applied_and_changes_nothing(db, rule_on) -> None:
    alert_id = _with_lookup(db, 0.91)

    run_triage_job(db, _job(alert_id), adapter=_model())

    stored = _stored(db, alert_id)
    assert stored["result"]["suggested_action"] == TP
    assert stored["gate_result"]["rag_rule"] == _rule(91, "incident", verdict=TP, changed=False)
    assert stored["gate_result"]["steps"]["3r"] == "applied"


def test_a_benign_item_at_89_percent_turns_a_model_true_positive_into_false_positive(
    db, rule_on
) -> None:
    alert_id = _with_lookup(db, 0.89, BENIGN)

    run_triage_job(db, _job(alert_id), adapter=_model())

    stored = _stored(db, alert_id)
    assert stored["result"]["suggested_action"] == FP
    gate_result = stored["gate_result"]
    assert gate_result["proposed_verdict"] == TP and gate_result["final_verdict"] == FP
    assert gate_result["rag_rule"] == _rule(89, "benign", verdict=FP, changed=True)
    assert gate_result["steps"]["3r"] == "changed"
    assert gate_result["forced"] is False and gate_result["forced_by"] == []


@pytest.mark.parametrize(
    "conclusion", ["closed_fp", "closed_benign", "concluded_fp", "concluded_policy_violation"]
)
def test_every_closed_conclusion_is_the_benign_side(db, rule_on, conclusion) -> None:
    alert_id = _with_lookup(db, 0.9, conclusion)

    run_triage_job(db, _job(alert_id), adapter=_model())

    stored = _stored(db, alert_id)
    assert stored["gate_result"]["rag_rule"]["entry_side"] == "benign"
    assert stored["result"]["suggested_action"] == FP


def test_a_benign_item_at_62_percent_is_not_applied_and_the_models_true_positive_stands(
    db, rule_on
) -> None:
    alert_id = _with_lookup(db, 0.62, BENIGN)

    run_triage_job(db, _job(alert_id), adapter=_model())

    stored = _stored(db, alert_id)
    assert stored["result"]["suggested_action"] == TP
    gate_result = stored["gate_result"]
    assert gate_result["proposed_verdict"] == gate_result["final_verdict"] == TP
    assert gate_result["rag_rule"] == _rule(
        62, "benign", verdict=None, changed=False, applied=False
    )
    assert gate_result["steps"]["3r"] == "n/a"
    assert gate_result["forced"] is False and gate_result["forced_by"] == []


def test_the_percentage_and_the_side_are_the_top_items_and_the_percentage_is_the_pages(
    db, rule_on
) -> None:
    """The top item is the match with the highest score, whatever else matched: 71 % benign here (the 55 % one is
    an incident). The rule's `best_pct` is the number the page shows for the same stored run."""
    alert_id = _seed_alert(db, suggestion_visible=True)
    matches = [
        approved(db, ENTRY, "giong", 0.55, INCIDENT),
        approved(db, ENTRY + " (2)", "giong", 0.71, BENIGN),
    ]
    put_lookup(db, alert_id, matches=matches)

    run_triage_job(db, _job(alert_id), adapter=_model())

    stored = _stored(db, alert_id)
    _suggestion, _proposed, _held, rag = queue.latest_suggestion_rag(db, alert_id)
    rule = stored["gate_result"]["rag_rule"]
    assert rule["best_pct"] == rag["best_pct"] == 71
    assert (rule["entry_side"], rule["applied"]) == ("benign", False)  # benign under 80: the model
    assert stored["result"]["suggested_action"] == TP


def test_two_entries_tied_on_the_top_score_with_opposite_sides_the_incident_wins(
    db, rule_on
) -> None:
    alert_id = _seed_alert(db, suggestion_visible=True)
    matches = [
        approved(db, ENTRY, "giong", 0.85, BENIGN),
        approved(db, ENTRY + " (2)", "giong", 0.85, INCIDENT),
    ]
    put_lookup(db, alert_id, matches=matches)

    run_triage_job(db, _job(alert_id), adapter=_model_fp())

    stored = _stored(db, alert_id)
    assert stored["result"]["suggested_action"] == TP
    assert stored["gate_result"]["rag_rule"] == _rule(85, "incident", verdict=TP, changed=True)


def test_the_conclusion_is_read_whatever_the_entrys_status(db, rule_on) -> None:
    """An entry retired after the lookup ran is still the top item of that lookup: its `conclusion` is its side."""
    alert_id = _with_lookup(db, 0.9, INCIDENT)
    db.execute("UPDATE knowledge_entries SET status = 'retired'")

    run_triage_job(db, _job(alert_id), adapter=_model_fp())

    stored = _stored(db, alert_id)
    assert stored["result"]["suggested_action"] == TP
    assert stored["gate_result"]["rag_rule"]["entry_side"] == "incident"


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
        "entry_side": None,
        "rule_verdict": None,
        "basis": None,
    }
    assert stored["gate_result"]["steps"]["3r"] == "n/a"
    assert stored["gate_result"]["forced"] is False and stored["gate_result"]["forced_by"] == []


def test_a_lookup_that_kept_no_match_and_scored_nothing_leaves_the_models_verdict(
    db, rule_on
) -> None:
    alert_id = _seed_alert(db, suggestion_visible=True)
    put_lookup(db, alert_id, matches=[])

    run_triage_job(db, _job(alert_id), adapter=_model())

    stored = _stored(db, alert_id)
    assert stored["result"]["suggested_action"] == TP
    assert stored["gate_result"]["rag_rule"]["best_pct"] is None
    assert stored["gate_result"]["rag_rule"]["entry_side"] is None


def _with_ranked_lookup(db, ranked: tuple[tuple[float, str], ...]) -> str:
    """A visible-arm head with a stored `ok` lookup that KEPT NO MATCH (`matches` is `[]`) and whose rerank
    scored `ranked` - `(score, the candidate entry's conclusion)`, best first (DEC-220: `rag_results.ranked`, every
    candidate): the history is in the prompt, so the run names the lookup. A candidate is a real entry, so its
    conclusion can be read. `rag_results` is append-only, so the row is written with its ranking.
    """
    alert_id = _seed_alert(db, suggestion_visible=True)
    ranking = [
        {"entry_id": add_entry(db, conclusion=conclusion), "score": score}
        for score, conclusion in ranked
    ]
    db.execute(
        "INSERT INTO rag_results (lookup_id, subject_kind, subject_id, status, history, matches, ranked)"
        " VALUES (%s, 'alert', %s, 'ok', %s::jsonb, '[]'::jsonb, %s::jsonb)",
        (uuid.uuid4(), alert_id, json.dumps(history_json(4)), json.dumps(ranking)),
    )
    return alert_id


# ── a lookup that kept no match: the best scored candidate, under the floor, is the top item ─────


def test_a_47_percent_incident_candidate_under_the_floor_turns_a_model_true_positive_into_false_positive(
    db, rule_on, monkeypatch
) -> None:
    """The lookup scored 47 % and kept no match (the floor is 50 %), the threshold is 80. "Under 80" includes
    "under the floor": the candidate is the top item, an incident under the threshold, so ① says `false_positive`.
    The percentage is the page's `below_floor_pct` for the same stored run."""
    monkeypatch.setenv("RAG_MIN_SCORE", "0.5")
    alert_id = _with_ranked_lookup(db, ((0.47, INCIDENT), (0.31, BENIGN), (0.12, BENIGN)))

    run_triage_job(db, _job(alert_id), adapter=_model())

    stored = _stored(db, alert_id)
    assert (
        stored["rag_lookup_id"] is not None
    )  # the run holds the lookup whose ranking the page reads
    assert stored["result"]["suggested_action"] == FP
    gate_result = stored["gate_result"]
    assert gate_result["final_verdict"] == FP and gate_result["proposed_verdict"] == TP
    assert gate_result["rag_rule"] == _rule(
        47, "incident", verdict=FP, changed=True, basis="below_floor"
    )
    assert gate_result["steps"]["3r"] == "changed"
    assert gate_result["forced"] is False and gate_result["forced_by"] == []

    view = get_alert_view(db, alert_id)
    assert view["rag"] == {
        "best_pct": None,
        "not_applied": None,
        "below_floor_pct": 47,
        "floor_pct": 50,
    }
    assert gate_result["rag_rule"]["best_pct"] == view["rag"]["below_floor_pct"]
    # served as an ordinary conclusion: the verdict ① ended with, no confidence, nothing of a rule
    assert view["proposed_action"] == FP
    assert view["suggestion"]["confidence"] is None
    assert "rag_rule" not in set(_keys(view))
    assert _stored(db, alert_id) == stored  # serving changed nothing


def test_a_47_percent_benign_candidate_leaves_the_models_verdict(db, rule_on, monkeypatch) -> None:
    monkeypatch.setenv("RAG_MIN_SCORE", "0.5")
    alert_id = _with_ranked_lookup(db, ((0.47, BENIGN), (0.31, INCIDENT)))

    run_triage_job(db, _job(alert_id), adapter=_model())

    stored = _stored(db, alert_id)
    assert stored["result"]["suggested_action"] == TP
    assert stored["gate_result"]["rag_rule"] == _rule(
        47, "benign", verdict=None, changed=False, applied=False, basis="below_floor"
    )
    assert stored["gate_result"]["steps"]["3r"] == "n/a"
    view = get_alert_view(db, alert_id)
    assert view["rag"]["below_floor_pct"] == 47
    assert view["proposed_action"] == TP  # served as the model's own answer, with its confidence
    assert view["suggestion"]["confidence"] == TRIAGE_V4_TRUE_POSITIVE["confidence"]


def test_the_best_candidate_decides_and_a_tie_goes_to_the_incident(
    db, rule_on, monkeypatch
) -> None:
    monkeypatch.setenv("RAG_MIN_SCORE", "0.5")
    alert_id = _with_ranked_lookup(db, ((0.4, BENIGN), (0.4, INCIDENT), (0.2, BENIGN)))

    run_triage_job(db, _job(alert_id), adapter=_model())

    rule = _stored(db, alert_id)["gate_result"]["rag_rule"]
    assert (rule["best_pct"], rule["entry_side"], rule["basis"]) == (40, "incident", "below_floor")


def test_a_candidate_whose_entry_is_gone_gives_a_number_and_no_side(
    db, rule_on, monkeypatch
) -> None:
    monkeypatch.setenv("RAG_MIN_SCORE", "0.5")
    alert_id = _seed_alert(db, suggestion_visible=True)
    ranking = [{"entry_id": str(uuid.uuid4()), "score": 0.47}]  # no such entry
    db.execute(
        "INSERT INTO rag_results (lookup_id, subject_kind, subject_id, status, history, matches, ranked)"
        " VALUES (%s, 'alert', %s, 'ok', %s::jsonb, '[]'::jsonb, %s::jsonb)",
        (uuid.uuid4(), alert_id, json.dumps(history_json(4)), json.dumps(ranking)),
    )

    run_triage_job(db, _job(alert_id), adapter=_model())

    stored = _stored(db, alert_id)
    assert stored["result"]["suggested_action"] == TP
    rule = stored["gate_result"]["rag_rule"]
    assert (rule["best_pct"], rule["entry_side"], rule["applied"]) == (47, None, False)


def test_a_kept_match_is_the_top_item_and_the_page_has_no_below_floor_number(
    db, rule_on, monkeypatch
) -> None:
    """The counterpart: the lookup kept a 62 % incident match. The basis is `match`, the page's `best_pct` is 62
    and `below_floor_pct` is null: the two are never both set."""
    monkeypatch.setenv("RAG_MIN_SCORE", "0.5")
    alert_id = _with_lookup(db, 0.62)

    run_triage_job(db, _job(alert_id), adapter=_model())

    stored = _stored(db, alert_id)
    assert stored["gate_result"]["rag_rule"]["best_pct"] == 62
    assert stored["gate_result"]["rag_rule"]["basis"] == "match"
    assert stored["result"]["suggested_action"] == FP
    rag = get_alert_view(db, alert_id)["rag"]
    assert rag["best_pct"] == 62
    assert rag["below_floor_pct"] is None and rag["floor_pct"] is None


def test_the_switch_off_still_shows_the_percentage_below_the_floor(db, monkeypatch) -> None:
    """The display does not depend on the rule's switch: with `TRIAGE_RAG_FP_BELOW_PCT` off the model's verdict
    stays (as it always did) and the page says the same 47 %."""
    _enable_llm(monkeypatch)
    monkeypatch.setenv("RAG_ENABLED", "true")
    monkeypatch.setenv("RAG_MIN_SCORE", "0.5")
    monkeypatch.delenv("TRIAGE_RAG_FP_BELOW_PCT", raising=False)
    alert_id = _with_ranked_lookup(db, ((0.47, INCIDENT),))

    run_triage_job(db, _job(alert_id), adapter=_model())

    assert _stored(db, alert_id)["result"]["suggested_action"] == TP
    assert get_alert_view(db, alert_id)["rag"]["below_floor_pct"] == 47


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


def test_entries_the_token_budget_dropped_leave_the_models_verdict(
    db, rule_on, monkeypatch
) -> None:
    """A budget one token under the full prompt takes the first cut, the entries (`learned_entries_dropped`): the
    history stays, so the run still names its lookup, but none of its matches reached the prompt. The page shows no
    number, and the rule has none: the model's verdict stays, though an incident matched at 91 %."""
    alert_id = _with_lookup(db, 0.91)
    full = evaluate_alert(
        db, alert_id, adapter=_model_fp(), cfg=config.load(), switches=EvalSwitches(rag=True)
    )
    monkeypatch.setenv("PROMPT_TOTAL_BUDGET_TOKENS", str(full.built.estimated_tokens - 1))

    run_triage_job(db, _job(alert_id), adapter=_model_fp())

    row = db.execute(
        "SELECT citation_warnings FROM llm_runs WHERE subject_id = %s AND role = 'proposer'",
        (alert_id,),
    ).fetchone()
    assert "learned_entries_dropped" in row[0]
    stored = _stored(db, alert_id)
    assert stored["rag_lookup_id"] is not None
    assert (
        stored["result"]["suggested_action"] == FP
    )  # the model's own answer, not the rule's `true_positive`
    rule = stored["gate_result"]["rag_rule"]
    assert (rule["best_pct"], rule["entry_side"], rule["applied"]) == (None, None, False)
    assert get_alert_view(db, alert_id)["rag"]["best_pct"] is None


# ── what Tier 1 is served ────────────────────────────────────────────────────────────────────────


def test_the_queue_row_serves_the_verdict_it_ended_with_and_no_confidence(db, rule_on) -> None:
    alert_id = _with_lookup(db, 0.62)
    run_triage_job(db, _job(alert_id), adapter=_model())

    row = _queue_row(db, alert_id)

    assert row["suggested_action"] == FP
    assert row["proposed_action"] == FP  # not `true_positive`, the model's own answer
    assert row["confidence"] is None
    assert row["gate_forced"] is False


def test_the_alert_view_serves_the_verdict_it_ended_with_and_no_confidence_and_no_rule(
    db, rule_on
) -> None:
    alert_id = _with_lookup(db, 0.62)
    run_triage_job(db, _job(alert_id), adapter=_model())

    view = get_alert_view(db, alert_id)

    assert view["proposed_action"] == FP
    suggestion = view["suggestion"]
    assert suggestion["suggested_action"] == FP and suggestion["confidence"] is None
    assert suggestion["gate"]["proposed_verdict"] == FP
    assert suggestion["gate"]["final_verdict"] == FP
    assert suggestion["gate"]["forced"] is False
    assert view["rag"]["best_pct"] == 62
    # DEC-225: Tier 1 is not told that a rule exists
    assert "rag_rule" not in suggestion["gate"]
    assert "rag_rule" not in set(_keys(view))
    assert "3r" not in [row["id"] for row in view["analysis"]["checks"]]
    assert view["analysis"]["rag"]["threshold_pct"] == 0


def test_the_other_direction_is_served_as_an_ordinary_true_positive(db, rule_on) -> None:
    """The model said `false_positive`; an incident at 85 % made it `true_positive`. Tier 1 reads "AI kết luận: TP"
    with the 85 % and nothing else: not the model's own answer, its confidence, the verifier's verdict, a
    disagreement or a rule."""
    alert_id = _with_lookup(db, 0.85)
    run_triage_job(db, _job(alert_id), adapter=_model_fp(verifier=VERIFIER_DISAGREES))

    row = _queue_row(db, alert_id)
    view = get_alert_view(db, alert_id)

    assert row["suggested_action"] == TP and row["proposed_action"] == TP
    assert row["confidence"] is None and row["gate_forced"] is False
    assert view["proposed_action"] == TP
    suggestion = view["suggestion"]
    assert suggestion["suggested_action"] == TP and suggestion["confidence"] is None
    assert (
        suggestion["gate"]["proposed_verdict"] == TP and suggestion["gate"]["final_verdict"] == TP
    )
    assert suggestion["gate"]["verifier_verdict"] is None
    assert (
        "verifier_disagrees" not in row["held_by"] and "verifier_disagrees" not in view["held_by"]
    )
    assert view["rag"]["best_pct"] == 85
    for shown in (view, row):
        assert "rag_rule" not in set(_keys(shown))
    assert "3r" not in [r["id"] for r in view["analysis"]["checks"]]
    assert "6" not in [
        r["id"] for r in view["analysis"]["checks"]
    ]  # the verifier row would give it away
    assert view["analysis"]["reading_attack"] is None


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
    assert after["result"]["confidence"] == TRIAGE_V4_TRUE_POSITIVE["confidence"]


def test_a_run_the_rule_applied_to_without_changing_it_is_served_the_same(db, rule_on) -> None:
    alert_id = _with_lookup(db, 0.62)
    run_triage_job(db, _job(alert_id), adapter=_model_fp())

    row = _queue_row(db, alert_id)
    view = get_alert_view(db, alert_id)

    assert row["proposed_action"] == FP and row["confidence"] is None
    assert view["proposed_action"] == FP and view["suggestion"]["confidence"] is None
    assert "rag_rule" not in view["suggestion"]["gate"]


def test_a_run_the_rule_did_not_apply_to_is_served_the_models_answer_and_confidence(
    db, rule_on
) -> None:
    alert_id = _with_lookup(db, 0.62, BENIGN)  # a benign item under the threshold: not applied
    run_triage_job(db, _job(alert_id), adapter=_model())

    row = _queue_row(db, alert_id)
    view = get_alert_view(db, alert_id)

    assert row["proposed_action"] == TP
    assert row["confidence"] == TRIAGE_V4_TRUE_POSITIVE["confidence"]
    assert view["proposed_action"] == TP
    assert view["suggestion"]["confidence"] == TRIAGE_V4_TRUE_POSITIVE["confidence"]
    assert view["suggestion"]["gate"]["proposed_verdict"] == TP
    assert "rag_rule" not in set(_keys(view))  # not served for any run


def test_a_dec_219_stored_document_still_reads_in_every_reader(db, rule_on) -> None:
    """A run stored before this change carries a four-key `rag_rule`: it is withheld the same way (its `applied` is
    what the readers use) and read without an error by the alert view, the queue and the analysis.
    """
    alert_id = _seed_alert(db, suggestion_visible=True)
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
        "steps": {"1": "ok", "2": "ok", "3": "dropped:0", "3r": "changed", "4": "ok", "6": "agree"},
        "missing": [],
        "warnings": [],
        "facts": {"correlated_clusters": 2},
        "verifier_verdict": TP,
    }
    _decide_insert_run(db, alert_id, result=result, gate_result=gate_result)

    view = get_alert_view(db, alert_id)
    row = _queue_row(db, alert_id)

    assert view["proposed_action"] == FP and row["proposed_action"] == FP
    assert view["suggestion"]["confidence"] is None and row["confidence"] is None
    assert view["suggestion"]["gate"]["verifier_verdict"] is None
    assert "rag_rule" not in set(_keys(view)) and "rag_rule" not in set(_keys(row))
    assert "3r" not in [r["id"] for r in view["analysis"]["checks"]]


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
        "rag_rule": _rule(62, "incident", verdict=FP, changed=True),
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


# ── nothing served gives the model's answer away (fix round 1) ──────────────────────────────────

#: The verifier answers `needs_review`: step 6 flags the run, `verifier_verdict` is stored, and `held_by` would
#: say `verifier_disagrees` - which, for a run the rule applied to, would tell that the model's verdict was not
#: the verdict ① ended with (the verifier was sent the model's own verdict).
VERIFIER_DISAGREES = {"agree": False, "structured_only_verdict": "needs_review", "reason": "no"}


def test_an_applied_run_is_served_no_verifier_verdict_and_no_verifier_disagrees(
    db, rule_on
) -> None:
    alert_id = _with_lookup(db, 0.62)
    run_triage_job(db, _job(alert_id), adapter=_model(verifier=VERIFIER_DISAGREES))

    row = _queue_row(db, alert_id)
    view = get_alert_view(db, alert_id)

    assert "verifier_disagrees" not in row["held_by"]
    assert "verifier_disagrees" not in view["held_by"]
    assert row["held_by"] == view["held_by"]
    assert view["suggestion"]["gate"]["verifier_verdict"] is None


def test_the_stored_gate_result_keeps_what_serving_withholds(db, rule_on) -> None:
    alert_id = _with_lookup(db, 0.62)
    run_triage_job(db, _job(alert_id), adapter=_model(verifier=VERIFIER_DISAGREES))
    before = _stored(db, alert_id)

    get_alert_view(db, alert_id)
    _queue_row(db, alert_id)

    after = _stored(db, alert_id)
    assert after == before
    gate_result = after["gate_result"]
    assert gate_result["rag_rule"]["changed"] is True
    assert gate_result["verifier_verdict"] == "needs_review"
    assert gate_result["steps"]["6"] == "disagree" and "step6" in gate_result["flagged_by"]


def test_a_run_the_rule_did_not_apply_to_is_served_the_verifier_verdict_and_the_disagreement(
    db, rule_on
) -> None:
    alert_id = _with_lookup(
        db, 0.91, BENIGN
    )  # a benign item at 91 %: the rule applies (false_positive)
    run_triage_job(db, _job(alert_id), adapter=_model_fp(verifier=VERIFIER_DISAGREES))
    applied_row = _queue_row(db, alert_id)
    assert "verifier_disagrees" not in applied_row["held_by"]  # control: this one IS applied

    other = _with_lookup(db, 0.62, BENIGN)  # a benign item under 80: not applied
    run_triage_job(db, _job(other), adapter=_model_fp(verifier=VERIFIER_DISAGREES))

    row = _queue_row(db, other)
    view = get_alert_view(db, other)

    assert "verifier_disagrees" in row["held_by"] and "verifier_disagrees" in view["held_by"]
    assert view["suggestion"]["gate"]["verifier_verdict"] == "needs_review"
    assert "rag_rule" not in set(_keys(view))


def test_an_unusable_verifier_answer_stays_in_held_by_for_an_applied_run(db, rule_on) -> None:
    alert_id = _with_lookup(db, 0.62)
    not_the_verifiers_shape = {"agree": "yes"}  # twice: the first call and the repair round
    adapter = _RecordingLLM(
        responses=[TRIAGE_V4_TRUE_POSITIVE, not_the_verifiers_shape, not_the_verifiers_shape]
    )
    run_triage_job(db, _job(alert_id), adapter=adapter)

    row = _queue_row(db, alert_id)
    view = get_alert_view(db, alert_id)

    assert "verifier_invalid" in row["held_by"] and "verifier_invalid" in view["held_by"]


# ── the blind arm sees none of it ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("answer, score", [("tp", 0.62), ("fp", 0.85)])
def test_a_blind_undecided_head_shows_no_rag_rule_and_no_served_verdict(
    db, rule_on, answer, score
) -> None:
    alert_id = _seed_alert(db, suggestion_visible=False)
    put_lookup(db, alert_id, matches=[approved(db, ENTRY, "giong", score, INCIDENT)])
    run_triage_job(db, _job(alert_id), adapter=_model() if answer == "tp" else _model_fp())

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
            "analysis",
        ):
            assert key not in shown
