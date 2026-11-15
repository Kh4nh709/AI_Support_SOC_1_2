"""DEC-221, card AP-T2: how `tier1.queue` feeds `tier1.analysis` and what the blind arm does with the result. PURE: the
connection is a fake that answers the two statements the reader runs, so nothing here needs a database (the same
paths against a real one are `test_analysis_db.py`).

* the newest run's row is read ONCE and unpacked strictly (the statement always returns the `ranked` column; a row of
  any other width is a bug, not "a lookup with none");
* the statement selects what the analysis reads and no model column, and no other statement of the view names one
  (goal G5);
* `analysis` is a `visibility.ANALYST_HIDE` key: dropped wherever `suggestion` is dropped, in analyst mode and in
  labeling mode, at any depth.
"""

from __future__ import annotations

import datetime as dt
import inspect
import re
from types import SimpleNamespace

import pytest
from app.tier1 import analysis, queue, visibility

RUN_ID = "11111111-1111-1111-1111-111111111111"
NOW = dt.datetime(2026, 11, 15, 9, 30, tzinfo=dt.UTC)
RESULT = {
    "suggested_action": "false_positive",
    "confidence": "high",
    "reasons": [{"claim": "c", "quote": "q", "source": "wazuh_raw_log"}],
    "summary": "SUMMARY-OF-THE-MODEL",
    "next_checks": ["one"],
}
GATE = {
    "version": 2,
    "proposed_verdict": "false_positive",
    "final_verdict": "false_positive",
    "forced": False,
    "forced_by": [],
    "flagged_by": [],
    "steps": {
        "1": "ok",
        "2": "ok",
        "3": "dropped:0",
        "3r": "n/a",
        "4": "ok",
        "5": "findings:0",
        "6": "agree",
    },
    "facts": {"category": "brute_force", "severity": "low", "correlated_clusters": 3},
}


def _row(**over):
    """A row as `queue._SUGGESTION_SQL` returns it, in its column order."""
    cols = {
        "run_id": RUN_ID,
        "result": RESULT,
        "gate_result": GATE,
        "created_at": NOW,
        "citation_warnings": [],
        "matches": None,
        "ranked": None,
        "history": None,
        "input_tokens": 1000,
        "output_tokens": 200,
        "latency_ms": 1500,
        "cost_usd": None,
    }
    cols.update(over)
    return tuple(cols.values())


class _Conn:
    """What the reader needs of a connection: the newest proposer row, and the entries read when candidates are
    listed. It records every statement."""

    def __init__(self, row, entries=()):
        self.row = row
        self.entries = list(entries)
        self.statements: list[str] = []

    def execute(self, statement, params=None):
        text = str(statement)
        self.statements.append(text)
        if "FROM llm_runs" in text:
            return SimpleNamespace(fetchone=lambda: self.row)
        if "FROM knowledge_entries" in text:
            return SimpleNamespace(fetchall=lambda: self.entries)
        raise AssertionError(f"unexpected statement: {text[:60]}")


# ── the row is read once and unpacked strictly ──────────────────────────────────────────────────


def test_the_statement_returns_the_twelve_columns_in_this_order():
    sql = " ".join(queue._SUGGESTION_SQL.split())
    select = sql[len("SELECT ") : sql.index(" FROM llm_runs")]
    assert [c.strip() for c in select.split(",")] == [
        "r.run_id",
        "r.result",
        "r.gate_result",
        "r.created_at",
        "r.citation_warnings",
        "g.matches",
        "g.ranked",
        "g.history",
        "r.input_tokens",
        "r.output_tokens",
        "r.latency_ms",
        "r.cost_usd",
    ]
    assert "rag_results g ON g.lookup_id = r.rag_lookup_id" in sql
    assert "LIMIT 1" in sql


@pytest.mark.parametrize("width", [0, 1, 4, 5, 6, 7, 8, 11, 13])
def test_a_row_of_any_other_width_is_refused(width):
    """The statement always returns its twelve columns: a row with fewer (the shape before DEC-220 had six) is not
    read as "a lookup with none" any more."""
    row = _row()[:width] + (None,) * max(0, width - 12)
    with pytest.raises((TypeError, ValueError)):
        queue.latest_suggestion_rag(_Conn(row), "a-1")
    with pytest.raises((TypeError, ValueError)):
        queue.latest_suggestion_analysis(_Conn(row), "a-1", mitre_ids=[])


def test_no_run_gives_no_suggestion_the_empty_pair_and_no_analysis_and_no_second_statement():
    conn = _Conn(None)
    suggestion, proposed, held, rag, built = queue.latest_suggestion_analysis(
        conn, "a-1", mitre_ids=["T1110"]
    )
    assert (suggestion, proposed, held, built) == (None, None, [], None)
    assert rag == {
        "best_pct": None,
        "not_applied": None,
        "below_floor_pct": None,
        "floor_pct": None,
    }
    assert len(conn.statements) == 1


def test_a_run_with_no_result_has_a_pair_and_no_suggestion_and_no_analysis():
    conn = _Conn(_row(result=None, citation_warnings=["rag_not_applied:quota"]))
    suggestion, _proposed, _held, rag, built = queue.latest_suggestion_analysis(
        conn, "a-1", mitre_ids=[]
    )
    assert suggestion is None and built is None
    assert rag["not_applied"] == "quota"


def test_the_four_values_of_the_old_reader_are_the_first_four_of_the_new_one():
    row = _row()
    old = queue.latest_suggestion_rag(_Conn(row), "a-1")
    new = queue.latest_suggestion_analysis(_Conn(row), "a-1", mitre_ids=["T1110"])
    assert len(old) == 4 and len(new) == 5
    assert old[1:] == new[1:4]
    assert old[0].to_dict() == new[0].to_dict()


def test_the_run_is_read_once_and_a_run_with_no_candidate_costs_no_second_statement():
    conn = _Conn(_row())
    *_rest, built = queue.latest_suggestion_analysis(conn, "a-1", mitre_ids=["T1110"])
    assert len(conn.statements) == 1
    assert built["summary"] == "SUMMARY-OF-THE-MODEL"
    assert built["tech"]["mitre_ids"] == ["T1110"]
    assert built["tech"]["input_tokens"] == 1000 and built["tech"]["correlated_at_analysis"] == 3


def test_candidates_are_read_with_one_more_statement_that_touches_only_the_entries():
    entry = "22222222-2222-2222-2222-222222222222"
    ranked = [{"entry_id": entry, "score": 0.47}]
    conn = _Conn(
        _row(matches=[], ranked=ranked),
        entries=[(entry, "confirmed_incident", "---\nx: 1\n---\n\n# A title\n\nbody\n")],
    )
    *_rest, built = queue.latest_suggestion_analysis(conn, "a-1", mitre_ids=[], rag_min_score=0.5)
    assert len(conn.statements) == 2 and "FROM knowledge_entries" in conn.statements[1]
    assert built["rag"]["candidates"] == [
        {"pct": 47, "title": "A title", "conclusion": "confirmed_incident"}
    ]
    assert built["rag"]["state"] == "below_floor" and built["rag"]["best_pct"] == 47


def test_the_rag_pair_and_the_panel_come_from_the_same_floor():
    ranked = [{"entry_id": "not-a-uuid", "score": 0.4999}]
    conn = _Conn(_row(matches=[], ranked=ranked))
    _s, _p, _h, pair, built = queue.latest_suggestion_analysis(
        conn, "a-1", mitre_ids=[], rag_min_score=0.5
    )
    assert pair["below_floor_pct"] == 49 and built["rag"]["best_pct"] == 49
    assert pair["floor_pct"] == built["rag"]["floor_pct"] == 50
    assert len(conn.statements) == 1  # an id that is not a UUID is not looked up


# ── G5: the model's name is never selected ──────────────────────────────────────────────────────


def test_no_statement_of_the_tier_1_readers_selects_a_model_column():
    for name in (
        "_SUGGESTION_SQL",
        "_STOPPED_BY_SQL",
        "_SUGGESTIONS_SQL",
        "_QUEUE_SQL",
        "_VIEW_SQL",
        "_SOAR_SQL",
    ):
        assert "model" not in getattr(queue, name).lower(), name
    assert "model_id" not in inspect.getsource(analysis)
    assert "model_id" not in inspect.getsource(queue.get_alert_view)
    assert not [c for c in queue._VIEW_COLUMNS if "model" in c]
    assert not [c for c in queue._QUEUE_COLUMNS if "model" in c]
    assert not [f for f in queue.Suggestion.__dataclass_fields__ if "model" in f]


# ── the blind arm ───────────────────────────────────────────────────────────────────────────────


def test_analysis_is_hidden_wherever_the_suggestion_is_hidden():
    assert "analysis" in visibility.ANALYST_HIDE
    assert "analysis" in visibility.LABELING_DENYLIST
    assert visibility.ANALYST_HIDE <= visibility.LABELING_DENYLIST


def _view():
    return {
        "alert_id": "a-1",
        "status": "queued_tier1",
        "suggestion_visible": False,
        "suggestion": {"suggested_action": "false_positive"},
        "analysis": {"summary": "SUMMARY-OF-THE-MODEL", "tech": {"mitre_ids": ["T1110"]}},
        "rag": {"best_pct": 87},
        "nested": [{"analysis": {"summary": "x"}, "keep": 1}],
    }


def _keys(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _keys(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _keys(item)


@pytest.mark.parametrize("status", ["queued_tier1", "tier1_active", "archived"])
def test_a_blind_undecided_view_never_has_analysis(status):
    got = visibility.strip(_view(), status=status, suggestion_visible=False, mode="analyst")
    assert "analysis" not in got and "SUMMARY-OF-THE-MODEL" not in repr(got)
    assert "suggestion" not in got  # dropped by the same rule


@pytest.mark.parametrize(
    "status", ["closed_fp", "closed_benign", "closed_confirmed", "escalated_tier2", "auto_closed"]
)
def test_a_decided_view_keeps_it_like_the_suggestion(status):
    got = visibility.strip(_view(), status=status, suggestion_visible=False, mode="analyst")
    assert "analysis" in got and "suggestion" in got


def test_the_visible_arm_keeps_it():
    got = visibility.strip(_view(), status="queued_tier1", suggestion_visible=True, mode="analyst")
    assert got["analysis"]["summary"] == "SUMMARY-OF-THE-MODEL"


@pytest.mark.parametrize("visible", [True, False])
@pytest.mark.parametrize("status", ["queued_tier1", "closed_fp"])
def test_the_labelling_page_never_has_it_at_any_depth(visible, status):
    got = visibility.strip(_view(), status=status, suggestion_visible=visible, mode="labeling")
    assert "analysis" not in set(_keys(got))
    assert "SUMMARY-OF-THE-MODEL" not in repr(got)


def test_the_queue_rows_carry_no_analysis():
    assert "analysis" not in queue._QUEUE_COLUMNS
    assert not re.search(r"\banalysis\b", queue._QUEUE_SQL)
