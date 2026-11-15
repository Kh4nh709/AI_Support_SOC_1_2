"""DEC-221, card AP-T2: `llm.rag_view.rag_panel`, the part of `analysis.rag` that the alert view and (later) the case
view share (`docs/superpowers/specs/2026-11-15-ai-analysis-panel-redesign.md` section 5). Pure: no database.

It takes what the two readers already hold - the stored `matches` and `ranked` of the lookup the run's prompt held,
the run's `citation_warnings`, the failure kinds, the floor and the rule's threshold - and returns the state, the
numbers and the top three candidates as `{entry_id, pct}`. The title and the conclusion of an entry are a database
read (`rag.entries.entry_cards`) and belong to the reader. The numbers must be the ones the `rag` pair of
DEC-213/220 gives for the same run (`rag_view.rag_view`): the tests hold the two together.
"""

from __future__ import annotations

import copy
import math

import pytest
from app.llm import rag_view
from app.llm.builder import LEARNED_ENTRIES_DROPPED_WARNING, rag_not_applied_warning
from app.rag.failures import FAILURE_KINDS

KINDS = FAILURE_KINDS
FLOOR = 0.5


def _match(score: object, entry: str = "m1") -> dict:
    return {"entry_id": entry, "level": "giong", "content_sha256": "0" * 64, "score": score}


def _cand(score: object, entry: str = "c1") -> dict:
    return {"entry_id": entry, "score": score}


def _panel(matches, ranked, *, warnings=None, floor=FLOOR, threshold=0) -> dict:
    return rag_view.rag_panel(
        matches, warnings, KINDS, ranked=ranked, floor=floor, threshold=threshold
    )


def test_the_states_are_five_and_in_this_order():
    assert rag_view.STATES == ("matched", "below_floor", "no_candidate", "failed", "no_lookup")
    assert rag_view.CANDIDATES_SHOWN == 3


def test_the_panel_has_exactly_these_keys():
    assert list(_panel(None, None)) == [
        "state",
        "failure",
        "best_pct",
        "floor_pct",
        "threshold_pct",
        "scored",
        "candidates",
    ]


# ── matched ─────────────────────────────────────────────────────────────────────────────────────


def test_a_kept_match_is_matched_with_the_best_match_and_the_top_three_of_the_ranking():
    ranked = [_cand(0.87, "a"), _cand(0.61, "b"), _cand(0.47, "c"), _cand(0.3, "d")]
    panel = _panel([_match(0.87, "a"), _match(0.61, "b")], ranked, threshold=80)
    assert panel == {
        "state": "matched",
        "failure": None,
        "best_pct": 87,
        "floor_pct": 50,
        "threshold_pct": 80,
        "scored": 4,
        "candidates": [
            {"entry_id": "a", "pct": 87},
            {"entry_id": "b", "pct": 61},
            {"entry_id": "c", "pct": 47},
        ],
    }


def test_a_matched_runs_best_pct_keeps_the_pages_rounding():
    panel = _panel([_match(0.866)], [_cand(0.866)])
    assert panel["best_pct"] == rag_view.percent(0.866) == 87


def test_matched_without_a_ranking_reads_the_candidates_from_the_matches():
    """A lookup stored before migration 023 has no `ranked`; its kept matches are the ranking."""
    panel = _panel([_match(0.7, "x"), _match(0.9, "y")], None)
    assert panel["state"] == "matched"
    assert [c["entry_id"] for c in panel["candidates"]] == ["y", "x"]
    assert panel["scored"] == 2


def test_a_match_with_no_score_is_still_matched_with_no_number():
    panel = _panel([{"entry_id": "old"}], None)
    assert (panel["state"], panel["best_pct"], panel["candidates"]) == ("matched", None, [])


# ── below the floor ─────────────────────────────────────────────────────────────────────────────


def test_candidates_all_under_the_floor_are_below_floor_with_the_best_of_them():
    panel = _panel([], [_cand(0.31, "a"), _cand(0.47, "b"), _cand(0.12, "c")], threshold=80)
    assert panel == {
        "state": "below_floor",
        "failure": None,
        "best_pct": 47,
        "floor_pct": 50,
        "threshold_pct": 80,
        "scored": 3,
        "candidates": [
            {"entry_id": "b", "pct": 47},
            {"entry_id": "a", "pct": 31},
            {"entry_id": "c", "pct": 12},
        ],
    }


def test_a_candidate_under_the_floor_is_cut_down_everywhere_it_is_printed():
    """DEC-221: the best candidate is 49, in `best_pct` and in the list, never 50 beside a floor of 50."""
    panel = _panel([], [_cand(0.4999, "a"), _cand(0.3, "b")])
    assert panel["best_pct"] == 49
    assert panel["candidates"][0] == {"entry_id": "a", "pct": 49}


def test_the_candidates_are_the_top_three_best_first_and_ties_keep_the_stored_order():
    ranked = [_cand(0.2, "a"), _cand(0.4, "b"), _cand(0.4, "c"), _cand(0.1, "d"), _cand(0.3, "e")]
    panel = _panel([], ranked)
    assert [c["entry_id"] for c in panel["candidates"]] == ["b", "c", "e"]
    assert panel["scored"] == 5


def test_a_candidate_without_an_entry_id_counts_as_scored_but_is_not_listed():
    panel = _panel([], [{"score": 0.45}, _cand(0.3, "b")])
    assert panel["scored"] == 2
    assert [c["entry_id"] for c in panel["candidates"]] == ["b"]
    assert panel["best_pct"] == 45  # the pair's number: the best score of the ranking, listed or not


@pytest.mark.parametrize("junk", [None, "0.4", True, math.nan, math.inf, -0.1, 1.01, 47])
def test_a_score_that_is_not_a_number_in_zero_to_one_is_not_scored(junk):
    panel = _panel([], [_cand(junk, "j"), _cand(0.44, "k")])
    assert panel["scored"] == 1
    assert [c["entry_id"] for c in panel["candidates"]] == ["k"]


# ── no candidate ────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("ranked", [[], ["x", None, 3], [_cand(None)], [_cand("0.4")]])
def test_a_lookup_that_scored_nothing_is_no_candidate(ranked):
    panel = _panel([], ranked, threshold=80)
    assert panel == {
        "state": "no_candidate",
        "failure": None,
        "best_pct": None,
        "floor_pct": 50,
        "threshold_pct": 80,
        "scored": 0,
        "candidates": [],
    }


def test_a_lookup_row_with_matches_but_no_ranking_and_none_kept_is_no_candidate():
    assert _panel([], None)["state"] == "no_candidate"
    assert _panel(None, [])["state"] == "no_candidate"


def test_the_floor_moved_since_the_lookup_gives_no_candidate_like_the_pair_does():
    """The lookup kept nothing, and its best candidate is now over the (lowered) floor: the DEC-220 pair says
    nothing of a floor then, so the panel must not call it below the floor."""
    panel = _panel([], [_cand(0.55, "a")], floor=0.5)
    assert panel["state"] == "no_candidate" and panel["best_pct"] is None
    assert panel["candidates"] == []


# ── failed ──────────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("kind", FAILURE_KINDS)
def test_a_failed_lookup_is_failed_with_the_closed_kind_and_nothing_else(kind):
    panel = _panel(None, None, warnings=[rag_not_applied_warning(kind)], threshold=80)
    assert panel == {
        "state": "failed",
        "failure": kind,
        "best_pct": None,
        "floor_pct": None,
        "threshold_pct": 80,
        "scored": None,
        "candidates": [],
    }


def test_a_failure_wins_over_a_ranking_the_run_cannot_have():
    panel = _panel([], [_cand(0.4)], warnings=[rag_not_applied_warning("quota")])
    assert (panel["state"], panel["failure"], panel["candidates"]) == ("failed", "quota", [])


def test_a_notice_of_a_kind_this_build_does_not_know_is_not_a_failure():
    assert _panel(None, None, warnings=["rag_not_applied:martian"])["state"] == "no_lookup"


# ── no lookup ───────────────────────────────────────────────────────────────────────────────────


def test_a_run_that_holds_no_lookup_is_no_lookup():
    assert _panel(None, None) == {
        "state": "no_lookup",
        "failure": None,
        "best_pct": None,
        "floor_pct": None,
        "threshold_pct": 0,
        "scored": None,
        "candidates": [],
    }


def test_entries_the_budget_dropped_never_reached_the_prompt_so_the_run_has_no_lookup():
    """The lookup kept matches but the token budget cut them: the DEC-213 pair gives `best_pct` None for such a
    run, and the panel says `no_lookup` with nothing listed rather than numbers the run did not use."""
    panel = _panel(
        [_match(0.62)], [_cand(0.62), _cand(0.4)], warnings=[LEARNED_ENTRIES_DROPPED_WARNING]
    )
    assert panel["state"] == "no_lookup"
    assert (panel["best_pct"], panel["scored"], panel["candidates"]) == (None, None, [])


# ── the threshold ───────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("given", "served"),
    [(0, 0), (80, 80), (100, 100), (None, 0), (True, 0), ("80", 0), (-5, 0), (80.0, 0)],
)
def test_the_threshold_is_the_rules_integer_and_zero_for_anything_else(given, served):
    assert _panel(None, None, threshold=given)["threshold_pct"] == served


# ── it is the pair's number ─────────────────────────────────────────────────────────────────────

_CASES = [
    ([_match(0.87), _match(0.61)], [_cand(0.87), _cand(0.61), _cand(0.47)], None),
    ([_match(0.5)], [_cand(0.5)], None),
    ([], [_cand(0.47), _cand(0.31)], None),
    ([], [_cand(0.4999)], None),
    ([], [_cand(0.29)], None),
    ([], [], None),
    ([], None, None),
    (None, None, None),
    ([_match(0.62)], [_cand(0.62)], [LEARNED_ENTRIES_DROPPED_WARNING]),
    (None, None, [rag_not_applied_warning("timeout")]),
    ([], [_cand(0.55)], None),
    ([{"entry_id": "old"}], None, None),
]


@pytest.mark.parametrize(("matches", "ranked", "warnings"), _CASES)
def test_the_numbers_are_the_ones_the_rag_pair_gives_for_the_same_run(matches, ranked, warnings):
    pair = rag_view.rag_view(matches, warnings, KINDS, ranked=ranked, floor=FLOOR)
    panel = _panel(matches, ranked, warnings=warnings)
    expected = pair["best_pct"] if pair["best_pct"] is not None else pair["below_floor_pct"]
    assert panel["best_pct"] == expected
    assert panel["failure"] == pair["not_applied"]
    if pair["below_floor_pct"] is not None:
        assert panel["state"] == "below_floor" and panel["floor_pct"] == pair["floor_pct"]
    if pair["best_pct"] is not None:
        assert panel["state"] == "matched"
    if pair["not_applied"] is not None:
        assert panel["state"] == "failed"


@pytest.mark.parametrize(("matches", "ranked", "warnings"), _CASES)
def test_the_panel_never_changes_what_it_is_given(matches, ranked, warnings):
    before = copy.deepcopy((matches, ranked, warnings))
    _panel(matches, ranked, warnings=warnings, threshold=80)
    assert (matches, ranked, warnings) == before


@pytest.mark.parametrize("floor", [None, True, "0.5", math.nan, -0.1, 1.5])
def test_a_floor_that_is_not_a_number_in_zero_to_one_gives_no_floor_and_no_below_floor(floor):
    panel = _panel([], [_cand(0.4)], floor=floor)
    assert panel["floor_pct"] is None
    assert panel["state"] == "no_candidate"
