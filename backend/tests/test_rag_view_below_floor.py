"""DEC-220 (trial; `docs/superpowers/specs/2026-11-15-rag-below-floor-percentage.md`): `llm.rag_view.rag_view`
gains two keys, `below_floor_pct` and `floor_pct` - the percentage of the best candidate the rerank scored, for a
run whose lookup kept no match, and the floor it was under. Pure: no database. The readers that feed it
(`tier1.queue.get_alert_view`, `tier2.investigation_view`) are tested in `test_queue_rag.py` and
`test_investigation_view_rag.py`; this file pins the rules they share.

`ranked` is `rag_results.ranked` (`[{entry_id, score}]`, every candidate the rerank scored) and `floor` is
`RAG_MIN_SCORE`; both are plain values handed in (`llm` may not import `rag`, nor read the configuration).
`best_pct` and `not_applied` keep their meaning (`test_rag_view.py` holds them).
"""

from __future__ import annotations

import math

import pytest
from app.llm import rag_view
from app.llm.builder import rag_not_applied_warning
from app.rag.failures import FAILURE_KINDS
from app.tier1 import visibility

KINDS = FAILURE_KINDS
FLOOR = 0.5

#: The two keys of the pair that stay `None` for every run but one whose lookup kept no match.
NO_FLOOR = {"below_floor_pct": None, "floor_pct": None}
NOTHING = {"best_pct": None, "not_applied": None, **NO_FLOOR}


def _match(score: object) -> dict:
    return {"entry_id": "e1", "level": "giong", "content_sha256": "0" * 64, "score": score}


def _cand(score: object, entry: str = "c1") -> dict:
    return {"entry_id": entry, "score": score}


def _below(matches, ranked, *, warnings=None, floor=FLOOR) -> dict:
    return rag_view.rag_view(matches, warnings, KINDS, ranked=ranked, floor=floor)


# ── the number ──────────────────────────────────────────────────────────────────────────────────


def test_candidates_all_under_the_floor_give_the_best_of_them_and_the_floor():
    """The lookup kept no match (`matches` is `[]`); the best candidate scored 0.47 against a floor of 0.5."""
    pair = _below([], [_cand(0.31), _cand(0.47), _cand(0.12)])
    assert pair == {"best_pct": None, "not_applied": None, "below_floor_pct": 47, "floor_pct": 50}


def test_the_candidate_is_the_best_of_the_list_not_the_first_or_the_last():
    assert _below([], [_cand(0.2), _cand(0.49), _cand(0.3)])["below_floor_pct"] == 49
    assert _below([], [_cand(0.49), _cand(0.2)])["below_floor_pct"] == 49
    assert _below([], [_cand(0.2), _cand(0.49)])["below_floor_pct"] == 49


def test_the_percentage_is_the_score_times_a_hundred_cut_down_not_rounded():
    """DEC-221 (spec 5, last paragraph): the number under the floor is cut down, so it is always below
    `floor_pct`. A raw 0.4999 is 49, not 50; `best_pct` of a kept match keeps `round` (`rag_view.percent`)."""
    for value, expected in (
        (0.0, 0),
        (0.004, 0),
        (0.005, 0),
        (0.1, 10),
        (0.333, 33),
        (0.465, 46),
        (0.47, 47),
        (0.477, 47),
        (0.484, 48),
        (0.4949, 49),
        (0.495, 49),
        (0.4999, 49),
    ):
        assert _below([], [_cand(value)])["below_floor_pct"] == expected, value
    assert rag_view.percent(0.477) == 48  # the pages' own rounding is untouched
    assert rag_view.percent(0.4999) == 50


def test_cutting_down_is_not_fooled_by_the_floating_point_representation():
    """0.29 * 100 is 28.999999999999996 and 0.57 * 100 is 56.99999999999999: a plain `floor` would print 28
    and 56 for a score the model-free reranker returned as 29 % and 57 %."""
    assert 0.29 * 100 < 29 and 0.57 * 100 < 57
    assert _below([], [_cand(0.29)])["below_floor_pct"] == 29
    assert _below([], [_cand(0.57)], floor=0.6)["below_floor_pct"] == 57
    assert _below([], [_cand(0.58)], floor=0.6)["below_floor_pct"] == 58


@pytest.mark.parametrize("floor", [0.5, 0.505, 0.455, 0.9, 0.333])
def test_the_number_is_always_below_the_floor_it_is_printed_beside(floor):
    for raw in (0.0, 0.1, 0.3, 0.4, 0.4999, 0.5049, 0.4549, 0.8999, 0.3329):
        pair = _below([], [_cand(raw)], floor=floor)
        if raw < floor:
            assert pair["below_floor_pct"] < pair["floor_pct"], (raw, floor, pair)


def test_the_floor_is_the_rounded_floor_times_a_hundred():
    pair = _below([], [_cand(0.47)], floor=0.65)
    assert (pair["below_floor_pct"], pair["floor_pct"]) == (47, 65)
    pair = _below([], [_cand(0.1)], floor=0.855)
    assert (pair["below_floor_pct"], pair["floor_pct"]) == (10, rag_view.percent(0.855))


def test_a_candidate_with_a_score_of_zero_is_a_candidate():
    assert _below([], [_cand(0)]) == {**NOTHING, "below_floor_pct": 0, "floor_pct": 50}


# ── when there is none ──────────────────────────────────────────────────────────────────────────


def test_a_kept_match_gives_best_pct_and_no_below_floor_number():
    """Unchanged for a lookup that kept a match: `best_pct` is the number and the two new keys are `None`, even
    though the rerank's list holds candidates under the floor too."""
    matches = [_match(0.87), _match(0.61)]
    pair = _below(matches, [_cand(0.87), _cand(0.61), _cand(0.47)])
    assert pair == {"best_pct": 87, "not_applied": None, **NO_FLOOR}


@pytest.mark.parametrize("ranked", [[_cand(0.3), _cand(0.7)], [_cand(0.2)], [], None])
def test_best_pct_and_below_floor_pct_are_never_both_set(ranked):
    for matches in (None, [], [_match(0.55)], [_match(0.9)], ["x"], [{"entry_id": "old"}]):
        pair = _below(matches, ranked)
        assert pair["best_pct"] is None or pair["below_floor_pct"] is None


def test_a_kept_match_the_budget_dropped_still_gives_no_below_floor_number():
    """The lookup kept a match, the token budget cut its entries (`best_pct` None): the lookup did keep a match,
    so the page does not say it kept none."""
    pair = _below([_match(0.62)], [_cand(0.62), _cand(0.4)], warnings=["learned_entries_dropped"])
    assert pair == NOTHING


@pytest.mark.parametrize(
    "ranked", [None, [], {}, "x", 7, [None], ["x", 3], [{}], [{"entry_id": "e"}]]
)
def test_no_candidate_with_a_score_gives_none(ranked):
    assert _below([], ranked) == NOTHING


@pytest.mark.parametrize(
    "score", [None, "0.4", True, False, [0.4], {"v": 0.4}, math.nan, math.inf, -0.1, 1.01, 47]
)
def test_a_score_that_is_not_a_number_in_zero_to_one_is_not_a_candidate(score):
    """The rule is `rag_view.score`'s, the one the pages and the admin page read: nothing else is a score."""
    assert _below([], [_cand(score)]) == NOTHING
    assert _below([], [_cand(score), _cand(0.44)])["below_floor_pct"] == 44


def test_an_item_that_is_not_an_object_is_skipped_in_the_ranking():
    assert _below([], ["x", None, 3, _cand(0.45)])["below_floor_pct"] == 45


def test_no_lookup_gives_none():
    """The run names no lookup: the readers hand in `None` for both the matches and the ranking."""
    assert _below(None, None) == NOTHING


@pytest.mark.parametrize("kind", FAILURE_KINDS)
def test_a_failed_lookup_gives_none_and_not_applied_says_so(kind):
    pair = _below(None, [_cand(0.4)], warnings=[rag_not_applied_warning(kind)])
    assert pair == {**NOTHING, "not_applied": kind}
    both = _below([], [_cand(0.4)], warnings=[rag_not_applied_warning(kind)])
    assert both["below_floor_pct"] is None and both["not_applied"] == kind


def test_a_candidate_at_or_over_the_floor_is_not_below_it():
    """The configuration's floor may have moved since the lookup ran: a list the lookup would now keep from is
    not described as under the floor. Compared on the raw score, not on the rounded percentage."""
    assert _below([], [_cand(0.5)]) == NOTHING
    assert _below([], [_cand(0.62)]) == NOTHING
    just_under = _below([], [_cand(0.4999)])  # 49.99 would round to 50; it is cut down to 49 (DEC-221)
    assert (just_under["below_floor_pct"], just_under["floor_pct"]) == (49, 50)


@pytest.mark.parametrize("floor", [None, True, "0.5", math.nan, math.inf, -0.1, 1.5])
def test_a_floor_that_is_not_a_number_in_zero_to_one_gives_none(floor):
    assert _below([], [_cand(0.3)], floor=floor) == NOTHING


# ── the shape ───────────────────────────────────────────────────────────────────────────────────


def test_the_two_new_arguments_default_to_nothing():
    """`tier1.triage` calls `rag_view(matches, warnings, kinds)` and reads `best_pct`: untouched by DEC-220."""
    assert rag_view.rag_view([_match(0.62)], None, KINDS)["best_pct"] == 62
    assert rag_view.rag_view([], None, KINDS) == NOTHING
    assert rag_view.rag_view(None, None, KINDS) == NOTHING


def test_floor_pct_is_present_exactly_when_below_floor_pct_is():
    cases = [
        ([], [_cand(0.2)]),
        ([], None),
        ([_match(0.7)], [_cand(0.7)]),
        (None, None),
        ([], [_cand(0.5)]),
    ]
    for matches, ranked in cases:
        pair = _below(matches, ranked)
        assert (pair["floor_pct"] is None) is (pair["below_floor_pct"] is None), (matches, ranked)


def test_the_result_is_a_new_dict_each_time():
    first, second = _below([], [_cand(0.2)]), _below([], [_cand(0.2)])
    first["below_floor_pct"] = 1
    assert second["below_floor_pct"] == 20


# ── the blind arm: the pair goes whole, the new keys with it ────────────────────────────────────


def test_the_blind_arm_loses_the_new_keys_with_the_pair():
    view = {"alert_id": "a", "rag": _below([], [_cand(0.47)])}
    assert view["rag"]["below_floor_pct"] == 47
    blind = visibility.strip(view, status="queued_tier1", suggestion_visible=False, mode="analyst")
    assert "rag" not in blind
    assert {"below_floor_pct", "floor_pct"}.isdisjoint(blind)
    decided = visibility.strip(view, status="closed_fp", suggestion_visible=False, mode="analyst")
    assert decided["rag"]["below_floor_pct"] == 47 and decided["rag"]["floor_pct"] == 50
    visible = visibility.strip(view, status="queued_tier1", suggestion_visible=True, mode="analyst")
    assert visible["rag"]["below_floor_pct"] == 47
    labeller = visibility.strip(view, status="closed_fp", suggestion_visible=True, mode="labeling")
    assert "rag" not in labeller
