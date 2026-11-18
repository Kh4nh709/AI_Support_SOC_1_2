"""P14-T07 (DEC-213, spec §4.3): `llm.rag_view` - what the alert page and the case page say of the RAG beside the
AI's conclusion, as the closed pair `{"best_pct": int | None, "not_applied": str | None}` and, since DEC-220, the
two keys of a lookup that kept no match, `below_floor_pct` and `floor_pct` (the section at the end of this file).

Pure: no database. The two readers that feed it (`tier1.queue.get_alert_view` and `tier2.investigation_view`)
are tested in `test_queue_rag.py` and `test_investigation_view_rag.py`; this file pins the rules they share.
"""

from __future__ import annotations

import math

import pytest
from app.llm import rag_view
from app.llm.builder import KbLearnedLevel, rag_not_applied_warning
from app.rag.failures import FAILURE_KINDS
from app.rag.match import Match
from app.tier1 import visibility

KINDS = FAILURE_KINDS

#: The two keys DEC-220 adds to the pair; both `None` for every run but one whose lookup kept no match.
NO_FLOOR = {"below_floor_pct": None, "floor_pct": None}


def _match(score: object) -> dict:
    return {"entry_id": "e1", "level": "giong", "content_sha256": "0" * 64, "score": score}


# ── the percentage: the formula the prompt's `trung_pct` uses ───────────────────────────────────


@pytest.mark.parametrize(
    "score", [0.0, 0.004, 0.005, 0.5, 0.505, 0.65, 0.87, 0.875, 0.8749, 0.9, 0.999, 1.0]
)
def test_the_percentage_is_the_one_match_pct_gives(score):
    """`Match.pct` is `round(score * 100)`: the page, the prompt's `trung_pct` and the admin page say one number."""
    expected = Match("e1", KbLearnedLevel.GIONG, "0" * 64, score).pct
    assert rag_view.percent(score) == expected
    assert rag_view.rag_view([_match(score)], None, KINDS)["best_pct"] == expected


def test_the_percentage_is_the_rounded_score_times_a_hundred():
    assert rag_view.percent(0.87) == 87
    assert rag_view.percent(0.866) == 87
    assert rag_view.percent(0.864) == 86
    assert rag_view.percent(0.5) == 50
    assert rag_view.percent(1.0) == 100


# ── best_pct: the best of the lookup's matches ──────────────────────────────────────────────────


def test_best_pct_is_the_highest_of_the_matches_not_the_first_or_the_last():
    matches = [_match(0.61), _match(0.87), _match(0.72)]
    assert rag_view.rag_view(matches, None, KINDS) == {
        "best_pct": 87,
        "not_applied": None,
        **NO_FLOOR,
    }


def test_a_single_match_gives_its_percentage():
    assert rag_view.rag_view([_match(0.5)], None, KINDS)["best_pct"] == 50


@pytest.mark.parametrize("matches", [None, [], {}, "x", 7, [None], [{}], [{"entry_id": "e1"}]])
def test_no_match_gives_no_percentage(matches):
    assert rag_view.rag_view(matches, None, KINDS)["best_pct"] is None


@pytest.mark.parametrize(
    "score", [None, "0.9", True, False, [0.9], {"v": 0.9}, math.nan, math.inf, -0.1, 1.01, 87]
)
def test_a_score_that_is_not_a_number_in_zero_to_one_is_not_counted(score):
    """A stored score is one `rag.voyage.rerank` already checked; the reader still counts only a number in
    [0, 1], so a row of another shape never puts a wild figure on a page."""
    assert rag_view.rag_view([_match(score)], None, KINDS)["best_pct"] is None
    assert rag_view.rag_view([_match(score), _match(0.6)], None, KINDS)["best_pct"] == 60


def test_an_item_that_is_not_an_object_is_skipped():
    assert rag_view.rag_view(["x", None, 3, _match(0.7)], None, KINDS)["best_pct"] == 70


def test_an_integer_score_of_zero_or_one_is_a_score():
    assert rag_view.rag_view([_match(0)], None, KINDS)["best_pct"] == 0
    assert rag_view.rag_view([_match(1)], None, KINDS)["best_pct"] == 100


# ── score: the one reading of a stored score, public so the admin page uses it too ──────────────


def test_score_reads_the_score_of_one_stored_item():
    """`rag_view.score` is what `best_pct` and the admin page's list both read: a number in [0, 1] of an object,
    else None. It is public so no second copy of the rule exists."""
    assert rag_view.score({"entry_id": "e1", "score": 0.87}) == 0.87
    assert rag_view.score({"score": 0}) == 0.0
    assert rag_view.score({"score": 1}) == 1.0
    for item in (None, "x", 3, [], {}, {"score": None}, {"score": True}, {"score": "0.9"}):
        assert rag_view.score(item) is None, item
    for value in (math.nan, math.inf, -0.01, 1.01, 87):
        assert rag_view.score({"score": value}) is None, value


# ── not_applied: the closed kind of a rag_not_applied warning ───────────────────────────────────


@pytest.mark.parametrize("kind", FAILURE_KINDS)
def test_every_failure_kind_comes_back_from_its_warning(kind):
    warnings = [rag_not_applied_warning(kind)]
    assert rag_view.rag_view(None, warnings, KINDS) == {
        "best_pct": None,
        "not_applied": kind,
        **NO_FLOOR,
    }


def test_the_kind_is_found_among_other_warnings():
    warnings = ["learned_dropped", rag_not_applied_warning("auth"), "something_else"]
    assert rag_view.rag_view(None, warnings, KINDS)["not_applied"] == "auth"


@pytest.mark.parametrize(
    "kind",
    ["weird", "unknown", "AUTH", "auth ", " auth", "auth;drop", "rate-limit", "", "<b>x</b>"],
)
def test_a_kind_outside_the_closed_list_is_not_passed_through(kind):
    """Only a kind of `rag.failures.FAILURE_KINDS` reaches a page; anything else - a stored `unknown`, text a
    provider might have written - is `None`, never echoed."""
    assert rag_view.rag_view(None, [f"rag_not_applied:{kind}"], KINDS)["not_applied"] is None


@pytest.mark.parametrize(
    "warnings",
    [None, [], "rag_not_applied:auth", {"rag_not_applied:auth": 1}, 3, [None], [3], [{"a": 1}]],
)
def test_warnings_that_do_not_hold_the_warning_give_none(warnings):
    assert rag_view.rag_view(None, warnings, KINDS)["not_applied"] is None


def test_the_prefix_must_start_the_warning():
    assert rag_view.rag_view(None, ["x rag_not_applied:auth"], KINDS)["not_applied"] is None
    assert rag_view.rag_view(None, ["RAG_NOT_APPLIED:auth"], KINDS)["not_applied"] is None


def test_an_unknown_kind_does_not_hide_a_valid_one_after_it():
    warnings = ["rag_not_applied:weird", "rag_not_applied:quota"]
    assert rag_view.rag_view(None, warnings, KINDS)["not_applied"] == "quota"


def test_the_two_parts_are_independent():
    both = rag_view.rag_view([_match(0.92)], [rag_not_applied_warning("timeout")], KINDS)
    assert both == {"best_pct": 92, "not_applied": "timeout", **NO_FLOOR}


def test_the_shape_is_exactly_the_four_keys():
    assert set(rag_view.rag_view(None, None, KINDS)) == {
        "best_pct",
        "not_applied",
        "below_floor_pct",
        "floor_pct",
    }
    assert rag_view.rag_view(None, None, KINDS) == {
        "best_pct": None,
        "not_applied": None,
        **NO_FLOOR,
    }


def test_the_result_is_a_new_dict_each_time():
    first, second = rag_view.rag_view(None, None, KINDS), rag_view.rag_view(None, None, KINDS)
    first["best_pct"] = 1
    assert second["best_pct"] is None


# ── the blind arm: the key is ①'s verdict by another name ───────────────────────────────────────


def test_rag_is_hidden_on_the_blind_arm_and_from_the_labeller():
    assert "rag" in visibility.ANALYST_HIDE
    assert "rag" in visibility.LABELING_DENYLIST


def test_a_blind_undecided_view_loses_rag_and_a_decided_one_keeps_it():
    view = {"alert_id": "a", "rag": {"best_pct": 87, "not_applied": None, **NO_FLOOR}}
    blind = visibility.strip(view, status="queued_tier1", suggestion_visible=False, mode="analyst")
    assert "rag" not in blind
    decided = visibility.strip(view, status="closed_fp", suggestion_visible=False, mode="analyst")
    assert decided["rag"] == {"best_pct": 87, "not_applied": None, **NO_FLOOR}
    visible = visibility.strip(view, status="queued_tier1", suggestion_visible=True, mode="analyst")
    assert visible["rag"] == {"best_pct": 87, "not_applied": None, **NO_FLOOR}
    assert "rag" not in visibility.strip(
        view, status="closed_fp", suggestion_visible=True, mode="labeling"
    )


# ── the single top item of a stored list (DEC-225, the RAG rule) ───────────────────────────────


def _item(entry: object, score: object) -> dict:
    return {"entry_id": entry, "score": score}


def test_top_entry_ids_is_the_item_with_the_highest_score():
    items = [_item("a", 0.55), _item("b", 0.91), _item("c", 0.62)]
    assert rag_view.top_entry_ids(items) == ["b"]


def test_top_entry_ids_lists_every_item_tied_on_the_top_score_in_stored_order():
    items = [_item("a", 0.5), _item("b", 0.85), _item("c", 0.85), _item("d", 0.84)]
    assert rag_view.top_entry_ids(items) == ["b", "c"]


def test_top_entry_ids_lists_an_entry_once():
    assert rag_view.top_entry_ids([_item("a", 0.8), _item("a", 0.8)]) == ["a"]


def test_top_entry_ids_marks_an_item_with_no_text_id_as_none():
    """The best item cannot be named: the caller must not read the next best in its place."""
    assert rag_view.top_entry_ids([_item(None, 0.9), _item("b", 0.5)]) == [None]
    assert rag_view.top_entry_ids([_item(7, 0.9), _item("b", 0.9)]) == [None, "b"]


@pytest.mark.parametrize(
    "items",
    [
        None,
        [],
        {"not": "a list"},
        "text",
        [_item("a", None)],
        [_item("a", True)],
        [_item("a", "0.9")],
        [_item("a", float("nan"))],
        [_item("a", 1.5), _item("b", -0.2)],
        ["not an item", None, 3],
    ],
)
def test_top_entry_ids_is_empty_where_no_item_has_a_valid_score(items):
    assert rag_view.top_entry_ids(items) == []


def test_top_entry_ids_skips_items_without_a_valid_score_but_keeps_the_rest():
    items = ["x", _item("a", None), _item("b", 1.5), _item("c", 0.4)]
    assert rag_view.top_entry_ids(items) == ["c"]


def test_top_entry_ids_agrees_with_the_percentage_the_page_prints():
    """The percentage of the top item is `best_pct` (kept matches) - the same maximum, the same `score` rule."""
    matches = [_item("a", 0.625), _item("b", 0.91), _item("c", 0.62)]
    top = rag_view.top_entry_ids(matches)
    assert top == ["b"]
    assert rag_view.rag_view(matches, None, KINDS)["best_pct"] == rag_view.percent(0.91)
