"""P14 final fix wave, M2 - the percentage the pages show for a run whose budget cut dropped the entries.

①'s token budget cuts the learned section first: the entries (warning `learned_entries_dropped`), then the
history. A cut that drops only the entries leaves the run naming its lookup (`rag_lookup_id`, because the history
did reach the prompt), so the page read the lookup's matches and said "trùng 87 %" for a match that never
reached the prompt. The warning is stored with the run (`llm_runs.citation_warnings` is `built.warnings`; the
queue reads it with the matches, in the same row), so `rag_view` honours it: no entries in the prompt, no
percentage. The other cut (the history) keeps the entries, and the failure notice is unaffected.
"""

from __future__ import annotations

from app.llm import builder as B
from app.llm import rag_view
from app.rag.failures import FAILURE_KINDS

_MATCHES = [
    {"entry_id": "e1", "level": "giong", "content_sha256": "0" * 64, "score": 0.87},
    {"entry_id": "e2", "level": "giong", "content_sha256": "1" * 64, "score": 0.66},
]


def test_the_percentage_is_the_best_match_when_no_entry_was_cut():
    assert rag_view.rag_view(_MATCHES, [], FAILURE_KINDS) == {
        "best_pct": 87,
        "not_applied": None,
        "below_floor_pct": None,
        "floor_pct": None,
    }
    assert rag_view.rag_view(_MATCHES, None, FAILURE_KINDS)["best_pct"] == 87


def test_a_budget_cut_that_dropped_the_entries_leaves_no_percentage():
    for warnings in (
        [B.LEARNED_ENTRIES_DROPPED_WARNING],
        ["learned_entries_dropped", "learned_history_dropped"],
        ["some_other_warning", "learned_entries_dropped"],
    ):
        assert rag_view.rag_view(_MATCHES, warnings, FAILURE_KINDS)["best_pct"] is None


def test_the_history_cut_alone_keeps_the_entries_and_so_the_percentage():
    assert rag_view.rag_view(_MATCHES, ["learned_history_dropped"], FAILURE_KINDS)["best_pct"] == 87


def test_the_failure_notice_is_read_as_before():
    warnings = ["learned_entries_dropped", "rag_not_applied:rate_limit"]
    assert rag_view.rag_view(_MATCHES, warnings, FAILURE_KINDS) == {
        "best_pct": None,
        "not_applied": "rate_limit",
        "below_floor_pct": None,
        "floor_pct": None,
    }
    assert (
        rag_view.best_pct(_MATCHES) == 87
    )  # the function of the stored matches alone is unchanged


def test_the_warning_is_the_text_the_budget_cut_writes():
    assert B.LEARNED_ENTRIES_DROPPED_WARNING == "learned_entries_dropped"
