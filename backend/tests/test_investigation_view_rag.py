"""DB tests for P14-T07 (DEC-213, spec §4.3): the case page's run carries `rag` - `{"best_pct", "not_applied"}` -
the percentage ("trùng 87% với tri thức đã duyệt") and the notice ("Không áp dụng RAG cho case này"), read from the
run the page presents (`present_run`'s run): its `rag_lookup_id` and its `citation_warnings`, in the same statement
that reads the run.

Rows are inserted directly in the shape `tier2/investigate.py` and `rag/lookup.py` write; no test calls a model or
Voyage. The helpers are this file's own copies (project convention).
"""

from __future__ import annotations

import json
import uuid
from types import SimpleNamespace

import pytest
from app.llm.builder import rag_not_applied_warning
from app.rag.failures import FAILURE_KINDS
from app.tier2 import investigation_view as view
from psycopg.types.json import Jsonb

pytestmark = pytest.mark.db

#: DEC-220: the two keys of a lookup that kept no match; `None` for every run these tests build but the ones
#: that say otherwise (the section at the end of this file).
NO_FLOOR = {"below_floor_pct": None, "floor_pct": None}
NO_RAG = {"best_pct": None, "not_applied": None, **NO_FLOOR}
CFG = SimpleNamespace(
    JOB_LOCK_TIMEOUT_S=300
)  # read only when a job is live, and these tests insert none

RESULT = {
    "summary": "S",
    "attack_narrative": "N",
    "suggested_conclusion": "confirmed_incident",
    "confidence": "high",
    "gia_thuyet": [],
    "evidence": [],
    "next_steps": [],
    "playbook_used": None,
}


def _case(conn) -> str:
    user_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash) "
        "VALUES (%s, %s, 'Analyst', 'tier2', 'x')",
        (user_id, f"user-{user_id[:8]}"),
    )
    case_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO cases (case_id, title, status, severity, created_by) "
        "VALUES (%s, 'case', 'investigating', 'high', %s)",
        (case_id, user_id),
    )
    return case_id


def _lookup(
    conn,
    case_id: str,
    scores: tuple[float, ...],
    *,
    status: str = "ok",
    ranked: tuple[float, ...] | None = None,
) -> str:
    """`ranked` (DEC-220) is the rerank's list, every candidate it scored; NULL when not given."""
    lookup_id = str(uuid.uuid4())
    matches = [
        {"entry_id": f"entry-{i}", "level": "giong", "content_sha256": "0" * 64, "score": s}
        for i, s in enumerate(scores)
    ]
    ranking = (
        None
        if ranked is None
        else Jsonb([{"entry_id": f"cand-{i}", "score": value} for i, value in enumerate(ranked)])
    )
    conn.execute(
        "INSERT INTO rag_results (lookup_id, subject_kind, subject_id, status, matches, match_notes, ranked) "
        "VALUES (%s, 'case', %s, %s, %s, '{}'::jsonb, %s)",
        (lookup_id, case_id, status, Jsonb(matches), ranking),
    )
    return lookup_id


def _run(
    conn,
    case_id: str,
    *,
    lookup_id: str | None = None,
    warnings: list[str] | None = None,
    result: dict | None = RESULT,
    stopped_by: str | None = None,
    offset_s: int = 0,
) -> str:
    run_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, role, system_prompt, "
        "user_message, result, evidence_check, stopped_by, rag_lookup_id, citation_warnings, created_at) "
        "VALUES (%s, 'investigate', 'case', %s, 'investigator', 's', 'u', %s, %s, %s, %s, %s, "
        "now() + %s * interval '1 second')",
        (
            run_id,
            case_id,
            Jsonb(result) if result is not None else None,
            Jsonb({"verified": [], "rejected": []}) if result is not None else None,
            stopped_by,
            lookup_id,
            Jsonb(warnings) if warnings is not None else None,
            offset_s,
        ),
    )
    return run_id


def _presented(conn, case_id: str, cfg=CFG) -> dict:
    body = view.build_investigation(conn, cfg, case_id, None)
    assert body["state"] == "done"
    return body["run"]


# ── best_pct ────────────────────────────────────────────────────────────────────────────────────


def test_best_pct_is_the_best_match_of_the_lookup_the_run_held(db):
    case_id = _case(db)
    _run(db, case_id, lookup_id=_lookup(db, case_id, (0.61, 0.87, 0.72)))

    assert _presented(db, case_id)["rag"] == {"best_pct": 87, "not_applied": None, **NO_FLOOR}


def test_a_run_with_no_lookup_id_has_no_percentage_even_when_the_case_has_a_lookup(db):
    case_id = _case(db)
    _lookup(db, case_id, (0.9,))
    _run(db, case_id, lookup_id=None)

    assert _presented(db, case_id)["rag"] == NO_RAG


def test_the_lookup_the_run_names_is_the_one_read_not_the_newest_of_the_case(db):
    case_id = _case(db)
    held = _lookup(db, case_id, (0.55,))
    _lookup(db, case_id, (0.99,))
    _run(db, case_id, lookup_id=held)

    assert _presented(db, case_id)["rag"]["best_pct"] == 55


def test_a_lookup_without_a_match_has_no_percentage(db):
    case_id = _case(db)
    _run(db, case_id, lookup_id=_lookup(db, case_id, (), status="empty"))

    assert _presented(db, case_id)["rag"] == NO_RAG


# ── not_applied ─────────────────────────────────────────────────────────────────────────────────


def test_not_applied_is_the_kind_of_rag_not_applied_auth(db):
    case_id = _case(db)
    _run(db, case_id, warnings=["rag_not_applied:auth"])

    assert _presented(db, case_id)["rag"] == {"best_pct": None, "not_applied": "auth", **NO_FLOOR}


@pytest.mark.parametrize("kind", FAILURE_KINDS)
def test_every_failure_kind_reaches_the_view(db, kind):
    case_id = _case(db)
    _run(db, case_id, warnings=[rag_not_applied_warning(kind)])

    assert _presented(db, case_id)["rag"]["not_applied"] == kind


@pytest.mark.parametrize("kind", ["unknown", "weird", "AUTH", ""])
def test_a_kind_outside_the_closed_list_is_none(db, kind):
    case_id = _case(db)
    _run(db, case_id, warnings=[f"rag_not_applied:{kind}"])

    assert _presented(db, case_id)["rag"] == NO_RAG


def test_other_warnings_are_not_a_notice(db):
    case_id = _case(db)
    _run(db, case_id, warnings=["learned_dropped"])

    assert _presented(db, case_id)["rag"] == NO_RAG


# ── old and stopped runs ────────────────────────────────────────────────────────────────────────


def test_a_run_from_before_the_lookup_columns_has_the_empty_pair(db):
    """No `rag_lookup_id`, no `citation_warnings` (NULL): the pair is there, empty."""
    case_id = _case(db)
    _run(db, case_id)

    run = _presented(db, case_id)
    assert run["rag"] == NO_RAG
    assert set(run["rag"]) == {"best_pct", "not_applied", "below_floor_pct", "floor_pct"}


def test_a_stopped_run_carries_the_empty_pair(db):
    case_id = _case(db)
    _run(db, case_id, result=None, stopped_by="cap")

    run = _presented(db, case_id)
    assert run["result"] is None
    assert run["rag"] == NO_RAG


def test_a_stopped_run_that_carries_the_warning_gives_the_kind(db):
    """② stops (the cap, the provider) with the RAG already off: the warning is on every row, stopped ones
    included (T06), and the view gives the kind for it."""
    case_id = _case(db)
    _run(
        db,
        case_id,
        result=None,
        stopped_by="permanent",
        warnings=[rag_not_applied_warning("rate_limit")],
    )

    run = _presented(db, case_id)
    assert run["result"] is None
    assert run["rag"] == {"best_pct": None, "not_applied": "rate_limit", **NO_FLOOR}


def test_the_presented_run_is_the_latest_one_and_only_its_rag_counts(db):
    case_id = _case(db)
    _run(db, case_id, warnings=[rag_not_applied_warning("auth")], offset_s=0)
    _run(db, case_id, lookup_id=_lookup(db, case_id, (0.8,)), offset_s=5)

    assert _presented(db, case_id)["rag"] == {"best_pct": 80, "not_applied": None, **NO_FLOOR}


def test_the_failed_state_presents_the_last_runs_rag(db):
    """A failed job shows the last final run (`latest_final_row`); it carries its `rag` like a done one."""
    case_id = _case(db)
    _run(db, case_id, warnings=[rag_not_applied_warning("timeout")])
    db.execute(
        "INSERT INTO jobs (job_type, subject_id, status, attempts) VALUES ('investigate', %s, 'failed', 3)",
        (case_id,),
    )

    body = view.build_investigation(db, CFG, case_id, None)

    assert body["state"] == "failed"
    assert body["run"]["rag"] == {"best_pct": None, "not_applied": "timeout", **NO_FLOOR}


def test_the_view_is_json_plain(db):
    case_id = _case(db)
    _run(db, case_id, lookup_id=_lookup(db, case_id, (0.87,)), warnings=["rag_not_applied:auth"])

    body = view.build_investigation(db, CFG, case_id, None)

    assert json.loads(json.dumps(body["run"]["rag"])) == {
        "best_pct": 87,
        "not_applied": "auth",
        **NO_FLOOR,
    }


def test_the_run_is_read_in_one_statement_with_its_lookup(db):
    case_id = _case(db)
    _run(db, case_id, lookup_id=_lookup(db, case_id, (0.9,)))
    statements: list[str] = []
    original = db.execute

    def spy(query, *args, **kwargs):
        statements.append(str(query))
        return original(query, *args, **kwargs)

    db.execute = spy  # type: ignore[method-assign]
    try:
        run = _presented(db, case_id)
    finally:
        db.execute = original  # type: ignore[method-assign]

    assert run["rag"]["best_pct"] == 90
    assert not [s for s in statements if "FROM rag_results" in s and "FROM llm_runs" not in s]


# ── DEC-220: the best candidate's percentage when the lookup kept no match ──────────────────────
#
# `rag_results.ranked` rides the same statement as the `matches` (a second scalar subquery on the run's
# `rag_lookup_id`); the floor is the `RAG_MIN_SCORE` of the `cfg` the route hands `build_investigation`.

CFG_FLOOR = SimpleNamespace(JOB_LOCK_TIMEOUT_S=300, RAG_MIN_SCORE=0.5)
BELOW_47 = {"best_pct": None, "not_applied": None, "below_floor_pct": 47, "floor_pct": 50}


def test_a_lookup_that_kept_no_match_gives_its_best_candidates_percentage_and_the_floor(db):
    case_id = _case(db)
    _run(db, case_id, lookup_id=_lookup(db, case_id, (), ranked=(0.31, 0.47, 0.12)))

    assert _presented(db, case_id, CFG_FLOOR)["rag"] == BELOW_47


def test_the_floor_is_the_one_of_the_cfg_the_route_hands_in(db):
    case_id = _case(db)
    _run(db, case_id, lookup_id=_lookup(db, case_id, (), ranked=(0.47,)))

    cfg = SimpleNamespace(JOB_LOCK_TIMEOUT_S=300, RAG_MIN_SCORE=0.65)
    rag = _presented(db, case_id, cfg)["rag"]

    assert (rag["below_floor_pct"], rag["floor_pct"]) == (47, 65)


def test_a_floor_the_best_candidate_reaches_is_not_below_it(db):
    case_id = _case(db)
    _run(db, case_id, lookup_id=_lookup(db, case_id, (), ranked=(0.47,)))

    cfg = SimpleNamespace(JOB_LOCK_TIMEOUT_S=300, RAG_MIN_SCORE=0.4)
    assert _presented(db, case_id, cfg)["rag"] == NO_RAG


def test_a_kept_match_is_unchanged_and_carries_no_below_floor_number(db):
    case_id = _case(db)
    lookup = _lookup(db, case_id, (0.62,), ranked=(0.62, 0.47, 0.31))
    _run(db, case_id, lookup_id=lookup)

    assert _presented(db, case_id, CFG_FLOOR)["rag"] == {
        "best_pct": 62,
        "not_applied": None,
        **NO_FLOOR,
    }


def test_a_kept_match_the_budget_dropped_carries_no_below_floor_number(db):
    case_id = _case(db)
    lookup = _lookup(db, case_id, (0.62,), ranked=(0.62, 0.47))
    _run(db, case_id, lookup_id=lookup, warnings=["learned_entries_dropped"])

    assert _presented(db, case_id, CFG_FLOOR)["rag"] == NO_RAG


@pytest.mark.parametrize("ranked", [None, ()], ids=["null", "empty"])
def test_a_lookup_with_no_ranking_gives_no_below_floor_number(db, ranked):
    case_id = _case(db)
    _run(db, case_id, lookup_id=_lookup(db, case_id, (), ranked=ranked))

    assert _presented(db, case_id, CFG_FLOOR)["rag"] == NO_RAG


def test_a_run_that_names_no_lookup_gives_no_below_floor_number(db):
    case_id = _case(db)
    _lookup(db, case_id, (), ranked=(0.47,))  # the case has one; the run did not hold it
    _run(db, case_id, lookup_id=None)

    assert _presented(db, case_id, CFG_FLOOR)["rag"] == NO_RAG


def test_a_failed_lookup_gives_no_below_floor_number_and_not_applied_says_so(db):
    case_id = _case(db)
    lookup = _lookup(db, case_id, (), status="failed", ranked=(0.47,))
    _run(db, case_id, lookup_id=lookup, warnings=["rag_not_applied:auth"])

    assert _presented(db, case_id, CFG_FLOOR)["rag"] == {**NO_RAG, "not_applied": "auth"}


def test_the_lookup_the_run_names_is_the_one_whose_ranking_is_read(db):
    case_id = _case(db)
    held = _lookup(db, case_id, (), ranked=(0.47,))
    _lookup(db, case_id, (), ranked=(0.31,))
    _run(db, case_id, lookup_id=held)

    assert _presented(db, case_id, CFG_FLOOR)["rag"] == BELOW_47


def test_a_stopped_run_still_carries_the_number(db):
    case_id = _case(db)
    lookup = _lookup(db, case_id, (), ranked=(0.47,))
    _run(db, case_id, result=None, stopped_by="cap", lookup_id=lookup)

    run = _presented(db, case_id, CFG_FLOOR)
    assert run["result"] is None
    assert run["rag"] == BELOW_47


def test_the_ranking_rides_the_statement_that_reads_the_run(db):
    case_id = _case(db)
    _run(db, case_id, lookup_id=_lookup(db, case_id, (), ranked=(0.47,)))
    statements: list[str] = []
    original = db.execute

    def spy(query, *args, **kwargs):
        statements.append(str(query))
        return original(query, *args, **kwargs)

    db.execute = spy  # type: ignore[method-assign]
    try:
        run = _presented(db, case_id, CFG_FLOOR)
    finally:
        db.execute = original  # type: ignore[method-assign]

    assert run["rag"] == BELOW_47
    assert not [s for s in statements if "FROM rag_results" in s and "FROM llm_runs" not in s]


def test_a_cfg_with_no_floor_gives_no_below_floor_number(db):
    """A `cfg` that carries no `RAG_MIN_SCORE` (a caller with a partial one): the number is not guessed at."""
    case_id = _case(db)
    _run(db, case_id, lookup_id=_lookup(db, case_id, (), ranked=(0.47,)))

    assert _presented(db, case_id)["rag"] == NO_RAG


def test_present_run_with_no_floor_gives_no_below_floor_number(db):
    case_id = _case(db)
    _run(db, case_id, lookup_id=_lookup(db, case_id, (), ranked=(0.47,)))

    run = view.present_run(view.latest_final_row(db, case_id))
    assert run["rag"] == NO_RAG
    run = view.present_run(view.latest_final_row(db, case_id), rag_min_score=0.5)
    assert run["rag"] == BELOW_47


def test_the_pair_survives_json(db):
    case_id = _case(db)
    _run(db, case_id, lookup_id=_lookup(db, case_id, (), ranked=(0.47,)))

    body = view.build_investigation(db, CFG_FLOOR, case_id, None)

    assert json.loads(json.dumps(body["run"]["rag"])) == BELOW_47
