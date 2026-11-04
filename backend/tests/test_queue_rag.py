"""DB tests for P14-T07 (DEC-213, spec §4.3): the alert view carries `rag` - `{"best_pct", "not_applied"}`,
what the page says beside ①'s conclusion ("trùng 87% với tri thức đã duyệt", "Không áp dụng RAG cho alert này")
- read from the very row of the newest proposer run that the suggestion is built from, and the blind arm
(DEC-101) shows neither until the alert is decided.

Fixtures are `test_queue.py`'s: a head through the real transitions, and `llm_runs` / `rag_results` rows inserted
in the shape `tier1/triage.py` and `rag/lookup.py` write. Every test runs in the `db` fixture's transaction. No
test calls Voyage.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from app.domain.transitions import acknowledge, decide
from app.llm.builder import rag_not_applied_warning
from app.rag.failures import FAILURE_KINDS
from app.tier1.queue import (
    get_alert_view,
    latest_suggestion_held,
    latest_suggestion_rag,
    list_queue,
)
from app.tier1.visibility import ANALYST_HIDE, LABELING_DENYLIST
from psycopg.types.json import Jsonb

from tests.test_queue import (
    GATE,
    RESULT,
    USER_ID,
    _duplicate,
    _queued,
    _seed_user,
    _walk_keys,
)

pytestmark = pytest.mark.db

NO_RAG = {"best_pct": None, "not_applied": None}


def _lookup(
    conn,
    alert_id: str,
    *,
    status: str = "ok",
    scores: tuple[float, ...] = (),
    failure_kind: str | None = None,
    subject_kind: str = "alert",
) -> str:
    """One `rag_results` row in the shape `rag.lookup._store` writes: matches `{entry_id, level, content_sha256,
    score}`, `match_notes` empty."""
    lookup_id = str(uuid.uuid4())
    matches = [
        {"entry_id": f"entry-{i}", "level": "giong", "content_sha256": "0" * 64, "score": score}
        for i, score in enumerate(scores)
    ]
    conn.execute(
        "INSERT INTO rag_results (lookup_id, subject_kind, subject_id, status, history, matches, "
        "match_notes, failure_kind) VALUES (%s, %s, %s, %s, NULL, %s, %s, %s)",
        (lookup_id, subject_kind, alert_id, status, Jsonb(matches), Jsonb({}), failure_kind),
    )
    return lookup_id


def _run(
    conn,
    alert_id: str,
    *,
    lookup_id: str | None = None,
    warnings: list[str] | None = None,
    result: dict | None = RESULT,
    gate_result: dict | None = GATE,
    role: str = "proposer",
    offset_s: int = 0,
    stopped_by: str | None = None,
) -> str:
    """One `llm_runs` row of ① with the two columns T06 fills: `rag_lookup_id` and `citation_warnings`."""
    run_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt, user_message, "
        "result, role, gate_result, stopped_by, rag_lookup_id, citation_warnings, created_at) "
        "VALUES (%s, 'triage', 'alert', %s, 's', 'u', %s, %s, %s, %s, %s, %s, "
        "now() + %s * interval '1 second')",
        (
            run_id,
            alert_id,
            Jsonb(result) if result is not None else None,
            role,
            Jsonb(gate_result) if gate_result is not None else None,
            stopped_by,
            lookup_id,
            Jsonb(warnings) if warnings is not None else None,
            offset_s,
        ),
    )
    return run_id


# ── best_pct: the best match of the lookup the run's prompt held ────────────────────────────────


def test_best_pct_is_the_best_match_of_the_lookup_the_latest_run_held(db):
    alert_id = _queued(db, suggestion_visible=True)
    lookup = _lookup(db, alert_id, scores=(0.61, 0.87, 0.72))
    _run(db, alert_id, lookup_id=lookup)

    assert get_alert_view(db, alert_id)["rag"] == {"best_pct": 87, "not_applied": None}


def test_the_percentage_is_the_rounded_score_times_a_hundred(db):
    alert_id = _queued(db, suggestion_visible=True)
    _run(db, alert_id, lookup_id=_lookup(db, alert_id, scores=(0.866,)))

    assert get_alert_view(db, alert_id)["rag"]["best_pct"] == 87


def test_a_run_with_no_lookup_id_has_no_percentage(db):
    alert_id = _queued(db, suggestion_visible=True)
    _lookup(db, alert_id, scores=(0.9,))  # a lookup exists for the alert, the run did not hold it
    _run(db, alert_id, lookup_id=None)

    assert get_alert_view(db, alert_id)["rag"] == NO_RAG


def test_a_lookup_without_a_match_has_no_percentage(db):
    alert_id = _queued(db, suggestion_visible=True)
    _run(db, alert_id, lookup_id=_lookup(db, alert_id, status="empty", scores=()))

    assert get_alert_view(db, alert_id)["rag"] == NO_RAG


def test_a_lookup_row_from_before_scores_has_no_percentage(db):
    """Matches written before T06 carry no `score`: nothing is invented for them."""
    alert_id = _queued(db, suggestion_visible=True)
    lookup = str(uuid.uuid4())
    db.execute(
        "INSERT INTO rag_results (lookup_id, subject_kind, subject_id, status, matches, match_notes) "
        "VALUES (%s, 'alert', %s, 'ok', %s, '{}'::jsonb)",
        (
            lookup,
            alert_id,
            Jsonb([{"entry_id": "old", "level": "giong", "content_sha256": "0" * 64}]),
        ),
    )
    _run(db, alert_id, lookup_id=lookup)

    assert get_alert_view(db, alert_id)["rag"] == NO_RAG


def test_the_lookup_the_run_names_is_the_one_read_not_the_newest_of_the_alert(db):
    """The run's prompt held lookup A; a newer lookup B (a refresh after ①) must not change the figure."""
    alert_id = _queued(db, suggestion_visible=True)
    held = _lookup(db, alert_id, scores=(0.55,))
    _lookup(db, alert_id, scores=(0.99,))
    _run(db, alert_id, lookup_id=held)

    assert get_alert_view(db, alert_id)["rag"]["best_pct"] == 55


def test_a_lookup_row_that_is_gone_gives_no_percentage(db):
    alert_id = _queued(db, suggestion_visible=True)
    _run(db, alert_id, lookup_id=str(uuid.uuid4()))  # a plain uuid, no foreign key (migration 020)

    assert get_alert_view(db, alert_id)["rag"] == NO_RAG


# ── the latest run only ─────────────────────────────────────────────────────────────────────────


def test_only_the_latest_proposer_run_counts(db):
    """An older run's lookup does not stand in for a newer run that held none."""
    alert_id = _queued(db, suggestion_visible=True)
    _run(db, alert_id, lookup_id=_lookup(db, alert_id, scores=(0.9,)), offset_s=0)
    _run(db, alert_id, lookup_id=None, offset_s=5)

    assert get_alert_view(db, alert_id)["rag"] == NO_RAG


def test_a_newer_run_replaces_an_older_notice(db):
    alert_id = _queued(db, suggestion_visible=True)
    _run(db, alert_id, warnings=[rag_not_applied_warning("timeout")], offset_s=0)
    _run(db, alert_id, lookup_id=_lookup(db, alert_id, scores=(0.7,)), offset_s=5)

    assert get_alert_view(db, alert_id)["rag"] == {"best_pct": 70, "not_applied": None}


def test_the_verifier_row_is_never_read(db):
    alert_id = _queued(db, suggestion_visible=True)
    _run(db, alert_id, lookup_id=_lookup(db, alert_id, scores=(0.6,)), offset_s=0)
    _run(
        db,
        alert_id,
        role="verifier",
        warnings=[rag_not_applied_warning("auth")],
        lookup_id=_lookup(db, alert_id, scores=(0.99,)),
        offset_s=5,
    )

    assert get_alert_view(db, alert_id)["rag"] == {"best_pct": 60, "not_applied": None}


# ── not_applied: the kind from the run's citation_warnings ──────────────────────────────────────


def test_not_applied_is_the_kind_of_rag_not_applied_auth(db):
    alert_id = _queued(db, suggestion_visible=True)
    _run(db, alert_id, warnings=["rag_not_applied:auth"])

    assert get_alert_view(db, alert_id)["rag"] == {"best_pct": None, "not_applied": "auth"}


@pytest.mark.parametrize("kind", FAILURE_KINDS)
def test_every_failure_kind_reaches_the_view(db, kind):
    alert_id = _queued(db, suggestion_visible=True)
    _run(db, alert_id, warnings=[rag_not_applied_warning(kind)])

    assert get_alert_view(db, alert_id)["rag"]["not_applied"] == kind


@pytest.mark.parametrize("kind", ["unknown", "weird", "AUTH", "auth;x", ""])
def test_a_kind_outside_the_closed_list_is_none(db, kind):
    alert_id = _queued(db, suggestion_visible=True)
    _run(db, alert_id, warnings=[f"rag_not_applied:{kind}"])

    assert get_alert_view(db, alert_id)["rag"] == NO_RAG


def test_other_warnings_are_not_a_notice(db):
    alert_id = _queued(db, suggestion_visible=True)
    _run(db, alert_id, warnings=["learned_dropped", "something"])

    assert get_alert_view(db, alert_id)["rag"] == NO_RAG


def test_a_run_with_no_warnings_column_is_not_a_notice(db):
    alert_id = _queued(db, suggestion_visible=True)
    _run(db, alert_id, warnings=None)

    assert get_alert_view(db, alert_id)["rag"] == NO_RAG


def test_a_stopped_run_still_carries_the_kind_but_no_suggestion(db):
    """① gave up (`result` NULL) with the RAG already off: the view says so; the page words it only beside a
    conclusion, and there is none."""
    alert_id = _queued(db, suggestion_visible=True)
    _run(
        db,
        alert_id,
        result=None,
        gate_result=None,
        stopped_by="unavailable",
        warnings=[rag_not_applied_warning("quota")],
    )

    view = get_alert_view(db, alert_id)
    assert view["suggestion"] is None
    assert view["rag"] == {"best_pct": None, "not_applied": "quota"}


# ── no run at all, a duplicate, the reader's shape ──────────────────────────────────────────────


def test_an_alert_without_a_run_has_the_empty_pair(db):
    alert_id = _queued(db, suggestion_visible=True)

    assert get_alert_view(db, alert_id)["rag"] == NO_RAG


def test_a_duplicates_view_carries_its_heads_rag(db):
    head = _queued(db, suggestion_visible=True)
    _run(db, head, lookup_id=_lookup(db, head, scores=(0.8,)))
    duplicate = _duplicate(db, head)

    view = get_alert_view(db, duplicate)
    assert view["alert_id"] == head
    assert view["rag"]["best_pct"] == 80


def test_the_view_reads_the_newest_run_once_for_the_suggestion_the_held_reasons_and_rag(db):
    """The percentage and the notice come out of the statement that builds the suggestion: still two
    `llm_runs` statements in the view (that one and the stop reason's), and one read of `rag_results` inside it,
    never a statement of its own."""
    alert_id = _queued(db, suggestion_visible=True)
    _run(db, alert_id, lookup_id=_lookup(db, alert_id, scores=(0.9,)))
    statements: list[str] = []
    original = db.execute

    def spy(query, *args, **kwargs):
        statements.append(str(query))
        return original(query, *args, **kwargs)

    db.execute = spy  # type: ignore[method-assign]
    try:
        view = get_alert_view(db, alert_id)
    finally:
        db.execute = original  # type: ignore[method-assign]

    assert view["rag"]["best_pct"] == 90
    assert len([s for s in statements if "FROM llm_runs" in s]) == 2
    assert not [s for s in statements if "FROM rag_results" in s and "FROM llm_runs" not in s]


def test_a_run_inserted_between_the_reads_cannot_pair_one_runs_suggestion_with_anothers_rag(db):
    alert_id = _queued(db, suggestion_visible=True)
    _run(db, alert_id, lookup_id=_lookup(db, alert_id, scores=(0.5,)), offset_s=0)
    original = db.execute
    fired: list[bool] = []

    def spy(query, *args, **kwargs):
        answer = original(query, *args, **kwargs)
        if not fired and "FROM llm_runs" in str(query):
            fired.append(True)
            _run(db, alert_id, warnings=[rag_not_applied_warning("auth")], offset_s=9)
        return answer

    db.execute = spy  # type: ignore[method-assign]
    try:
        view = get_alert_view(db, alert_id)
    finally:
        db.execute = original  # type: ignore[method-assign]

    assert fired
    assert view["rag"] == {"best_pct": 50, "not_applied": None}


def test_latest_suggestion_held_keeps_its_three_values(db):
    """The T03 reader is unchanged; `latest_suggestion_rag` is the same read with the fourth value."""
    alert_id = _queued(db, suggestion_visible=True)
    _run(db, alert_id, lookup_id=_lookup(db, alert_id, scores=(0.66,)))

    triple = latest_suggestion_held(db, alert_id)
    quad = latest_suggestion_rag(db, alert_id)

    assert len(triple) == 3 and len(quad) == 4
    assert quad[:3] == triple
    assert quad[3] == {"best_pct": 66, "not_applied": None}


# ── the blind arm (DEC-101) ─────────────────────────────────────────────────────────────────────


def test_rag_is_an_analyst_hide_key_and_a_labelling_denylist_key():
    assert "rag" in ANALYST_HIDE
    assert "rag" in LABELING_DENYLIST


def test_a_blind_undecided_view_has_no_rag_key_and_none_of_its_values(db):
    alert_id = _queued(db, suggestion_visible=False)
    _run(
        db,
        alert_id,
        lookup_id=_lookup(db, alert_id, scores=(0.87,)),
        warnings=["rag_not_applied:auth"],
    )

    view = get_alert_view(db, alert_id)

    assert "rag" not in view
    assert "suggestion" not in view
    text = json.dumps(view, default=str)
    assert "87" not in text.replace("-", "")  # no figure of the lookup survives anywhere
    assert "rag_not_applied" not in text and '"auth"' not in text


def test_the_visible_arm_has_rag_while_undecided(db):
    alert_id = _queued(db, suggestion_visible=True)
    _run(db, alert_id, lookup_id=_lookup(db, alert_id, scores=(0.87,)))

    assert get_alert_view(db, alert_id)["rag"]["best_pct"] == 87


def test_a_decision_brings_rag_back_on_the_blind_arm(db):
    _seed_user(db)
    alert_id = _queued(db, suggestion_visible=False, risk_score=30)
    _run(db, alert_id, lookup_id=_lookup(db, alert_id, scores=(0.87,)))
    acknowledge(db, alert_id, USER_ID)
    assert "rag" not in get_alert_view(db, alert_id)  # still undecided, still blind

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
    assert view["rag"] == {"best_pct": 87, "not_applied": None}


@pytest.mark.parametrize("suggestion_visible", [True, False], ids=["visible", "blind"])
def test_the_labelling_page_never_has_rag(db, suggestion_visible):
    alert_id = _queued(db, suggestion_visible=suggestion_visible)
    _run(
        db,
        alert_id,
        lookup_id=_lookup(db, alert_id, scores=(0.87,)),
        warnings=["rag_not_applied:auth"],
    )

    labelling = get_alert_view(db, alert_id, mode="labeling")

    keys: set[Any] = set(_walk_keys(labelling))
    assert "rag" not in keys and "best_pct" not in keys and "not_applied" not in keys
    assert not keys & LABELING_DENYLIST
    analyst = get_alert_view(
        db, alert_id
    )  # the control: the analyst view has it on the visible arm
    assert ("rag" in analyst) is suggestion_visible


def test_the_queue_rows_do_not_carry_rag(db):
    """The queue shows ①'s verdict only; the percentage and the notice are the alert page's."""
    alert_id = _queued(db, suggestion_visible=True)
    _run(db, alert_id, lookup_id=_lookup(db, alert_id, scores=(0.87,)))

    rows = list_queue(db).rows
    assert [row for row in rows if row["alert_id"] == alert_id]
    assert all("rag" not in row for row in rows)
