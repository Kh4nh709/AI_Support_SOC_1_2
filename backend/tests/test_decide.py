"""DB tests for app.tier1.decide — `acknowledge`, `decide`, `escalate`, `reopen` (P4-T03).

Fixtures go through `domain.transitions.open_alert` → `start_enrichment` →
`finish_enrichment` from the canonical `alert_40112.json` (the P4-T02 pattern,
`test_queue.py`'s `_alert`/`_queued`/`_duplicate` copied), plus `_active` and
`_auto_closed` for the two starting states this card needs that P4-T02 never
did. `llm_runs` is empty on every host until P3-T10 lands, so the payload test
brings its own proposer row in P3-T10's shape (the P4-T02 fixture INSERT,
copied verbatim — planning decision 5). Every test runs inside the `db`
fixture's transaction and is rolled back (conftest.py).
`TEST_DATABASE_URL=postgresql:///soc_p4t03_test`.
"""

from __future__ import annotations

import dataclasses
import hashlib
import itertools
import json
import uuid
from pathlib import Path
from typing import Any

import psycopg
import pytest
from app.domain import transitions
from app.domain.alert import Alert, AlertContext
from app.domain.transitions import AutocloseMatch, finish_enrichment, open_alert, start_enrichment
from app.infra import config
from app.ingest.wazuh_parser import parse_wazuh_alert
from app.tier1.decide import (
    Actor,
    DecisionConflict,
    NotFound,
    acknowledge,
    decide,
    escalate,
    reopen,
)
from psycopg.types.json import Jsonb

pytestmark = pytest.mark.db

FIXTURES = Path(__file__).resolve().parent / "fixtures"
_CANONICAL: Alert = parse_wazuh_alert(
    json.loads((FIXTURES / "alert_40112.json").read_text(encoding="utf-8"))
).alert
assert _CANONICAL is not None

USER_ID = "00000000-0000-0000-0000-000000040300"
USER_NAME = "P4-T03 analyst"
OTHER_USER_ID = "00000000-0000-0000-0000-000000040301"
OTHER_USER_NAME = "P4-T03 other analyst"

_EMPTY_CONTEXT = AlertContext(
    asset_present=False,
    asset_criticality="unknown",
    asset_owner=None,
    asset_role=None,
    identity_privileged=None,
    ioc_reputation="skipped",
    lookup_status={},
)

RESULT: dict[str, Any] = {
    "suggested_action": "false_positive",
    "confidence": "high",
    "structured_basis": {"severity": "critical", "occurrence_count": 1},
    "reasons": [{"claim": "c", "quote": "q", "source": "wazuh_raw_log"}],
    "playbook_used": None,
}
GATE: dict[str, Any] = {
    "proposed_verdict": "false_positive",
    "final_verdict": "false_positive",
    "forced": False,
    "forced_by": [],
    "warnings": [],
    "facts": {"correlated_clusters": 1},
    "verifier_verdict": "false_positive",
}

_counter = itertools.count()


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _alert(**overrides: Any) -> Alert:
    n = next(_counter)
    alert_id = overrides.pop("alert_id", f"p4t03-{n}")
    fields: dict[str, Any] = {"alert_id": alert_id, "event_bucket_hash": _hash(alert_id)}
    fields.update(overrides)
    return dataclasses.replace(_CANONICAL, **fields)


def _seed_user(conn: psycopg.Connection, user_id: str, name: str) -> None:
    conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash) "
        "VALUES (%s, %s, %s, 'tier1', 'x') ON CONFLICT (user_id) DO NOTHING",
        (user_id, f"u{user_id[-6:]}", name),
    )


def _actor(user_id: str = USER_ID, role: str = "tier1") -> Actor:
    return Actor(user_id=user_id, role=role)


def _queued(
    conn: psycopg.Connection,
    *,
    suggestion_visible: bool = True,
    source: str = "wazuh",
    **overrides: Any,
) -> str:
    alert = _alert(**overrides)
    open_alert(conn, alert, kind="received", source=source, suggestion_visible=suggestion_visible)
    start_enrichment(conn, alert.alert_id)
    finish_enrichment(
        conn, alert.alert_id, context=_EMPTY_CONTEXT, risk_score=10, risk_components={}
    )
    return alert.alert_id


def _duplicate(conn: psycopg.Connection, head_id: str, **overrides: Any) -> str:
    alert = _alert(**overrides)
    open_alert(
        conn, alert, kind="duplicate", source="wazuh", suggestion_visible=True, duplicate_of=head_id
    )
    return alert.alert_id


def _active(conn: psycopg.Connection, *, actor_id: str = USER_ID, **overrides: Any) -> str:
    alert_id = _queued(conn, **overrides)
    transitions.acknowledge(conn, alert_id, actor_id)
    return alert_id


def _autoclose_rule(conn: psycopg.Connection, created_by: str) -> str:
    """`autoclose_rules` FKs `created_by` to `users` — `rule_id` must be a real row."""
    rule_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO autoclose_rules (autoclose_rule_id, name, match, reason, created_by) "
        "VALUES (%s, %s, %s, %s, %s)",
        (rule_id, "p4t03-idle", Jsonb({}), "idle_gap", created_by),
    )
    return rule_id


def _auto_closed(conn: psycopg.Connection, *, created_by: str = USER_ID, **overrides: Any) -> str:
    alert = _alert(**overrides)
    rule_id = _autoclose_rule(conn, created_by)
    open_alert(
        conn,
        alert,
        kind="auto_closed",
        source="wazuh",
        suggestion_visible=False,
        rule=AutocloseMatch(rule_id=rule_id, name="idle", reason="idle_gap"),
    )
    return alert.alert_id


def _insert_run(
    conn: psycopg.Connection,
    alert_id: str,
    *,
    result: dict[str, Any] = RESULT,
    gate_result: dict[str, Any] = GATE,
) -> str:
    """One `llm_runs` proposer row in P3-T10's shape (P4-T02's fixture INSERT)."""
    row = conn.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt, "
        "user_message, result, role, gate_result) "
        "VALUES (gen_random_uuid(), 'triage', 'alert', %s, 's', 'u', %s::jsonb, 'proposer', "
        "%s::jsonb) RETURNING run_id",
        (alert_id, json.dumps(result), json.dumps(gate_result)),
    ).fetchone()
    return str(row[0])


def _make_case(conn: psycopg.Connection, created_by: str, *, title: str = "other") -> str:
    case_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO cases (case_id, title, status, severity, created_by) "
        "VALUES (%s, %s, 'investigating', 'high', %s)",
        (case_id, title, created_by),
    )
    return case_id


def _status(conn: psycopg.Connection, alert_id: str) -> str:
    return conn.execute("SELECT status FROM alerts WHERE alert_id = %s", (alert_id,)).fetchone()[0]


def _audit_rows(conn: psycopg.Connection, subject_id: str) -> list[tuple]:
    return conn.execute(
        "SELECT event_type, payload FROM audit_events WHERE subject_id = %s ORDER BY created_at",
        (subject_id,),
    ).fetchall()


# ---------------------------------------------------------------------------
# acknowledge
# ---------------------------------------------------------------------------


def test_acknowledge_first_wins_second_is_idempotent(db) -> None:
    _seed_user(db, USER_ID, USER_NAME)
    _seed_user(db, OTHER_USER_ID, OTHER_USER_NAME)
    alert_id = _queued(db)

    first = acknowledge(db, alert_id, _actor(USER_ID))
    assert first["first"] is True
    assert first["status"] == "tier1_active"
    assert str(first["acknowledged_by"]) == USER_ID
    assert first["acknowledged_by_name"] == USER_NAME

    second = acknowledge(db, alert_id, _actor(OTHER_USER_ID))
    assert second["first"] is False
    assert str(second["acknowledged_by"]) == USER_ID  # the first acknowledger, never overwritten
    assert second["acknowledged_by_name"] == USER_NAME
    assert second["acknowledged_at"] == first["acknowledged_at"]


def test_acknowledge_from_closed_is_conflict(db) -> None:
    _seed_user(db, USER_ID, USER_NAME)
    alert_id = _active(db)
    transitions.decide(
        db,
        alert_id,
        USER_ID,
        decision="closed_fp",
        reason="test",
        seen_occurrence_count=1,
        llm_suggestion=None,
        llm_confidence=None,
    )
    with pytest.raises(DecisionConflict) as excinfo:
        acknowledge(db, alert_id, _actor(USER_ID))
    assert excinfo.value.body["kind"] == "not_active"
    assert excinfo.value.body["status"] == "closed_fp"


def test_acknowledge_unknown_alert_is_not_found(db) -> None:
    with pytest.raises(NotFound):
        acknowledge(db, "does-not-exist", _actor(USER_ID))


# ---------------------------------------------------------------------------
# decide
# ---------------------------------------------------------------------------


def test_decide_within_tolerance_fans_out_and_sets_triaged_count(db) -> None:
    _seed_user(db, USER_ID, USER_NAME)
    head = _active(db)
    dup1 = _duplicate(db, head)
    dup2 = _duplicate(db, head)
    dup3 = _duplicate(db, head)
    db.execute("UPDATE alerts SET occurrence_count = 4 WHERE alert_id = %s", (head,))

    result = decide(
        db, head, _actor(USER_ID), decision="benign", reason="looks fine", seen_occurrence_count=4
    )
    assert result == {
        "alert_id": head,
        "status": "closed_benign",
        "closed_count": 4,
        "case_id": None,
    }

    for alert_id in (head, dup1, dup2, dup3):
        status, closed_at, sealed_at = db.execute(
            "SELECT status, closed_at, sealed_at FROM alerts WHERE alert_id = %s", (alert_id,)
        ).fetchone()
        assert status == "closed_benign"
        assert closed_at is not None
        assert sealed_at is not None
    triaged_count = db.execute(
        "SELECT triaged_count FROM alerts WHERE alert_id = %s", (head,)
    ).fetchone()[0]
    assert triaged_count == 4


def test_decide_over_tolerance_is_cluster_grew_with_numbers_and_writes_nothing(db) -> None:
    _seed_user(db, USER_ID, USER_NAME)
    head = _active(db)
    db.execute("UPDATE alerts SET occurrence_count = 25 WHERE alert_id = %s", (head,))

    with pytest.raises(DecisionConflict) as excinfo:
        decide(db, head, _actor(USER_ID), decision="benign", reason="x", seen_occurrence_count=4)
    body = excinfo.value.body
    assert body["kind"] == "cluster_grew"
    assert body["occurrence_count"] == 25
    assert body["seen_occurrence_count"] == 4
    assert body["delta"] == 21
    assert body["tolerance"] == config.load().REVIEW_DELTA_TOLERANCE == 20
    assert _status(db, head) == "tier1_active"  # nothing written


def test_decide_already_decided_names_decider(db) -> None:
    _seed_user(db, USER_ID, USER_NAME)
    head = _active(db)
    transitions.decide(
        db,
        head,
        USER_ID,
        decision="closed_benign",
        reason="already closed",
        seen_occurrence_count=1,
        llm_suggestion=None,
        llm_confidence=None,
    )
    with pytest.raises(DecisionConflict) as excinfo:
        decide(
            db,
            head,
            _actor(USER_ID),
            decision="false_positive",
            reason="x",
            seen_occurrence_count=1,
        )
    body = excinfo.value.body
    assert body["kind"] == "already_decided"
    assert body["decided_by"] == USER_NAME
    assert body["decision"] == "closed_benign"
    assert body["decided_at"] is not None


def _archive_everything(db) -> None:
    """The real `archive_before` over every row of the transaction (a cutoff in the future)."""
    from datetime import UTC, datetime, timedelta

    transitions.archive_before(
        db, before=datetime.now(UTC) + timedelta(hours=1), reason="DEC-212 test"
    )


@pytest.mark.parametrize("held", [False, True])
def test_an_archived_alert_is_not_active_and_nobody_decided_it(db, held) -> None:
    """INT-T03 / DEC-212: acknowledge, decide, escalate and reopen on an archived alert are refused as
    `not_active`, and the 409 body must not read the archive as a decision: no `decided_by` (the
    holder, when it was held, did not decide it), no `decision`, no `decided_at`."""
    _seed_user(db, USER_ID, USER_NAME)
    alert_id = _active(db) if held else _queued(db)
    _archive_everything(db)
    assert _status(db, alert_id) == "archived"
    cases = db.execute("SELECT count(*) FROM cases").fetchone()[0]

    attempts = (
        lambda: acknowledge(db, alert_id, _actor(OTHER_USER_ID)),
        lambda: decide(
            db, alert_id, _actor(USER_ID), decision="benign", reason="x", seen_occurrence_count=1
        ),
        lambda: escalate(db, alert_id, _actor(USER_ID), title="t", severity="high"),
        lambda: reopen(db, alert_id, _actor(USER_ID), reason="x"),
    )
    expected_kind = ("not_active", "not_active", "not_active", "not_reopenable")
    for attempt, kind in zip(attempts, expected_kind, strict=True):
        with pytest.raises(DecisionConflict) as excinfo:
            attempt()
        body = excinfo.value.body
        assert body["kind"] == kind
        assert body["status"] == "archived"
        assert body["decided_by"] is None
        assert body["decision"] is None
        assert body["decided_at"] is None
    assert db.execute("SELECT count(*) FROM cases").fetchone()[0] == cases  # no case was opened
    assert _status(db, alert_id) == "archived"


def test_decide_payload_has_eight_keys(db) -> None:
    _seed_user(db, USER_ID, USER_NAME)
    head = _active(db)
    run_id = _insert_run(db, head)

    decide(
        db,
        head,
        _actor(USER_ID),
        decision="false_positive",
        reason="matches ①",
        seen_occurrence_count=1,
    )

    rows = [r for r in _audit_rows(db, head) if r[0] == "tier1.decided"]
    assert len(rows) == 1
    payload = rows[0][1]
    assert set(payload) == {
        "decision",
        "reason",
        "occurrence_count",
        "llm_suggestion",
        "llm_confidence",
        "gate_forced",
        "suggestion_visible",
        "llm_run_id",
    }
    assert payload["llm_suggestion"] == "false_positive"
    assert payload["llm_confidence"] == "high"
    assert payload["gate_forced"] is False
    assert payload["suggestion_visible"] is True
    assert payload["llm_run_id"] == run_id


@pytest.mark.parametrize("proposed", ["false_positive", "true_positive"])
def test_decide_records_the_served_verdict_of_a_stored_needs_review_run(db, proposed) -> None:
    """DEC-217 (G3, spec 5): `decide` joins ①'s latest suggestion to the decision, and that is what Tier 1 was
    shown: for a run the old gate held (stored `needs_review`, version 1) the model's own `proposed_verdict`,
    never the raw stored value. `gate_forced` stays what the run stored (`True`)."""
    _seed_user(db, USER_ID, USER_NAME)
    head = _active(db)
    held = {**RESULT, "suggested_action": "needs_review", "confidence": "medium"}
    held_gate = {
        **GATE,
        "version": 1,
        "proposed_verdict": proposed,
        "final_verdict": "needs_review",
        "forced": True,
        "forced_by": ["step6"],
    }
    run_id = _insert_run(db, head, result=held, gate_result=held_gate)

    decide(
        db,
        head,
        _actor(USER_ID),
        decision="false_positive",
        reason="as ① said",
        seen_occurrence_count=1,
    )

    (payload,) = [r[1] for r in _audit_rows(db, head) if r[0] == "tier1.decided"]
    assert payload["llm_suggestion"] == proposed  # the served verdict, not `needs_review`
    assert payload["llm_confidence"] == "medium"
    assert payload["gate_forced"] is True
    assert payload["llm_run_id"] == run_id
    stored = db.execute(
        "SELECT result->>'suggested_action' FROM llm_runs WHERE run_id = %s", (run_id,)
    ).fetchone()
    assert stored == ("needs_review",)  # llm_runs is the record: untouched


def test_decide_reason_validation(db) -> None:
    _seed_user(db, USER_ID, USER_NAME)
    head = _active(db)
    with pytest.raises(ValueError):
        decide(db, head, _actor(USER_ID), decision="benign", reason="   ", seen_occurrence_count=1)
    with pytest.raises(ValueError):
        decide(
            db, head, _actor(USER_ID), decision="benign", reason="x" * 501, seen_occurrence_count=1
        )
    assert _status(db, head) == "tier1_active"


# ---------------------------------------------------------------------------
# escalate
# ---------------------------------------------------------------------------


def test_escalate_from_active_takes_only_the_trigger_not_its_correlated_heads(db) -> None:
    """T2 (the Owner, 11/11): the correlated open heads stay in the queue with their status and
    `case_id` as they were — they used to be swept into the case, and the closed one never was."""
    _seed_user(db, USER_ID, USER_NAME)
    agent = f"shared-agent-{next(_counter)}"
    trigger = _active(db, agent_name=agent)
    correlated_queued = _queued(db, agent_name=agent)
    correlated_auto_closed = _auto_closed(db, agent_name=agent)

    result = escalate(db, trigger, _actor(USER_ID), title="brute force", severity="high")
    assert result["status"] == "escalated_tier2"
    assert result["head_count"] == 1
    assert "truncated" not in result  # no cap can cut a case of one alert any more

    heads = {
        r[0]
        for r in db.execute(
            "SELECT alert_id FROM case_alerts WHERE case_id = %s", (result["case_id"],)
        ).fetchall()
    }
    assert heads == {trigger}
    assert _status(db, trigger) == "escalated_tier2"
    for sibling, status in (
        (correlated_queued, "queued_tier1"),
        (correlated_auto_closed, "auto_closed"),
    ):
        assert _status(db, sibling) == status  # untouched
        assert (
            db.execute("SELECT case_id FROM alerts WHERE alert_id = %s", (sibling,)).fetchone()[0]
            is None
        )


def test_escalate_duplicates_keep_status_and_get_case_id(db) -> None:
    _seed_user(db, USER_ID, USER_NAME)
    trigger = _active(db)
    dup = _duplicate(db, trigger)

    result = escalate(db, trigger, _actor(USER_ID), title="t", severity="high")

    status, case_id = db.execute(
        "SELECT status, case_id FROM alerts WHERE alert_id = %s", (dup,)
    ).fetchone()
    assert status == "duplicate"
    assert str(case_id) == result["case_id"]


def test_escalate_from_closed_is_conflict_before_any_case_insert(db) -> None:
    _seed_user(db, USER_ID, USER_NAME)
    head = _active(db)
    transitions.decide(
        db,
        head,
        USER_ID,
        decision="closed_fp",
        reason="fp",
        seen_occurrence_count=1,
        llm_suggestion=None,
        llm_confidence=None,
    )
    before = db.execute("SELECT count(*) FROM cases").fetchone()[0]

    with pytest.raises(DecisionConflict) as excinfo:
        escalate(db, head, _actor(USER_ID), title="t", severity="high")
    assert excinfo.value.body["kind"] == "already_decided"
    after = db.execute("SELECT count(*) FROM cases").fetchone()[0]
    assert after == before


def test_escalate_already_in_case_is_conflict(db) -> None:
    _seed_user(db, USER_ID, USER_NAME)
    head = _active(db)
    escalate(db, head, _actor(USER_ID), title="t", severity="high")

    with pytest.raises(DecisionConflict) as excinfo:
        escalate(db, head, _actor(USER_ID), title="t2", severity="high")
    assert excinfo.value.body["kind"] == "already_in_case"


def test_escalate_trigger_claimed_concurrently_is_conflict_and_nothing_half_written(db) -> None:
    """Review round 1, item 3 — the `UniqueViolation` flavor of `transitions.
    escalate`'s `StaleState` (the trigger already sits in `case_alerts` for
    another case, as it would if a concurrent escalate had committed first):
    without the savepoint around the call, the connection's transaction is
    aborted by the `UniqueViolation` and `_conflict()`'s own re-read would
    itself raise `InFailedSqlTransaction` instead of building the 409 body."""
    _seed_user(db, USER_ID, USER_NAME)
    trigger = _active(db)
    other_case = _make_case(db, USER_ID)
    db.execute(
        "INSERT INTO case_alerts (case_id, alert_id, added_by) VALUES (%s, %s, %s)",
        (other_case, trigger, USER_ID),
    )
    cases_before = db.execute("SELECT count(*) FROM cases").fetchone()[0]

    with pytest.raises(DecisionConflict) as excinfo:
        escalate(db, trigger, _actor(USER_ID), title="t", severity="high")
    assert excinfo.value.body["kind"] == "already_in_case"

    assert db.execute("SELECT count(*) FROM cases").fetchone()[0] == cases_before
    status, case_id = db.execute(
        "SELECT status, case_id FROM alerts WHERE alert_id = %s", (trigger,)
    ).fetchone()
    assert (status, case_id) == ("tier1_active", None)


def test_escalate_rowcount_mismatch_is_conflict_and_nothing_half_written(db) -> None:
    """Review round 1, item 3 — the other `StaleState` flavor: the trigger's
    `case_id` is already set directly (no `case_alerts` row, so no
    `UniqueViolation`), so `transitions.escalate` gets as far as inserting the
    `cases` row and the `case_alerts` row before the rowcount mismatch on the
    trigger raises `StaleState`. The savepoint must undo all of it, not just
    skip re-raising."""
    _seed_user(db, USER_ID, USER_NAME)
    trigger = _active(db)
    other_case = _make_case(db, USER_ID)
    db.execute("UPDATE alerts SET case_id = %s WHERE alert_id = %s", (other_case, trigger))
    cases_before = db.execute("SELECT count(*) FROM cases").fetchone()[0]

    with pytest.raises(DecisionConflict) as excinfo:
        escalate(db, trigger, _actor(USER_ID), title="t", severity="high")
    assert excinfo.value.body["kind"] == "already_in_case"

    assert db.execute("SELECT count(*) FROM cases").fetchone()[0] == cases_before
    assert db.execute("SELECT count(*) FROM case_alerts").fetchone()[0] == 0
    status, case_id = db.execute(
        "SELECT status, case_id FROM alerts WHERE alert_id = %s", (trigger,)
    ).fetchone()
    assert (status, str(case_id)) == ("tier1_active", other_case)


def test_escalate_is_not_blocked_by_a_correlated_alert_already_in_another_case(db) -> None:
    """The old sweep answered 409 when a correlated candidate was already in another case; the
    siblings are no longer looked at, so the escalation goes through and that case is untouched."""
    _seed_user(db, USER_ID, USER_NAME)
    agent = f"probe-agent-{next(_counter)}"
    trigger = _active(db, agent_name=agent)
    sibling = _active(db, agent_name=agent)
    other_case = _make_case(db, USER_ID)
    db.execute(
        "INSERT INTO case_alerts (case_id, alert_id, added_by) VALUES (%s, %s, %s)",
        (other_case, sibling, USER_ID),
    )

    result = escalate(db, trigger, _actor(USER_ID), title="t", severity="high")

    assert result["head_count"] == 1
    members = db.execute("SELECT case_id, alert_id FROM case_alerts ORDER BY alert_id").fetchall()
    assert {(str(c), a) for c, a in members} == {
        (other_case, sibling),
        (result["case_id"], trigger),
    }
    assert _status(db, sibling) == "tier1_active"


# ---------------------------------------------------------------------------
# reopen
# ---------------------------------------------------------------------------


def test_reopen_from_auto_closed_only(db) -> None:
    _seed_user(db, USER_ID, USER_NAME)
    alert_id = _auto_closed(db)

    result = reopen(db, alert_id, _actor(USER_ID), reason="reviewed, was noise")
    assert result == {"alert_id": alert_id, "status": "queued_tier1"}
    assert _status(db, alert_id) == "queued_tier1"
    events = [r[0] for r in _audit_rows(db, alert_id)]
    assert "alert.reopened" in events


def test_reopen_from_queued_is_not_reopenable(db) -> None:
    _seed_user(db, USER_ID, USER_NAME)
    alert_id = _queued(db)
    with pytest.raises(DecisionConflict) as excinfo:
        reopen(db, alert_id, _actor(USER_ID), reason="x")
    assert excinfo.value.body["kind"] == "not_reopenable"


def test_reopen_empty_reason_is_value_error(db) -> None:
    _seed_user(db, USER_ID, USER_NAME)
    alert_id = _auto_closed(db)
    with pytest.raises(ValueError):
        reopen(db, alert_id, _actor(USER_ID), reason="")
    assert _status(db, alert_id) == "auto_closed"
