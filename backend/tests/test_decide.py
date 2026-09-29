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


def _insert_run(conn: psycopg.Connection, alert_id: str) -> str:
    """One `llm_runs` proposer row in P3-T10's shape (P4-T02's fixture INSERT)."""
    row = conn.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt, "
        "user_message, result, role, gate_result) "
        "VALUES (gen_random_uuid(), 'triage', 'alert', %s, 's', 'u', %s::jsonb, 'proposer', "
        "%s::jsonb) RETURNING run_id",
        (alert_id, json.dumps(RESULT), json.dumps(GATE)),
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


def test_escalate_from_active_pulls_correlated_queued_head_not_auto_closed(db) -> None:
    _seed_user(db, USER_ID, USER_NAME)
    agent = f"shared-agent-{next(_counter)}"
    trigger = _active(db, agent_name=agent)
    correlated_queued = _queued(db, agent_name=agent)
    correlated_auto_closed = _auto_closed(db, agent_name=agent)

    result = escalate(db, trigger, _actor(USER_ID), title="brute force", severity="high")
    assert result["status"] == "escalated_tier2"
    assert result["head_count"] == 2
    assert result["truncated"] is False

    heads = {
        r[0]
        for r in db.execute(
            "SELECT alert_id FROM case_alerts WHERE case_id = %s", (result["case_id"],)
        ).fetchall()
    }
    assert heads == {trigger, correlated_queued}
    assert correlated_auto_closed not in heads
    assert _status(db, correlated_queued) == "escalated_tier2"
    assert _status(db, correlated_auto_closed) == "auto_closed"  # untouched


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


def test_escalate_candidate_claimed_concurrently_is_conflict_and_nothing_half_written(db) -> None:
    """Review round 1, item 3 — the `UniqueViolation` flavor of `transitions.
    escalate`'s `StaleState` (a correlated candidate already sits in
    `case_alerts` for another case): without the savepoint around the call,
    the connection's transaction is aborted by the `UniqueViolation` and
    `_conflict()`'s own re-read would itself raise `InFailedSqlTransaction`
    instead of building the 409 body."""
    _seed_user(db, USER_ID, USER_NAME)
    agent = f"probe-agent-{next(_counter)}"
    trigger = _active(db, agent_name=agent)
    other = _queued(db, agent_name=agent)
    other_case = _make_case(db, USER_ID)
    db.execute(
        "INSERT INTO case_alerts (case_id, alert_id, added_by) VALUES (%s, %s, %s)",
        (other_case, other, USER_ID),
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
    """Review round 1, item 3 — the other `StaleState` flavor: a correlated
    candidate's `case_id` is already set directly (no `case_alerts` row, so no
    `UniqueViolation`), so `transitions.escalate` gets as far as inserting the
    `cases` row, the two `case_alerts` rows and updating the trigger's own
    status before the rowcount mismatch on `other` raises `StaleState`. The
    savepoint must undo all of it, not just skip re-raising."""
    _seed_user(db, USER_ID, USER_NAME)
    agent = f"probe-agent-{next(_counter)}"
    trigger = _active(db, agent_name=agent)
    other = _queued(db, agent_name=agent)
    other_case = _make_case(db, USER_ID)
    db.execute("UPDATE alerts SET case_id = %s WHERE alert_id = %s", (other_case, other))
    cases_before = db.execute("SELECT count(*) FROM cases").fetchone()[0]

    with pytest.raises(DecisionConflict) as excinfo:
        escalate(db, trigger, _actor(USER_ID), title="t", severity="high")
    assert excinfo.value.body["kind"] == "already_in_case"

    assert db.execute("SELECT count(*) FROM cases").fetchone()[0] == cases_before
    status, case_id = db.execute(
        "SELECT status, case_id FROM alerts WHERE alert_id = %s", (trigger,)
    ).fetchone()
    assert (status, case_id) == ("tier1_active", None)


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
