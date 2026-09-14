"""Tests for app.audit.events.write_event and EVENT_TYPES.

Three things are on trial (design note 5): the Python-side EVENT_TYPES gate
runs before any SQL (acceptance 7's second case, proven here by checking the
connection's transaction status stays IDLE); the two DB CHECKs
(`ck_audit_actor_id_theo_role`) and the append-only trigger are real,
measured behaviour, not assumptions; and EVENT_TYPES itself is checked
against the live `ck_audit_event_type` constraint so the two lists cannot
drift apart silently.
"""

from __future__ import annotations

import psycopg
import psycopg.pq
import pytest
from app.audit import events
from app.infra.errors import PermanentError


def test_event_types_has_exactly_27_entries():
    assert len(events.EVENT_TYPES) == 27


def test_event_types_contains_the_v1_and_v3_spot_checks():
    for name in ("alert.received", "tier1.decided", "case.analyzed"):
        assert name in events.EVENT_TYPES
    for name in ("job.exhausted", "autoclose.reviewed", "health.alarm", "label.created"):
        assert name in events.EVENT_TYPES  # v3 additions


@pytest.mark.db
def test_event_types_matches_the_live_ck_audit_event_type_constraint(db):
    constraint_def = db.execute(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'ck_audit_event_type'"
    ).fetchone()[0]
    for event_type in events.EVENT_TYPES:
        assert f"'{event_type}'" in constraint_def, event_type


@pytest.mark.db
def test_write_event_inserts_a_row_and_returns_the_audit_id(db):
    audit_id = events.write_event(db, "alert.received", "wr-1", "system")
    row = db.execute(
        "SELECT event_type, subject_id, actor_role, actor_id, payload FROM audit_events "
        "WHERE audit_id = %s",
        (audit_id,),
    ).fetchone()
    assert row == ("alert.received", "wr-1", "system", None, None)


@pytest.mark.db
def test_write_event_stores_payload_as_jsonb(db):
    audit_id = events.write_event(
        db,
        "tier1.decided",
        "wr-2",
        "analyst",
        actor_id="11111111-1111-1111-1111-111111111111",
        payload={"decision": "closed_fp", "count": 2},
    )
    payload = db.execute(
        "SELECT payload FROM audit_events WHERE audit_id = %s", (audit_id,)
    ).fetchone()[0]
    assert payload == {"decision": "closed_fp", "count": 2}


@pytest.mark.db
def test_write_event_rejects_unknown_event_type_before_touching_the_connection(db):
    assert db.info.transaction_status == psycopg.pq.TransactionStatus.IDLE
    with pytest.raises(PermanentError, match="not.an.event"):
        events.write_event(db, "not.an.event", "wr-3", "system")
    # No SQL was ever sent: the connection never left IDLE.
    assert db.info.transaction_status == psycopg.pq.TransactionStatus.IDLE


@pytest.mark.db
def test_write_event_system_actor_with_actor_id_violates_the_role_check(db):
    with pytest.raises(psycopg.errors.CheckViolation, match="ck_audit_actor_id_theo_role"):
        events.write_event(
            db,
            "alert.received",
            "wr-4",
            "system",
            actor_id="11111111-1111-1111-1111-111111111111",
        )
    db.rollback()


@pytest.mark.db
def test_audit_events_is_append_only_through_this_writers_connection(db):
    events.write_event(db, "alert.received", "wr-5", "system")
    db.execute("SAVEPOINT before_update")
    with pytest.raises(
        psycopg.errors.RaiseException, match="append-only table: audit_events is immutable"
    ):
        db.execute("UPDATE audit_events SET subject_id = 'x' WHERE subject_id = 'wr-5'")
    db.execute("ROLLBACK TO SAVEPOINT before_update")
    # connection still usable after the savepoint rollback
    still_there = db.execute(
        "SELECT subject_id FROM audit_events WHERE subject_id = 'wr-5'"
    ).fetchone()
    assert still_there == ("wr-5",)
