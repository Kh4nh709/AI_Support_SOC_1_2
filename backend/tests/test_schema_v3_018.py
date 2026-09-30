"""Migration 018 — the `alerts_changed` NOTIFY trigger (P10-T05, DEC-162).

The trigger tells listeners that an alert the queue or the alert page shows has
changed. What is on trial is the channel's CONTRACT, not plpgsql:

* the payload names the alert and the operation and nothing else — no content, so
  nothing the blind arm (DEC-101) hides can travel on a channel every logged-in
  browser is subscribed to;
* NOTIFY is delivered at COMMIT, so a rolled-back write is never announced;
* only the columns the queue and the alert page render wake listeners — a write to
  any other column is silent, so the channel does not chatter.

The catalog checks read the shared `db` fixture (nothing is committed). Everything
that has to *commit* to be seen runs against a scratch database of this module's own
(`tests/scratch_db.py`), never the shared transaction: a second connection LISTENs,
the writer commits, and the second connection reads what was delivered.
"""

from __future__ import annotations

import json

import psycopg
import pytest

from tests.scratch_db import insert_alert, insert_user, scratch_database

CHANNEL = "alerts_changed"
# The columns the UPDATE trigger watches, exactly as the brief spells them.
WATCHED = (
    "status",
    "occurrence_count",
    "last_seen_at",
    "triage_status",
    "acknowledged_by",
    "closed_at",
    "case_id",
    "risk_score",
)


@pytest.fixture(scope="module")
def scratch():
    with scratch_database("018") as dsn:
        yield dsn


@pytest.fixture
def writer(scratch):
    conn = psycopg.connect(scratch)
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


@pytest.fixture
def listener(scratch):
    """A second connection already LISTENing: notifications sent before LISTEN are lost."""
    conn = psycopg.connect(scratch, autocommit=True)
    conn.execute(f"LISTEN {CHANNEL}")
    try:
        yield conn
    finally:
        conn.close()


def _delivered(listener: psycopg.Connection, wait_s: float = 1.0) -> list[dict]:
    """Every payload delivered so far, parsed; waits `wait_s` for quiet."""
    return [json.loads(n.payload) for n in listener.notifies(timeout=wait_s)]


# --------------------------------------------------------------------------------------
# The migration recorded itself, and built what the brief names (shared db, no commit)
# --------------------------------------------------------------------------------------


@pytest.mark.db
def test_018_records_itself(db):
    with db.cursor() as cur:
        cur.execute("SELECT 1 FROM schema_migrations WHERE version = '018_alerts_notify'")
        assert cur.fetchone() is not None, "018 did not record itself; migrate.sh will re-apply it"


@pytest.mark.db
def test_the_trigger_is_an_after_row_trigger_on_the_watched_columns(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT pg_get_triggerdef(oid) FROM pg_trigger "
            "WHERE NOT tgisinternal AND tgrelid = 'public.alerts'::regclass "
            "AND tgname = 'trg_alerts_notify'"
        )
        rows = cur.fetchall()
    assert len(rows) == 1, "trg_alerts_notify is not attached exactly once"
    definition = rows[0][0]
    assert "AFTER INSERT OR UPDATE OF " + ", ".join(WATCHED) + " ON public.alerts" in definition
    assert "FOR EACH ROW" in definition
    assert "notify_alerts_changed()" in definition


# --------------------------------------------------------------------------------------
# The payload — the alert and the operation, and nothing else
# --------------------------------------------------------------------------------------


@pytest.mark.db
def test_insert_notifies_with_id_and_op_only(writer, listener):
    # Every free-text column carries a marker: any of them in the payload is a leak.
    insert_alert(writer, "p10t05-ins-1", raw_log="LEAK-MARKER-raw-log")
    writer.commit()

    payloads = _delivered(listener)

    assert payloads == [{"alert_id": "p10t05-ins-1", "op": "INSERT"}]
    assert set(payloads[0]) == {"alert_id", "op"}
    assert "LEAK-MARKER" not in json.dumps(payloads)


@pytest.mark.db
def test_update_of_a_watched_column_notifies_update(writer, listener):
    insert_alert(writer, "p10t05-upd-1")
    writer.commit()
    _delivered(listener)  # the INSERT's notification

    writer.execute("UPDATE alerts SET status = 'queued_tier1' WHERE alert_id = 'p10t05-upd-1'")
    writer.commit()

    assert _delivered(listener) == [{"alert_id": "p10t05-upd-1", "op": "UPDATE"}]


@pytest.mark.db
@pytest.mark.parametrize(
    "assignment",
    [
        "status = 'enriching'",
        "occurrence_count = occurrence_count + 1",
        "last_seen_at = now()",
        "triage_status = 'ready'",
        "acknowledged_by = %(user)s",
        "closed_at = now()",
        "risk_score = 42",
    ],
)
def test_every_watched_column_wakes_listeners(writer, listener, assignment):
    alert_id = f"p10t05-col-{assignment.split()[0]}"
    user_id = insert_user(writer)  # `acknowledged_by` is a foreign key to users
    insert_alert(writer, alert_id)
    writer.commit()
    _delivered(listener)

    writer.execute(
        f"UPDATE alerts SET {assignment} WHERE alert_id = %(alert_id)s",
        {"user": user_id, "alert_id": alert_id},
    )
    writer.commit()

    assert _delivered(listener) == [{"alert_id": alert_id, "op": "UPDATE"}]


@pytest.mark.db
def test_case_id_wakes_listeners(writer, listener):
    insert_alert(writer, "p10t05-case-1")
    writer.execute(
        "INSERT INTO cases (case_id, title, severity, created_by) VALUES "
        "('00000000-0000-4000-8000-0000000000c5', 'p10t05', 'high', %s)",
        (insert_user(writer),),
    )
    writer.commit()
    _delivered(listener)

    writer.execute(
        "UPDATE alerts SET case_id = '00000000-0000-4000-8000-0000000000c5' "
        "WHERE alert_id = 'p10t05-case-1'"
    )
    writer.commit()

    assert _delivered(listener) == [{"alert_id": "p10t05-case-1", "op": "UPDATE"}]


# --------------------------------------------------------------------------------------
# Commit-time delivery, and silence for everything the UI does not render
# --------------------------------------------------------------------------------------


@pytest.mark.db
def test_rolled_back_insert_does_not_notify(writer, listener):
    insert_alert(writer, "p10t05-rb-1")
    writer.rollback()

    assert _delivered(listener, wait_s=0.5) == []


@pytest.mark.db
def test_nothing_is_delivered_before_commit(writer, listener):
    insert_alert(writer, "p10t05-pre-1")

    assert _delivered(listener, wait_s=0.5) == []  # still open
    writer.commit()
    assert _delivered(listener) == [{"alert_id": "p10t05-pre-1", "op": "INSERT"}]


@pytest.mark.db
def test_update_of_an_unlisted_column_does_not_notify(writer, listener):
    insert_alert(writer, "p10t05-quiet-1")
    writer.commit()
    _delivered(listener)

    # `description` and `agent_name` are outside the trigger's column list.
    writer.execute(
        "UPDATE alerts SET description = 'changed', agent_name = 'other-agent' "
        "WHERE alert_id = 'p10t05-quiet-1'"
    )
    writer.commit()

    assert _delivered(listener, wait_s=0.5) == []


@pytest.mark.db
def test_the_application_role_write_still_notifies(writer, listener):
    """Production writes as `app_rw`. The trigger function runs with the writer's rights,
    so this proves `pg_notify` is reachable by that role and no grant is missing."""
    writer.execute("SET ROLE app_rw")
    insert_alert(writer, "p10t05-role-1")
    writer.execute("UPDATE alerts SET status = 'queued_tier1' WHERE alert_id = 'p10t05-role-1'")
    writer.execute("RESET ROLE")
    writer.commit()

    payloads = _delivered(listener)

    # Both writes are in one transaction and name the same alert: Postgres delivers
    # identical (channel, payload) pairs of one transaction once, so a bulk write of one
    # alert does not repeat itself; the INSERT and the UPDATE differ by `op`.
    assert {p["op"] for p in payloads} == {"INSERT", "UPDATE"}
    assert {p["alert_id"] for p in payloads} == {"p10t05-role-1"}
