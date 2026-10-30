"""INT-T03 / DEC-212 — `domain.transitions.archive_before`: the old queue closed out without review.

Cases first (`investigating` and created before the cutoff), then those cases' alerts that are
still `escalated_tier2`, then the queue heads (`received`, `enriching`, `queued_tier1`,
`tier1_active`, received before the cutoff). Everything else is left alone: duplicates, anything
a person or a rule closed, concluded cases, and whatever came at or after the cutoff. Each row
becomes `archived` with `closed_at`, `sealed_at` and `close_reason` (an alert) or `concluded_at`
and `conclusion_reason` (a case, `concluded_by` NULL), and writes ONE audit event of its own
(`alert.archived` / `case.archived`, `actor_role='system'`). No decision event, no label, no job.

The cutoff of these tests is in 2001 and the rows are dated before it: `archive_before` acts on the
whole table, and no other test's row can sit before a cutoff that old.
"""

from __future__ import annotations

import threading
import time
import uuid
from datetime import UTC, datetime, timedelta, timezone

import psycopg
import pytest
from app.domain import transitions

from tests.scratch_db import INSERT_ALERT, insert_user, scratch_database

pytestmark = pytest.mark.db

BEFORE = datetime(2001, 1, 1, 8, 0, tzinfo=timezone(timedelta(hours=7)))
REASON = "DEC-212: queue archived for a fresh start"
EARLIER = BEFORE - timedelta(days=3)

#: What each status carries in `closed_at` / `sealed_at` (the table's own rules, `ck_alerts_*`).
_CLOSED = {"auto_closed", "closed_fp", "closed_benign", "closed_confirmed", "duplicate", "archived"}
_SEALED = {"closed_fp", "closed_benign", "closed_confirmed", "duplicate", "archived"}


def _put_alert(
    conn,
    alert_id: str,
    *,
    status: str = "queued_tier1",
    received_at: datetime = EARLIER,
    duplicate_of: str | None = None,
    case_id: str | None = None,
    acknowledged_by: str | None = None,
    triage_status: str = "ready",
    triaged_count: int = 3,
    occurrence_count: int = 5,
    suggestion_visible: bool = False,
    close_reason: str | None = None,
) -> str:
    conn.execute(
        INSERT_ALERT, (alert_id, alert_id, "log " + alert_id, suggestion_visible, "received")
    )
    conn.execute(
        "UPDATE alerts SET status = %(status)s, received_at = %(received_at)s,"
        " first_seen_at = %(received_at)s, last_seen_at = %(received_at)s,"
        " duplicate_of = %(duplicate_of)s, case_id = %(case_id)s,"
        " acknowledged_by = %(ack)s, acknowledged_at = CASE WHEN %(ack)s::uuid IS NULL THEN NULL"
        " ELSE %(received_at)s END, triage_status = %(triage_status)s,"
        " triaged_count = %(triaged_count)s, occurrence_count = %(occurrence_count)s,"
        " risk_score = 40, close_reason = %(close_reason)s,"
        " closed_at = CASE WHEN %(closed)s THEN %(received_at)s END,"
        " sealed_at = CASE WHEN %(sealed)s THEN %(received_at)s END"
        " WHERE alert_id = %(alert_id)s",
        {
            "alert_id": alert_id,
            "status": status,
            "received_at": received_at,
            "duplicate_of": duplicate_of,
            "case_id": case_id,
            "ack": acknowledged_by,
            "triage_status": triage_status,
            "triaged_count": triaged_count,
            "occurrence_count": occurrence_count,
            "close_reason": close_reason,
            "closed": status in _CLOSED,
            "sealed": status in _SEALED,
        },
    )
    return alert_id


def _put_case(
    conn,
    user_id: str,
    heads: list[str],
    *,
    status: str = "investigating",
    created_at: datetime = EARLIER,
    head_status: str = "escalated_tier2",
    duplicates: tuple[str, ...] = (),
) -> str:
    case_id = str(uuid.uuid4())
    concluded = status != "investigating"
    conn.execute(
        "INSERT INTO cases (case_id, title, status, severity, created_by, created_at,"
        " concluded_at, concluded_by, conclusion_reason) VALUES (%(c)s, 'int-t03', %(s)s,"
        " 'medium', %(u)s, %(t)s, CASE WHEN %(k)s THEN %(t)s END,"
        " CASE WHEN %(k)s THEN %(u)s::uuid END, CASE WHEN %(k)s THEN 'r' END)",
        {"c": case_id, "s": status, "u": user_id, "t": created_at, "k": concluded},
    )
    for head in heads:
        conn.execute(
            "INSERT INTO case_alerts (case_id, alert_id, added_by) VALUES (%s, %s, %s)",
            (case_id, head, user_id),
        )
        conn.execute(
            "UPDATE alerts SET case_id = %s, status = %s, closed_at = CASE WHEN %s <> "
            "'escalated_tier2' THEN %s END, sealed_at = CASE WHEN %s <> 'escalated_tier2' "
            "THEN %s END WHERE alert_id = %s",
            (case_id, head_status, head_status, created_at, head_status, created_at, head),
        )
    for duplicate in duplicates:
        conn.execute("UPDATE alerts SET case_id = %s WHERE alert_id = %s", (case_id, duplicate))
    return case_id


def _row(conn, alert_id: str) -> dict:
    """The whole row as JSON, for comparisons that name what moved and what did not."""
    return conn.execute(
        "SELECT to_jsonb(a) FROM alerts a WHERE alert_id = %s", (alert_id,)
    ).fetchone()[0]


MOVED = ("status", "closed_at", "sealed_at", "close_reason")


def _unmoved(row: dict) -> dict:
    return {k: v for k, v in row.items() if k not in MOVED}


def _status(conn, alert_id: str) -> str:
    return conn.execute("SELECT status FROM alerts WHERE alert_id = %s", (alert_id,)).fetchone()[0]


def _events(conn, subject_ids: list[str]) -> list[tuple]:
    return conn.execute(
        "SELECT event_type, subject_id, actor_role, actor_id, payload FROM audit_events"
        " WHERE subject_id = ANY(%s) ORDER BY audit_id",
        (subject_ids,),
    ).fetchall()


def _count(conn, table: str) -> int:
    return conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


def _decision_events(conn) -> int:
    return conn.execute(
        "SELECT count(*) FROM audit_events WHERE event_type IN"
        " ('tier1.decided', 'tier2.concluded', 'label.created')"
    ).fetchone()[0]


def _world(db) -> dict:
    """One of everything the archive must and must not touch."""
    user = insert_user(db, "tier1")
    tier2 = insert_user(db, "tier2")
    w: dict = {"user": user, "tier2": tier2}

    # the queue heads it archives, one per from-status
    for name in ("received", "enriching", "queued_tier1", "tier1_active"):
        w[name] = _put_alert(
            db,
            f"it03-{name}",
            status=name,
            acknowledged_by=user if name == "tier1_active" else None,
        )
    w["queued_2"] = _put_alert(db, "it03-queued-2", received_at=EARLIER - timedelta(days=5))

    # the boundary: at the cutoff is NOT before it; a second later is after it
    w["at_cutoff"] = _put_alert(db, "it03-at", received_at=BEFORE)
    w["after"] = _put_alert(db, "it03-after", received_at=BEFORE + timedelta(seconds=1))

    # decided or closed by a person or a rule: not touched
    for name, status in (
        ("fp", "closed_fp"),
        ("benign", "closed_benign"),
        ("confirmed", "closed_confirmed"),
        ("auto", "auto_closed"),
    ):
        w[name] = _put_alert(
            db, f"it03-{name}", status=status, acknowledged_by=user, close_reason="by a person"
        )

    # duplicates: already sealed, never touched, even those of an archived head
    w["dup"] = _put_alert(
        db, "it03-dup", status="duplicate", duplicate_of=w["queued_tier1"], occurrence_count=1
    )

    # an old case with two escalated heads and a duplicate of one of them that carries its case_id
    h1 = _put_alert(db, "it03-case-h1", status="escalated_tier2")
    h2 = _put_alert(
        db, "it03-case-h2", status="escalated_tier2", received_at=EARLIER - timedelta(days=9)
    )
    d1 = _put_alert(db, "it03-case-d1", status="duplicate", duplicate_of=h1, occurrence_count=1)
    w["old_case"] = _put_case(db, tier2, [h1, h2], duplicates=(d1,))
    w["old_case_alerts"] = [h1, h2]
    w["old_case_dup"] = d1

    # a case at the cutoff (not before it): it and its alert stay, though the alert is old
    h3 = _put_alert(db, "it03-newcase-h", status="escalated_tier2")
    w["new_case"] = _put_case(db, tier2, [h3], created_at=BEFORE)
    w["new_case_alert"] = h3

    # a concluded case: untouched, with its closed alert
    h4 = _put_alert(db, "it03-done-h", status="closed_fp", acknowledged_by=user)
    w["done_case"] = _put_case(db, tier2, [h4], status="concluded_fp", head_status="closed_fp")
    w["done_case_alert"] = h4
    return w


STILL = ("fp", "benign", "confirmed", "auto", "dup", "at_cutoff", "after")


# ── what moves ──────────────────────────────────────────────────────────────────────────────


def test_the_queue_heads_before_the_cutoff_become_archived_and_nothing_else_of_theirs_moves(db):
    w = _world(db)
    names = ("received", "enriching", "queued_tier1", "tier1_active", "queued_2")
    before = {n: _row(db, w[n]) for n in names}

    transitions.archive_before(db, before=BEFORE, reason=REASON)

    for name in names:
        after = _row(db, w[name])
        assert after["status"] == "archived", name
        assert after["close_reason"] == REASON, name
        assert after["closed_at"] is not None and after["sealed_at"] is not None, name
        # case_id, acknowledged_by, triage_status, triaged_count ... every other column: as it was
        assert _unmoved(after) == _unmoved(before[name]), name


def test_closed_and_auto_closed_and_duplicates_and_the_cutoff_and_later_are_not_touched(db):
    w = _world(db)
    before = {n: _row(db, w[n]) for n in STILL}

    transitions.archive_before(db, before=BEFORE, reason=REASON)

    for name in STILL:
        assert _row(db, w[name]) == before[name], name


def test_an_old_investigating_case_is_archived_with_its_escalated_alerts(db):
    w = _world(db)
    heads_before = {a: _row(db, a) for a in w["old_case_alerts"]}

    transitions.archive_before(db, before=BEFORE, reason=REASON)

    status, reason, concluded_at, concluded_by = db.execute(
        "SELECT status, conclusion_reason, concluded_at, concluded_by FROM cases WHERE case_id = %s",
        (w["old_case"],),
    ).fetchone()
    assert status == "archived"
    assert reason == REASON
    assert concluded_at is not None
    assert concluded_by is None  # nobody concluded it
    for alert_id, row in heads_before.items():
        after = _row(db, alert_id)
        assert after["status"] == "archived"
        assert after["case_id"] == w["old_case"]  # the case link is kept
        assert after["close_reason"] == REASON
        assert after["closed_at"] is not None and after["sealed_at"] is not None
        assert _unmoved(after) == _unmoved(row)
    # the duplicate that carries the case_id is a duplicate still
    dup = _row(db, w["old_case_dup"])
    assert dup["status"] == "duplicate" and dup["case_id"] == w["old_case"]


def test_a_case_at_the_cutoff_and_its_alerts_and_a_concluded_case_stay(db):
    w = _world(db)
    new_before = (_row(db, w["new_case_alert"]), _case_row(db, w["new_case"]))
    done_before = (_row(db, w["done_case_alert"]), _case_row(db, w["done_case"]))

    transitions.archive_before(db, before=BEFORE, reason=REASON)

    assert (_row(db, w["new_case_alert"]), _case_row(db, w["new_case"])) == new_before
    assert (_row(db, w["done_case_alert"]), _case_row(db, w["done_case"])) == done_before
    assert _status(db, w["new_case_alert"]) == "escalated_tier2"


def _case_row(conn, case_id: str) -> dict:
    return conn.execute(
        "SELECT to_jsonb(c) FROM cases c WHERE case_id = %s", (case_id,)
    ).fetchone()[0]


def test_an_escalated_alert_of_a_case_that_is_not_archived_is_not_a_queue_head(db):
    """`escalated_tier2` is not a head status: it is archived only through its archived case."""
    w = _world(db)
    transitions.archive_before(db, before=BEFORE, reason=REASON)
    assert _status(db, w["new_case_alert"]) == "escalated_tier2"


# ── the counts ──────────────────────────────────────────────────────────────────────────────


def test_the_counts_are_per_from_status_the_cases_and_the_oldest_and_newest_received_at(db):
    w = _world(db)

    counts = transitions.archive_before(db, before=BEFORE, reason=REASON)

    assert counts.by_status == {
        "received": 1,
        "enriching": 1,
        "queued_tier1": 2,
        "tier1_active": 1,
        "escalated_tier2": 2,
    }
    assert counts.cases == 1
    assert counts.alerts == 7
    assert counts.oldest_received_at == EARLIER - timedelta(days=9)  # the case head h2
    assert counts.newest_received_at == EARLIER
    assert w  # the world stays referenced


def test_nothing_to_archive_is_all_zeros_and_no_dates(db):
    counts = transitions.archive_before(db, before=BEFORE, reason=REASON)
    assert counts.alerts == 0 and counts.cases == 0
    assert all(n == 0 for n in counts.by_status.values())
    assert counts.oldest_received_at is None and counts.newest_received_at is None


def test_a_second_run_archives_nothing(db):
    _world(db)
    transitions.archive_before(db, before=BEFORE, reason=REASON)
    events = _count(db, "audit_events")

    again = transitions.archive_before(db, before=BEFORE, reason=REASON)

    assert again.alerts == 0 and again.cases == 0
    assert _count(db, "audit_events") == events  # and writes nothing


# ── the audit events ────────────────────────────────────────────────────────────────────────


def test_one_alert_archived_event_per_alert_with_the_payload_and_no_actor(db):
    w = _world(db)
    queue = {
        w["received"]: "received",
        w["enriching"]: "enriching",
        w["queued_tier1"]: "queued_tier1",
        w["tier1_active"]: "tier1_active",
        w["queued_2"]: "queued_tier1",
    }
    case_alerts = {a: "escalated_tier2" for a in w["old_case_alerts"]}
    # the events written by the world's own inserts are none: `_put_alert` writes rows, not events
    transitions.archive_before(db, before=BEFORE, reason=REASON)

    for alert_id, from_status in {**queue, **case_alerts}.items():
        events = _events(db, [alert_id])
        assert len(events) == 1, alert_id
        event_type, subject, role, actor, payload = events[0]
        assert (event_type, subject, role, actor) == ("alert.archived", alert_id, "system", None)
        expected = {
            "reason": REASON,
            "before": BEFORE.isoformat(),
            "from_status": from_status,
            "decision": "DEC-212",
        }
        if alert_id in case_alerts:
            expected["case_id"] = w["old_case"]
        assert payload == expected, alert_id


def test_one_case_archived_event_per_case_with_the_payload_and_no_actor(db):
    w = _world(db)
    transitions.archive_before(db, before=BEFORE, reason=REASON)

    events = _events(db, [w["old_case"]])
    assert len(events) == 1
    event_type, subject, role, actor, payload = events[0]
    assert (event_type, subject, role, actor) == ("case.archived", w["old_case"], "system", None)
    assert payload == {
        "reason": REASON,
        "before": BEFORE.isoformat(),
        "from_status": "investigating",
        "decision": "DEC-212",
    }


def test_untouched_rows_get_no_event(db):
    w = _world(db)
    transitions.archive_before(db, before=BEFORE, reason=REASON)
    untouched = [w[n] for n in STILL] + [w["new_case"], w["done_case"], w["new_case_alert"]]
    assert _events(db, untouched) == []


def test_it_writes_no_decision_no_label_and_no_job(db):
    _world(db)
    jobs, decisions = _count(db, "jobs"), _decision_events(db)
    last = db.execute("SELECT coalesce(max(audit_id), 0) FROM audit_events").fetchone()[0]

    counts = transitions.archive_before(db, before=BEFORE, reason=REASON)

    assert _count(db, "jobs") == jobs  # no knowledge_draft, no rag_lookup, no triage
    assert _decision_events(db) == decisions  # no tier1.decided, tier2.concluded, label.created
    written = db.execute(
        "SELECT event_type, count(*) FROM audit_events WHERE audit_id > %s GROUP BY 1", (last,)
    ).fetchall()
    assert dict(written) == {"alert.archived": counts.alerts, "case.archived": counts.cases}


def test_it_enqueues_nothing_even_with_the_rag_and_draft_switches_on(db, monkeypatch):
    monkeypatch.setenv("RAG_ENABLED", "true")
    monkeypatch.setenv("KNOWLEDGE_DRAFT_ENABLED", "true")
    _world(db)
    jobs = _count(db, "jobs")
    transitions.archive_before(db, before=BEFORE, reason=REASON)
    assert _count(db, "jobs") == jobs


# ── refusals ────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("reason", ["", "   ", "x" * 501])
def test_a_reason_must_be_one_to_five_hundred_characters(db, reason):
    w = _world(db)
    with pytest.raises(ValueError, match="reason"):
        transitions.archive_before(db, before=BEFORE, reason=reason)
    assert _status(db, w["queued_tier1"]) == "queued_tier1"


def test_a_cutoff_without_an_offset_is_refused(db):
    w = _world(db)
    with pytest.raises(ValueError, match="before"):
        transitions.archive_before(
            db, before=datetime(2001, 1, 1, 8, 0), reason=REASON  # noqa: DTZ001 - naive on purpose
        )
    assert _status(db, w["queued_tier1"]) == "queued_tier1"


def test_the_cutoff_is_compared_as_an_instant_not_as_a_wall_clock(db):
    """The same instant in UTC and in +07:00 archives the same rows."""
    w = _world(db)
    in_utc = BEFORE.astimezone(UTC)
    counts = transitions.archive_before(db, before=in_utc, reason=REASON)
    assert counts.alerts == 7
    assert _status(db, w["at_cutoff"]) == "queued_tier1"
    event = _events(db, [w["queued_tier1"]])[0][4]
    assert event["before"] == in_utc.isoformat()


# ── concurrency: a row an analyst moved meanwhile is skipped, never forced ───────────────────


def _waiting_on_a_lock(admin) -> bool:
    return (
        admin.execute(
            "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()"
            " AND wait_event_type = 'Lock' AND pid <> pg_backend_pid()"
        ).fetchone()[0]
        > 0
    )


def _archive_in_a_thread(dsn, results: list, errors: list) -> threading.Thread:
    def run() -> None:
        try:
            with psycopg.connect(dsn) as conn:
                results.append(transitions.archive_before(conn, before=BEFORE, reason=REASON))
                conn.commit()
        except Exception as exc:  # noqa: BLE001 - a thread's error is handed to the test
            errors.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    return thread


def _wait_until_blocked(admin, thread: threading.Thread) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if _waiting_on_a_lock(admin):
            return
        assert thread.is_alive(), "the archive finished without waiting for the analyst's lock"
        time.sleep(0.05)
    pytest.fail("the archive never waited for the analyst's lock")


def test_a_head_an_analyst_closes_while_the_archive_waits_is_skipped_not_forced():
    with scratch_database("archive") as dsn:
        with psycopg.connect(dsn) as setup:
            _put_alert(setup, "it03-a")
            _put_alert(setup, "it03-b")
            setup.commit()
        analyst = psycopg.connect(dsn)
        admin = psycopg.connect(dsn, autocommit=True)
        results: list = []
        errors: list = []
        try:
            # the analyst closes A and holds the row until it commits
            analyst.execute(
                "UPDATE alerts SET status = 'closed_fp', closed_at = now(), sealed_at = now(),"
                " close_reason = 'a person decided' WHERE alert_id = 'it03-a'"
            )
            thread = _archive_in_a_thread(dsn, results, errors)
            _wait_until_blocked(admin, thread)
            analyst.commit()
            thread.join(timeout=20)
            assert not thread.is_alive() and not errors, errors
            counts = results[0]
            assert counts.by_status["queued_tier1"] == 1  # B only
            a = admin.execute(
                "SELECT status, close_reason FROM alerts WHERE alert_id = 'it03-a'"
            ).fetchone()
            assert a == ("closed_fp", "a person decided")  # theirs, not overwritten
            assert admin.execute(
                "SELECT status FROM alerts WHERE alert_id = 'it03-b'"
            ).fetchone() == ("archived",)
            assert (
                admin.execute(
                    "SELECT count(*) FROM audit_events WHERE subject_id = 'it03-a'"
                ).fetchone()[0]
                == 0
            )
        finally:
            analyst.close()
            admin.close()


def test_a_case_an_analyst_concludes_while_the_archive_waits_is_skipped_with_its_alerts():
    with scratch_database("archive") as dsn:
        with psycopg.connect(dsn) as setup:
            tier2 = insert_user(setup, "tier2")
            head = _put_alert(setup, "it03-h", status="escalated_tier2")
            case_id = _put_case(setup, tier2, [head])
            setup.commit()
        analyst = psycopg.connect(dsn)
        admin = psycopg.connect(dsn, autocommit=True)
        results: list = []
        errors: list = []
        try:
            analyst.execute(
                "UPDATE cases SET status = 'concluded_fp', concluded_at = now(),"
                " concluded_by = %s, conclusion_reason = 'a person concluded'"
                " WHERE case_id = %s",
                (tier2, case_id),
            )
            analyst.execute(
                "UPDATE alerts SET status = 'closed_fp', closed_at = now(), sealed_at = now()"
                " WHERE alert_id = %s",
                (head,),
            )
            thread = _archive_in_a_thread(dsn, results, errors)
            _wait_until_blocked(admin, thread)
            analyst.commit()
            thread.join(timeout=20)
            assert not thread.is_alive() and not errors, errors
            counts = results[0]
            assert counts.cases == 0 and counts.alerts == 0
            assert admin.execute(
                "SELECT status, conclusion_reason FROM cases WHERE case_id = %s", (case_id,)
            ).fetchone() == ("concluded_fp", "a person concluded")
            assert admin.execute(
                "SELECT status FROM alerts WHERE alert_id = %s", (head,)
            ).fetchone() == ("closed_fp",)
        finally:
            analyst.close()
            admin.close()
