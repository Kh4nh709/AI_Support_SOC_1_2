"""Tests for `app.tier1.digest` (P5-T08). Design note 6: measured 23/09,
`soc_dev` has zero `auto_closed` alerts and zero `autoclose_rules` — every
test here builds its own auto-closed cluster directly with SQL, bypassing
`domain.transitions.open_alert(kind="auto_closed")` the way `test_transitions.py`
and `test_queue.py` do, so none of it depends on live content.

`llm_runs` rows are inserted directly in P3-T10's shape (`test_queue.py`'s
own convention), since `llm_runs` carries no `db.py`-level helper of its own.
"""

from __future__ import annotations

import csv
import hashlib
import io
import itertools
import json
import uuid
from datetime import UTC, datetime

import psycopg
import pytest
from app.audit.events import EVENT_TYPES
from app.domain.transitions import StaleState
from app.infra.jobs import Job, enqueue
from app.tier1.digest import (
    build,
    ensure_scheduled,
    review,
    run_digest_job,
    to_csv,
    unreviewed_count,
)
from psycopg.types.json import Jsonb

pytestmark = pytest.mark.db

assert "rule.suspected_wrong" in EVENT_TYPES  # sanity: no new event type needed

_DAY = "2026-09-29"
_IN_DAY = datetime(2026, 9, 29, 10, 0, tzinfo=UTC)
_BEFORE_DAY = datetime(2026, 9, 28, 23, 59, 59, tzinfo=UTC)
_AT_BOUNDARY = datetime(2026, 9, 30, 0, 0, 0, tzinfo=UTC)  # exclusive upper bound

_counter = itertools.count()


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _make_user(conn: psycopg.Connection) -> str:
    user_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash) "
        "VALUES (%s, %s, 'Test Analyst', 'tier1', 'x')",
        (user_id, f"user-{user_id[:8]}"),
    )
    return user_id


def _make_autoclose_rule(
    conn: psycopg.Connection, user_id: str, *, name: str = "known-scanner"
) -> str:
    rule_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO autoclose_rules (autoclose_rule_id, name, match, reason, created_by) "
        "VALUES (%s, %s, %s, %s, %s)",
        (rule_id, name, Jsonb({}), "matched scanner", user_id),
    )
    return rule_id


def _insert_alert(
    conn: psycopg.Connection,
    *,
    status: str = "auto_closed",
    closed_at: datetime | None = _IN_DAY,
    autoclose_rule_id: str | None = None,
    occurrence_count: int = 1,
    agent_name: str = "host-1",
    severity: str = "high",
    category: str = "brute_force",
    description: str = "SSH brute force",
    alert_id: str | None = None,
) -> str:
    """A direct INSERT bypassing `open_alert`, matching `test_transitions.py`
    and `test_queue.py`'s own convention for setting up an arbitrary starting
    status."""
    alert_id = alert_id or f"digest-{next(_counter)}"
    conn.execute(
        """
        INSERT INTO alerts (
            alert_id, rule_id, rule_level, severity, description, agent_name,
            alert_time, category, resolved_by, mapping_version,
            event_bucket_hash, raw_payload, status, occurrence_count,
            closed_at, autoclose_rule_id, close_reason
        ) VALUES (
            %s, '40112', 10, %s, %s, %s,
            now(), %s, 'rule_groups', 'v1',
            %s, %s, %s, %s,
            %s, %s, %s
        )
        """,
        (
            alert_id,
            severity,
            description,
            agent_name,
            category,
            _hash(alert_id),
            Jsonb({}),
            status,
            occurrence_count,
            closed_at,
            autoclose_rule_id,
            "matched scanner" if closed_at is not None else None,
        ),
    )
    return alert_id


def _insert_run(
    conn: psycopg.Connection,
    alert_id: str,
    *,
    suggested_action: str | None = "false_positive",
    role: str = "proposer",
) -> str:
    """One `llm_runs` row in P3-T10's shape (`test_queue.py`'s own
    convention)."""
    result = {"suggested_action": suggested_action, "confidence": "high", "reasons": []}
    row = conn.execute(
        """
        INSERT INTO llm_runs (
            run_id, pipeline, subject_type, subject_id, system_prompt,
            user_message, result, role, gate_result
        ) VALUES (
            gen_random_uuid(), 'triage', 'alert', %s, 's', 'u', %s::jsonb, %s, %s::jsonb
        ) RETURNING run_id
        """,
        (alert_id, json.dumps(result), role, json.dumps({})),
    ).fetchone()
    return str(row[0])


def _fetch_alert(conn: psycopg.Connection, alert_id: str, *cols: str):
    row = conn.execute(
        f"SELECT {', '.join(cols)} FROM alerts WHERE alert_id = %s", (alert_id,)
    ).fetchone()
    return tuple(str(v) if isinstance(v, uuid.UUID) else v for v in row)


def _reviews(conn: psycopg.Connection, alert_id: str):
    return conn.execute(
        "SELECT reviewer_id, verdict FROM autoclose_reviews WHERE alert_id = %s", (alert_id,)
    ).fetchall()


def _labels(conn: psycopg.Connection, alert_id: str):
    return conn.execute(
        "SELECT labeler_id, source, label FROM triage_labels WHERE alert_id = %s", (alert_id,)
    ).fetchall()


def _pending_jobs(conn: psycopg.Connection, job_type: str = "digest"):
    return conn.execute(
        "SELECT subject_id, status, scheduled_at FROM jobs WHERE job_type = %s ORDER BY job_id",
        (job_type,),
    ).fetchall()


# ---------------------------------------------------------------------------
# build()
# ---------------------------------------------------------------------------


def test_build_picks_up_only_the_24h_window_and_only_auto_closed(db):
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    in_window = _insert_alert(db, closed_at=_IN_DAY, autoclose_rule_id=rule)
    _insert_run(db, in_window)
    before_window = _insert_alert(db, closed_at=_BEFORE_DAY, autoclose_rule_id=rule)
    _insert_run(db, before_window)
    at_boundary = _insert_alert(db, closed_at=_AT_BOUNDARY, autoclose_rule_id=rule)
    _insert_run(db, at_boundary)
    _insert_alert(db, status="queued_tier1", closed_at=None)  # not auto_closed — excluded

    rows = build(db, _DAY)

    assert [r.alert_id for r in rows] == [in_window]


def test_build_membership_both_agreeing_and_disagreeing_clusters(db):
    """The red-step (a) pair for `test_disagreements_sort_first`: removing the
    disagreement sort key must not break this one (DEC-025)."""
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    agree = _insert_alert(db, autoclose_rule_id=rule, occurrence_count=10)
    _insert_run(db, agree, suggested_action="false_positive")
    disagree = _insert_alert(db, autoclose_rule_id=rule, occurrence_count=1)
    _insert_run(db, disagree, suggested_action="needs_review")

    rows = build(db, _DAY)

    assert {r.alert_id for r in rows} == {agree, disagree}


def test_disagreements_sort_first(db):
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    # Higher occurrence_count, but agrees — must still sort AFTER the
    # disagreement, proving the disagreement key dominates occurrence_count.
    agree = _insert_alert(db, autoclose_rule_id=rule, occurrence_count=10)
    _insert_run(db, agree, suggested_action="false_positive")
    disagree = _insert_alert(db, autoclose_rule_id=rule, occurrence_count=1)
    _insert_run(db, disagree, suggested_action="needs_review")

    rows = build(db, _DAY)

    assert [r.alert_id for r in rows] == [disagree, agree]
    assert rows[0].disagreement is True
    assert rows[1].disagreement is False


def test_build_ties_break_on_occurrence_count_then_alert_id(db):
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    low = _insert_alert(db, autoclose_rule_id=rule, occurrence_count=1, alert_id="digest-z")
    _insert_run(db, low, suggested_action="false_positive")
    high = _insert_alert(db, autoclose_rule_id=rule, occurrence_count=5, alert_id="digest-a")
    _insert_run(db, high, suggested_action="false_positive")

    rows = build(db, _DAY)

    assert [r.alert_id for r in rows] == [high, low]


def test_build_verdict_with_no_llm_run_is_not_a_disagreement(db):
    """D8 enqueues `triage` on every auto-close, but it may not have run yet
    by digest time — no verdict is not evidence of disagreement."""
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    _insert_alert(db, autoclose_rule_id=rule)

    rows = build(db, _DAY)

    assert len(rows) == 1
    assert rows[0].suggested_action is None
    assert rows[0].disagreement is False


def test_build_carries_the_rule_name_and_autoclose_rule_id(db):
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user, name="scanner-a")
    alert_id = _insert_alert(db, autoclose_rule_id=rule)
    _insert_run(db, alert_id)

    rows = build(db, _DAY)

    assert rows[0].autoclose_rule_id == rule
    assert rows[0].autoclose_rule_name == "scanner-a"


def test_build_includes_already_reviewed_alerts_with_their_verdict(db):
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    alert_id = _insert_alert(db, autoclose_rule_id=rule)
    _insert_run(db, alert_id)
    review(db, alert_id, "correct", user)

    rows = build(db, _DAY)

    assert len(rows) == 1
    assert rows[0].reviewed_verdict == "correct"


# ---------------------------------------------------------------------------
# unreviewed_count()
# ---------------------------------------------------------------------------


def test_unreviewed_count_excludes_reviewed_alerts(db):
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    reviewed = _insert_alert(db, autoclose_rule_id=rule)
    _insert_run(db, reviewed)
    review(db, reviewed, "unsure", user)
    _insert_alert(db, autoclose_rule_id=rule)  # unreviewed

    assert unreviewed_count(db, _DAY) == 1


# ---------------------------------------------------------------------------
# review() — (a) the review row, (b) the label, (c) the reopen
# ---------------------------------------------------------------------------


def test_review_correct_writes_review_and_false_positive_label(db):
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    alert_id = _insert_alert(db, autoclose_rule_id=rule)

    review(db, alert_id, "correct", user)

    assert [r[1] for r in _reviews(db, alert_id)] == ["correct"]
    labels = _labels(db, alert_id)
    assert len(labels) == 1
    assert labels[0][1] == "digest"
    assert labels[0][2] == "false_positive"
    # correct does not reopen
    assert _fetch_alert(db, alert_id, "status")[0] == "auto_closed"


def test_wrong_reopens_and_keeps_autoclose_rule_id(db):
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    alert_id = _insert_alert(db, autoclose_rule_id=rule, closed_at=_IN_DAY)

    review(db, alert_id, "wrong", user)

    status, closed_at, autoclose_rule_id = _fetch_alert(
        db, alert_id, "status", "closed_at", "autoclose_rule_id"
    )
    assert status == "queued_tier1"
    assert closed_at is None
    assert autoclose_rule_id == rule  # kept — architecture §3.4
    assert [r[1] for r in _reviews(db, alert_id)] == ["wrong"]


def test_review_wrong_writes_no_label(db):
    """Guards P7's gold set: `wrong` says only that auto-closing was wrong,
    never what the alert *is* (design note 2(b))."""
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    alert_id = _insert_alert(db, autoclose_rule_id=rule)

    review(db, alert_id, "wrong", user)

    assert _labels(db, alert_id) == []


def test_review_unsure_writes_only_the_review(db):
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    alert_id = _insert_alert(db, autoclose_rule_id=rule)

    review(db, alert_id, "unsure", user)

    assert [r[1] for r in _reviews(db, alert_id)] == ["unsure"]
    assert _labels(db, alert_id) == []
    assert _fetch_alert(db, alert_id, "status")[0] == "auto_closed"


def test_review_wrong_on_a_non_auto_closed_alert_is_stale_state(db):
    user = _make_user(db)
    alert_id = _insert_alert(db, status="queued_tier1", closed_at=None)

    with pytest.raises(StaleState), db.transaction():
        review(db, alert_id, "wrong", user)

    assert _reviews(db, alert_id) == []  # whole transaction rolled back


def test_second_review_of_the_same_alert_upserts_last_reviewer_wins(db):
    user1 = _make_user(db)
    user2 = _make_user(db)
    rule = _make_autoclose_rule(db, user1)
    alert_id = _insert_alert(db, autoclose_rule_id=rule)

    review(db, alert_id, "correct", user1)
    review(db, alert_id, "unsure", user2)

    rows = _reviews(db, alert_id)
    assert len(rows) == 1
    assert rows[0] == (uuid.UUID(user2), "unsure")


# ---------------------------------------------------------------------------
# rule.suspected_wrong
# ---------------------------------------------------------------------------


def _audit_count(conn: psycopg.Connection, rule_id: str) -> int:
    return conn.execute(
        "SELECT count(*) FROM audit_events WHERE event_type = 'rule.suspected_wrong' "
        "AND subject_id = %s",
        (rule_id,),
    ).fetchone()[0]


def test_rule_suspected_wrong_fires_once_per_window(db):
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    first = _insert_alert(db, autoclose_rule_id=rule)
    second = _insert_alert(db, autoclose_rule_id=rule)

    review(db, first, "wrong", user)
    assert _audit_count(db, rule) == 0  # one `wrong` alone does not fire

    review(db, second, "wrong", user)
    assert _audit_count(db, rule) == 1  # the second, within 7 days, fires


def test_rule_suspected_wrong_does_not_refire_on_a_third_wrong(db):
    """The red-step (b) test: drop the existing-event check in
    `_flag_rule_if_suspected_wrong` and this goes red (DEC-025)."""
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    first = _insert_alert(db, autoclose_rule_id=rule)
    second = _insert_alert(db, autoclose_rule_id=rule)
    third = _insert_alert(db, autoclose_rule_id=rule)

    review(db, first, "wrong", user)
    review(db, second, "wrong", user)
    assert _audit_count(db, rule) == 1

    review(db, third, "wrong", user)
    assert _audit_count(db, rule) == 1  # unchanged


def test_rule_suspected_wrong_is_per_rule(db):
    user = _make_user(db)
    rule_a = _make_autoclose_rule(db, user, name="rule-a")
    rule_b = _make_autoclose_rule(db, user, name="rule-b")
    a1 = _insert_alert(db, autoclose_rule_id=rule_a)
    a2 = _insert_alert(db, autoclose_rule_id=rule_a)
    b1 = _insert_alert(db, autoclose_rule_id=rule_b)

    review(db, a1, "wrong", user)
    review(db, a2, "wrong", user)
    review(db, b1, "wrong", user)

    assert _audit_count(db, rule_a) == 1
    assert _audit_count(db, rule_b) == 0


# ---------------------------------------------------------------------------
# to_csv()
# ---------------------------------------------------------------------------


def test_to_csv_byte_stable_across_two_builds(db):
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    agree = _insert_alert(db, autoclose_rule_id=rule, occurrence_count=3)
    _insert_run(db, agree, suggested_action="false_positive")
    disagree = _insert_alert(db, autoclose_rule_id=rule, occurrence_count=1)
    _insert_run(db, disagree, suggested_action="needs_review")

    csv_1 = to_csv(build(db, _DAY))
    csv_2 = to_csv(build(db, _DAY))

    assert csv_1 == csv_2
    assert csv_1  # not empty


def test_to_csv_changes_when_the_database_does(db):
    """Design note 5's failing case: one more auto-closed cluster and the
    digests differ, which proves the check is live."""
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    alert_id = _insert_alert(db, autoclose_rule_id=rule)
    _insert_run(db, alert_id)

    before = to_csv(build(db, _DAY))
    _insert_alert(db, autoclose_rule_id=rule)  # no llm_runs row needed

    after = to_csv(build(db, _DAY))

    assert before != after


def test_to_csv_header_and_line_endings(db):
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    alert_id = _insert_alert(db, autoclose_rule_id=rule, occurrence_count=2)
    _insert_run(db, alert_id, suggested_action="needs_review")

    text = to_csv(build(db, _DAY))

    assert "\r\n" not in text
    lines = text.split("\n")
    header = next(csv.reader(io.StringIO(lines[0])))
    assert header[0] == "alert_id"
    assert "disagreement" in header
    row = next(csv.reader(io.StringIO(lines[1])))
    assert row[header.index("alert_id")] == alert_id
    assert row[header.index("disagreement")] == "true"


# ---------------------------------------------------------------------------
# ensure_scheduled() / run_digest_job() — the self-chaining job
# ---------------------------------------------------------------------------


def test_enqueue_the_same_day_twice_is_one_jobs_row(db):
    id1 = enqueue(db, "digest", _DAY)
    id2 = enqueue(db, "digest", _DAY)

    assert id1 is not None
    assert id2 is None
    rows = db.execute(
        "SELECT count(*) FROM jobs WHERE job_type = 'digest' AND subject_id = %s", (_DAY,)
    ).fetchone()
    assert rows[0] == 1


def test_ensure_scheduled_is_idempotent(db):
    id1 = ensure_scheduled(db)
    id2 = ensure_scheduled(db)

    assert id1 is not None
    assert id2 is None
    assert len(_pending_jobs(db)) == 1


def test_ensure_scheduled_arms_tomorrow_at_0800(db):
    ensure_scheduled(db)

    tomorrow = db.execute("SELECT (now()::date + 1)::text").fetchone()[0]
    subject_id, status, scheduled_at = _pending_jobs(db)[0]
    assert subject_id == tomorrow
    assert status == "pending"
    assert scheduled_at.date().isoformat() == tomorrow
    assert scheduled_at.time().isoformat() == "08:00:00"


def test_run_digest_job_leaves_exactly_one_pending_job_for_tomorrow(db):
    today = db.execute("SELECT now()::date::text").fetchone()[0]
    job = Job(job_id=1, job_type="digest", subject_id=today, attempts=1)

    run_digest_job(db, job)

    rows = _pending_jobs(db)
    assert len(rows) == 1
    tomorrow = db.execute("SELECT (now()::date + 1)::text").fetchone()[0]
    assert rows[0][0] == tomorrow
    assert rows[0][1] == "pending"


def test_run_digest_job_is_idempotent_on_the_rearm(db):
    """A retry of the same job (or a second worker cycle) must not duplicate
    tomorrow's row."""
    today = db.execute("SELECT now()::date::text").fetchone()[0]
    job = Job(job_id=1, job_type="digest", subject_id=today, attempts=1)

    run_digest_job(db, job)
    run_digest_job(db, job)

    assert len(_pending_jobs(db)) == 1


def test_run_digest_job_does_not_crash_on_an_empty_day(db):
    """No alerts at all for the day — `build()` returns []; the job still
    runs and re-arms."""
    job = Job(job_id=1, job_type="digest", subject_id="2020-01-01", attempts=1)

    run_digest_job(db, job)  # must not raise

    assert len(_pending_jobs(db)) == 1
