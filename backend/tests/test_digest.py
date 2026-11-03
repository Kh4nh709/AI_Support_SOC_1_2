"""Tests for `app.tier1.digest` (P5-T08, including review round 1's B1-B3,
S4, S5 and N6/N8/N9 fixes). Design note 6: measured 23/09, `soc_dev` has zero
`auto_closed` alerts and zero `autoclose_rules` — every test here builds its
own auto-closed cluster directly with SQL, bypassing
`domain.transitions.open_alert(kind="auto_closed")` the way `test_transitions.py`
and `test_queue.py` do, so none of it depends on live content.

`llm_runs` rows are inserted directly in P3-T10's shape (`test_queue.py`'s
own convention), since `llm_runs` carries no `db.py`-level helper of its own.

Round 1 · S4: the digest's day bounds are in the display zone
(`Asia/Ho_Chi_Minh`, UTC+7, no DST), not UTC — `_TZ` is passed explicitly to
`build`/`unreviewed_count`/`ensure_scheduled` wherever a test cares about the
exact boundary, and relied on as `cfg.DISPLAY_TZ`'s default everywhere else
(no `DISPLAY_TZ` env var is set in this process, so the two are the same
value).
"""

from __future__ import annotations

import csv
import hashlib
import io
import itertools
import json
import uuid
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import psycopg
import pytest
from app.audit.events import EVENT_TYPES
from app.domain.transitions import StaleState
from app.infra.jobs import Job, enqueue
from app.tier1.digest import (
    AlreadyReviewed,
    build,
    ensure_scheduled,
    review,
    run_digest_job,
    to_csv,
    unreviewed_count,
)
from psycopg import sql
from psycopg.types.json import Jsonb

pytestmark = pytest.mark.db

assert "rule.suspected_wrong" in EVENT_TYPES  # sanity: no new event type needed
assert "autoclose.reviewed" in EVENT_TYPES
assert "label.created" in EVENT_TYPES

_TZ = "Asia/Ho_Chi_Minh"  # UTC+7, no DST — cfg.DISPLAY_TZ's default (round 1 S4)
_DAY = "2026-09-29"
# Local day 2026-09-29 (ICT) spans [2026-09-28 17:00 UTC, 2026-09-29 17:00 UTC).
_IN_DAY = datetime(2026, 9, 29, 10, 0, tzinfo=UTC)  # 17:00 ICT on the 29th
_BEFORE_DAY = datetime(2026, 9, 28, 16, 59, 59, tzinfo=UTC)  # 23:59:59 ICT on the 28th
_AT_BOUNDARY = datetime(2026, 9, 29, 17, 0, 0, tzinfo=UTC)  # local midnight of the 30th

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
    sealed_at: datetime | None = None,
    autoclose_rule_id: str | None = None,
    occurrence_count: int = 1,
    agent_name: str = "host-1",
    severity: str = "high",
    category: str = "brute_force",
    description: str = "SSH brute force",
    alert_id: str | None = None,
    is_synthetic: bool = False,
) -> str:
    """A direct INSERT bypassing `open_alert`, matching `test_transitions.py`
    and `test_queue.py`'s own convention for setting up an arbitrary starting
    status. `sealed_at` is required by `ck_alerts_h2_dong_boi_nguoi_phai_seal`
    for the human-closed statuses (`closed_fp`/`closed_benign`/`closed_confirmed`)
    — S5's control rows pass it explicitly."""
    alert_id = alert_id or f"digest-{next(_counter)}"
    conn.execute(
        """
        INSERT INTO alerts (
            alert_id, rule_id, rule_level, severity, description, agent_name,
            alert_time, category, resolved_by, mapping_version,
            event_bucket_hash, raw_payload, status, occurrence_count,
            closed_at, sealed_at, autoclose_rule_id, close_reason, is_synthetic
        ) VALUES (
            %s, '40112', 10, %s, %s, %s,
            now(), %s, 'rule_groups', 'v1',
            %s, %s, %s, %s,
            %s, %s, %s, %s, %s
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
            sealed_at,
            autoclose_rule_id,
            "matched scanner" if closed_at is not None else None,
            is_synthetic,
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


def _events(conn: psycopg.Connection, event_type: str, subject_id: str):
    return conn.execute(
        "SELECT actor_role, actor_id, payload FROM audit_events "
        "WHERE event_type = %s AND subject_id = %s ORDER BY audit_id",
        (event_type, subject_id),
    ).fetchall()


def _pending_jobs(conn: psycopg.Connection, job_type: str = "digest"):
    return conn.execute(
        "SELECT subject_id, status, scheduled_at FROM jobs WHERE job_type = %s ORDER BY job_id",
        (job_type,),
    ).fetchall()


def _next_run_date_local(conn: psycopg.Connection, tz: str = _TZ) -> str:
    """Round 1 · A1: mirrors `digest._next_run_expr`'s date half (today's,
    if the real `now()` is before 08:00 local; otherwise tomorrow's), so a
    test using production's real clock can predict what `ensure_scheduled`
    will pick without hard-coding "tomorrow" and without duplicating the
    boundary logic in a way that could silently drift from it."""
    return conn.execute(
        """
        SELECT (CASE WHEN (now() AT TIME ZONE %(tz)s)::time < time '08:00'
                     THEN (now() AT TIME ZONE %(tz)s)::date
                     ELSE (now() AT TIME ZONE %(tz)s)::date + 1
                END)::text
        """,
        {"tz": tz},
    ).fetchone()[0]


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
    # S5: closed_at INSIDE the window but status != 'auto_closed' — closed_at
    # alone can't exercise the status filter (a NULL closed_at is already
    # excluded by the day-range condition on its own), so this control row
    # is what actually proves `a.status = 'auto_closed'` is doing something.
    _insert_alert(
        db, status="closed_fp", closed_at=_IN_DAY, sealed_at=_IN_DAY, autoclose_rule_id=rule
    )

    rows = build(db, _DAY)

    assert [r.alert_id for r in rows] == [in_window]


def test_build_excludes_synthetic_alerts(db):
    """Round 1 · N8, matching `queue.py`'s `list_queue` and
    `ingest/autoclose.simulate`."""
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    real = _insert_alert(db, autoclose_rule_id=rule)
    _insert_run(db, real)
    _insert_alert(db, autoclose_rule_id=rule, is_synthetic=True)

    rows = build(db, _DAY)

    assert [r.alert_id for r in rows] == [real]


def test_build_uses_display_tz_not_utc_at_the_day_boundary(db):
    """Round 1 · S4. Asia/Ho_Chi_Minh is UTC+7, no DST: 23:30 local on
    2026-09-29 == 16:30 UTC belongs to the 2026-09-29 local day; 00:30 local
    on 2026-09-30 == 17:30 UTC (still 2026-09-29 by the clock on the wall in
    UTC) belongs to the 2026-09-30 local day."""
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    late_on_d_minus_1 = _insert_alert(
        db, autoclose_rule_id=rule, closed_at=datetime(2026, 9, 29, 16, 30, tzinfo=UTC)
    )
    early_on_d = _insert_alert(
        db, autoclose_rule_id=rule, closed_at=datetime(2026, 9, 29, 17, 30, tzinfo=UTC)
    )

    d_minus_1_rows = build(db, "2026-09-29", tz=_TZ)
    d_rows = build(db, "2026-09-30", tz=_TZ)

    assert [r.alert_id for r in d_minus_1_rows] == [late_on_d_minus_1]
    assert [r.alert_id for r in d_rows] == [early_on_d]


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


def test_a_true_positive_run_is_listed_as_true_positive_and_is_a_disagreement(db):
    """P14-T03 (DEC-213): ①'s verdict is `true_positive` (it was `escalate`). The digest reviews
    auto-closed clusters against it: the rule closed the cluster, the model would have raised it,
    so it sorts first, is flagged, and the CSV carries the word as ① wrote it."""
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    agree = _insert_alert(db, autoclose_rule_id=rule, occurrence_count=10)
    _insert_run(db, agree, suggested_action="false_positive")
    raised = _insert_alert(db, autoclose_rule_id=rule, occurrence_count=1)
    _insert_run(db, raised, suggested_action="true_positive")

    rows = build(db, _DAY)

    assert [r.alert_id for r in rows] == [raised, agree]
    assert rows[0].suggested_action == "true_positive" and rows[0].disagreement is True
    assert rows[1].suggested_action == "false_positive" and rows[1].disagreement is False
    csv_rows = list(csv.DictReader(io.StringIO(to_csv(rows))))
    assert [(r["suggested_action"], r["disagreement"]) for r in csv_rows] == [
        ("true_positive", "true"),
        ("false_positive", "false"),
    ]


def test_a_verdict_the_gate_held_is_still_a_disagreement_with_the_rule(db):
    """The model said `false_positive` and gate step 4 held it as `needs_review` (the reader sees the
    gated verdict, `result.suggested_action`, never `gate_result.proposed_verdict`): the system did not
    close it, so the digest still asks a person whether the rule was right to."""
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    alert_id = _insert_alert(db, autoclose_rule_id=rule)
    _insert_run(db, alert_id, suggested_action="needs_review")

    (row,) = build(db, _DAY)

    assert row.suggested_action == "needs_review" and row.disagreement is True


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


def test_unreviewed_count_only_counts_auto_closed(db):
    """Round 1 · S5, the same case as build()'s but for unreviewed_count."""
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    _insert_alert(db, autoclose_rule_id=rule)  # auto_closed, unreviewed
    _insert_alert(
        db, status="closed_fp", closed_at=_IN_DAY, sealed_at=_IN_DAY, autoclose_rule_id=rule
    )

    assert unreviewed_count(db, _DAY) == 1


def test_unreviewed_count_excludes_synthetic_alerts(db):
    """Round 1 · N8."""
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    _insert_alert(db, autoclose_rule_id=rule)
    _insert_alert(db, autoclose_rule_id=rule, is_synthetic=True)

    assert unreviewed_count(db, _DAY) == 1


# ---------------------------------------------------------------------------
# review() — the three plain-path verdicts
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


# ---------------------------------------------------------------------------
# review() — round 1 · B1/B3: the status guard and the savepoint
# ---------------------------------------------------------------------------


def test_review_wrong_on_a_non_auto_closed_alert_is_stale_state(db):
    user = _make_user(db)
    alert_id = _insert_alert(db, status="queued_tier1", closed_at=None)

    with pytest.raises(StaleState), db.transaction():
        review(db, alert_id, "wrong", user)

    assert _reviews(db, alert_id) == []  # whole transaction rolled back


def test_correct_on_a_never_auto_closed_alert_is_stale_state(db):
    """B1: before round 1, `correct`/`unsure` had no status guard at all."""
    user = _make_user(db)
    alert_id = _insert_alert(db, status="queued_tier1", closed_at=None)

    with pytest.raises(StaleState):
        review(db, alert_id, "correct", user)

    assert _reviews(db, alert_id) == []
    assert _labels(db, alert_id) == []


def test_unsure_on_a_never_auto_closed_alert_is_stale_state(db):
    user = _make_user(db)
    alert_id = _insert_alert(db, status="queued_tier1", closed_at=None)

    with pytest.raises(StaleState):
        review(db, alert_id, "unsure", user)

    assert _reviews(db, alert_id) == []


def test_stale_state_does_not_abort_the_callers_transaction(db):
    """B3: `review()`'s own internal savepoint absorbs the failure — no
    outer `db.transaction()` needed by the caller, unlike a bare failed
    statement, which would poison the connection's transaction until a full
    ROLLBACK. Proven by simply continuing to use `db` afterward."""
    user = _make_user(db)
    alert_id = _insert_alert(db, status="queued_tier1", closed_at=None)

    with pytest.raises(StaleState):
        review(db, alert_id, "correct", user)

    # No rollback here: if review() had not wrapped its body in a savepoint,
    # this query would itself fail with "current transaction is aborted".
    assert _reviews(db, alert_id) == []


def test_correct_then_wrong_from_another_reviewer_is_already_reviewed(db):
    user1 = _make_user(db)
    user2 = _make_user(db)
    rule = _make_autoclose_rule(db, user1)
    alert_id = _insert_alert(db, autoclose_rule_id=rule)

    review(db, alert_id, "correct", user1)
    with pytest.raises(AlreadyReviewed):
        review(db, alert_id, "wrong", user2)

    assert [r[1] for r in _reviews(db, alert_id)] == ["correct"]
    assert len(_labels(db, alert_id)) == 1
    assert _fetch_alert(db, alert_id, "status")[0] == "auto_closed"  # not reopened


def test_correct_then_unsure_from_another_reviewer_is_already_reviewed(db):
    user1 = _make_user(db)
    user2 = _make_user(db)
    rule = _make_autoclose_rule(db, user1)
    alert_id = _insert_alert(db, autoclose_rule_id=rule)

    review(db, alert_id, "correct", user1)
    with pytest.raises(AlreadyReviewed):
        review(db, alert_id, "unsure", user2)

    assert [r[1] for r in _reviews(db, alert_id)] == ["correct"]


def test_wrong_then_correct_from_a_stale_page_is_stale_state(db):
    """Once `wrong` reopens the alert, a second reviewer's page is stale —
    the status guard (not the conflict guard) is what catches it."""
    user1 = _make_user(db)
    user2 = _make_user(db)
    rule = _make_autoclose_rule(db, user1)
    alert_id = _insert_alert(db, autoclose_rule_id=rule)

    review(db, alert_id, "wrong", user1)
    with pytest.raises(StaleState):
        review(db, alert_id, "correct", user2)

    assert [r[1] for r in _reviews(db, alert_id)] == ["wrong"]  # intact
    assert _labels(db, alert_id) == []


def test_two_correct_reviews_from_different_people_write_one_review_and_one_label(db):
    user1 = _make_user(db)
    user2 = _make_user(db)
    rule = _make_autoclose_rule(db, user1)
    alert_id = _insert_alert(db, autoclose_rule_id=rule)

    review(db, alert_id, "correct", user1)
    with pytest.raises(AlreadyReviewed):
        review(db, alert_id, "correct", user2)

    assert len(_reviews(db, alert_id)) == 1
    assert len(_labels(db, alert_id)) == 1


# ---------------------------------------------------------------------------
# review() — round 1 · B2: the audit events every verdict writes
# ---------------------------------------------------------------------------


def test_review_writes_autoclose_reviewed_event_for_every_verdict(db):
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    alert_id = _insert_alert(db, autoclose_rule_id=rule)
    _insert_run(db, alert_id, suggested_action="needs_review")

    review(db, alert_id, "wrong", user)

    events = _events(db, "autoclose.reviewed", alert_id)
    assert len(events) == 1
    actor_role, actor_id, payload = events[0]
    assert actor_role == "admin"
    assert str(actor_id) == user
    assert payload["verdict"] == "wrong"
    assert payload["autoclose_rule_id"] == rule
    assert payload["suggested_action"] == "needs_review"
    assert payload["run_id"] is not None


def test_review_correct_writes_autoclose_reviewed_and_label_created_events(db):
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    alert_id = _insert_alert(db, autoclose_rule_id=rule)

    review(db, alert_id, "correct", user)

    reviewed = _events(db, "autoclose.reviewed", alert_id)
    assert len(reviewed) == 1
    assert reviewed[0][2]["verdict"] == "correct"  # payload

    events = _events(db, "label.created", alert_id)
    assert len(events) == 1
    actor_role, actor_id, payload = events[0]
    assert actor_role == "admin"
    assert str(actor_id) == user
    assert payload["alert_id"] == alert_id
    assert payload["label"] == "false_positive"
    assert payload["source"] == "digest"


def test_review_unsure_writes_autoclose_reviewed_event_and_no_label_created(db):
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    alert_id = _insert_alert(db, autoclose_rule_id=rule)

    review(db, alert_id, "unsure", user)

    reviewed = _events(db, "autoclose.reviewed", alert_id)
    assert len(reviewed) == 1
    assert reviewed[0][2]["verdict"] == "unsure"
    assert _events(db, "label.created", alert_id) == []


def test_review_wrong_writes_no_label_created_event(db):
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    alert_id = _insert_alert(db, autoclose_rule_id=rule)

    review(db, alert_id, "wrong", user)

    assert _events(db, "label.created", alert_id) == []


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


def test_correct_plus_wrong_on_same_rule_does_not_fire_suspected_wrong(db):
    """Round 1 · N6: only `wrong` verdicts count toward the threshold."""
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    correct_alert = _insert_alert(db, autoclose_rule_id=rule)
    wrong_alert = _insert_alert(db, autoclose_rule_id=rule)

    review(db, correct_alert, "correct", user)
    review(db, wrong_alert, "wrong", user)

    assert _audit_count(db, rule) == 0


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
    id1 = ensure_scheduled(db, tz=_TZ)
    id2 = ensure_scheduled(db, tz=_TZ)

    assert id1 is not None
    assert id2 is None
    assert len(_pending_jobs(db)) == 1


def test_ensure_scheduled_arms_the_next_0800_local(db):
    """Round 1 · S4/A1: 08:00 in `cfg.DISPLAY_TZ`, not UTC — converted back
    explicitly with `zoneinfo` rather than assumed, since the `timestamptz`
    psycopg hands back may carry any tzinfo. Uses the real clock (no `as_of`
    override), so it predicts against `_next_run_date_local` rather than
    hard-coding "tomorrow" — A1 means that is only sometimes the answer."""
    ensure_scheduled(db, tz=_TZ)

    expected_date = _next_run_date_local(db)
    subject_id, status, scheduled_at = _pending_jobs(db)[0]
    assert subject_id == expected_date
    assert status == "pending"
    local = scheduled_at.astimezone(ZoneInfo(_TZ))
    assert local.date().isoformat() == expected_date
    assert local.time().isoformat() == "08:00:00"
    # And the report's own "local and UTC" pair: UTC+7, so 08:00 ICT is
    # 01:00 UTC the same calendar day.
    assert scheduled_at.astimezone(UTC).time().isoformat() == "01:00:00"


def test_ensure_scheduled_arms_today_when_before_0800_local(db):
    """Round 1 · A1: a worker restart before 08:00 local must not skip that
    day's digest. `as_of` is the private testing seam — every real caller
    leaves it unset and gets the database's actual `now()`."""
    as_of = sql.Literal(datetime(2026, 9, 29, 6, 30, tzinfo=ZoneInfo(_TZ)))

    ensure_scheduled(db, tz=_TZ, as_of=as_of)

    subject_id, status, scheduled_at = _pending_jobs(db)[0]
    assert subject_id == "2026-09-29"
    assert status == "pending"
    local = scheduled_at.astimezone(ZoneInfo(_TZ))
    assert (local.date().isoformat(), local.time().isoformat()) == ("2026-09-29", "08:00:00")


def test_ensure_scheduled_arms_tomorrow_when_at_or_after_0800_local(db):
    """Round 1 · A1's other side — also the red-step-discriminating pair for
    the "before 08:00" test above (DEC-025: an implementation that always
    arms tomorrow keeps this one green while the "before" test goes red)."""
    as_of = sql.Literal(datetime(2026, 9, 29, 8, 0, tzinfo=ZoneInfo(_TZ)))

    ensure_scheduled(db, tz=_TZ, as_of=as_of)

    subject_id, status, scheduled_at = _pending_jobs(db)[0]
    assert subject_id == "2026-09-30"
    assert status == "pending"
    local = scheduled_at.astimezone(ZoneInfo(_TZ))
    assert (local.date().isoformat(), local.time().isoformat()) == ("2026-09-30", "08:00:00")


def test_run_digest_job_leaves_exactly_one_pending_job_for_the_next_local_run(db):
    today_local = db.execute(
        "SELECT (now() AT TIME ZONE %(tz)s)::date::text", {"tz": _TZ}
    ).fetchone()[0]
    job = Job(job_id=1, job_type="digest", subject_id=today_local, attempts=1)
    expected_date = _next_run_date_local(db)

    run_digest_job(db, job)

    rows = _pending_jobs(db)
    assert len(rows) == 1
    assert rows[0][0] == expected_date
    assert rows[0][1] == "pending"


def test_run_digest_job_builds_the_previous_local_day(db, capsys):
    """Round 1 · S4: the job that fires on local day D reviews D-1."""
    user = _make_user(db)
    rule = _make_autoclose_rule(db, user)
    _insert_alert(db, autoclose_rule_id=rule, closed_at=datetime(2026, 9, 28, 10, 0, tzinfo=UTC))
    job = Job(job_id=1, job_type="digest", subject_id="2026-09-29", attempts=1)

    run_digest_job(db, job)

    summary = json.loads(capsys.readouterr().out.strip())
    assert summary == {"day": "2026-09-28", "clusters": 1}


def test_run_digest_job_is_idempotent_on_the_rearm(db):
    """A retry of the same job (or a second worker cycle) must not duplicate
    tomorrow's row."""
    today_local = db.execute(
        "SELECT (now() AT TIME ZONE %(tz)s)::date::text", {"tz": _TZ}
    ).fetchone()[0]
    job = Job(job_id=1, job_type="digest", subject_id=today_local, attempts=1)

    run_digest_job(db, job)
    run_digest_job(db, job)

    assert len(_pending_jobs(db)) == 1


def test_run_digest_job_does_not_crash_on_an_empty_day(db):
    """No alerts at all for the day — `build()` returns []; the job still
    runs and re-arms."""
    job = Job(job_id=1, job_type="digest", subject_id="2020-01-01", attempts=1)

    run_digest_job(db, job)  # must not raise

    assert len(_pending_jobs(db)) == 1
