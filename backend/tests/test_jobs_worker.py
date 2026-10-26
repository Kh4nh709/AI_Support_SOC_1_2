"""Tests for app.infra.jobs (the queue) and app.infra.worker (the loop).

Concurrency and retry claims are proven against a real PostgreSQL server
rather than asserted from the SQL text: SKIP LOCKED is exercised with two
live connections (test_claim_job_skip_locked...), and the backoff/exhaustion
schedule is read back from the database's own clock, not computed in Python.

Commit discipline: most tests never call `db.commit()` at all and rely on the
`db` fixture's rollback at teardown — the `jobs`/`audit_events` tables are
shared with the rest of the session's test run (other files' tests do
unfiltered `count(*)` reads), so nothing here may leak a committed row.
A commit is used only where it is load-bearing (cross-connection visibility
for the SKIP LOCKED test, or `run_forever`'s own internal commits, which
happen regardless of what the test itself does) — and every such test cleans
up what it committed before returning.
"""

from __future__ import annotations

import dataclasses
import inspect
import time

import psycopg
import pytest
from app.infra import jobs, worker
from app.infra.errors import PermanentError

# ---------------------------------------------------------------------------
# enqueue
# ---------------------------------------------------------------------------


def test_enqueue_rejects_unknown_job_type_before_touching_the_connection():
    """job_type is validated in Python too (design note 3) — no connection needed
    to prove it: passing None as `conn` would blow up immediately if validation
    happened after trying to use it."""
    with pytest.raises(PermanentError, match="bogus"):
        jobs.enqueue(None, "bogus", "x")  # type: ignore[arg-type]


@pytest.mark.db
def test_enqueue_is_single_flight_through_the_partial_unique_index(db):
    id1 = jobs.enqueue(db, "pipeline", "enq-1")
    id2 = jobs.enqueue(db, "pipeline", "enq-1")
    id3 = jobs.enqueue(db, "pipeline", "enq-2")
    assert id1 is not None
    assert id2 is None
    assert id3 is not None
    assert id3 != id1
    pending = db.execute(
        "SELECT count(*) FROM jobs WHERE status = 'pending' AND subject_id IN ('enq-1', 'enq-2')"
    ).fetchone()[0]
    assert pending == 2


@pytest.mark.db
def test_a_plain_insert_bypassing_on_conflict_hits_the_unique_violation(db):
    """The failing case behind enqueue's single-flight guarantee (acceptance 2):
    replacing ON CONFLICT ... DO NOTHING with a plain INSERT must raise this."""
    jobs.enqueue(db, "pull", "enq-collision-1")
    with pytest.raises(psycopg.errors.UniqueViolation) as exc_info:
        db.execute("INSERT INTO jobs (job_type, subject_id) VALUES ('pull', 'enq-collision-1')")
    assert exc_info.value.diag.constraint_name == "ux_jobs_mot_job_song_moi_subject"
    db.rollback()


# ---------------------------------------------------------------------------
# claim_job
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_claim_job_only_returns_the_requested_job_types(db):
    jobs.enqueue(db, "pipeline", "claim-1")
    jobs.enqueue(db, "pipeline", "claim-2")
    jobs.enqueue(db, "triage", "claim-3")

    j1 = jobs.claim_job(db, ["pull", "pipeline"])
    j2 = jobs.claim_job(db, ["pull", "pipeline"])
    j3 = jobs.claim_job(db, ["pull", "pipeline"])

    assert {j1.subject_id, j2.subject_id} == {"claim-1", "claim-2"}
    assert j3 is None
    triage_status = db.execute("SELECT status FROM jobs WHERE subject_id = 'claim-3'").fetchone()[0]
    assert triage_status == "pending"


@pytest.mark.db
def test_claim_job_skips_jobs_scheduled_in_the_future(db):
    db.execute(
        "INSERT INTO jobs (job_type, subject_id, scheduled_at) "
        "VALUES ('pipeline', 'claim-future-1', now() + interval '1 hour')"
    )
    assert jobs.claim_job(db, ["pipeline"]) is None


@pytest.mark.db
def test_claim_job_marks_running_and_increments_attempts(db):
    jobs.enqueue(db, "pipeline", "claim-attempts-1")
    job = jobs.claim_job(db, ["pipeline"])
    assert job.attempts == 1
    status, locked_at = db.execute(
        "SELECT status, locked_at FROM jobs WHERE job_id = %s", (job.job_id,)
    ).fetchone()
    assert status == "running"
    assert locked_at is not None


@pytest.mark.db
def test_claim_job_skip_locked_lets_a_second_session_claim_a_different_row(db, _test_database):
    # A second, independent connection needs these rows to be committed to see
    # them at all (read-committed isolation) — genuinely load-bearing, unlike
    # most commits in this file, so this test cleans up after itself.
    jobs.enqueue(db, "pipeline", "conc-1")
    jobs.enqueue(db, "pipeline", "conc-2")
    db.commit()
    other = psycopg.connect(_test_database)
    try:
        job_a = jobs.claim_job(db, ["pipeline"])
        job_b = jobs.claim_job(other, ["pipeline"])
        assert job_a is not None
        assert job_b is not None
        assert job_a.subject_id != job_b.subject_id
        db.commit()
        other.commit()
    finally:
        other.execute("DELETE FROM jobs WHERE subject_id IN ('conc-1', 'conc-2')")
        other.commit()
        other.close()


# ---------------------------------------------------------------------------
# finish_job — backoff, exhaustion, permanent, succeeded
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_finish_job_transient_backs_off_then_exhausts_on_the_third_attempt(db):
    jobs.enqueue(db, "pipeline", "backoff-1")
    seen = []
    for _ in range(3):
        db.execute("UPDATE jobs SET scheduled_at = now() WHERE subject_id = 'backoff-1'")
        job = jobs.claim_job(db, ["pipeline"])
        jobs.finish_job(db, job, outcome="transient", error="boom")
        row = db.execute(
            "SELECT attempts, status, round(extract(epoch from scheduled_at - now())) "
            "FROM jobs WHERE subject_id = 'backoff-1'"
        ).fetchone()
        seen.append(row)

    assert seen[0][0:2] == (1, "pending")
    assert abs(seen[0][2] - 10) <= 3
    assert seen[1][0:2] == (2, "pending")
    assert abs(seen[1][2] - 60) <= 3
    assert seen[2][0:2] == (3, "failed")

    exhausted = db.execute(
        "SELECT event_type, subject_id FROM audit_events "
        "WHERE event_type = 'job.exhausted' AND subject_id = 'backoff-1'"
    ).fetchall()
    assert exhausted == [("job.exhausted", "backoff-1")]


@pytest.mark.db
def test_finish_job_respects_job_max_attempts_env_override(db, monkeypatch):
    """The failing case named by acceptance 4: JOB_MAX_ATTEMPTS=1 exhausts on
    the very first failure instead of backing off."""
    monkeypatch.setenv("JOB_MAX_ATTEMPTS", "1")
    jobs.enqueue(db, "pipeline", "maxattempts-1")
    job = jobs.claim_job(db, ["pipeline"])
    jobs.finish_job(db, job, outcome="transient", error="boom")
    status = db.execute("SELECT status FROM jobs WHERE subject_id = 'maxattempts-1'").fetchone()[0]
    assert status == "failed"
    exhausted = db.execute(
        "SELECT 1 FROM audit_events WHERE event_type = 'job.exhausted' "
        "AND subject_id = 'maxattempts-1'"
    ).fetchone()
    assert exhausted is not None


@pytest.mark.db
def test_finish_job_permanent_fails_immediately_without_retry(db):
    jobs.enqueue(db, "pipeline", "perm-1")
    job = jobs.claim_job(db, ["pipeline"])
    jobs.finish_job(db, job, outcome="permanent", error="bad payload")
    row = db.execute(
        "SELECT status, attempts, last_error FROM jobs WHERE subject_id = 'perm-1'"
    ).fetchone()
    assert row == ("failed", 1, "bad payload")


@pytest.mark.db
def test_finish_job_succeeded_sets_status(db):
    jobs.enqueue(db, "pipeline", "ok-1")
    job = jobs.claim_job(db, ["pipeline"])
    jobs.finish_job(db, job, outcome="succeeded")
    status = db.execute("SELECT status FROM jobs WHERE subject_id = 'ok-1'").fetchone()[0]
    assert status == "succeeded"


# ---------------------------------------------------------------------------
# reclaim_stale
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_reclaim_stale_reclaims_old_locks_but_not_recent_ones(db):
    # Committed (not just left open) to prove the reclaim survives across
    # transactions the way a worker that died mid-job actually would.
    db.execute(
        "INSERT INTO jobs (job_type, subject_id, status, locked_at, attempts) "
        "VALUES ('pipeline', 'stale-1', 'running', now() - interval '301 seconds', 1)"
    )
    db.execute(
        "INSERT INTO jobs (job_type, subject_id, status, locked_at, attempts) "
        "VALUES ('pipeline', 'fresh-1', 'running', now() - interval '10 seconds', 1)"
    )
    db.commit()

    n = jobs.reclaim_stale(db, ["pipeline"])
    db.commit()

    assert n == 1
    stale_row = db.execute(
        "SELECT status, locked_at FROM jobs WHERE subject_id = 'stale-1'"
    ).fetchone()
    assert stale_row == ("pending", None)
    fresh_status = db.execute("SELECT status FROM jobs WHERE subject_id = 'fresh-1'").fetchone()[0]
    assert fresh_status == "running"

    # `stale-1` is now a genuinely claimable pending `pipeline` job — clean up
    # so it cannot leak into a later test in this session.
    db.execute("DELETE FROM jobs WHERE subject_id IN ('stale-1', 'fresh-1')")
    db.commit()


def test_reclaim_stale_requires_the_job_types():
    """DEC-210: a worker reclaims only what it can run. The parameter has no default, so a caller
    that forgets it is a `TypeError`, never a worker that quietly reclaims every type."""
    parameter = inspect.signature(jobs.reclaim_stale).parameters["job_types"]
    assert parameter.default is inspect.Parameter.empty
    with pytest.raises(TypeError):
        jobs.reclaim_stale(None)  # type: ignore[call-arg]


@pytest.mark.db
def test_reclaim_stale_takes_only_its_types(db):
    """The `rag-worker` shares the `jobs` table with the main worker. Its reclaim must leave a
    stale `triage` row alone: that job may still be running, inside its own long transaction, and
    a second worker taking it would run ① twice (spec §6, "Lock timing")."""
    db.execute(
        "INSERT INTO jobs (job_type, subject_id, status, locked_at, attempts) "
        "VALUES ('triage', 'typed-stale-1', 'running', now() - interval '301 seconds', 1)"
    )
    db.commit()

    other = jobs.reclaim_stale(db, ["rag_lookup"])
    db.commit()
    untouched = db.execute(
        "SELECT status, locked_at IS NOT NULL FROM jobs WHERE subject_id = 'typed-stale-1'"
    ).fetchone()

    own = jobs.reclaim_stale(db, ["triage"])
    db.commit()
    reclaimed = db.execute(
        "SELECT status, locked_at FROM jobs WHERE subject_id = 'typed-stale-1'"
    ).fetchone()

    db.execute("DELETE FROM jobs WHERE subject_id = 'typed-stale-1'")
    db.commit()

    assert (other, untouched) == (0, ("running", True))
    assert (own, reclaimed) == (1, ("pending", None))


@pytest.mark.db
def test_reclaim_stale_with_several_types_takes_each_and_only_those(db):
    for job_type, subject in (
        ("rag_lookup", "typed-many-1"),
        ("knowledge_draft", "typed-many-2"),
        ("triage", "typed-many-3"),
    ):
        db.execute(
            "INSERT INTO jobs (job_type, subject_id, status, locked_at, attempts) "
            "VALUES (%s, %s, 'running', now() - interval '301 seconds', 1)",
            (job_type, subject),
        )
    db.commit()

    n = jobs.reclaim_stale(db, ["rag_lookup", "knowledge_draft"])
    db.commit()
    statuses = dict(
        db.execute(
            "SELECT subject_id, status FROM jobs WHERE subject_id LIKE 'typed-many-%'"
        ).fetchall()
    )

    db.execute("DELETE FROM jobs WHERE subject_id LIKE 'typed-many-%'")
    db.commit()

    assert n == 2
    assert statuses == {
        "typed-many-1": "pending",
        "typed-many-2": "pending",
        "typed-many-3": "running",
    }


@pytest.mark.db
def test_reclaim_stale_with_no_types_reclaims_nothing(db):
    db.execute(
        "INSERT INTO jobs (job_type, subject_id, status, locked_at, attempts) "
        "VALUES ('pipeline', 'typed-none-1', 'running', now() - interval '301 seconds', 1)"
    )
    db.commit()

    n = jobs.reclaim_stale(db, [])
    db.commit()
    status = db.execute("SELECT status FROM jobs WHERE subject_id = 'typed-none-1'").fetchone()[0]

    db.execute("DELETE FROM jobs WHERE subject_id = 'typed-none-1'")
    db.commit()

    assert (n, status) == (0, "running")


# ---------------------------------------------------------------------------
# The two P13 job types
# ---------------------------------------------------------------------------


def test_job_types_hold_the_two_rag_types_next_to_the_six():
    assert {"rag_lookup", "knowledge_draft"} <= jobs.JOB_TYPES
    assert {"pipeline", "triage", "investigate", "digest", "health", "pull"} <= jobs.JOB_TYPES
    assert len(jobs.JOB_TYPES) == 8


@pytest.mark.db
@pytest.mark.parametrize("job_type", ["rag_lookup", "knowledge_draft"])
def test_enqueue_admits_each_rag_type_and_is_single_flight_per_subject(db, job_type):
    first = jobs.enqueue(db, job_type, "alert:gl-x")
    again = jobs.enqueue(db, job_type, "alert:gl-x")
    other_type = "knowledge_draft" if job_type == "rag_lookup" else "rag_lookup"
    sibling = jobs.enqueue(db, other_type, "alert:gl-x")
    assert first is not None and again is None
    assert sibling is not None  # single-flight is per (job_type, subject)


# ---------------------------------------------------------------------------
# Job / Reschedule dataclasses
# ---------------------------------------------------------------------------


def test_job_is_a_frozen_dataclass_with_the_four_named_fields():
    job = jobs.Job(job_id=1, job_type="pipeline", subject_id="x", attempts=2)
    assert (job.job_id, job.job_type, job.subject_id, job.attempts) == (1, "pipeline", "x", 2)
    with pytest.raises(dataclasses.FrozenInstanceError):
        job.attempts = 3  # type: ignore[misc]


def test_reschedule_is_a_frozen_dataclass():
    r = jobs.Reschedule(5)
    assert r.delay_s == 5
    with pytest.raises(dataclasses.FrozenInstanceError):
        r.delay_s = 10  # type: ignore[misc]


# ---------------------------------------------------------------------------
# run_forever
#
# Every test below hands `run_forever` the live `db` connection via
# `lambda: db`. `run_forever` commits internally as part of its own correct
# behaviour (reclaim_stale, claim_job, and the success/exception paths all
# commit) — regardless of what the test body itself does — so every test that
# calls it commits a real row and must clean it up explicitly; relying on the
# `db` fixture's rollback would not be enough.
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_run_forever_once_with_no_jobs_returns_immediately_without_sleeping(db):
    # This test's premise is an empty pipeline queue; guarantee it locally
    # rather than assume no earlier test in this session left one claimable.
    db.execute("DELETE FROM jobs WHERE job_type = 'pipeline' AND status = 'pending'")
    db.commit()
    called = {"n": 0}

    def handler(conn, job):
        called["n"] += 1

    start = time.monotonic()
    worker.run_forever(lambda: db, {"pipeline": handler}, once=True, sleep_s=5)
    elapsed = time.monotonic() - start

    assert called["n"] == 0
    assert elapsed < 2


@pytest.mark.db
def test_run_forever_once_claims_dispatches_and_succeeds_one_job(db):
    jobs.enqueue(db, "pipeline", "wf-ok-1")
    seen = []

    def handler(conn, job):
        seen.append(job.subject_id)

    worker.run_forever(lambda: db, {"pipeline": handler}, once=True)

    assert seen == ["wf-ok-1"]
    status = db.execute("SELECT status FROM jobs WHERE subject_id = 'wf-ok-1'").fetchone()[0]
    assert status == "succeeded"

    db.execute("DELETE FROM jobs WHERE subject_id = 'wf-ok-1'")
    db.commit()


@pytest.mark.db
def test_run_forever_leaves_other_job_types_alone(db):
    """The loop must not claim a job type outside its handler table (design
    note 3: a P2 worker must leave `triage` rows untouched for P3)."""
    jobs.enqueue(db, "triage", "wf-other-1")

    def handler(conn, job):
        raise AssertionError("must not be called for a job type it wasn't given")

    worker.run_forever(lambda: db, {"pipeline": handler}, once=True)

    status = db.execute("SELECT status FROM jobs WHERE subject_id = 'wf-other-1'").fetchone()[0]
    assert status == "pending"

    db.execute("DELETE FROM jobs WHERE subject_id = 'wf-other-1'")
    db.commit()


@pytest.mark.db
def test_run_forever_permanent_exception_fails_job_without_raising(db):
    jobs.enqueue(db, "pipeline", "wf-perm-1")

    def boom(conn, job):
        raise ValueError("bad data")

    worker.run_forever(lambda: db, {"pipeline": boom}, once=True)  # must not raise

    row = db.execute("SELECT status, attempts FROM jobs WHERE subject_id = 'wf-perm-1'").fetchone()
    assert row == ("failed", 1)

    db.execute("DELETE FROM jobs WHERE subject_id = 'wf-perm-1'")
    db.commit()


@pytest.mark.db
def test_run_forever_transient_exception_reschedules_the_job(db):
    jobs.enqueue(db, "pipeline", "wf-trans-1")

    def boom(conn, job):
        raise psycopg.OperationalError("connection reset")

    worker.run_forever(lambda: db, {"pipeline": boom}, once=True)  # must not raise

    row = db.execute("SELECT status, attempts FROM jobs WHERE subject_id = 'wf-trans-1'").fetchone()
    assert row == ("pending", 1)

    # Committed by finish_job; it would become claimable again in ~10s otherwise.
    db.execute("DELETE FROM jobs WHERE subject_id = 'wf-trans-1'")
    db.commit()


@pytest.mark.db
def test_run_forever_reschedule_enqueues_only_after_finish_job_commits(db):
    jobs.enqueue(db, "pull", "wf-reschedule-1")

    def handler(conn, job):
        return jobs.Reschedule(5)

    worker.run_forever(lambda: db, {"pull": handler}, once=True)

    rows = db.execute(
        "SELECT status, round(extract(epoch from scheduled_at - now())) FROM jobs "
        "WHERE job_type = 'pull' AND subject_id = 'wf-reschedule-1' ORDER BY status"
    ).fetchall()
    statuses = {r[0] for r in rows}
    assert statuses == {"succeeded", "pending"}
    pending_delay = next(r[1] for r in rows if r[0] == "pending")
    assert abs(pending_delay - 5) <= 3

    # Committed by finish_job/enqueue; the rearmed row would become claimable
    # again in ~5s otherwise.
    db.execute("DELETE FROM jobs WHERE subject_id = 'wf-reschedule-1'")
    db.commit()


@pytest.mark.db
def test_a_knowledge_draft_rescheduled_to_next_month_is_a_pending_row_nobody_can_claim_yet(db):
    """P13 fix wave, item 20 (I1): what `Reschedule` does to a `knowledge_draft` job. The old row is
    `succeeded`, a new `pending` row for the same subject is due `delay_s` seconds after the database's
    `now()` (31 days here), `claim_job` leaves it alone until then, and it is no job backlog."""
    from app.infra import health

    jobs.enqueue(db, "knowledge_draft", "alert:wf-month-1")
    month = 31 * 24 * 3600

    def handler(conn, job):
        return jobs.Reschedule(month)

    worker.run_forever(lambda: db, {"knowledge_draft": handler}, once=True)
    try:
        rows = db.execute(
            "SELECT status, round(extract(epoch from scheduled_at - now())) FROM jobs"
            " WHERE job_type = 'knowledge_draft' AND subject_id = 'alert:wf-month-1'"
            " ORDER BY status"
        ).fetchall()
        assert [r[0] for r in rows] == ["pending", "succeeded"]
        assert abs(rows[0][1] - month) <= 5
        assert jobs.claim_job(db, ["knowledge_draft"]) is None
        assert health._check_job_backlog(db).ok is True
    finally:
        db.execute("DELETE FROM jobs WHERE subject_id = 'alert:wf-month-1'")
        db.commit()


@pytest.mark.db
def test_claim_order_tries_each_group_in_turn_and_the_default_stays_the_oldest_first(db):
    """P13 fix wave, item 21: `claim_order` is a list of job-type groups; the first group with a due job
    wins, whatever the age of the other groups' jobs. Without it, `claim_job`'s oldest-first order over all
    the handlers' types is exactly what it was (the main worker passes none)."""
    ran: list[str] = []

    def handler(conn, job):
        ran.append(job.job_type)

    handlers = {"rag_lookup": handler, "knowledge_draft": handler}
    subjects = ("wf-order-draft", "wf-order-lookup")
    try:
        for order in (None, [["rag_lookup"], ["knowledge_draft"]]):
            ran.clear()
            db.execute("DELETE FROM jobs WHERE subject_id = ANY(%s)", (list(subjects),))
            db.execute(
                "INSERT INTO jobs (job_type, subject_id, scheduled_at)"
                " VALUES ('knowledge_draft', 'wf-order-draft', now() - interval '10 minutes'),"
                " ('rag_lookup', 'wf-order-lookup', now() - interval '1 minute')"
            )
            db.commit()
            kwargs = {} if order is None else {"claim_order": order}
            worker.run_forever(lambda: db, handlers, once=True, **kwargs)
            worker.run_forever(lambda: db, handlers, once=True, **kwargs)
            assert ran == (
                ["knowledge_draft", "rag_lookup"]
                if order is None
                else ["rag_lookup", "knowledge_draft"]
            )
    finally:
        db.execute("DELETE FROM jobs WHERE subject_id = ANY(%s)", (list(subjects),))
        db.commit()


@pytest.mark.db
def test_a_group_with_no_due_job_falls_through_to_the_next(db):
    ran: list[str] = []
    try:
        jobs.enqueue(db, "knowledge_draft", "wf-order-only-draft")
        worker.run_forever(
            lambda: db,
            {
                "rag_lookup": lambda c, j: ran.append("lookup"),
                "knowledge_draft": lambda c, j: ran.append("draft"),
            },
            once=True,
            claim_order=[["rag_lookup"], ["knowledge_draft"]],
        )
        assert ran == ["draft"]
    finally:
        db.execute("DELETE FROM jobs WHERE subject_id = 'wf-order-only-draft'")
        db.commit()


def test_claim_order_must_name_exactly_the_handlers_types():
    handlers = {"rag_lookup": lambda c, j: None, "knowledge_draft": lambda c, j: None}
    for order in ([["rag_lookup"]], [["rag_lookup"], ["knowledge_draft", "pull"]], [[]]):
        with pytest.raises(ValueError, match="claim_order"):
            worker.run_forever(lambda: None, handlers, once=True, claim_order=order)


@pytest.mark.db
def test_run_forever_uses_a_longer_timeout_when_given_one_for_the_job_type(db):
    """Design note 4's per-job-type timeout, option B (a second mapping)."""
    jobs.enqueue(db, "investigate", "wf-timeout-1")
    seen_timeout = {}

    def handler(conn, job):
        seen_timeout["value"] = conn.execute("SHOW statement_timeout").fetchone()[0]

    worker.run_forever(
        lambda: db,
        {"investigate": handler},
        once=True,
        timeouts={"investigate": "5s"},
    )

    assert seen_timeout["value"] == "5s"

    db.execute("DELETE FROM jobs WHERE subject_id = 'wf-timeout-1'")
    db.commit()


@pytest.mark.db
def test_run_forever_reclaims_only_its_handlers(db):
    """`run_forever` hands `reclaim_stale` its own handler keys. A `rag_lookup` worker meets a
    stale `triage` row and a stale `rag_lookup` row: the second is reclaimed (and, being due, run),
    the first is not reclaimed at all."""
    for job_type, subject in (("triage", "wf-reclaim-triage"), ("rag_lookup", "wf-reclaim-rag")):
        db.execute(
            "INSERT INTO jobs (job_type, subject_id, status, locked_at, attempts) "
            "VALUES (%s, %s, 'running', now() - interval '301 seconds', 1)",
            (job_type, subject),
        )
    db.commit()
    seen = []

    def handler(conn, job):
        seen.append((job.job_type, job.subject_id, job.attempts))

    worker.run_forever(lambda: db, {"rag_lookup": handler}, once=True)

    rows = {
        row[0]: row[1:]
        for row in db.execute(
            "SELECT subject_id, status, locked_at IS NOT NULL FROM jobs "
            "WHERE subject_id IN ('wf-reclaim-triage', 'wf-reclaim-rag')"
        ).fetchall()
    }
    db.execute("DELETE FROM jobs WHERE subject_id IN ('wf-reclaim-triage', 'wf-reclaim-rag')")
    db.commit()

    assert seen == [("rag_lookup", "wf-reclaim-rag", 2)]
    assert rows["wf-reclaim-rag"][0] == "succeeded"
    assert rows["wf-reclaim-triage"] == ("running", True)
