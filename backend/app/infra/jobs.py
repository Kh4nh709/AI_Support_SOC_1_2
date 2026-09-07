"""Claim and finish jobs with FOR UPDATE SKIP LOCKED; retry backoff [10, 60, 300].

The single queue (§6.5): `enqueue` is single-flight through the partial unique
index `ux_jobs_mot_job_song_moi_subject` (job_type, subject_id) WHERE status IN
('pending','running') — not through a Python-side check. `claim_job` and
`finish_job` are plain statements on whatever transaction the caller already
has open; neither commits for you (see the acceptance scripts and
`infra/worker.py`, which does).

This module writes one audit row itself (`job.exhausted`) via a direct INSERT
rather than calling `app.audit.events.write_event`: G1 (context pack §2, §4)
lets `infra` import nothing from the rest of `backend/app`, `audit` included.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence
from typing import Literal

import psycopg
from psycopg import sql

from app.infra import config
from app.infra.errors import PermanentError

# §6.5 — the six v3 job types. A frozen contract, not a Config knob: mirrors
# `ck_jobs_job_type` exactly.
JOB_TYPES = frozenset({"pipeline", "triage", "investigate", "digest", "health", "pull"})


@dataclasses.dataclass(frozen=True)
class Job:
    job_id: int
    job_type: str
    subject_id: str
    attempts: int


@dataclasses.dataclass(frozen=True)
class Reschedule:
    """A handler returns this to ask for a follow-up run of the same
    (job_type, subject_id) after `delay_s` seconds — see `infra/worker.py`."""

    delay_s: float


def enqueue(
    conn: psycopg.Connection,
    job_type: str,
    subject_id: str,
    *,
    scheduled_at: sql.Composable | None = None,
) -> int | None:
    """Insert a `pending` job, or do nothing if one is already live.

    `job_type` is validated against `JOB_TYPES` in Python first — before `conn`
    is touched at all — so a bad value is a clear `PermanentError` naming it,
    rather than `ck_jobs_job_type`'s generic constraint-violation message.

    `scheduled_at`, when given, is a raw SQL expression (e.g. built with
    `psycopg.sql.SQL`/`sql.Literal`) evaluated by the database, never a Python
    value: control timestamps come from the database's own clock (§9 "Time"),
    and the one caller that needs a delay (`infra/worker.py`'s `Reschedule`
    handling) computes it as `now() + <n> * interval '1 second'` in SQL. `None`
    means "now", via the column's own `DEFAULT now()`.
    """
    if job_type not in JOB_TYPES:
        raise PermanentError(
            f"job_type: must be one of {'|'.join(sorted(JOB_TYPES))}, got {job_type!r}"
        )
    scheduled_expr = sql.SQL("now()") if scheduled_at is None else scheduled_at
    query = sql.SQL("""
        INSERT INTO jobs (job_type, subject_id, scheduled_at)
        VALUES (%s, %s, {scheduled_expr})
        ON CONFLICT (job_type, subject_id) WHERE status IN ('pending', 'running') DO NOTHING
        RETURNING job_id
        """).format(scheduled_expr=scheduled_expr)
    row = conn.execute(query, (job_type, subject_id)).fetchone()
    return row[0] if row else None


def claim_job(conn: psycopg.Connection, job_types: Sequence[str]) -> Job | None:
    """Claim the oldest due `pending` job whose type is in `job_types`, or None.

    Two statements in one (the caller's already-open) transaction — a `SELECT
    ... FOR UPDATE SKIP LOCKED` so concurrent workers never block on each
    other or double-claim, then the `UPDATE` that marks it running. The
    `job_type = ANY(%s)` filter is load-bearing: a worker given only
    `["pull", "pipeline"]` must leave `triage` rows untouched for P3's handler.
    """
    row = conn.execute(
        """
        SELECT job_id, job_type, subject_id
        FROM jobs
        WHERE status = 'pending' AND scheduled_at <= now() AND job_type = ANY(%s)
        ORDER BY scheduled_at
        FOR UPDATE SKIP LOCKED
        LIMIT 1
        """,
        (list(job_types),),
    ).fetchone()
    if row is None:
        return None
    job_id, job_type, subject_id = row
    updated = conn.execute(
        """
        UPDATE jobs SET status = 'running', locked_at = now(), attempts = attempts + 1
        WHERE job_id = %s
        RETURNING attempts
        """,
        (job_id,),
    ).fetchone()
    return Job(job_id=job_id, job_type=job_type, subject_id=subject_id, attempts=updated[0])


def finish_job(
    conn: psycopg.Connection,
    job: Job,
    *,
    outcome: Literal["succeeded", "transient", "permanent"],
    error: str | None = None,
) -> None:
    """Resolve a claimed job. `JOB_MAX_ATTEMPTS`/`JOB_BACKOFF` are read fresh
    from `Config` on every call (not module constants) so an environment
    override such as `JOB_MAX_ATTEMPTS=1` takes effect immediately — the
    acceptance failing case for this card.

    `succeeded` sets `status='succeeded'`. `permanent` sets `status='failed'`
    with `last_error`, no retry. `transient` backs off with
    `JOB_BACKOFF[attempts-1]` seconds (computed by the database, never by
    Python) unless `attempts >= JOB_MAX_ATTEMPTS`, in which case it fails and
    writes a `job.exhausted` audit row directly (see module docstring).
    """
    if outcome == "succeeded":
        conn.execute("UPDATE jobs SET status = 'succeeded' WHERE job_id = %s", (job.job_id,))
        return

    if outcome == "permanent":
        conn.execute(
            "UPDATE jobs SET status = 'failed', last_error = %s WHERE job_id = %s",
            (error, job.job_id),
        )
        return

    cfg = config.load()
    if job.attempts >= cfg.JOB_MAX_ATTEMPTS:
        conn.execute(
            "UPDATE jobs SET status = 'failed', last_error = %s WHERE job_id = %s",
            (error, job.job_id),
        )
        conn.execute(
            "INSERT INTO audit_events (event_type, subject_id, actor_role) VALUES (%s, %s, %s)",
            ("job.exhausted", job.subject_id, "system"),
        )
        return

    backoff_s = cfg.JOB_BACKOFF[job.attempts - 1]
    conn.execute(
        """
        UPDATE jobs
        SET status = 'pending',
            scheduled_at = now() + (%s * interval '1 second'),
            last_error = %s
        WHERE job_id = %s
        """,
        (backoff_s, error, job.job_id),
    )


def reclaim_stale(conn: psycopg.Connection) -> int:
    """Return stale `running` jobs (worker died mid-job) to `pending`; return
    the count reclaimed. Staleness threshold is `Config.JOB_LOCK_TIMEOUT_S`."""
    cfg = config.load()
    cur = conn.execute(
        """
        UPDATE jobs
        SET status = 'pending', locked_at = NULL
        WHERE status = 'running' AND locked_at < now() - (%s * interval '1 second')
        """,
        (cfg.JOB_LOCK_TIMEOUT_S,),
    )
    return cur.rowcount
