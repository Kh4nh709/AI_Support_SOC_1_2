"""The single worker loop claiming and running pull, pipeline, triage, investigate, health jobs.

This module names no handler and imports no tier (G1, planning decision 1):
`run_forever` takes a `handlers` mapping it is given and does not own. A real
handler table is assembled elsewhere, by a composition root allowed to import
everything (`web/worker.py`, P2-T10) — `python3 -m app.infra.worker` no longer
runs a worker on its own; `make run-worker`'s target changes with that task.

Per-job-type statement timeouts (design note 4 lets either a `(handler, timeout)`
tuple table or a second mapping carry them): this module keeps `handlers` a
plain `Mapping[str, Handler]` — exactly what `web/worker.py` builds
(`{"pull": ..., "pipeline": ...}`, plain callables) — and adds an optional
second mapping, `timeouts`, for the job types that need longer than the 3s
default (P5's `conclude`, for `investigate`, asks for 5s).
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping

import psycopg
from psycopg import sql

from app.infra.db import transaction
from app.infra.errors import classify
from app.infra.jobs import Job, Reschedule, claim_job, enqueue, finish_job, reclaim_stale

Handler = Callable[[psycopg.Connection, Job], "Reschedule | None"]

DEFAULT_STATEMENT_TIMEOUT = "3s"


def run_forever(
    conn_factory: Callable[[], psycopg.Connection],
    handlers: Mapping[str, Handler],
    *,
    once: bool = False,
    sleep_s: float = 1.0,
    timeouts: Mapping[str, str] | None = None,
) -> None:
    """Claim-dispatch-finish, forever (or once).

    Per iteration: `reclaim_stale`, committed on its own; `claim_job` restricted
    to `handlers`' keys, committed on its own; if a job was claimed, run its
    handler inside `transaction(conn, statement_timeout=...)` and finish it —
    on success inside that same transaction (so the handler's writes and the
    `succeeded` status land in one commit), on exception after a rollback, in a
    fresh one. A handler's exception never escapes this function: it is
    classified transient/permanent and the job is finished accordingly — a bad
    job must not kill the worker. `once=True` runs exactly one such cycle
    (claim included) and returns, whether or not a job was found; this
    function never closes `conn` — the caller who built it via `conn_factory`
    owns its lifetime.
    """
    timeouts = timeouts or {}
    conn = conn_factory()
    while True:
        reclaim_stale(conn)
        conn.commit()

        job = claim_job(conn, list(handlers.keys()))
        conn.commit()

        if job is None:
            if once:
                return
            time.sleep(sleep_s)
            continue

        _run_claimed_job(conn, job, handlers, timeouts)

        if once:
            return


def _run_claimed_job(
    conn: psycopg.Connection,
    job: Job,
    handlers: Mapping[str, Handler],
    timeouts: Mapping[str, str],
) -> None:
    handler = handlers[job.job_type]
    statement_timeout = timeouts.get(job.job_type, DEFAULT_STATEMENT_TIMEOUT)
    start = time.monotonic()

    try:
        with transaction(conn, statement_timeout=statement_timeout):
            result = handler(conn, job)
            finish_job(conn, job, outcome="succeeded")
    except Exception as exc:  # noqa: BLE001 — deliberately broad: any handler
        # exception, of any type, must be classified and finished, never left
        # to kill the worker (design note 4: "never re-raise out of the loop").
        outcome = classify(exc)
        finish_job(conn, job, outcome=outcome, error=str(exc)[:1000])
        conn.commit()
        _log(job, outcome, start)
        return

    _log(job, "succeeded", start)
    if isinstance(result, Reschedule):
        # Only now, after "succeeded" has committed, does a new `pending` row
        # for the same (job_type, subject_id) stop colliding with
        # ux_jobs_mot_job_song_moi_subject.
        enqueue(
            conn,
            job.job_type,
            job.subject_id,
            scheduled_at=sql.SQL("now() + {} * interval '1 second'").format(
                sql.Literal(result.delay_s)
            ),
        )
        conn.commit()


def _log(job: Job, outcome: str, start: float) -> None:
    elapsed_ms = int((time.monotonic() - start) * 1000)
    print(
        json.dumps(
            {"job_id": job.job_id, "job_type": job.job_type, "outcome": outcome, "ms": elapsed_ms}
        )
    )
