"""`health`'s handler, re-exported for `web/handlers/__init__.py`'s discovery
(P5-tasks.md planning decision 1). The tier code is `app.infra.health.check`;
this module wraps it in the job contract and keeps it self-perpetuating every
`_HEALTH_INTERVAL_S` (§6.5 "every 5 min"), the same `Reschedule` shape
`infra/puller.pull_job` uses for `pull`.

No `STATEMENT_TIMEOUT` here (P5-tasks.md §5: *"investigate declares '5s' and
nothing else does"*) — `health`'s ten checks stay under the worker's 3 s
default.

Review round 1, B1: `check()` calls `infra.notify.send` inside this job's own
transaction (`infra/worker.py`'s `_run_claimed_job` wraps every handler call
in `infra.db.transaction`, which sets `idle_in_transaction_session_timeout =
'10s'`). `notify.send`'s own client timeout is at most 10 s per phase plus
DNS, so a slow Telegram response can leave the connection sitting idle for
longer than that 10 s ceiling while `httpx` blocks — Postgres then kills the
session, and the next statement on it raises `psycopg.OperationalError`,
which escaped `_run_claimed_job` and took the worker down (the Reviewer's
probe). `_raise_idle_timeout` is this handler's first statement, exactly
`tier1/triage.py`'s `_raise_idle_timeout` — a second `SET LOCAL`, to
`JOB_LOCK_TIMEOUT_S` (300 s by default, the same bound `reclaim_stale`
uses), overrides the wrapper's 10 s before `notify.send` ever runs.
"""

from __future__ import annotations

import psycopg
from psycopg import sql

from app.infra import config, health
from app.infra.config import Config
from app.infra.jobs import Job, Reschedule

JOB_TYPE = "health"

_HEALTH_INTERVAL_S = 300  # §6.5 "every 5 min"


def _raise_idle_timeout(conn: psycopg.Connection, cfg: Config) -> None:
    """B1 — mirrors `tier1/triage.py:_raise_idle_timeout` exactly: `SET` takes
    no bind parameter, hence `sql.Literal`, not `%s`."""
    conn.execute(
        sql.SQL("SET LOCAL idle_in_transaction_session_timeout = {}").format(
            sql.Literal(f"{cfg.JOB_LOCK_TIMEOUT_S}s")
        )
    )


def handle(conn: psycopg.Connection, job: Job, *, cfg: Config | None = None) -> Reschedule:
    del job  # `health`'s subject_id is the constant "system" (P5-tasks.md §5); no per-job data
    cfg = cfg or config.load()
    _raise_idle_timeout(conn, cfg)
    health.check(conn, cfg)
    return Reschedule(_HEALTH_INTERVAL_S)
