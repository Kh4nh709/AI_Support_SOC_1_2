"""`web/routers/admin_overview.py` — the admin overview page's two API routes (P11-T05, spec §4.1
and §5.4): `GET /api/admin/overview?range=24h|7d|30d` and `POST /api/admin/jobs/{job_id}/retry`.
Both are `Admin` only; `iter_routers()` discovers this module.

**Each section fails alone.** The overview is ten independent reads. Each runs in its own
savepoint (`conn.transaction()` inside the request's transaction), after its own
`SET LOCAL statement_timeout`. A `psycopg.Error` rolls that savepoint back, so the request's
transaction stays usable: the section answers `null`, `{section, error}` is added to `errors`,
and the next section runs as if nothing had happened. `infra/db.transaction()` is NOT used here:
it issues its own `BEGIN`/`COMMIT`, and inside a request that would commit (or warn about) the
transaction `deps.Conn` owns. The `error` is a short code, `timeout` or `query_failed`: never
the driver's message, which can carry SQL text, and never a DSN.

**The 3 s is per statement, not per section.** `statement_timeout` limits each SQL statement on
its own. Every section is one statement except two: `by_source`, which reads `alerts` and then
`rejected_alerts`, and `llm_month`, which reads `settings` (the cap) and then `llm_runs` (the
month's spend). Each of those two can take up to twice `SECTION_TIMEOUT` before it is cut.

**`llm_month`** (P11-T20 row 50, DEC-203 item 1) is `{spent_usd, cap_usd, pct}` of the calendar
month, the figures of `GET /api/admin/llm/usage`'s `month` from the same code
(`admin_llm.llm_month`): `pct` is floored to one decimal, and `cap_usd` and `pct` are `null` when
the limits cannot be read, which is not an error. Only a failure of the spend query is: the
section is `null` with `{section: "llm_month", error}`, the others untouched. The cost card reads
it instead of a second `llm/usage?range=month` read, which answers 503 as a whole when any one of
its four blocks fails.

`SET LOCAL` inside a savepoint lasts until the end of the request's transaction unless the
savepoint is rolled back, so a section's `3s` is still set while the next one runs: each section
sets its own anyway, and nothing runs after the last one but the commit.

Read rules shared by the alert sections:
- synthetic alerts (`is_synthetic`) are left out, as the queue, the digest and the health
  checks leave them out;
- the window is `received_at >= now() - <range>`, on the database's clock; `waiting` is the one
  alert section the range does not bound (it is what waits for Tier 1 now);
- a head is `duplicate_of IS NULL`.

`failed_jobs` is ordered by the job's last attempt, `COALESCE(locked_at, created_at)` newest
first: `claim_job` stamps `locked_at` on every attempt and `finish_job` keeps it, while a retried
job keeps its old `created_at`, so ordering by creation would push a job that failed again
behind newer-created ones.

**Retry.** `POST /api/admin/jobs/{job_id}/retry` puts one `failed` job back to `pending` with
`attempts=0` and `scheduled_at=now()`, which is exactly what `infra/jobs.claim_job` takes
(`status='pending' AND scheduled_at <= now()`); `last_error` is kept. The job row is locked
`FOR UPDATE` first, and the lock must be exclusive: with `FOR SHARE` two simultaneous retries
both read `failed`, then deadlock on their UPDATEs and one of them is a 500. A live sibling
(same `job_type` and `subject_id`, `pending` or `running`) is a `409 already_queued`, checked
before the UPDATE and again by catching the partial unique index `ux_jobs_mot_job_song_moi_subject`
on a savepoint: `enqueue` can insert that sibling between the check and the UPDATE, and that
race must be a 409, not a 500.

A 404/409 body is `{"detail": {"reason": ...}}` (spec §3: a `detail` that is an object carries a
machine-readable `reason`).
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Annotated, Any, Literal

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from psycopg import sql

from app.audit.events import write_event
from app.infra.auth import Claims
from app.web.deps import Cfg, Conn, require_role
from app.web.routers import admin_llm

router = APIRouter()

require_admin = require_role("admin")
Admin = Annotated[Claims, Depends(require_admin)]

logger = logging.getLogger(__name__)

#: The `SET LOCAL statement_timeout` each section sets: a limit PER STATEMENT, not per section
#: (`by_source` runs two statements). Read when a section runs, so a test can shorten it.
SECTION_TIMEOUT = "3s"

#: `?range=` -> the window. Anything else is a 422 from the `Literal` below.
_WINDOWS: dict[str, timedelta] = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}
RangeName = Literal["24h", "7d", "30d"]

_TOP_AGENTS = 5
_FAILED_JOBS_LIMIT = 50
#: `last_error` is cut to this many characters, in the response and in the audit payload.
_ERROR_CHARS = 200
_BIGINT_MAX = 2**63 - 1
_LIVE_JOB_INDEX = "ux_jobs_mot_job_song_moi_subject"

#: `jobs.job_id` is a bigint: outside 1..2^63-1 is a 422, never a driver error.
JobId = Annotated[int, Path(ge=1, le=_BIGINT_MAX)]


# ---------------------------------------------------------------------------
# The ten sections — each one plain reads on the connection it is given
# ---------------------------------------------------------------------------


def _alerts_by_day(conn: Any, tz: str, window: timedelta) -> list[dict[str, Any]]:
    """Alerts per local day, ascending; a day with none is absent. The zone is a bound
    parameter, never spliced into the SQL."""
    rows = conn.execute(
        """
        SELECT (received_at AT TIME ZONE %(tz)s)::date AS day,
               count(*) AS total,
               count(*) FILTER (WHERE duplicate_of IS NULL) AS heads,
               count(*) FILTER (WHERE duplicate_of IS NOT NULL) AS duplicates
        FROM alerts
        WHERE NOT is_synthetic AND received_at >= now() - %(window)s
        GROUP BY 1
        ORDER BY 1
        """,
        {"tz": tz, "window": window},
    ).fetchall()
    return [
        {"day": day.isoformat(), "total": total, "heads": heads, "duplicates": duplicates}
        for day, total, heads, duplicates in rows
    ]


def _by_source(conn: Any, window: timedelta) -> dict[str, Any]:
    rows = conn.execute(
        """
        SELECT source, count(*), count(*) FILTER (WHERE duplicate_of IS NULL)
        FROM alerts
        WHERE NOT is_synthetic AND received_at >= now() - %s
        GROUP BY source
        ORDER BY 2 DESC, source
        """,
        (window,),
    ).fetchall()
    (rejected,) = conn.execute(
        "SELECT count(*) FROM rejected_alerts WHERE received_at >= now() - %s", (window,)
    ).fetchone()
    return {
        "rows": [
            {"source": source, "alerts": alerts, "heads": heads} for source, alerts, heads in rows
        ],
        "rejected": rejected,
    }


def _top_agents(conn: Any, window: timedelta) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT agent_name, count(*) AS alerts
        FROM alerts
        WHERE NOT is_synthetic AND received_at >= now() - %s
        GROUP BY agent_name
        ORDER BY alerts DESC, agent_name
        LIMIT %s
        """,
        (window, _TOP_AGENTS),
    ).fetchall()
    return [{"agent_name": agent_name, "alerts": alerts} for agent_name, alerts in rows]


def _funnel(conn: Any, window: timedelta) -> dict[str, Any]:
    """Heads only. One statement, grouped by `(status, triage_status)`: the status counts are the
    sums over `triage_status`, the triage counts the sums over `status` (`none` is a NULL one)."""
    rows = conn.execute(
        """
        SELECT status, triage_status, count(*)
        FROM alerts
        WHERE duplicate_of IS NULL AND NOT is_synthetic AND received_at >= now() - %s
        GROUP BY status, triage_status
        """,
        (window,),
    ).fetchall()
    by_status: dict[str, int] = {}
    triage = {"ready": 0, "unavailable": 0, "pending": 0, "none": 0}
    for status, triage_status, n in rows:
        by_status[status] = by_status.get(status, 0) + n
        key = triage_status if triage_status is not None else "none"
        triage[key] = triage.get(key, 0) + n
    return {"by_status": by_status, "triage": triage}


def _waiting(conn: Any) -> dict[str, Any]:
    """Clusters waiting for Tier 1 now (spec §4.1 KPI): heads in `queued_tier1`, synthetic left
    out, NOT bounded by the range. `oldest_received_at` is `None` when none waits."""
    count, oldest = conn.execute("""
        SELECT count(*), min(received_at)
        FROM alerts
        WHERE duplicate_of IS NULL AND status = 'queued_tier1' AND NOT is_synthetic
        """).fetchone()
    return {"count": count, "oldest_received_at": oldest}


def _cases_open(conn: Any) -> int:
    (count,) = conn.execute("SELECT count(*) FROM cases WHERE status = 'investigating'").fetchone()
    return count


def _health(conn: Any) -> dict[str, Any] | None:
    """The newest `system_health` row, or `None` before the first health run."""
    row = conn.execute(
        "SELECT checked_at, ok, checks FROM system_health ORDER BY checked_at DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return None
    checked_at, ok, checks = row
    return {"checked_at": checked_at, "ok": ok, "checks": checks}


def _failed_jobs(conn: Any) -> list[dict[str, Any]]:
    """The 50 failed jobs whose last attempt is newest (module docstring). `left()` cuts
    `last_error` in the database, so a huge error text never leaves it; NULL stays NULL."""
    rows = conn.execute(
        """
        SELECT job_id, job_type, subject_id, attempts, left(last_error, %s), locked_at, created_at
        FROM jobs
        WHERE status = 'failed'
        ORDER BY COALESCE(locked_at, created_at) DESC, job_id DESC
        LIMIT %s
        """,
        (_ERROR_CHARS, _FAILED_JOBS_LIMIT),
    ).fetchall()
    return [
        {
            "job_id": job_id,
            "job_type": job_type,
            "subject_id": subject_id,
            "attempts": attempts,
            "last_error": last_error,
            "locked_at": locked_at,
            "created_at": created_at,
        }
        for job_id, job_type, subject_id, attempts, last_error, locked_at, created_at in rows
    ]


def _inventory(conn: Any) -> dict[str, Any]:
    """Active rows of the three tables, and the newest `loaded_at` among them (GREATEST skips
    a NULL, so a table whose rows predate `loaded_at` does not hide the others)."""
    assets, identities, iocs, loaded_at = conn.execute("""
        SELECT (SELECT count(*) FROM assets WHERE active),
               (SELECT count(*) FROM identities WHERE active),
               (SELECT count(*) FROM iocs WHERE active),
               GREATEST((SELECT max(loaded_at) FROM assets WHERE active),
                        (SELECT max(loaded_at) FROM identities WHERE active),
                        (SELECT max(loaded_at) FROM iocs WHERE active))
        """).fetchone()
    return {"assets": assets, "identities": identities, "iocs": iocs, "loaded_at": loaded_at}


def _llm_month(conn: Any, cfg: Any) -> dict[str, Any]:
    """`{spent_usd, cap_usd, pct}` of the calendar month (DEC-203 item 1): the figures of
    `GET /api/admin/llm/usage`'s `month`, from the same code (`admin_llm.llm_month`), so the cost
    card needs no second read of that route, which answers 503 as a whole when any one of its four
    blocks fails. `cap_usd` and `pct` are `null` when the limits cannot be read; that is not an
    error. A failure of the spend query is this section's `errors` entry, like any other's."""
    return admin_llm.llm_month(conn, cfg)


# ---------------------------------------------------------------------------
# One section, alone
# ---------------------------------------------------------------------------


def _run_section(conn: Any, name: str, compute: Any, errors: list[dict[str, str]]) -> Any:
    """`compute()` in a savepoint under its own `statement_timeout`; `None` plus an `errors`
    entry on any `psycopg.Error`. The savepoint rollback leaves the transaction usable."""
    try:
        with conn.transaction():
            conn.execute(
                sql.SQL("SET LOCAL statement_timeout = {}").format(sql.Literal(SECTION_TIMEOUT))
            )
            return compute()
    except psycopg.errors.QueryCanceled:
        errors.append({"section": name, "error": "timeout"})
    except psycopg.Error as exc:
        # The class and SQLSTATE only: the message can hold SQL text.
        logger.warning("overview section %s failed: %s %s", name, type(exc).__name__, exc.sqlstate)
        errors.append({"section": name, "error": "query_failed"})
    return None


@router.get("/api/admin/overview")
def api_overview(
    conn: Conn,
    cfg: Cfg,
    claims: Admin,
    range_: Annotated[RangeName, Query(alias="range")] = "24h",
) -> dict[str, Any]:
    window = _WINDOWS[range_]
    errors: list[dict[str, str]] = []
    # Looked up by name when the request runs (not captured at import), so a test can replace
    # one section's function to make it fail.
    sections = (
        ("alerts_by_day", lambda: _alerts_by_day(conn, cfg.DISPLAY_TZ, window)),
        ("by_source", lambda: _by_source(conn, window)),
        ("top_agents", lambda: _top_agents(conn, window)),
        ("funnel", lambda: _funnel(conn, window)),
        ("waiting", lambda: _waiting(conn)),
        ("cases_open", lambda: _cases_open(conn)),
        ("health", lambda: _health(conn)),
        ("failed_jobs", lambda: _failed_jobs(conn)),
        ("inventory", lambda: _inventory(conn)),
        ("llm_month", lambda: _llm_month(conn, cfg)),
    )
    body: dict[str, Any] = {"range": range_, "errors": errors}
    for name, compute in sections:
        body[name] = _run_section(conn, name, compute, errors)
    return body


# ---------------------------------------------------------------------------
# Retry
# ---------------------------------------------------------------------------


def _refuse(status_code: int, reason: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"reason": reason})


def _has_live_sibling(conn: Any, job_id: int, job_type: str, subject_id: str) -> bool:
    """Another job of the same type and subject that is `pending` or `running`: what
    `ux_jobs_mot_job_song_moi_subject` would refuse the retry for."""
    row = conn.execute(
        """
        SELECT 1 FROM jobs
        WHERE job_type = %s AND subject_id = %s AND status IN ('pending', 'running')
          AND job_id <> %s
        LIMIT 1
        """,
        (job_type, subject_id, job_id),
    ).fetchone()
    return row is not None


@router.post("/api/admin/jobs/{job_id}/retry")
def api_retry_job(conn: Conn, claims: Admin, job_id: JobId) -> dict[str, Any]:
    row = conn.execute(
        "SELECT job_type, subject_id, status, attempts, left(last_error, %s) "
        "FROM jobs WHERE job_id = %s FOR UPDATE",
        (_ERROR_CHARS, job_id),
    ).fetchone()
    if row is None:
        raise _refuse(404, "not_found")
    job_type, subject_id, status, attempts_before, last_error = row
    if status != "failed":
        raise _refuse(409, "not_failed")
    if _has_live_sibling(conn, job_id, job_type, subject_id):
        raise _refuse(409, "already_queued")
    try:
        with conn.transaction():
            conn.execute(
                "UPDATE jobs SET status = 'pending', attempts = 0, scheduled_at = now(), "
                "locked_at = NULL WHERE job_id = %s",
                (job_id,),
            )
    except psycopg.errors.UniqueViolation as exc:
        # `enqueue` slipped a sibling in after the check above. Only that index means
        # "already queued"; anything else is a real fault and stays a 500.
        if exc.diag.constraint_name != _LIVE_JOB_INDEX:
            raise
        raise _refuse(409, "already_queued") from exc
    write_event(
        conn,
        "admin.job_retried",
        str(job_id),
        "admin",
        actor_id=claims.user_id,
        payload={
            "job_id": job_id,
            "job_type": job_type,
            "subject_id": subject_id,
            "attempts_before": attempts_before,
            "last_error": last_error,
        },
    )
    return {"job_id": job_id, "status": "pending"}
