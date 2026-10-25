"""web/routers/tier2_runs.py — the two ② operations (P5-T04, design note 6):
`POST /api/tier2/cases/{case_id}/analyze`, `GET /api/tier2/runs/{run_id}`.

A separate module from `web/routers/tier2.py` (P5-T06's four case operations) on
purpose — the two cards' Files lists never collide (P5-tasks.md §9), and
`web/routers/__init__.py::iter_routers()` discovers both without either module
touching `web/main.py` (acceptance 3: `git diff main --stat -- backend/app/web/main.py`
is empty).

**The quota is counted from `audit_events`**, not from `llm_runs` (design note 6): rows
with `event_type='case.analyzed'`, `actor_id=<this user>`, `created_at > now() -
interval '1 day'`. This route writes that row itself, at 202 time, `actor_role='analyst'`
— **a departure from `docs/phase-7-tier2.md:284`**, which has the *job* write
`case.analyzed` with `actor_role='llm'` after the model call completes. A quota that is
only counted after the model has already been paid for is not a quota; §0 of the context
pack puts the v1 phase docs below it, so this card follows the context pack's route list
(§6.4) and departs from the phase doc's actor/timing detail. Named here and in the task
report.

**`run_id` without a schema change** (design note 5): `llm_runs` is append-only and
`jobs` has no payload column, so neither side can hand the other a pre-generated id.
`tier2.investigate.run_id_for_job(job_id)` is deterministic (`uuid5`) — `enqueue()`
returns the `job_id`, so this route computes the same id it returns in the 202 and the
job computes the same id again when it writes the row.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException

from app.audit.events import write_event
from app.infra import config, settings
from app.infra.auth import Claims
from app.infra.jobs import enqueue
from app.rag.lookup import latest_lookup
from app.rag.subject import Subject
from app.tier2 import investigation_view
from app.tier2.investigate import run_id_for_job
from app.web.deps import CaseId, Cfg, Conn, require_role

router = APIRouter(prefix="/api/tier2")

#: One dependency object (the `web/routers/tier2.py` / `web/routers/labels.py` pattern)
#: so `Depends` resolves it once per request.
require_tier2 = require_role("tier2", "admin")
Tier2 = Annotated[Claims, Depends(require_tier2)]


#: The only `cases.status` value that is not a conclusion (`ck_cases_status`: `investigating`
#: | `concluded_fp` | `concluded_policy_violation` | `confirmed_incident`). Everything else
#: is concluded — `confirmed_incident` included, though it does not start with `concluded_`.
OPEN_CASE_STATUS = "investigating"


def _case_status(conn: Any, case_id: str) -> str | None:
    """`cases.status`, or `None` when there is no such case."""
    row = conn.execute("SELECT status FROM cases WHERE case_id = %s", (case_id,)).fetchone()
    return None if row is None else row[0]


#: The ② quota's counting rule, written ONCE: an analysis is a `case.analyzed` audit row, and it
#: counts for the rolling 24 hours after it was written (never "since midnight": decision 8 of
#: the admin console spec). `_analyze_quota_count` below builds its query from this fragment, and
#: so does `admin_llm`'s usage page (P11-T04), so the number the route enforces and the number the
#: admin reads cannot drift apart. The fragment names `audit_events` columns without an alias:
#: use it on a query over `audit_events` alone.
ANALYZE_QUOTA_WHERE = "event_type = 'case.analyzed' AND created_at > now() - interval '1 day'"


def _analyze_quota_count(conn: Any, actor_id: str) -> int:
    row = conn.execute(
        f"SELECT count(*) FROM audit_events WHERE {ANALYZE_QUOTA_WHERE} AND actor_id = %s",
        (actor_id,),
    ).fetchone()
    return row[0]


def _queue_case_lookup_if_stale(conn: Any, cfg: config.Config, case_id: str) -> None:
    """P13-T08 (DEC-210, spec §7.6): with `RAG_ENABLED`, queue a `rag_lookup` for the case when its newest
    stored lookup (whatever its status) is older than `RAG_CASE_REFRESH_H` hours, or it has none. The age is
    read against the database's clock, like every control timestamp. Single-flight (`enqueue`) keeps a
    lookup that is already queued or running. Nothing here waits: ② reads whatever lookup exists when the
    investigation job runs, and a lookup queued now serves the next analysis. Written in the request's
    transaction, before its commit."""
    if not cfg.RAG_ENABLED:
        return
    latest = latest_lookup(conn, Subject("case", case_id.lower()))
    if latest is not None:
        (stale,) = conn.execute(
            "SELECT %s::timestamptz < now() - %s * interval '1 hour'",
            (latest.created_at, cfg.RAG_CASE_REFRESH_H),
        ).fetchone()
        if not stale:
            return
    enqueue(conn, "rag_lookup", Subject("case", case_id.lower()).key)


@router.post("/cases/{case_id}/analyze", status_code=202)
def api_analyze(conn: Conn, claims: Tier2, cfg: Cfg, case_id: CaseId) -> dict[str, Any]:
    """404 if the case does not exist; **409 "case đã kết luận" when the case is already
    concluded** (review round 1, N15 — a conclusion is the end of the analysis, so a run
    on it would spend money on a case nobody can act on, and would be checked against the
    quota before it was refused; nothing is enqueued and no quota row is written); **503
    `{"reason": "limits_unavailable"}` when the quota limit cannot be read** (fail closed,
    DEC-200 item 3 — nothing falls back to `.env`); 429 over the per-person quota
    (`ANALYZE_QUOTA_PER_USER_DAY`, or the admin's saved value, read through
    `infra.settings`); 409 when `enqueue()` returns `None` (a run is
    already live for this case — the single-flight index, not a query); 202
    `{run_id, job_id}` otherwise. With `RAG_ENABLED` the 202 path also queues the case's
    learned-knowledge lookup when it has none newer than `RAG_CASE_REFRESH_H` hours
    (`_queue_case_lookup_if_stale`, P13-T08); the body, the `run_id` and the `investigate` job are
    what they were, and the investigation does not wait for it.

    Every non-2xx path rolls back first (`web/routers/tier1.py`'s `_conflict_response`
    precedent — a returned `Response` is a success as far as `get_conn` is concerned and
    would otherwise commit whatever this function read). The 429 path in particular must
    never see a partially-written quota row survive it; the 202 path's own
    `case.analyzed` write is committed explicitly, right here, before the response is
    built — not left to an ambient commit-on-2xx some test harnesses do not provide —
    so a later request's quota count sees it regardless of how the caller wired
    `get_conn` (P4 planning decision 3, applied to this route's own write instead of a
    403's)."""
    case_id_str = str(case_id)

    status = _case_status(conn, case_id_str)
    if status is None:
        conn.rollback()
        raise HTTPException(status_code=404, detail="case not found")

    if status != OPEN_CASE_STATUS:
        conn.rollback()
        raise HTTPException(status_code=409, detail="case đã kết luận")

    # The per-person limit is the admin's saved one, else `.env`. Fail closed (DEC-200 item 3):
    # if it cannot be read the quota cannot be checked, so nothing is enqueued — never a
    # silent fall back to the `.env` value.
    try:
        quota = settings.effective_limits(conn, cfg).quota_per_24h
    except settings.SettingsUnavailable as exc:
        conn.rollback()
        raise HTTPException(status_code=503, detail={"reason": "limits_unavailable"}) from exc

    if _analyze_quota_count(conn, claims.user_id) >= quota:
        conn.rollback()
        raise HTTPException(status_code=429, detail="analyze quota exceeded for today")

    job_id = enqueue(conn, "investigate", case_id_str)
    if job_id is None:
        conn.rollback()
        raise HTTPException(
            status_code=409, detail="an investigation is already running for this case"
        )

    run_id = run_id_for_job(job_id)
    write_event(
        conn,
        "case.analyzed",
        case_id_str,
        "analyst",
        actor_id=claims.user_id,
        payload={"run_id": str(run_id), "job_id": job_id},
    )
    # P13-T08: after the investigation is queued (its job id, the run id and the 202 body are what they
    # were) and before the commit, so one commit makes both visible together.
    _queue_case_lookup_if_stale(conn, cfg, case_id_str)
    conn.commit()
    return {"run_id": run_id, "job_id": job_id}


@router.get("/runs/{run_id}")
def api_get_run(conn: Conn, claims: Tier2, run_id: uuid.UUID) -> dict[str, Any]:
    """`{status: "done", result, evidence_check, citation_warnings, stopped_by}` once the
    job's FINAL row exists (`stopped_by` is `null` on a normal answer; `cap` / `permanent`
    / `linter` / `schema` / `transient` say why `result` is `null` — N13);
    `{status: "running"}` while a live `investigate` job's deterministic id matches and no
    final row exists yet — which includes the gap between two attempts, whose transient
    rows sit under attempt-scoped ids this route never looks up (B1); **404** otherwise.

    The suggestion-visibility rule (§6.4: "the suggestion of ① is removed from any
    response while `suggestion_visible = false`") does **not** apply here — ② is
    Tier-2's own requested analysis of a case, not ①'s hidden suggestion surfaced on a
    blind alert queue, so there is no `suggestion_visible`-style filter to add. Stated
    so the next reader does not add one and break this screen.
    """
    del claims  # role gate only (`require_role`) — every tier2/admin session may read
    # any run; there is no per-case ownership column to filter on (`web/routers/
    # tier2.py`'s `list_cases`/`case_detail` have none either).
    row = conn.execute(
        "SELECT result, evidence_check, citation_warnings, stopped_by FROM llm_runs "
        "WHERE run_id = %s AND pipeline = 'investigate'",
        (str(run_id),),
    ).fetchone()
    if row is not None:
        result, evidence_check, citation_warnings, stopped_by = row
        return {
            "status": "done",
            "result": result,
            "evidence_check": evidence_check,
            "citation_warnings": citation_warnings,
            "stopped_by": stopped_by,
        }

    live_job_ids = conn.execute(
        "SELECT job_id FROM jobs WHERE job_type = 'investigate' AND status IN ('pending', 'running')"
    ).fetchall()
    for (job_id,) in live_job_ids:
        if run_id_for_job(job_id) == run_id:
            return {"status": "running"}

    conn.rollback()
    raise HTTPException(status_code=404, detail="run not found")


@router.get("/cases/{case_id}/investigation")
def api_investigation(
    conn: Conn, _: Tier2, cfg: Cfg, case_id: CaseId, run_id: uuid.UUID | None = None
) -> dict[str, Any]:
    """`{state, run_id, minutes, run, current, case_open}` — the ② view the React case page
    (P10-T11) renders from, built by `tier2.investigation_view.build_investigation` (P10-T03;
    the Jinja page that shared it retired in P10-T13). `state` is `idle` |
    `running` | `stalled` | `done` | `failed`; `run_id` (the query parameter) is the one the 202
    of `POST .../analyze` returned, so a poll that finds nothing behind it answers `failed`
    rather than `idle`; `case_open` is False once the case is concluded. **404** for an unknown
    case.

    Read-only, and it ends on `conn.rollback()` after the reads it answers from: a returned
    dict is a success as far as `get_conn` is concerned, and would otherwise commit them."""
    status = _case_status(conn, str(case_id))
    if status is None:
        conn.rollback()
        raise HTTPException(status_code=404, detail="case not found")
    body = investigation_view.build_investigation(conn, cfg, str(case_id), run_id)
    conn.rollback()
    return {**body, "case_open": status == OPEN_CASE_STATUS}
