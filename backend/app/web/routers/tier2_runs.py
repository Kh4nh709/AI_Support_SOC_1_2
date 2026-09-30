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
from app.infra.auth import Claims
from app.infra.jobs import enqueue
from app.tier2 import investigation_view
from app.tier2.investigate import run_id_for_job
from app.web.deps import Cfg, Conn, require_role

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


def _analyze_quota_count(conn: Any, actor_id: str) -> int:
    row = conn.execute(
        "SELECT count(*) FROM audit_events WHERE event_type = 'case.analyzed' "
        "AND actor_id = %s AND created_at > now() - interval '1 day'",
        (actor_id,),
    ).fetchone()
    return row[0]


@router.post("/cases/{case_id}/analyze", status_code=202)
def api_analyze(conn: Conn, claims: Tier2, cfg: Cfg, case_id: uuid.UUID) -> dict[str, Any]:
    """404 if the case does not exist; **409 "case đã kết luận" when the case is already
    concluded** (review round 1, N15 — a conclusion is the end of the analysis, so a run
    on it would spend money on a case nobody can act on, and would be checked against the
    quota before it was refused; nothing is enqueued and no quota row is written); 429
    over `ANALYZE_QUOTA_PER_USER_DAY`; 409 when `enqueue()` returns `None` (a run is
    already live for this case — the single-flight index, not a query); 202
    `{run_id, job_id}` otherwise.

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

    if _analyze_quota_count(conn, claims.user_id) >= cfg.ANALYZE_QUOTA_PER_USER_DAY:
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
    conn: Conn, _: Tier2, cfg: Cfg, case_id: uuid.UUID, run_id: uuid.UUID | None = None
) -> dict[str, Any]:
    """`{state, run_id, minutes, run, current, case_open}` — the ② view the React case page
    (P10-T11) renders and the Jinja page (`GET /cases/{id}/investigation`) renders from, both
    built by `tier2.investigation_view.build_investigation` (P10-T03). `state` is `idle` |
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
