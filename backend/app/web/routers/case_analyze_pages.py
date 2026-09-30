"""web/routers/case_analyze_pages.py — the ② half of the case screen (P5-T05, DEC-151
wave 4): `POST /cases/{case_id}/analyze` (the *Phân tích* button) and
`GET /cases/{case_id}/investigation` (the "đang phân tích…" polling partial and the result
block, with a verified / unverified mark on every evidence item).

Both routes render `_investigation.html`, the one `<section id="investigation">` that
`case.html` (P5-T07) includes — via `{% include ... ignore missing %}`, with no run data,
so the included partial is a shell that loads `GET .../investigation` on page load. This
module is the other half of that seam; neither `case.html` nor `cases_pages.py` is touched.

**The state is read from the database, not over HTTP** — since P10-T03 by
`app.tier2.investigation_view.build_investigation`, which `GET /api/tier2/cases/{id}/investigation`
serves as JSON too; the rules below are unchanged. `POST` calls
`tier2_runs.api_analyze` in-process (the same quota / single-flight / concluded logic as
`POST /api/tier2/cases/{id}/analyze`, no second copy of it) and catches its
`HTTPException`; `GET` derives the state from `jobs` and `llm_runs` directly:

* the case's newest `investigate` job has its FINAL row (`run_id_for_job(job_id)`) -> the
  result, whatever the job's status (a live job with a row is `done`, as `GET
  /api/tier2/runs/{id}` treats it);
* no row and the job is `pending`/`running` -> `running`, and the fragment polls — unless the
  job is *stalled* (review round 1, S2): `pending` for more than 2 x `JOB_LOCK_TIMEOUT_S` since
  `scheduled_at`, or `running` for more than that since `locked_at`, by the database's `now()`.
  A stalled job renders "Chưa được xử lý sau N phút — kiểm tra worker" with a *Kiểm tra lại*
  button (an `hx-get` of this same GET), no polling and no *Phân tích* button. The page does not
  say the worker is dead: a triage backlog can legitimately delay the job;
* no row and the job is `failed` -> `failed` (a last attempt that dies without an LLM error
  — a statement timeout while the dossier is built — leaves no row, so the API answers 404
  after the 202; here it is "Phân tích thất bại — có thể thử lại" and the polling stops);
* no usable job -> the newest row that is not a transient attempt (`stopped_by !=
  'transient'`: a non-final failed attempt writes one under an attempt-scoped id, P5-T04
  round 1 B1, and is not an outcome), else `idle`.

A poll also carries the `run_id` of the 202. If the server finds nothing at all behind it
(no job, no row) that is the API's 404, and it is shown as a failure rather than an idle
screen. It only ever turns `idle` into `failed`: a real running or finished state wins.

**Rulings from the Director** (P5-T05 dispatch, written against the merged code):

* Every message is rendered inside the swapped fragment. `case.html` has no `#flash`
  placeholder, so an out-of-band `_flash.html` would be dropped by htmx 2.0.4 (P4-T05's
  review proved it); `_case_notes.html` does the same.
* `case.html`'s `htmx:beforeSwap` listener swaps only 409, 422 and 503. The quota answers
  **200** plus the message (a 429 would never be swapped, and no JS may be added); the
  already-running and concluded refusals answer 409.
* A returned non-2xx (and the 200 quota message) ends on `conn.rollback()` after the reads
  it renders from — `get_conn` would otherwise commit them, since a returned response is a
  success as far as it can tell (P4-T03's `_conflict_response` pattern).
* A plain (non-htmx) form POST redirects to the case page, as `cases_pages.add_note_page`
  does; only an htmx request gets the bare fragment.

**Deviation from the card** (recorded in the report): `GET /api/tier2/runs/{id}` does not
return `agent_trace` (the P7-2 snapshot) or `created_at`, and does not check that the run
belongs to a case, so this module reads `llm_runs` itself, always filtered by
`subject_id = <this case>`.

Model output is untrusted. Everything reaches the template as plain strings and is
autoescaped there; this module builds no markup.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.infra.auth import Claims
from app.tier2 import investigation_view
from app.web import templating
from app.web.deps import Cfg, Conn, require_role
from app.web.routers import tier2_runs
from app.web.routers.pages import page_user

router = APIRouter()

#: One dependency object, so `Depends` resolves it once per request.
require_tier2 = require_role("tier2", "admin")
Tier2 = Annotated[Claims, Depends(require_tier2)]

OPEN_CASE_STATUS = tier2_runs.OPEN_CASE_STATUS

#: Messages rendered inside the fragment (the wording the Director dispatched).
MSG_ALREADY_RUNNING = "Đang có một lượt phân tích chạy cho case này"
MSG_QUOTA = "Đã dùng hết {n} lượt phân tích hôm nay"
MSG_CONCLUDED = "Case đã kết luận — không thể phân tích thêm"


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _not_found_page(request: Request, user: Claims | None) -> HTMLResponse:
    """An unknown case renders the same HTML page `cases_pages` does, never a bare JSON
    `HTTPException` body."""
    page = templating.render(request, "case_not_found.html", user=user)
    page.status_code = 404
    return page


def _render_state(
    request: Request,
    conn: psycopg.Connection,
    cfg: Any,
    case_id: str,
    case_open: bool,
    *,
    body: dict[str, Any],
    message: dict[str, str] | None = None,
    status_code: int = 200,
    rollback: bool = False,
) -> HTMLResponse:
    """Render `_investigation.html` for `body`, the dict `investigation_view.build_investigation`
    returns (`investigation=` all of it but `current`, and `current=` beside it — the context
    the template has always had). `rollback=True` ends the request on `conn.rollback()` AFTER
    the reads it renders from — for every response that is not a plain success, so `get_conn`
    has nothing to commit."""
    page = templating.render(
        request,
        "_investigation.html",
        tz=cfg.DISPLAY_TZ,
        case_id=case_id,
        case_open=case_open,
        message=message,
        investigation={key: value for key, value in body.items() if key != "current"},
        current=body["current"],
    )
    page.status_code = status_code
    if rollback:
        conn.rollback()
    return page


def _parse_uuid(value: str | None) -> uuid.UUID | None:
    if not value:
        return None
    try:
        return uuid.UUID(value)
    except ValueError:
        return None


def _is_htmx(request: Request) -> bool:
    return request.headers.get("HX-Request") == "true"


# ---------------------------------------------------------------------------
# GET /cases/{case_id}/investigation — the state (and the poll)
# ---------------------------------------------------------------------------


@router.get("/cases/{case_id}/investigation", response_class=HTMLResponse)
def investigation_page(
    request: Request,
    conn: Conn,
    cfg: Cfg,
    user: Annotated[Claims, Depends(page_user)],
    _: Tier2,
    case_id: uuid.UUID,
    run_id: str | None = None,
) -> HTMLResponse:
    case_id_str = str(case_id)
    status = investigation_view.case_status(conn, case_id_str)
    if status is None:
        conn.rollback()
        return _not_found_page(request, user)
    body = investigation_view.build_investigation(conn, cfg, case_id_str, _parse_uuid(run_id))
    return _render_state(request, conn, cfg, case_id_str, status == OPEN_CASE_STATUS, body=body)


# ---------------------------------------------------------------------------
# POST /cases/{case_id}/analyze — the Phân tích button
# ---------------------------------------------------------------------------


def _refusal(
    request: Request,
    conn: psycopg.Connection,
    cfg: Any,
    user: Claims,
    case_id: str,
    exc: HTTPException,
) -> HTMLResponse:
    """`api_analyze` already rolled back before raising; the reads below open a new
    transaction, which `_render_state(rollback=True)` closes again before returning."""
    if exc.status_code == 404:
        return _not_found_page(request, user)
    if exc.status_code not in (409, 429):
        raise exc  # nothing else is raised there; do not paper over a new refusal

    status = investigation_view.case_status(conn, case_id)
    if status is None:  # deleted between the refusal and this read
        conn.rollback()
        return _not_found_page(request, user)
    case_open = status == OPEN_CASE_STATUS

    if exc.status_code == 429:
        message = {"level": "warn", "text": MSG_QUOTA.format(n=cfg.ANALYZE_QUOTA_PER_USER_DAY)}
        status_code = 200  # 429 is never swapped by case.html's beforeSwap; the quota is a message
    elif not case_open:
        message = {"level": "warn", "text": MSG_CONCLUDED}
        status_code = 409
    else:
        message = {"level": "warn", "text": MSG_ALREADY_RUNNING}
        status_code = 409

    return _render_state(
        request,
        conn,
        cfg,
        case_id,
        case_open,
        body=investigation_view.build_investigation(conn, cfg, case_id, None),
        message=message,
        status_code=status_code,
        rollback=True,
    )


@router.post("/cases/{case_id}/analyze", response_class=HTMLResponse)
def analyze_page(
    request: Request,
    conn: Conn,
    cfg: Cfg,
    user: Annotated[Claims, Depends(page_user)],
    _: Tier2,
    case_id: uuid.UUID,
):
    case_id_str = str(case_id)
    try:
        started = tier2_runs.api_analyze(conn, user, cfg, case_id)
    except HTTPException as exc:
        return _refusal(request, conn, cfg, user, case_id_str, exc)
    if not _is_htmx(request):
        return RedirectResponse(f"/cases/{case_id_str}", status_code=303)
    return _render_state(
        request,
        conn,
        cfg,
        case_id_str,
        True,  # api_analyze only enqueues for an open case
        body={
            "state": "running",
            "run_id": str(started["run_id"]),
            "minutes": None,
            "run": None,
            "current": None,
        },
    )
