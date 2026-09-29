"""web/routers/case_analyze_pages.py — the ② half of the case screen (P5-T05, DEC-151
wave 4): `POST /cases/{case_id}/analyze` (the *Phân tích* button) and
`GET /cases/{case_id}/investigation` (the "đang phân tích…" polling partial and the result
block, with a verified / unverified mark on every evidence item).

Both routes render `_investigation.html`, the one `<section id="investigation">` that
`case.html` (P5-T07) includes — via `{% include ... ignore missing %}`, with no run data,
so the included partial is a shell that loads `GET .../investigation` on page load. This
module is the other half of that seam; neither `case.html` nor `cases_pages.py` is touched.

**The state is read from the database, not over HTTP.** `POST` calls
`tier2_runs.api_analyze` in-process (the same quota / single-flight / concluded logic as
`POST /api/tier2/cases/{id}/analyze`, no second copy of it) and catches its
`HTTPException`; `GET` derives the state from `jobs` and `llm_runs` directly:

* the case's newest `investigate` job has its FINAL row (`run_id_for_job(job_id)`) -> the
  result, whatever the job's status (a live job with a row is `done`, as `GET
  /api/tier2/runs/{id}` treats it);
* no row and the job is `pending`/`running` -> `running`, and the fragment polls;
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
from datetime import datetime
from typing import Annotated, Any

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.infra.auth import Claims
from app.tier2.investigate import MIN_QUOTE_CHARS, run_id_for_job
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

#: `investigate_v2.suggested_conclusion` in Vietnamese — the three-conclusion table of
#: `docs/phase-7-tier2.md` (the same wording `cases_pages.STATUS_LABELS` uses for the three
#: conclusions) plus ②'s fourth value.
CONCLUSION_LABELS: dict[str, str] = {
    "false_positive": "Không phải sự cố",
    "policy_violation": "Có vi phạm nội quy, không phải tấn công",
    "confirmed_incident": "Là sự cố thật",
    "need_more_data": "Cần thêm dữ liệu",
}

#: `llm_runs.stopped_by` for a row with no `result` (P5-T04's closed set).
STOPPED_TEXT: dict[str, str] = {
    "cap": "đã chạm hạn mức chi phí LLM",
    "permanent": "mô hình từ chối yêu cầu, lỗi không thể thử lại",
    "linter": "dữ liệu của case không qua bộ kiểm tra an toàn trước khi gửi cho mô hình",
    "schema": "mô hình trả lời sai định dạng, kể cả sau một lần sửa",
    "transient": "mô hình không phản hồi sau nhiều lần thử",
}

#: `evidence_check.rejected[].reason` — the three `_check_evidence` writes.
REJECT_TEXT: dict[str, str] = {
    "not_in_case": "alert này không thuộc case",
    "quote_not_found": "trích dẫn không có trong log hay mô tả của alert",
    "quote_too_short": f"trích dẫn ngắn hơn {MIN_QUOTE_CHARS} ký tự nên không kiểm chứng được",
}
REJECT_TEXT_UNKNOWN = "chưa được đối chiếu với log của alert"

#: `evidence_check.forced_by`, in words.
FORCED_BY_TEXT: dict[str, str] = {
    "high_severity_injection_finding": (
        "dữ liệu của case chứa dấu hiệu tiêm lệnh (prompt injection) mức cao, "
        "nên không được kết luận là dương tính giả (false_positive)"
    ),
}
OVERRULE_NO_EVIDENCE = "không có bằng chứng nào kiểm chứng được với log của case"

_LIVE_JOB_STATUSES = ("pending", "running")

_LATEST_JOB_SQL = (
    "SELECT job_id, status FROM jobs WHERE job_type = 'investigate' AND subject_id = %s "
    "ORDER BY job_id DESC LIMIT 1"
)
_RUN_COLUMNS = "run_id, created_at, stopped_by, result, evidence_check, agent_trace"
_RUN_BY_ID_SQL = (
    f"SELECT {_RUN_COLUMNS} FROM llm_runs "
    "WHERE run_id = %s AND pipeline = 'investigate' AND subject_id = %s"
)
_LATEST_FINAL_RUN_SQL = (
    f"SELECT {_RUN_COLUMNS} FROM llm_runs "
    "WHERE pipeline = 'investigate' AND subject_id = %s "
    "AND stopped_by IS DISTINCT FROM 'transient' "
    "ORDER BY created_at DESC, run_id DESC LIMIT 1"
)

#: The same three numbers `tier2.dossier.build` records as the run's snapshot — heads plus
#: the duplicates absorbed into them, the heads' `occurrence_count` summed, the newest
#: `last_seen_at` among the heads — read now, so the page can show them beside the recorded
#: ones. (`alerts.occurrence_count` on a head already counts its merged duplicates.)
_CURRENT_SQL = """
    WITH heads AS (
        SELECT alert_id, occurrence_count, last_seen_at FROM alerts
        WHERE alert_id IN (SELECT alert_id FROM case_alerts WHERE case_id = %s)
    )
    SELECT (SELECT count(*) FROM heads)
             + (SELECT count(*) FROM alerts WHERE duplicate_of IN (SELECT alert_id FROM heads)),
           (SELECT coalesce(sum(occurrence_count), 0) FROM heads),
           (SELECT max(last_seen_at) FROM heads)
"""


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


def _case_status(conn: psycopg.Connection, case_id: str) -> str | None:
    row = conn.execute("SELECT status FROM cases WHERE case_id = %s", (case_id,)).fetchone()
    return None if row is None else row[0]


def _latest_final_row(conn: psycopg.Connection, case_id: str) -> tuple | None:
    return conn.execute(_LATEST_FINAL_RUN_SQL, (case_id,)).fetchone()


def _current_values(conn: psycopg.Connection, case_id: str) -> dict[str, Any]:
    alert_count, total_occurrences, last_seen_at = conn.execute(
        _CURRENT_SQL, (case_id,)
    ).fetchone()
    return {
        "alert_count": int(alert_count),
        "total_occurrences": int(total_occurrences),
        "last_seen_at": last_seen_at,
    }


def _derive_view(
    conn: psycopg.Connection, case_id: str, run_id_hint: uuid.UUID | None
) -> dict[str, Any]:
    """`{"state": idle|running|done|failed, "run_id": ..., "run_row": ...}` — see the module
    docstring for the rules."""
    job = conn.execute(_LATEST_JOB_SQL, (case_id,)).fetchone()
    if job is not None:
        job_id, job_status = job
        final_id = run_id_for_job(job_id)
        row = conn.execute(_RUN_BY_ID_SQL, (str(final_id), case_id)).fetchone()
        if row is not None:
            return {"state": "done", "run_row": row}
        if job_status in _LIVE_JOB_STATUSES:
            return {"state": "running", "run_id": str(final_id)}
        if job_status == "failed":
            return {"state": "failed", "run_row": _latest_final_row(conn, case_id)}
    row = _latest_final_row(conn, case_id)
    if row is not None:
        return {"state": "done", "run_row": row}
    if run_id_hint is not None:
        return {"state": "failed", "run_row": None}
    return {"state": "idle", "run_row": None}


# ---------------------------------------------------------------------------
# Presentation — model output becomes plain values here; the template escapes them.
# ---------------------------------------------------------------------------


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _stopped_text(stopped_by: str | None) -> str:
    if stopped_by is None:
        return "không rõ lý do"
    return STOPPED_TEXT.get(stopped_by, f"dừng ở bước {stopped_by}")


def _evidence_rows(result: dict[str, Any], check: dict[str, Any]) -> list[dict[str, Any]]:
    """One row per `result.evidence[i]`, marked from `evidence_check`. An item is verified
    only if its index is in `verified` and not in `rejected`; with no usable check nothing
    is verified — a mark is never assumed."""
    verified = {
        i for i in _as_list(check.get("verified")) if isinstance(i, int) and not isinstance(i, bool)
    }
    rejected: dict[int, Any] = {}
    for entry in _as_list(check.get("rejected")):
        if isinstance(entry, dict) and isinstance(entry.get("index"), int):
            rejected[entry["index"]] = entry.get("reason")

    rows: list[dict[str, Any]] = []
    for index, item in enumerate(_as_list(result.get("evidence"))):
        item = item if isinstance(item, dict) else {}
        is_verified = index in verified and index not in rejected
        rows.append(
            {
                "alert_id": item.get("alert_id"),
                "quote": item.get("quote"),
                "why": item.get("why"),
                "verified": is_verified,
                "reason_text": None
                if is_verified
                else REJECT_TEXT.get(rejected.get(index), REJECT_TEXT_UNKNOWN),
            }
        )
    return rows


def _overrule_text(result: dict[str, Any], check: dict[str, Any]) -> str | None:
    """Said only when `_check_evidence`'s caller recorded `original_conclusion` — the model
    was overruled, not merely doubted."""
    original = check.get("original_conclusion")
    if not original:
        return None
    now = result.get("suggested_conclusion") or "need_more_data"
    forced_by = check.get("forced_by")
    if forced_by:
        cause = FORCED_BY_TEXT.get(forced_by, f"quy tắc {forced_by}")
    else:
        cause = OVERRULE_NO_EVIDENCE
    return f"Mô hình đề xuất {original} nhưng kết luận đã bị hạ xuống {now}: {cause}."


def _snapshot(agent_trace: Any) -> dict[str, Any] | None:
    """`{alert_count, total_occurrences, last_seen_at}` from `llm_runs.agent_trace` (P5-T04
    `_snapshot_trace`), or `None` when the row carries none."""
    if not isinstance(agent_trace, dict):
        return None
    try:
        alert_count = int(agent_trace["alert_count"])
        total_occurrences = int(agent_trace["total_occurrences"])
    except (KeyError, TypeError, ValueError):
        return None
    raw = agent_trace.get("last_seen_at")
    last_seen_at = None
    if isinstance(raw, str):
        try:
            last_seen_at = datetime.fromisoformat(raw)
        except ValueError:
            last_seen_at = None
    return {
        "alert_count": alert_count,
        "total_occurrences": total_occurrences,
        "last_seen_at": last_seen_at,
    }


def _present_run(row: tuple) -> dict[str, Any]:
    run_id, created_at, stopped_by, result, evidence_check, agent_trace = row
    base: dict[str, Any] = {"run_id": str(run_id), "created_at": created_at}
    if not isinstance(result, dict):
        return {**base, "result": None, "stopped_text": _stopped_text(stopped_by)}

    check = evidence_check if isinstance(evidence_check, dict) else {}
    conclusion = result.get("suggested_conclusion")
    return {
        **base,
        "result": result,
        "conclusion": conclusion,
        "conclusion_label": CONCLUSION_LABELS.get(conclusion, "Chưa rõ kết luận"),
        "confidence": result.get("confidence"),
        "summary": result.get("summary"),
        "narrative": result.get("attack_narrative"),
        "hypotheses": [
            {
                "text": h.get("noi_dung"),
                "evidence_for": _as_list(h.get("evidence_for")),
                "evidence_against": _as_list(h.get("evidence_against")),
            }
            for h in _as_list(result.get("gia_thuyet"))
            if isinstance(h, dict)
        ],
        "evidence": _evidence_rows(result, check),
        "next_steps": _as_list(result.get("next_steps")),
        "playbook_used": result.get("playbook_used"),
        "overruled": _overrule_text(result, check),
        "snapshot": _snapshot(agent_trace),
        "changed": False,
    }


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
    view: dict[str, Any],
    message: dict[str, str] | None = None,
    status_code: int = 200,
    rollback: bool = False,
) -> HTMLResponse:
    """Render `_investigation.html` for `view`. `rollback=True` ends the request on
    `conn.rollback()` AFTER the reads it renders from — for every response that is not a
    plain success, so `get_conn` has nothing to commit."""
    run = None
    current = None
    if view["state"] != "running" and view.get("run_row") is not None:
        run = _present_run(view["run_row"])
        if run.get("snapshot") is not None:
            current = _current_values(conn, case_id)
            snap = run["snapshot"]
            run["changed"] = (
                snap["alert_count"],
                snap["total_occurrences"],
                snap["last_seen_at"],
            ) != (current["alert_count"], current["total_occurrences"], current["last_seen_at"])

    page = templating.render(
        request,
        "_investigation.html",
        tz=cfg.DISPLAY_TZ,
        case_id=case_id,
        case_open=case_open,
        message=message,
        investigation={"state": view["state"], "run_id": view.get("run_id"), "run": run},
        current=current,
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
    status = _case_status(conn, case_id_str)
    if status is None:
        conn.rollback()
        return _not_found_page(request, user)
    view = _derive_view(conn, case_id_str, _parse_uuid(run_id))
    return _render_state(
        request, conn, cfg, case_id_str, status == OPEN_CASE_STATUS, view=view
    )


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

    status = _case_status(conn, case_id)
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
        view=_derive_view(conn, case_id, None),
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
        view={"state": "running", "run_id": str(started["run_id"])},
    )
