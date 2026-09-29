"""web/routers/cases_pages.py — the case list and case detail pages (P5-T07):
`GET /cases`, `GET /cases/{case_id}`, `POST /cases/{case_id}/notes` (the
`_case_notes.html` HTMX swap target) and `POST /cases/{case_id}/conclude`
(posts to this page, never the JSON API).

Reads `app.web.routers.tier2.list_cases`/`case_detail` and `app.tier2.conclude`
directly — the functions P5-T06 exposed at module level for exactly this use
(its own report, §3: "P5-T07 ... reads straight from these two functions
rather than re-deriving the SQL") — this module writes no second case or head
query.

**One deviation, named here and in the report.** `case_detail()`'s heads carry
only the "case-overview grid" columns P5-T06 chose (its own report, §3) —
`raw_log`, `risk_score` and `last_seen_at` are not among them, but this
card's own design note 3 and its acceptance items need all three: escaped
`raw_log`, the risk band (never the raw score — P4's rule), and the
"đợt tấn công đang tiếp diễn" ongoing-cluster label (`docs/phase-7-tier2.md`
§P7-2). `_supplement` below is one additional, read-only, G10-explicit-column
`alert_id = ANY(...)` query for exactly those three fields — it does not
re-derive `list_cases`/`case_detail`'s own case/head listing SQL, which this
module still calls unchanged.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

import psycopg
from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.domain import transitions
from app.infra.auth import Claims
from app.tier1.queue import risk_band
from app.tier2 import conclude
from app.web import templating
from app.web.deps import Cfg, Conn, require_role
from app.web.routers import tier2
from app.web.routers.pages import page_user

router = APIRouter()

#: One dependency object, so `Depends` resolves it once per request (the
#: pattern `web/routers/labels.py` uses for `Admin`).
require_tier2 = require_role("tier2", "admin")
Tier2 = Annotated[Claims, Depends(require_tier2)]

#: The four `cases.status` values / three `conclude` conclusions, in
#: Vietnamese — `docs/phase-7-tier2.md`'s own "Ba kết luận" table (its lines
#: 335-337) verbatim for the three conclusions; "Đang điều tra" for the
#: fourth, the same vocabulary that document uses throughout ("Trợ lý điều
#: tra"). Reused as the conclude form's three radio labels too — one table,
#: one place to change the wording.
STATUS_LABELS: dict[str, str] = {
    "investigating": "Đang điều tra",
    "concluded_fp": "Không phải sự cố",
    "concluded_policy_violation": "Có vi phạm nội quy, không phải tấn công",
    "confirmed_incident": "Là sự cố thật",
}

#: A head's own `alerts.status` while it belongs to a case — always
#: `escalated_tier2` during investigation (H3 forbids `sealed_at` while
#: escalated) or one of the three closed states after conclusion (§B3's
#: conclusion → `alerts.status` map, `domain/transitions.py:82`).
HEAD_STATUS_LABELS: dict[str, str] = {
    "escalated_tier2": "Đang xử lý Tier 2",
    "closed_fp": "Đã đóng — không phải sự cố",
    "closed_benign": "Đã đóng — vi phạm nội quy",
    "closed_confirmed": "Đã đóng — sự cố xác nhận",
}

#: Design note 4: the one sentence of scope, on the screen and not only in
#: the report — `docs/phase-7-tier2.md` §Ba kết luận / §P7-7:
#: `confirmed_incident` is the end of this project's scope, and the screen
#: must not imply a response step follows.
CONFIRMED_INCIDENT_SCOPE_NOTE = (
    "Kết luận này chỉ ghi nhận sự cố — hệ thống dừng lại ở đây, không có "
    "bước cách ly, ứng cứu hay khắc phục nào (hệ thống phát hiện và phân "
    "loại, không ứng cứu)."
)

_SUPPLEMENT_COLUMNS: tuple[str, ...] = (
    "alert_id",
    "raw_log",
    "raw_log_truncated",
    "risk_score",
    "last_seen_at",
)


def _supplement(conn: psycopg.Connection, alert_ids: list[str]) -> dict[str, dict[str, Any]]:
    """`raw_log`, `raw_log_truncated`, `risk_score` and `last_seen_at` for
    `alert_ids` — the module docstring's deviation. One `alert_id = ANY(...)`
    read, G10 explicit columns, `{}` for an empty case."""
    if not alert_ids:
        return {}
    rows = conn.execute(
        f"SELECT {', '.join(_SUPPLEMENT_COLUMNS)} FROM alerts WHERE alert_id = ANY(%s)",
        (alert_ids,),
    ).fetchall()
    return {row[0]: dict(zip(_SUPPLEMENT_COLUMNS[1:], row[1:], strict=True)) for row in rows}


def _username(conn: psycopg.Connection, user_id: Any) -> str | None:
    """`None` for `None` or an unknown id — never raises; a display-only
    lookup for the conclude form's 409 flash ("naming the concluder")."""
    if user_id is None:
        return None
    row = conn.execute("SELECT username FROM users WHERE user_id = %s", (user_id,)).fetchone()
    return row[0] if row else None


def _not_found_page(
    request: Request, user: Claims | None, *, status_code: int = 404
) -> HTMLResponse:
    """Review round 1, alignment item: an unknown or missing case renders an
    HTML page through the same `templating.render` path every other page
    uses — never a bare `HTTPException`'s JSON body."""
    page = templating.render(request, "case_not_found.html", user=user)
    page.status_code = status_code
    return page


def _conclude_error_text(exc: ValueError) -> str:
    """A Vietnamese sentence for `conclude.submit`'s `ValueError`s — review
    round 1, nit N7: never `str(exc)` (English, and for the bad-conclusion
    case would echo the posted value verbatim back into the page)."""
    msg = str(exc)
    if msg.startswith("conclusion:"):
        return "Kết luận không hợp lệ."
    if "NUL" in msg:
        return "Lý do chứa ký tự không hợp lệ."
    if msg.startswith("reason:"):
        return "Lý do không được để trống."
    return "Dữ liệu không hợp lệ."  # pragma: no cover — no other ValueError shape exists today


def _note_error_text(exc: ValueError) -> str:
    """A Vietnamese sentence for `conclude.add_note`'s `ValueError`s — same
    reasoning as `_conclude_error_text`."""
    msg = str(exc)
    if "NUL" in msg:
        return "Ghi chú chứa ký tự không hợp lệ."
    if "exceeds" in msg:
        return "Ghi chú quá dài."
    if msg.startswith("body:"):
        return "Ghi chú không được để trống."
    return "Dữ liệu không hợp lệ."  # pragma: no cover — no other ValueError shape exists today


def _enrich_heads(
    conn: psycopg.Connection, heads: list[dict[str, Any]], since: datetime
) -> datetime | None:
    """Merges `_supplement`'s fields into each head in place — `raw_log`
    (escaped by the template, never `|safe`) with `raw_log_truncated`,
    `risk_band` (`risk_score` replaced by the band, never the bare number —
    P4's rule; `risk_score` itself is not stored on the dict, so it cannot
    leak into the template by accident) and `last_seen_at` (shown per head,
    `local_time`-formatted, design note 3).

    Returns the latest `last_seen_at` among heads that are both still
    `escalated_tier2` **and** newer than `since` — `None` when no head
    qualifies. Review round 1, blocker B1: `alerts.last_seen_at` is `NOT NULL
    DEFAULT now()`, so `last_seen_at is not None` alone is always true and
    the old rule reduced to "the case is open." `since` is
    `case.last_analyzed_at or case.created_at`, matching
    `docs/phase-7-tier2.md:452`'s "`last_seen_at` mới hơn `last_analyzed_at`"
    once ② starts writing `last_analyzed_at`, and correct before that too:
    `escalate` inserts the case and its heads in one transaction (`now()` is
    the transaction start time), so an unbumped head's `last_seen_at` equals
    `case.created_at` exactly — not "newer than" — and only `bump_parent`
    (a duplicate arriving) ever moves it forward. Known limit, noted in the
    report: a duplicate whose dedup transaction overlaps the `escalate`
    transaction can be missed until the next duplicate arrives, since both
    transactions read their own `now()` snapshot.
    """
    supplement = _supplement(conn, [h["alert_id"] for h in heads])
    ongoing_last_seen = None
    for head in heads:
        extra = supplement.get(head["alert_id"], {})
        head["raw_log"] = extra.get("raw_log", "")
        head["raw_log_truncated"] = bool(extra.get("raw_log_truncated"))
        head["risk_band"] = risk_band(extra.get("risk_score"))
        last_seen = extra.get("last_seen_at")
        head["last_seen_at"] = last_seen
        is_growing = (
            head["status"] == "escalated_tier2" and last_seen is not None and last_seen > since
        )
        if is_growing and (ongoing_last_seen is None or last_seen > ongoing_last_seen):
            ongoing_last_seen = last_seen
    return ongoing_last_seen


# ---------------------------------------------------------------------------
# GET /cases — the list
# ---------------------------------------------------------------------------


@router.get("/cases", response_class=HTMLResponse)
def cases_page(
    request: Request,
    conn: Conn,
    cfg: Cfg,
    user: Annotated[Claims, Depends(page_user)],
    _: Tier2,
    offset: Annotated[int, Query(ge=0, le=2**31 - 1)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> HTMLResponse:
    cases = tier2.list_cases(conn, offset=offset, limit=limit)
    return templating.render(
        request,
        "cases.html",
        user=user,
        tz=cfg.DISPLAY_TZ,
        cases=cases,
        offset=offset,
        limit=limit,
        status_labels=STATUS_LABELS,
    )


# ---------------------------------------------------------------------------
# GET /cases/{case_id} — the detail
# ---------------------------------------------------------------------------


def _case_page(
    request: Request,
    conn: psycopg.Connection,
    cfg: Any,
    user: Claims,
    case_id: str,
    *,
    flash: dict[str, str] | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    case = tier2.case_detail(conn, case_id)
    if case is None:
        return _not_found_page(request, user)
    since = case["last_analyzed_at"] or case["created_at"]
    ongoing_last_seen = _enrich_heads(conn, case["heads"], since)
    concluded_by_name = _username(conn, case["concluded_by"])
    page = templating.render(
        request,
        "case.html",
        user=user,
        tz=cfg.DISPLAY_TZ,
        flash=flash,
        case=case,
        case_id=case["case_id"],
        notes=case["notes"],
        note_error=None,
        status_labels=STATUS_LABELS,
        head_status_labels=HEAD_STATUS_LABELS,
        scope_note=CONFIRMED_INCIDENT_SCOPE_NOTE,
        ongoing=ongoing_last_seen is not None,
        ongoing_last_seen=ongoing_last_seen,
        concluded_by_name=concluded_by_name,
    )
    page.status_code = status_code
    return page


@router.get("/cases/{case_id}", response_class=HTMLResponse)
def case_page(
    request: Request,
    conn: Conn,
    cfg: Cfg,
    user: Annotated[Claims, Depends(page_user)],
    _: Tier2,
    case_id: uuid.UUID,
) -> HTMLResponse:
    return _case_page(request, conn, cfg, user, str(case_id))


# ---------------------------------------------------------------------------
# POST /cases/{case_id}/notes — the _case_notes.html HTMX swap target
# ---------------------------------------------------------------------------


def _notes_fragment(
    request: Request,
    conn: psycopg.Connection,
    cfg: Any,
    case_id: str,
    *,
    note_error: str | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    notes = conclude.list_notes(conn, case_id)
    page = templating.render(
        request,
        "_case_notes.html",
        tz=cfg.DISPLAY_TZ,
        case_id=case_id,
        notes=notes,
        note_error=note_error,
    )
    page.status_code = status_code
    return page


def _is_htmx(request: Request) -> bool:
    return request.headers.get("HX-Request") == "true"


@router.post("/cases/{case_id}/notes", response_class=HTMLResponse)
def add_note_page(
    request: Request,
    conn: Conn,
    cfg: Cfg,
    user: Annotated[Claims, Depends(page_user)],
    _: Tier2,
    case_id: uuid.UUID,
    body: Annotated[str, Form()] = "",
):
    case_id_str = str(case_id)
    htmx = _is_htmx(request)
    try:
        conclude.add_note(conn, case_id_str, user.user_id, body)
    except ValueError as exc:
        text = _note_error_text(exc)
        if htmx:
            return _notes_fragment(
                request, conn, cfg, case_id_str, note_error=text, status_code=422
            )
        return _case_page(
            request,
            conn,
            cfg,
            user,
            case_id_str,
            flash={"level": "error", "text": text},
            status_code=422,
        )
    except conclude.UnknownCase:
        return _not_found_page(request, user)
    if htmx:
        return _notes_fragment(request, conn, cfg, case_id_str)
    # review round 1, nit N10: a plain (non-htmx) form POST redirects, like
    # every other page mutation in this app (labels.py's own convention) —
    # only an htmx request gets the bare `_case_notes.html` fragment back.
    return RedirectResponse(f"/cases/{case_id_str}", status_code=303)


# ---------------------------------------------------------------------------
# POST /cases/{case_id}/conclude — posts to this page, never the JSON API
# ---------------------------------------------------------------------------


@router.post("/cases/{case_id}/conclude", response_class=HTMLResponse)
def conclude_page(
    request: Request,
    conn: Conn,
    cfg: Cfg,
    user: Annotated[Claims, Depends(page_user)],
    _: Tier2,
    case_id: uuid.UUID,
    conclusion: Annotated[str, Form()] = "",
    reason: Annotated[str, Form()] = "",
):
    case_id_str = str(case_id)
    try:
        # review round 1, should S2: a savepoint. `psycopg.errors.QueryCanceled`
        # (a real statement-timeout abort) leaves the surrounding transaction
        # unusable — the re-read `_case_page` does next would raise
        # `InFailedSqlTransaction`. `conn.transaction()` rolls back to this
        # savepoint on *any* exception out of the block (re-raising it
        # unchanged), which restores the connection before every `except`
        # below runs its own query.
        with conn.transaction():
            conclude.submit(conn, case_id_str, user.user_id, conclusion=conclusion, reason=reason)
    except ValueError as exc:
        return _case_page(
            request,
            conn,
            cfg,
            user,
            case_id_str,
            flash={"level": "error", "text": _conclude_error_text(exc)},
            status_code=422,
        )
    except conclude.UnknownCase:
        return _not_found_page(request, user)
    except conclude.ConcludeConflict as exc:
        # design note 3 / docs/phase-7-tier2.md:349: who, what and when —
        # never a silent overwrite and never a raw status code (review round
        # 1, nit N6 added "what": the conclusion itself).
        who = _username(conn, exc.concluded_by) or str(exc.concluded_by)
        what = STATUS_LABELS.get(exc.status, exc.status)
        when = templating.local_time(exc.concluded_at, cfg.DISPLAY_TZ)
        text = f"Case đã được {who} kết luận là “{what}” lúc {when} — không ghi đè."
        return _case_page(
            request,
            conn,
            cfg,
            user,
            case_id_str,
            flash={"level": "error", "text": text},
            status_code=409,
        )
    except transitions.IllegalTransition:
        return _case_page(
            request,
            conn,
            cfg,
            user,
            case_id_str,
            flash={"level": "error", "text": "Không thể kết luận: chuyển trạng thái không hợp lệ."},
            status_code=500,
        )
    except psycopg.errors.QueryCanceled:
        return _case_page(
            request,
            conn,
            cfg,
            user,
            case_id_str,
            flash={"level": "error", "text": "Kết luận quá thời gian chờ — thử lại."},
            status_code=503,
        )
    return RedirectResponse(f"/cases/{case_id_str}", status_code=303)
