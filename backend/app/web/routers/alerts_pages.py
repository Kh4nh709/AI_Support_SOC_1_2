"""`web/routers/alerts_pages.py` — the Tier-1 queue page (`GET /queue`), the alert
detail page (`GET /alerts/{id}`) and the four HTMX partial POSTs
(`acknowledge|decide|escalate|reopen`) that call `tier1/decide.py` and answer with a
fragment (P4-T05).

This module reads nothing from `alerts`/`llm_runs` directly (a grep guard, acceptance
2) — every fact comes from `tier1.queue.list_queue`/`get_alert_view` (already filtered
through `visibility.strip`) and every write goes through `tier1.decide`. It mirrors
`web/routers/tier1.py`'s exception -> status mapping for HTML instead of JSON:

- `decide.NotFound` -> `404` (the exception path; nothing needs to survive it, so
  `get_conn`'s own rollback-on-exception is enough).
- `decide.DecisionConflict` -> `409`, `ValueError` -> `422`,
  `psycopg.errors.QueryCanceled` (only on `decide`, the one call that sets a
  transaction-local statement timeout) -> `503`. All three are *returned* fragments,
  not raised — `deps.get_conn` treats a normal return as success and commits, so each
  branch below calls `conn.rollback()` first (pitfall 1 / `tier1.py`'s
  `_conflict_response`, review round 1 item 4), then re-reads the alert's current view
  so the re-rendered `_decision_form.html` carries fresh data (a stale-cluster 409's
  hidden `seen_occurrence_count` becomes the current count, not the one that was
  refused).
- `require_role("tier1")` answers a wrong role's POST with its own `403`, having
  already written and committed `authz.denied` (pitfall 2) — reused as a dependency,
  not reimplemented here (the card's "prefer the dependency").

Every page goes through `page_user` first (a `303` to `/login`, never a JSON `401`);
`require_role("tier1")` is a second, later dependency on the four POSTs only, so an
unauthenticated request is redirected before role checking ever runs (the same
ordering `web/routers/admin_rules.py` uses for `page_user` + `require_role("admin")`).
"""

from __future__ import annotations

import math
from typing import Annotated

import psycopg
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from app.infra.auth import Claims
from app.tier1 import decide, queue
from app.web import templating
from app.web.deps import Cfg, Conn, require_role
from app.web.routers.pages import page_user

router = APIRouter()

require_tier1 = require_role("tier1")
PageUser = Annotated[Claims, Depends(page_user)]
Tier1 = Annotated[Claims, Depends(require_tier1)]

_NOT_FOUND_TEXT = "Không tìm thấy alert"
#: `web/routers/tier1.py`'s `EscalateIn.severity` set — `decide.escalate` itself does
#: not validate this (it is a thin layer, planning decision 4), and an invalid value
#: would otherwise surface as a raw DB CHECK violation (a 500) instead of a clean 422;
#: the severity `<select>` in `_decision_form.html` only ever offers these four, so
#: this only fires on a hand-crafted request.
_SEVERITIES = ("critical", "high", "medium", "low")


def _actor(user: Claims) -> decide.Actor:
    return decide.Actor(user_id=user.user_id, role=user.role)


def _reject_nul(value: str, field: str) -> str:
    """A NUL byte can never reach a query (psycopg raises a driver-level error, not a
    clean 422) — rejected here instead, the same guard `web/routers/tier1.py`'s
    Pydantic validators apply to the JSON API's bodies (this router's bodies are
    HTML forms, so there is no Pydantic model to hang the check on)."""
    if "\x00" in value:
        raise ValueError(f"{field}: must not contain a NUL byte")
    return value


def _total_pages(total: int, page_size: int) -> int:
    if page_size <= 0:
        return 1
    return max(1, math.ceil(total / page_size))


def _render_fragment(name: str, /, **ctx: object) -> str:
    """A template rendered to a plain string — for a partial response, never a full
    page (`templating.render` wraps `TemplateResponse`, which is one full-page
    context; a 409/422/503 body is up to two fragments concatenated, so each piece is
    rendered on its own and joined by the caller)."""
    return templating.templates.get_template(name).render(**ctx)


def _flash_fragment(level: str, text: str) -> str:
    return _render_fragment("_flash.html", flash={"level": level, "text": text})


def _decision_fragment(conn: psycopg.Connection, alert_id: str) -> str:
    """Re-reads the alert's current view and re-renders `_decision_form.html` from
    it — called after every write (success or refusal) so the fragment a partial
    response returns always reflects what is now true in the database, never what
    was true when the request started (pitfall 1's "then re-read what you
    re-render")."""
    view = queue.get_alert_view(conn, alert_id, mode="analyst")
    if view is None:  # pragma: no cover — unreachable: alert_id was just confirmed to exist
        raise HTTPException(status_code=404, detail=_NOT_FOUND_TEXT)
    return _render_fragment("_decision_form.html", view=view)


def _conflict_text(body: dict) -> str:
    """The flash sentence for one `DecisionConflict.body` (`tier1/decide.py`'s five
    `kind`s). `cluster_grew` and `already_decided` are phase-6's own wording
    (`docs/phase-6-tier1.md`, P4-tasks.md planning decision 10); the other three
    ("the kind in words", card design note 1) are this card's phrasing — nothing
    those three refuse is ever destructive, so no exact wording was pinned."""
    kind = body["kind"]
    if kind == "cluster_grew":
        return (
            f"Cụm đã tăng từ {body['seen_occurrence_count']} lên {body['occurrence_count']} "
            f"bản sao trong lúc bạn đọc (chênh {body['delta']} > {body['tolerance']}) — "
            "xem lại rồi xác nhận"
        )
    if kind == "already_decided":
        return f"Đã được {body['decided_by']} quyết {body['decision']} lúc {body['decided_at']}"
    if kind == "already_in_case":
        return "Alert đã thuộc một case khác — không thể escalate lại"
    if kind == "not_reopenable":
        return "Alert không ở trạng thái tự động đóng nên không mở lại được"
    return "Alert không còn ở trạng thái có thể thao tác — tải lại trang để xem hiện trạng"


def _conflict_response(
    conn: psycopg.Connection, alert_id: str, exc: decide.DecisionConflict
) -> HTMLResponse:
    """`conn.rollback()` before anything else — a returned fragment is a success as
    far as the real `get_conn` is concerned and would otherwise commit whatever the
    guard's own reads left behind (pitfall 1, mirroring `web/routers/tier1.py`'s
    `_conflict_response`)."""
    conn.rollback()
    body = _flash_fragment("error", _conflict_text(exc.body)) + _decision_fragment(conn, alert_id)
    return HTMLResponse(content=body, status_code=409)


def _value_error_response(conn: psycopg.Connection, alert_id: str, text: str) -> HTMLResponse:
    conn.rollback()
    body = _flash_fragment("error", text) + _decision_fragment(conn, alert_id)
    return HTMLResponse(content=body, status_code=422)


def _query_canceled_response(conn: psycopg.Connection, alert_id: str) -> HTMLResponse:
    conn.rollback()
    body = _flash_fragment("error", "Đóng cụm quá lâu, chưa ghi gì — thử lại") + _decision_fragment(
        conn, alert_id
    )
    return HTMLResponse(content=body, status_code=503)


# ---------------------------------------------------------------------------
# The two pages
# ---------------------------------------------------------------------------


@router.get("/queue", response_class=HTMLResponse)
def queue_page(
    request: Request,
    conn: Conn,
    cfg: Cfg,
    user: PageUser,
    page: Annotated[int, Query(ge=1)] = 1,
) -> HTMLResponse:
    result = queue.list_queue(conn, page=page)
    return templating.render(
        request,
        "queue.html",
        user=user,
        page=result,
        tz=cfg.DISPLAY_TZ,
        total_pages=_total_pages(result.total, result.page_size),
    )


@router.get("/alerts/{alert_id}", response_class=HTMLResponse)
def alert_detail_page(
    alert_id: str, request: Request, conn: Conn, cfg: Cfg, user: PageUser
) -> HTMLResponse:
    view = queue.get_alert_view(conn, alert_id, mode="analyst")
    if view is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND_TEXT)
    return templating.render(
        request,
        "alert.html",
        user=user,
        view=view,
        tz=cfg.DISPLAY_TZ,
        correlated_now=view["correlated_now"],
    )


# ---------------------------------------------------------------------------
# The four HTMX partials — tier1 only
# ---------------------------------------------------------------------------


@router.post("/alerts/{alert_id}/acknowledge", response_class=HTMLResponse)
def post_acknowledge(alert_id: str, conn: Conn, user: PageUser, _: Tier1) -> HTMLResponse:
    try:
        decide.acknowledge(conn, alert_id, _actor(user))
    except decide.NotFound as exc:
        raise HTTPException(status_code=404, detail=_NOT_FOUND_TEXT) from exc
    except decide.DecisionConflict as exc:
        return _conflict_response(conn, alert_id, exc)
    return HTMLResponse(content=_decision_fragment(conn, alert_id))


@router.post("/alerts/{alert_id}/decide", response_class=HTMLResponse)
def post_decide(
    alert_id: str,
    conn: Conn,
    user: PageUser,
    _: Tier1,
    decision: Annotated[str, Form()],
    reason: Annotated[str, Form()],
    seen_occurrence_count: Annotated[int, Form()],
) -> HTMLResponse:
    try:
        reason = _reject_nul(reason, "reason")
        result = decide.decide(
            conn,
            alert_id,
            _actor(user),
            decision=decision,  # decide.decide validates against the two allowed literals
            reason=reason,
            seen_occurrence_count=seen_occurrence_count,
        )
    except decide.NotFound as exc:
        raise HTTPException(status_code=404, detail=_NOT_FOUND_TEXT) from exc
    except ValueError:
        return _value_error_response(conn, alert_id, "Lý do là bắt buộc (≤ 500 ký tự)")
    except decide.DecisionConflict as exc:
        return _conflict_response(conn, alert_id, exc)
    except psycopg.errors.QueryCanceled:
        return _query_canceled_response(conn, alert_id)

    text = f"Đã đóng cụm ({result['closed_count']} alert)"
    resp = HTMLResponse(content=_flash_fragment("info", text), status_code=200)
    resp.headers["HX-Redirect"] = "/queue"
    return resp


@router.post("/alerts/{alert_id}/escalate", status_code=201, response_class=HTMLResponse)
def post_escalate(
    alert_id: str,
    conn: Conn,
    cfg: Cfg,
    user: PageUser,
    _: Tier1,
    title: Annotated[str, Form()],
    severity: Annotated[str | None, Form()] = None,
) -> HTMLResponse:
    severity = severity or None
    try:
        title = _reject_nul(title, "title")
        if severity is not None and severity not in _SEVERITIES:
            raise ValueError(f"severity: must be one of {_SEVERITIES}")
        result = decide.escalate(conn, alert_id, _actor(user), title=title, severity=severity)
    except decide.NotFound as exc:
        raise HTTPException(status_code=404, detail=_NOT_FOUND_TEXT) from exc
    except ValueError as exc:
        return _value_error_response(conn, alert_id, str(exc))
    except decide.DecisionConflict as exc:
        return _conflict_response(conn, alert_id, exc)

    text = f"Đã mở case {result['case_id'][:8]}"
    if result["truncated"]:
        text += f" (cắt ở {cfg.MAX_ALERTS_PER_CASE} cụm)"
    resp = HTMLResponse(content=_flash_fragment("info", text), status_code=201)
    resp.headers["HX-Redirect"] = "/queue"
    return resp


@router.post("/alerts/{alert_id}/reopen", response_class=HTMLResponse)
def post_reopen(
    alert_id: str,
    conn: Conn,
    user: PageUser,
    _: Tier1,
    reason: Annotated[str, Form()],
) -> HTMLResponse:
    try:
        reason = _reject_nul(reason, "reason")
        decide.reopen(conn, alert_id, _actor(user), reason=reason)
    except decide.NotFound as exc:
        raise HTTPException(status_code=404, detail=_NOT_FOUND_TEXT) from exc
    except ValueError:
        return _value_error_response(conn, alert_id, "Lý do là bắt buộc (≤ 500 ký tự)")
    except decide.DecisionConflict as exc:
        return _conflict_response(conn, alert_id, exc)

    resp = HTMLResponse(content="", status_code=200)
    resp.headers["HX-Redirect"] = f"/alerts/{alert_id}"
    return resp
