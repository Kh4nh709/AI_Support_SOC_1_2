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
  not reimplemented here. **Review round 1, S3:** that JSON `403` is now unreachable
  from the UI — a non-tier1 viewer is never shown the controls that would post here in
  the first place (`_decision_form.html`'s own role gate) — kept as the belt to that
  braces for a hand-crafted request.

Every page goes through `page_user` first (a `303` to `/login`, never a JSON `401`);
`require_role("tier1")` is a second, later dependency on the four POSTs only, so an
unauthenticated request is redirected before role checking ever runs (the same
ordering `web/routers/admin_rules.py` uses for `page_user` + `require_role("admin")`).

**Review round 1 (REQUEST CHANGES) fixes in this revision:**
- B1: `alert.html` gets an empty `<div id="flash"></div>` placeholder *outside*
  `#decision` (an `outerHTML` swap of `#decision` would otherwise wipe an inner one) —
  the only way `_flash.html`'s `hx-swap-oob` fragment has anywhere to land, since the
  page's own `_flash.html` include renders nothing when `flash` is `None` (every GET
  here).
- S2: the success flash for `decide`/`escalate` travels as a query string on the
  `HX-Redirect` target instead of a dead-code response body (htmx navigates before any
  swap) — `queue_page` builds it from a fixed message table, interpolating only a
  digits-only `n` or an 8-hex `case`.
- S3: `_decision_form.html` renders the acknowledge/decide/escalate/reopen controls
  only for `user.role == "tier1"`, and the case link only for `tier2`/`admin` (a tier1
  viewer sees the short case id as plain text, never a link to a page tier1 cannot
  open).
- S4/S5: `queue.html`'s ① column and this module's `STATUS_LABELS` (now defined here
  and passed to both `alert.html` and `_decision_form.html`'s renders, review round 1's
  "deviation 2 is flipped" ruling).
- N6-N9: fixed Vietnamese `422` text (`_error_text`, never `str(exc)`), an HTML
  `alert_not_found.html` page instead of a bare `HTTPException` body, a NUL byte in the
  `{alert_id}` path segment rejected before any query, and the typed `reason` kept
  (escaped, by Jinja's autoescape) across a `409`/`422` re-render.
"""

from __future__ import annotations

import math
import re
from datetime import datetime
from typing import Annotated

import psycopg
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from app.infra.auth import Claims
from app.infra.config import Config
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

#: Review round 1, S5 ruling ("deviation 2 is flipped"): defined once here, passed to
#: *both* `alert.html`'s and `_decision_form.html`'s renders. `_decision_form.html` is
#: also rendered standalone (every HTMX partial response), where it has no parent
#: template to inherit a `{% set %}` from — so the label table has to live where every
#: caller already is, this module, not in a template.
STATUS_LABELS: dict[str, str] = {
    "received": "Đã nhận",
    "duplicate": "Bản sao",
    "enriching": "Đang làm giàu dữ liệu",
    "queued_tier1": "Chờ xử lý",
    "tier1_active": "Đang xử lý",
    "auto_closed": "Tự động đóng",
    "escalated_tier2": "Đã chuyển tier 2",
    "closed_fp": "Đã đóng — dương tính giả",
    "closed_benign": "Đã đóng — lành tính",
    "closed_confirmed": "Đã đóng — xác nhận sự cố",
}

#: Review round 1, S2: only these two `/queue?flash=` kinds exist; a digits-only `n`
#: and an 8-hex `case` (an `escalate`d case id is always `case_id[:8]` of a UUID, which
#: is always 8 hex characters) are the only values ever interpolated.
_DIGITS_RE = re.compile(r"^[0-9]+$")
_HEX8_RE = re.compile(r"^[0-9a-fA-F]{8}$")


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


def _nul_in_path(alert_id: str) -> bool:
    """Review round 1, nit N8: a NUL byte in the `{alert_id}` path segment can never
    match a real row — psycopg raises a driver-level error, not a clean 404, if one
    reaches a query. Checked before any call into `tier1.*` on all five routes that
    take `alert_id`."""
    return "\x00" in alert_id


def _error_text(exc: ValueError) -> str:
    """Review round 1, nit N6: a fixed Vietnamese sentence per `ValueError` shape,
    never `str(exc)` (English, and would echo the posted value verbatim back into the
    page). `web/routers/cases_pages.py`'s `_conclude_error_text` pattern. The NUL
    check runs first: `_reject_nul`'s own message also starts with the field name
    (`"reason: must not contain..."`), so it would otherwise match the field-specific
    branch below it instead of this one."""
    msg = str(exc)
    if "NUL byte" in msg:
        return "Dữ liệu chứa ký tự không hợp lệ."
    if msg.startswith("title:"):
        return "Tiêu đề không được để trống (tối đa 200 ký tự)."
    if msg.startswith("reason:"):
        return "Lý do là bắt buộc (≤ 500 ký tự)."
    if msg.startswith("decision:"):
        return "Quyết định không hợp lệ."
    if msg.startswith("severity:"):
        return "Mức độ nghiêm trọng không hợp lệ."
    return "Dữ liệu không hợp lệ."  # pragma: no cover — no other ValueError shape exists today


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


def _decision_fragment(
    conn: psycopg.Connection,
    alert_id: str,
    user: Claims,
    *,
    typed_reason: str | None = None,
) -> str:
    """Re-reads the alert's current view and re-renders `_decision_form.html` from
    it — called after every write (success or refusal) so the fragment a partial
    response returns always reflects what is now true in the database, never what
    was true when the request started (pitfall 1's "then re-read what you
    re-render"). `typed_reason` (review round 1, N9) carries the analyst's own
    unsaved text back into the re-rendered `reason`/reopen-reason textarea — Jinja's
    autoescape (on) covers it the same as every other value here.

    Review round 1, N9: `view is None` **is** reachable here, not
    unreachable — a `ValueError` this module raises itself (a bad `decision`/
    `severity`, or a NUL byte, via `_reject_nul` above) fires *before*
    `tier1/decide.py`'s own functions ever check whether `alert_id` exists, so a
    caller can reach this re-read with an `alert_id` that never existed at all."""
    view = queue.get_alert_view(conn, alert_id, mode="analyst")
    if view is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND_TEXT)
    return _render_fragment(
        "_decision_form.html",
        view=view,
        user=user,
        status_labels=STATUS_LABELS,
        typed_reason=typed_reason,
    )


def _conflict_text(body: dict, cfg: Config) -> str:
    """The flash sentence for one `DecisionConflict.body` (`tier1/decide.py`'s five
    `kind`s). `cluster_grew` is phase-6's own wording (P4-tasks.md planning decision
    10) verbatim. `already_decided` (review round 1, S5): the Vietnamese status label,
    not the raw enum, and `decided_at` formatted through `templating.local_time` at
    `cfg.DISPLAY_TZ` — `web/routers/cases_pages.py`'s conclude-conflict flash does the
    same for the same reason (a bare UTC ISO string is not what an analyst reads).
    The other three ("the kind in words") are this card's own phrasing — nothing
    those three refuse is destructive, so no exact wording was pinned."""
    kind = body["kind"]
    if kind == "cluster_grew":
        return (
            f"Cụm đã tăng từ {body['seen_occurrence_count']} lên {body['occurrence_count']} "
            f"bản sao trong lúc bạn đọc (chênh {body['delta']} > {body['tolerance']}) — "
            "xem lại rồi xác nhận"
        )
    if kind == "already_decided":
        what = STATUS_LABELS.get(body["decision"], body["decision"])
        when = body["decided_at"]
        if when is not None:
            when = templating.local_time(datetime.fromisoformat(when), cfg.DISPLAY_TZ)
        return f"Đã được {body['decided_by']} quyết {what} lúc {when}"
    if kind == "already_in_case":
        return "Alert đã thuộc một case khác — không thể escalate lại"
    if kind == "not_reopenable":
        return "Alert không ở trạng thái tự động đóng nên không mở lại được"
    return "Alert không còn ở trạng thái có thể thao tác — tải lại trang để xem hiện trạng"


def _conflict_response(
    conn: psycopg.Connection,
    alert_id: str,
    user: Claims,
    cfg: Config,
    exc: decide.DecisionConflict,
    *,
    typed_reason: str | None = None,
) -> HTMLResponse:
    """`conn.rollback()` before anything else — a returned fragment is a success as
    far as the real `get_conn` is concerned and would otherwise commit whatever the
    guard's own reads left behind (pitfall 1, mirroring `web/routers/tier1.py`'s
    `_conflict_response`)."""
    conn.rollback()
    body = _flash_fragment("error", _conflict_text(exc.body, cfg)) + _decision_fragment(
        conn, alert_id, user, typed_reason=typed_reason
    )
    return HTMLResponse(content=body, status_code=409)


def _value_error_response(
    conn: psycopg.Connection,
    alert_id: str,
    user: Claims,
    text: str,
    *,
    typed_reason: str | None = None,
) -> HTMLResponse:
    conn.rollback()
    body = _flash_fragment("error", text) + _decision_fragment(
        conn, alert_id, user, typed_reason=typed_reason
    )
    return HTMLResponse(content=body, status_code=422)


def _query_canceled_response(conn: psycopg.Connection, alert_id: str, user: Claims) -> HTMLResponse:
    conn.rollback()
    body = _flash_fragment("error", "Đóng cụm quá lâu, chưa ghi gì — thử lại") + _decision_fragment(
        conn, alert_id, user
    )
    return HTMLResponse(content=body, status_code=503)


def _queue_flash(
    flash: str | None, n: str | None, case: str | None, cut: str | None, cfg: Config
) -> dict[str, str] | None:
    """Review round 1, S2: `HX-Redirect`'s response body is dead code — htmx
    navigates before it ever processes a swap, so the confirmation instead travels as
    a query string on the redirect target, and `/queue` builds the flash from a fixed
    message table keyed on `flash`. Only a digits-only `n` and an 8-hex `case` are
    ever interpolated into that fixed text; anything else — an unknown `flash` kind,
    or a malformed `n`/`case` — drops the whole flash rather than showing a broken or
    attacker-controlled one (a `?flash=<script>` never reaches the page at all, not
    even escaped)."""
    if flash == "closed":
        if n is None or not _DIGITS_RE.match(n):
            return None
        return {"level": "info", "text": f"Đã đóng cụm ({n} alert)"}
    if flash == "escalated":
        if case is None or not _HEX8_RE.match(case):
            return None
        text = f"Đã mở case {case}"
        if cut == "1":
            text += f" (cắt ở {cfg.MAX_ALERTS_PER_CASE} cụm)"
        return {"level": "info", "text": text}
    return None


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
    flash: Annotated[str | None, Query()] = None,
    n: Annotated[str | None, Query()] = None,
    case: Annotated[str | None, Query()] = None,
    cut: Annotated[str | None, Query()] = None,
) -> HTMLResponse:
    result = queue.list_queue(conn, page=page)
    return templating.render(
        request,
        "queue.html",
        user=user,
        page=result,
        tz=cfg.DISPLAY_TZ,
        total_pages=_total_pages(result.total, result.page_size),
        flash=_queue_flash(flash, n, case, cut, cfg),
    )


@router.get("/alerts/{alert_id}", response_class=HTMLResponse)
def alert_detail_page(
    alert_id: str, request: Request, conn: Conn, cfg: Cfg, user: PageUser
) -> HTMLResponse:
    view = None if _nul_in_path(alert_id) else queue.get_alert_view(conn, alert_id, mode="analyst")
    if view is None:
        # Review round 1, nit N7: an HTML page through the same `templating.render`
        # path every other page uses, never a bare `HTTPException`'s JSON body.
        page = templating.render(request, "alert_not_found.html", user=user)
        page.status_code = 404
        return page
    return templating.render(
        request,
        "alert.html",
        user=user,
        view=view,
        tz=cfg.DISPLAY_TZ,
        correlated_now=view["correlated_now"],
        status_labels=STATUS_LABELS,
    )


# ---------------------------------------------------------------------------
# The four HTMX partials — tier1 only
# ---------------------------------------------------------------------------


@router.post("/alerts/{alert_id}/acknowledge", response_class=HTMLResponse)
def post_acknowledge(alert_id: str, conn: Conn, cfg: Cfg, user: PageUser, _: Tier1) -> HTMLResponse:
    if _nul_in_path(alert_id):
        raise HTTPException(status_code=404, detail=_NOT_FOUND_TEXT)
    try:
        decide.acknowledge(conn, alert_id, _actor(user))
    except decide.NotFound as exc:
        raise HTTPException(status_code=404, detail=_NOT_FOUND_TEXT) from exc
    except decide.DecisionConflict as exc:
        return _conflict_response(conn, alert_id, user, cfg, exc)
    return HTMLResponse(content=_decision_fragment(conn, alert_id, user))


@router.post("/alerts/{alert_id}/decide", response_class=HTMLResponse)
def post_decide(
    alert_id: str,
    conn: Conn,
    cfg: Cfg,
    user: PageUser,
    _: Tier1,
    decision: Annotated[str, Form()],
    reason: Annotated[str, Form()],
    seen_occurrence_count: Annotated[int, Form()],
) -> HTMLResponse:
    if _nul_in_path(alert_id):
        raise HTTPException(status_code=404, detail=_NOT_FOUND_TEXT)
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
    except ValueError as exc:
        return _value_error_response(conn, alert_id, user, _error_text(exc), typed_reason=reason)
    except decide.DecisionConflict as exc:
        return _conflict_response(conn, alert_id, user, cfg, exc, typed_reason=reason)
    except psycopg.errors.QueryCanceled:
        return _query_canceled_response(conn, alert_id, user)

    # Review round 1, S2: the confirmation travels on the redirect target, not in
    # this response's body (htmx navigates before it ever processes a swap here).
    resp = HTMLResponse(content="", status_code=200)
    resp.headers["HX-Redirect"] = f"/queue?flash=closed&n={result['closed_count']}"
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
    if _nul_in_path(alert_id):
        raise HTTPException(status_code=404, detail=_NOT_FOUND_TEXT)
    severity = severity or None
    try:
        title = _reject_nul(title, "title")
        if severity is not None and severity not in _SEVERITIES:
            raise ValueError(f"severity: must be one of {_SEVERITIES}")
        result = decide.escalate(conn, alert_id, _actor(user), title=title, severity=severity)
    except decide.NotFound as exc:
        raise HTTPException(status_code=404, detail=_NOT_FOUND_TEXT) from exc
    except ValueError as exc:
        return _value_error_response(conn, alert_id, user, _error_text(exc))
    except decide.DecisionConflict as exc:
        return _conflict_response(conn, alert_id, user, cfg, exc)

    redirect = f"/queue?flash=escalated&case={result['case_id'][:8]}"
    if result["truncated"]:
        redirect += "&cut=1"
    resp = HTMLResponse(content="", status_code=201)
    resp.headers["HX-Redirect"] = redirect
    return resp


@router.post("/alerts/{alert_id}/reopen", response_class=HTMLResponse)
def post_reopen(
    alert_id: str,
    conn: Conn,
    cfg: Cfg,
    user: PageUser,
    _: Tier1,
    reason: Annotated[str, Form()],
) -> HTMLResponse:
    if _nul_in_path(alert_id):
        raise HTTPException(status_code=404, detail=_NOT_FOUND_TEXT)
    try:
        reason = _reject_nul(reason, "reason")
        decide.reopen(conn, alert_id, _actor(user), reason=reason)
    except decide.NotFound as exc:
        raise HTTPException(status_code=404, detail=_NOT_FOUND_TEXT) from exc
    except ValueError as exc:
        return _value_error_response(conn, alert_id, user, _error_text(exc), typed_reason=reason)
    except decide.DecisionConflict as exc:
        return _conflict_response(conn, alert_id, user, cfg, exc, typed_reason=reason)

    resp = HTMLResponse(content="", status_code=200)
    resp.headers["HX-Redirect"] = f"/alerts/{alert_id}"
    return resp
