"""`web/routers/admin_digest.py` — the admin digest page (P5-T09, DEC-151 wave
3): `GET /admin/digest` and the HTMX partial behind
`POST /admin/digest/{alert_id}/review`, over P5-T08's `app.tier1.digest`.

All logic is `app.tier1.digest` (`build`, `review`) and `app.ingest.autoclose`
(`load_rules`, read-only, for the two-empty-states distinction); this module
writes no SQL of its own (scope out — `tier1/digest.py` is not edited here).

**Days are local (P5-T08 review round 1 · S4).** `build`/`unreviewed_count`
take `day` as a date string in `cfg.DISPLAY_TZ`. The default day is
**yesterday** in that zone — the 08:00-local job reviews yesterday, so that
is what a reviewer opening this page without a `?day=` cold expects to
clear. `?day=YYYY-MM-DD` picks any day; a link to today (so far) is always
shown. A malformed `?day=` never 4xx's the page itself (nit 8): it falls
back to the default day and says so in a flash — this is a page, and a page
answers with HTML, never a bare JSON error body.

**`wrong` reopens the alert, and `build()` stops listing it** (it only shows
`auto_closed` rows). The re-rendered row for a successful `Sai` therefore
cannot come from a fresh `build()` call — it is built from the pre-review
snapshot (`before`, read at the top of `review_submit`, before anything is
mutated) plus the verdict, exactly as the card's deviation note directs.
The "đã mở lại..." note is keyed on an explicit `reopened` flag set only by
*this* success path (review round 1, nit 10) — never on
`row.reviewed_verdict == "wrong"` alone, which can be a stale historical
verdict on a cluster that auto-closed again after being reopened (P5-T08's
own recorded limit: `autoclose_reviews` is keyed on `alert_id` alone).

**A 409 is a normal outcome** (`StaleState`/`AlreadyReviewed` from
`digest.review`): `conn.rollback()` first — a returned response is a success
as far as `get_conn` is concerned and would otherwise commit whatever the
guard itself read (P4-T03's `_conflict_response` shape, `web/routers/tier1.py`)
— then the row is re-read from the database before it is re-rendered, never
served from the pre-call snapshot, so two reviewers racing the same row see
the row the way it actually ended up, not the way either of them last saw
it. When neither the re-read nor the pre-call snapshot has any cosmetic data
left for the alert (review round 1, should-4), the row renders as one wide
cell naming the id and the conflict — never a fake-looking row of blank
cells and a "Số lần 0" that reads as real (but wrong) data.
"""

from __future__ import annotations

import dataclasses
from datetime import date, datetime, timedelta
from typing import Annotated
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse

from app.domain.transitions import StaleState
from app.infra.auth import Claims
from app.ingest import autoclose
from app.tier1 import digest
from app.web import templating
from app.web.deps import Cfg, Conn, require_role
from app.web.routers.pages import page_user

router = APIRouter()

#: One dependency object, so `Depends` resolves it once per request — the
#: same shape `labels.py`/`admin_rules.py` use.
require_admin = require_role("admin")
Admin = Annotated[Claims, Depends(require_admin)]

_VERDICT_LABEL = {"correct": "Đúng", "wrong": "Sai", "unsure": "Không chắc"}

_ALREADY_REVIEWED_TEXT = "Cụm này đã được duyệt trước đó"
_STALE_STATE_TEXT = "Cụm không còn ở trạng thái tự đóng"
_REOPENED_CLAUSE = "đã mở lại về hàng đợi Tier 1"
_DAY_INVALID_TEXT = "Ngày không hợp lệ — phải có dạng YYYY-MM-DD"
_VERDICT_INVALID_TEXT = "Đánh giá không hợp lệ"
#: The row's own wide-cell text on a conflict with no cosmetic data left to
#: show (should-4) — the same clause the flash carries, so the row and the
#: flash agree.
_CONFLICT_ROW_TEXT = "trạng thái đã thay đổi — tải lại trang"

_ROW_TEMPLATE = "_digest_row.html"
_ROW_COLUMNS = 10  # autoclose_rule_name, rule_id, description, severity, category,
# agent_name, occurrence_count, span, suggested_action, verdict (nit 9's split)


# ---------------------------------------------------------------------------
# Small seams — "now, in the display zone" is read from the process clock
# (this page writes no SQL of its own, so it cannot ask the database for
# `now()` the way `tier1/digest.py`'s own CLI does); `_now_local` is the one
# place a test replaces it.
# ---------------------------------------------------------------------------


def _now_local(tz: str) -> datetime:
    return datetime.now(ZoneInfo(tz))


def _today_local(tz: str) -> str:
    return _now_local(tz).date().isoformat()


def _yesterday_local(tz: str) -> str:
    return (_now_local(tz) - timedelta(days=1)).date().isoformat()


def _parse_day(raw: str) -> str | None:
    """`raw` as a normalised `YYYY-MM-DD`, or `None` if it is not one — never
    raises. Every caller decides for itself what "not a valid day" means for
    its own response (review round 1, nit 8): the page falls back and says
    so in a flash; a row POST answers 422 with the row plus a flash. Neither
    is a bare JSON error body."""
    try:
        return date.fromisoformat(raw).isoformat()
    except ValueError:
        return None


def _find(rows: list[digest.DigestRow], alert_id: str) -> digest.DigestRow | None:
    return next((r for r in rows if r.alert_id == alert_id), None)


_BLANK_ROW_FIELDS = {
    "rule_id": "",
    "description": "",
    "severity": "",
    "category": "",
    "agent_name": "",
    "occurrence_count": 0,
    "first_seen_at": None,
    "last_seen_at": None,
    "autoclose_rule_id": None,
    "autoclose_rule_name": None,
    "suggested_action": None,
    "disagreement": False,
}


def _blank_row(alert_id: str, *, reviewed_verdict: str | None) -> digest.DigestRow:
    """A placeholder for the rare case neither a fresh re-read nor the
    pre-call snapshot has any cosmetic data for `alert_id` — a hardcoded or
    stale id, or the wrong `day` was posted, not a real race. Always
    rendered with `blank=True` (never the normal nine data cells): review
    round 1, should-4 — a row of empty cells and a "Số lần 0" reads as real
    (if odd) data, not as the conflict it actually is."""
    return digest.DigestRow(
        alert_id=alert_id, reviewed_verdict=reviewed_verdict, **_BLANK_ROW_FIELDS
    )


def _render_row(
    row: digest.DigestRow,
    *,
    day: str,
    tz: str,
    conflict: bool = False,
    blank: bool = False,
    reopened: bool = False,
) -> str:
    return templating.templates.get_template(_ROW_TEMPLATE).render(
        row=row,
        day=day,
        tz=tz,
        verdict_labels=_VERDICT_LABEL,
        conflict=conflict,
        blank=blank,
        reopened=reopened,
        conflict_text=_CONFLICT_ROW_TEXT,
        colspan=_ROW_COLUMNS,
    )


def _render_flash(flash: dict[str, str]) -> str:
    return templating.templates.get_template("_flash.html").render(flash=flash)


def _fragment(
    row: digest.DigestRow,
    flash: dict[str, str],
    *,
    day: str,
    tz: str,
    conflict: bool,
    status_code: int,
    blank: bool = False,
    reopened: bool = False,
) -> HTMLResponse:
    body = _render_row(
        row, day=day, tz=tz, conflict=conflict, blank=blank, reopened=reopened
    ) + _render_flash(flash)
    return HTMLResponse(content=body, status_code=status_code)


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


def _page(
    request: Request,
    conn: Conn,
    cfg: Cfg,
    user: Claims,
    *,
    day: str,
    flash: dict[str, str] | None = None,
) -> HTMLResponse:
    tz = cfg.DISPLAY_TZ
    rows = digest.build(conn, day, tz=tz)
    return templating.render(
        request,
        "digest.html",
        user=user,
        flash=flash,
        tz=tz,
        day=day,
        today=_today_local(tz),
        rows=rows,
        # review round 1's blocker: rows first. A rule that closed clusters
        # earlier today and was then disabled must never hide those rows —
        # `rules_exist` (design note 1's *other* empty state) is consulted
        # by the template only when `rows` is itself empty.
        rules_exist=bool(autoclose.load_rules(conn)),
        verdict_labels=_VERDICT_LABEL,
    )


@router.get("/admin/digest", response_class=HTMLResponse)
def digest_page(
    request: Request,
    conn: Conn,
    cfg: Cfg,
    user: Annotated[Claims, Depends(page_user)],
    _: Admin,
    day: str | None = None,
) -> HTMLResponse:
    tz = cfg.DISPLAY_TZ
    flash: dict[str, str] | None = None
    if day:
        resolved_day = _parse_day(day)
        if resolved_day is None:
            resolved_day = _yesterday_local(tz)
            flash = {"level": "error", "text": f"{_DAY_INVALID_TEXT} — hiển thị {resolved_day}"}
    else:
        resolved_day = _yesterday_local(tz)
    return _page(request, conn, cfg, user, day=resolved_day, flash=flash)


@router.post("/admin/digest/{alert_id}/review", response_class=HTMLResponse)
def review_submit(
    request: Request,
    conn: Conn,
    cfg: Cfg,
    user: Annotated[Claims, Depends(page_user)],
    _: Admin,
    alert_id: str,
    day: Annotated[str, Form()],
    verdict: Annotated[str, Form()],
) -> HTMLResponse:
    del request  # the fragment needs no page-level context (no `{% extends %}`)
    if "\x00" in alert_id:
        # review round 1, nit 7: a NUL byte can never name a real alert_id
        # (Postgres text columns cannot hold one) — 404, matching P4-T05's
        # merged pages, never a raw 500 from psycopg rejecting it later.
        raise HTTPException(status_code=404)
    tz = cfg.DISPLAY_TZ

    parsed_day = _parse_day(day)
    if parsed_day is None:
        flash = {"level": "error", "text": _DAY_INVALID_TEXT}
        return _fragment(
            _blank_row(alert_id, reviewed_verdict=None),
            flash,
            day=day,
            tz=tz,
            conflict=True,
            blank=True,
            status_code=422,
        )
    day = parsed_day

    before = _find(digest.build(conn, day, tz=tz), alert_id)

    if verdict not in _VERDICT_LABEL:
        flash = {"level": "error", "text": _VERDICT_INVALID_TEXT}
        blank = before is None
        row = before if not blank else _blank_row(alert_id, reviewed_verdict=None)
        return _fragment(row, flash, day=day, tz=tz, conflict=blank, blank=blank, status_code=422)

    try:
        digest.review(conn, alert_id, verdict, user.user_id)
    except StaleState as exc:
        # Known pitfall 1: a *returned* 409 is a success as far as `get_conn`
        # is concerned and would otherwise commit whatever the guard itself
        # read. Roll back first, then re-read — never render the pre-call
        # snapshot as if it were still current (design note 4).
        conn.rollback()
        text = (
            _ALREADY_REVIEWED_TEXT if isinstance(exc, digest.AlreadyReviewed) else _STALE_STATE_TEXT
        )
        flash = {"level": "error", "text": text}
        after = _find(digest.build(conn, day, tz=tz), alert_id)
        if after is not None:
            # Still `auto_closed` (an *earlier* review by someone else won
            # the race) — the re-read row carries their verdict.
            return _fragment(after, flash, day=day, tz=tz, conflict=False, status_code=409)
        if before is not None:
            # No longer `auto_closed` at all (e.g. reopened by a `wrong`
            # review elsewhere) — `build()` cannot show it; fall back to the
            # pre-call cosmetic snapshot, buttons suppressed.
            return _fragment(before, flash, day=day, tz=tz, conflict=True, status_code=409)
        # Neither snapshot has it — a hardcoded/wrong alert_id, or the wrong
        # `day` was posted. No cosmetic data exists to show (should-4).
        return _fragment(
            _blank_row(alert_id, reviewed_verdict=None),
            flash,
            day=day,
            tz=tz,
            conflict=True,
            blank=True,
            status_code=409,
        )

    if verdict == "wrong":
        # `build()` only lists `auto_closed` rows; `wrong` just reopened this
        # one (queued_tier1), so it is gone from a fresh `build()`. Render
        # from the pre-call snapshot plus the verdict instead (card deviation).
        blank = before is None
        row = (
            dataclasses.replace(before, reviewed_verdict="wrong")
            if not blank
            else _blank_row(alert_id, reviewed_verdict="wrong")
        )
        flash_text = f"Đã ghi nhận: {_VERDICT_LABEL['wrong']} — {_REOPENED_CLAUSE}"
        return _fragment(
            row,
            {"level": "info", "text": flash_text},
            day=day,
            tz=tz,
            conflict=False,
            blank=blank,
            # review round 1, nit 10: `reopened` is this call's own flag, set
            # only on this success path — never derived from
            # `reviewed_verdict == "wrong"`, which can be a stale verdict
            # from a cluster that auto-closed again after being reopened.
            reopened=True,
            status_code=200,
        )

    row = _find(digest.build(conn, day, tz=tz), alert_id)
    blank = row is None
    if blank:  # practically unreachable — review() just proved it auto_closed
        row = _blank_row(alert_id, reviewed_verdict=verdict)
    flash_text = f"Đã ghi nhận: {_VERDICT_LABEL[verdict]}"
    return _fragment(
        row,
        {"level": "info", "text": flash_text},
        day=day,
        tz=tz,
        conflict=False,
        blank=blank,
        status_code=200,
    )
