"""`web/routers/admin_digest.py` — the admin digest API (P5-T09, P11-T07, spec §4.5 and §5.6):
`GET /api/admin/digest?day=` and `POST /api/admin/digest/{alert_id}/review`, over P5-T08's
`app.tier1.digest` (`build`, `review`), for the React digest page. The Jinja page and its HTMX
partial this module also served (`GET /admin/digest` and `POST /admin/digest/{alert_id}/review`)
were retired in P11-T19 (spec §8, DEC-205); nothing here renders HTML.

All logic is `app.tier1.digest` (`build`, `review`); this module writes no SQL of its own. It
needs a few small reads that live there: `review_details`, `rules_enabled`, `left_digest_on`,
`reopened_by_review` and `build(alert_id=)`.

**Days are local (P5-T08 review round 1 · S4).** `build` takes `day` as a date string in
`cfg.DISPLAY_TZ`, and the day's bounds are that zone's local midnights. **The default day is
today** in `DISPLAY_TZ` (spec §5.6), and `today` is returned beside `day` so the UI can offer
both it and yesterday, the day the 08:00 job reviews.

- **A day is `YYYY-MM-DD` and nothing else** (`_strict_day`): `date.fromisoformat` also takes
  `20260930` and `2026-W40-3`, which the API does not. A bad day is
  `422 {"detail": {"reason": "bad_day"}}`, answered before any SQL; the UI falls back by itself.
- **Errors are objects with a `reason`** (spec §3), never text from the driver: `bad_day`,
  `{"field": "verdict", "reason": "invalid"}`, `not_in_digest` (404), `already_reviewed` (409,
  with the row as it now stands) and `not_auto_closed` (409).
- **A review needs the alert on that day's digest** (`build(day)`), so a stale or forged
  `{day}` cannot review an alert of another day. A row reopened by Tier 1 or by a `wrong`
  review leaves `build` the moment it is reopened, and that is exactly what a stale page
  sends, so one case off the digest is the conflict the page maps to "no longer auto-closed"
  (`409 not_auto_closed`): an alert that is not synthetic, that a rule auto-closed
  (`autoclose_rule_id` set), whose `alert.auto_closed` audit event falls inside the posted
  day's bounds in `DISPLAY_TZ`, and that is now in another status (`digest.left_digest_on`).
  Everything else off the digest (unknown, synthetic, never auto-closed, closed on another
  day) is `404 not_in_digest`.
- **The list keeps the alerts a digest review reopened.** `build` reads `status =
  'auto_closed'`, so an alert reviewed "Sai" (reopened by `digest.review`) would leave the
  next refetch with its verdict, its reviewer and the "đã mở lại về hàng đợi Tier 1" note, and
  the day's counts would drop. The GET therefore also lists, beside `build`'s rows,
  `digest.reopened_by_review(day)`: an `autoclose_reviews` row with verdict `wrong`, an alert
  no longer `auto_closed`, not synthetic, whose `alert.auto_closed` event falls on that day.
  Each row carries `reopened_by_review` (true for these, false for every other); the page
  counts clusters, reviewed and waiting from the rows, so they are still counted. An alert
  reopened by Tier 1 without a digest review, or reviewed `correct`/`unsure` and then reopened,
  leaves the list as before. It lives here, not in `digest.build`, so `build` is unchanged.
- **A POST reads one alert, not the day.** `digest.build` and `digest.reopened_by_review`
  take `alert_id`, so the cost of a review does not grow with the day's rows (it was one
  `latest_suggestion` query per row, twice).
- **A conflict is raised, not returned.** `digest.review` is one savepoint, so a refused review
  has written nothing, and `deps.get_conn` rolls the request back on the `HTTPException`.
- **The body is a Pydantic model**, so FastAPI's strict content-type rule applies: a form or a
  `text/plain` post is not parsed as JSON and is a 422. Its two fields are read as `Any` and
  judged by the route, so a missing or mistyped `day` or `verdict` gets the same `reason` as a
  wrong one, not FastAPI's error list.
- **The row after a `wrong` review** is the row the list shows next (`reopened_by_review` true,
  the recorded verdict, reviewer and time), read after the review with the same `alert_id` reads.
"""

from __future__ import annotations

import dataclasses
import re
from datetime import date, datetime
from typing import Annotated, Any
from zoneinfo import ZoneInfo

import psycopg
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.domain.transitions import StaleState
from app.infra.auth import Claims
from app.tier1 import digest
from app.web.deps import AlertId, Cfg, Conn, require_role

router = APIRouter()

#: One dependency object, so `Depends` resolves it once per request — the
#: same shape `labels.py`/`admin_rules.py` use.
require_admin = require_role("admin")
Admin = Annotated[Claims, Depends(require_admin)]

_VERDICT_LABEL = {"correct": "Đúng", "wrong": "Sai", "unsure": "Không chắc"}

# ---------------------------------------------------------------------------
# Small seams — "now, in the display zone" is read from the process clock
# (this module writes no SQL of its own, so it cannot ask the database for
# `now()` the way `tier1/digest.py`'s own CLI does); `_now_local` is the one
# place a test replaces it.
# ---------------------------------------------------------------------------


def _now_local(tz: str) -> datetime:
    return datetime.now(ZoneInfo(tz))


def _today_local(tz: str) -> str:
    return _now_local(tz).date().isoformat()


# ---------------------------------------------------------------------------
# The JSON API (P11-T07) — see the module docstring for the rules it follows
# ---------------------------------------------------------------------------

#: `YYYY-MM-DD`, ASCII digits only; `fullmatch`, so a trailing newline is not a day.
_DAY_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def _strict_day(raw: object) -> str | None:
    """`raw` as a calendar day in exactly the form `YYYY-MM-DD`, or `None`: never raises. It
    refuses the other ISO 8601 spellings `date.fromisoformat` accepts (`20260930`, `2026-W40-3`)."""
    if not isinstance(raw, str) or _DAY_RE.fullmatch(raw) is None:
        return None
    try:
        return date.fromisoformat(raw).isoformat()
    except ValueError:  # 2026-02-30, month 13, year 0000
        return None


def _refuse(status_code: int, reason: str, **extra: Any) -> HTTPException:
    """The body is `{"detail": {"reason": ..., **extra}}` (spec §3). Fixed codes only: nothing
    from an exception, a query or the configuration goes into it."""
    return HTTPException(status_code=status_code, detail={"reason": reason, **extra})


class DigestRowOut(BaseModel):
    """`digest.DigestRow`, field for field, plus the review on file: who (`users.display_name`,
    else the username) and when, both `None` while the row is unreviewed, and
    `reopened_by_review`: true for an alert a digest review ("Sai") reopened, which the list
    keeps (see `_day_rows`), false for every other row."""

    alert_id: str
    rule_id: str
    description: str
    severity: str
    category: str
    agent_name: str
    occurrence_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    autoclose_rule_id: str | None
    autoclose_rule_name: str | None
    suggested_action: str | None
    disagreement: bool
    reviewed_verdict: str | None
    reviewed_by_name: str | None
    reviewed_at: datetime | None
    reopened_by_review: bool

    @classmethod
    def of(
        cls, row: digest.DigestRow, info: digest.ReviewInfo | None, *, reopened: bool = False
    ) -> DigestRowOut:
        return cls(
            **dataclasses.asdict(row),
            reviewed_by_name=None if info is None else info.reviewer_name,
            reviewed_at=None if info is None else info.reviewed_at,
            reopened_by_review=reopened,
        )


class DigestOut(BaseModel):
    day: str
    today: str
    rules_enabled: bool
    rows: list[DigestRowOut]


class ReviewIn(BaseModel):
    """`day` and `verdict` are `Any` on purpose: the route judges them, so the answer for a
    missing, mistyped or wrong value is one `reason`, whichever it is."""

    day: Any = None
    verdict: Any = None


class ReviewOut(BaseModel):
    row: DigestRowOut
    reopened: bool


def _day_rows(
    conn: psycopg.Connection, day: str, tz: str, alert_id: str | None = None
) -> list[tuple[digest.DigestRow, bool]]:
    """The day's rows with their `reopened_by_review` flag: `build`'s (auto-closed that day,
    flag false) and the alerts a digest review reopened (`digest.reopened_by_review`, flag
    true), in `build`'s order. Spec §4.5: after a review the row shows the verdict, the
    reviewer and, for "Sai", that it was reopened; the row has to survive a refetch and a
    reload, so it stays on the list. `alert_id` narrows both reads to one alert, so a POST
    costs a constant number of statements however big the day is."""
    rows = [(r, False) for r in digest.build(conn, day, tz=tz, alert_id=alert_id)]
    rows += [(r, True) for r in digest.reopened_by_review(conn, day, tz=tz, alert_id=alert_id)]
    rows.sort(
        key=lambda pair: (not pair[0].disagreement, -pair[0].occurrence_count, pair[0].alert_id)
    )
    return rows


@router.get("/api/admin/digest")
def api_digest(conn: Conn, cfg: Cfg, claims: Admin, day: str | None = None) -> DigestOut:
    tz = cfg.DISPLAY_TZ
    today = _today_local(tz)
    # `?day=` present but empty is a bad day, not "the default": only an absent one defaults.
    resolved = today if day is None else _strict_day(day)
    if resolved is None:
        raise _refuse(422, "bad_day")
    rows = _day_rows(conn, resolved, tz)
    infos = digest.review_details(conn, [r.alert_id for r, _ in rows if r.reviewed_verdict])
    return DigestOut(
        day=resolved,
        today=today,
        rules_enabled=digest.rules_enabled(conn),
        rows=[DigestRowOut.of(r, infos.get(r.alert_id), reopened=flag) for r, flag in rows],
    )


def _row_now(
    conn: psycopg.Connection, day: str, tz: str, alert_id: str, snapshot: digest.DigestRow
) -> DigestRowOut:
    """`alert_id`'s row as the database has it now, with its review: the row the list shows
    (`_day_rows`, one alert), so after a `wrong` review that is the reopened row. Only when
    neither read has it (an alert reviewed `correct` and since reopened by Tier 1, say) does it
    come from `snapshot`, read before the review, with the verdict on file."""
    info = digest.review_details(conn, [alert_id]).get(alert_id)
    listed = _day_rows(conn, day, tz, alert_id)
    if listed:
        row, reopened = listed[0]
    else:
        # The snapshot was read while the alert was auto-closed (decided, so ① shown); the alert
        # may be blind and undecided again by now (a reopen landed between), and a response
        # carries no suggestion for such an alert (DEC-101, P11-T20 part 4).
        row = digest.withhold_if_blind(conn, snapshot)
        reopened = info is not None and info.verdict == "wrong"
    if info is not None and row.reviewed_verdict != info.verdict:
        row = dataclasses.replace(row, reviewed_verdict=info.verdict)
    return DigestRowOut.of(row, info, reopened=reopened)


@router.post("/api/admin/digest/{alert_id}/review")
def api_review(conn: Conn, cfg: Cfg, claims: Admin, alert_id: AlertId, body: ReviewIn) -> ReviewOut:
    tz = cfg.DISPLAY_TZ
    day = _strict_day(body.day)
    if day is None:
        raise _refuse(422, "bad_day")
    verdict = body.verdict
    if not isinstance(verdict, str) or verdict not in _VERDICT_LABEL:
        raise _refuse(422, "invalid", field="verdict")

    found = digest.build(conn, day, tz=tz, alert_id=alert_id)
    if not found:
        # Not on that day's digest. The stale-page conflict is exactly an alert a rule
        # auto-closed on that day that has since left `auto_closed` (module docstring); anything
        # else (unknown, synthetic, never auto-closed, closed on another day) is a 404.
        if digest.left_digest_on(conn, alert_id, day, tz=tz):
            raise _refuse(409, "not_auto_closed")
        raise _refuse(404, "not_in_digest")
    before = found[0]

    try:
        digest.review(conn, alert_id, verdict, reviewer_id=claims.user_id)
    except digest.AlreadyReviewed as exc:
        # `review`'s savepoint is rolled back: nothing was written. The row is read again, so
        # it carries the review that is on file, not the one this request tried to add.
        row = _row_now(conn, day, tz, alert_id, before)
        raise _refuse(409, "already_reviewed", row=row.model_dump(mode="json")) from exc
    except StaleState as exc:
        raise _refuse(409, "not_auto_closed") from exc
    return ReviewOut(row=_row_now(conn, day, tz, alert_id, before), reopened=verdict == "wrong")
