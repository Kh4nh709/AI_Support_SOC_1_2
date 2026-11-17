"""`web/routers/ti.py` — the Threat Intel API (DEC-224 T3, spec 2026-11-17 §7): read-only routes over `ti_ioc` and `ti_import_log`.
All the SQL and the two export formats are `app.ti.queries`; this module reads the request, checks the role, bounds every input and
shapes the answer. `iter_routers()` discovers it.

    GET /api/ti/iocs      200 {rows: [ioc], total, page, page_size}
    GET /api/ti/stats     200 {days, today, sources, by_day, top_malware, high_confidence, matched_in_logs, imported_today,
                               newest_malware}
    GET /api/ti/lookup    200 {value, rows: [ioc], total}
    GET /api/ti/status    200 {latest, latest_success, stale, stale_after_hours}
    GET /api/ti/export    200 text/csv or text/plain, admin only; 422 {"detail": {"field": "filters", "reason": "too_many_rows", "limit"}}

Any of them: 503 {"detail": {"reason": "timeout"}} when a read outlives its statement timeout.

Signed-in users only, the Bearer token as every `/api` route: `tier1`, `tier2` and `admin` read, `admin` alone exports (a refusal is a
`403` and an `authz.denied` event, as `deps.require_role` writes it; no token is a `401`). The role is checked before the inputs: a
caller of the wrong role gets the `403` whatever they sent. Nothing here writes a row.

**The inputs are bounded and a bad one is the app's usual `422`**, never a `500`: `page` 1..1 000 000, `page_size` 1..200 (default
50), `days` 1..30 (default 30, the retention window: see `queries.DAYS_MAX`), `min_confidence` 0..100, `source` one of the three, `expired` a boolean, `q` at most 128
characters (a substring search over four columns: a whole URL belongs to the lookup), `value` of the lookup at most 2 048 (the
importer's bound on a value), `malware` 256, `type` 64, `from` / `to` at most 64 characters and a date or an ISO time
(`queries.parse_bound`: a date, or a time with no offset, is read in GMT+7). `to` is inclusive in both forms: a date `to` takes in
its whole day, and a `to` with a time is inclusive to the instant given, to the microsecond (`to=…T08:30:00Z` keeps a row at
08:30:00.000000 and drops one at 08:30:00.000001). The page sends dates. A NUL or a lone surrogate in a
text is refused (the database cannot hold one). Nothing in a request chooses a sort column or a direction: the order is fixed.

**Every read runs under a statement timeout** (`queries.STATEMENT_TIMEOUT`, 5 s, `SET LOCAL`: it is set for the transaction of the
request and dies with it). A statement that outlives it is cancelled and the route answers `503 {"detail": {"reason": "timeout"}}`,
the project's own shape for a read that timed out (`admin_audit.py`): no driver text, no SQL, never a `500`. `infra/db.transaction()`
is NOT used, as in the other routers: it issues its own BEGIN and COMMIT, which would end the transaction `deps.Conn` owns.

An IOC value is DATA. The routes return it as it is stored; they never build a link from it and never fetch, resolve or preview
anything (this module imports no networking at all, which a test pins).

The export is a download: the CSV starts with a UTF-8 byte order mark (so Excel reads UTF-8; the first header cell is still `id`)
and every cell is guarded against a formula; the blocklist carries only addresses and names that are safe to block (see
`queries.NEVER_BLOCK_V4`, `GLOBAL_UNICAST_V6`, `NEVER_BLOCK_V6_WITHIN_GLOBAL`, `NEVER_BLOCK_NAME_ENDINGS`, and a name's last label
must be a real top-level label).

The route is a plain `def`, which FastAPI runs in a worker thread. `get_clock` is the clock of every route (a dependency, so a test
moves it): expiry, "today" and `stale` are all judged against it.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import AfterValidator

from app.infra.auth import Claims
from app.infra.storable import is_storable
from app.ti import queries
from app.web.deps import Conn, require_role

router = APIRouter()
logger = logging.getLogger(__name__)

Reader = Annotated[Claims, Depends(require_role("tier1", "tier2", "admin"))]
Admin = Annotated[Claims, Depends(require_role("admin"))]

Source = Literal["threatfox", "urlhaus", "malwarebazaar"]

#: The fixed names of a download: nothing of the request is in them.
CSV_FILE = "threat-intel-iocs.csv"
BLOCKLIST_FILE = "threat-intel-blocklist.txt"


def get_clock() -> Callable[[], datetime]:
    """The clock of the routes; the real one reads the wall clock. A test overrides this dependency."""
    return lambda: datetime.now(UTC)


Clock = Annotated[Callable[[], datetime], Depends(get_clock)]


@contextmanager
def _bounded(conn: psycopg.Connection) -> Iterator[None]:
    """The body of every read: under the statement timeout, and a statement the timeout cancels is the closed `503`. The log
    carries the fact, never the request's text or the statement; any other database error is a bug and stays a `500`.
    """
    queries.set_statement_timeout(conn)
    try:
        yield
    except psycopg.errors.QueryCanceled as exc:
        logger.warning(
            "ti: a read outlived statement_timeout=%s; answering 503", queries.STATEMENT_TIMEOUT
        )
        raise HTTPException(status_code=503, detail={"reason": "timeout"}) from exc


def _storable(value: str | None) -> str | None:
    """A NUL, or a lone surrogate, would reach the driver and be a `500`: it is a `422` instead."""
    if value is not None and not is_storable(value):
        raise ValueError("must be text without a NUL or a lone surrogate")
    return value


def _lower_bound(value: str | None) -> datetime | None:
    return None if value is None else queries.parse_bound(value, upper=False)


def _upper_bound(value: str | None) -> datetime | None:
    return None if value is None else queries.parse_bound(value, upper=True)


def _lookup_value(value: str) -> str:
    _storable(value)
    if not value.strip():
        raise ValueError("must not be blank")
    return value


def filters(
    source: Source | None = None,
    type_: Annotated[
        str | None, Query(alias="type", max_length=queries.TYPE_MAX), AfterValidator(_storable)
    ] = None,
    malware: Annotated[
        str | None, Query(max_length=queries.MALWARE_MAX), AfterValidator(_storable)
    ] = None,
    first_from: Annotated[
        str | None, Query(alias="from", max_length=64), AfterValidator(_lower_bound)
    ] = None,
    first_to: Annotated[
        str | None, Query(alias="to", max_length=64), AfterValidator(_upper_bound)
    ] = None,
    min_confidence: Annotated[int | None, Query(ge=0, le=100)] = None,
    q: Annotated[str | None, Query(max_length=queries.Q_MAX), AfterValidator(_storable)] = None,
    expired: bool = False,
) -> queries.Filters:
    """The filters of the list and of the export, one definition. `from` and `to` arrive as UTC instants (`first_from` inclusive,
    `first_to` exclusive)."""
    return queries.Filters(
        source=source,
        type=type_,
        malware=malware,
        first_seen_from=first_from,  # type: ignore[arg-type]  # the validator turned the text into an instant
        first_seen_before=first_to,  # type: ignore[arg-type]
        min_confidence=min_confidence,
        q=q,
        include_expired=expired,
    )


Filt = Annotated[queries.Filters, Depends(filters)]


@router.get("/api/ti/iocs")
def api_list_iocs(
    conn: Conn,
    claims: Reader,
    clock: Clock,
    filt: Filt,
    page: Annotated[int, Query(ge=1, le=queries.PAGE_MAX)] = 1,
    page_size: Annotated[int, Query(ge=1, le=queries.PAGE_SIZE_MAX)] = queries.PAGE_SIZE_DEFAULT,
) -> dict[str, Any]:
    del claims
    with _bounded(conn):
        rows, total = queries.list_iocs(conn, filt, page=page, page_size=page_size, now=clock())
    return {"rows": rows, "total": total, "page": page, "page_size": page_size}


@router.get("/api/ti/stats")
def api_stats(
    conn: Conn,
    claims: Reader,
    clock: Clock,
    days: Annotated[int, Query(ge=1, le=queries.DAYS_MAX)] = queries.DAYS_DEFAULT,
) -> dict[str, Any]:
    del claims
    with _bounded(conn):
        return queries.stats(conn, days=days, now=clock())


@router.get("/api/ti/lookup")
def api_lookup(
    conn: Conn,
    claims: Reader,
    clock: Clock,
    value: Annotated[str, Query(max_length=queries.VALUE_MAX), AfterValidator(_lookup_value)],
) -> dict[str, Any]:
    del claims
    with _bounded(conn):
        needle, rows, total = queries.lookup(conn, value, now=clock())
    return {"value": needle, "rows": rows, "total": total}


@router.get("/api/ti/status")
def api_status(conn: Conn, claims: Reader, clock: Clock) -> dict[str, Any]:
    del claims
    with _bounded(conn):
        return queries.status(conn, now=clock())


@router.get("/api/ti/export")
def api_export(
    conn: Conn,
    claims: Admin,
    clock: Clock,
    filt: Filt,
    fmt: Annotated[Literal["csv", "blocklist"], Query(alias="format")] = "csv",
) -> Response:
    del claims
    try:
        with _bounded(conn):
            rows = queries.export_iocs(conn, filt, now=clock(), limit=queries.EXPORT_MAX_ROWS)
    except queries.TooManyRows as exc:
        raise HTTPException(
            status_code=422,
            detail={"field": "filters", "reason": "too_many_rows", "limit": exc.limit},
        ) from None
    if fmt == "csv":
        body, media_type, name = queries.export_csv(rows), "text/csv; charset=utf-8", CSV_FILE
    else:
        body, media_type, name = (
            queries.blocklist_text(rows),
            "text/plain; charset=utf-8",
            BLOCKLIST_FILE,
        )
    return Response(
        content=body,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )
