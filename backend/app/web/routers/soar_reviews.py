"""`web/routers/soar_reviews.py` — the SOAR review tickets on the web (SR-T1, spec 2026-11-16 §3 to §5): the API behind the page
"Phản hồi SOAR". All logic is `app.soar.reviews`; this module reads the request, binds the caller, maps the refusals to status
codes and shapes the answers. `iter_routers()` discovers it.

    GET  /api/soar/reviews                       200 {rows: [review], total, page, page_size}
    GET  /api/soar/reviews/count                 200 {count, latest_received_at}
    GET  /api/soar/reviews/{id}                  200 review + raw, history, related_alerts, related_total; 404
    POST /api/soar/reviews/{id}/decision         200 {outcome, message, review}; 403, 404, 409, 422, 503

Signed-in users only, the Bearer token as every `/api` route; the three roles read. A `review` is the object of spec §4 (see
`soar/reviews.py` `serve`).

**The list.** Filters, all optional and ANDed: `status` (repeatable; the EFFECTIVE status: a stale lock is served as, and found as,
the state the row had), `kind`, `action_type`, `case_number`, `from` (`created_at`, inclusive) and `to` (exclusive), both ISO 8601
WITH an offset (one with none is ambiguous: `422`), and `q` (a case number when it is all digits, a leading `#` and the whitespace around it ignored so `#65` finds case 65, else a case-insensitive substring
of `src_ip`, `host`, `action_target`, `user_name` and `domain`; at most 100 characters, `%`, `_` and `\\` escaped so they match
themselves). `page` ≥ 1, `page_size` ≥ 1, clamped to 200: the queue's convention. Newest `created_at` first, then `id`.
`status`, `kind`, `action_type` and the numbers are closed sets and ranges: anything else is a `422`.

**The count.** `status` (repeatable, default `open`): how many REVIEWS (never notices) are in those states and the newest one's
`received_at`, which the page compares with the last it saw to know a ticket arrived. `received_at` is the web's own clock when it
first stored the ticket and no update moves it: n8n's `created_at` can be older than a ticket already shown when a delivery is late.

**The decision.** Body `{"decision": "keep|undo|fp", "note": "<optional, at most 500>"}`, read by hand (as `admin_lab.py`: a `422`
repeats nothing the client sent), JSON only (`deps.require_json_type`, the repo's rule for a route that changes something: the token
is in `sessionStorage`, there is no cookie to forge a request with). Order: not signed in `401`; a role that is in NONE of
`SOAR_ROLES_KEEP|UNDO|FP` `403` (and its `authz.denied` event), before the body is even looked at; the type and the body `422`; a role
not allowed THE decision asked `403` with the `authz.denied` event, like `deps.require_role` writes (commit before raise); an unknown
id `404`; then `soar/reviews.decide`: `409 {"detail": {"reason": "locked" | "invalid_state", "review": ...}}` (the press's own
`soar.review_decided` event written and committed first), `503 {"detail": "soar approval not configured"}` before anything is locked,
else `200 {outcome, message, review}` whatever n8n answered (`ok`, `failed`, `unavailable`, `conflict`): the HTTP errors are only the
web's own refusals.

The route is a plain `def`, which FastAPI runs in a worker thread: the call to n8n, which may take up to
`N8N_APPROVAL_TIMEOUT_SECONDS`, never stands on the event loop. The request's connection (`Conn`) is committed by `decide` itself at
each step that must survive the next (the lock before the call; the finish and its event after).

The id of a ticket in a path is `deps.clean_path_id`'d, as an alert id is: a control character names nothing (`404`), where a NUL
would reach the driver and be a 500.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

import httpx
import psycopg
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import AfterValidator, BeforeValidator

from app.audit.events import write_event
from app.infra.auth import Claims
from app.infra.storable import is_storable
from app.soar import reviews
from app.web.deps import (
    ROLE_TO_ACTOR,
    Cfg,
    Conn,
    clean_path_id,
    current_user,
    require_json_type,
    require_role,
)

router = APIRouter()

#: The note a person may attach to a decision, in characters.
NOTE_MAX = 500
#: The body of a decision is a few dozen bytes plus a note of at most 500 characters (2,000 bytes): 8 KiB is far more than it needs,
#: and the cap is what keeps the body from being read whole, or parsed, when it is not one.
BODY_MAX_BYTES = 8 * 1024
#: What a timed-out request tells the sender (the webhook's own value).
RETRY_AFTER_S = "2"
#: A page number past this is not a page: the offset would overflow the driver's integer.
PAGE_MAX = 1_000_000

ReviewId = Annotated[str, BeforeValidator(clean_path_id)]
Reader = Annotated[Claims, Depends(require_role("tier1", "tier2", "admin"))]


def get_approval_client_factory() -> Callable[[], httpx.Client] | None:
    """The client of the call to n8n; `None` is the real one. A test overrides this dependency with a fake's factory
    (`tests/fakes/n8n.py`), so the real client runs against no socket."""
    return None


ApprovalClientFactory = Annotated[
    Callable[[], httpx.Client] | None, Depends(get_approval_client_factory)
]


def _no_control(value: str | None) -> str | None:
    """A NUL byte in `q` would reach the driver and be a 500: it is a 422 instead."""
    if value is not None and "\x00" in value:
        raise ValueError("must not contain a NUL character")
    return value


def _instant(value: str | None) -> datetime | None:
    """`from` and `to`: ISO 8601 WITH an offset. One with none is ambiguous and is refused; so is anything that is not an ISO
    time (a bare number is not read as a Unix time, as a `datetime` parameter would)."""
    if value is None:
        return None
    try:
        moment = datetime.fromisoformat(value)
        if moment.utcoffset() is None:
            raise ValueError("must carry an offset")
        moment.astimezone(UTC)  # a time with no UTC form (year 1 at +14:00) is refused too
    except (ValueError, OverflowError):
        raise ValueError("must be an ISO 8601 time with an offset") from None
    return moment


Status = Literal["open", "kept", "undone", "false_positive", "expired", "info", "processing"]
Kind = Literal["review", "notice"]
ActionType = Literal[
    "block_ip",
    "sinkhole_domain",
    "isolate_host",
    "disable_user",
    "disable_xp_cmdshell",
    "kill_process",
]


# ── the reads ───────────────────────────────────────────────────────────────────────────────


@router.get("/api/soar/reviews")
def api_list_reviews(
    conn: Conn,
    cfg: Cfg,
    claims: Reader,
    status: Annotated[list[Status] | None, Query()] = None,
    kind: Kind | None = None,
    action_type: ActionType | None = None,
    case_number: Annotated[int | None, Query(ge=0, le=2**63 - 1)] = None,
    created_from: Annotated[
        str | None, Query(alias="from", max_length=64), AfterValidator(_instant)
    ] = None,
    created_to: Annotated[
        str | None, Query(alias="to", max_length=64), AfterValidator(_instant)
    ] = None,
    q: Annotated[
        str | None, Query(max_length=reviews.Q_MAX_LENGTH), AfterValidator(_no_control)
    ] = None,
    page: Annotated[int, Query(ge=1, le=PAGE_MAX)] = 1,
    page_size: Annotated[int, Query(ge=1)] = reviews.PAGE_SIZE_DEFAULT,
) -> dict[str, Any]:
    filters = reviews.Filters(
        statuses=None if status is None else tuple(status),
        kind=kind,
        action_type=action_type,
        case_number=case_number,
        created_from=created_from,
        created_to=created_to,
        q=q,
    )
    rows, total = reviews.list_reviews(
        conn, filters, page=page, page_size=page_size, role=claims.role, cfg=cfg
    )
    return {
        "rows": rows,
        "total": total,
        "page": page,
        "page_size": min(page_size, reviews.PAGE_SIZE_MAX),
    }


# Declared before `/{review_id}`: `count` is a route, not an id.
@router.get("/api/soar/reviews/count")
def api_count_reviews(
    conn: Conn, claims: Reader, status: Annotated[list[Status] | None, Query()] = None
) -> dict[str, Any]:
    del claims
    count, latest = reviews.count_reviews(conn, tuple(status) if status else ("open",))
    return {"count": count, "latest_received_at": latest}


@router.get("/api/soar/reviews/{review_id}")
def api_get_review(review_id: ReviewId, conn: Conn, cfg: Cfg, claims: Reader) -> dict[str, Any]:
    detail = reviews.get_detail(conn, review_id, claims.role, cfg)
    if detail is None:
        raise HTTPException(status_code=404, detail="review not found")
    return detail


# ── the decision ────────────────────────────────────────────────────────────────────────────


def _bad(field: str, reason: str) -> HTTPException:
    return HTTPException(status_code=422, detail={"field": field, "reason": reason})


def _deny(
    request: Request, conn: psycopg.Connection, claims: Claims, required: list[str]
) -> HTTPException:
    """Write, and commit, the `authz.denied` event `deps.require_role` writes, and return the 403 to raise (the request's
    connection rolls back on any raise, so the event is committed first)."""
    write_event(
        conn,
        "authz.denied",
        request.url.path,
        ROLE_TO_ACTOR.get(claims.role, "analyst"),
        actor_id=claims.user_id,
        payload={"required": required, "role": claims.role, "method": request.method},
    )
    conn.commit()
    return HTTPException(status_code=403, detail="forbidden")


def _holds_a_role(
    request: Request, conn: Conn, cfg: Cfg, claims: Annotated[Claims, Depends(current_user)]
) -> Claims:
    """The caller, if some decision is allowed to their role: otherwise `403` before the body is read."""
    required = reviews.roles_for_any(cfg)
    if claims.role not in required:
        raise _deny(request, conn, claims, required)
    return claims


async def _read_body(
    request: Request, _claims: Annotated[Claims, Depends(_holds_a_role)]
) -> dict[str, Any]:
    """The JSON object of the body. The type first (`deps.require_json_type`), after the role: a signed-in caller of no role is a
    403 whatever they sent. An empty body, one that is not JSON and one that is not an object are the same 422.
    """
    require_json_type(request)
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > BODY_MAX_BYTES:
        raise HTTPException(status_code=413, detail="payload too large")
    chunks: list[bytes] = []
    size = 0
    async for (
        chunk
    ) in request.stream():  # counted as it arrives: a chunked upload declares no length
        size += len(chunk)
        if size > BODY_MAX_BYTES:
            raise HTTPException(status_code=413, detail="payload too large")
        chunks.append(chunk)
    try:
        value = json.loads(b"".join(chunks))
    except (
        ValueError,
        RecursionError,
    ):  # not JSON, not UTF-8, or nested past what the parser will read
        raise _bad("body", "invalid") from None
    if not isinstance(value, dict):
        raise _bad("body", "invalid")
    return value


JsonBody = Annotated[dict[str, Any], Depends(_read_body)]
Caller = Annotated[Claims, Depends(_holds_a_role)]


def _validated(body: dict[str, Any]) -> tuple[str, str | None]:
    """`(decision, note)` or a 422 naming the field. Nothing the client sent is repeated."""
    if set(body) - {"decision", "note"}:
        raise _bad("body", "invalid")
    decision = body.get("decision")
    if decision is None:
        raise _bad("decision", "required")
    if not isinstance(decision, str) or decision not in ("keep", "undo", "fp"):
        raise _bad("decision", "invalid")
    note = body.get("note")
    if note is not None:
        if not isinstance(note, str) or not is_storable(
            note
        ):  # a NUL or a lone surrogate: 422 before any lock
            raise _bad("note", "invalid")
        if len(note) > NOTE_MAX:
            raise _bad("note", "too_long")
    return decision, note


@router.post(
    "/api/soar/reviews/{review_id}/decision",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "decision": {"type": "string", "enum": ["keep", "undo", "fp"]},
                            "note": {"type": "string", "maxLength": NOTE_MAX},
                        },
                        "additionalProperties": False,
                        "required": ["decision"],
                    }
                }
            },
        }
    },
)
def api_decide(
    review_id: ReviewId,
    request: Request,
    conn: Conn,
    cfg: Cfg,
    claims: Caller,
    body: JsonBody,
    client_factory: ApprovalClientFactory,
) -> JSONResponse:
    decision, note = _validated(body)
    if claims.role not in reviews.roles_for(decision, cfg):
        raise _deny(request, conn, claims, reviews.roles_for(decision, cfg))
    person = reviews.Person(
        user_id=claims.user_id,
        username=claims.username,
        role=claims.role,
        actor_role=ROLE_TO_ACTOR.get(claims.role, "analyst"),
    )
    try:
        decided = reviews.decide(conn, review_id, person, decision, note, cfg, client_factory)
    except reviews.NotFound:
        raise HTTPException(status_code=404, detail="review not found") from None
    except reviews.NotConfigured:
        raise HTTPException(status_code=503, detail="soar approval not configured") from None
    except reviews.Refused as refused:
        # `decide` committed the press's own event; the 409 is raised after it
        raise HTTPException(
            status_code=409, detail={"reason": refused.reason, "review": refused.review}
        ) from None
    except (psycopg.errors.LockNotAvailable, psycopg.errors.QueryCanceled):
        # `lock_timeout` / `statement_timeout` (`reviews.LOCK_TIMEOUT`, `STATEMENT_TIMEOUT`) fired before anything was locked: the
        # webhook's own answer, "try again". After the call these are caught by the finish, which writes the outcome anyway.
        raise HTTPException(
            status_code=503, detail="busy", headers={"Retry-After": RETRY_AFTER_S}
        ) from None
    return JSONResponse(
        {"outcome": decided.outcome, "message": decided.message, "review": decided.review}
    )
