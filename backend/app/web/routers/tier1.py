"""`web/routers/tier1.py` — the six Tier-1 operations (context pack §6.4):
`GET /api/tier1/queue`, `GET /api/tier1/alerts/{id}`, and the four
`POST /api/tier1/alerts/{id}/{acknowledge,decide,escalate,reopen}` verbs.

All logic is `app.tier1.decide` and `app.tier1.queue`; this module binds the
request to an `Actor`, maps `tier1/decide.py`'s guard refusals to status
codes, and enforces the blind-branch read roles — the two `GET`s admit
`tier1`, `tier2` and `admin` (the *filter* inside `queue.py` hides the
suggestion, not the role); the four `POST`s are `tier1`-only, P4-T01's
`require_role` writing `authz.denied` for anyone else.

`DecisionConflict` is returned as a flat `JSONResponse` (`.body` verbatim),
never nested under `HTTPException`'s `"detail"` key — the flash message P4-T05
renders reads `kind`/`occurrence_count`/`seen_occurrence_count` straight off
the response body.
"""

from __future__ import annotations

from typing import Annotated, Literal

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

from app.infra.auth import Claims
from app.tier1 import decide, queue
from app.web.deps import Conn, require_role

router = APIRouter(prefix="/api/tier1")


def _actor(claims: Claims) -> decide.Actor:
    return decide.Actor(user_id=claims.user_id, role=claims.role)


def _conflict_response(conn: psycopg.Connection, exc: decide.DecisionConflict) -> JSONResponse:
    """A returned `Response` is a success as far as `get_conn` is concerned — it
    would commit (planning decision 3's dependency, P4-tasks.md:141,156). Roll
    back first, so a 409 never persists a guard's own reads or anything a
    call before it wrote (review round 1, item 4)."""
    conn.rollback()
    return JSONResponse(status_code=409, content=exc.body)


def _no_nul(value: str) -> str:
    """A NUL byte (0x00) cannot be stored in a `text` column — psycopg raises a
    driver-level error, not a clean 422, if one reaches a query. Rejected at the
    body's own validation instead (review round 1, item 10)."""
    if "\x00" in value:
        raise ValueError("must not contain a NUL byte")
    return value


class DecideIn(BaseModel):
    decision: Literal["false_positive", "benign"]
    reason: str
    seen_occurrence_count: int

    @field_validator("reason")
    @classmethod
    def _reason_no_nul(cls, value: str) -> str:
        return _no_nul(value)


class EscalateIn(BaseModel):
    title: str
    severity: Literal["critical", "high", "medium", "low"] | None = None

    @field_validator("title")
    @classmethod
    def _title_no_nul(cls, value: str) -> str:
        return _no_nul(value)


class ReopenIn(BaseModel):
    reason: str

    @field_validator("reason")
    @classmethod
    def _reason_no_nul(cls, value: str) -> str:
        return _no_nul(value)


# ---------------------------------------------------------------------------
# GET — read access for all three roles; the filter hides the suggestion
# ---------------------------------------------------------------------------


@router.get("/queue")
def get_queue(
    conn: Conn,
    claims: Annotated[Claims, Depends(require_role("tier1", "tier2", "admin"))],
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1)] = queue.PAGE_SIZE_DEFAULT,
) -> dict:
    del claims  # auth only — the role does not change what the page shows
    result = queue.list_queue(conn, page=page, page_size=page_size)
    return {
        "rows": result.rows,
        "total": result.total,
        "page": result.page,
        "page_size": result.page_size,
    }


@router.get("/alerts/{alert_id}")
def get_alert(
    alert_id: str,
    conn: Conn,
    claims: Annotated[Claims, Depends(require_role("tier1", "tier2", "admin"))],
) -> dict:
    del claims
    view = queue.get_alert_view(conn, alert_id, mode="analyst")
    if view is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return view


# ---------------------------------------------------------------------------
# POST — tier1 only
# ---------------------------------------------------------------------------


@router.post("/alerts/{alert_id}/acknowledge")
def post_acknowledge(
    alert_id: str, conn: Conn, claims: Annotated[Claims, Depends(require_role("tier1"))]
) -> dict:
    try:
        return decide.acknowledge(conn, alert_id, _actor(claims))
    except decide.NotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except decide.DecisionConflict as exc:
        return _conflict_response(conn, exc)


@router.post("/alerts/{alert_id}/decide")
def post_decide(
    alert_id: str,
    body: DecideIn,
    conn: Conn,
    claims: Annotated[Claims, Depends(require_role("tier1"))],
) -> dict:
    try:
        return decide.decide(
            conn,
            alert_id,
            _actor(claims),
            decision=body.decision,
            reason=body.reason,
            seen_occurrence_count=body.seen_occurrence_count,
        )
    except decide.NotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except decide.DecisionConflict as exc:
        return _conflict_response(conn, exc)
    except psycopg.errors.QueryCanceled as exc:
        raise HTTPException(
            status_code=503, detail="fan-out timed out; nothing was written"
        ) from exc


@router.post("/alerts/{alert_id}/escalate", status_code=201)
def post_escalate(
    alert_id: str,
    body: EscalateIn,
    conn: Conn,
    claims: Annotated[Claims, Depends(require_role("tier1"))],
) -> dict:
    try:
        return decide.escalate(
            conn, alert_id, _actor(claims), title=body.title, severity=body.severity
        )
    except decide.NotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except decide.DecisionConflict as exc:
        return _conflict_response(conn, exc)


@router.post("/alerts/{alert_id}/reopen")
def post_reopen(
    alert_id: str,
    body: ReopenIn,
    conn: Conn,
    claims: Annotated[Claims, Depends(require_role("tier1"))],
) -> dict:
    try:
        return decide.reopen(conn, alert_id, _actor(claims), reason=body.reason)
    except decide.NotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except decide.DecisionConflict as exc:
        return _conflict_response(conn, exc)
