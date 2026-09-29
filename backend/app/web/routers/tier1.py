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
from pydantic import BaseModel

from app.infra.auth import Claims
from app.tier1 import decide, queue
from app.web.deps import Conn, require_role

router = APIRouter(prefix="/api/tier1")


def _actor(claims: Claims) -> decide.Actor:
    return decide.Actor(user_id=claims.user_id, role=claims.role)


class DecideIn(BaseModel):
    decision: Literal["false_positive", "benign"]
    reason: str
    seen_occurrence_count: int


class EscalateIn(BaseModel):
    title: str
    severity: Literal["critical", "high", "medium", "low"] | None = None


class ReopenIn(BaseModel):
    reason: str


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
        return JSONResponse(status_code=409, content=exc.body)


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
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except decide.DecisionConflict as exc:
        return JSONResponse(status_code=409, content=exc.body)
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
        return JSONResponse(status_code=409, content=exc.body)


@router.post("/alerts/{alert_id}/reopen")
def post_reopen(
    alert_id: str,
    body: ReopenIn,
    conn: Conn,
    claims: Annotated[Claims, Depends(require_role("tier1"))],
) -> dict:
    try:
        return decide.reopen(conn, alert_id, _actor(claims), reason=body.reason)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except decide.DecisionConflict as exc:
        return JSONResponse(status_code=409, content=exc.body)
