"""web/routers/tier2.py — the four §6.4 case operations (P5-T06): `GET
/api/tier2/cases`, `GET /api/tier2/cases/{case_id}`, `POST
…/{case_id}/notes`, `POST …/{case_id}/conclude`. All `require_role("tier2",
"admin")`.

The ② operations (`POST …/analyze`, `GET /api/tier2/runs/{run_id}`) are
P5-T04's and are not in this file — this card is dispatched and merged
whether or not ② survives (the card's own header note). `list_cases()` and
`case_detail()` are exposed at module level, not prefixed `_`, because
P5-T07's case pages are the next card built on this REST layer and read
straight from these two functions rather than re-deriving the SQL.
"""

from __future__ import annotations

import dataclasses
import uuid
from typing import Annotated, Any

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.domain import transitions
from app.infra.auth import Claims
from app.tier2 import case_view, conclude
from app.web.deps import Conn, require_role

router = APIRouter()

#: One dependency object, so `Depends` resolves it once per request (the
#: pattern `web/routers/labels.py` uses for `Admin`).
require_tier2 = require_role("tier2", "admin")
Tier2 = Annotated[Claims, Depends(require_tier2)]

#: G10 — never `SELECT *` on `alerts` in a list query. A case overview's
#: working set: an analyst deciding whether to conclude needs `status` too,
#: which is why this is not `web/routers/labels.py`'s `_ALERT_COLUMNS`.
_HEAD_COLUMNS: tuple[str, ...] = (
    "alert_id",
    "rule_id",
    "severity",
    "description",
    "agent_name",
    "alert_time",
    "srcip",
    "category",
    "occurrence_count",
    "status",
)

_CASE_COLUMNS: tuple[str, ...] = (
    "case_id",
    "title",
    "status",
    "severity",
    "created_by",
    "created_at",
    "last_analyzed_at",
    "concluded_by",
    "concluded_at",
    "conclusion_reason",
)


def list_cases(
    conn: psycopg.Connection, *, offset: int = 0, limit: int = 50
) -> list[dict[str, Any]]:
    """OFFSET-paged, `investigating` first then `created_at DESC, case_id` (a
    total order — design note 3). `occurrence_count` is a row **count** over
    the case's heads *and* their duplicates — measured on `soc_dev`: a head's
    own `occurrence_count` already counts its merged duplicates one-for-one
    (`ingest/dedup.py`'s `bump_parent` bumps only the head, a duplicate's own
    column stays at its default of 1), so this row count and
    `sum(occurrence_count)` restricted to heads alone agree numerically — but
    the row-count form is the one design note 3 and DEC-036 name. Written as
    `heads + duplicates` (two `JOIN`-able counts) rather than one `OR`ed `IN`
    (…) `IN` (…) `WHERE`, for the query plan (`duplicate_of` and `case_id`
    both carry an index; a `JOIN` on `duplicate_of = case_alerts.alert_id`
    reaches it the way an `OR` of two `IN` subqueries does not) — the
    `duplicate_of` half stays, so removing it (red step (a)) still turns the
    duplicate-inclusive count red while `cluster_count` stays right."""
    rows = conn.execute(
        """
        SELECT c.case_id, c.title, c.status, c.severity, c.created_at, c.last_analyzed_at,
               (SELECT count(*) FROM case_alerts ca
                 WHERE ca.case_id = c.case_id) AS cluster_count,
               (SELECT count(*) FROM case_alerts ca
                 WHERE ca.case_id = c.case_id)
             + (SELECT count(*) FROM alerts a JOIN case_alerts ca ON a.duplicate_of = ca.alert_id
                 WHERE ca.case_id = c.case_id) AS occurrence_count
        FROM cases c
        ORDER BY (c.status <> 'investigating'), c.created_at DESC, c.case_id
        OFFSET %s LIMIT %s
        """,
        (offset, limit),
    ).fetchall()
    columns = (
        "case_id",
        "title",
        "status",
        "severity",
        "created_at",
        "last_analyzed_at",
        "cluster_count",
        "occurrence_count",
    )
    return [dict(zip(columns, row, strict=True)) for row in rows]


def case_detail(conn: psycopg.Connection, case_id: str) -> dict[str, Any] | None:
    """The case, its heads (G10 explicit column list, ordered `added_at,
    alert_id` — a total order) and its notes. `None` when `case_id` names no
    row — the router answers 404 (design note 3).

    P10-T04: also the fields the case pages used to recompute — `concluded_by_name` and each
    note's `author_name` (one `case_view.usernames` read), each head's `raw_log`,
    `raw_log_truncated`, `risk_band` and `last_seen_at` (never `risk_score`), and `ongoing` /
    `ongoing_last_seen` (`case_view.enrich_heads`' rule). Every earlier key is unchanged."""
    row = conn.execute(
        f"SELECT {', '.join(_CASE_COLUMNS)} FROM cases WHERE case_id = %s",
        (case_id,),
    ).fetchone()
    if row is None:
        return None
    case = dict(zip(_CASE_COLUMNS, row, strict=True))
    heads = conn.execute(
        f"SELECT {', '.join(f'a.{c}' for c in _HEAD_COLUMNS)} "
        "FROM case_alerts ca JOIN alerts a ON a.alert_id = ca.alert_id "
        "WHERE ca.case_id = %s ORDER BY ca.added_at, a.alert_id",
        (case_id,),
    ).fetchall()
    case["heads"] = [dict(zip(_HEAD_COLUMNS, head, strict=True)) for head in heads]
    case["notes"] = [dataclasses.asdict(note) for note in conclude.list_notes(conn, case_id)]
    since = case["last_analyzed_at"] or case["created_at"]
    ongoing_last_seen = case_view.enrich_heads(conn, case["heads"], since)
    case["ongoing"] = ongoing_last_seen is not None
    case["ongoing_last_seen"] = ongoing_last_seen
    names = case_view.usernames(
        conn, {case["concluded_by"]} | {note["author_id"] for note in case["notes"]}
    )
    case["concluded_by_name"] = (
        names.get(str(case["concluded_by"])) if case["concluded_by"] is not None else None
    )
    for note in case["notes"]:
        note["author_name"] = names.get(str(note["author_id"]))
    return case


class NoteIn(BaseModel):
    body: str


class ConcludeIn(BaseModel):
    conclusion: str
    reason: str


@router.get("/api/tier2/cases")
def api_list_cases(
    conn: Conn,
    _: Tier2,
    offset: Annotated[int, Query(ge=0, le=2**31 - 1)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[dict[str, Any]]:
    return list_cases(conn, offset=offset, limit=limit)


@router.get("/api/tier2/cases/{case_id}")
def api_case_detail(conn: Conn, _: Tier2, case_id: uuid.UUID) -> dict[str, Any]:
    case = case_detail(conn, str(case_id))
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    return case


@router.post("/api/tier2/cases/{case_id}/notes", status_code=201)
def api_add_note(conn: Conn, claims: Tier2, case_id: uuid.UUID, body: NoteIn) -> dict[str, Any]:
    try:
        note_id = conclude.add_note(conn, str(case_id), claims.user_id, body.body)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except conclude.UnknownCase as exc:
        raise HTTPException(status_code=404, detail="case not found") from exc
    row = conn.execute(
        "SELECT note_id, case_id, author_id, body, created_at FROM case_notes WHERE note_id = %s",
        (note_id,),
    ).fetchone()
    assert row is not None
    return dict(zip(("note_id", "case_id", "author_id", "body", "created_at"), row, strict=True))


@router.post("/api/tier2/cases/{case_id}/conclude")
def api_conclude(conn: Conn, claims: Tier2, case_id: uuid.UUID, body: ConcludeIn) -> dict[str, Any]:
    case_id_str = str(case_id)
    try:
        conclude.submit(
            conn, case_id_str, claims.user_id, conclusion=body.conclusion, reason=body.reason
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except conclude.UnknownCase as exc:
        raise HTTPException(status_code=404, detail="case not found") from exc
    except conclude.ConcludeConflict as exc:
        detail: dict[str, Any] = {"status": exc.status}
        if exc.concluded_by is not None:
            detail["concluded_by"] = str(exc.concluded_by)
            detail["concluded_at"] = (
                exc.concluded_at.isoformat() if exc.concluded_at is not None else None
            )
        raise HTTPException(status_code=409, detail=detail) from exc
    except transitions.IllegalTransition as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except psycopg.errors.QueryCanceled as exc:
        raise HTTPException(status_code=503, detail="conclude: statement timeout") from exc
    case = case_detail(conn, case_id_str)
    assert case is not None  # just concluded successfully — the row exists
    return case
