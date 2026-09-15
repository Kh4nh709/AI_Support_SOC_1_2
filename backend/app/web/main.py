"""web/main.py — the FastAPI application (composition root, context pack §4).

`make run-app` already points `uvicorn` at `app.web.main:app`. Only one route
exists so far: `POST /api/admin/reload-inventory` (P2-T08). `GET /health` is
P5, `POST /webhook/alerts` is P2-T12, and every `tier1`/`tier2`/`admin` route of
§6.4 arrives with its own task — nothing here anticipates them.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterator
from typing import Annotated

import psycopg
from fastapi import Depends, FastAPI, HTTPException

from app.enrichment.inventory import load
from app.infra import db
from app.infra.errors import PermanentError

app = FastAPI()


def get_conn() -> Iterator[psycopg.Connection]:
    """One connection per request: committed on success, rolled back on error,
    closed always. `db.connect()` (no DSN) reads `Config.DATABASE_URL`, the
    `app_rw` role's DSN — absent from every worktree's `.env`-less environment,
    which is why every test overrides this dependency (design note 4) rather
    than exercising the default.
    """
    conn = db.connect()
    try:
        yield conn
    except BaseException:
        conn.rollback()
        raise
    else:
        conn.commit()
    finally:
        conn.close()


_Conn = Annotated[psycopg.Connection, Depends(get_conn)]


@app.post("/api/admin/reload-inventory")
def reload_inventory(conn: _Conn) -> dict:
    # No authentication in P2 (context pack §6.4 hand-off item 2 / P2-tasks.md
    # P2-T08 row): P4 wraps this route with the `admin` role dependency once
    # `infra/auth.py` exists. DEC-058 / DEC-066: the block this route's data
    # feeds (G8′ "asset not in inventory") is unchanged by that hand-off.
    try:
        report = load(conn)
    except PermanentError as exc:
        raise HTTPException(status_code=422, detail=str(exc).splitlines()) from exc
    return dataclasses.asdict(report)
