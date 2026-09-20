"""web/main.py — the FastAPI application (composition root, context pack §4).

`make run-app` points `uvicorn` at `app.web.main:app`. Routes live in modules
under `app.web.routers/`, discovered and mounted here (P4-tasks.md planning
decision 1) — a later card adds one module there and touches no shared file.
The one exception is `POST /api/admin/reload-inventory` (P2-T08), kept here
with its body unchanged and now behind the `admin` role (P4-T01).

`get_conn` lives in `app.web.deps` and is re-exported so that
`test_reload_inventory.py`'s `dependency_overrides[main.get_conn]` keeps
hitting the same object (`main.get_conn is deps.get_conn`).
"""

from __future__ import annotations

import dataclasses
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException

from app.enrichment.inventory import load
from app.infra.auth import Claims
from app.infra.errors import PermanentError
from app.web.deps import Conn, get_conn, require_role  # re-export: tests override main.get_conn
from app.web.routers import iter_routers

__all__ = ["app", "get_conn"]

app = FastAPI()

for router in iter_routers():
    app.include_router(router)


@app.post("/api/admin/reload-inventory")
def reload_inventory(conn: Conn, _: Annotated[Claims, Depends(require_role("admin"))]) -> dict:
    # DEC-058 / DEC-066: the block this route's data feeds (G8′ "asset not in
    # inventory") is unchanged by the role dependency P4-T01 added.
    try:
        report = load(conn)
    except PermanentError as exc:
        raise HTTPException(status_code=422, detail=str(exc).splitlines()) from exc
    return dataclasses.asdict(report)
