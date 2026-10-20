"""The FastAPI dependencies every router shares: a connection, the config, the
signed-in user, and the role check.

This is the HTTP half of auth (P4-tasks.md planning decision 2): `infra/auth.py`
raises typed exceptions and cannot write an audit event (G1 — `infra` imports
nothing from the app); this module, being `web`, may import everything, so it
maps those exceptions to status codes and writes the one event a refusal owes,
`authz.denied`.

Commit before raise (planning decision 3): `get_conn` rolls back on *any*
exception, `HTTPException` included, so a write that must survive a 4xx —
here the `authz.denied` row, in `routers/auth.py` the failed-login counter —
is `conn.commit()`ed explicitly before the exception is raised.
"""

from __future__ import annotations

import unicodedata
import uuid
from collections.abc import Callable, Iterator
from typing import Annotated

import psycopg
from fastapi import Depends, HTTPException, Request
from pydantic import BeforeValidator

from app.audit.events import write_event
from app.infra import auth, config, db
from app.infra.auth import Claims
from app.infra.config import Config

# The two audit CHECKs (`ck_audit_actor_role`, `ck_audit_actor_id_theo_role`)
# know four actor roles, not three user roles: both analyst tiers are 'analyst'.
ROLE_TO_ACTOR = {"tier1": "analyst", "tier2": "analyst", "admin": "admin"}


def get_conn() -> Iterator[psycopg.Connection]:
    """One connection per request: committed on success, rolled back on error,
    closed always. `db.connect()` (no DSN) reads `Config.DATABASE_URL`, the
    `app_rw` role's DSN — absent from every worktree's `.env`-less environment,
    which is why every test overrides this dependency (P2-T08 design note 4)
    rather than exercising the default. Moved here from `main.py` unchanged;
    `main.py` re-exports it so `main.get_conn is deps.get_conn`.
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


def get_config() -> Config:
    """`config.load()` per request; tests override it with a `Config` carrying a
    literal `JWT_SECRET` (DEC-047: never read from `.env` in a test)."""
    return config.load()


# `scope="function"` (FastAPI ≥ 0.121): `get_conn`'s exit code — the commit —
# runs after the path operation and *before* the response is sent. The default
# `"request"` scope runs it after the response has gone out (measured on
# 0.141.1 at the ASGI level), so a 2xx would not yet mean the write is visible
# to any other connection — a logout answering 204 while the old token still
# verified. A route's exception still reaches the `except` above first.
Conn = Annotated[psycopg.Connection, Depends(get_conn, scope="function")]
Cfg = Annotated[Config, Depends(get_config)]


def clean_path_id(value: object) -> object:
    """The one check on an `alert_id` / `case_id` path parameter (P10-T17 item 8e, M1): a NUL byte,
    or any other control character (Unicode category `Cc`: C0, DEL, C1), names nothing, so the
    answer is 404. Without it a NUL reached `WHERE alert_id = %s` and the driver raised
    `DataError`, a 500; no real id holds one, and a `text` column cannot.

    It runs as the path value is parsed, which FastAPI does after the dependencies: the role check
    still answers first (a wrong role is a 403 whatever the id), and the type check comes after
    (a `CaseId` that is plain text without a control character is still the 422 it was)."""
    if isinstance(value, str) and any(unicodedata.category(ch) == "Cc" for ch in value):
        raise HTTPException(status_code=404, detail="not found")
    return value


# The two annotated types the routes under `/api/tier1` and `/api/tier2` take their ids as. A new
# route with an `{alert_id}` or `{case_id}` must use them (`test_path_id_guard.py` pins every
# existing one and the list of routes itself).
AlertId = Annotated[str, BeforeValidator(clean_path_id)]
CaseId = Annotated[uuid.UUID, BeforeValidator(clean_path_id)]


def read_token(request: Request) -> str | None:
    """The `Authorization: Bearer <token>` header, and nothing else. The session is the token the
    caller holds (the React UI keeps it in the tab's `sessionStorage`); since P11-T19 (spec §8) no
    cookie carries or sets one, so a request that names only a cookie has no token and is a 401."""
    scheme, _, value = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() == "bearer" and value.strip():
        return value.strip()
    return None


def current_user(request: Request, conn: Conn, cfg: Cfg) -> Claims:
    """The signed-in user, checked against the `users` row on every request."""
    token = read_token(request)
    if token is None:
        raise HTTPException(status_code=401, detail="not authenticated")
    try:
        return auth.verify(conn, token, cfg)
    except auth.AuthDisabled as exc:
        raise HTTPException(status_code=503, detail="auth disabled: JWT_SECRET unset") from exc
    except auth.Unauthorized as exc:
        raise HTTPException(status_code=401, detail=exc.reason) from exc


def require_role(*roles: str) -> Callable[..., Claims]:
    """A dependency factory: `Depends(require_role("admin"))` yields the `Claims`
    or answers `403` after writing — and committing — an `authz.denied` event."""

    def dependency(
        request: Request, conn: Conn, claims: Annotated[Claims, Depends(current_user)]
    ) -> Claims:
        if claims.role in roles:
            return claims
        write_event(
            conn,
            "authz.denied",
            request.url.path,
            ROLE_TO_ACTOR.get(claims.role, "analyst"),
            actor_id=claims.user_id,
            payload={"required": list(roles), "role": claims.role, "method": request.method},
        )
        conn.commit()
        raise HTTPException(status_code=403, detail="forbidden")

    return dependency
