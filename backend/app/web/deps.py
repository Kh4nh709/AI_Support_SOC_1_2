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

from collections.abc import Callable, Iterator
from typing import Annotated

import psycopg
from fastapi import Depends, HTTPException, Request, Response

from app.audit.events import write_event
from app.infra import auth, config, db
from app.infra.auth import Claims
from app.infra.config import Config

COOKIE_NAME = "soc_session"

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


Conn = Annotated[psycopg.Connection, Depends(get_conn)]
Cfg = Annotated[Config, Depends(get_config)]


def read_token(request: Request) -> str | None:
    """`Authorization: Bearer <token>` first, else the `soc_session` cookie."""
    scheme, _, value = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() == "bearer" and value.strip():
        return value.strip()
    return request.cookies.get(COOKIE_NAME) or None


def set_session_cookie(response: Response, token: str, cfg: Config) -> None:
    """The one place the cookie's attributes are spelled (P4-T04's page login
    calls this too). `secure=False` because the app binds `127.0.0.1:8000` with
    no TLS (Makefile `run-app`) — a P8 limitation, stated, not hidden."""
    response.set_cookie(
        COOKIE_NAME,
        token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=cfg.JWT_TTL_HOURS * 3600,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/", httponly=True, samesite="lax")


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
