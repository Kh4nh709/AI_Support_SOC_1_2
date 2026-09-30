"""`POST /api/auth/login`, `POST /api/auth/logout` (context pack §6.4) and `GET /api/auth/me`.

Login answers with the token in the body *and* sets the `soc_session` cookie,
so the HTML pages (P4-T04) and the API share one login. The three login
failures — unknown user, wrong password, inactive — get the same `401` body;
which one it was is never said. A locked account is `423` with `locked_until`.

Commit before raise (planning decision 3): the failed-login `UPDATE` in
`auth.login` must survive the `401`/`423`, and `get_conn` rolls back on any
exception, so each `except` commits first.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.infra import auth
from app.infra.auth import Claims
from app.web.deps import Cfg, Conn, clear_session_cookie, current_user, set_session_cookie

router = APIRouter()


class LoginBody(BaseModel):
    username: str
    password: str


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).isoformat()


@router.post("/api/auth/login")
def login(body: LoginBody, response: Response, conn: Conn, cfg: Cfg) -> dict:
    try:
        claims = auth.login(conn, body.username, body.password, cfg)
    except auth.AuthDisabled as exc:
        raise HTTPException(status_code=503, detail="auth disabled: JWT_SECRET unset") from exc
    except auth.LoginFailed as exc:
        conn.commit()
        raise HTTPException(status_code=401, detail="invalid credentials") from exc
    except auth.AccountLocked as exc:
        conn.commit()
        # A flat body (`detail` + `locked_until`) — `HTTPException` would nest
        # everything under `detail`, so the response is built directly.
        return JSONResponse(
            status_code=423,
            content={"detail": "locked", "locked_until": exc.locked_until.isoformat()},
        )
    token = auth.issue_token(claims, cfg)
    set_session_cookie(response, token, cfg)
    return {
        "token": token,
        "role": claims.role,
        "user_id": claims.user_id,
        "expires_at": _iso(claims.exp),
    }


@router.post("/api/auth/logout", status_code=204)
def logout(conn: Conn, claims: Annotated[Claims, Depends(current_user)]) -> Response:
    auth.logout(conn, claims.user_id)
    response = Response(status_code=204)
    clear_session_cookie(response)
    return response


@router.get("/api/auth/me")
def me(conn: Conn, claims: Annotated[Claims, Depends(current_user)]) -> dict:
    """The signed-in user, as the React header needs it on reload (P10-T01). The name
    comes from the row, and the role from the verified token (`verify` already re-reads
    the row's role on every request)."""
    row = conn.execute(
        "SELECT display_name FROM users WHERE user_id = %s", (claims.user_id,)
    ).fetchone()
    return {
        "user_id": claims.user_id,
        "username": claims.username,
        "display_name": row[0] if row else None,
        "role": claims.role,
        "expires_at": _iso(claims.exp),
    }
