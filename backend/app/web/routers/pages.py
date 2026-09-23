"""`web/routers/pages.py` — `GET`/`POST /login`, `POST /logout`, `GET /` → `/queue`
(P4-T04). `page_user`/`optional_user` are exported for P4-T05 and P6-T02:
**pages redirect, APIs answer 401** — the one difference from `deps.current_user`.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.infra import auth
from app.infra.auth import Claims
from app.web import templating
from app.web.deps import (
    Cfg,
    Conn,
    clear_session_cookie,
    current_user,
    read_token,
    set_session_cookie,
)

router = APIRouter()

_LOGIN_FAILED_TEXT = "Sai tên đăng nhập hoặc mật khẩu"
_AUTH_DISABLED_TEXT = "Đăng nhập chưa được bật (JWT_SECRET chưa đặt)"


class _RenderedPage(Exception):
    """Carries a pre-rendered page past `Conn`'s exit (DEC-025's shape,
    `routers/auth.py`'s design note): raising this, instead of returning the
    response directly, lets `get_conn`'s rollback-on-exception undo an
    uncommitted write when the caller forgot `conn.commit()` first. `deps.Conn`
    is a `scope="function"` dependency, whose exit code only runs for an
    exception that reaches an *app-level* handler (measured — a plain
    try/except inside this router's own dispatch runs before that exit code
    and would silently commit regardless); `HTTPException` gets this for free
    from FastAPI's built-in handler, and this module extends the same
    contract to an HTML body via its own handler, installed below.
    """

    def __init__(self, response: HTMLResponse) -> None:
        self.response = response


async def _rendered_page_handler(request: Request, exc: _RenderedPage) -> HTMLResponse:
    return exc.response


def _install_error_handler() -> None:
    """Registers `_RenderedPage`'s handler on the app at import time — not in
    `web/main.py` (untouched by this card, and `add_exception_handler` has no
    router-scoped form) and not lazily on first request (measured: Starlette
    freezes `app.exception_handlers` into `ExceptionMiddleware` on the first
    ASGI call and never rebuilds, so a handler added after that call is never
    seen). `web/main.py` assigns `app = FastAPI()` before its `iter_routers()`
    loop imports this module, so `main.app` already exists here regardless of
    which module triggers the import chain first.
    """
    from app.web import main

    main.app.add_exception_handler(_RenderedPage, _rendered_page_handler)


_install_error_handler()


def optional_user(request: Request, conn: Conn, cfg: Cfg) -> Claims | None:
    """The signed-in user, or `None` — never raises (a page's "am I signed in?" check)."""
    token = read_token(request)
    if token is None:
        return None
    try:
        return auth.verify(conn, token, cfg)
    except (auth.AuthDisabled, auth.Unauthorized):
        return None


def page_user(request: Request, conn: Conn, cfg: Cfg) -> Claims:
    """Like `deps.current_user`, but a `303` to `/login` instead of a JSON
    `401` — pages redirect, APIs answer (exported for P4-T05 and P6-T02)."""
    user = optional_user(request, conn, cfg)
    if user is None:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user


@router.get("/login")
def login_page(request: Request, user: Annotated[Claims | None, Depends(optional_user)]):
    if user is not None:
        return RedirectResponse("/queue", status_code=303)
    return templating.render(request, "login.html")


@router.post("/login")
def login_submit(
    request: Request,
    conn: Conn,
    cfg: Cfg,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
):
    try:
        claims = auth.login(conn, username, password, cfg)
    except auth.AuthDisabled:
        page = templating.render(
            request, "login.html", flash={"level": "error", "text": _AUTH_DISABLED_TEXT}
        )
        page.status_code = 503
        raise _RenderedPage(page) from None
    except auth.LoginFailed:
        conn.commit()  # planning decision 3: survive the redraw with a 401
        page = templating.render(
            request, "login.html", flash={"level": "error", "text": _LOGIN_FAILED_TEXT}
        )
        page.status_code = 401
        raise _RenderedPage(page) from None
    except auth.AccountLocked as exc:
        conn.commit()  # the lockout UPDATE must survive the 423
        locked_text = (
            f"Tài khoản bị khoá tới {templating.local_time(exc.locked_until, cfg.DISPLAY_TZ)}"
        )
        page = templating.render(
            request, "login.html", flash={"level": "error", "text": locked_text}
        )
        page.status_code = 423
        raise _RenderedPage(page) from None
    token = auth.issue_token(claims, cfg)
    redirect = RedirectResponse("/queue", status_code=303)
    set_session_cookie(redirect, token, cfg)
    return redirect


@router.post("/logout")
def logout_submit(conn: Conn, claims: Annotated[Claims, Depends(current_user)]):
    auth.logout(conn, claims.user_id)
    redirect = RedirectResponse("/login", status_code=303)
    clear_session_cookie(redirect)
    return redirect


@router.get("/")
def root_redirect():
    return RedirectResponse("/queue", status_code=303)
