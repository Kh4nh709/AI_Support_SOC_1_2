"""GET /api/ws — the queue's real-time socket (DEC-162, P10-T05).

The protocol, in the order the server speaks it:

1. The server accepts, then waits up to `AUTH_TIMEOUT_S` (5 s) for exactly one message,
   `{"type": "auth", "token": "<jwt>"}`. The token travels in that FIRST MESSAGE and
   nowhere else — never the URL. A URL lands in access logs, reverse-proxy logs and browser
   history; a frame does not. A `?token=` (and an `Authorization` header) is ignored: this
   socket reads no request metadata for identity.
2. A missing, malformed, invalid or expired token — an unknown, inactive or logged-out user
   — closes the socket with code **4401**. (Any other message, or none inside 5 s, is 4401
   too.) The signature and expiry are checked FIRST, without the database (`auth.decode`):
   a token that cannot be valid never costs a connection. The browser client treats 4401 as
   "sign in again" and never as "retry".
3. Otherwise `{"type": "ready"}`, then `{"type": "alerts.changed", "ids": [...]}` or
   `{"type": "alerts.changed", "many": true}` from the hub (`app.web.live`).
4. The token is re-verified against the `users` row every `REVERIFY_INTERVAL_S` (60 s) and
   again at its own `exp`; a failure closes 4401. A logout or a deactivation therefore ends
   an open socket within a minute, exactly as it ends an HTTP session on its next request.
5. tier1, tier2 and admin may connect. The role is the ROW's, as on every HTTP route.

Two more closes are deliberate. **1011** is an infrastructure failure while checking (the
database unreachable, the secret unset): it is never 4401, because 4401 sends the browser to
the login page and an outage is not a logout. **4403** is a verified user whose role is not
in `ALLOWED_ROLES`; with today's three roles it is unreachable, and it is here so that a
fourth role is refused, not admitted by omission.

The subscription is taken BEFORE `ready` is sent, so anything committed after the client has
seen `ready` reaches it. Lifecycle: `lifespan` (merged into the app's by `include_router`)
starts ONE listener task on `Config.DATABASE_URL` and cancels it at shutdown.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI, WebSocket
from fastapi.concurrency import run_in_threadpool
from starlette.websockets import WebSocketDisconnect

from app.infra import auth, config, db
from app.infra.auth import Claims
from app.infra.config import Config
from app.web import live
from app.web.deps import Cfg

log = logging.getLogger(__name__)

AUTH_TIMEOUT_S = 5
REVERIFY_INTERVAL_S = 60
VERIFY_TIMEOUT_S = 10  # one lookup; a black-holed database must not hold a socket open
CONNECT_TIMEOUT_S = 10  # libpq's connect_timeout for that lookup's connection (seconds)
MAX_AUTH_MESSAGE_CHARS = 8192  # a signed token is a few hundred bytes
ALLOWED_ROLES = frozenset({"tier1", "tier2", "admin"})

CLOSE_UNAUTHORIZED = 4401
CLOSE_FORBIDDEN = 4403
CLOSE_INTERNAL = 1011


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """One LISTEN connection for this process, for as long as the app runs."""
    dsn = config.load().DATABASE_URL
    task: asyncio.Task | None = None
    if dsn:
        task = asyncio.create_task(live.run_listener(live.HUB, dsn), name="alerts-listener")
    else:
        log.warning("DATABASE_URL is not set: /api/ws will answer, but no alert will reach it")
    try:
        yield
    finally:
        if task is not None:
            await _retire(task)


router = APIRouter(lifespan=lifespan)


async def _retire(*tasks: asyncio.Future) -> None:
    """Cancel `tasks`, wait until they are gone, and mark their outcome as seen.

    Not `asyncio.gather(..., return_exceptions=True)`: a `gather` that is itself cancelled
    while it waits raises a bare `CancelledError()` (its outer future is failed with a new,
    message-less one), and anyio — which runs the app under Starlette's `TestClient` — does
    not recognise a cancellation without its message as its own, so it neither swallows it
    nor lets the test end cleanly. `asyncio.wait` keeps the cancellation's message.
    """
    for task in tasks:
        task.cancel()
    try:
        await asyncio.wait(tasks)
    finally:
        for task in tasks:
            if task.done() and not task.cancelled():
                task.exception()  # retrieved: no "exception was never retrieved" at GC


async def _close(websocket: WebSocket, code: int, reason: str) -> None:
    try:
        await websocket.close(code=code, reason=reason)
    except (RuntimeError, WebSocketDisconnect):  # the peer went first
        pass


def _token_of(message: dict) -> str | None:
    """The token of a well-formed auth frame, else None."""
    text = message.get("text")
    if not isinstance(text, str) or len(text) > MAX_AUTH_MESSAGE_CHARS:
        return None
    try:
        body = json.loads(text)
    except ValueError:
        return None
    if not isinstance(body, dict) or body.get("type") != "auth":
        return None
    token = body.get("token")
    return token if isinstance(token, str) and token else None


def _verify_blocking(token: str, cfg: Config) -> Claims:
    """The HTTP `current_user` check, on a connection of its own (thread-pool work).

    The signature and expiry come first (`auth.decode`, the very code `auth.verify` starts
    with): a socket that has said nothing yet must not cost a connection to anyone who
    cannot even forge a token, so a bad one is refused (`Unauthorized`, 4401) before the
    database is touched. `verify` then decodes again and checks the row — the same single
    implementation as HTTP, no copy of it here. `CONNECT_TIMEOUT_S` because this runs for
    an unauthenticated peer, on a thread of the shared pool: a black-holed host must not
    keep it for libpq's default.
    """
    auth.decode(token, cfg)
    conn = db.connect(cfg.DATABASE_URL, connect_timeout=CONNECT_TIMEOUT_S)
    try:
        return auth.verify(conn, token, cfg)
    finally:
        conn.close()


async def _verified(websocket: WebSocket, token: str, cfg: Config) -> Claims | None:
    """The row-checked claims, or None after closing the socket with the right code."""
    try:
        claims = await asyncio.wait_for(
            run_in_threadpool(_verify_blocking, token, cfg), VERIFY_TIMEOUT_S
        )
    except auth.Unauthorized:
        await _close(websocket, CLOSE_UNAUTHORIZED, "unauthorized")
        return None
    except Exception as exc:  # noqa: BLE001 — an outage is not a logout
        # The class only: a driver message can quote the DSN.
        log.warning("/api/ws: could not verify a token (%s)", type(exc).__name__)
        await _close(websocket, CLOSE_INTERNAL, "verification unavailable")
        return None
    if claims.role not in ALLOWED_ROLES:
        await _close(websocket, CLOSE_FORBIDDEN, "forbidden")
        return None
    return claims


async def _first_token(websocket: WebSocket) -> str | None:
    """The token of the first message, or None after closing (or after the peer left)."""
    try:
        message = await asyncio.wait_for(websocket.receive(), AUTH_TIMEOUT_S)
    except TimeoutError:
        await _close(websocket, CLOSE_UNAUTHORIZED, "auth timeout")
        return None
    if message["type"] == "websocket.disconnect":
        return None
    token = _token_of(message)
    if token is None:
        await _close(websocket, CLOSE_UNAUTHORIZED, "auth required")
    return token


async def _serve(
    websocket: WebSocket, sub: live.Subscription, token: str, claims: Claims, cfg: Config
) -> None:
    """Forward hub messages; re-verify every interval and at `exp`; stop on disconnect."""
    next_check = time.monotonic() + REVERIFY_INTERVAL_S
    outgoing = asyncio.ensure_future(sub.next_message())
    incoming = asyncio.ensure_future(websocket.receive())
    try:
        while True:
            if time.time() >= claims.exp:
                await _close(websocket, CLOSE_UNAUTHORIZED, "token expired")
                return
            if time.monotonic() >= next_check:
                checked = await _verified(websocket, token, cfg)
                if checked is None:
                    return
                claims, next_check = checked, time.monotonic() + REVERIFY_INTERVAL_S
                continue
            wait = min(next_check - time.monotonic(), claims.exp - time.time())
            done, _ = await asyncio.wait(
                {outgoing, incoming}, timeout=max(wait, 0), return_when=asyncio.FIRST_COMPLETED
            )
            if incoming in done:
                if incoming.result()["type"] == "websocket.disconnect":
                    return
                # Nothing a client sends after `auth` means anything: read it and go on.
                incoming = asyncio.ensure_future(websocket.receive())
            if outgoing in done:
                await websocket.send_json(outgoing.result())
                outgoing = asyncio.ensure_future(sub.next_message())
    finally:
        await _retire(outgoing, incoming)


@router.websocket("/api/ws")
async def alerts_socket(websocket: WebSocket, cfg: Cfg) -> None:
    await websocket.accept()
    token = await _first_token(websocket)
    if token is None:
        return
    claims = await _verified(websocket, token, cfg)
    if claims is None:
        return
    sub = live.HUB.subscribe()  # before `ready`: nothing after it can be missed
    try:
        await websocket.send_json({"type": "ready"})
        await _serve(websocket, sub, token, claims, cfg)
    except (WebSocketDisconnect, RuntimeError):  # the peer went away mid-send
        pass
    finally:
        sub.close()
