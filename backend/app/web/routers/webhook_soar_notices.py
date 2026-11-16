"""`POST /webhook/soar-notices` (SR-T1, spec 2026-11-16 §2, "Contract A") — n8n, the SOAR, pushes the review tickets it opens
for the analyst on duty, and the plain notices, to the web. A machine key, not a person, so this route depends on neither
`current_user` nor `require_role`: like `/webhook/alerts` (`routers/webhook.py`, whose pattern this follows) it
authenticates with `X-API-Key` and an IP allowlist, and it is served by the app itself (the UI's nginx proxies only `/api/`:
n8n posts to the app's own port).

Order, exactly (spec §2; the reasons are `webhook.py`'s): an empty `SOAR_NOTICE_API_KEY` → `503` (never "no auth"); a
missing or wrong `X-API-Key` → `401`, **writing nothing** and checked before the body is read, so an attacker without the key
learns nothing about the body and grows nothing; a source address outside `SOAR_NOTICE_IP_ALLOWLIST` (empty = deny all) →
`403`, logged at warning (the address, never the key); a body over `MAX_PAYLOAD_BYTES` → `413`; then the body is parsed
(`400 {"detail": {"errors": [{"field", "reason"}]}}`, every fault listed, nothing written) and stored by the upsert table of
the spec (`soar/review_notice.py`): `201 {id, created: true}` for a new ticket, `200` for the others.

The three checks are a dependency declared BEFORE the connection (`_checked`): a request that fails one opens no connection.

The key is compared with `hmac.compare_digest` on bytes, so its time does not tell how much of a guess was right and a
non-ASCII header is a `401`, not an exception.

The size is enforced as the body is read, not only against `Content-Length`: a chunked upload declares no length, and the
cap must hold for it too.

No blocking call on the event loop (S0, 27/10/2026): this route is `async def` and the database half is blocking psycopg I/O,
so it runs in a worker thread (`_store_in_thread`), exactly as `webhook.py` does. Every wait there is bounded by
`lock_timeout` / `statement_timeout` (transaction-local): a wait that cannot end (a row another session holds) is cut into one
failed request, answered `503 busy` + `Retry-After` — n8n retries, and nothing wedges.

The request's connection (`Conn`) commits on success and rolls back on any raise, so a ticket and its audit event land
together or not at all.
"""

from __future__ import annotations

import hmac
import ipaddress
import logging
from typing import Annotated

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from app.infra.config import Config
from app.soar import review_notice
from app.web.deps import Cfg, Conn

router = APIRouter()

logger = logging.getLogger(__name__)

# The bounds of every database wait of the request (see the module docstring); read at call time, so a test shortens them.
_LOCK_TIMEOUT = "3s"
_STATEMENT_TIMEOUT = "5s"
# What a timed-out request tells the sender: a 503 "busy", unlike the 503 "disabled", carries a Retry-After.
_RETRY_AFTER_S = "2"


def _ip_allowed(host: str, allowlist: list[str]) -> bool:
    """An empty allowlist denies all: the loop then has nothing to match against. An entry that is not a network cannot be in
    the list (the configuration refuses it at the start), and a source that is no address at all matches nothing.
    """
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(address in ipaddress.ip_network(entry, strict=False) for entry in allowlist)


async def _read_body(request: Request, limit: int) -> bytes:
    """The body, at most `limit` bytes: `413` as soon as it is known to be longer, by the declared length or by what has
    arrived."""
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise HTTPException(status_code=413, detail="payload too large")
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HTTPException(status_code=413, detail="payload too large")
        chunks.append(chunk)
    return b"".join(chunks)


def _store_in_thread(conn: psycopg.Connection, body: bytes) -> review_notice.Applied:
    """The blocking half of the request, run by `run_in_threadpool` — never on the event loop.

    Bounds the waits, reads the body (`NoticeRejected` is raised with nothing written: a `400` has no row to commit before it
    is raised, unlike the alerts webhook's `rejected_alerts`) and stores it. Commit is left to `Conn`. `conn` is used by one
    thread at a time: made by the dependency, used here, closed by its teardown.
    """
    conn.execute(
        "SELECT set_config('lock_timeout', %s, true), set_config('statement_timeout', %s, true)",
        (_LOCK_TIMEOUT, _STATEMENT_TIMEOUT),
    )
    return review_notice.apply(conn, review_notice.parse(body))


def _checked(request: Request, cfg: Cfg) -> Config:
    """The three checks, in the order of the spec, and NOTHING that touches a database: this dependency is declared before `Conn`, so
    a request that fails one of them never opens a connection (m4: an unauthenticated flood used to hold one open per request).
    Returns the configuration the route goes on with."""
    config: Config = cfg
    if not config.SOAR_NOTICE_API_KEY:
        raise HTTPException(status_code=503, detail="soar notices disabled")

    given = request.headers.get("x-api-key", "")
    if not given or not hmac.compare_digest(given.encode(), config.SOAR_NOTICE_API_KEY.encode()):
        raise HTTPException(status_code=401, detail="unauthorized")

    host = request.client.host if request.client else ""
    if not _ip_allowed(host, config.SOAR_NOTICE_IP_ALLOWLIST):
        logger.warning("soar notices: source ip %s is outside SOAR_NOTICE_IP_ALLOWLIST", host)
        raise HTTPException(status_code=403, detail="forbidden")
    return config


Checked = Annotated[Config, Depends(_checked)]


@router.post("/webhook/soar-notices")
async def receive_soar_notice(request: Request, config: Checked, conn: Conn) -> JSONResponse:
    # `config` comes first on purpose: FastAPI solves the dependencies in the order of the parameters, so the checks run, and may
    # answer, before `conn` opens a connection.
    body = await _read_body(request, config.MAX_PAYLOAD_BYTES)
    try:
        applied = await run_in_threadpool(_store_in_thread, conn, body)
    except review_notice.NoticeRejected as exc:
        raise HTTPException(status_code=400, detail={"errors": exc.faults}) from exc
    except (psycopg.errors.LockNotAvailable, psycopg.errors.QueryCanceled) as exc:
        # `lock_timeout` / `statement_timeout` fired: "try again" is what this is. Exactly these two classes: anything else
        # is a bug and stays a 500. `Conn` rolls the aborted transaction back on the way out.
        logger.warning("soar notices: a wait timed out (%s); answering 503", type(exc).__name__)
        raise HTTPException(
            status_code=503, detail="busy", headers={"Retry-After": _RETRY_AFTER_S}
        ) from exc
    # A returned response is a success to `Conn`, which commits.
    return JSONResponse(applied.body(), status_code=201 if applied.outcome == "created" else 200)
