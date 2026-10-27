"""`POST /webhook/alerts` (context pack §6.4, §6.3, architecture §3.1) — the
secondary intake path: a machine key, not a person, so this route depends on
neither `current_user` nor `require_role` (P4-tasks.md planning decision 2's
`web/deps.py` glue is for analysts; a manager integration authenticates with
`X-API-Key` + an IP allowlist instead).

Order, exactly (design note 2): empty `WEBHOOK_API_KEY` → `503` (DEC-040 —
never "no auth"); missing/wrong key → `401`, **writing nothing** — checked
before the body is even read, so an attacker cannot grow the database without
a key; source IP outside `WEBHOOK_IP_ALLOWLIST` → `403` (logged at warning:
the IP, never the key); then the body is read and handed to `intake.receive`.

Commit before raise (planning decision 3): a `400` (`intake.Rejected`) has
already written a `rejected_alerts` row inside `receive()`, and `Conn`
(`scope="function"`) rolls back on any exception including `HTTPException` —
so that row must be committed explicitly before the `400` is raised, exactly
as `routers/auth.py` does for the failed-login counter and `authz.denied`.

No blocking call on the event loop (S0, 27/10/2026): this route is `async def`, and
`intake.receive` is blocking psycopg I/O. Run on the loop it wedged the whole app: with
`PULL_ENABLED=false` every accepted alert upserts the ONE `source_heartbeat` row, so request A
held that row's lock until its `Conn` teardown committed, and that commit had to be scheduled by
the very loop request B was blocking inside its own `UPDATE` — A waited for the loop, B held the
loop waiting for A, nothing bounded the wait, and even the 401 path (which touches no database)
went unanswered until a restart. So the database half of the request (the waits' bounds,
`intake.receive`, the 400's commit) runs in a worker thread (`_receive_in_thread`) and the loop
never blocks: the `Conn` teardown that commits is always schedulable (FastAPI runs a sync
dependency's exit on a limiter of its own, so a busy default pool cannot starve it either), and a
wait that still cannot end — a lock held by another session — is cut by `lock_timeout` into one
failed request.
"""

from __future__ import annotations

import hmac
import ipaddress
import logging

import psycopg
from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from app.infra import intake
from app.infra.config import Config
from app.web.deps import Cfg, Conn

router = APIRouter()

logger = logging.getLogger(__name__)

# Defence in depth (S0): every database wait on the intake path is bounded, so the worst case of
# contention is one failed request (a 500 the sender retries), never a wedge. `lock_timeout` is
# the one that matters here (the hot `source_heartbeat` row); `statement_timeout` caps anything
# else. Transaction-local (`set_config(..., true)`), so nothing leaks into the next use of the
# connection. Read at call time, so a test can shorten them.
_LOCK_TIMEOUT = "3s"
_STATEMENT_TIMEOUT = "5s"


def _ip_allowed(host: str, allowlist: list[str]) -> bool:
    """An empty allowlist denies all (DEC-040) — the loop below then has
    nothing to match against, which already gives that answer."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    for cidr in allowlist:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if addr in network:
            return True
    return False


def _receive_in_thread(
    conn: psycopg.Connection, body: bytes, host: str, cfg: Config
) -> intake.Receipt:
    """The blocking half of the request, run by `run_in_threadpool` — never on the event loop.

    Bounds the waits, then calls `intake.receive` unchanged. Commit before raise (module
    docstring): a `Rejected` has written its `rejected_alerts` row, so it is committed here, in
    the worker thread, before the route turns it into the 400 (a commit on the loop would be a
    blocking call too). Every other outcome is left to `Conn`: commit on success, rollback on any
    exception. `conn` is used by one thread at a time — made by the dependency, used here, closed
    by its teardown — never concurrently.
    """
    conn.execute(
        "SELECT set_config('lock_timeout', %s, true), set_config('statement_timeout', %s, true)",
        (_LOCK_TIMEOUT, _STATEMENT_TIMEOUT),
    )
    try:
        return intake.receive(conn, body, host, cfg)
    except intake.Rejected:
        conn.commit()
        raise


@router.post("/webhook/alerts", status_code=201)
async def receive_alert(request: Request, conn: Conn, cfg: Cfg) -> dict:
    if not cfg.WEBHOOK_API_KEY:
        raise HTTPException(status_code=503, detail="webhook disabled")

    given = request.headers.get("x-api-key", "")
    if not given or not hmac.compare_digest(given.encode(), cfg.WEBHOOK_API_KEY.encode()):
        raise HTTPException(status_code=401, detail="unauthorized")

    host = request.client.host if request.client else ""
    if not _ip_allowed(host, cfg.WEBHOOK_IP_ALLOWLIST):
        logger.warning("webhook: source ip %s is outside WEBHOOK_IP_ALLOWLIST", host)
        raise HTTPException(status_code=403, detail="forbidden")

    body = await request.body()
    try:
        receipt = await run_in_threadpool(_receive_in_thread, conn, body, host, cfg)
    except intake.PayloadTooLarge as exc:
        raise HTTPException(status_code=413, detail="payload too large") from exc
    except intake.Rejected as exc:
        raise HTTPException(status_code=400, detail={"missing": exc.reason}) from exc
    except intake.Duplicate as exc:
        raise HTTPException(status_code=409, detail="duplicate") from exc

    if receipt.kind == "heartbeat":
        return {"heartbeat": True}
    return {"intake_id": receipt.intake_id}
