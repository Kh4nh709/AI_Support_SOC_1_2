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
"""

from __future__ import annotations

import hmac
import ipaddress
import logging

from fastapi import APIRouter, HTTPException, Request

from app.infra import intake
from app.web.deps import Cfg, Conn

router = APIRouter()

logger = logging.getLogger(__name__)


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
        receipt = intake.receive(conn, body, host, cfg)
    except intake.PayloadTooLarge as exc:
        raise HTTPException(status_code=413, detail="payload too large") from exc
    except intake.Rejected as exc:
        conn.commit()
        raise HTTPException(status_code=400, detail={"missing": exc.reason}) from exc
    except intake.Duplicate as exc:
        raise HTTPException(status_code=409, detail="duplicate") from exc

    if receipt.kind == "heartbeat":
        return {"heartbeat": True}
    return {"intake_id": receipt.intake_id}
