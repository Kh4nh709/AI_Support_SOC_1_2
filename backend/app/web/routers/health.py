"""`GET /health` (context pack §6.4, §6.3) — the one unauthenticated route P5
adds, and it is narrow (P5-tasks.md planning decision 3): open only from
loopback; every other caller goes through the `require_role("admin")`
dependency, so an admin session still answers and anyone else gets 403. Two
literals and this comment are the whole exemption — not a config key, not a
CIDR list, not a header check.

`current_user`'s 401 ("not authenticated") is caught and re-raised as 403
here, specifically for this route: design note 6 and its own acceptance list
both call for "a non-loopback client without a session -> 403", not the 401
`require_role` gives every other admin route when no session is presented —
this route answers uniformly (wrong role or no session, both 403) rather than
distinguishing the two for a caller outside the trust boundary in the first
place. `web/deps.py` itself is untouched (not in this card's file list); both
functions are reused exactly as written elsewhere.

Limitation (design note 6, stated, not hidden): `request.client.host` is the
direct TCP peer. Behind a reverse proxy it would be the proxy's own address,
not the original caller's — this deployment has none (`make run-app` binds
`127.0.0.1:8000`), so the check is correct here and would need revisiting
behind one.

The response body is exactly the newest `system_health` row (`checked_at`,
`checks`, `ok`) — no DSN, no secret, no internal filesystem path: `checks`'
`detail` strings never include one (see `infra/health.py`'s check functions).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from app.web.deps import Cfg, Conn, current_user, require_role

router = APIRouter()

# §6.4 "no auth from localhost" — the whole allowlist, named here, not in Config.
_LOOPBACK_HOSTS = {"127.0.0.1", "::1"}


@router.get("/health")
def get_health(request: Request, conn: Conn, cfg: Cfg) -> dict:
    host = request.client.host if request.client else ""
    if host not in _LOOPBACK_HOSTS:
        try:
            claims = current_user(request, conn, cfg)
        except HTTPException as exc:
            if exc.status_code == 401:
                raise HTTPException(status_code=403, detail="forbidden") from exc
            raise
        require_role("admin")(request, conn, claims)

    row = conn.execute(
        "SELECT checked_at, checks, ok FROM system_health ORDER BY checked_at DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return {"checked_at": None, "checks": [], "ok": None}
    checked_at, checks, ok = row
    return {"checked_at": checked_at.isoformat(), "checks": checks, "ok": ok}
