"""`web/routers/admin_llm.py` — the admin's LLM page (spec §4.3, §5.2, §5.3).

Today one operation, `PUT /api/admin/llm/limits` (P11-T03): the admin changes any of the three
limits the pipelines read through `infra.settings` — the monthly cost cap, the per-person ②
quota in 24 h, the model-call timeout. P11-T04 adds `GET /api/admin/llm/usage` to this same
module and embeds `limits_out()` in its answer.

The body is any of `cap_usd`, `quota_per_24h`, `timeout_s`, each a JSON integer inside
`settings.bounds(cfg)`: the Owner's decision 2, with the timeout's top held to what the job
lock allows (DEC-202: 120 s at the default `JOB_LOCK_TIMEOUT_S` of 300, so the 422's `max` is
that derived one, not 600). Everything the PUT says about a bad value is a 422
whose `detail` is one object: `{field, reason: "unknown"}`, `{field, reason: "not_integer"}`
(`"30"`, `30.5`, `30.0`, `true`, `null`, a list are all this), or `{field, reason:
"out_of_range", min, max}`. It names the FIRST bad field in the order the body gave them, and
a bad field makes the whole request write nothing.

In the request's own transaction (`Conn` is `scope="function"`: a 2xx means committed) it
takes a transaction-scoped advisory lock, reads the effective limits, upserts ONLY the keys
whose value changes, and writes ONE `admin.settings_changed` event `{changes: [{key, old,
new}]}` — so two admins saving at once are a chain (the second's `old` is the first's `new`),
and the row and its audit trail are written together or not at all. A body that changes
nothing — empty, or equal to the effective values — writes nothing and answers the limits as
they are.

**Fail closed** (DEC-200 item 3): limits that cannot be read answer `503 {reason:
"limits_unavailable"}` and nothing is written.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException

from app.audit.events import write_event
from app.infra import settings
from app.infra.auth import Claims
from app.web.deps import Cfg, Conn, require_role

router = APIRouter(prefix="/api/admin/llm")

#: One dependency object (the `admin_rules.py` / `tier2_runs.py` pattern) so `Depends`
#: resolves it once per request, and a test can find it on every route of this module.
require_admin = require_role("admin")
Admin = Annotated[Claims, Depends(require_admin)]

#: The request/response field of each key — the inverse of `settings.FIELD_OF_KEY`.
KEY_OF_FIELD = {field: key for key, field in settings.FIELD_OF_KEY.items()}

#: `pg_advisory_xact_lock(hashtext(...))`: held until the request's transaction ends.
_LOCK_NAME = "admin.llm.limits"

_UPSERT = (
    "INSERT INTO settings (key, value, updated_by) VALUES (%s, %s, %s) "
    "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(), "
    "updated_by = EXCLUDED.updated_by"
)


def _unprocessable(**detail: Any) -> HTTPException:
    return HTTPException(status_code=422, detail=detail)


def _read_limits(conn: Any, cfg: Any) -> settings.Limits:
    """The effective limits, or the 503 every reader of them answers when they cannot be read."""
    try:
        return settings.effective_limits(conn, cfg)
    except settings.SettingsUnavailable as exc:
        raise HTTPException(status_code=503, detail={"reason": "limits_unavailable"}) from exc


def _validate(body: dict[str, Any], cfg: Any) -> dict[str, int]:
    """`{field: value}` for a body of valid integers inside `settings.bounds(cfg)`, or the 422 of
    its first bad field."""
    ranges = settings.bounds(cfg)
    wanted: dict[str, int] = {}
    for field, value in body.items():
        key = KEY_OF_FIELD.get(field)
        if key is None:
            raise _unprocessable(field=field, reason="unknown")
        # `bool` is an `int` in Python; JSON `true` is not a number of ours. A float (even
        # `30.0`) is not a JSON integer either.
        if isinstance(value, bool) or not isinstance(value, int):
            raise _unprocessable(field=field, reason="not_integer")
        low, high = ranges[key]
        if not low <= value <= high:
            raise _unprocessable(field=field, reason="out_of_range", min=low, max=high)
        wanted[field] = value
    return wanted


def limits_out(conn: Any, limits: settings.Limits) -> dict[str, Any]:
    """`LimitsOut`: the three values and, per key, where each came from — `env`, or `web` with
    the time of the save and who made it (`users.display_name`, the username when that is
    empty; `null` for `env`). `clamped` says a stored web timeout was above its ceiling and the
    value shown is the ceiling (DEC-202). `bounds` is what the page's form may offer, per field —
    the timeout's `max` is the derived one. P11-T04 embeds the same object in the usage answer."""
    user_ids = sorted({s.updated_by for s in limits.sources.values() if s.updated_by})
    names: dict[str, str] = {}
    if user_ids:
        rows = conn.execute(
            "SELECT user_id::text, display_name, username FROM users WHERE user_id = ANY(%s::uuid[])",
            (user_ids,),
        ).fetchall()
        names = {user_id: display_name or username for user_id, display_name, username in rows}
    return {
        "cap_usd": limits.cap_usd,
        "quota_per_24h": limits.quota_per_24h,
        "timeout_s": limits.timeout_s,
        "sources": {
            key: {
                "source": source.source,
                "updated_at": source.updated_at,
                "updated_by_name": names.get(source.updated_by) if source.updated_by else None,
                "clamped": source.clamped,
            }
            for key, source in limits.sources.items()
        },
        "bounds": {
            settings.FIELD_OF_KEY[key]: {"min": low, "max": high}
            for key, (low, high) in settings.bounds_of(limits).items()
        },
    }


@router.put("/limits")
def api_put_limits(
    conn: Conn,
    claims: Admin,
    cfg: Cfg,
    body: Annotated[dict[str, Any] | None, Body()] = None,
) -> dict[str, Any]:
    """`200 {limits: LimitsOut}`; 422 per the module docstring; 503 when the limits cannot be
    read. The 4xx/5xx paths raise before anything is written, and `get_conn` rolls back."""
    wanted = _validate(body or {}, cfg)

    conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (_LOCK_NAME,))
    current = _read_limits(conn, cfg)

    changes = []
    for key in settings.KEYS:  # the same order every time, whatever order the body had
        field = settings.FIELD_OF_KEY[key]
        if field in wanted and wanted[field] != getattr(current, field):
            changes.append({"key": key, "old": getattr(current, field), "new": wanted[field]})
    if not changes:
        return {"limits": limits_out(conn, current)}

    with conn.transaction():  # the rows and their one event: all or nothing
        for change in changes:
            conn.execute(_UPSERT, (change["key"], change["new"], claims.user_id))
        write_event(
            conn,
            "admin.settings_changed",
            "llm_limits",
            "admin",
            actor_id=claims.user_id,
            payload={"changes": changes},
        )
    return {"limits": limits_out(conn, _read_limits(conn, cfg))}
