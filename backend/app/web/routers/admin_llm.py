"""`web/routers/admin_llm.py` — the admin's LLM page (spec §4.3, §5.2, §5.3).

Two operations, both `Admin` only: `PUT /api/admin/llm/limits` (P11-T03) and `GET
/api/admin/llm/usage` (P11-T04, below).

`PUT /api/admin/llm/limits`: the admin changes any of the three limits the pipelines read
through `infra.settings` — the monthly cost cap, the per-person ② quota in 24 h, the model-call
timeout.

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
and the row and its audit trail are written together or not at all. When `old` is a clamped
value (DEC-202: the stored timeout was above its ceiling and the ceiling was in force), that
entry also carries `stored`, the row's own value, so the trail explains the drop. A body that
changes nothing — empty, or equal to the effective values — writes nothing and answers the
limits as they are.

**Fail closed** (DEC-200 item 3): limits that cannot be read answer `503 {reason:
"limits_unavailable"}` and nothing is written.

`GET /api/admin/llm/usage?range=24h|7d|30d|month` (default `month`; anything else is a 422):
read-only, from `llm_runs` and `audit_events`, in five parts.

- **`month`** is the CALENDAR month, whatever the range: `spent_usd` is `month_spend_usd` itself
  (`created_at >= date_trunc('month', now())`, the query the adapter's cap check reads, so the
  page and the cap cannot disagree); `cap_usd` the effective cap (`null` when the limits cannot
  be read); `pct` = spent / cap x 100 FLOORED to one decimal (`null` without a cap), so that
  `pct >= 100` exactly when `spent >= cap`, which is the adapter's own comparison (rounded half up,
  29.99 of 30 would read 100.0 while the model still runs); `projected_usd` is the linear
  projection `spent / elapsed_days x days_in_month`, where `elapsed_days` is the time since the
  month began, fractional, with a FLOOR of one day (so a few minutes of spend on day 1 are not
  multiplied by thousands: day 1 projects `spent x days_in_month`, and from day 2 on the
  projection is the real linear one) and `days_in_month` the length of this month, both in days
  of 86400 s on the database's clock and time zone (the same `now()` the spend used).
- **`by_pipeline_role`** is the only part the range filters: one row per `(pipeline, role)` that
  has a run in the window (a rolling `now() - interval` for `24h`/`7d`/`30d`, and since the
  month began for `month`), ordered by pipeline then role (a NULL role, which v1 rows have,
  last): `calls`, `with_result` (`result IS NOT NULL`), `stopped` (`stopped_by` -> count, the
  NULL ones left out; a reason longer than 32 characters, the limit `recent` applies, is counted
  under `other`, so no key of the answer is longer than a short code), token sums,
  `latency_p50_ms` and `latency_p95_ms` (`percentile_cont`, rounded half up to an integer, `null`
  when no row carries a latency) and `cost_usd`. There is no chat row: `llm_runs.pipeline` admits
  `triage|investigate` only (spec decision 5).
- **`quota`**, always the rolling 24 h: `case.analyzed` events per user, counted by the rule
  `tier2_runs.ANALYZE_QUOTA_WHERE` that the analyze route enforces (one constant, two queries);
  `limit` the effective per-person quota (`null` when unreadable), `remaining = max(0, limit -
  used)` (`null` without a limit); only users with at least one event, most used first, then by
  username, at most `_QUOTA_USERS_LIMIT`.
- **`recent`**: the last 20 runs whatever the range, newest first. A prompt, a trace, a finding
  or the `result` never reaches Python: `outcome` is built in SQL from the one verdict key of
  the row (`suggested_action` for ① proposer, `structured_only_verdict` for ① verifier,
  `suggested_conclusion` for ②), and only when that value is a JSON STRING of at most 40
  characters; any other value, however it got there, is `null` (model output is untrusted, and
  the database's own CHECKs are not relied on). A row with no verdict is `stopped:<stopped_by>`
  when it has a (short) stop reason, else `null`.
- **`limits`**: `limits_out(conn, effective_limits(conn, cfg))`; when they cannot be read, `null`
  with `limits_error: "limits_unavailable"` and the rest is still served (the page shows the
  fail-closed panel). `tool_calls` is always 0 (spec decision 4).

Money is a JSON number with at most four decimals: `numeric` (a `Decimal` from psycopg) is
rounded half up to 4 places and converted to `float`, whose shortest repr is what the JSON holds
(`cost_usd` is `numeric(10,5)`, so the fifth decimal is the one dropped).

**Each block fails alone, and then the whole answer fails.** `month`, `by_pipeline_role`,
`quota` and `recent` each run in a savepoint (`conn.transaction()` inside the request's
transaction) after their own `SET LOCAL statement_timeout` (`BLOCK_TIMEOUT`); a `psycopg.Error`
rolls the savepoint back, so the transaction stays usable, and the answer is `503 {"detail":
{"reason": "timeout" | "query_failed"}}` (the codes of the overview). The limits block is the one
that degrades instead. `infra/db.transaction()` is NOT used: it issues its own BEGIN/COMMIT.
"""

from __future__ import annotations

import logging
from decimal import ROUND_DOWN, ROUND_HALF_UP, Decimal
from typing import Annotated, Any, Literal

import psycopg
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from psycopg import sql

from app.audit import llm_runs
from app.audit.events import write_event
from app.infra import settings
from app.infra.auth import Claims
from app.web.deps import Cfg, Conn, require_role
from app.web.routers import tier2_runs

router = APIRouter(prefix="/api/admin/llm")

logger = logging.getLogger(__name__)

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
            change = {"key": key, "old": getattr(current, field), "new": wanted[field]}
            if current.sources[key].clamped:
                # `old` is the value in force (the ceiling); the row's own value would otherwise
                # vanish from the trail with no event to explain the drop (P11-T03 review N3).
                change["stored"] = current.sources[key].stored
            changes.append(change)
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


# ---------------------------------------------------------------------------
# GET /usage — P11-T04
# ---------------------------------------------------------------------------

#: The `SET LOCAL statement_timeout` each block sets: a limit per statement. Read when a block
#: runs, so a test can shorten it.
BLOCK_TIMEOUT = "5s"

RangeName = Literal["24h", "7d", "30d", "month"]

#: `?range=` -> the lower bound of `by_pipeline_role`, as SQL on the database's clock. Constants
#: only (the `Literal` above is what a request can name), spliced with `sql.SQL`, never a request
#: value. `month` is the calendar month, as `llm_runs.month_spend_usd` reads it.
_SINCE_SQL = {
    "24h": "now() - interval '24 hours'",
    "7d": "now() - interval '7 days'",
    "30d": "now() - interval '30 days'",
    "month": "date_trunc('month', now())",
}

_RECENT_LIMIT = 20
#: The usage page's row cap on the one block that grows with the number of people.
_QUOTA_USERS_LIMIT = 200
#: A verdict or a stop reason longer than this is not a short code, so it is not served.
_OUTCOME_MAX_CHARS = 40
_STOPPED_PREFIX = "stopped:"
_STOPPED_MAX_CHARS = _OUTCOME_MAX_CHARS - len(_STOPPED_PREFIX)
#: The floor of the projection's elapsed time: one day (module docstring). A floor of one hour
#: still multiplied the first day's spend by up to 744 (P11-T04 review m3).
_ELAPSED_FLOOR_S = 86400.0

_BY_PIPELINE_ROLE_SQL = """
WITH win AS (
    SELECT pipeline, role, stopped_by, (result IS NOT NULL) AS has_result,
           input_tokens, output_tokens, latency_ms, cost_usd
    FROM llm_runs
    WHERE created_at >= {since}
), stopped AS (
    SELECT pipeline, role, jsonb_object_agg(reason, n) AS counts
    FROM (SELECT pipeline, role,
                 CASE WHEN length(stopped_by) <= {stopped_max} THEN stopped_by
                      ELSE 'other' END AS reason,
                 count(*) AS n
          FROM win WHERE stopped_by IS NOT NULL
          GROUP BY pipeline, role, 3) g
    GROUP BY pipeline, role
)
SELECT w.pipeline, w.role,
       count(*) AS calls,
       count(*) FILTER (WHERE w.has_result) AS with_result,
       (SELECT s.counts FROM stopped s
        WHERE s.pipeline = w.pipeline AND s.role IS NOT DISTINCT FROM w.role) AS stopped,
       coalesce(sum(w.input_tokens), 0) AS input_tokens,
       coalesce(sum(w.output_tokens), 0) AS output_tokens,
       round((percentile_cont(0.5) WITHIN GROUP (ORDER BY w.latency_ms))::numeric)::int AS p50,
       round((percentile_cont(0.95) WITHIN GROUP (ORDER BY w.latency_ms))::numeric)::int AS p95,
       coalesce(sum(w.cost_usd), 0) AS cost_usd
FROM win w
GROUP BY w.pipeline, w.role
ORDER BY w.pipeline, w.role NULLS LAST
"""

#: ② quota: the SAME rule as the analyze route (`tier2_runs.ANALYZE_QUOTA_WHERE`), grouped by
#: actor. The grouping runs on `audit_events` alone, so the fragment's unqualified `created_at`
#: is not ambiguous with `users.created_at`.
_QUOTA_USED_SQL = f"""
SELECT u.username, u.display_name, q.used
FROM (SELECT actor_id, count(*) AS used
      FROM audit_events
      WHERE {tier2_runs.ANALYZE_QUOTA_WHERE} AND actor_id IS NOT NULL
      GROUP BY actor_id) q
JOIN users u ON u.user_id = q.actor_id
ORDER BY q.used DESC, u.username
LIMIT %s
"""

#: `recent` selects NO text the model saw or wrote: `outcome` is computed here, from the one
#: verdict key of the row, and is a string of at most 40 characters or NULL. `result`,
#: `system_prompt`, `user_message`, `agent_trace` and the findings are not in the select list,
#: so nothing in Python can leak them.
_RECENT_SQL = """
SELECT r.run_id, r.created_at, r.pipeline, r.role, r.subject_type, r.subject_id,
       r.input_tokens, r.output_tokens, r.latency_ms,
       CASE
         WHEN r.result IS NOT NULL AND r.result -> k.verdict_key IS NOT NULL THEN
           CASE WHEN jsonb_typeof(r.result -> k.verdict_key) = 'string'
                     AND length(r.result ->> k.verdict_key) <= %(outcome_max)s
                THEN r.result ->> k.verdict_key END
         WHEN r.stopped_by IS NOT NULL AND length(r.stopped_by) <= %(stopped_max)s
           THEN %(prefix)s || r.stopped_by
       END AS outcome,
       r.cost_usd
FROM llm_runs r
CROSS JOIN LATERAL (
    SELECT CASE WHEN r.pipeline = 'investigate' THEN 'suggested_conclusion'
                WHEN r.role = 'verifier' THEN 'structured_only_verdict'
                ELSE 'suggested_action' END AS verdict_key
) k
ORDER BY r.created_at DESC, r.run_id DESC
LIMIT %(limit)s
"""

#: Seconds since this calendar month began, and its length in seconds: one statement on one
#: `now()`, in the session's time zone, like `llm_runs.month_spend_usd`.
_MONTH_CLOCK_SQL = """
SELECT extract(epoch FROM now() - date_trunc('month', now())),
       extract(epoch FROM (date_trunc('month', now()) + interval '1 month')
                          - date_trunc('month', now()))
"""


def _round(value: Any, places: int, rounding: str = ROUND_HALF_UP) -> float | None:
    """`value` (a `Decimal` from `numeric`, or a `float`) rounded to `places` decimals, HALF UP
    unless `rounding` says otherwise, as the `float` whose shortest repr is the JSON number;
    `None` stays `None`."""
    if value is None:
        return None
    step = Decimal(1).scaleb(-places)
    return float(Decimal(str(value)).quantize(step, rounding=rounding))


def _projected_usd(spent: float, elapsed_s: float, month_s: float) -> float:
    """The linear projection of the month's spend: `spent / elapsed_days x days_in_month`, in
    seconds `spent x month_s / max(elapsed_s, 86400)` — `elapsed_s` floored at one day, so the
    first hours of a month do not blow a few cents up by a factor of hundreds: the whole of day 1
    projects `spent x days_in_month`, and from day 2 on the projection is the real linear one."""
    return spent * month_s / max(elapsed_s, _ELAPSED_FLOOR_S)


def _block(conn: Any, name: str, compute: Any) -> Any:
    """`compute()` in a savepoint under its own `statement_timeout`. A database error rolls the
    savepoint back (the request's transaction stays usable) and becomes the 503 of the whole
    answer: `{"reason": "timeout"}` for a cancelled statement, `{"reason": "query_failed"}` for
    anything else. Never the driver's message: it can hold SQL text."""
    try:
        with conn.transaction():
            conn.execute(
                sql.SQL("SET LOCAL statement_timeout = {}").format(sql.Literal(BLOCK_TIMEOUT))
            )
            return compute()
    except psycopg.errors.QueryCanceled as exc:
        raise HTTPException(status_code=503, detail={"reason": "timeout"}) from exc
    except psycopg.Error as exc:
        logger.warning("usage block %s failed: %s %s", name, type(exc).__name__, exc.sqlstate)
        raise HTTPException(status_code=503, detail={"reason": "query_failed"}) from exc


def _limits_block(conn: Any, cfg: Any) -> tuple[settings.Limits | None, dict[str, Any] | None]:
    """`(limits, LimitsOut)`, or `(None, None)` when they cannot be read — the one block that
    degrades instead of failing the answer, because the page's fail-closed panel needs the rest.
    Same savepoint and timeout as the others; a failure of `limits_out`'s own read of the
    users counts as unreadable too."""
    try:
        with conn.transaction():
            conn.execute(
                sql.SQL("SET LOCAL statement_timeout = {}").format(sql.Literal(BLOCK_TIMEOUT))
            )
            limits = settings.effective_limits(conn, cfg)
            return limits, limits_out(conn, limits)
    except settings.SettingsUnavailable:
        return None, None
    except psycopg.Error as exc:
        logger.warning("usage limits failed: %s %s", type(exc).__name__, exc.sqlstate)
        return None, None


def month_figures(spent: float, cap_usd: int | None) -> dict[str, Any]:
    """`{spent_usd, cap_usd, pct}` of the calendar month: the three figures the usage page's
    `month` and the overview's `llm_month` (DEC-203 item 1) both serve, from ONE definition.
    `spent` is `llm_runs.month_spend_usd`; `cap_usd` the effective cap, `None` when the limits
    cannot be read (then `pct` is `None`, as it is for a cap of 0)."""
    pct = None
    if cap_usd is not None and cap_usd > 0:
        # Floored, not rounded: `pct >= 100` exactly when `spent >= cap_usd`, the adapter's own
        # comparison. Half up read 29.99 of 30 as 100.0 while the model still ran (review m1).
        pct = _round(Decimal(str(spent)) * 100 / cap_usd, 1, ROUND_DOWN)
    return {"spent_usd": _round(spent, 4), "cap_usd": cap_usd, "pct": pct}


def month_cap_usd(conn: Any, cfg: Any) -> int | None:
    """The effective monthly cap, or `None` when the limits cannot be read (`effective_limits`
    raises `SettingsUnavailable` on any database error, inside a savepoint of its own, so the
    caller's transaction stays usable)."""
    try:
        return settings.effective_limits(conn, cfg).cap_usd
    except settings.SettingsUnavailable:
        return None


def llm_month(conn: Any, cfg: Any) -> dict[str, Any]:
    """The overview's `llm_month` section (DEC-203): `month_figures` for the cap in force. A
    failure of the spend query is the CALLER's to turn into the section's error; an unreadable
    cap is not a failure (`cap_usd` and `pct` are `None`), as on the usage page."""
    cap_usd = month_cap_usd(conn, cfg)
    return month_figures(llm_runs.month_spend_usd(conn), cap_usd)


def _month(conn: Any, cap_usd: int | None) -> dict[str, Any]:
    spent = llm_runs.month_spend_usd(conn)  # the adapter's own query, not a copy of it
    elapsed_s, month_s = conn.execute(_MONTH_CLOCK_SQL).fetchone()
    return {
        **month_figures(spent, cap_usd),
        "projected_usd": _round(_projected_usd(spent, float(elapsed_s), float(month_s)), 4),
    }


def _by_pipeline_role(conn: Any, range_: str) -> list[dict[str, Any]]:
    query = sql.SQL(_BY_PIPELINE_ROLE_SQL).format(
        since=sql.SQL(_SINCE_SQL[range_]), stopped_max=sql.Literal(_STOPPED_MAX_CHARS)
    )
    rows = conn.execute(query).fetchall()
    return [
        {
            "pipeline": pipeline,
            "role": role,
            "calls": calls,
            "with_result": with_result,
            "stopped": dict(stopped or {}),
            "input_tokens": int(input_tokens),
            "output_tokens": int(output_tokens),
            "latency_p50_ms": p50,
            "latency_p95_ms": p95,
            "cost_usd": _round(cost, 4),
        }
        for (
            pipeline,
            role,
            calls,
            with_result,
            stopped,
            input_tokens,
            output_tokens,
            p50,
            p95,
            cost,
        ) in rows
    ]


def _quota_used(conn: Any) -> list[tuple[str, str, int]]:
    """`(username, display_name, used)`, most used first: the rolling 24 h of `case.analyzed`."""
    return conn.execute(_QUOTA_USED_SQL, (_QUOTA_USERS_LIMIT,)).fetchall()


def _recent(conn: Any) -> list[dict[str, Any]]:
    rows = conn.execute(
        _RECENT_SQL,
        {
            "outcome_max": _OUTCOME_MAX_CHARS,
            "stopped_max": _STOPPED_MAX_CHARS,
            "prefix": _STOPPED_PREFIX,
            "limit": _RECENT_LIMIT,
        },
    ).fetchall()
    return [
        {
            "run_id": run_id,
            "created_at": created_at,
            "pipeline": pipeline,
            "role": role,
            "subject_type": subject_type,
            "subject_id": subject_id,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "latency_ms": latency_ms,
            "outcome": outcome,
            "cost_usd": _round(cost, 4),
        }
        for (
            run_id,
            created_at,
            pipeline,
            role,
            subject_type,
            subject_id,
            input_tokens,
            output_tokens,
            latency_ms,
            outcome,
            cost,
        ) in rows
    ]


@router.get("/usage")
def api_usage(
    conn: Conn,
    cfg: Cfg,
    claims: Admin,
    range_: Annotated[RangeName, Query(alias="range")] = "month",
) -> dict[str, Any]:
    """The module docstring says what each part holds. 422 for a `range` outside the four; 503
    `{reason: "timeout" | "query_failed"}` when a block fails; 200 otherwise, `limits` being
    `null` (with `limits_error`) when they cannot be read."""
    limits, limits_payload = _limits_block(conn, cfg)
    cap_usd = None if limits is None else limits.cap_usd
    quota_limit = None if limits is None else limits.quota_per_24h

    # Looked up by name when the request runs (not captured at import), so a test can replace
    # one block's function to make it fail.
    month = _block(conn, "month", lambda: _month(conn, cap_usd))
    by_pipeline_role = _block(conn, "by_pipeline_role", lambda: _by_pipeline_role(conn, range_))
    used = _block(conn, "quota", lambda: _quota_used(conn))
    recent = _block(conn, "recent", lambda: _recent(conn))

    return {
        "range": range_,
        "month": month,
        "by_pipeline_role": by_pipeline_role,
        "quota": {
            "limit": quota_limit,
            "window": "24h",
            "users": [
                {
                    "username": username,
                    "display_name": display_name,
                    "used": count,
                    "remaining": None if quota_limit is None else max(0, quota_limit - count),
                }
                for username, display_name, count in used
            ],
        },
        "recent": recent,
        "limits": limits_payload,
        "limits_error": None if limits is not None else "limits_unavailable",
        "tool_calls": 0,
    }
