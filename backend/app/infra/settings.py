"""`infra.settings` — the ONE accessor of the three LLM limits the admin may change on the web
(P11-T03, DEC-200 item 3, spec §5.2).

`LLM_MONTHLY_USD_CAP`, `ANALYZE_QUOTA_PER_USER_DAY` and `LLM_TIMEOUT_S` live in `Config` (the
`.env` default) and may be overridden at run time by a row of the `settings` table (migration
019). Every reader asks this module, never `cfg`: `test_settings.py` greps `backend/app` for
an attribute access to the three names outside `infra/config.py` and this file.

**Fail closed.** `effective_limits` raises `SettingsUnavailable` when the table cannot be read
(it does not exist because the code was deployed before `make migrate`, the connection broke,
a privilege is missing). It never answers the `.env` value on an error: a caller that cannot
learn the limits must not spend money or admit a run. What each caller does with the
exception is the caller's, and written next to it: the adapter raises `LLMBudgetExceeded`
(① and ② record `stopped_by='cap'`), the ② route answers 503, the `monthly_cost` check fails.
A missing ROW is not an error: it means "not overridden" and the `.env` value applies.

**Read on every use, never cached**: one read of at most three rows, so a save takes effect
on the next call. The read runs in `with conn.transaction():`, which is a savepoint when the
connection is already inside a transaction (every request, every job) — a failed read rolls
back to it, so the CALLER'S transaction stays usable and whatever it wrote earlier is kept.
(Not `infra.db.transaction()`: that one issues its own BEGIN and COMMIT.)

**The timeout is bounded by the job lock** (DEC-202, review finding I1, and the amendment of
18/10 that followed the second review). A job holds one transaction open while it waits on the
model. ① makes up to FOUR sends (the proposer and the verifier, each with at most one repair); ②
makes up to TWO (the call, then its repair). `JOB_LOCK_TIMEOUT_S` is the job transaction's
idle-in-transaction timeout and the age at which `reclaim_stale` calls a job dead
(`tier2/investigate.py:19-33`).

- The bound protects EACH SEND. The adapter runs SQL before every attempt, which resets the
  idle-in-transaction timer, so a send held to `timeout_max(cfg)` = `(JOB_LOCK_TIMEOUT_S - 60)
  // 2` (120 s at the default 300 s, never above the Owner's static 600) finishes inside the
  session.
- The TOTAL margin, `2 x LLM_TIMEOUT_S + 60 <= JOB_LOCK_TIMEOUT_S`, holds for ② and, for ①, only
  while one worker runs: `reclaim_stale` is called by a worker's own loop, so with one worker it
  cannot reclaim a job that is still running. ①'s four sends predate P11, with the `.env`
  timeout of 120.
- The invariant needs `JOB_LOCK_TIMEOUT_S >= 80`: below it the web floor of 10 cannot keep it,
  and the unclamped `.env` timeout is the larger risk anyway.

`effective_limits` holds a STORED value to the bound when it reads it — a later lowering of
`JOB_LOCK_TIMEOUT_S` in `.env` cannot reopen the hole. The `.env` value is the Owner's own and
is not clamped.

`infra` imports nothing from the app outside `infra` (G1): this module needs only `psycopg`
and `infra.config`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

import psycopg

from app.infra.config import Config

KEYS = ("LLM_MONTHLY_USD_CAP", "ANALYZE_QUOTA_PER_USER_DAY", "LLM_TIMEOUT_S")

#: The STATIC envelope of the web values (the Owner's decision 2, spec §10), inclusive. What the
#: route enforces and the readers hold to is `bounds(cfg)`: the same, but with the timeout's top
#: derived from the job lock (DEC-202) — never above the 600 here. The database only refuses
#: what no bound could make sense of: zero, negative, an unknown key.
BOUNDS = {
    "LLM_MONTHLY_USD_CAP": (1, 1000),
    "ANALYZE_QUOTA_PER_USER_DAY": (1, 200),
    "LLM_TIMEOUT_S": (10, 600),
}

#: The margin `tier2/investigate.py:19-33` keeps between a job's model time and
#: `JOB_LOCK_TIMEOUT_S`. A module value (read at call time) so the scaled test of the job lock
#: can shrink it together with the lock itself.
JOB_MARGIN_S = 60

#: The `Limits` attribute (and the request/response field of `PUT /api/admin/llm/limits`)
#: each key is read and written as.
FIELD_OF_KEY = {
    "LLM_MONTHLY_USD_CAP": "cap_usd",
    "ANALYZE_QUOTA_PER_USER_DAY": "quota_per_24h",
    "LLM_TIMEOUT_S": "timeout_s",
}


class SettingsUnavailable(Exception):
    """The stored limits could not be read. Never answered with the `.env` value."""


@dataclass(frozen=True)
class LimitSource:
    source: Literal["env", "web"]
    updated_at: datetime | None
    updated_by: str | None  # a user_id as text; None for `env`
    clamped: bool = False  # True: the stored web value was above its ceiling and was held to it
    #: The row's own value, set only when `clamped` (the effective value is then the ceiling, not
    #: this): the audit entry of a change over a clamped value carries it (P11-T20 row 6).
    stored: int | None = None


@dataclass(frozen=True)
class Limits:
    cap_usd: int
    quota_per_24h: int
    timeout_s: int
    sources: dict[str, LimitSource]  # keyed by the KEYS names
    #: The ceiling the timeout is held to (`timeout_max(cfg)`), carried so the answer of the
    #: admin route can show the page the real maximum without being handed `cfg` again.
    timeout_max: int = BOUNDS["LLM_TIMEOUT_S"][1]


def timeout_max(cfg: Config) -> int:
    """The highest model timeout the web may set: `(JOB_LOCK_TIMEOUT_S - 60) // 2` (120 s at the
    default 300), never above the Owner's static ceiling and never below the floor of the
    envelope. The bound protects each send (① makes up to four, ② up to two). The total margin,
    `2 x timeout + 60 <= JOB_LOCK_TIMEOUT_S`, holds for ② and, for ①, only while one worker runs;
    the invariant needs `JOB_LOCK_TIMEOUT_S >= 80`, as the floor cannot keep it below that."""
    low, high = BOUNDS["LLM_TIMEOUT_S"]
    return max(low, min(high, (cfg.JOB_LOCK_TIMEOUT_S - JOB_MARGIN_S) // 2))


def _bounds_with_timeout_max(ceiling: int) -> dict[str, tuple[int, int]]:
    return {**BOUNDS, "LLM_TIMEOUT_S": (BOUNDS["LLM_TIMEOUT_S"][0], ceiling)}


def bounds(cfg: Config) -> dict[str, tuple[int, int]]:
    """Inclusive `(min, max)` per key as the route enforces them: `BOUNDS` with the timeout's top
    derived from the job lock of `cfg` (`timeout_max`)."""
    return _bounds_with_timeout_max(timeout_max(cfg))


def bounds_of(limits: Limits) -> dict[str, tuple[int, int]]:
    """The same ranges for limits already read: the ceiling they were held to is in them."""
    return _bounds_with_timeout_max(limits.timeout_max)


def from_config(cfg: Config) -> Limits:
    """The `.env` view: every value from `cfg`, every source `env`. The adapter's default when
    nothing is wired (the eval harness, which has no `settings` table to read) and the base
    `effective_limits` lays the table's rows over. The `.env` timeout is the Owner's own and is
    not clamped."""
    return Limits(
        cap_usd=cfg.LLM_MONTHLY_USD_CAP,
        quota_per_24h=cfg.ANALYZE_QUOTA_PER_USER_DAY,
        timeout_s=cfg.LLM_TIMEOUT_S,
        sources={key: LimitSource("env", None, None) for key in KEYS},
        timeout_max=timeout_max(cfg),
    )


def effective_limits(conn: psycopg.Connection, cfg: Config) -> Limits:
    """A `settings` row wins; otherwise the `.env` value of `cfg` applies, per key.

    Raises `SettingsUnavailable` on any `psycopg.Error` — the read failed, so nothing is known.
    The savepoint makes the failure harmless to the caller's own transaction."""
    if conn.info.transaction_status == psycopg.pq.TransactionStatus.INERROR:
        # The caller's transaction is already aborted: nothing can be read, and entering
        # `conn.transaction()` here would fail on its SAVEPOINT *after* psycopg has counted
        # the block as open — leaving `conn.rollback()` and `commit()` refused for good.
        raise SettingsUnavailable("settings unreadable: the transaction is already aborted")
    try:
        with conn.transaction():
            rows = conn.execute(
                "SELECT key, value, updated_at, updated_by FROM settings"
            ).fetchall()
    except psycopg.Error as exc:
        raise SettingsUnavailable(f"settings unreadable: {type(exc).__name__}") from exc

    limits = from_config(cfg)
    values = {
        "cap_usd": limits.cap_usd,
        "quota_per_24h": limits.quota_per_24h,
        "timeout_s": limits.timeout_s,
    }
    sources = dict(limits.sources)
    for key, value, updated_at, updated_by in rows:
        if key not in FIELD_OF_KEY:  # `ck_settings_key` makes this unreachable; never trust it
            continue
        value = int(value)
        clamped = key == "LLM_TIMEOUT_S" and value > limits.timeout_max
        values[FIELD_OF_KEY[key]] = limits.timeout_max if clamped else value
        sources[key] = LimitSource(
            "web",
            updated_at,
            None if updated_by is None else str(updated_by),
            clamped,
            value if clamped else None,
        )
    return Limits(sources=sources, timeout_max=limits.timeout_max, **values)
