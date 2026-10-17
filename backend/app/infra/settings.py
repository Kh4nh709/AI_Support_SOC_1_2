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

#: Inclusive bounds the web route enforces (the Owner's decision 2, spec §10). The database
#: only refuses what no bound could make sense of — zero, negative, an unknown key.
BOUNDS = {
    "LLM_MONTHLY_USD_CAP": (1, 1000),
    "ANALYZE_QUOTA_PER_USER_DAY": (1, 200),
    "LLM_TIMEOUT_S": (10, 600),
}

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


@dataclass(frozen=True)
class Limits:
    cap_usd: int
    quota_per_24h: int
    timeout_s: int
    sources: dict[str, LimitSource]  # keyed by the KEYS names


def from_config(cfg: Config) -> Limits:
    """The `.env` view: every value from `cfg`, every source `env`. The adapter's default when
    nothing is wired (the eval harness, which has no `settings` table to read) and the base
    `effective_limits` lays the table's rows over."""
    return Limits(
        cap_usd=cfg.LLM_MONTHLY_USD_CAP,
        quota_per_24h=cfg.ANALYZE_QUOTA_PER_USER_DAY,
        timeout_s=cfg.LLM_TIMEOUT_S,
        sources={key: LimitSource("env", None, None) for key in KEYS},
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
        values[FIELD_OF_KEY[key]] = int(value)
        sources[key] = LimitSource(
            "web", updated_at, None if updated_by is None else str(updated_by)
        )
    return Limits(sources=sources, **values)
