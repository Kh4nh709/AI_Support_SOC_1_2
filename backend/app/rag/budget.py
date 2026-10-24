"""What the RAG may spend (P13-T03, spec §7.1 "Spend").

The lookup and the draft are model calls the analysts did not ask for, so they have a sub-cap of their
own, `RAG_MONTHLY_USD_CAP`, which is spent inside the global one: a call stops when the RAG's month
reaches its cap, or when the month's whole spend reaches the global cap (the effective one, which the
admin may have changed on the web, read through `infra.settings` and failing closed).

* `rag_spent_usd`: this calendar month's `cost_usd` of the pipelines `rag_lookup` and `knowledge_draft`;
* `global_exhausted`: the whole month's spend (every pipeline) has reached the effective global cap, or
  that cap cannot be read;
* `rag_limits`: the limits the RAG's `DeepSeekAdapter` reads before each attempt, with the RAG cap as
  `cap_usd`. The adapter compares `rag_spent_usd` to it, so it stops a call at the sub-cap and, when
  `settings.effective_limits` raises `SettingsUnavailable`, stops it as `LLMBudgetExceeded`.

The global cap is checked by the job before it starts (`global_exhausted`); the adapter's per-attempt
check is the RAG's own. One lookup costs a fraction of a cent, so the two never differ by more than that.
"""

from __future__ import annotations

import dataclasses

import psycopg

from app.audit.llm_runs import month_spend_usd
from app.infra import settings
from app.infra.config import Config

#: The pipelines the sub-cap counts (`llm_runs.pipeline`).
RAG_PIPELINES = ("rag_lookup", "knowledge_draft")


def rag_spent_usd(conn: psycopg.Connection) -> float:
    """The cost of this month's RAG calls, `0.0` when there were none. The month is the one that
    `audit.llm_runs.month_spend_usd` sums, so the two are on one clock."""
    row = conn.execute(
        "SELECT coalesce(sum(cost_usd), 0) FROM llm_runs"
        " WHERE pipeline = ANY(%s) AND created_at >= date_trunc('month', now())",
        (list(RAG_PIPELINES),),
    ).fetchone()
    return float(row[0])


def global_exhausted(conn: psycopg.Connection, cfg: Config) -> bool:
    """True when the month's spend, every pipeline together, is at or over the effective global cap.
    Limits that cannot be read count as exhausted: nothing is known, so nothing is spent."""
    try:
        limits = settings.effective_limits(conn, cfg)
    except settings.SettingsUnavailable:
        return True
    return month_spend_usd(conn) >= limits.cap_usd


def rag_limits(conn: psycopg.Connection, cfg: Config) -> settings.Limits:
    """The effective limits with the RAG's cap in place of the global one. The timeout and the rest
    are the effective ones. Raises `SettingsUnavailable` like `effective_limits`: the adapter
    turns that into a stopped call."""
    limits = settings.effective_limits(conn, cfg)
    return dataclasses.replace(limits, cap_usd=cfg.RAG_MONTHLY_USD_CAP)
