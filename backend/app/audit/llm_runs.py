"""Append an llm_runs row for every model call: prompt, gate result, verifier result, cost.

Append-only (§6.1 layer 1/2, migration 017): this module holds no update, delete or
truncate statement — a fresh row per call, never a rewrite. `gate_result` is required
on every row (G11); `agent_trace` and `evidence_check` are always NULL here —
pipeline ② (P5) is the only writer of those two.
"""

from __future__ import annotations

import uuid

import psycopg
from psycopg.types.json import Jsonb

from app.infra.errors import PermanentError

_ROLES = frozenset({"proposer", "verifier"})

# Explicit column list (never `INSERT INTO llm_runs VALUES (...)`), in the order the
# VALUES tuple below fills them. `pipeline`/`subject_type` are hard-coded to ①'s
# values (`ck_llm_runs_pipeline_khop_subject`); `agent_trace`/`evidence_check` are
# always NULL here — ②'s columns (planning decision 1).
_COLUMNS = (
    "run_id",
    "pipeline",
    "subject_type",
    "subject_id",
    "role",
    "system_prompt",
    "user_message",
    "agent_trace",
    "result",
    "gate_result",
    "verifier_result",
    "evidence_check",
    "injection_findings",
    "citation_warnings",
    "input_tokens",
    "output_tokens",
    "latency_ms",
    "model_id",
    "prompt_version",
    "cost_usd",
    "stopped_by",
)

_INSERT_SQL = (
    f"INSERT INTO llm_runs ({', '.join(_COLUMNS)}) "
    f"VALUES ({', '.join(['%s'] * len(_COLUMNS))}) RETURNING run_id"
)


def write_run(
    conn: psycopg.Connection,
    *,
    run_id: uuid.UUID,
    role: str,
    subject_id: str,
    system_prompt: str,
    user_message: str,
    result: dict | None,
    gate_result: dict,
    verifier_result: dict | None,
    injection_findings: list | None,
    citation_warnings: list | None,
    input_tokens: int | None,
    output_tokens: int | None,
    latency_ms: int | None,
    model_id: str | None,
    prompt_version: str,
    cost_usd: float | None,
    stopped_by: str | None,
) -> uuid.UUID:
    """Insert one `llm_runs` row for pipeline ①'s proposer or verifier call and return
    its `run_id`. `role` is checked in Python (the DB CHECK is the backstop, planning
    decision 2) before any SQL runs; `gate_result` is required, not optional — every
    row carries one (G11).
    """
    if role not in _ROLES:
        raise PermanentError(f"write_run: role must be one of {sorted(_ROLES)}, got {role!r}")
    row = conn.execute(
        _INSERT_SQL,
        (
            run_id,
            "triage",
            "alert",
            subject_id,
            role,
            system_prompt,
            user_message,
            None,  # agent_trace — ②'s
            Jsonb(result) if result is not None else None,
            Jsonb(gate_result),
            Jsonb(verifier_result) if verifier_result is not None else None,
            None,  # evidence_check — ②'s
            Jsonb(injection_findings) if injection_findings is not None else None,
            Jsonb(citation_warnings) if citation_warnings is not None else None,
            input_tokens,
            output_tokens,
            latency_ms,
            model_id,
            prompt_version,
            cost_usd,
            stopped_by,
        ),
    ).fetchone()
    return row[0]


def month_spend_usd(conn: psycopg.Connection) -> float:
    """`sum(cost_usd)` over the calendar month containing `now()`, `0.0` when nothing
    has been spent yet — the adapter's monthly-cap check (planning decision 10)."""
    row = conn.execute(
        "SELECT coalesce(sum(cost_usd), 0) FROM llm_runs "
        "WHERE created_at >= date_trunc('month', now())"
    ).fetchone()
    return float(row[0])
