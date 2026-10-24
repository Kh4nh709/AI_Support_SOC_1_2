"""The `llm_runs` row of a RAG call (P13-T03, spec §7.1).

`audit.llm_runs.write_run` is ①'s: it fixes the pipeline at `triage`, the subject at an alert and the
role at proposer or verifier. A RAG call is a `rag_lookup` run by a `retriever` or a `knowledge_draft`
run by a `drafter`, for an alert or for a case (migration 020 pairs them so), and has no verifier
result, no evidence check and no citation warnings. This is its own INSERT, as `tier2/investigate.py`
has its own for ②. The table is append-only (017): a row is written, never changed.

`rag_lookup_id` is the lookup a run belongs to: the lookup's own run carries the id of the
`rag_results` row it produced, which carries this run's id in `llm_run_id` (the two point at each other,
migration 020). It is None for a run with no result row of its own — an attempt that will be retried,
or a draft.

Everything stored as JSON passes `_clean` first: PostgreSQL's jsonb refuses a NUL character and a lone
surrogate, a model can write both inside a valid string, and a row that cannot be written would cost
the job its record and its retry.
"""

from __future__ import annotations

import uuid
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from app.infra.errors import PermanentError
from app.rag.subject import Subject

#: pipeline -> the role that runs it (`ck_llm_runs_role`, migration 020).
ROLE_OF_PIPELINE = {"rag_lookup": "retriever", "knowledge_draft": "drafter"}

_COLUMNS = (
    "run_id",
    "pipeline",
    "subject_type",
    "subject_id",
    "role",
    "system_prompt",
    "user_message",
    "result",
    "gate_result",
    "injection_findings",
    "input_tokens",
    "output_tokens",
    "latency_ms",
    "model_id",
    "prompt_version",
    "cost_usd",
    "stopped_by",
    "rag_lookup_id",
)
_INSERT = (
    f"INSERT INTO llm_runs ({', '.join(_COLUMNS)}) "
    f"VALUES ({', '.join(['%s'] * len(_COLUMNS))}) RETURNING run_id"
)


def _clean(value: Any) -> Any:
    """`value` with every string free of NUL and of lone surrogates (replaced by U+FFFD)."""
    if isinstance(value, str):
        return "".join("�" if ch == "\x00" or "\ud800" <= ch <= "\udfff" else ch for ch in value)
    if isinstance(value, dict):
        return {_clean(key): _clean(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clean(item) for item in value]
    return value


def _jsonb(value: Any) -> Jsonb | None:
    return None if value is None else Jsonb(_clean(value))


def write_rag_run(
    conn: psycopg.Connection,
    *,
    run_id: uuid.UUID,
    pipeline: str,
    role: str,
    subject: Subject,
    system_prompt: str,
    user_message: str,
    result: dict | None,
    gate_result: dict | None,
    injection_findings: list | None,
    input_tokens: int | None,
    output_tokens: int | None,
    latency_ms: int | None,
    model_id: str | None,
    prompt_version: str,
    cost_usd: float | None,
    stopped_by: str | None,
    rag_lookup_id: uuid.UUID | None = None,
) -> uuid.UUID:
    """Insert one `llm_runs` row for a RAG call and return its `run_id`. `pipeline` and `role` are
    checked together before any SQL runs (the CHECKs are the backstop). `result` is the schema-valid
    answer, or None when the model failed; `stopped_by` is None for a call that completed."""
    if ROLE_OF_PIPELINE.get(pipeline) != role:
        raise PermanentError(
            f"write_rag_run: pipeline {pipeline!r} is run by {ROLE_OF_PIPELINE.get(pipeline)!r}, "
            f"not {role!r}"
        )
    row = conn.execute(
        _INSERT,
        (
            run_id,
            pipeline,
            subject.kind,
            subject.id,
            role,
            _clean(system_prompt),
            _clean(user_message),
            _jsonb(result),
            _jsonb(gate_result),
            _jsonb(injection_findings),
            input_tokens,
            output_tokens,
            latency_ms,
            model_id,
            prompt_version,
            cost_usd,
            stopped_by,
            rag_lookup_id,
        ),
    ).fetchone()
    return row[0]
