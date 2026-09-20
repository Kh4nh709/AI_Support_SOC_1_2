"""`audit.llm_runs` — `write_run`'s explicit column set and `month_spend_usd` (P3-T10).

`write_run` is exercised end to end here on a real database; `tier1/triage.py`'s own
tests (`test_triage_job.py`) exercise it again through the full job, but this file is
what proves the writer itself: every column round-trips, `role` is validated before
the connection is touched, and the spend query sums only the current calendar month.
"""

from __future__ import annotations

import uuid

import pytest
from app.audit import llm_runs
from app.infra.errors import PermanentError
from psycopg.types.json import Jsonb

pytestmark = pytest.mark.db

_PROMPT_VERSION = "abc1234+" + "0" * 64


def _write(conn, **overrides) -> uuid.UUID:
    kwargs = {
        "run_id": uuid.uuid4(),
        "role": "proposer",
        "subject_id": "write-run-1",
        "system_prompt": "System prompt names JSON.",
        "user_message": "User message.",
        "result": {"suggested_action": "escalate", "confidence": "high"},
        "gate_result": {"version": 1, "final_verdict": "escalate"},
        "verifier_result": {"agree": True},
        "injection_findings": [{"category": "instruction_override"}],
        "citation_warnings": ["no_playbook"],
        "input_tokens": 123,
        "output_tokens": 45,
        "latency_ms": 678,
        "model_id": "fake-model",
        "prompt_version": _PROMPT_VERSION,
        "cost_usd": 0.00012,
        "stopped_by": None,
    }
    kwargs.update(overrides)
    return llm_runs.write_run(conn, **kwargs)


def _read(conn, run_id: uuid.UUID) -> dict:
    cur = conn.execute(
        "SELECT run_id, pipeline, subject_type, subject_id, role, system_prompt, "
        "user_message, agent_trace, result, gate_result, verifier_result, "
        "evidence_check, injection_findings, citation_warnings, input_tokens, "
        "output_tokens, latency_ms, model_id, prompt_version, cost_usd, stopped_by "
        "FROM llm_runs WHERE run_id = %s",
        (run_id,),
    )
    columns = [c.name for c in cur.description]
    return dict(zip(columns, cur.fetchone(), strict=True))


@pytest.mark.db
def test_write_run_reads_back_every_column(db):
    run_id = _write(db)
    row = _read(db, run_id)

    assert row["run_id"] == run_id
    assert row["pipeline"] == "triage"
    assert row["subject_type"] == "alert"
    assert row["subject_id"] == "write-run-1"
    assert row["role"] == "proposer"
    assert row["system_prompt"] == "System prompt names JSON."
    assert row["user_message"] == "User message."
    assert row["agent_trace"] is None
    assert row["result"] == {"suggested_action": "escalate", "confidence": "high"}
    assert row["gate_result"] == {"version": 1, "final_verdict": "escalate"}
    assert row["verifier_result"] == {"agree": True}
    assert row["evidence_check"] is None
    assert row["injection_findings"] == [{"category": "instruction_override"}]
    assert row["citation_warnings"] == ["no_playbook"]
    assert row["input_tokens"] == 123
    assert row["output_tokens"] == 45
    assert row["latency_ms"] == 678
    assert row["model_id"] == "fake-model"
    assert row["prompt_version"] == _PROMPT_VERSION
    assert float(row["cost_usd"]) == pytest.approx(0.00012)
    assert row["stopped_by"] is None


@pytest.mark.db
def test_write_run_result_and_stopped_by_may_be_null(db):
    """The `unavailable` shape: no model result, a `stopped_by` reason, `verifier_result`
    absent — `ck_llm_runs_suggested_action` admits a NULL `result` (G11 holds on a row
    that never produced a verdict at all)."""
    run_id = _write(
        db,
        result=None,
        verifier_result=None,
        input_tokens=None,
        output_tokens=None,
        latency_ms=None,
        model_id=None,
        cost_usd=None,
        stopped_by="cap",
    )
    row = _read(db, run_id)
    assert row["result"] is None
    assert row["stopped_by"] == "cap"


def test_write_run_rejects_unknown_role_before_touching_the_connection():
    """`role` is validated in Python first (design note 2) — passing `conn=None`
    would blow up immediately if validation happened after trying to use it."""
    with pytest.raises(PermanentError, match="bogus"):
        llm_runs.write_run(
            None,  # type: ignore[arg-type]
            run_id=uuid.uuid4(),
            role="bogus",
            subject_id="x",
            system_prompt="s",
            user_message="u",
            result=None,
            gate_result={},
            verifier_result=None,
            injection_findings=None,
            citation_warnings=None,
            input_tokens=None,
            output_tokens=None,
            latency_ms=None,
            model_id=None,
            prompt_version=_PROMPT_VERSION,
            cost_usd=None,
            stopped_by=None,
        )


@pytest.mark.db
def test_month_spend_sums_current_month_only(db):
    _write(db, subject_id="spend-this-month-1", cost_usd=0.5)
    _write(db, subject_id="spend-this-month-2", cost_usd=0.25)

    db.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, role, "
        "system_prompt, user_message, result, gate_result, cost_usd, prompt_version, "
        "created_at) VALUES (%s, 'triage', 'alert', 'spend-last-month', 'proposer', "
        "'sys', 'u', NULL, %s, 100.0, %s, date_trunc('month', now()) - interval '1 day')",
        (uuid.uuid4(), Jsonb({"v": 1}), _PROMPT_VERSION),
    )

    assert llm_runs.month_spend_usd(db) == pytest.approx(0.75)


@pytest.mark.db
def test_month_spend_is_zero_with_no_rows(db):
    assert llm_runs.month_spend_usd(db) == pytest.approx(0.0)
