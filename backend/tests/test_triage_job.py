"""`tier1.triage.run_triage_job` end to end on a database, with the fake adapter (P3-T10).

Written against `docs/plan/tasks/P3/P3-T10.prompt.md`'s design notes and acceptance
list. Every model call goes through `backend/tests/fakes/llm.py`'s `FakeLLM` (or a
tiny local double for the one branch `FakeLLM` cannot express — a budget check that
must fire before any call is recorded); nothing here opens a socket. The seeded
alert reuses the canonical fixture's values (context pack §8) so `TRIAGE_V3_TRUE_POSITIVE`'s
quote is a real substring of the seeded `raw_log` and its `structured_basis` matches
the facts `build_facts` derives from the seed — see `_seed_alert`.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import itertools
import json
import re
import time
import uuid
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path
from types import SimpleNamespace

import pytest
from app.infra import config, worker
from app.infra.errors import TransientError
from app.infra.jobs import Job
from app.kb.lookup import DecisionTable, Rule
from app.llm.adapter import LLMBudgetExceeded, LLMUnavailable
from app.security.linter import Violation
from app.tier1 import triage as triage_module
from app.tier1.triage import _make_rule_check, run_triage_job
from app.web.worker import HANDLERS
from psycopg.types.json import Jsonb

from tests.fakes.llm import (
    TRIAGE_V2_FALSE_POSITIVE,
    TRIAGE_V3_TRUE_POSITIVE,
    VERIFIER_V2_AGREE,
    VERIFIER_V2_DISAGREE,
    FakeLLM,
)

pytestmark = pytest.mark.db

_FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "alert_40112.json").read_text("utf-8"))[
    "_source"
]
_FULL_LOG = _FIXTURE["full_log"]
_ALERT_TIME = datetime(2026, 8, 16, 17, 56, 56, tzinfo=UTC)

_counter = itertools.count()

_TERMINAL_STATUSES = frozenset(
    {"duplicate", "auto_closed", "closed_fp", "closed_benign", "closed_confirmed", "archived"}
)
# `archived` (021, DEC-212) is sealed like a person's close, though no person closed it.
_HUMAN_CLOSED_STATUSES = frozenset({"closed_fp", "closed_benign", "closed_confirmed", "archived"})


def _hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _seed_alert(conn, **overrides) -> str:
    """Insert one `alerts` row plus its pending `triage` job (design note 8): the
    twelve NOT NULL-without-default columns, `status`, the four `*_context`/
    `lookup_status` columns in `finish_enrichment`'s shape, `occurrence_count`. The
    defaults reuse the canonical alert (context pack §8) exactly — same `rule_level`
    (12, critical), same `raw_log` (so `TRIAGE_V3_TRUE_POSITIVE`'s quote is a real
    substring), same lookups (asset unknown, ioc skipped, identity unknown) — so a
    test that does not override anything reproduces the canonical facts.
    """
    n = next(_counter)
    alert_id = overrides.pop("alert_id", None) or f"1786903016.{300_000 + n}"
    fields = {
        "alert_id": alert_id,
        "rule_id": _FIXTURE["rule"]["id"],
        "rule_level": _FIXTURE["rule"]["level"],
        "severity": "critical",
        "description": _FIXTURE["rule"]["description"],
        "agent_name": _FIXTURE["agent"]["name"],
        "alert_time": _ALERT_TIME,
        "category": "ssh_brute_force",
        "categories": ["ssh_brute_force", "suspicious_login"],
        "resolved_by": "rule_groups",
        "mapping_version": "v1",
        "event_bucket_hash": _hash(alert_id),
        "raw_payload": {"rule": {"id": _FIXTURE["rule"]["id"]}},
        "raw_log": _FULL_LOG,
        "raw_log_truncated": False,
        "origin_host": _FIXTURE["predecoder"]["hostname"],
        "agent_id": _FIXTURE["agent"]["id"],
        "alert_user": _FIXTURE["data"]["dstuser"],
        "srcip": _FIXTURE["data"]["srcip"],
        "mitre_ids": list(_FIXTURE["rule"]["mitre"]["id"]),
        "status": "queued_tier1",
        "triage_status": "pending",
        "occurrence_count": 1,
        "risk_score": 61,
        "asset_context": {"present": False, "criticality": "unknown", "owner": None, "role": None},
        "identity_context": {"privileged": None},
        "ioc_context": {"reputation": None},
        "lookup_status": {"asset": "not_found", "identity": "not_found", "ioc": "skipped"},
        "first_seen_at": _ALERT_TIME,
        "last_seen_at": _ALERT_TIME,
        "closed_at": None,
        "sealed_at": None,
    }
    fields.update(overrides)
    fields["alert_id"] = alert_id
    # G3/H2 — every terminal status must carry closed_at, and a human-decided one
    # (never auto_closed, M4) must also carry sealed_at.
    if fields["status"] in _TERMINAL_STATUSES and fields["closed_at"] is None:
        fields["closed_at"] = _ALERT_TIME
    if fields["status"] in _HUMAN_CLOSED_STATUSES and fields["sealed_at"] is None:
        fields["sealed_at"] = _ALERT_TIME

    json_columns = {
        "raw_payload",
        "asset_context",
        "identity_context",
        "ioc_context",
        "lookup_status",
    }
    columns = list(fields.keys())
    values = [
        Jsonb(fields[c]) if c in json_columns and fields[c] is not None else fields[c]
        for c in columns
    ]
    conn.execute(
        f"INSERT INTO alerts ({', '.join(columns)}) VALUES ({', '.join(['%s'] * len(columns))})",
        values,
    )
    conn.execute(
        "INSERT INTO jobs (job_type, subject_id) VALUES ('triage', %s) "
        "ON CONFLICT (job_type, subject_id) WHERE status IN ('pending', 'running') DO NOTHING",
        (alert_id,),
    )
    return alert_id


def _job(alert_id: str, *, attempts: int = 1) -> Job:
    return Job(job_id=1, job_type="triage", subject_id=alert_id, attempts=attempts)


def _rows(db, alert_id: str, *columns: str) -> list[tuple]:
    return db.execute(
        f"SELECT {', '.join(columns)} FROM llm_runs WHERE subject_id = %s ORDER BY role",
        (alert_id,),
    ).fetchall()


def _event_types(db, alert_id: str) -> set[str]:
    return {
        r[0]
        for r in db.execute(
            "SELECT event_type FROM audit_events WHERE subject_id = %s", (alert_id,)
        ).fetchall()
    }


def _enable_llm(monkeypatch) -> None:
    monkeypatch.setenv("LLM_MODEL_PROPOSER", "fake-deepseek")


class _RecordingLLM(FakeLLM):
    """`FakeLLM` plus the `model` keyword the real adapter's `complete()` takes
    (P3-T04) and `llm.triage.propose`/`verify` always pass — mirrors
    `test_llm_triage.py`'s `RecordingLLM`."""

    def complete(self, *, system, user, response_format=None, timeout_s=None, model=None):
        return super().complete(
            system=system, user=user, response_format=response_format, timeout_s=timeout_s
        )


class _AlwaysOverBudget:
    """A double for the one branch `FakeLLM` cannot express: the real adapter's
    monthly-cap check fires before it ever opens a socket, so `.calls` must stay
    empty (acceptance: `test_cap_is_unavailable_before_any_call`)."""

    def __init__(self) -> None:
        self.calls: list = []

    def complete(self, **kwargs):
        raise LLMBudgetExceeded("over the monthly cap")


class _AlwaysUnavailable:
    """The provider answers 402 (no balance / exhausted quota): the adapter raises LLMUnavailable
    on the first call. Like `_AlwaysOverBudget`, but a distinct provider-side cause (S8)."""

    def __init__(self) -> None:
        self.calls: list = []

    def complete(self, **kwargs):
        raise LLMUnavailable(
            "LLM provider unavailable (402): Error code: 402 - {'message': 'Insufficient Balance'}"
        )


class _FailVerifyCall(_RecordingLLM):
    """Succeeds on the first call (the proposer) exactly like `FakeLLM`, then
    raises on every call after that (the verifier) — the one shape `FakeLLM`'s
    own `raises` cannot express (it only fires on call index 0). Exercises
    design note 2's "same two branches as above" for the verify() call."""

    def __init__(self, *args, raises: Exception, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._verify_exc = raises

    def complete(self, **kwargs):
        if len(self.calls) >= 1:
            raise self._verify_exc
        return super().complete(**kwargs)


class _SlowFirstCallLLM(_RecordingLLM):
    """The first `complete()` sleeps `sleep_s` — long enough to trip `infra/db.py`'s
    10s default idle-in-transaction timeout if the handler's own `SET LOCAL`
    (design note 3) did not override it first."""

    def __init__(self, *args, sleep_s: float = 11.0, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._sleep_s = sleep_s
        self._slept = False

    def complete(self, **kwargs):
        if not self._slept:
            self._slept = True
            time.sleep(self._sleep_s)
        return super().complete(**kwargs)


# ---------------------------------------------------------------------------
# Happy path / forcing
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_happy_path_writes_two_rows_ready_and_audit(db, monkeypatch):
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(db)
    fake = _RecordingLLM(responses=[TRIAGE_V3_TRUE_POSITIVE, VERIFIER_V2_AGREE])

    run_triage_job(db, _job(alert_id), adapter=fake)

    rows = _rows(db, alert_id, "role", "gate_result", "cost_usd", "prompt_version")
    assert {r[0] for r in rows} == {"proposer", "verifier"}
    for _role, gate_result, cost_usd, prompt_version in rows:
        assert gate_result is not None
        assert cost_usd is not None
        assert re.match(r"^[0-9a-f]{7,}\+[0-9a-f]{64}$|^nogit\+", prompt_version)

    status, triage_status, triaged_count = db.execute(
        "SELECT status, triage_status, triaged_count FROM alerts WHERE alert_id = %s", (alert_id,)
    ).fetchone()
    assert status == "queued_tier1"  # G2 — never touched
    assert triage_status == "ready"
    assert triaged_count == 1

    events = _event_types(db, alert_id)
    assert "triage.suggested" in events
    assert "llm.gate_forced" not in events

    payload = db.execute(
        "SELECT actor_role FROM audit_events WHERE subject_id = %s AND event_type = 'triage.suggested'",
        (alert_id,),
    ).fetchone()
    assert payload == ("llm",)


@pytest.mark.db
def test_forced_path_writes_gate_forced(db, monkeypatch):
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(
        db,
        severity="low",
        rule_level=3,
        occurrence_count=3,
        asset_context={"present": True, "criticality": "low", "owner": "a", "role": "b"},
        identity_context={"privileged": False},
        ioc_context={"reputation": "clean"},
        lookup_status={"asset": "found", "identity": "found", "ioc": "found"},
    )
    fake = _RecordingLLM(responses=[TRIAGE_V2_FALSE_POSITIVE, VERIFIER_V2_DISAGREE])

    run_triage_job(db, _job(alert_id), adapter=fake)

    result, gate_result = db.execute(
        "SELECT result, gate_result FROM llm_runs WHERE subject_id = %s AND role = 'proposer'",
        (alert_id,),
    ).fetchone()
    assert result["suggested_action"] == "needs_review"
    assert gate_result["forced"] is True
    assert gate_result["proposer_raw"]["suggested_action"] == "false_positive"

    assert "llm.gate_forced" in _event_types(db, alert_id)


@pytest.mark.db
def test_result_column_never_carries_ungated_fp(db, monkeypatch):
    """G11, on the column (acceptance 3): `result` never carries an ungated
    `false_positive`, even though the model's own answer did."""
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(
        db,
        severity="low",
        rule_level=3,
        occurrence_count=3,
        asset_context={"present": True, "criticality": "low", "owner": "a", "role": "b"},
        identity_context={"privileged": False},
        ioc_context={"reputation": "clean"},
        lookup_status={"asset": "found", "identity": "found", "ioc": "found"},
    )
    fake = _RecordingLLM(responses=[TRIAGE_V2_FALSE_POSITIVE, VERIFIER_V2_DISAGREE])

    run_triage_job(db, _job(alert_id), adapter=fake)

    survivors = db.execute(
        "SELECT count(*) FROM llm_runs WHERE result->>'suggested_action' = 'false_positive'"
    ).fetchone()[0]
    assert survivors == 0

    proposer_raw_action = db.execute(
        "SELECT gate_result->'proposer_raw'->>'suggested_action' FROM llm_runs "
        "WHERE subject_id = %s AND role = 'proposer'",
        (alert_id,),
    ).fetchone()[0]
    assert proposer_raw_action == "false_positive"


# ---------------------------------------------------------------------------
# Failure branches — each ends `unavailable` with exactly one row (or none)
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_schema_failure_after_repair_is_unavailable(db, monkeypatch):
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(db)
    fake = _RecordingLLM(responses=["not valid json", "still not valid json"])

    run_triage_job(db, _job(alert_id), adapter=fake)

    rows = _rows(db, alert_id, "result", "stopped_by")
    assert len(rows) == 1
    result, stopped_by = rows[0]
    assert result is None
    assert stopped_by == "schema"
    assert len(fake.calls) == 2  # the one repair round, never a third call

    triage_status = db.execute(
        "SELECT triage_status FROM alerts WHERE alert_id = %s", (alert_id,)
    ).fetchone()[0]
    assert triage_status == "unavailable"


@pytest.mark.db
@pytest.mark.parametrize("refused", ["needs_review", "escalate"])
def test_a_model_answer_outside_the_definite_pair_twice_is_stopped_by_schema(
    db, monkeypatch, refused
):
    """P14-T01 (DEC-213): ①'s model answer is `false_positive | true_positive`. `needs_review` is
    the system's alone, and the old `escalate` is gone: either, twice, ends exactly as invalid JSON
    does today (the one repair round, then `stopped_by='schema'`, no result, `unavailable`)."""
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(db)
    bad = {**TRIAGE_V3_TRUE_POSITIVE, "suggested_action": refused}
    fake = _RecordingLLM(responses=[bad, bad, VERIFIER_V2_AGREE])

    run_triage_job(db, _job(alert_id), adapter=fake)

    rows = _rows(db, alert_id, "result", "stopped_by", "role")
    assert len(rows) == 1
    result, stopped_by, role = rows[0]
    assert (result, stopped_by, role) == (None, "schema", "proposer")
    assert len(fake.calls) == 2  # the one repair round, never a third call, never the verifier
    triage_status = db.execute(
        "SELECT triage_status FROM alerts WHERE alert_id = %s", (alert_id,)
    ).fetchone()[0]
    assert triage_status == "unavailable"


@pytest.mark.db
def test_a_true_positive_answer_is_stored_as_the_suggested_action(db, monkeypatch):
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(db)
    fake = _RecordingLLM(responses=[TRIAGE_V3_TRUE_POSITIVE, VERIFIER_V2_AGREE])

    run_triage_job(db, _job(alert_id), adapter=fake)

    result, gate_result = db.execute(
        "SELECT result, gate_result FROM llm_runs WHERE subject_id = %s AND role = 'proposer'",
        (alert_id,),
    ).fetchone()
    assert result["suggested_action"] == "true_positive"
    assert gate_result["proposed_verdict"] == gate_result["final_verdict"] == "true_positive"
    assert gate_result["forced"] is False and gate_result["forced_by"] == []
    assert gate_result["proposer_raw"]["suggested_action"] == "true_positive"
    assert gate_result["verifier_verdict"] == "true_positive"
    assert db.execute(
        "SELECT triage_status FROM alerts WHERE alert_id = %s", (alert_id,)
    ).fetchone() == ("ready",)
    assert "escalate" not in json.dumps(result)


@pytest.mark.db
def test_a_true_positive_the_gate_holds_keeps_the_models_answer_beside_the_held_one(
    db, monkeypatch
):
    """The model concluded; the system held it (here, the verifier disagrees): `result` says
    `needs_review`, `gate_result.proposed_verdict` still says what the model concluded."""
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(db)
    fake = _RecordingLLM(responses=[TRIAGE_V3_TRUE_POSITIVE, VERIFIER_V2_DISAGREE])

    run_triage_job(db, _job(alert_id), adapter=fake)

    result, gate_result = db.execute(
        "SELECT result, gate_result FROM llm_runs WHERE subject_id = %s AND role = 'proposer'",
        (alert_id,),
    ).fetchone()
    assert result["suggested_action"] == "needs_review"
    assert gate_result["proposed_verdict"] == "true_positive"
    assert gate_result["final_verdict"] == "needs_review"
    assert gate_result["forced_by"] == ["step6"]


@pytest.mark.db
def test_the_prompts_of_the_job_carry_the_v3_and_v2_schemas(db, monkeypatch):
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(db)
    fake = _RecordingLLM(responses=[TRIAGE_V3_TRUE_POSITIVE, VERIFIER_V2_AGREE])

    run_triage_job(db, _job(alert_id), adapter=fake)

    proposer_system, verifier_system = fake.calls[0]["system"], fake.calls[1]["system"]
    assert "## Schema triage_v3\n" in proposer_system
    assert "suggested_action: false_positive|true_positive" in proposer_system
    assert "needs_review" not in proposer_system
    assert "## Schema verifier_v2\n" in verifier_system
    assert "structured_only_verdict: false_positive|needs_review|true_positive" in verifier_system


@pytest.mark.db
def test_builder_violation_is_unavailable_with_event(db, monkeypatch):
    _enable_llm(monkeypatch)
    from app.security import linter as linter_module

    monkeypatch.setattr(
        linter_module, "lint", lambda *a, **kw: [Violation(kind="free_text", token="x", line=1)]
    )
    alert_id = _seed_alert(db)
    fake = _RecordingLLM(responses=[TRIAGE_V3_TRUE_POSITIVE, VERIFIER_V2_AGREE])

    run_triage_job(db, _job(alert_id), adapter=fake)

    assert fake.calls == []
    rows = _rows(db, alert_id, "stopped_by")
    assert [r[0] for r in rows] == ["linter"]
    assert "llm.builder_violation" in _event_types(db, alert_id)

    triage_status = db.execute(
        "SELECT triage_status FROM alerts WHERE alert_id = %s", (alert_id,)
    ).fetchone()[0]
    assert triage_status == "unavailable"


@pytest.mark.db
def test_cap_is_unavailable_before_any_call(db, monkeypatch):
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(db)
    fake = _AlwaysOverBudget()

    run_triage_job(db, _job(alert_id), adapter=fake)

    assert fake.calls == []
    rows = _rows(db, alert_id, "stopped_by")
    assert [r[0] for r in rows] == ["cap"]

    triage_status = db.execute(
        "SELECT triage_status FROM alerts WHERE alert_id = %s", (alert_id,)
    ).fetchone()[0]
    assert triage_status == "unavailable"


@pytest.mark.db
def test_provider_402_is_unavailable_with_the_error_recorded(db, monkeypatch):
    """A provider 402 (no balance / quota) ends the alert `unavailable` with ONE proposer row whose
    stopped_by is 'unavailable' and whose gate_result records the provider's message — not a hard
    job failure that leaves triage_status dangling with no row (S8, DEC-211). The job itself
    succeeds (it recorded an outcome), so the webhook/pipeline does not retry it forever."""
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(db)
    fake = _AlwaysUnavailable()

    run_triage_job(db, _job(alert_id), adapter=fake)

    rows = _rows(db, alert_id, "result", "stopped_by", "gate_result")
    assert len(rows) == 1
    result, stopped_by, gate_result = rows[0]
    assert result is None
    assert stopped_by == "unavailable"
    assert gate_result["error"] == "unavailable"
    assert "402" in gate_result["message"]  # the provider's own reason is kept

    triage_status = db.execute(
        "SELECT triage_status FROM alerts WHERE alert_id = %s", (alert_id,)
    ).fetchone()[0]
    assert triage_status == "unavailable"


@pytest.mark.db
def test_verifier_402_writes_both_rows_unavailable(db, monkeypatch):
    """A 402 on the verifier call, after a schema-valid proposal, writes both rows stopped_by
    'unavailable' and ends the alert 'unavailable' — mirroring the verifier-cap branch (S8)."""
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(db)
    fake = _FailVerifyCall(
        responses=[TRIAGE_V3_TRUE_POSITIVE],
        raises=LLMUnavailable("LLM provider unavailable (402): Insufficient Balance"),
    )

    run_triage_job(db, _job(alert_id), adapter=fake)

    rows = _rows(db, alert_id, "role", "stopped_by")
    assert {r[0] for r in rows} == {"proposer", "verifier"}
    assert all(stopped_by == "unavailable" for _role, stopped_by in rows)

    triage_status = db.execute(
        "SELECT triage_status FROM alerts WHERE alert_id = %s", (alert_id,)
    ).fetchone()[0]
    assert triage_status == "unavailable"


class _NoSocketClient:
    """An OpenAI-SDK-shaped client for the REAL `DeepSeekAdapter` that must never be called:
    every `create` is recorded in `calls` and fails, so a model call that should have been
    refused shows up as a non-empty `calls` (and, failing, as a `permanent` row)."""

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        raise AssertionError("a model call was made")


def _real_adapter_over(monkeypatch, client) -> None:
    """`run_triage_job(adapter=None)` builds a `DeepSeekAdapter` itself — this keeps that
    construction (its `spent_usd=` and `limits=` wiring) and only swaps the SDK client."""
    real = triage_module.DeepSeekAdapter
    monkeypatch.setattr(
        triage_module, "DeepSeekAdapter", lambda cfg, **kw: real(cfg, client=client, **kw)
    )


@pytest.mark.db
def test_unreadable_limits_stop_the_run_as_cap_with_no_model_call(db, monkeypatch):
    """P11-T03 / DEC-200 item 3: the `settings` table is missing (code deployed before
    `make migrate`). Nothing falls back to `.env`: ① is `stopped_by='cap'`, the real adapter
    opened no socket, and the job's own transaction is still usable afterwards — it wrote its
    `llm_runs` row and the alert's `triage_status` after the failed read (the savepoint)."""
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(db)
    client = _NoSocketClient()
    _real_adapter_over(monkeypatch, client)
    db.execute("DROP TABLE settings")  # rolled back with the test's transaction

    run_triage_job(db, _job(alert_id))  # adapter=None: the production wiring

    assert client.calls == []
    assert [r[0] for r in _rows(db, alert_id, "stopped_by")] == ["cap"]
    triage_status = db.execute(
        "SELECT triage_status FROM alerts WHERE alert_id = %s", (alert_id,)
    ).fetchone()[0]
    assert triage_status == "unavailable"


@pytest.mark.db
def test_a_web_cap_below_the_spend_stops_the_run_as_cap_with_no_model_call(db, monkeypatch):
    """The cap the admin saved on the web, not the `.env` one, gates ①: 5 USD spent is under
    the `.env` cap (30) and over the saved one (1)."""
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(db)
    client = _NoSocketClient()
    _real_adapter_over(monkeypatch, client)
    monkeypatch.setattr(triage_module.llm_runs, "month_spend_usd", lambda conn: 5.0)
    user_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash) "
        "VALUES (%s, %s, 'Admin', 'admin', 'x')",
        (user_id, f"user-{user_id[:8]}"),
    )
    db.execute(
        "INSERT INTO settings (key, value, updated_by) VALUES ('LLM_MONTHLY_USD_CAP', 1, %s)",
        (user_id,),
    )

    run_triage_job(db, _job(alert_id))

    assert client.calls == []
    assert [r[0] for r in _rows(db, alert_id, "stopped_by")] == ["cap"]


@pytest.mark.db
def test_transient_before_last_attempt_propagates_and_writes_nothing(db, monkeypatch):
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(db)
    fake = _RecordingLLM(raises=TransientError("stalled"))

    with pytest.raises(TransientError):
        run_triage_job(db, _job(alert_id, attempts=1), adapter=fake)  # < JOB_MAX_ATTEMPTS (3)

    count = db.execute(
        "SELECT count(*) FROM llm_runs WHERE subject_id = %s", (alert_id,)
    ).fetchone()[0]
    assert count == 0


@pytest.mark.db
def test_transient_on_last_attempt_is_unavailable_with_job_exhausted(db, monkeypatch):
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(db)
    fake = _RecordingLLM(raises=TransientError("stalled"))

    run_triage_job(db, _job(alert_id, attempts=3), adapter=fake)  # == JOB_MAX_ATTEMPTS

    rows = _rows(db, alert_id, "role", "result", "stopped_by")
    assert len(rows) == 1
    role, result, stopped_by = rows[0]
    assert role == "proposer"
    assert result is None
    assert stopped_by == "transient"

    triage_status = db.execute(
        "SELECT triage_status FROM alerts WHERE alert_id = %s", (alert_id,)
    ).fetchone()[0]
    assert triage_status == "unavailable"
    assert "job.exhausted" in _event_types(db, alert_id)


@pytest.mark.db
def test_verify_transient_before_last_attempt_propagates_and_writes_nothing(db, monkeypatch):
    """Design note 2: a `verify()` failure follows the same two branches as a
    `propose()` failure — below `JOB_MAX_ATTEMPTS` it still just raises, and the
    proposer row is not written on a retry (the whole transaction rolls back)."""
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(db)
    fake = _FailVerifyCall(responses=[TRIAGE_V3_TRUE_POSITIVE], raises=TransientError("stalled"))

    with pytest.raises(TransientError):
        run_triage_job(db, _job(alert_id, attempts=1), adapter=fake)

    count = db.execute(
        "SELECT count(*) FROM llm_runs WHERE subject_id = %s", (alert_id,)
    ).fetchone()[0]
    assert count == 0


@pytest.mark.db
def test_verify_transient_on_last_attempt_writes_both_rows_unavailable(db, monkeypatch):
    """On the last attempt both rows are written "with what exists" (design note
    2): the proposer's real prompt/usage, the verifier's prompt with no result."""
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(db)
    fake = _FailVerifyCall(responses=[TRIAGE_V3_TRUE_POSITIVE], raises=TransientError("stalled"))

    run_triage_job(db, _job(alert_id, attempts=3), adapter=fake)

    rows = _rows(db, alert_id, "role", "result", "stopped_by")
    assert {r[0] for r in rows} == {"proposer", "verifier"}
    for _role, result, stopped_by in rows:
        assert result is None
        assert stopped_by == "transient"

    triage_status = db.execute(
        "SELECT triage_status FROM alerts WHERE alert_id = %s", (alert_id,)
    ).fetchone()[0]
    assert triage_status == "unavailable"
    assert "job.exhausted" in _event_types(db, alert_id)


@pytest.mark.db
def test_verify_cap_writes_both_rows_unavailable(db, monkeypatch):
    """The monthly cap fires while building the verifier call — no retry concept
    applies (cap never retries), so both rows are written immediately."""
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(db)
    fake = _FailVerifyCall(
        responses=[TRIAGE_V3_TRUE_POSITIVE], raises=LLMBudgetExceeded("over cap")
    )

    run_triage_job(db, _job(alert_id), adapter=fake)

    rows = _rows(db, alert_id, "role", "stopped_by")
    assert {r[0] for r in rows} == {"proposer", "verifier"}
    assert all(stopped_by == "cap" for _role, stopped_by in rows)

    triage_status = db.execute(
        "SELECT triage_status FROM alerts WHERE alert_id = %s", (alert_id,)
    ).fetchone()[0]
    assert triage_status == "unavailable"


# ---------------------------------------------------------------------------
# Skip / disabled — no rows at all
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_closed_alert_is_skipped_without_rows(db, monkeypatch):
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(db, status="closed_fp", triage_status="ready")

    run_triage_job(db, _job(alert_id), adapter=_RecordingLLM())

    count = db.execute(
        "SELECT count(*) FROM llm_runs WHERE subject_id = %s", (alert_id,)
    ).fetchone()[0]
    assert count == 0
    row = db.execute(
        "SELECT status, triage_status FROM alerts WHERE alert_id = %s", (alert_id,)
    ).fetchone()
    assert row == ("closed_fp", "ready")  # phase-5: never overwrite a closed alert


@pytest.mark.db
def test_archived_alert_is_skipped_without_rows(db, monkeypatch):
    """INT-T03 / DEC-212: a `triage` job queued before the archive and run after it must not run ①
    on an alert nobody is going to read: no model call, no `llm_runs` row, no event, and
    `triage_status` / `triaged_count` stay as the archive left them."""
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(db, status="archived", triage_status="pending", triaged_count=0)
    fake = _RecordingLLM()  # no responses: a call would fail the test

    run_triage_job(db, _job(alert_id), adapter=fake)

    assert fake.calls == []
    assert db.execute(
        "SELECT count(*) FROM llm_runs WHERE subject_id = %s", (alert_id,)
    ).fetchone() == (0,)
    assert _event_types(db, alert_id) == set()
    row = db.execute(
        "SELECT status, triage_status, triaged_count FROM alerts WHERE alert_id = %s", (alert_id,)
    ).fetchone()
    assert row == ("archived", "pending", 0)


@pytest.mark.db
def test_a_new_alert_beside_an_archived_one_is_triaged_and_does_not_see_it(db, monkeypatch):
    """INT-T03 / DEC-212: ① on a NEW alert (same agent, inside the +-2 h window) of an archived one
    runs, and the correlation section of its prompt does not mention the archived alert: its rule,
    its description, its id. `AlertStatus` has no `archived`, so a row for it would be a crash."""
    _enable_llm(monkeypatch)
    archived = _seed_alert(
        db,
        status="archived",
        rule_id="99999",
        description="ARCHIVED-NEIGHBOUR-MARKER",
        occurrence_count=5000,  # the busiest neighbour: it would head the correlation rows
    )
    alert_id = _seed_alert(db)
    fake = _RecordingLLM(responses=[TRIAGE_V3_TRUE_POSITIVE, VERIFIER_V2_AGREE])

    run_triage_job(db, _job(alert_id), adapter=fake)

    assert {r[0] for r in _rows(db, alert_id, "role")} == {"proposer", "verifier"}
    assert db.execute(
        "SELECT triage_status FROM alerts WHERE alert_id = %s", (alert_id,)
    ).fetchone() == ("ready",)
    for call in fake.calls:
        sent = call["system"] + call["user"]
        assert "99999" not in sent
        assert "ARCHIVED-NEIGHBOUR-MARKER" not in sent
        assert archived not in sent
        assert "archived" not in sent


@pytest.mark.db
def test_disabled_llm_is_unavailable_without_rows(db):
    # LLM_MODEL_PROPOSER stays unset — the autouse `_no_ambient_env_file` fixture
    # (conftest.py, DEC-047) means `config.load()` sees no `.env` here either.
    alert_id = _seed_alert(db)

    run_triage_job(db, _job(alert_id))

    count = db.execute(
        "SELECT count(*) FROM llm_runs WHERE subject_id = %s", (alert_id,)
    ).fetchone()[0]
    assert count == 0
    triage_status = db.execute(
        "SELECT triage_status FROM alerts WHERE alert_id = %s", (alert_id,)
    ).fetchone()[0]
    assert triage_status == "unavailable"


@pytest.mark.db
def test_auto_closed_alert_takes_the_same_path(db, monkeypatch):
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(db, status="auto_closed")
    fake = _RecordingLLM(responses=[TRIAGE_V3_TRUE_POSITIVE, VERIFIER_V2_AGREE])

    run_triage_job(db, _job(alert_id), adapter=fake)

    rows = _rows(db, alert_id, "role")
    assert {r[0] for r in rows} == {"proposer", "verifier"}
    row = db.execute(
        "SELECT status, triage_status FROM alerts WHERE alert_id = %s", (alert_id,)
    ).fetchone()
    assert row == ("auto_closed", "ready")


# ---------------------------------------------------------------------------
# G2 across every path
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_never_touches_alerts_status(db, monkeypatch):
    _enable_llm(monkeypatch)
    scenarios = (
        ("queued_tier1", _RecordingLLM(responses=[TRIAGE_V3_TRUE_POSITIVE, VERIFIER_V2_AGREE])),
        ("queued_tier1", _RecordingLLM(responses=["bad", "bad"])),
        ("auto_closed", _RecordingLLM(responses=[TRIAGE_V3_TRUE_POSITIVE, VERIFIER_V2_AGREE])),
        ("closed_fp", _RecordingLLM()),
    )
    for status, fake in scenarios:
        alert_id = _seed_alert(db, status=status)
        run_triage_job(db, _job(alert_id), adapter=fake)
        after = db.execute("SELECT status FROM alerts WHERE alert_id = %s", (alert_id,)).fetchone()[
            0
        ]
        assert after == status


# ---------------------------------------------------------------------------
# The idle timeout (design note 3)
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_idle_timeout_survives_an_eleven_second_call(db, monkeypatch):
    # 11 s on purpose — design note 3
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(db)
    slow = _SlowFirstCallLLM(responses=[TRIAGE_V3_TRUE_POSITIVE, VERIFIER_V2_AGREE])

    worker.run_forever(lambda: db, {"triage": partial(run_triage_job, adapter=slow)}, once=True)

    job_status = db.execute(
        "SELECT status FROM jobs WHERE subject_id = %s", (alert_id,)
    ).fetchone()[0]
    assert job_status == "succeeded"
    count = db.execute(
        "SELECT count(*) FROM llm_runs WHERE subject_id = %s", (alert_id,)
    ).fetchone()[0]
    assert count == 2

    # run_forever commits internally (reclaim_stale, claim_job, the handler's own
    # transaction) regardless of what this test does — clean up what it committed.
    # `llm_runs`/`audit_events` are append-only (017's triggers) and cannot be
    # deleted; only `jobs`/`alerts` are ordinary mutable tables.
    db.execute("DELETE FROM jobs WHERE subject_id = %s", (alert_id,))
    db.execute("DELETE FROM alerts WHERE alert_id = %s", (alert_id,))
    db.commit()


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_rule_check_six_reasons():
    """Design note 5 — six strings, six tests, plus the `True` case."""
    reviewed = DecisionTable(
        category="ssh_brute_force",
        playbook="ssh_brute_force_v1",
        reviewed_by="owner",
        reviewed_at="2026-09-19",
        rules=(
            Rule(id="sbf-1", condition={"severity": ("low", "medium")}, action="false_positive"),
            Rule(id="sbf-3", condition={"rule_level_gte": 12}, action="true_positive"),
        ),
    )
    unreviewed = dataclasses.replace(reviewed, reviewed_by=None, reviewed_at=None)

    assert _make_rule_check(reviewed, {})(None) == (False, "no_rule_cited")
    assert _make_rule_check(None, {})("sbf-1") == (False, "no_table")
    assert _make_rule_check(unreviewed, {})("sbf-1") == (False, "table_unreviewed")
    assert _make_rule_check(reviewed, {"severity": "low"})("missing-id") == (False, "unknown_rule")
    assert _make_rule_check(reviewed, {"severity": "high"})("sbf-1") == (
        False,
        "rule_does_not_hold",
    )
    assert _make_rule_check(reviewed, {"rule_level": 12})("sbf-3") == (
        False,
        "rule_is_not_false_positive",
    )
    assert _make_rule_check(reviewed, {"severity": "low"})("sbf-1") == (True, None)


def test_worker_handler_table_has_triage():
    assert HANDLERS["triage"] is run_triage_job


# ---------------------------------------------------------------------------
# Row content
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_verifier_row_links_proposer_run_id(db, monkeypatch):
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(db)
    fake = _RecordingLLM(responses=[TRIAGE_V3_TRUE_POSITIVE, VERIFIER_V2_AGREE])

    run_triage_job(db, _job(alert_id), adapter=fake)

    proposer_run_id = db.execute(
        "SELECT run_id FROM llm_runs WHERE subject_id = %s AND role = 'proposer'", (alert_id,)
    ).fetchone()[0]
    linked = db.execute(
        "SELECT gate_result->>'proposer_run_id' FROM llm_runs "
        "WHERE subject_id = %s AND role = 'verifier'",
        (alert_id,),
    ).fetchone()[0]
    assert linked == str(proposer_run_id)


@pytest.mark.db
def test_user_message_is_the_prompt_sent(db, monkeypatch):
    """T7 (phase-5): `user_message` is the prompt actually sent, verbatim."""
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(db)
    fake = _RecordingLLM(responses=[TRIAGE_V3_TRUE_POSITIVE, VERIFIER_V2_AGREE])

    run_triage_job(db, _job(alert_id), adapter=fake)

    stored_user_message = db.execute(
        "SELECT user_message FROM llm_runs WHERE subject_id = %s AND role = 'proposer'",
        (alert_id,),
    ).fetchone()[0]
    assert stored_user_message == fake.calls[0]["user"]


# ---------------------------------------------------------------------------
# P10-T16 / DEC-165 R22 — `DEDUP_ENABLED=false`: the gate's occurrence facts are the burst count
# ---------------------------------------------------------------------------
#
# With the grouping switch off every alert row carries `occurrence_count` 1, which would
# silently disable `occurrence_lt` / `occurrence_gte` (`sbf-1` would admit every alert of a
# 500-attempt burst as a false positive). R22: with the switch off, the value the job puts
# into the facts and into the prompt is the number of alerts with the same
# rule_id/srcip/dstip/agent_name whose `first_seen_at` is at or after this alert's minus
# `MAX_CLUSTER_AGE_HOURS`, this alert included. With the switch on nothing changes.

#: `sbf-1`'s FP-only path (`kb/decision_tables/ssh_brute_force.yaml`): low severity, a clean
#: ioc, a low-criticality asset, an unprivileged user.
_FP_ALERT = {
    "severity": "low",
    "rule_level": 3,
    "asset_context": {"present": True, "criticality": "low", "owner": "a", "role": "b"},
    "identity_context": {"privileged": False},
    "ioc_context": {"reputation": "clean"},
    "lookup_status": {"asset": "found", "identity": "found", "ioc": "found"},
}
_VERIFIER_FP_AGREE = {
    "agree": True,
    "structured_only_verdict": "false_positive",
    "reason": "Structured facts alone (low severity, clean ioc, sbf-1 rule condition) justify it.",
}
_VERIFIER_REVIEW_AGREE = {
    "agree": True,
    "structured_only_verdict": "needs_review",
    "reason": "Structured facts alone (a burst of sixty, past sbf-1's ceiling) leave it for review.",
}


def _fp_proposal(occurrence: int, rule: str = "sbf-1") -> dict:
    proposal = copy.deepcopy(TRIAGE_V2_FALSE_POSITIVE)
    proposal["structured_basis"]["occurrence_count"] = occurrence
    proposal["structured_basis"]["playbook_rule_applied"] = rule
    return proposal


def _seed_burst(db, n: int, **overrides) -> list[str]:
    """`n` alerts sharing one cluster key (the canonical rule, srcip, dstip '' and agent),
    each `occurrence_count` 1 as the switch-off pipeline writes them, one second apart."""
    return [
        _seed_alert(
            db,
            first_seen_at=_ALERT_TIME + timedelta(seconds=i),
            last_seen_at=_ALERT_TIME + timedelta(seconds=i),
            **overrides,
        )
        for i in range(n)
    ]


def _proposer_gate_result(db, alert_id: str) -> dict:
    return db.execute(
        "SELECT gate_result FROM llm_runs WHERE subject_id = %s AND role = 'proposer'",
        (alert_id,),
    ).fetchone()[0]


def _switch(monkeypatch, value: str) -> None:
    _enable_llm(monkeypatch)
    monkeypatch.setenv("DEDUP_ENABLED", value)


@pytest.mark.db
def test_switch_off_sixty_alert_burst_cannot_take_sbf_1(db, monkeypatch):
    """The safety case: 60 identical alerts, each row at 1. The gate must see 60, so
    `sbf-1` (`occurrence_lt: 50`) does not hold and the false positive is forced away."""
    _switch(monkeypatch, "false")
    ids = _seed_burst(db, 60, **_FP_ALERT)
    fake = _RecordingLLM(responses=[_fp_proposal(60), _VERIFIER_REVIEW_AGREE])

    run_triage_job(db, _job(ids[-1]), adapter=fake)

    gate_result = _proposer_gate_result(db, ids[-1])
    assert gate_result["facts"]["occurrence_count"] == 60
    assert gate_result["steps"]["2"] == "ok"  # the model was shown 60, the gate holds 60
    assert gate_result["proposed_verdict"] == "false_positive"
    assert gate_result["final_verdict"] == "needs_review"  # never an accepted FP
    assert gate_result["forced_by"] == ["step4"]
    assert gate_result["missing"] == ["playbook_rule"]
    assert "rule_does_not_hold" in gate_result["warnings"]
    assert "occurrence_count: 60" in fake.calls[0]["user"]  # the prompt shows it too
    row_count = db.execute(
        "SELECT occurrence_count FROM alerts WHERE alert_id = %s", (ids[-1],)
    ).fetchone()
    assert row_count == (1,)  # the row itself is never rewritten


@pytest.mark.db
def test_switch_off_three_alerts_can_still_take_sbf_1(db, monkeypatch):
    """The other side: a burst of 3 is under 50, so the guard lets `sbf-1` through."""
    _switch(monkeypatch, "false")
    ids = _seed_burst(db, 3, **_FP_ALERT)
    fake = _RecordingLLM(responses=[_fp_proposal(3), _VERIFIER_FP_AGREE])

    run_triage_job(db, _job(ids[0]), adapter=fake)

    gate_result = _proposer_gate_result(db, ids[0])
    assert gate_result["facts"]["occurrence_count"] == 3
    assert gate_result["final_verdict"] == "false_positive"
    assert gate_result["forced"] is False
    assert gate_result["steps"]["4"] == "ok"
    assert "occurrence_count: 3" in fake.calls[0]["user"]


@pytest.mark.db
def test_switch_off_burst_count_reaches_both_llm_runs_and_the_verifier_prompt(db, monkeypatch):
    _switch(monkeypatch, "false")
    ids = _seed_burst(db, 5, **_FP_ALERT)
    fake = _RecordingLLM(responses=[_fp_proposal(5), _VERIFIER_FP_AGREE])

    run_triage_job(db, _job(ids[0]), adapter=fake)

    rows = db.execute(
        "SELECT role, gate_result->'facts'->>'occurrence_count' FROM llm_runs "
        "WHERE subject_id = %s ORDER BY role",
        (ids[0],),
    ).fetchall()
    assert [r[0] for r in rows] == ["proposer", "verifier"]
    assert rows[0][1] == "5"
    assert "occurrence_count: 5" in fake.calls[1]["user"]  # the verifier prompt


@pytest.mark.db
def test_switch_on_keeps_the_rows_occurrence_count_and_never_counts_a_burst(db, monkeypatch):
    """Byte-identical with the switch on: 60 same-key rows at 1 are still 1, a head at 7
    is 7, and the burst query is not even run."""
    _switch(monkeypatch, "true")

    def _forbidden(*args, **kwargs):
        raise AssertionError("burst_count was reached with DEDUP_ENABLED=true")

    monkeypatch.setattr(triage_module, "burst_count", _forbidden)
    ids = _seed_burst(db, 60, **_FP_ALERT)
    head = _seed_alert(db, occurrence_count=7, **_FP_ALERT)
    fake = _RecordingLLM(
        responses=[_fp_proposal(1), _VERIFIER_FP_AGREE, _fp_proposal(7), _VERIFIER_FP_AGREE]
    )

    run_triage_job(db, _job(ids[-1]), adapter=fake)
    run_triage_job(db, _job(head), adapter=fake)

    assert _proposer_gate_result(db, ids[-1])["facts"]["occurrence_count"] == 1
    assert _proposer_gate_result(db, ids[-1])["final_verdict"] == "false_positive"
    assert _proposer_gate_result(db, head)["facts"]["occurrence_count"] == 7


@pytest.mark.db
def test_switch_unset_is_on_and_leaves_the_facts_alone(db, monkeypatch):
    _enable_llm(monkeypatch)
    monkeypatch.delenv("DEDUP_ENABLED", raising=False)
    ids = _seed_burst(db, 60, **_FP_ALERT)
    fake = _RecordingLLM(responses=[_fp_proposal(1), _VERIFIER_FP_AGREE])

    run_triage_job(db, _job(ids[0]), adapter=fake)

    assert _proposer_gate_result(db, ids[0])["facts"]["occurrence_count"] == 1


def _gte_table() -> DecisionTable:
    """A reviewed table with an `occurrence_gte` false-positive rule. No shipped table has
    one, so the guard the format offers besides `occurrence_lt` is exercised on a synthetic
    table."""
    return DecisionTable(
        category="ssh_brute_force",
        playbook="ssh_brute_force_v1",
        reviewed_by="owner",
        reviewed_at="2026-09-30",
        rules=(
            Rule(
                id="sbf-9",
                condition={"severity": ("low", "medium"), "occurrence_gte": 10},
                action="false_positive",
            ),
        ),
    )


@pytest.mark.db
def test_switch_off_an_occurrence_gte_rule_fires_on_a_burst(db, monkeypatch):
    """`occurrence_gte` is dead at 1 per row and live on the burst count."""
    _switch(monkeypatch, "false")
    monkeypatch.setattr(triage_module.kb, "get_decision_table", lambda category: _gte_table())
    ids = _seed_burst(db, 12, **_FP_ALERT)
    fake = _RecordingLLM(responses=[_fp_proposal(12, "sbf-9"), _VERIFIER_FP_AGREE])

    run_triage_job(db, _job(ids[0]), adapter=fake)

    gate_result = _proposer_gate_result(db, ids[0])
    assert gate_result["facts"]["occurrence_count"] == 12
    assert gate_result["steps"]["4"] == "ok"  # `sbf-9` holds: 12 >= 10
    assert gate_result["final_verdict"] == "false_positive"


@pytest.mark.db
def test_switch_on_the_same_occurrence_gte_rule_does_not_fire_at_one(db, monkeypatch):
    _switch(monkeypatch, "true")
    monkeypatch.setattr(triage_module.kb, "get_decision_table", lambda category: _gte_table())
    ids = _seed_burst(db, 12, **_FP_ALERT)
    fake = _RecordingLLM(responses=[_fp_proposal(1, "sbf-9"), _VERIFIER_FP_AGREE])

    run_triage_job(db, _job(ids[0]), adapter=fake)

    gate_result = _proposer_gate_result(db, ids[0])
    assert gate_result["facts"]["occurrence_count"] == 1
    assert gate_result["final_verdict"] == "needs_review"
    assert "rule_does_not_hold" in gate_result["warnings"]


# --- the burst query itself --------------------------------------------------------------


def _cfg(monkeypatch=None, **env: str) -> config.Config:
    if monkeypatch is not None:
        for key, value in env.items():
            monkeypatch.setenv(key, value)
    return config.load(env_file="/dev/null")


@pytest.mark.db
def test_burst_count_counts_the_key_inside_the_window_this_alert_included(db):
    cfg = _cfg()
    base = _seed_alert(db, first_seen_at=_ALERT_TIME, last_seen_at=_ALERT_TIME)
    assert triage_module.burst_count(db, base, cfg) == 1  # itself

    edge = _ALERT_TIME - timedelta(hours=cfg.MAX_CLUSTER_AGE_HOURS)
    on_edge = _seed_alert(db, first_seen_at=edge, last_seen_at=edge)
    outside = edge - timedelta(seconds=1)
    _seed_alert(db, first_seen_at=outside, last_seen_at=outside)
    later_time = _ALERT_TIME + timedelta(minutes=30)
    later = _seed_alert(db, first_seen_at=later_time, last_seen_at=later_time)

    # `base`: itself, the row exactly on the window's edge ("at or after"), and the later
    # one (counted when (1) runs, no upper bound) — not the row one second outside.
    assert triage_module.burst_count(db, base, cfg) == 3
    # `on_edge`'s own window starts 4 h earlier still: it sees all four.
    assert triage_module.burst_count(db, on_edge, cfg) == 4
    # `later`'s window starts at t0 + 30 min - 4 h: only itself and `base`.
    assert triage_module.burst_count(db, later, cfg) == 2


@pytest.mark.db
def test_burst_count_is_keyed_on_all_four_columns(db):
    base = _seed_alert(db, srcip="10.0.0.1", dstip="10.0.0.2")
    _seed_alert(db, srcip="10.0.0.1", dstip="10.0.0.2")  # same key
    _seed_alert(db, srcip="10.0.0.9", dstip="10.0.0.2")  # srcip differs
    _seed_alert(db, srcip="10.0.0.1", dstip="10.0.0.9")  # dstip differs
    _seed_alert(db, srcip="10.0.0.1", dstip="10.0.0.2", agent_name="other-agent")
    _seed_alert(db, srcip="10.0.0.1", dstip="10.0.0.2", rule_id="99999")
    assert triage_module.burst_count(db, base, _cfg()) == 2


@pytest.mark.db
def test_burst_count_counts_every_status_and_honours_the_configured_window(db, monkeypatch):
    base = _seed_alert(db)
    _seed_alert(db, status="closed_fp")
    _seed_alert(db, status="auto_closed")
    sibling = _seed_alert(db, status="queued_tier1")
    _seed_alert(db, status="duplicate", duplicate_of=sibling, sealed_at=_ALERT_TIME)
    assert triage_module.burst_count(db, base, _cfg()) == 5

    old = _ALERT_TIME - timedelta(hours=3)
    _seed_alert(db, first_seen_at=old, last_seen_at=old)
    assert triage_module.burst_count(db, base, _cfg()) == 6  # 3 h < 4 h
    assert triage_module.burst_count(db, base, _cfg(monkeypatch, MAX_CLUSTER_AGE_HOURS="2")) == 5


@pytest.mark.db
def test_burst_count_of_a_missing_alert_is_zero(db):
    assert triage_module.burst_count(db, "no-such-alert", _cfg()) == 0


@pytest.mark.db
def test_burst_query_takes_bound_parameters_only_and_uses_an_index(db):
    alert = _seed_alert(db)
    statement, params = triage_module.burst_count_query(alert, _cfg())
    assert statement.count("%s") == len(params) == 2
    assert alert not in statement
    db.execute("SET LOCAL enable_seqscan = off")
    plan = "\n".join(r[0] for r in db.execute("EXPLAIN " + statement, params).fetchall())
    assert "Seq Scan on alerts" not in plan, plan
    assert "ix_alerts_" in plan, plan
