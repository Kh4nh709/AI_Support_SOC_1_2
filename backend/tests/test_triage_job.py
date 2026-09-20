"""`tier1.triage.run_triage_job` end to end on a database, with the fake adapter (P3-T10).

Written against `docs/plan/tasks/P3/P3-T10.prompt.md`'s design notes and acceptance
list. Every model call goes through `backend/tests/fakes/llm.py`'s `FakeLLM` (or a
tiny local double for the one branch `FakeLLM` cannot express — a budget check that
must fire before any call is recorded); nothing here opens a socket. The seeded
alert reuses the canonical fixture's values (context pack §8) so `TRIAGE_V2_ESCALATE`'s
quote is a real substring of the seeded `raw_log` and its `structured_basis` matches
the facts `build_facts` derives from the seed — see `_seed_alert`.
"""

from __future__ import annotations

import dataclasses
import hashlib
import itertools
import json
import re
import time
from datetime import UTC, datetime
from functools import partial
from pathlib import Path

import pytest
from app.infra import worker
from app.infra.errors import TransientError
from app.infra.jobs import Job
from app.kb.lookup import DecisionTable, Rule
from app.llm.adapter import LLMBudgetExceeded
from app.security.linter import Violation
from app.tier1.triage import _make_rule_check, run_triage_job
from app.web.worker import HANDLERS
from psycopg.types.json import Jsonb

from tests.fakes.llm import (
    TRIAGE_V2_ESCALATE,
    TRIAGE_V2_FALSE_POSITIVE,
    VERIFIER_V1_AGREE,
    VERIFIER_V1_DISAGREE,
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
    {"duplicate", "auto_closed", "closed_fp", "closed_benign", "closed_confirmed"}
)
_HUMAN_CLOSED_STATUSES = frozenset({"closed_fp", "closed_benign", "closed_confirmed"})


def _hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _seed_alert(conn, **overrides) -> str:
    """Insert one `alerts` row plus its pending `triage` job (design note 8): the
    twelve NOT NULL-without-default columns, `status`, the four `*_context`/
    `lookup_status` columns in `finish_enrichment`'s shape, `occurrence_count`. The
    defaults reuse the canonical alert (context pack §8) exactly — same `rule_level`
    (12, critical), same `raw_log` (so `TRIAGE_V2_ESCALATE`'s quote is a real
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
    fake = _RecordingLLM(responses=[TRIAGE_V2_ESCALATE, VERIFIER_V1_AGREE])

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
    fake = _RecordingLLM(responses=[TRIAGE_V2_FALSE_POSITIVE, VERIFIER_V1_DISAGREE])

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
    fake = _RecordingLLM(responses=[TRIAGE_V2_FALSE_POSITIVE, VERIFIER_V1_DISAGREE])

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
def test_builder_violation_is_unavailable_with_event(db, monkeypatch):
    _enable_llm(monkeypatch)
    from app.security import linter as linter_module

    monkeypatch.setattr(
        linter_module, "lint", lambda *a, **kw: [Violation(kind="free_text", token="x", line=1)]
    )
    alert_id = _seed_alert(db)
    fake = _RecordingLLM(responses=[TRIAGE_V2_ESCALATE, VERIFIER_V1_AGREE])

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
    fake = _FailVerifyCall(responses=[TRIAGE_V2_ESCALATE], raises=TransientError("stalled"))

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
    fake = _FailVerifyCall(responses=[TRIAGE_V2_ESCALATE], raises=TransientError("stalled"))

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
    fake = _FailVerifyCall(responses=[TRIAGE_V2_ESCALATE], raises=LLMBudgetExceeded("over cap"))

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
    fake = _RecordingLLM(responses=[TRIAGE_V2_ESCALATE, VERIFIER_V1_AGREE])

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
        ("queued_tier1", _RecordingLLM(responses=[TRIAGE_V2_ESCALATE, VERIFIER_V1_AGREE])),
        ("queued_tier1", _RecordingLLM(responses=["bad", "bad"])),
        ("auto_closed", _RecordingLLM(responses=[TRIAGE_V2_ESCALATE, VERIFIER_V1_AGREE])),
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
    slow = _SlowFirstCallLLM(responses=[TRIAGE_V2_ESCALATE, VERIFIER_V1_AGREE])

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
            Rule(id="sbf-3", condition={"rule_level_gte": 12}, action="escalate"),
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
    fake = _RecordingLLM(responses=[TRIAGE_V2_ESCALATE, VERIFIER_V1_AGREE])

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
    fake = _RecordingLLM(responses=[TRIAGE_V2_ESCALATE, VERIFIER_V1_AGREE])

    run_triage_job(db, _job(alert_id), adapter=fake)

    stored_user_message = db.execute(
        "SELECT user_message FROM llm_runs WHERE subject_id = %s AND role = 'proposer'",
        (alert_id,),
    ).fetchone()[0]
    assert stored_user_message == fake.calls[0]["user"]
