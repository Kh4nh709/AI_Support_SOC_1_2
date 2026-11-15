"""`tier1.triage.evaluate_alert` and `EvalSwitches`: ① computed for one alert without
writing anything, with P7's evaluation switches (P7-T01).

Written against `docs/plan/tasks/P7/P7-T01.prompt.md`. B2 is the builder's own
`include_context=False, include_correlation=False`; B3 is `gate_mode="steps_1_3"` (gate
steps 1-3, then the step-7 output guard, no verifier); B4 is `DEPLOYED`.
`run_triage_job`'s behaviour is pinned by `test_triage_job.py`'s 20 tests, which this
card does not touch; here it appears only to show that the job *is* `evaluate_alert`
with `DEPLOYED`, followed by its writes.

Alerts go through `domain.transitions.open_alert` -> `start_enrichment` ->
`finish_enrichment` from the canonical `alert_40112.json` (context pack §8), as
`test_queue.py` does, with this file's own `agent_name`/`alert_user`/`srcip`, so the ±2h
correlation window holds only what a test here seeds. The model is `FakeLLM`; nothing
opens a socket, and every test runs inside the `db` fixture's transaction and is rolled
back.
"""

from __future__ import annotations

import dataclasses
import hashlib
import itertools
import json
import re
from pathlib import Path

import pytest
from app.domain.alert import AlertContext
from app.domain.transitions import finish_enrichment, open_alert, start_enrichment
from app.infra import config
from app.infra.errors import TransientError
from app.infra.jobs import Job
from app.ingest.wazuh_parser import parse_wazuh_alert
from app.llm.adapter import LLMBudgetExceeded, cost_usd
from app.llm.builder import HEADING_CONTEXT, HEADING_CORRELATION
from app.llm.triage import TRIAGE_TEMPLATE, prompt_version
from app.security import linter
from app.security.linter import Violation
from app.tier1 import triage as triage_module
from app.tier1.triage import (
    DEPLOYED,
    EvalSwitches,
    TriageEvaluation,
    evaluate_alert,
    run_triage_job,
)
from psycopg import sql

from tests.fakes.llm import VERIFIER_V2_AGREE, VERIFIER_V2_DISAGREE, FakeLLM

_DOC = json.loads((Path(__file__).parent / "fixtures" / "alert_40112.json").read_text("utf-8"))
_CANONICAL = parse_wazuh_alert(_DOC).alert
assert _CANONICAL is not None
_RAW_LOG = _DOC["_source"]["full_log"]
_QUOTE = _RAW_LOG[_RAW_LOG.index("Accepted password") :]

#: This file's own correlation keys: the window predicate is agent OR user OR srcip, and
#: no other test file seeds these, so a test here sees only its own neighbours.
_AGENT = "p7t01-agent"
_USER = "p7t01-user"
_SRCIP = "10.71.0.1"

#: The canonical enrichment (context pack §8): asset not in inventory, identity not
#: found, IoC skipped -> facts critical / unknown / skipped / unknown.
_CANONICAL_CONTEXT = AlertContext(
    asset_present=False,
    asset_criticality="unknown",
    asset_owner=None,
    asset_role=None,
    identity_privileged=None,
    ioc_reputation="skipped",
    lookup_status={"asset": "not_found", "identity": "not_found", "ioc": "skipped"},
)
#: Every lookup found, so the deployed prompt carries a `context` block.
_FOUND_CONTEXT = AlertContext(
    asset_present=True,
    asset_criticality="low",
    asset_owner="p7t01-owner",
    asset_role="p7t01-role",
    identity_privileged=False,
    ioc_reputation="clean",
    lookup_status={"asset": "found", "identity": "found", "ioc": "found"},
)
_CANONICAL_BASIS = {
    "severity": "critical",
    "ioc_reputation": "skipped",
    "asset_criticality": "unknown",
    "identity_privileged": "unknown",
    "occurrence_count": 1,
}
_FOUND_BASIS = {
    "severity": "critical",
    "ioc_reputation": "clean",
    "asset_criticality": "low",
    "identity_privileged": "false",
    "occurrence_count": 1,
}
_GOOD_REASON = {
    "claim": "The log shows a password login that succeeded.",
    "quote": _QUOTE,
    "source": "wazuh_raw_log",
}


def _proposal(
    action: str,
    *,
    rule: str | None = None,
    basis: dict | None = None,
    reasons: list[dict] | None = None,
) -> dict:
    """A schema-valid `triage_v3` answer whose `structured_basis` matches the seeded facts
    (gate step 2 passes) and whose reason quotes the raw log (step 3 keeps it)."""
    return {
        "suggested_action": action,
        "confidence": "medium",
        "structured_basis": {**(basis or _CANONICAL_BASIS), "playbook_rule_applied": rule},
        "reasons": reasons if reasons is not None else [dict(_GOOD_REASON)],
        "playbook_used": None,
    }


_TRUE_POSITIVE = _proposal("true_positive", rule="sbf-3")
#: Gate step 4 forbids this on the canonical alert (context pack §8): severity is
#: critical, the asset is not in inventory, and no decision-table rule is cited.
_POLICY_BLOCKED_FP = _proposal("false_positive")
#: DEC-217: step 4 flags that answer, it no longer holds it, so the verifier is asked about the model's own
#: `false_positive` and a verifier that agrees with it says so.
_VERIFIER_AGREES_FALSE_POSITIVE = {
    "agree": True,
    "structured_only_verdict": "false_positive",
    "reason": "Nothing in the structured facts contradicts the model's false_positive.",
}

_B2 = EvalSwitches(include_context=False, include_correlation=False)
_B3 = EvalSwitches(gate_mode="steps_1_3")

_counter = itertools.count()


class _FakeLLM(FakeLLM):
    """`FakeLLM` plus the `model` keyword `llm.triage.propose`/`verify` always pass (the
    real adapter's `complete()` takes it) - the same shim `test_triage_job.py` uses."""

    def complete(self, *, system, user, response_format=None, timeout_s=None, model=None):
        return super().complete(
            system=system, user=user, response_format=response_format, timeout_s=timeout_s
        )


class _AlwaysOverBudget:
    """The monthly cap fires before any call is recorded, as the real adapter's does
    (it is checked before a socket opens)."""

    def __init__(self) -> None:
        self.calls: list = []

    def complete(self, **kwargs):
        raise LLMBudgetExceeded("over the monthly cap")


class _FailAfterFirstCall(_FakeLLM):
    """The first call (the proposer) answers; every later one (the verifier) raises."""

    def __init__(self, *args, raises: Exception, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._later = raises

    def complete(self, **kwargs):
        if len(self.calls) >= 1:
            raise self._later
        return super().complete(**kwargs)


@pytest.fixture
def cfg(monkeypatch) -> config.Config:
    """The LLM enabled (as `run_triage_job` needs, which loads its own), prices set so a
    cost is never trivially 0, and no DSN on the object: `Config`'s repr prints its
    fields, and a failing assertion must never put a credential in the test output."""
    monkeypatch.setenv("LLM_MODEL_PROPOSER", "fake-deepseek")
    return dataclasses.replace(
        config.load(),
        DATABASE_URL="",
        DATABASE_URL_OWNER="",
        TEST_DATABASE_URL="",
        LLM_PRICE_IN_PER_M=0.27,
        LLM_PRICE_OUT_PER_M=1.10,
    )


def _seed(conn, *, context: AlertContext = _CANONICAL_CONTEXT) -> str:
    """One `queued_tier1` cluster head through the real transitions (A1, A4, A5)."""
    alert_id = f"1786907101.{710_000 + next(_counter)}"
    alert = dataclasses.replace(
        _CANONICAL,
        alert_id=alert_id,
        event_bucket_hash=hashlib.sha256(alert_id.encode()).hexdigest(),
        agent_name=_AGENT,
        alert_user=_USER,
        srcip=_SRCIP,
    )
    open_alert(conn, alert, kind="received", source="wazuh", suggestion_visible=True)
    start_enrichment(conn, alert_id)
    finish_enrichment(conn, alert_id, context=context, risk_score=61, risk_components={})
    return alert_id


def _job(alert_id: str) -> Job:
    return Job(job_id=1, job_type="triage", subject_id=alert_id, attempts=1)


def _snapshot(db, alert_id: str) -> dict:
    """What `evaluate_alert` must leave alone: every table's row count, the alert row
    whole (`triage_status`, `triaged_count`, `status`, ...), and the alert's jobs."""
    tables = [
        r[0]
        for r in db.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename"
        ).fetchall()
    ]
    counts = {
        t: db.execute(sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(t))).fetchone()[0]
        for t in tables
    }
    alert = db.execute(
        "SELECT to_jsonb(a) FROM alerts a WHERE alert_id = %s", (alert_id,)
    ).fetchone()[0]
    jobs = [
        r[0]
        for r in db.execute(
            "SELECT to_jsonb(j) FROM jobs j WHERE subject_id = %s ORDER BY to_jsonb(j)::text",
            (alert_id,),
        ).fetchall()
    ]
    return {"counts": counts, "alert": alert, "jobs": jobs}


# ---------------------------------------------------------------------------
# The switches
# ---------------------------------------------------------------------------


def test_deployed_is_the_default_switches():
    assert DEPLOYED == EvalSwitches()
    assert (
        DEPLOYED.include_context,
        DEPLOYED.include_correlation,
        DEPLOYED.gate_mode,
        DEPLOYED.proposer_template,
    ) == (True, True, "full", None)
    assert _B3.gate_mode == "steps_1_3"
    with pytest.raises(dataclasses.FrozenInstanceError):
        DEPLOYED.gate_mode = "steps_1_3"  # type: ignore[misc]


@pytest.mark.parametrize("mode", ["steps_1_5", "", "FULL", "steps_1_3 ", "verifier_only"])
def test_unknown_gate_mode_raises(mode):
    with pytest.raises(ValueError, match="gate_mode"):
        EvalSwitches(gate_mode=mode)
    with pytest.raises(ValueError, match="gate_mode"):
        dataclasses.replace(DEPLOYED, gate_mode=mode)


@pytest.mark.db
def test_missing_alert_returns_none(db, cfg):
    fake = _FakeLLM(responses=[_TRUE_POSITIVE, VERIFIER_V2_AGREE])

    ev = evaluate_alert(db, "1786907101.999999", adapter=fake, cfg=cfg)

    assert ev is None
    assert fake.calls == []


# ---------------------------------------------------------------------------
# Writes nothing, on every outcome
# ---------------------------------------------------------------------------

_WRITES_NOTHING_CASES = {
    "ok_b4": (lambda: _FakeLLM(responses=[_TRUE_POSITIVE, VERIFIER_V2_AGREE]), DEPLOYED, "ok"),
    "ok_b2": (lambda: _FakeLLM(responses=[_TRUE_POSITIVE, VERIFIER_V2_AGREE]), _B2, "ok"),
    "ok_b3": (lambda: _FakeLLM(responses=[_TRUE_POSITIVE]), _B3, "ok"),
    "schema": (lambda: _FakeLLM(responses=["not json", "still not json"]), DEPLOYED, "schema"),
    "cap": (_AlwaysOverBudget, DEPLOYED, "cap"),
    "transient": (lambda: _FakeLLM(raises=TransientError("stalled")), DEPLOYED, "transient"),
    "verifier_cap": (
        lambda: _FailAfterFirstCall(responses=[_TRUE_POSITIVE], raises=LLMBudgetExceeded("cap")),
        DEPLOYED,
        "verifier_cap",
    ),
    "verifier_transient": (
        lambda: _FailAfterFirstCall(responses=[_TRUE_POSITIVE], raises=TransientError("stalled")),
        DEPLOYED,
        "verifier_transient",
    ),
    "builder_violation": (_FakeLLM, DEPLOYED, "builder_violation"),
}


@pytest.mark.db
@pytest.mark.parametrize("case", list(_WRITES_NOTHING_CASES))
def test_evaluate_alert_writes_nothing(db, cfg, monkeypatch, case):
    make_adapter, switches, expected_outcome = _WRITES_NOTHING_CASES[case]
    alert_id = _seed(db)
    if case == "builder_violation":
        monkeypatch.setattr(
            linter, "lint", lambda *a, **kw: [Violation(kind="free_text", token="x", line=1)]
        )
    before = _snapshot(db, alert_id)
    assert {"alerts", "llm_runs", "audit_events", "jobs"} <= set(before["counts"])  # a real net
    assert before["alert"]["triage_status"] == "pending"
    assert before["jobs"], "finish_enrichment enqueues the alert's triage job"

    ev = evaluate_alert(db, alert_id, adapter=make_adapter(), cfg=cfg, switches=switches)

    assert ev.outcome == expected_outcome
    after = _snapshot(db, alert_id)
    for table in ("llm_runs", "audit_events", "jobs"):
        assert after["counts"][table] == before["counts"][table], table
    assert after["alert"]["triage_status"] == before["alert"]["triage_status"]
    assert after == before  # and nothing anywhere else either


# ---------------------------------------------------------------------------
# The gate modes
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_steps_1_3_makes_one_call_and_keeps_a_policy_blocked_fp(db, cfg):
    alert_id = _seed(db)

    b3_llm = _FakeLLM(responses=[_POLICY_BLOCKED_FP])
    b3 = evaluate_alert(db, alert_id, adapter=b3_llm, cfg=cfg, switches=_B3)

    assert isinstance(b3, TriageEvaluation)
    assert b3.outcome == "ok"
    assert b3.final_verdict == "false_positive" == b3.result["suggested_action"]
    assert b3.forced_by == () and b3.flagged_by == ()  # B3 stops after step 3: step 4 never ran
    assert len(b3_llm.calls) == 1 and b3.calls == 1  # the verifier is never called
    assert b3.vbuilt is None and b3.verification is None and b3.verifier_verdict is None
    # no 4, no 5, no 6; the RAG rule's step (DEC-219) sits after 3 and is `n/a` with the switch off
    assert sorted(b3.gate_result["steps"]) == ["1", "2", "3", "3r", "7"]
    assert b3.gate_result["steps"]["3r"] == "n/a"

    full_llm = _FakeLLM(responses=[_POLICY_BLOCKED_FP, _VERIFIER_AGREES_FALSE_POSITIVE])
    full = evaluate_alert(db, alert_id, adapter=full_llm, cfg=cfg)  # DEPLOYED

    assert full.outcome == "ok"
    assert len(full_llm.calls) == 2 and full.calls == 2
    assert full.proposed_verdict == b3.proposed_verdict == "false_positive"
    assert full.gate_result["steps"]["4"] == "missing"
    assert full.gate_result["missing"] == ["severity", "asset_criticality", "playbook_rule"]
    # DEC-217: step 4 flags, it does not hold - the verifier was asked about the model's own verdict
    assert full.verdict_for_verifier == "false_positive"
    assert full.forced_by == () and full.flagged_by == ("step4",)
    assert full.final_verdict == "false_positive" == full.proposed_verdict
    assert full.gate_result["flagged_by"] == ["step4"] and full.gate_result["forced"] is False


@pytest.mark.db
def test_full_mode_calls_the_verifier_and_respects_disagreement(db, cfg):
    alert_id = _seed(db)

    agreed = evaluate_alert(
        db, alert_id, adapter=_FakeLLM(responses=[_TRUE_POSITIVE, VERIFIER_V2_AGREE]), cfg=cfg
    )
    assert (agreed.final_verdict, agreed.forced_by, agreed.flagged_by) == ("true_positive", (), ())
    assert agreed.gate_result["steps"]["6"] == "agree"

    llm = _FakeLLM(responses=[_TRUE_POSITIVE, VERIFIER_V2_DISAGREE])
    ev = evaluate_alert(db, alert_id, adapter=llm, cfg=cfg)

    assert ev.outcome == "ok"
    assert len(llm.calls) == 2 and ev.calls == 2
    assert "## Schema verifier_v2" in llm.calls[1]["system"]  # the second call is the verifier
    assert llm.calls[1]["user"] == ev.vbuilt.prompt.user
    assert ev.verdict_for_verifier == "true_positive"
    assert ev.verifier_verdict == "needs_review"
    assert ev.gate_result["steps"]["6"] == "disagree"
    assert ev.forced_by == () and ev.flagged_by == ("step6",)  # a warning, not a hold (DEC-217)
    assert (ev.proposed_verdict, ev.final_verdict) == ("true_positive", "true_positive")
    # the numbers are the two calls', summed
    p, v = ev.proposal, ev.verification
    assert ev.usage["prompt_tokens"] == p.usage["prompt_tokens"] + v.usage["prompt_tokens"]
    assert ev.usage["completion_tokens"] == (
        p.usage["completion_tokens"] + v.usage["completion_tokens"]
    )
    assert ev.latency_ms == p.latency_ms + v.latency_ms == 2
    both = round(cost_usd(p.usage, cfg) + cost_usd(v.usage, cfg), 5)
    assert ev.cost_usd == both > 0
    assert ev.model_id == "fake-deepseek-1"


@pytest.mark.db
def test_calls_are_counted_from_the_adapter_results(db, cfg):
    """Design note 3: a schema repair is a call too, and it is counted from what came
    back, not assumed."""
    alert_id = _seed(db)

    b3_llm = _FakeLLM(responses=["not json", _TRUE_POSITIVE])
    b3 = evaluate_alert(db, alert_id, adapter=b3_llm, cfg=cfg, switches=_B3)
    assert b3.gate_result["steps"]["1"] == "repaired"
    assert b3.calls == len(b3_llm.calls) == 2

    full_llm = _FakeLLM(responses=["not json", _TRUE_POSITIVE, VERIFIER_V2_AGREE])
    full = evaluate_alert(db, alert_id, adapter=full_llm, cfg=cfg)
    assert full.calls == len(full_llm.calls) == 3

    # a call that raised brought no result back: nothing to count, nothing to price
    raised = _FakeLLM(raises=TransientError("stalled"))
    failed = evaluate_alert(db, alert_id, adapter=raised, cfg=cfg)
    assert (failed.outcome, failed.calls, failed.usage, failed.cost_usd) == (
        "transient",
        0,
        {},
        0.0,
    )


@pytest.mark.db
def test_reasons_kept_and_dropped_are_counted_after_step_3(db, cfg):
    alert_id = _seed(db)
    two_reasons = _proposal(
        "true_positive",
        rule="sbf-3",
        reasons=[
            dict(_GOOD_REASON),
            {"claim": "Made up.", "quote": "a quote found in no block", "source": "wazuh_raw_log"},
        ],
    )

    for switches, responses in ((DEPLOYED, [two_reasons, VERIFIER_V2_AGREE]), (_B3, [two_reasons])):
        ev = evaluate_alert(
            db, alert_id, adapter=_FakeLLM(responses=responses), cfg=cfg, switches=switches
        )
        assert (ev.reasons_kept, ev.reasons_dropped) == (1, 1), switches
        assert ev.gate_result["steps"]["3"] == "dropped:1"
        assert ev.final_verdict == "true_positive"


# ---------------------------------------------------------------------------
# B2 and the template override
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_b2_switches_remove_context_and_correlation_blocks(db, cfg):
    neighbour = _seed(db, context=_FOUND_CONTEXT)  # same agent, same minute: correlated
    alert_id = _seed(db, context=_FOUND_CONTEXT)
    answer = _proposal("true_positive", rule="sbf-3", basis=_FOUND_BASIS)

    deployed = evaluate_alert(
        db, alert_id, adapter=_FakeLLM(responses=[answer, VERIFIER_V2_AGREE]), cfg=cfg
    )
    b2_llm = _FakeLLM(responses=[answer, VERIFIER_V2_AGREE])
    b2 = evaluate_alert(db, alert_id, adapter=b2_llm, cfg=cfg, switches=_B2)

    # not vacuous: with the deployed switches both blocks are there
    assert {"context", "correlation_samples"} <= set(deployed.built.prompt.block_index)
    assert 'source="context"' in deployed.built.prompt.user
    assert 'source="correlation_samples"' in deployed.built.prompt.user
    assert neighbour in deployed.built.prompt.block_index["correlation_samples"].plain

    user = b2.built.prompt.user
    assert "context" not in b2.built.prompt.block_index
    assert "correlation_samples" not in b2.built.prompt.block_index
    assert 'source="context"' not in user and 'source="correlation_samples"' not in user
    assert HEADING_CONTEXT not in user and HEADING_CORRELATION not in user
    assert b2_llm.calls[0]["user"] == user  # what was built is what was sent
    # the gate still reads the database, not the prompt
    assert b2.facts == deployed.facts and b2.facts["correlated_clusters"] == 1
    assert b2.outcome == deployed.outcome == "ok"


@pytest.mark.db
def test_override_template_changes_prompt_version_to_file_sha(db, cfg, tmp_path):
    alert_id = _seed(db)
    deployed_text = TRIAGE_TEMPLATE.read_text("utf-8")
    template = tmp_path / "triage_system_v1_1.txt"
    template.write_text(deployed_text + "\nVÍ DỤ: một dòng few-shot để thử.\n", encoding="utf-8")
    file_version = "file:" + hashlib.sha256(template.read_bytes()).hexdigest()[:12]

    llm = _FakeLLM(responses=[_TRUE_POSITIVE, VERIFIER_V2_AGREE])
    ev = evaluate_alert(
        db, alert_id, adapter=llm, cfg=cfg, switches=EvalSwitches(proposer_template=template)
    )
    deployed = evaluate_alert(
        db, alert_id, adapter=_FakeLLM(responses=[_TRUE_POSITIVE, VERIFIER_V2_AGREE]), cfg=cfg
    )

    assert re.fullmatch(r"file:[0-9a-f]{12}", ev.prompt_version)
    assert ev.prompt_version == file_version == ev.gate_result["prompt_version"]
    assert deployed.prompt_version == prompt_version(TRIAGE_TEMPLATE)
    assert not deployed.prompt_version.startswith("file:")
    # the override is the system prompt that was sent, template first, schema after -
    # the same composition as the deployed one, only the template differs
    system = ev.built.prompt.system
    assert llm.calls[0]["system"] == system != deployed.built.prompt.system
    assert system.startswith(template.read_text("utf-8"))
    assert system.removeprefix(template.read_text("utf-8")) == (
        deployed.built.prompt.system.removeprefix(deployed_text)
    )
    assert "## Schema triage_v3" in system
    assert "## Schema verifier_v2" in llm.calls[1]["system"]  # the verifier keeps its own
    # and the user message is untouched (up to the per-build nonce)
    assert ev.built.prompt.user.replace(ev.built.prompt.nonce, "N") == (
        deployed.built.prompt.user.replace(deployed.built.prompt.nonce, "N")
    )


# ---------------------------------------------------------------------------
# Failures become outcomes
# ---------------------------------------------------------------------------

_FAILURES = {
    "cap": (_AlwaysOverBudget, LLMBudgetExceeded, 0),
    "transient": (lambda: _FakeLLM(raises=TransientError("stalled")), TransientError, 0),
    "verifier_cap": (
        lambda: _FailAfterFirstCall(responses=[_TRUE_POSITIVE], raises=LLMBudgetExceeded("cap")),
        LLMBudgetExceeded,
        1,
    ),
    "verifier_transient": (
        lambda: _FailAfterFirstCall(responses=[_TRUE_POSITIVE], raises=TransientError("stalled")),
        TransientError,
        1,
    ),
}


@pytest.mark.db
@pytest.mark.parametrize("outcome", list(_FAILURES))
def test_budget_and_transient_become_outcomes_not_raises(db, cfg, outcome):
    make_adapter, exc_type, calls = _FAILURES[outcome]
    alert_id = _seed(db)

    ev = evaluate_alert(db, alert_id, adapter=make_adapter(), cfg=cfg)  # does not raise

    assert ev.outcome == outcome
    assert isinstance(ev.exception, exc_type)
    assert ev.calls == calls
    assert ev.final_verdict is None and ev.gate_result is None
    if calls:  # the proposal came back; only the verifier call failed
        assert ev.proposed_verdict == "true_positive" and ev.vbuilt is not None
        assert ev.usage == ev.proposal.usage
    else:
        assert ev.proposal is None and ev.usage == {} and ev.cost_usd == 0.0


# ---------------------------------------------------------------------------
# The deployed job is evaluate_alert(DEPLOYED) followed by its writes
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_run_triage_job_is_evaluate_alert_with_the_deployed_switches(db, cfg, monkeypatch):
    alert_id = _seed(db)
    seen: list = []
    real = triage_module.evaluate_alert

    def spy(conn, subject_id, **kwargs):
        ev = real(conn, subject_id, **kwargs)
        seen.append((subject_id, kwargs["switches"], ev))
        return ev

    monkeypatch.setattr(triage_module, "evaluate_alert", spy)
    run_triage_job(
        db,
        _job(alert_id),
        adapter=_FakeLLM(responses=[_POLICY_BLOCKED_FP, _VERIFIER_AGREES_FALSE_POSITIVE]),
    )

    assert [(s, w) for s, w, _ in seen] == [(alert_id, DEPLOYED)]
    assert seen[0][1] is DEPLOYED
    ev = seen[0][2]
    stored = db.execute(
        "SELECT system_prompt, user_message, result, gate_result, prompt_version "
        "FROM llm_runs WHERE subject_id = %s AND role = 'proposer'",
        (alert_id,),
    ).fetchone()
    assert stored == (
        ev.built.prompt.system,
        ev.built.prompt.user,
        ev.result,
        ev.gate_result,
        ev.prompt_version,
    )


@pytest.mark.db
def test_what_is_measured_is_what_is_deployed(db, cfg):
    """An evaluation run first, then the job on the same alert with the same answers:
    the gate document the job writes is the one the evaluation measured."""
    alert_id = _seed(db)
    answers = [_POLICY_BLOCKED_FP, _VERIFIER_AGREES_FALSE_POSITIVE]

    measured = evaluate_alert(db, alert_id, adapter=_FakeLLM(responses=answers), cfg=cfg)
    run_triage_job(db, _job(alert_id), adapter=_FakeLLM(responses=answers))

    gate_result, result = db.execute(
        "SELECT gate_result, result FROM llm_runs WHERE subject_id = %s AND role = 'proposer'",
        (alert_id,),
    ).fetchone()
    assert gate_result == measured.gate_result
    assert result == measured.result
    assert gate_result["flagged_by"] == ["step4"] and gate_result["forced_by"] == []
