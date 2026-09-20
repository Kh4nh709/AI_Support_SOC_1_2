"""Job (1): typed prompt, proposer and verifier through the gate; sets triage_status.

The orchestration is this module's (context pack §7.3, §7.5): build -> detector ->
linter -> proposer -> gate steps 1-5 -> verifier prompt -> verify -> gate step 6 ->
gate step 7 -> two `llm_runs` rows -> `triage_status`/`triaged_count` -> audit. Every
call is made from this job, never from a request handler (§7.5); the whole handler
runs inside the worker's one transaction (`infra/worker.py`'s `transaction(conn,
statement_timeout=...)`), so a retry never sees a partial write.

`_set_triage_status` is this module's only write to `alerts` — it names
`triage_status` and `triaged_count` and nothing else (G2). `domain/`, not `tier1/`,
is the only package that may ever write `alerts.status`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from functools import partial
from typing import Any
from uuid import uuid4

import psycopg
from psycopg import sql

from app.audit import llm_runs
from app.audit.events import write_event
from app.domain import correlation
from app.infra import config
from app.infra.errors import PermanentError, TransientError
from app.infra.jobs import Job
from app.kb import lookup as kb
from app.llm import builder
from app.llm.adapter import DeepSeekAdapter, LLMBudgetExceeded, cost_usd
from app.llm.triage import (
    TRIAGE_TEMPLATE,
    VERIFIER_TEMPLATE,
    BuiltTriagePrompt,
    Proposal,
    TriageInput,
    build_facts,
    build_proposer_prompt,
    build_verifier_prompt,
    prompt_version,
    propose,
    verify,
)
from app.security import detector, gate, linter

#: The four terminal alert statuses phase-5 says a triage job must never overwrite
#: (`duplicate` never reaches `queued_tier1` either, but a stray job for one must
#: still be skipped, not error). `auto_closed` is deliberately absent: phase-5's M2
#: sample runs the identical path on it (design note 8 / acceptance 11).
_CLOSED_STATUSES = frozenset({"closed_fp", "closed_benign", "closed_confirmed", "duplicate"})

#: G10 — the explicit 26-column select `_load` runs; never a wildcard select.
_ALERT_COLUMNS = (
    "alert_id",
    "status",
    "triage_status",
    "rule_id",
    "rule_level",
    "alert_time",
    "severity",
    "category",
    "categories",
    "occurrence_count",
    "risk_score",
    "description",
    "raw_log",
    "raw_log_truncated",
    "agent_name",
    "origin_host",
    "agent_id",
    "alert_user",
    "srcip",
    "mitre_ids",
    "asset_context",
    "identity_context",
    "ioc_context",
    "lookup_status",
    "first_seen_at",
    "last_seen_at",
)
_SELECT_ALERT_SQL = f"SELECT {', '.join(_ALERT_COLUMNS)} FROM alerts WHERE alert_id = %s"

_DEFAULT_ASSET_CONTEXT = {"criticality": "unknown"}
_DEFAULT_LOOKUP_STATUS = {"asset": "skipped", "identity": "skipped", "ioc": "skipped"}


@dataclass(frozen=True)
class _Subject:
    """Just enough of an alert for `correlation.summarize_for_prompt`'s window
    predicate (`agent_name`/`alert_user`/`srcip`/`alert_time`) — mirrors
    `app.domain.transitions._CorrelationSubject`; not imported, that name is
    private to `domain/` (design note 6)."""

    alert_id: str
    agent_name: str
    alert_user: str | None
    srcip: str
    alert_time: datetime


@dataclass(frozen=True)
class _AlertRow:
    alert_id: str
    status: str
    triage_status: str
    rule_id: str
    rule_level: int
    alert_time: datetime
    severity: str
    category: str
    categories: tuple[str, ...]
    occurrence_count: int
    risk_score: int | None
    description: str
    raw_log: str
    raw_log_truncated: bool
    agent_name: str
    origin_host: str | None
    agent_id: str | None
    alert_user: str | None
    srcip: str
    mitre_ids: tuple[str, ...]
    asset_context: dict[str, Any]
    identity_context: dict[str, Any]
    ioc_context: dict[str, Any]
    lookup_status: dict[str, Any]
    first_seen_at: datetime
    last_seen_at: datetime


def _log(payload: dict[str, Any]) -> None:
    print(json.dumps(payload))


def _raise_idle_timeout(conn: psycopg.Connection, cfg: config.Config) -> None:
    """The handler's first statement (design note 3). `infra/db.py`'s `transaction()`
    sets `idle_in_transaction_session_timeout = '10s'`; a model call is client-side
    idle time to Postgres, so a second `SET LOCAL` in this same transaction — to
    `JOB_LOCK_TIMEOUT_S` (300 s by default), the same bound `reclaim_stale` uses —
    overrides it and lets two model calls finish without the session being killed.
    `SET` takes no bind parameter, hence `sql.Literal`, not `%s` (`infra/db.py`
    does the same)."""
    conn.execute(
        sql.SQL("SET LOCAL idle_in_transaction_session_timeout = {}").format(
            sql.Literal(f"{cfg.JOB_LOCK_TIMEOUT_S}s")
        )
    )


def _load(conn: psycopg.Connection, alert_id: str) -> _AlertRow | None:
    """The 26-column row job (1) needs, or `None` if the alert does not exist.

    A `received` alert can never have a `triage` job (it has not reached
    `queued_tier1` yet), so the four `*_context`/`lookup_status` columns are never
    actually `NULL` in practice — defended anyway (design note 6): `NULL` reads as
    "never enriched", not as an error.
    """
    row = conn.execute(_SELECT_ALERT_SQL, (alert_id,)).fetchone()
    if row is None:
        return None
    values = dict(zip(_ALERT_COLUMNS, row, strict=True))
    if values["asset_context"] is None:
        _log(
            {"triage": "defensive_default_context", "alert_id": alert_id, "column": "asset_context"}
        )
        values["asset_context"] = dict(_DEFAULT_ASSET_CONTEXT)
    if values["identity_context"] is None:
        values["identity_context"] = {}
    if values["ioc_context"] is None:
        values["ioc_context"] = {}
    if values["lookup_status"] is None:
        _log(
            {"triage": "defensive_default_context", "alert_id": alert_id, "column": "lookup_status"}
        )
        values["lookup_status"] = dict(_DEFAULT_LOOKUP_STATUS)
    values["categories"] = tuple(values["categories"] or ())
    values["mitre_ids"] = tuple(values["mitre_ids"] or ())
    return _AlertRow(**values)


def _set_triage_status(conn: psycopg.Connection, alert_id: str, status: str) -> None:
    """This module's only write to `alerts` (G2, acceptance 6's grep) — names
    `triage_status` and `triaged_count` and nothing else."""
    conn.execute(
        "UPDATE alerts SET triage_status=%s, triaged_count = triaged_count + 1 "
        "WHERE alert_id = %s",
        (status, alert_id),
    )


def _make_rule_check(table: Any, facts: dict[str, Any]):
    """The callable gate step 4 gets (design note 5). Six reasons, in order:
    `no_rule_cited` (no rule was cited), `no_table` (the category has no table),
    `table_unreviewed`, `unknown_rule` (the cited id is not in the table),
    `rule_does_not_hold`, `rule_is_not_false_positive` (it holds but its own
    action is not `false_positive`); else `(True, None)`."""

    def _check(rule_id: str | None) -> tuple[bool, str | None]:
        if rule_id is None:
            return False, "no_rule_cited"
        if table is None:
            return False, "no_table"
        if not table.reviewed:
            return False, "table_unreviewed"
        holds = kb.rule_holds(table, rule_id, facts)
        if holds is None:
            return False, "unknown_rule"
        if not holds:
            return False, "rule_does_not_hold"
        rule = next(r for r in table.rules if r.id == rule_id)
        if rule.action != "false_positive":
            return False, "rule_is_not_false_positive"
        return True, None

    return _check


def _last_attempt_or_raise(
    conn: psycopg.Connection,
    job: Job,
    cfg: config.Config,
    exc: Exception,
    built: BuiltTriagePrompt,
    facts: dict[str, Any],
) -> None:
    """Planning decision 3: the last attempt owns the outcome. Below
    `JOB_MAX_ATTEMPTS`, raise — the worker's transaction rolls back and the retry
    repeats both calls, nothing half-written. On the last attempt, write the
    outcome and stop; the job itself still records `succeeded` (its contract —
    record an outcome — was met)."""
    if job.attempts < cfg.JOB_MAX_ATTEMPTS:
        raise TransientError(str(exc))
    alert_id = job.subject_id
    llm_runs.write_run(
        conn,
        run_id=uuid4(),
        role="proposer",
        subject_id=alert_id,
        system_prompt=built.prompt.system,
        user_message=built.prompt.user,
        result=None,
        gate_result={
            "error": "transient",
            "message": str(exc)[:200],
            "attempts": job.attempts,
            "facts": facts,
        },
        verifier_result=None,
        injection_findings=None,
        citation_warnings=built.warnings,
        input_tokens=None,
        output_tokens=None,
        latency_ms=None,
        model_id=None,
        prompt_version=prompt_version(TRIAGE_TEMPLATE),
        cost_usd=None,
        stopped_by="transient",
    )
    _set_triage_status(conn, alert_id, "unavailable")
    write_event(
        conn,
        "job.exhausted",
        alert_id,
        "system",
        payload={"reason": "llm_transient", "attempts": job.attempts},
    )


def _verify_failed_last_attempt(
    conn: psycopg.Connection,
    built: BuiltTriagePrompt,
    vbuilt: BuiltTriagePrompt,
    facts: dict[str, Any],
    proposal: Proposal,
    alert_id: str,
    cfg: config.Config,
    exc: Exception,
    *,
    stopped_by: str,
) -> None:
    """The verifier call failed (`cap` or a `transient` exhaustion — the caller has
    already decided a retry is not coming). Design note 2: unlike a proposer-side
    failure, the proposer call itself succeeded, so both rows are written "with
    what exists" — the proposer's real prompt and usage, the verifier's prompt
    with no response."""
    pv = prompt_version(TRIAGE_TEMPLATE)
    proposer_id = llm_runs.write_run(
        conn,
        run_id=uuid4(),
        role="proposer",
        subject_id=alert_id,
        system_prompt=built.prompt.system,
        user_message=built.prompt.user,
        result=None,
        gate_result={"error": stopped_by, "message": str(exc)[:200], "facts": facts},
        verifier_result=None,
        injection_findings=None,
        citation_warnings=built.warnings,
        input_tokens=proposal.usage.get("prompt_tokens"),
        output_tokens=proposal.usage.get("completion_tokens"),
        latency_ms=proposal.latency_ms,
        model_id=proposal.model,
        prompt_version=pv,
        cost_usd=cost_usd(proposal.usage, cfg),
        stopped_by=stopped_by,
    )
    llm_runs.write_run(
        conn,
        run_id=uuid4(),
        role="verifier",
        subject_id=alert_id,
        system_prompt=vbuilt.prompt.system,
        user_message=vbuilt.prompt.user,
        result=None,
        gate_result={
            "role": "verifier",
            "error": stopped_by,
            "proposer_run_id": str(proposer_id),
        },
        verifier_result=None,
        injection_findings=None,
        citation_warnings=vbuilt.warnings,
        input_tokens=None,
        output_tokens=None,
        latency_ms=None,
        model_id=None,
        prompt_version=prompt_version(VERIFIER_TEMPLATE),
        cost_usd=None,
        stopped_by=stopped_by,
    )
    _set_triage_status(conn, alert_id, "unavailable")


def run_triage_job(conn: psycopg.Connection, job: Job, *, adapter: Any | None = None) -> None:
    """Run pipeline (1) for one alert and record everything (context pack §5, §7.3).

    `adapter` defaults to a real `DeepSeekAdapter`; every test passes a fake instead
    (design note 7) — production and P3-T11 are the only callers that leave it
    `None`.
    """
    cfg = config.load()
    _raise_idle_timeout(conn, cfg)

    alert_id = job.subject_id
    row = _load(conn, alert_id)
    if row is None:
        raise PermanentError(f"alert not found: {alert_id}")

    if row.status in _CLOSED_STATUSES:
        _log({"triage": "skipped", "alert_id": alert_id, "status": row.status})
        return

    if not cfg.llm_enabled:
        _set_triage_status(conn, alert_id, "unavailable")
        _log({"triage": "unavailable", "alert_id": alert_id, "stopped_by": "disabled"})
        return

    subject = _Subject(
        alert_id=row.alert_id,
        agent_name=row.agent_name,
        alert_user=row.alert_user,
        srcip=row.srcip,
        alert_time=row.alert_time,
    )
    corr = correlation.summarize_for_prompt(conn, subject)

    playbook_text = kb.get_playbook(row.category)
    table = kb.get_decision_table(row.category)

    inp = TriageInput(
        alert_id=row.alert_id,
        rule_id=row.rule_id,
        rule_level=row.rule_level,
        alert_time=row.alert_time,
        severity=row.severity,
        category=row.category,
        categories=row.categories,
        occurrence_count=row.occurrence_count,
        risk_score=row.risk_score,
        description=row.description,
        raw_log=row.raw_log,
        raw_log_truncated=row.raw_log_truncated,
        agent_name=row.agent_name,
        origin_host=row.origin_host or "",
        agent_id=row.agent_id,
        alert_user=row.alert_user,
        mitre_ids=row.mitre_ids,
        asset_context=row.asset_context,
        identity_context=row.identity_context,
        ioc_context=row.ioc_context,
        lookup_status=row.lookup_status,
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
    )
    facts = build_facts(inp, corr)
    built = build_proposer_prompt(inp, facts, corr, playbook_text, table, cfg=cfg)

    findings = detector.scan(built.prompt.block_index.values())
    violations = linter.lint(
        built.prompt.user,
        nonce=built.prompt.nonce,
        constants=builder.TEMPLATE_CONSTANTS,
        enums=builder.ENUM_VALUES,
    )
    if violations:
        llm_runs.write_run(
            conn,
            run_id=uuid4(),
            role="proposer",
            subject_id=alert_id,
            system_prompt=built.prompt.system,
            user_message=built.prompt.user,
            result=None,
            gate_result={
                "error": "builder_violation",
                "violations": [f"{v.kind}:{(v.token or '')[:200]}" for v in violations],
            },
            verifier_result=None,
            injection_findings=detector.as_json(findings),
            citation_warnings=built.warnings,
            input_tokens=None,
            output_tokens=None,
            latency_ms=None,
            model_id=None,
            prompt_version=prompt_version(TRIAGE_TEMPLATE),
            cost_usd=None,
            stopped_by="linter",
        )
        write_event(
            conn,
            "llm.builder_violation",
            alert_id,
            "system",
            payload={"violations_count": len(violations)},
        )
        _set_triage_status(conn, alert_id, "unavailable")
        return

    llm_adapter = adapter or DeepSeekAdapter(cfg, spent_usd=partial(llm_runs.month_spend_usd, conn))

    try:
        proposal = propose(llm_adapter, built, cfg=cfg)
    except LLMBudgetExceeded:
        llm_runs.write_run(
            conn,
            run_id=uuid4(),
            role="proposer",
            subject_id=alert_id,
            system_prompt=built.prompt.system,
            user_message=built.prompt.user,
            result=None,
            gate_result={"error": "cap", "facts": facts},
            verifier_result=None,
            injection_findings=detector.as_json(findings),
            citation_warnings=built.warnings,
            input_tokens=None,
            output_tokens=None,
            latency_ms=None,
            model_id=None,
            prompt_version=prompt_version(TRIAGE_TEMPLATE),
            cost_usd=None,
            stopped_by="cap",
        )
        _set_triage_status(conn, alert_id, "unavailable")
        return
    except TransientError as exc:
        _last_attempt_or_raise(conn, job, cfg, exc, built, facts)
        return

    if proposal.parsed is None:
        llm_runs.write_run(
            conn,
            run_id=uuid4(),
            role="proposer",
            subject_id=alert_id,
            system_prompt=built.prompt.system,
            user_message=built.prompt.user,
            result=None,
            gate_result={
                "error": "schema",
                "schema_errors": proposal.schema_errors,
                "facts": facts,
            },
            verifier_result=None,
            injection_findings=detector.as_json(findings),
            citation_warnings=built.warnings,
            input_tokens=proposal.usage.get("prompt_tokens"),
            output_tokens=proposal.usage.get("completion_tokens"),
            latency_ms=proposal.latency_ms,
            model_id=proposal.model,
            prompt_version=prompt_version(TRIAGE_TEMPLATE),
            cost_usd=cost_usd(proposal.usage, cfg),
            stopped_by="schema",
        )
        _set_triage_status(conn, alert_id, "unavailable")
        return

    rule_check = _make_rule_check(table, facts)
    state = gate.run_steps_1_to_5(
        proposal.parsed,
        facts,
        built.prompt.block_index,
        repaired=proposal.repaired,
        rule_check=rule_check,
        scan=lambda _: findings,
    )
    # step 6 may still change state.verdict; the verifier row must record what it
    # was actually asked to check, so this is captured before that happens.
    verdict_for_verifier = state.verdict
    vbuilt = build_verifier_prompt(facts, table, verdict_for_verifier, state.reasons, cfg=cfg)

    verifier_violations = linter.lint(
        vbuilt.prompt.user,
        nonce=vbuilt.prompt.nonce,
        constants=builder.TEMPLATE_CONSTANTS,
        enums=builder.ENUM_VALUES,
    )
    if verifier_violations:
        # A typed builder cannot produce this: a violation here is a template
        # defect, not a model outcome (design note 2) — it never reaches the model.
        raise PermanentError(f"verifier prompt failed the linter: {verifier_violations[0].kind}")

    try:
        verification = verify(llm_adapter, vbuilt, cfg=cfg)
    except LLMBudgetExceeded as exc:
        _verify_failed_last_attempt(
            conn, built, vbuilt, facts, proposal, alert_id, cfg, exc, stopped_by="cap"
        )
        return
    except TransientError as exc:
        if job.attempts < cfg.JOB_MAX_ATTEMPTS:
            raise
        _verify_failed_last_attempt(
            conn, built, vbuilt, facts, proposal, alert_id, cfg, exc, stopped_by="transient"
        )
        write_event(
            conn,
            "job.exhausted",
            alert_id,
            "system",
            payload={"reason": "llm_transient", "attempts": job.attempts},
        )
        return

    gate.step6_verifier(state, verification.parsed)
    result = gate.step7_output_guard(state)
    pv = prompt_version(TRIAGE_TEMPLATE)
    g = gate.gate_result(
        state, prompt_version=pv, playbook_used_effective=built.playbook_used_effective
    )

    proposer_id = llm_runs.write_run(
        conn,
        run_id=uuid4(),
        role="proposer",
        subject_id=alert_id,
        system_prompt=built.prompt.system,
        user_message=built.prompt.user,
        result=result,
        gate_result=g,
        verifier_result=verification.parsed,
        injection_findings=detector.as_json(findings),
        citation_warnings=built.warnings,
        input_tokens=proposal.usage.get("prompt_tokens"),
        output_tokens=proposal.usage.get("completion_tokens"),
        latency_ms=proposal.latency_ms,
        model_id=proposal.model,
        prompt_version=pv,
        cost_usd=cost_usd(proposal.usage, cfg),
        stopped_by=None,
    )
    llm_runs.write_run(
        conn,
        run_id=uuid4(),
        role="verifier",
        subject_id=alert_id,
        system_prompt=vbuilt.prompt.system,
        user_message=vbuilt.prompt.user,
        result=verification.parsed,
        gate_result={
            "role": "verifier",
            "step6": state.steps["6"],
            "compared_to": verdict_for_verifier,
            "proposer_run_id": str(proposer_id),
        },
        verifier_result=verification.parsed,
        injection_findings=None,
        citation_warnings=vbuilt.warnings,
        input_tokens=verification.usage.get("prompt_tokens"),
        output_tokens=verification.usage.get("completion_tokens"),
        latency_ms=verification.latency_ms,
        model_id=verification.model,
        prompt_version=prompt_version(VERIFIER_TEMPLATE),
        cost_usd=cost_usd(verification.usage, cfg),
        stopped_by=None if verification.parsed is not None else "schema",
    )

    _set_triage_status(conn, alert_id, "ready")
    write_event(
        conn,
        "triage.suggested",
        alert_id,
        "llm",
        payload={
            "suggested_action": result["suggested_action"],
            "confidence": result["confidence"],
            "forced": g["forced"],
            "run_id": str(proposer_id),
        },
    )
    if g["forced"]:
        write_event(
            conn,
            "llm.gate_forced",
            alert_id,
            "system",
            payload={
                "proposed": g["proposed_verdict"],
                "final": g["final_verdict"],
                "forced_by": g["forced_by"],
                "missing": g["missing"],
            },
        )
    return
