"""Job ②: the single-shot investigation that writes the case's attack narrative and
evidence check (`llm_runs`) — never a status.

P5-T04 (DEC-151 wave 3). `run_investigate_job(conn, job, *, adapter=None)`;
`job.subject_id` is the `case_id`. **G7 is absolute here** (design note 3(b)): this
module writes `llm_runs` and `cases.last_analyzed_at` and nothing else — no
`UPDATE alerts` and no `UPDATE cases SET status` anywhere in this file.

**The idle timeout (Director item 1).** `infra/db.py`'s `transaction()` sets
`idle_in_transaction_session_timeout = '10s'` on the job's own transaction before this
handler is ever entered — a model call is client-side idle time to Postgres, so this
handler's first statement raises it to `JOB_LOCK_TIMEOUT_S` (300 s by default), exactly
`tier1/triage.py:157-169`'s `_raise_idle_timeout` (duplicated here, not imported: `tier1`
and `tier2` may not import each other, G1).

**The worst case, reported (Director item 1).** `LLMTimeout` (the `LLM_TIMEOUT_S`
wall-clock deadline, DEC-033) is never retried inside `llm.adapter.DeepSeekAdapter.
complete()` — "a timeout is not retried inside the adapter" is that module's own design
note 3 — so a genuine timeout bounds ONE logical send at `LLM_TIMEOUT_S` (120 s
default), not `LLM_TIMEOUT_S × (1 + LLM_RETRY)`; the retry loop there is for *other*
(non-timeout) transient errors, which fail fast in practice. This handler makes at most
two logical sends (`llm.investigate.investigate()`'s "one repair and no more"), so the
worst case attributable to LLM calls is `2 × LLM_TIMEOUT_S = 240 s` at defaults — a 60 s
/ 20 % margin under `JOB_LOCK_TIMEOUT_S = 300 s`. (The adapter's own internal retry loop
for non-timeout errors could in theory push a single send past 120 s across up to
`1 + LLM_RETRY` attempts; that ceiling is identical to ①'s existing, already-accepted
`run_triage_job` — this card introduces no new exposure there.) Measured (P5-T02,
`docs/investigate-size-class.md`): real p95 latency at the 60 k-token synthetic class is
14.65 s and at the 12.8 k real-corpus ceiling is 14.68 s — the practical number is under
30 s even with a repair, far inside the 240 s theoretical bound and the 300 s job lock.

**The isolation level (Director item 4).** `dossier.build()` is attempted under
`REPEATABLE READ READ ONLY` — see `_try_repeatable_read_only()` below and the report for
whether the worker's transaction shape allows it.
"""

from __future__ import annotations

import uuid
from functools import partial
from typing import Any

import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb

from app.audit.llm_runs import month_spend_usd
from app.infra import config
from app.infra.errors import PermanentError
from app.infra.jobs import Job
from app.llm import investigate as llm_investigate
from app.llm.adapter import (
    DeepSeekAdapter,
    LLMBudgetExceeded,
    LLMPermanent,
    LLMTimeout,
    cost_usd,
)
from app.llm.triage import prompt_version
from app.security import detector, wrap
from app.tier2 import dossier as dossier_mod

#: uuid5(NAMESPACE_URL, "https://ai-support-soc/llm_runs/investigate") — a fixed
#: constant, never recomputed (design note 5). `llm_runs` is append-only (migration
#: 017 REVOKEs UPDATE/DELETE from app_rw and a trigger enforces it) and `jobs` has no
#: payload column, so the route cannot hand the job a pre-generated id and cannot
#: insert a placeholder row for the job to fill. `run_id_for_job(job_id)` is
#: deterministic and collision-free per job instead: the route computes the same id
#: it returns in the 202 (`enqueue()`'s return value is the job_id), and the job
#: computes the same id again when it writes the row — no migration, and the
#: single-flight index on (job_type, subject_id) keeps doing its job.
RUN_NAMESPACE = uuid.UUID("9c411a22-9778-5fc9-8403-1b7ec9e85b9f")


def run_id_for_job(job_id: int) -> uuid.UUID:
    return uuid.uuid5(RUN_NAMESPACE, f"investigate:{job_id}")


def _raise_idle_timeout(conn: psycopg.Connection, cfg: config.Config) -> None:
    """The handler's first statement — `tier1/triage.py:157-169`'s `_raise_idle_timeout`,
    duplicated rather than imported (`tier1` and `tier2` may not import each other, G1;
    both are siblings under the tier layer)."""
    conn.execute(
        sql.SQL("SET LOCAL idle_in_transaction_session_timeout = {}").format(
            sql.Literal(f"{cfg.JOB_LOCK_TIMEOUT_S}s")
        )
    )


def _try_repeatable_read_only(conn: psycopg.Connection) -> bool:
    """Best-effort `REPEATABLE READ READ ONLY` for the dossier read (design note 4).
    Postgres requires `SET TRANSACTION ISOLATION LEVEL` to precede any statement that
    reads or writes a table in the current transaction; the two `SET LOCAL` statements
    that already ran (this module's own idle-timeout raise, and `infra/db.py::
    transaction()`'s statement-timeout/idle-timeout pair before that) set session
    parameters, not table access, so they do not count against that rule — verified in
    `test_investigate.py`. Wrapped in a savepoint so a Postgres version or transaction
    shape that *does* reject it aborts only this one statement, never the idle-timeout
    raise already committed to this transaction; the card permits reporting "does not
    allow it" over restructuring the worker, so a failure here is swallowed, not
    raised."""
    conn.execute("SAVEPOINT p5t04_isolation")
    try:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
    except psycopg.Error:
        conn.execute("ROLLBACK TO SAVEPOINT p5t04_isolation")
        return False
    else:
        conn.execute("RELEASE SAVEPOINT p5t04_isolation")
        return True


# ---------------------------------------------------------------------------
# The llm_runs row — this module's own INSERT (design note 3(c)). Not
# `app.audit.llm_runs.write_run`: that helper hard-codes pipeline='triage',
# subject_type='alert' and `role in {proposer, verifier}` (①'s own contract);
# ②'s row needs pipeline='investigate', subject_type='case', role='investigator',
# plus `evidence_check` and `agent_trace`, which `write_run` always sends as NULL.
# ---------------------------------------------------------------------------

_LLM_RUNS_COLUMNS = (
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

_LLM_RUNS_INSERT_SQL = (
    f"INSERT INTO llm_runs ({', '.join(_LLM_RUNS_COLUMNS)}) "
    f"VALUES ({', '.join(['%s'] * len(_LLM_RUNS_COLUMNS))})"
)


def _write_llm_run(
    conn: psycopg.Connection,
    *,
    run_id: uuid.UUID,
    case_id: str,
    system_prompt: str,
    user_message: str,
    agent_trace: dict[str, Any] | None,
    result: dict[str, Any] | None,
    evidence_check: dict[str, Any] | None,
    citation_warnings: list[str] | None,
    injection_findings: list[dict[str, Any]] | None,
    input_tokens: int | None,
    output_tokens: int | None,
    latency_ms: int | None,
    model_id: str | None,
    cost_usd_value: float | None,
    stopped_by: str | None,
) -> None:
    conn.execute(
        _LLM_RUNS_INSERT_SQL,
        (
            run_id,
            "investigate",
            "case",
            case_id,
            "investigator",
            system_prompt,
            user_message,
            Jsonb(agent_trace) if agent_trace is not None else None,
            Jsonb(result) if result is not None else None,
            None,  # gate_result — ①'s concept, not ②'s
            None,  # verifier_result — ①'s concept, not ②'s
            Jsonb(evidence_check) if evidence_check is not None else None,
            Jsonb(injection_findings) if injection_findings is not None else None,
            Jsonb(citation_warnings) if citation_warnings is not None else None,
            input_tokens,
            output_tokens,
            latency_ms,
            model_id,
            prompt_version(llm_investigate.TEMPLATE_PATH),
            cost_usd_value,
            stopped_by,
        ),
    )


def _snapshot_trace(dossier: llm_investigate.DossierLike) -> dict[str, Any]:
    """The P7-2 snapshot plus `Dossier.truncations`/`estimated_tokens`, together in
    `agent_trace` (this card's choice — see the report; `result` stays the pure
    validated `investigate_v2` object, or `None`, never an envelope around it, so a
    reader does not have to know this module's storage convention to read a `result`
    that validates)."""
    snapshot = dossier.snapshot
    return {
        "alert_count": snapshot.alert_count,
        "total_occurrences": snapshot.total_occurrences,
        "last_seen_at": snapshot.last_seen_at.isoformat() if snapshot.last_seen_at else None,
        "truncations": [dict(t) for t in dossier.truncations],
        "estimated_tokens": dossier.estimated_tokens,
    }


# ---------------------------------------------------------------------------
# The evidence check — design note 4.
# ---------------------------------------------------------------------------

_EVIDENCE_ALERTS_SQL = """
    SELECT alert_id, raw_log, description FROM alerts
    WHERE alert_id IN (SELECT alert_id FROM case_alerts WHERE case_id = %s)
       OR duplicate_of IN (SELECT alert_id FROM case_alerts WHERE case_id = %s)
"""


def _check_evidence(conn: psycopg.Connection, case_id: str, parsed: dict[str, Any]) -> dict[str, Any]:
    """Per `evidence[i]`: `alert_id` must be a case head or a duplicate of one (DEC-036's
    query shape) *and* `quote` must be a substring of that alert's `raw_log` or
    `description` after `security.wrap.normalise` (NFKC) on both sides."""
    rows = conn.execute(_EVIDENCE_ALERTS_SQL, (case_id, case_id)).fetchall()
    texts = {alert_id: (raw_log or "", description or "") for alert_id, raw_log, description in rows}

    verified: list[int] = []
    rejected: list[dict[str, Any]] = []
    for index, item in enumerate(parsed.get("evidence") or []):
        alert_id = item.get("alert_id")
        quote = item.get("quote") or ""
        if alert_id not in texts:
            rejected.append({"index": index, "alert_id": alert_id, "reason": "not_in_case"})
            continue
        normalised_quote = wrap.normalise(quote)
        raw_log, description = texts[alert_id]
        found = bool(normalised_quote) and (
            normalised_quote in wrap.normalise(raw_log)
            or normalised_quote in wrap.normalise(description)
        )
        if found:
            verified.append(index)
        else:
            rejected.append({"index": index, "alert_id": alert_id, "reason": "quote_not_found"})
    return {"verified": verified, "rejected": rejected}


def _scan_for_injection(dossier: llm_investigate.DossierLike) -> list[detector.Finding]:
    """`app.security.detector` over the dossier (design note 4). `detector.scan()` is
    documented to run over per-block `.plain` content, never the assembled prompt
    (`security/detector.py`'s own module docstring) — but `Dossier`'s public API
    (`.text`, `.nonce`, `.snapshot`, `.truncations`, `.estimated_tokens`; P5-T03's file,
    not touched by this card) exposes no block index, so this scans `dossier.text` as
    one synthetic block. Recorded as a deviation in the report: the practical risk is
    bounded (the detector's 20+3+5 patterns target injection shapes — base64 runs,
    imperative-command density, hidden characters, delimiter look-alikes — that the
    dossier's own short, structural Vietnamese headings do not resemble), and the
    direction of any false positive is the conservative one (forcing `need_more_data`
    on a clean case, never the reverse)."""
    synthetic = wrap.Block(
        source="context",
        attrs={},
        plain=dossier.text,
        escaped=dossier.text,
        truncated=False,
        dropped_bytes=0,
        rendered=dossier.text,
    )
    return detector.scan([synthetic])


def run_investigate_job(conn: psycopg.Connection, job: Job, *, adapter: Any | None = None) -> None:
    """Run pipeline ② for one case. `adapter` defaults to a real `DeepSeekAdapter`;
    every test passes a fake instead (design note 8)."""
    cfg = config.load()
    _raise_idle_timeout(conn, cfg)
    _try_repeatable_read_only(conn)

    case_id = job.subject_id

    if not cfg.llm_enabled:
        # G7: the case is untouched, no status moves, and no attempt was made — not
        # even a dossier read, so this never opens a connection to a case that might
        # since have been concluded.
        return

    nonce = wrap.new_nonce()  # design note 3(a): a new nonce per attempt, never cached

    try:
        dossier = dossier_mod.build(conn, case_id, nonce=nonce, cfg=cfg)
    except dossier_mod.UnknownCase as exc:
        raise PermanentError(str(exc)) from exc

    system, user = llm_investigate.build(dossier, nonce=nonce, cfg=cfg)
    run_id = run_id_for_job(job.job_id)
    agent_trace = _snapshot_trace(dossier)

    llm_adapter = adapter or DeepSeekAdapter(cfg, spent_usd=partial(month_spend_usd, conn))

    try:
        result = llm_investigate.investigate(
            llm_adapter,
            dossier,
            nonce=nonce,
            cfg=cfg,
            extra_constants=dossier_mod.DOSSIER_TEMPLATE_CONSTANTS,
        )
    except LLMTimeout:
        # Transient (design note 3(d)): the row must survive the reschedule, and the
        # worker's `transaction()` rolls back the whole handler transaction on any
        # exception it lets through — so this commits explicitly before re-raising,
        # the same "commit before the caller sees the failure" shape `deps.require_role`
        # uses for its own 403 (P4 planning decision 3), applied to a job instead of a
        # route.
        _write_llm_run(
            conn,
            run_id=run_id,
            case_id=case_id,
            system_prompt=system,
            user_message=user,
            agent_trace=agent_trace,
            result=None,
            evidence_check=None,
            citation_warnings=None,
            injection_findings=None,
            input_tokens=None,
            output_tokens=None,
            latency_ms=None,
            model_id=None,
            cost_usd_value=None,
            stopped_by="transient",
        )
        conn.commit()
        raise
    except LLMBudgetExceeded:
        _write_llm_run(
            conn,
            run_id=run_id,
            case_id=case_id,
            system_prompt=system,
            user_message=user,
            agent_trace=agent_trace,
            result=None,
            evidence_check=None,
            citation_warnings=None,
            injection_findings=None,
            input_tokens=None,
            output_tokens=None,
            latency_ms=None,
            model_id=None,
            cost_usd_value=None,
            stopped_by="cap",
        )
        return  # permanent by nature (the cap will not clear itself) — no retry warranted
    except LLMPermanent:
        _write_llm_run(
            conn,
            run_id=run_id,
            case_id=case_id,
            system_prompt=system,
            user_message=user,
            agent_trace=agent_trace,
            result=None,
            evidence_check=None,
            citation_warnings=None,
            injection_findings=None,
            input_tokens=None,
            output_tokens=None,
            latency_ms=None,
            model_id=None,
            cost_usd_value=None,
            stopped_by="permanent",
        )
        return
    except PermanentError:
        # The pre-send linter guard (G6′, `llm.investigate._lint_or_raise`) — a
        # template defect, not a model outcome. Caught after the two LLM-specific
        # PermanentError subclasses above so their own `stopped_by` values are not
        # shadowed by this catch-all.
        _write_llm_run(
            conn,
            run_id=run_id,
            case_id=case_id,
            system_prompt=system,
            user_message=user,
            agent_trace=agent_trace,
            result=None,
            evidence_check=None,
            citation_warnings=None,
            injection_findings=None,
            input_tokens=None,
            output_tokens=None,
            latency_ms=None,
            model_id=None,
            cost_usd_value=None,
            stopped_by="linter",
        )
        return

    usage_input = result.usage.get("prompt_tokens")
    usage_output = result.usage.get("completion_tokens")
    usage_cost = cost_usd(result.usage, cfg)

    if result.parsed is None:
        # Schema-invalid after the one repair (design note 2: "a second failure sets
        # stopped_by='schema' and result stays NULL") — mirrors ①'s own "schema"
        # outcome (`tier1/triage.py`'s `run_triage_job`): write the row with the real
        # usage/cost the calls actually spent, and complete normally — a response was
        # received and recorded, so no retry would change anything.
        _write_llm_run(
            conn,
            run_id=run_id,
            case_id=case_id,
            system_prompt=system,
            user_message=user,
            agent_trace=agent_trace,
            result=None,
            evidence_check=None,
            citation_warnings=None,
            injection_findings=None,
            input_tokens=usage_input,
            output_tokens=usage_output,
            latency_ms=result.latency_ms,
            model_id=result.model,
            cost_usd_value=usage_cost,
            stopped_by="schema",
        )
        return

    evidence_check = _check_evidence(conn, case_id, result.parsed)
    findings = _scan_for_injection(dossier)
    injection_level = detector.level(findings)

    final_result = dict(result.parsed)
    original_conclusion = final_result["suggested_conclusion"]
    overridden = False

    if not evidence_check["verified"]:
        # Zero verified evidence -> need_more_data; the model's answer is overruled,
        # not deleted (design note 4).
        final_result["suggested_conclusion"] = "need_more_data"
        overridden = True

    if injection_level == "high" and final_result["suggested_conclusion"] == "false_positive":
        final_result["suggested_conclusion"] = "need_more_data"
        evidence_check["forced_by"] = "high_severity_injection_finding"
        overridden = True

    if overridden:
        evidence_check["original_conclusion"] = original_conclusion

    citation_warnings = [
        f"alert_id {item['alert_id']!r} rejected: {item['reason']}"
        for item in evidence_check["rejected"]
    ]

    _write_llm_run(
        conn,
        run_id=run_id,
        case_id=case_id,
        system_prompt=system,
        user_message=user,
        agent_trace=agent_trace,
        result=final_result,
        evidence_check=evidence_check,
        citation_warnings=citation_warnings or None,
        injection_findings=detector.as_json(findings),
        input_tokens=usage_input,
        output_tokens=usage_output,
        latency_ms=result.latency_ms,
        model_id=result.model,
        cost_usd_value=usage_cost,
        stopped_by=None,
    )
    conn.execute("UPDATE cases SET last_analyzed_at = now() WHERE case_id = %s", (case_id,))
