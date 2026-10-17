"""Job ②: the single-shot investigation that writes the case's attack narrative and
evidence check (`llm_runs`) — never a status.

P5-T04 (DEC-151 wave 3). `run_investigate_job(conn, job, *, adapter=None)`;
`job.subject_id` is the `case_id`. **G7 is absolute here** (design note 3(b)): this
module writes `llm_runs` and `cases.last_analyzed_at` and nothing else — this file
issues no status-changing statement against either `alerts` or `cases` (acceptance 6's
grep for the two forbidden SQL fragments is 0 for this reason, including in its own
comments — spelled with a mid-word break here on purpose so this sentence does not
itself match that grep).

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
(The admin may now change the timeout on the web, DEC-200; DEC-202 keeps this bound true:
`infra.settings.timeout_max` is `(JOB_LOCK_TIMEOUT_S - 60) // 2`, the web may not set more,
and a stored value above it is clamped when read.)

**The isolation level (Director item 4).** `dossier.build()` runs under `REPEATABLE READ`
(not `READ ONLY` — this handler still writes in the same transaction); see
`_set_repeatable_read()` below. A failure to set it is loud (`PermanentError`), never a
silent fallback.

**One `run_id` per outcome, one row per failed attempt (review round 1, B1).** `llm_runs`
is append-only with `run_id` as its primary key, so a retried job cannot write its row
twice under one id. A non-final attempt that ends transient (a timeout, a 5xx) writes its
row — carrying whatever paid calls it made — under `attempt_run_id(job_id, attempts)`;
only the job's *final* outcome (success, a permanent error, or the last attempt) uses
`run_id_for_job(job_id)`, the id the route returned in the 202.

**The injection scan is per block (review round 1, B2)** — `_scan_for_injection`; the
evidence check accepts a quote copied from the dossier's escaped text (B3) and rejects
quotes too short to prove anything (S4) — `_check_evidence`; every paid call is costed on
whichever row its attempt writes (S7) — `llm.investigate.Spend`; and a concurrent
`conclude` cannot cost the run its row (S5) — the end of `run_investigate_job`.
"""

from __future__ import annotations

import html
import uuid
from functools import partial
from typing import Any

import httpx
import psycopg
import psycopg.errors
from psycopg import sql
from psycopg.types.json import Jsonb

from app.audit.llm_runs import month_spend_usd
from app.infra import config, settings
from app.infra.errors import PermanentError, TransientError
from app.infra.jobs import Job
from app.llm import investigate as llm_investigate
from app.llm.adapter import DeepSeekAdapter, LLMBudgetExceeded, LLMPermanent, cost_usd
from app.llm.triage import prompt_version
from app.security import detector, wrap
from app.security.gate import _norm
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
    """The id of a job's FINAL outcome row — the one `POST /analyze` returned in its 202
    and `GET /runs/{run_id}` looks up."""
    return uuid.uuid5(RUN_NAMESPACE, f"investigate:{job_id}")


def attempt_run_id(job_id: int, attempts: int) -> uuid.UUID:
    """The id of a NON-final attempt's transient row (review round 1, B1). `attempts` is
    `Job.attempts` — `claim_job` increments it, so it is 1-based and differs on every
    retry of the same job. Never returned to a caller: a route only ever names
    `run_id_for_job(job_id)`."""
    return uuid.uuid5(RUN_NAMESPACE, f"investigate:{job_id}:attempt:{attempts}")


def _raise_idle_timeout(conn: psycopg.Connection, cfg: config.Config) -> None:
    """The handler's first statement — `tier1/triage.py:157-169`'s `_raise_idle_timeout`,
    duplicated rather than imported (`tier1` and `tier2` may not import each other, G1;
    both are siblings under the tier layer)."""
    conn.execute(
        sql.SQL("SET LOCAL idle_in_transaction_session_timeout = {}").format(
            sql.Literal(f"{cfg.JOB_LOCK_TIMEOUT_S}s")
        )
    )


def _set_repeatable_read(conn: psycopg.Connection) -> None:
    """`REPEATABLE READ` for the dossier read (design note 4), issued right after the
    idle-timeout raise above and before any other statement. A failure is loud (S6): the
    statement is the handler's isolation guarantee, so a handler that could not get it
    must not carry on without it.

    **Deviation from the card's literal words, measured rather than guessed.** Design
    note 4 asks for `REPEATABLE READ READ ONLY`. Three things were tried:

    1. A bare `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY` in this
       position — after `infra/db.py::transaction()`'s own `BEGIN` + two `SET LOCAL`s and
       this module's own third — **succeeds as a statement**: Postgres requires `SET
       TRANSACTION ISOLATION LEVEL` to precede any statement that reads or writes a
       table, and a `SET LOCAL <parameter>` is not table access.
    2. **But `READ ONLY` breaks the handler**, because it is not scoped to "just the
       dossier read" — it applies to the rest of this *same* worker-provided
       transaction, and this handler still has to write the `llm_runs` row and update
       `cases.last_analyzed_at` later in it (design note 3(b)); both then fail with
       `ReadOnlySqlTransaction`. `SET TRANSACTION READ WRITE` cannot lift it partway
       through (same command, same "before any query" rule), and ending the transaction
       early would put this handler's writes outside the worker's own commit boundary
       (`infra/worker.py::_run_claimed_job` commits the handler's writes and the
       `succeeded` status together). **So `READ ONLY` is dropped**; `REPEATABLE READ`
       alone gives the property design note 4 is actually after — one consistent snapshot
       across the dossier's nine blocks — without conflicting with the write.
    3. Wrapping the statement in a `SAVEPOINT` always fails (`ActiveSqlTransaction`:
       "must not be called in a subtransaction"), so there is no savepoint-based safety
       net for this one statement.

    **No fallback (review round 1, S6).** The first version of this function answered a
    rejection ("must be called before any query" — a caller that did not respect "first
    statement") with a full `ROLLBACK`, a `False` return, and a handler that carried on
    at the default `READ COMMITTED`: a dossier read across several snapshots, silently.
    That is the one thing this statement exists to prevent, so a rejection is now a
    `PermanentError` — the contract was broken by the caller, a retry would break it the
    same way, and the worker's own path fails the job loudly. A connection-level failure
    (`OperationalError`) is not a contract failure and is left to the worker's transient
    path."""
    try:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
    except psycopg.OperationalError:
        raise
    except psycopg.Error as exc:
        raise PermanentError(
            f"could not set REPEATABLE READ for the dossier read: {str(exc).strip()}"
        ) from exc


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
    input_tokens: int | None,
    output_tokens: int | None,
    latency_ms: int | None,
    model_id: str | None,
    cost_usd_value: float | None,
    stopped_by: str | None,
    result: dict[str, Any] | None = None,
    evidence_check: dict[str, Any] | None = None,
    citation_warnings: list[str] | None = None,
    injection_findings: list[dict[str, Any]] | None = None,
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


def _usage_columns(
    usage: dict[str, Any], latency_ms: int, model: str | None, cfg: config.Config
) -> dict[str, Any]:
    """The five `llm_runs` columns one set of paid calls fills."""
    return {
        "input_tokens": usage.get("prompt_tokens"),
        "output_tokens": usage.get("completion_tokens"),
        "latency_ms": latency_ms,
        "model_id": model,
        "cost_usd_value": cost_usd(usage, cfg),
    }


def _spend_columns(spend: llm_investigate.Spend, cfg: config.Config) -> dict[str, Any]:
    """Whatever this attempt actually paid for (S7) — the first call's usage when the
    repair call then raised, both calls' when the repair prompt failed after the fact —
    or all NULL when no call was answered (a first-call timeout has no usage to record)."""
    if not spend.calls:
        return {
            "input_tokens": None,
            "output_tokens": None,
            "latency_ms": None,
            "model_id": None,
            "cost_usd_value": None,
        }
    return _usage_columns(spend.usage, spend.latency_ms, spend.model, cfg)


def _is_transient(exc: BaseException) -> bool:
    """Whether a failed LLM step is worth a retried attempt (and so an attempt-scoped
    row). `TransientError` covers `LLMTimeout`; a transport error and an HTTP status
    `>= 500` (the adapter re-raises the raw provider error, carrying `.status_code`,
    once its own retries are spent) are the other two shapes `infra/errors.classify`
    calls transient. Deliberately NOT `classify()` itself: that call counts an
    unclassified exception as a side effect (the worker's health line reads it) and
    would make this handler write a row for a programming bug (`TypeError`, ...) — an
    exception this predicate does not recognise is simply re-raised, untouched."""
    if isinstance(exc, (TransientError, httpx.TransportError)):
        return True
    status = getattr(exc, "status_code", None)
    if not isinstance(status, int):
        status = getattr(getattr(exc, "response", None), "status_code", None)
    return isinstance(status, int) and status >= 500


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


#: A quote shorter than this, after normalisation, is not evidence (S4): one character
#: (or a run of spaces) is a substring of nearly every log line, so "verifying" it proves
#: nothing and would let a hallucinated citation count towards the `verified` list that
#: keeps a `false_positive` from being overruled. Eight characters is the shortest span
#: that still holds a real token (an address, a port, a short path, a verb + argument).
MIN_QUOTE_CHARS = 8


def _searchable(text: str) -> tuple[str, str]:
    """The two forms of an alert's text a quote may have been cut from: the plain text
    (the model un-escaped what it saw) and the exact escaped form the dossier showed it
    (`wrap.untrusted_block` NFKC-folds, then `html.escape(..., quote=False)`s, so a
    `&`, `<` or `>` in a log appears as `&amp;`, `&lt;`, `&gt;` in the dossier — the
    form a quote copied straight from `dossier.text` carries, B3). Both go through ①'s
    gate normalisation (`security.gate._norm`: NFKC, whitespace collapsed) so a quote
    that differs from the log only in spacing still matches — `security.gate.step3_quotes`
    matches `block.plain` and `block.escaped` the same way."""
    folded = wrap.normalise(text)
    return _norm(folded), _norm(html.escape(folded, quote=False))


def _check_evidence(
    conn: psycopg.Connection, case_id: str, parsed: dict[str, Any]
) -> dict[str, Any]:
    """Per `evidence[i]`: `alert_id` must be a case head or a duplicate of one (DEC-036's
    query shape) *and* `quote` must be at least `MIN_QUOTE_CHARS` long after
    normalisation *and* a substring of that alert's `raw_log` or `description`, plain or
    escaped (`_searchable`). Rejection reasons: `not_in_case`, `quote_too_short`,
    `quote_not_found`."""
    rows = conn.execute(_EVIDENCE_ALERTS_SQL, (case_id, case_id)).fetchall()
    texts = {
        alert_id: (*_searchable(raw_log or ""), *_searchable(description or ""))
        for alert_id, raw_log, description in rows
    }

    verified: list[int] = []
    rejected: list[dict[str, Any]] = []
    for index, item in enumerate(parsed.get("evidence") or []):
        alert_id = item.get("alert_id")
        if alert_id not in texts:
            rejected.append({"index": index, "alert_id": alert_id, "reason": "not_in_case"})
            continue
        quote = _norm(item.get("quote") or "")
        if len(quote) < MIN_QUOTE_CHARS:
            rejected.append({"index": index, "alert_id": alert_id, "reason": "quote_too_short"})
        elif any(quote in text for text in texts[alert_id]):
            verified.append(index)
        else:
            rejected.append({"index": index, "alert_id": alert_id, "reason": "quote_not_found"})
    return {"verified": verified, "rejected": rejected}


def _scan_for_injection(dossier: dossier_mod.Dossier) -> list[detector.Finding]:
    """`app.security.detector` over each wrapped block's own body, one block at a time
    (design note 4; review round 1, B2). `detector.scan()` is documented to run over
    per-block `.plain` content, never the assembled prompt — and the first version of
    this function scanned `dossier.text` whole, whose own `<untrusted_data ...>` wrappers
    trip `heuristic:delimiter_lookalike` (high) on every dossier, so every clean case
    read `high` and no `false_positive` could ever stand. `Dossier.blocks` (additive,
    P5-T04 round 1) hands over exactly the `(block_kind, body)` pairs the wrapper
    rendered — `body` being the block's `plain` text (NFKC-folded, nonce-stripped,
    truncated, unescaped; no wrapper) — and each becomes one `wrap.Block` here so a
    finding names the dossier block (`raw_log`, `correlation_samples`, ...) it came from.

    Known limit: the truncation flag is not carried, so a legitimate `[truncated] N bytes
    dropped` marker `wrap.truncate_block` appended reads as a `fake_truncation_marker`
    (medium). That level forces nothing (only `high` does), and it is recorded in
    `injection_findings` for the analyst to see."""
    blocks = [
        wrap.Block(
            source=source,
            attrs={},
            plain=body,
            escaped=body,
            truncated=False,
            dropped_bytes=0,
            rendered=body,
        )
        for source, body in dossier.blocks
    ]
    return detector.scan(blocks)


def run_investigate_job(conn: psycopg.Connection, job: Job, *, adapter: Any | None = None) -> None:
    """Run pipeline ② for one case. `adapter` defaults to a real `DeepSeekAdapter`;
    every test passes a fake instead (design note 8)."""
    cfg = config.load()
    _raise_idle_timeout(conn, cfg)
    _set_repeatable_read(conn)

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
    spend = llm_investigate.Spend()

    llm_adapter = adapter or DeepSeekAdapter(
        cfg,
        spent_usd=partial(month_spend_usd, conn),
        # the cap and the deadline are the admin's saved limits, read per attempt; a read that
        # fails stops the call as `LLMBudgetExceeded`, so the row below is `stopped_by='cap'`
        limits=partial(settings.effective_limits, conn, cfg),
    )

    def write_row(row_id: uuid.UUID, stopped_by: str | None, **outcome: Any) -> None:
        """This attempt's one `llm_runs` row. The usage columns come from `spend` unless
        the caller passes its own (`**outcome`) — so a failure row still carries whatever
        was already paid for (S7)."""
        _write_llm_run(
            conn,
            run_id=row_id,
            case_id=case_id,
            system_prompt=system,
            user_message=user,
            agent_trace=agent_trace,
            stopped_by=stopped_by,
            **{**_spend_columns(spend, cfg), **outcome},
        )

    try:
        result = llm_investigate.investigate(
            llm_adapter,
            dossier,
            nonce=nonce,
            cfg=cfg,
            extra_constants=dossier_mod.DOSSIER_TEMPLATE_CONSTANTS,
            spend=spend,
        )
    except LLMBudgetExceeded:
        write_row(run_id, "cap")
        return  # permanent by nature (the cap will not clear itself) — no retry warranted
    except LLMPermanent:
        write_row(run_id, "permanent")
        return
    except PermanentError:
        # The pre-send linter guard (G6′, `llm.investigate._lint_or_raise`) — a
        # template defect, not a model outcome. Caught after the two LLM-specific
        # PermanentError subclasses above so their own `stopped_by` values are not
        # shadowed by this catch-all.
        write_row(run_id, "linter")
        return
    except Exception as exc:
        if not _is_transient(exc):
            raise
        # Transient (design note 3(d)): the row must survive the reschedule, and the
        # worker's `transaction()` rolls back the whole handler transaction on any
        # exception it lets through — so this commits explicitly before re-raising,
        # the same "commit before the caller sees the failure" shape `deps.require_role`
        # uses for its own 403 (P4 planning decision 3), applied to a job instead of a
        # route.
        #
        # B1: `llm_runs.run_id` is a primary key and the table is append-only, so the
        # retry would die on `llm_runs_pkey` if every attempt wrote `run_id_for_job`.
        # A non-final attempt writes under its own attempt-scoped id; only the LAST
        # attempt — after which the job is `failed` and nothing will run again —
        # writes the id the route handed out, so `GET /runs/{run_id}` answers `running`
        # between attempts and `done` (stopped_by='transient', result NULL) only once
        # nothing more will run.
        is_final = job.attempts >= cfg.JOB_MAX_ATTEMPTS
        write_row(run_id if is_final else attempt_run_id(job.job_id, job.attempts), "transient")
        conn.commit()
        raise

    usage_columns = _usage_columns(result.usage, result.latency_ms, result.model, cfg)

    if result.parsed is None:
        # Schema-invalid after the one repair (design note 2: "a second failure sets
        # stopped_by='schema' and result stays NULL") — mirrors ①'s own "schema"
        # outcome (`tier1/triage.py`'s `run_triage_job`): write the row with the real
        # usage/cost the calls actually spent, and complete normally — a response was
        # received and recorded, so no retry would change anything.
        write_row(run_id, "schema", **usage_columns)
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

    write_row(
        run_id,
        None,
        result=final_result,
        evidence_check=evidence_check,
        citation_warnings=citation_warnings or None,
        injection_findings=detector.as_json(findings),
        **usage_columns,
    )

    # S5: under REPEATABLE READ a `cases` row that a concurrent transaction (a Tier-2
    # `conclude`, ...) changed after this transaction's snapshot cannot be updated —
    # Postgres raises `SerializationFailure` (40001) and aborts the transaction, which
    # would throw away the `llm_runs` row just written and the paid call with it. The
    # timestamp is a convenience and the run row is the record, so the UPDATE runs in a
    # savepoint: on a serialization failure only the savepoint is rolled back, the
    # timestamp is skipped, and the row (and the job's success) stand.
    try:
        with conn.transaction():
            conn.execute("UPDATE cases SET last_analyzed_at = now() WHERE case_id = %s", (case_id,))
    except psycopg.errors.SerializationFailure:
        pass
