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

**The learned section (P13-T08, DEC-210, spec §7.6 to §7.9).** With `RAG_ENABLED` the job reads the
case's newest stored lookup (`rag.lookup.lookup_material`: `latest_lookup` in a savepoint, so a database
error is no material and not a failed job) and the material it may put in a prompt
(`prompt_material`: each entry re-checked - active, hash intact) and hands it to `dossier.build` as
`learned`, which renders it as block 10. **② never waits**: whatever the lookup holds when the job
runs is used - the newest `ok` or `empty` row (spec §7.6: a `budget` refresh written after it does not hide
it; `rag.lookup.USABLE_STATUSES`), the "nothing found" form for an `empty` one, no section when there
is none of the two - and nothing is queued or slept on. A refresh that `failed` (DEC-213, P14-T06) does hide
it: the job reads `rag.lookup.lookup_failure` first and, when the newest lookup of the case failed, renders no
section and adds `rag_not_applied:<kind>` to the run's `citation_warnings`, so the notice the UI shows is true. The `llm_runs` row names the lookup
(`rag_lookup_id`) only when its material actually reached the prompt, after any budget cut. The
output schema, the injection scan and `_check_evidence` are unchanged: an entry is reference
material, and a quote taken from one is not in the alert's own text, so it is refused as any quote
that is not. With the switch off nothing here runs and nothing differs, the INSERT included.

**The definite conclusion (P14-T02, DEC-213, spec 4.2).** The model answers `investigate_v3`: one of
`llm.verdicts.MODEL_CONCLUSIONS`, never `need_more_data` (a prompt that no longer offers it, and a schema
that refuses it). The override is unchanged - zero verified evidence, or a high injection finding meeting a
`false_positive`, makes the stored conclusion `need_more_data`, which `ck_llm_runs_suggested_conclusion`
still admits - and `evidence_check.original_conclusion` is still written only when it fired. What is new is
`evidence_check.model_conclusion`: the model's own answer, written on every run with a parsed result, so a
reader can tell "the model concluded X and the system held it" from "the model concluded X".

**Computed, then written (P14-T11, DEC-213, spec §6).** `evaluate_case(conn, case_id, *, adapter, cfg, rag,
as_of=None)` is everything the job does up to its writes, and runs `SELECT`s only: the lookup, the dossier,
the model call, the evidence check, the injection scan and the override. It returns a `CaseEvaluation` and
writes nothing, so the lab measurement (`eval/lab_measure.py`) can ask ② about a case twice, RAG off and on,
without a row, an event or a timestamp. `run_investigate_job` is `evaluate_case(..., rag=cfg.RAG_ENABLED)`
and exactly the writes it made before: the `llm_runs` row of each outcome, the commit before a transient
failure is re-raised, and `cases.last_analyzed_at`. The idle timeout, the isolation level, the `llm_enabled`
check and the archived-case skip stay in the job: they are about the job's own transaction.

`as_of` (None: today's behaviour, byte for byte) makes the evaluation what ② could have known at that instant:
the dossier keeps only the rows created strictly before it in block 6 and block 8 (`dossier.build(as_of=)`),
and the RAG arm reads the newest lookup of the case created before it (`lookups_before`, which is `rag.lookup.latest_lookup(before=)`). The newest decides, as
in the product: a `failed` one hides an older good one. A tier-2 note, or an earlier ② answer, written after the
escalation would otherwise hand the human's (or an earlier run's) conclusion to both arms and hide the RAG's effect.
"""

from __future__ import annotations

import html
import json
import uuid
from dataclasses import dataclass
from datetime import datetime
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
from app.llm.builder import rag_not_applied_warning
from app.llm.triage import prompt_version
from app.rag.lookup import (
    UNKNOWN_FAILURE_KIND,
    USABLE_STATUSES,
    LookupResult,
    PromptMaterial,
    latest_lookup,
    lookup_failure,
    lookup_material,
    prompt_material,
)
from app.rag.subject import Subject
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

# P13-T08 (DEC-210): the one extra column, `rag_lookup_id` (migration 020), and the statement that names
# it, as `audit/llm_runs.py` has had them since P13-T07. It is used only for a row whose prompt held a
# lookup's material, which needs `RAG_ENABLED`; every other row - the whole of today's behaviour - is
# written by `_LLM_RUNS_INSERT_SQL`, whose text is what it was before, so a host that runs this code
# before `make migrate` has applied 020 still writes ②'s rows.
_LLM_RUNS_LOOKUP_COLUMNS = (*_LLM_RUNS_COLUMNS, "rag_lookup_id")
_LLM_RUNS_INSERT_WITH_LOOKUP_SQL = (
    f"INSERT INTO llm_runs ({', '.join(_LLM_RUNS_LOOKUP_COLUMNS)}) "
    f"VALUES ({', '.join(['%s'] * len(_LLM_RUNS_LOOKUP_COLUMNS))})"
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
    rag_lookup_id: uuid.UUID | None = None,
) -> None:
    """`rag_lookup_id` (P13-T08): the stored lookup whose approved material is in this row's prompt, so
    the admin can see which runs a lookup influenced. It is written only when given: None - today's row -
    is written by today's INSERT, which does not name the column at all."""
    values = (
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
    )
    if rag_lookup_id is None:
        conn.execute(_LLM_RUNS_INSERT_SQL, values)
    else:
        conn.execute(_LLM_RUNS_INSERT_WITH_LOOKUP_SQL, (*values, rag_lookup_id))


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
    validated `investigate_v3` object, or `None`, never an envelope around it, so a
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

#: Why the system held the model's conclusion back as `need_more_data` (P14-T02, spec 4.2), in the
#: words `investigation_view.held_by` uses. `HELD_HIGH_INJECTION` is also the value the job writes to
#: `evidence_check.forced_by` (a name that existed before P14 and is unchanged); no verified evidence
#: has no `forced_by` - it is read from `evidence_check.verified` being empty.
HELD_NO_VERIFIED_EVIDENCE = "no_verified_evidence"
HELD_HIGH_INJECTION = "high_severity_injection_finding"
HELD_BY: tuple[str, ...] = (HELD_NO_VERIFIED_EVIDENCE, HELD_HIGH_INJECTION)


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
    `quote_not_found`.

    Nothing else is evidence (P13-T08): the dossier's learned section (an approved entry, the
    decision history) is reference material about *other* cases, so a quote taken from it is in
    none of this case's alerts' text and comes back `quote_not_found`, with the alert's own id on
    it or not. The check reads alerts only, by design; a test pins it."""
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


# ---------------------------------------------------------------------------
# The lookup as of an instant (P14-T11).
# ---------------------------------------------------------------------------


def lookups_before(
    conn: psycopg.Connection, case_id: str, as_of: datetime
) -> tuple[LookupResult | None, LookupResult | None]:
    """`(newest, usable)`: the newest lookup of the case created before `as_of` whatever its status (None:
    there is none), and the newest of those with a status a prompt may use (`USABLE_STATUSES`: a `budget`
    row written after an `ok` one does not hide it, spec §7.6). `newest.status == "failed"` is the notice
    and no section, whatever `usable` holds: the newest lookup decides. Read as ② reads it and the
    measurement describes it, so the two cannot disagree about which lookup a case had."""
    subject = Subject("case", case_id.lower())
    return (
        latest_lookup(conn, subject, before=as_of),
        latest_lookup(conn, subject, statuses=USABLE_STATUSES, before=as_of),
    )


def _learned_before(
    conn: psycopg.Connection, case_id: str, as_of: datetime
) -> tuple[str | None, PromptMaterial | None]:
    """`(failure kind, material)` for ② as of an instant: the product's two reads (`lookup_failure`, then
    `lookup_material` over the usable statuses) on the lookups created before `as_of`. Read in a savepoint
    like theirs: the lookup is an extra, and a database error in it is no notice and no section, never a
    failed ②."""
    try:
        with conn.transaction():
            newest, usable = lookups_before(conn, case_id, as_of)
            if newest is not None and newest.status == "failed":
                return (newest.failure_kind or UNKNOWN_FAILURE_KIND), None
            return None, prompt_material(conn, usable)
    except psycopg.Error as exc:
        print(
            json.dumps(
                {"rag_lookup": "unreadable", "subject": case_id, "error": type(exc).__name__}
            )
        )
        return None, None


# ---------------------------------------------------------------------------
# ② computed, not written.
# ---------------------------------------------------------------------------

#: `CaseEvaluation.outcome`'s closed set: one per way ② can end for a case. `stopped_by` of the row the job
#: writes is the outcome itself, and `None` for "ok".
OUTCOMES = frozenset({"ok", "schema", "cap", "permanent", "linter", "transient"})


@dataclass(frozen=True)
class CaseEvaluation:
    """② on one case, computed and not written (P14-T11).

    `outcome` (`OUTCOMES`): "ok" - a schema-valid answer, checked and overridden; "schema" - still invalid
    after the repair round; "cap" / "permanent" / "linter" - the model call raised `LLMBudgetExceeded` /
    `LLMPermanent` / the pre-send linter's `PermanentError`; "transient" - a timeout, a transport error or a
    5xx (`exception` is the error; the job writes a row and re-raises it).

    `result` is the object the job stores: the model's `investigate_v3` answer with the override applied,
    only for "ok". `model_conclusion` is the model's own answer and `final_conclusion` the stored one (they
    differ exactly when `held_by` is not empty: `no_verified_evidence` and / or
    `high_severity_injection_finding`, the closed causes `investigation_view.held_by` reads from the same
    check). `rag_lookup_id` is the lookup whose material is in the prompt (None when there was none, and
    when the budget cut block 10); `rag_not_applied` the closed failure kind when the newest lookup
    `failed`. `usage` is summed over the calls that were answered; `cost_usd` prices it.

    The fields from `system_prompt` on are what the job writes its `llm_runs` row from: the prompt, the
    P7-2 snapshot, the evidence check, the warnings (the failed-lookup notice included), the injection
    findings and the five usage columns of the row.
    """

    outcome: str
    result: dict[str, Any] | None
    model_conclusion: str | None
    final_conclusion: str | None
    held_by: list[str]
    rag_lookup_id: uuid.UUID | None
    rag_not_applied: str | None
    usage: dict[str, Any]
    cost_usd: float
    system_prompt: str
    user_message: str
    agent_trace: dict[str, Any]
    evidence_check: dict[str, Any] | None
    citation_warnings: list[str] | None
    injection_findings: list[dict[str, Any]] | None
    columns: dict[str, Any]
    exception: BaseException | None = None

    def __post_init__(self) -> None:
        if self.outcome not in OUTCOMES:
            raise ValueError(f"outcome must be one of {sorted(OUTCOMES)}, got {self.outcome!r}")
        if self.outcome == "transient" and self.exception is None:
            raise ValueError("a transient outcome carries the error the job re-raises")

    @property
    def stopped_by(self) -> str | None:
        return None if self.outcome == "ok" else self.outcome


def held_causes(evidence_check: dict[str, Any]) -> list[str]:
    """Why the system held the model's conclusion back as `need_more_data`, read from an `evidence_check`
    (the one just built, or one stored): the closed causes in `HELD_BY`'s order - `no_verified_evidence` when
    no cited evidence verified, `high_severity_injection_finding` when `forced_by` says so. This is the one
    rule: `evaluate_case` uses it, and `investigation_view.held_by` (which imports this module, so it
    cannot be the other way round) calls it after its own check that the run carries a `model_conclusion`.
    """
    verified = evidence_check.get("verified")
    found = {
        HELD_NO_VERIFIED_EVIDENCE: isinstance(verified, list) and not verified,
        HELD_HIGH_INJECTION: evidence_check.get("forced_by") == HELD_HIGH_INJECTION,
    }
    return [cause for cause in HELD_BY if found[cause]]


def evaluate_case(
    conn: psycopg.Connection,
    case_id: str,
    *,
    adapter: Any | None,
    cfg: config.Config,
    rag: bool,
    as_of: datetime | None = None,
) -> CaseEvaluation | None:
    """`_compute_case` for a caller that wants `None` when the case does not exist (the lab measurement).
    `run_investigate_job` calls `_compute_case` itself to keep the `UnknownCase` it turns into a
    `PermanentError`."""
    try:
        return _compute_case(conn, case_id, adapter=adapter, cfg=cfg, rag=rag, as_of=as_of)
    except dossier_mod.UnknownCase:
        return None


def _compute_case(
    conn: psycopg.Connection,
    case_id: str,
    *,
    adapter: Any | None,
    cfg: config.Config,
    rag: bool,
    as_of: datetime | None = None,
) -> CaseEvaluation:
    """Pipeline (2) for one case, computed and returned, never written (P14-T11); `dossier_mod.UnknownCase`
    when the case does not exist (`evaluate_case` returns None for it).

    Only `SELECT`s run on `conn`: no `llm_runs`, no `audit_events`, no `cases` column, no job. `rag` says
    whether the learned section is put in the dossier (the job passes `cfg.RAG_ENABLED`; `cfg` itself is not
    asked). `as_of` is described in the module docstring; None is today's dossier and today's lookup (the
    newest of the case, read by `lookup_failure` and `lookup_material`). `adapter=None` builds the real
    `DeepSeekAdapter` at the same point, with the same spend check, as the job always has. A model failure is
    an `outcome` and not an exception, except that a transient one is also carried in `exception` for the
    caller to re-raise; anything else (a programming error) propagates untouched.

    The idle timeout, the isolation level, the `llm_enabled` check and the archived-case skip are the
    job's, not this function's: an evaluation may run on a concluded case."""
    nonce = wrap.new_nonce()  # design note 3(a): a new nonce per attempt, never cached

    # P13-T08: the learned section. With the switch off, not one query and `learned=None`. With it on, the
    # newest lookup of the case, whatever it holds (or nothing): ② never waits for the lookup job, never
    # queues one and never sleeps. The job reads it after `_set_repeatable_read`, so the lookup is part of
    # the snapshot the dossier is read in. `parse_subject` stores a case's id in lower case.
    material = None
    not_applied = None
    if rag:
        if as_of is None:
            # DEC-213: a newest lookup that `failed` is a notice and no section, whatever an older one held.
            not_applied = lookup_failure(conn, Subject("case", case_id.lower()))
            if not_applied is None:
                material = lookup_material(
                    conn, Subject("case", case_id.lower()), statuses=USABLE_STATUSES
                )
        else:
            not_applied, material = _learned_before(conn, case_id, as_of)

    dossier = dossier_mod.build(conn, case_id, nonce=nonce, cfg=cfg, learned=material, as_of=as_of)

    # The lookup is named on the row only when its material reached the prompt - not when there was none,
    # and not when the budget dropped block 10 (`Dossier.learned_used`).
    rag_lookup_id = material.lookup_id if material is not None and dossier.learned_used else None

    system, user = llm_investigate.build(dossier, nonce=nonce, cfg=cfg)
    agent_trace = _snapshot_trace(dossier)
    spend = llm_investigate.Spend()

    llm_adapter = adapter or DeepSeekAdapter(
        cfg,
        spent_usd=partial(month_spend_usd, conn),
        # the cap and the deadline are the admin's saved limits, read per attempt; a read that
        # fails stops the call as `LLMBudgetExceeded`, so the row is `stopped_by='cap'`
        limits=partial(settings.effective_limits, conn, cfg),
    )

    # DEC-213: every row of a run whose lookup failed says so, not only the one with a verdict - a `cap`,
    # `permanent`, `linter`, `schema` or `transient` row was built from the same dossier without block 10
    # (the way ① puts `built.warnings` on every row it writes). The success row passes its own list, which
    # already ends with it.
    notice = [rag_not_applied_warning(not_applied)] if not_applied is not None else []

    def evaluation(
        outcome: str,
        columns: dict[str, Any],
        usage: dict[str, Any],
        *,
        result: dict[str, Any] | None = None,
        model_conclusion: str | None = None,
        held_by: list[str] | None = None,
        evidence_check: dict[str, Any] | None = None,
        citation_warnings: list[str] | None = None,
        injection_findings: list[dict[str, Any]] | None = None,
        exception: BaseException | None = None,
    ) -> CaseEvaluation:
        return CaseEvaluation(
            outcome=outcome,
            result=result,
            model_conclusion=model_conclusion,
            final_conclusion=None if result is None else result["suggested_conclusion"],
            held_by=held_by or [],
            rag_lookup_id=rag_lookup_id,
            rag_not_applied=not_applied,
            usage=usage,
            cost_usd=round(cost_usd(usage, cfg), 5) if usage else 0.0,
            system_prompt=system,
            user_message=user,
            agent_trace=agent_trace,
            evidence_check=evidence_check,
            # the notice is on every row of a run whose lookup failed; the success row's own list ends with it
            citation_warnings=(
                citation_warnings if citation_warnings is not None else (notice or None)
            ),
            injection_findings=injection_findings,
            columns=columns,
            exception=exception,
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
        return evaluation("cap", _spend_columns(spend, cfg), spend.usage)
    except LLMPermanent:
        return evaluation("permanent", _spend_columns(spend, cfg), spend.usage)
    except PermanentError:
        # The pre-send linter guard (G6', `llm.investigate._lint_or_raise`) - a template defect, not a model
        # outcome. Caught after the two LLM-specific PermanentError subclasses above so their own outcomes
        # are not shadowed by this catch-all.
        return evaluation("linter", _spend_columns(spend, cfg), spend.usage)
    except Exception as exc:
        if not _is_transient(exc):
            raise
        # Transient (design note 3(d)): the caller keeps the row across the reschedule, so it commits and
        # re-raises `exception` after writing it.
        return evaluation("transient", _spend_columns(spend, cfg), spend.usage, exception=exc)

    usage_columns = _usage_columns(result.usage, result.latency_ms, result.model, cfg)

    if result.parsed is None:
        # Schema-invalid after the one repair (design note 2: "a second failure sets
        # stopped_by='schema' and result stays NULL") - mirrors ①'s own "schema" outcome: the row carries the
        # real usage/cost the calls spent.
        return evaluation("schema", usage_columns, result.usage)

    evidence_check = _check_evidence(conn, case_id, result.parsed)
    findings = _scan_for_injection(dossier)
    injection_level = detector.level(findings)

    final_result = dict(result.parsed)
    model_conclusion = final_result["suggested_conclusion"]
    # P14-T02 (spec 4.2): the model's own answer is stored beside the final one on EVERY run with a
    # parsed result, overruled or not - the reader (`investigation_view`) needs it to say what the
    # system held. `original_conclusion` below is unchanged: only when the answer was overruled.
    evidence_check["model_conclusion"] = model_conclusion
    overridden = False

    if not evidence_check["verified"]:
        # Zero verified evidence -> need_more_data; the model's answer is overruled,
        # not deleted (design note 4). The override is unchanged by P14: ck_llm_runs_suggested_conclusion
        # still admits the value, and the model can no longer answer it - only this line sets it.
        final_result["suggested_conclusion"] = "need_more_data"
        overridden = True

    if injection_level == "high" and final_result["suggested_conclusion"] == "false_positive":
        final_result["suggested_conclusion"] = "need_more_data"
        evidence_check["forced_by"] = HELD_HIGH_INJECTION
        overridden = True

    if overridden:
        evidence_check["original_conclusion"] = model_conclusion

    citation_warnings = [
        f"alert_id {item['alert_id']!r} rejected: {item['reason']}"
        for item in evidence_check["rejected"]
    ]
    citation_warnings.extend(notice)

    return evaluation(
        "ok",
        usage_columns,
        result.usage,
        result=final_result,
        model_conclusion=model_conclusion,
        held_by=held_causes(evidence_check),
        evidence_check=evidence_check,
        citation_warnings=citation_warnings or None,
        injection_findings=detector.as_json(findings),
    )


def run_investigate_job(conn: psycopg.Connection, job: Job, *, adapter: Any | None = None) -> None:
    """Run pipeline ② for one case. `adapter` defaults to a real `DeepSeekAdapter`;
    every test passes a fake instead (design note 8). `evaluate_case` does the work; this function adds the
    job's own checks and every write."""
    cfg = config.load()
    _raise_idle_timeout(conn, cfg)
    _set_repeatable_read(conn)

    case_id = job.subject_id

    if not cfg.llm_enabled:
        # G7: the case is untouched, no status moves, and no attempt was made — not
        # even a dossier read, so this never opens a connection to a case that might
        # since have been concluded.
        return

    # INT-T03 / DEC-212: the archive does not cancel the jobs it leaves behind. A case it set aside is
    # nobody's to investigate (`POST /analyze` refuses it with the same 409 as a concluded one): a job
    # queued before the archive makes no model call and writes no `llm_runs` row. Read after
    # `_set_repeatable_read`, so it is also the first statement of the snapshot the dossier reads in.
    archived = conn.execute("SELECT status FROM cases WHERE case_id = %s", (case_id,)).fetchone()
    if archived is not None and archived[0] == "archived":
        print(json.dumps({"investigate": "skipped", "reason": "archived", "case_id": case_id}))
        return

    try:
        evaluation = _compute_case(conn, case_id, adapter=adapter, cfg=cfg, rag=cfg.RAG_ENABLED)
    except dossier_mod.UnknownCase as exc:
        raise PermanentError(str(exc)) from exc

    run_id = run_id_for_job(job.job_id)

    def write_row(row_id: uuid.UUID) -> None:
        """This attempt's one `llm_runs` row, from the evaluation: the usage columns are what the calls that
        were answered cost, so a failure row still carries whatever was already paid for (S7)."""
        _write_llm_run(
            conn,
            run_id=row_id,
            case_id=case_id,
            system_prompt=evaluation.system_prompt,
            user_message=evaluation.user_message,
            agent_trace=evaluation.agent_trace,
            stopped_by=evaluation.stopped_by,
            rag_lookup_id=evaluation.rag_lookup_id,
            result=evaluation.result,
            evidence_check=evaluation.evidence_check,
            citation_warnings=evaluation.citation_warnings,
            injection_findings=evaluation.injection_findings,
            **evaluation.columns,
        )

    if evaluation.outcome == "transient":
        # The row must survive the reschedule, and the worker's `transaction()` rolls back the whole handler
        # transaction on any exception it lets through - so this commits explicitly before re-raising, the
        # same "commit before the caller sees the failure" shape `deps.require_role` uses for its own 403
        # (P4 planning decision 3), applied to a job instead of a route.
        #
        # B1: `llm_runs.run_id` is a primary key and the table is append-only, so the retry would die on
        # `llm_runs_pkey` if every attempt wrote `run_id_for_job`. A non-final attempt writes under its own
        # attempt-scoped id; only the LAST attempt - after which the job is `failed` and nothing will run
        # again - writes the id the route handed out, so `GET /runs/{run_id}` answers `running` between
        # attempts and `done` (stopped_by='transient', result NULL) only once nothing more will run.
        is_final = job.attempts >= cfg.JOB_MAX_ATTEMPTS
        write_row(run_id if is_final else attempt_run_id(job.job_id, job.attempts))
        conn.commit()
        error = evaluation.exception
        if error is None:  # never: `CaseEvaluation` refuses a transient outcome without its error
            raise PermanentError("a transient evaluation carries no error to re-raise")
        raise error

    write_row(run_id)
    if evaluation.outcome != "ok":
        return  # a refused, schema-invalid or linter-stopped attempt: the row is the record

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
