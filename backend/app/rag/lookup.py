"""The `rag_lookup` job, and what ① and ② read of its result (P13-T03, DEC-210, spec §7.6, §7.7, §7.9).

`run_lookup_job(conn, job, adapter=None)`; `job.subject_id` is `alert:<id>` or `case:<uuid>`. It runs on
the `rag-worker` and never blocks ① or ②: they read the newest stored row of their subject at prompt
time and carry on without it when there is none. One lookup, in order:

1. the idle timeout is raised (a model call is client-side idle time to PostgreSQL);
1b. an alert whose ① has finished (`alerts.triage_status` is not `pending`) is skipped: no call, nothing
   stored (`rag_results.status` has no `skipped`), because the lookup arrived too late for any prompt;
2. the subject is parsed, its fingerprint built, its self-exclusion and its decision history computed
   (no model: analysts' decisions need no approval);
3. the budget: when the global cap or the RAG's own is reached, a `budget` row is written (the history
   kept) and nothing else happens;
4. the candidates (a database search), each checked before it can be sent (V-R1, A4: an entry
   changed after approval reaches no prompt): `sha256(content)` is its `content_sha256` and its
   published file matches (`rag.entries.file_matches`). A candidate that fails is dropped, never sent
   and never matched, and writes `rag.integrity_failed`, once per entry per lookup. The rest are cut
   to the prompt budget (`rag.match.select_candidates`); none left -> `ok` when the history has
   data, else `empty`, and the model is not asked;
5. otherwise the ranking agent (`rag.match.rank`) is asked, through `DeepSeekAdapter` limited to the RAG
   budget; only a candidate that was sent can be matched;
6. the `llm_runs` row (`rag_lookup` / `retriever`) and the `rag_results` row are written in the job's
   one transaction. The row's `gate_result` holds `integrity_failed` (the entries dropped at 4),
   `candidates_dropped_for_budget` and, once an answer came, `faults`.

The outcomes (`rag_results.status`): `empty` (nothing to show, the first day); `ok` (a history, or
matches that passed V-R1 and V-R2); `budget` (a cap reached, before the call or between a call and
its repair); `failed` (the last attempt failed, the provider refused, or our own prompt failed the
linter) with the event `rag.lookup_failed {lookup_id}`. An answer the schema refuses after the one
repair is not a failure: V-R3, the lookup degrades and never blocks, so it is `ok` with the history,
or `empty`, and no match; its run row keeps `stopped_by='schema'` and `gate_result.schema_errors`.
A model failure that is worth another attempt writes its run row, commits it and re-raises until the
last attempt (the pattern of `tier2/investigate.py`: the worker rolls the handler's transaction back,
the paid call must not vanish with it).

What is stored. `rag_results.history`: `{level, key_name, total, by_conclusion (all six keys),
last_seen (isoformat or null), examples}`. `matches`: `[{entry_id, level, content_sha256}]`.
`match_notes`: `{entry_id: reason}`, the model's words, for the admin's page only: nothing here ever
puts them in a `Match`, a `LookupResult` or a `PromptMaterial`.

`prompt_material` is the other half of V-R (spec §7.7, "At prompt time"): it is what ① and ② may put in
a prompt, from the database alone (the `worker` does not mount `kb_learned/`). Each match is re-checked
— the entry is active and `sha256(content)`, its stored `content_sha256` and the hash stored with the
match are one value — and a match that fails is dropped, the rest rendered.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from functools import partial
from typing import Any

import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb

from app.audit.events import write_event
from app.infra import config
from app.infra.errors import PermanentError
from app.infra.jobs import Job
from app.llm.adapter import DeepSeekAdapter, LLMBudgetExceeded, LLMPermanent, cost_usd
from app.llm.builder import KbLearnedLevel
from app.llm.triage import prompt_version
from app.rag import agent
from app.rag.budget import rag_limits, rag_spent_or_exhausted
from app.rag.candidates import candidates
from app.rag.entries import KB_LEARNED_ROOT, Entry, entry_by_id, file_matches, sha256_text
from app.rag.fingerprint import Fingerprint, alert_fingerprint, case_fingerprint
from app.rag.history import (
    CONCLUSIONS,
    LEVELS,
    History,
    decision_history,
    render_history,
    self_exclusion,
)
from app.rag.match import (
    MAX_MATCHES,
    TEMPLATE_PATH,
    Match,
    injection_findings,
    rank,
    select_candidates,
    validate_matches,
)
from app.rag.runs import write_rag_run
from app.rag.subject import Subject, parse_subject
from app.security import detector

#: The statuses of a lookup a prompt may use: a `failed` or `budget` row carries no material (`prompt_material`).
USABLE_STATUSES = ("ok", "empty")


@dataclass(frozen=True)
class LookupResult:
    """One stored lookup, as ① and ② read it. `history` is the decision history; `matches` the
    kept matches, closed values only."""

    lookup_id: uuid.UUID
    status: str
    history: History
    matches: tuple[Match, ...]
    created_at: datetime


@dataclass(frozen=True)
class PromptMaterial:
    """What may reach a prompt: the history as `render_history` writes it (None when there is none)
    and the approved content of each matched entry with its level, best first. The reasons of the
    ranking agent are not here."""

    lookup_id: uuid.UUID
    history_text: str | None
    entries: tuple[tuple[KbLearnedLevel, str], ...]


def _log(payload: dict[str, Any]) -> None:
    print(json.dumps(payload))


def _raise_idle_timeout(conn: psycopg.Connection, cfg: config.Config) -> None:
    """The handler's first statement, `tier1/triage.py`'s `_raise_idle_timeout` (duplicated: `rag`
    imports no tier). `infra/db.py::transaction()` sets `idle_in_transaction_session_timeout` to 10 s;
    the model call is idle time to PostgreSQL, so the job raises it to `JOB_LOCK_TIMEOUT_S`, the
    bound `reclaim_stale` uses. `SET` takes no bind parameter, hence `sql.Literal`."""
    conn.execute(
        sql.SQL("SET LOCAL idle_in_transaction_session_timeout = {}").format(
            sql.Literal(f"{cfg.JOB_LOCK_TIMEOUT_S}s")
        )
    )


# ── what is stored ────────────────────────────────────────────────────────────────────────────


def _history_json(history: History) -> dict[str, Any]:
    return {
        "level": history.level,
        "key_name": history.key_name,
        "total": history.total,
        "by_conclusion": {name: history.by_conclusion.get(name, 0) for name in CONCLUSIONS},
        "last_seen": None if history.last_seen is None else history.last_seen.isoformat(),
        "examples": list(history.examples),
    }


_KEY_NAMES = frozenset(name for _level, name in LEVELS)


def _is_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _history_of(raw: Any) -> History:
    """A `History` from its stored JSON; whatever is missing or ill-shaped reads as 'none'. Only the six
    conclusions of `CONCLUSIONS` and the six names of `LEVELS` are kept: this is rendered into a prompt.
    """
    counts = dict.fromkeys(CONCLUSIONS, 0)
    if not isinstance(raw, dict):
        return History(None, None, 0, counts, None, ())
    by_conclusion = raw.get("by_conclusion")
    if isinstance(by_conclusion, dict):
        counts.update({k: v for k, v in by_conclusion.items() if k in counts and _is_count(v)})
    last_seen = None
    if isinstance(raw.get("last_seen"), str):
        try:
            last_seen = datetime.fromisoformat(raw["last_seen"])
        except ValueError:
            last_seen = None
    examples = raw.get("examples")
    key_name = raw.get("key_name")
    if key_name not in _KEY_NAMES:  # the name of one of the six levels, or nothing
        key_name = None
    return History(
        level=raw["level"] if _is_count(raw.get("level")) else None,
        key_name=key_name,
        total=raw["total"] if _is_count(raw.get("total")) else 0,
        by_conclusion=counts,
        last_seen=last_seen,
        examples=(
            tuple(e for e in examples if isinstance(e, str)) if isinstance(examples, list) else ()
        ),
    )


def _matches_json(matches: list[Match]) -> list[dict[str, str]]:
    return [
        {"entry_id": m.entry_id, "level": m.level.value, "content_sha256": m.content_sha256}
        for m in matches
    ]


def _matches_of(raw: Any) -> tuple[Match, ...]:
    """The stored matches; an item that is not one is left out."""
    if not isinstance(raw, list):
        return ()
    found = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        entry_id, level, digest = (item.get(k) for k in ("entry_id", "level", "content_sha256"))
        if not all(isinstance(value, str) for value in (entry_id, level, digest)):
            continue
        try:
            found.append(Match(entry_id, KbLearnedLevel(level), digest))
        except ValueError:
            continue
    return tuple(found)


def _store(
    conn: psycopg.Connection,
    lookup_id: uuid.UUID,
    subject: Subject,
    status: str,
    history: History,
    *,
    matches: list[Match] | None = None,
    notes: dict[str, str] | None = None,
    llm_run_id: uuid.UUID | None = None,
) -> None:
    conn.execute(
        "INSERT INTO rag_results (lookup_id, subject_kind, subject_id, status, history, matches,"
        " match_notes, llm_run_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (
            lookup_id,
            subject.kind,
            subject.id,
            status,
            Jsonb(_history_json(history)),
            Jsonb(_matches_json(matches or [])),
            Jsonb(notes or {}),
            llm_run_id,
        ),
    )
    _log({"rag_lookup": status, "subject": subject.key})


def _store_failed(
    conn: psycopg.Connection,
    lookup_id: uuid.UUID,
    subject: Subject,
    history: History,
    run_id: uuid.UUID | None,
) -> None:
    """The last word on a lookup that did not work: a `failed` row (what was known is kept) and the
    event the admin's audit page shows."""
    _store(conn, lookup_id, subject, "failed", history, llm_run_id=run_id)
    write_event(
        conn,
        "rag.lookup_failed",
        subject.id,
        "system",
        payload={"lookup_id": str(lookup_id)},
    )


def _record_run(
    conn: psycopg.Connection,
    cfg: config.Config,
    tape: agent.Tape,
    subject: Subject,
    findings: list[detector.Finding],
    *,
    stopped_by: str | None,
    result: dict | None = None,
    gate_result: dict | None = None,
    rag_lookup_id: uuid.UUID | None = None,
) -> uuid.UUID | None:
    """This attempt's one `llm_runs` row: the prompt of the first call and whatever the answered calls
    cost, so a failure still carries what was paid for. None when nothing was sent."""
    if not tape.sent:
        return None
    system, user = tape.sent[0]
    usage = tape.usage
    priced = tape.calls > 0 and "prompt_tokens" in usage and "completion_tokens" in usage
    return write_rag_run(
        conn,
        run_id=uuid.uuid4(),
        pipeline="rag_lookup",
        role="retriever",
        subject=subject,
        system_prompt=system,
        user_message=user,
        result=result,
        gate_result=gate_result,
        injection_findings=detector.as_json(findings),
        input_tokens=usage.get("prompt_tokens"),
        output_tokens=usage.get("completion_tokens"),
        latency_ms=tape.latency_ms if tape.calls else None,
        model_id=tape.model,
        prompt_version=prompt_version(TEMPLATE_PATH),
        cost_usd=cost_usd(usage, cfg) if priced else None,
        stopped_by=stopped_by,
        rag_lookup_id=rag_lookup_id,
    )


# ── the job ───────────────────────────────────────────────────────────────────────────────────


def _fingerprint_of(conn: psycopg.Connection, subject: Subject) -> Fingerprint:
    if subject.kind == "alert":
        return alert_fingerprint(conn, subject.id)
    return case_fingerprint(conn, subject.id)


def _over_budget(conn: psycopg.Connection, cfg: config.Config) -> bool:
    """The question the adapter asks before each attempt, asked once before the job starts."""
    return rag_spent_or_exhausted(conn, cfg) >= cfg.RAG_MONTHLY_USD_CAP


def _triage_has_finished(conn: psycopg.Connection, subject: Subject) -> bool:
    """Whether the alert's ① is done with it: `alerts.triage_status` is `ready` or `unavailable`, no longer
    `pending`. A case is never late (② reads the lookup when its own job runs), and an alert that is not
    there is not "finished": the fingerprint says so with the `PermanentError` it always did."""
    if subject.kind != "alert":
        return False
    row = conn.execute(
        "SELECT triage_status FROM alerts WHERE alert_id = %s", (subject.id,)
    ).fetchone()
    return row is not None and row[0] != "pending"


def run_lookup_job(conn: psycopg.Connection, job: Job, *, adapter: Any | None = None) -> None:
    """Run one lookup (module doc). `adapter` defaults to a `DeepSeekAdapter` limited to the RAG
    budget; every test passes a fake."""
    cfg = config.load()
    _raise_idle_timeout(conn, cfg)

    if not agent.rag_model(cfg):  # no model configured: the AI is off, as for ① and ② (G7)
        _log({"rag_lookup": "skipped", "reason": "no_model"})
        return

    try:
        subject = parse_subject(job.subject_id)
    except ValueError:
        raise PermanentError(
            "rag_lookup: the job's subject is neither 'alert:<id>' nor 'case:<uuid>'"
        ) from None

    if _triage_has_finished(conn, subject):
        # ① read the newest lookup when it ran, and it has run: this one could reach no prompt, and a model
        # call would be paid for nothing (a lookup queued behind other jobs is how it comes to be late)
        _log({"rag_lookup": "skipped", "reason": "late", "subject": subject.key})
        return

    fp = _fingerprint_of(conn, subject)  # PermanentError when the subject is not there
    exclusion = self_exclusion(conn, subject)
    history = decision_history(conn, subject, cfg)
    lookup_id = uuid.uuid4()

    if _over_budget(conn, cfg):
        _store(conn, lookup_id, subject, "budget", history)
        return

    intact: list[Entry] = []
    integrity_failed: list[str] = []
    for cand in candidates(conn, fp, exclusion):
        # A4: nothing changed after approval reaches a prompt, the ranking prompt included
        if sha256_text(cand.content) == cand.content_sha256 and file_matches(cand, KB_LEARNED_ROOT):
            intact.append(cand)
            continue
        integrity_failed.append(cand.entry_id)
        write_event(
            conn,
            "rag.integrity_failed",
            cand.entry_id,
            "system",
            payload={"entry_id": cand.entry_id},
        )
    sendable = select_candidates(fp, intact)
    if not sendable:
        _store(conn, lookup_id, subject, "ok" if history.total > 0 else "empty", history)
        return
    gate_base = {
        "integrity_failed": integrity_failed,
        "candidates_dropped_for_budget": len(intact) - len(sendable),
    }

    findings = injection_findings(fp, sendable)
    tape = agent.Tape(
        adapter
        if adapter is not None
        else DeepSeekAdapter(
            cfg,
            spent_usd=partial(rag_spent_or_exhausted, conn, cfg),
            limits=partial(rag_limits, conn, cfg),
        )
    )

    def record(
        stopped_by: str | None, *, gate_result: dict | None = None, **fields: Any
    ) -> uuid.UUID | None:
        gate = {**gate_base, **(gate_result or {})}
        return _record_run(
            conn, cfg, tape, subject, findings, stopped_by=stopped_by, gate_result=gate, **fields
        )

    try:
        matches, notes, result = rank(tape, fp, sendable, cfg=cfg)
    except LLMBudgetExceeded:
        # a cap reached between the check above and the call: the same outcome as that check
        run_id = record("cap", rag_lookup_id=lookup_id)
        _store(conn, lookup_id, subject, "budget", history, llm_run_id=run_id)
        return
    except LLMPermanent:
        _store_failed(
            conn, lookup_id, subject, history, record("permanent", rag_lookup_id=lookup_id)
        )
        return
    except PermanentError:
        # the prompt failed the linter: a template defect, not a model outcome
        _store_failed(conn, lookup_id, subject, history, record("linter", rag_lookup_id=lookup_id))
        return
    except Exception as exc:
        if not agent.is_transient(exc):
            raise  # a bug: the worker will classify it, and nothing here hides it
        if job.attempts < cfg.JOB_MAX_ATTEMPTS:
            # the paid call must outlive the handler's rolled-back transaction
            record("transient")
            conn.commit()
            raise
        _store_failed(
            conn, lookup_id, subject, history, record("transient", rag_lookup_id=lookup_id)
        )
        return

    if result.parsed is None:
        # The schema refused the answer, and the repair too. V-R3: the lookup degrades, it never
        # blocks — no match, the history as it is, and the run keeps what happened.
        gate = {"faults": [], "schema_errors": result.schema_errors}
        run_id = record("schema", gate_result=gate, rag_lookup_id=lookup_id)
        status = "ok" if history.total > 0 else "empty"
        _store(conn, lookup_id, subject, status, history, llm_run_id=run_id)
        return

    # every candidate sent was checked before the send: what the model matched is intact
    _, faults = validate_matches(result.parsed, sendable)
    run_id = record(
        None, result=result.parsed, gate_result={"faults": faults}, rag_lookup_id=lookup_id
    )
    status = "ok" if matches or history.total > 0 else "empty"
    _store(
        conn, lookup_id, subject, status, history, matches=matches, notes=notes, llm_run_id=run_id
    )


# ── what ① and ② read ─────────────────────────────────────────────────────────────────────────


def latest_lookup(
    conn: psycopg.Connection, subject: Subject, *, statuses: Sequence[str] | None = None
) -> LookupResult | None:
    """The newest stored lookup of `subject`, or None. By default whatever its status, which is how ①
    reads it. With `statuses`, the newest row among those statuses: ② passes `USABLE_STATUSES` because
    spec §7.6 says it uses "the newest `ok` row", and a `failed` or `budget` refresh written after one
    must not hide it. An empty `statuses` matches nothing."""
    query = (
        "SELECT lookup_id, status, history, matches, created_at FROM rag_results"
        " WHERE subject_kind = %s AND subject_id = %s"
    )
    params: list[Any] = [subject.kind, subject.id]
    if statuses is not None:
        query += " AND status = ANY(%s)"
        params.append(list(statuses))
    row = conn.execute(query + " ORDER BY created_at DESC, lookup_id LIMIT 1", params).fetchone()
    if row is None:
        return None
    lookup_id, status, history, matches, created_at = row
    return LookupResult(lookup_id, status, _history_of(history), _matches_of(matches), created_at)


def prompt_material(conn: psycopg.Connection, result: LookupResult | None) -> PromptMaterial | None:
    """What ① or ② may put in its prompt for `result`, or None when it may put nothing, not even the
    sentence that says nothing was found: no lookup, or one that `failed` or ran out of `budget`.

    For `empty`, and for an `ok` whose matches all fail the re-check and that has no history, the
    material is empty (`history_text=None`, `entries=()`): the prompt says so in a fixed sentence
    (Review Focus 1). A match is dropped unless its entry is active and `sha256(content)`, the
    entry's `content_sha256` and the hash stored with the match are one value."""
    if result is None or result.status not in USABLE_STATUSES:
        return None
    entries: list[tuple[KbLearnedLevel, str]] = []
    for found in result.matches[:MAX_MATCHES]:
        entry = entry_by_id(conn, found.entry_id)
        if entry is None or entry.status != "active":
            continue
        if not (sha256_text(entry.content) == entry.content_sha256 == found.content_sha256):
            continue
        entries.append((found.level, entry.content))
    history_text = render_history(result.history) if result.history.total > 0 else None
    return PromptMaterial(result.lookup_id, history_text, tuple(entries))
