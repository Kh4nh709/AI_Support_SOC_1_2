"""The `rag_lookup` job, and what ① and ② read of its result (P13-T03, DEC-210; rewritten by P14-T06, DEC-213,
spec §5.3, §5.4).

`run_lookup_job(conn, job, client=None, vconn=None)`; `job.subject_id` is `alert:<id>` or `case:<uuid>`. It
runs on the `rag-worker` and never blocks ① or ②: they read the newest stored row of their subject at prompt
time and carry on without it when there is none. **No model ranks anything here**: the entries are found with
Voyage embeddings in the independent pgvector and scored by Voyage rerank, and there is no fallback to an LLM
ranker (Owner, 03/11). One lookup, in order:

1. the idle timeout is raised (`infra.db.raise_idle_timeout`: a Voyage call is client-side idle time to
   PostgreSQL);
1a. an `archived` alert or case (DEC-212) is skipped: no call, nothing stored, like 1b;
1b. an alert whose ① has finished (`alerts.triage_status` is not `pending`) is skipped: no call, nothing
   stored (`rag_results.status` has no `skipped`), because the lookup arrived too late for any prompt. This is
   also what a rate-limited first attempt finds when it is retried after ① has run;
2. the subject is parsed, its fingerprint built, its self-exclusion and its decision history computed
   (no model: analysts' decisions need no approval);
3. the budget: when the global cap or the RAG's own is reached, a `budget` row is written (the history
   kept) and nothing else happens;
4. the candidates (spec §5.3 steps 2-5): the fingerprint's text is embedded as a `query`; the 20 nearest
   entries of this embedding model and size are asked of `vectordb`; they are read back from the main
   database (active, not drafted from the subject, A5: `candidates.by_ids`) and merged with the database search
   (`candidates()`): the vector hits first, no repeat, at most 40 (`candidates.hybrid`). **Every** one of
   them is then checked before it can be sent (V-R1, A4: an entry changed after approval reaches no prompt):
   `sha256(content)` is its `content_sha256` and its published file matches (`rag.entries.file_matches`). A
   candidate that fails is dropped, never sent and never matched, and writes `rag.integrity_failed`, once per
   entry per lookup. This is spec §5.1's re-check of every vector row against the main database: a stale or
   orphan vector costs a wasted candidate, never a wrong answer. None left: `ok` when the history has data,
   else `empty`, and Voyage is not asked to rerank;
5. otherwise `match.score` reranks the survivors against the fingerprint and `match.keep` takes at most 3 with
   a score of `RAG_MIN_SCORE` or more, each with its level (`match.level_for`);
6. the `llm_runs` row (`rag_lookup` / `retriever`, `rag.runs.write_rag_run`) and the `rag_results` row are
   written in the job's one transaction. The run row has `system_prompt=""`, `user_message` the fingerprint,
   `result={"ranked": [...]}`, `model_id` `"<embedding model>+<rerank model>"`, both calls' tokens as
   `input_tokens` and `output_tokens=0`, and `cost_usd` at Voyage's prices, so `rag.budget` counts it. Its
   `gate_result` holds `integrity_failed` (the entries dropped at 4), `vector_hits` and `candidates` (the
   number sent to the rerank). Every lookup that sent a request has one run row, whatever its outcome; one
   that sent none (an empty `VOYAGE_API_KEY`) has none, its `failed` row and event are its record.

The outcomes (`rag_results.status`): `empty` (nothing to show, the first day); `ok` (a history, or matches);
`budget` (a cap reached, before any call); `failed` with a closed `failure_kind` and the event
`rag.lookup_failed {lookup_id, failure_kind}`. **Any failure of Voyage or of `vectordb` is `failed`**
(`RagUnavailable`, `rag.failures`): an empty `VOYAGE_API_KEY` is `auth` and sends no request; a 429 is
`rate_limit`; 401 and 403 `auth`; 402 `quota`; a timeout `timeout`; `vectordb` that cannot be reached
`vectordb_unreachable`; the rest `provider_error`. ① and ② then run without the RAG and say so
(`rag_not_applied:<kind>`, `lookup_failure`). One exception (Director's call, spec §5.3): a `rate_limit` on the
job's **first** attempt is raised as `TransientError("rate_limit")`; the worker retries after 10 s, which is
inside `RAG_TRIAGE_DELAY_S`, and a retry that finds ① finished is "late" (1b) and writes nothing. On the
second attempt it is a failure like any other. What was paid for before that failure (the embedding, when the
rerank was refused) is written as a run row and committed first (the worker rolls the handler's transaction
back, the spend must not vanish with it).

What is stored. `rag_results.history`: `{level, key_name, total, by_conclusion (all six keys),
last_seen (isoformat or null), examples}`. `matches`: `[{entry_id, level, content_sha256, score}]`, the
`score` being Voyage's relevance score in [0, 1]. `ranked`: `[{entry_id, score}]`, every candidate that was
scored, best first (`[]` for a lookup with no candidate left to rerank; NULL only on a `budget` or a `failed` row). `match_notes`: `{}`, a reranker writes no text. `failure_kind`
on a `failed` row.

`prompt_material` is the other half of V-R (spec §7.7, "At prompt time"): it is what ① and ② may put in
a prompt, from the database alone (the `worker` does not mount `kb_learned/`). Each match is re-checked
— the entry is active and `sha256(content)`, its stored `content_sha256` and the hash stored with the
match are one value — and a match that fails is dropped, the rest rendered with their level and their
percentage (`Match.pct`). A stored match with no valid `score` is not a match (the rows 020 wrote before the
score existed).
"""

from __future__ import annotations

import json
import math
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx
import psycopg
from psycopg.types.json import Jsonb

from app.audit.events import write_event
from app.infra import config
from app.infra.db import raise_idle_timeout
from app.infra.errors import PermanentError, TransientError
from app.infra.jobs import Job
from app.llm.builder import KbLearnedLevel
from app.rag import match, vector_store, voyage
from app.rag.budget import rag_spent_or_exhausted
from app.rag.candidates import VECTOR_HITS, by_ids, candidates, hybrid
from app.rag.entries import KB_LEARNED_ROOT, Entry, entry_by_id, file_matches, sha256_text
from app.rag.failures import RagUnavailable
from app.rag.fingerprint import Fingerprint, alert_fingerprint, case_fingerprint
from app.rag.history import (
    CONCLUSIONS,
    LEVELS,
    Exclusion,
    History,
    decision_history,
    render_history,
    self_exclusion,
)
from app.rag.match import MAX_MATCHES, Match
from app.rag.runs import write_rag_run
from app.rag.subject import Subject, parse_subject

#: The statuses of a lookup a prompt may use: a `failed` or `budget` row carries no material (`prompt_material`).
USABLE_STATUSES = ("ok", "empty")

#: `llm_runs.prompt_version` of a lookup's run: there is no prompt to hash, so it names the retrieval itself
#: (the vector search and the database search merged, then Voyage rerank).
RETRIEVAL_VERSION = "voyage_hybrid_v1"

#: What a `failed` row with no stored kind (the rows 020 wrote before migration 023) is told as: a closed word
#: for the notice, the nearest to "the retrieval did not work and nothing says why".
UNKNOWN_FAILURE_KIND = "provider_error"


@dataclass(frozen=True)
class LookupResult:
    """One stored lookup, as ① and ② read it. `history` is the decision history; `matches` the kept
    matches, closed values and a score; `failure_kind` why it `failed` (None for any other status, and for
    a `failed` row older than migration 023)."""

    lookup_id: uuid.UUID
    status: str
    history: History
    matches: tuple[Match, ...]
    created_at: datetime
    failure_kind: str | None = None


@dataclass(frozen=True)
class PromptMaterial:
    """What may reach a prompt: the history as `render_history` writes it (None when there is none)
    and the approved content of each matched entry with its level and its percentage (0-100), best
    first. Voyage's scores are here only as that percentage."""

    lookup_id: uuid.UUID
    history_text: str | None
    entries: tuple[tuple[KbLearnedLevel, int, str], ...]


def _log(payload: dict[str, Any]) -> None:
    print(json.dumps(payload))


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


def _is_score(value: Any) -> bool:
    """A relevance score as `rag.voyage.rerank` lets one through: a finite number in [0, 1], not a bool."""
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and 0 <= value <= 1
    )


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


def _matches_json(matches: list[Match]) -> list[dict[str, Any]]:
    return [
        {
            "entry_id": m.entry_id,
            "level": m.level.value,
            "content_sha256": m.content_sha256,
            "score": m.score,
        }
        for m in matches
    ]


def _matches_of(raw: Any) -> tuple[Match, ...]:
    """The stored matches; an item that is not one (a missing field, a level that is not one of the three,
    a score that is not a number in [0, 1]) is left out."""
    if not isinstance(raw, list):
        return ()
    found = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        entry_id, level, digest = (item.get(k) for k in ("entry_id", "level", "content_sha256"))
        if not all(isinstance(value, str) for value in (entry_id, level, digest)):
            continue
        score = item.get("score")
        if not _is_score(score):
            continue
        try:
            found.append(Match(entry_id, KbLearnedLevel(level), digest, float(score)))
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
    ranked: list[dict[str, Any]] | None = None,
    llm_run_id: uuid.UUID | None = None,
    failure_kind: str | None = None,
) -> None:
    conn.execute(
        "INSERT INTO rag_results (lookup_id, subject_kind, subject_id, status, history, matches,"
        " match_notes, llm_run_id, failure_kind, ranked)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (
            lookup_id,
            subject.kind,
            subject.id,
            status,
            Jsonb(_history_json(history)),
            Jsonb(_matches_json(matches or [])),
            Jsonb({}),  # a reranker writes no text
            llm_run_id,
            failure_kind,
            None if ranked is None else Jsonb(ranked),
        ),
    )
    entry = {"rag_lookup": status, "subject": subject.key}
    if failure_kind is not None:
        entry["failure_kind"] = failure_kind
    _log(entry)


def _store_failed(
    conn: psycopg.Connection,
    lookup_id: uuid.UUID,
    subject: Subject,
    history: History,
    kind: str,
    run_id: uuid.UUID | None,
) -> None:
    """The last word on a lookup that did not work: a `failed` row with its closed kind (what was known is
    kept) and the event the admin's audit page shows. Never the provider's words: there are none here.
    """
    _store(conn, lookup_id, subject, "failed", history, llm_run_id=run_id, failure_kind=kind)
    write_event(
        conn,
        "rag.lookup_failed",
        subject.id,
        "system",
        payload={"lookup_id": str(lookup_id), "failure_kind": kind},
    )


def _write_integrity_events(conn: psycopg.Connection, entry_ids: Sequence[str]) -> None:
    for entry_id in entry_ids:
        write_event(
            conn, "rag.integrity_failed", entry_id, "system", payload={"entry_id": entry_id}
        )


# ── what one attempt has done ─────────────────────────────────────────────────────────────────


@dataclass
class _Attempt:
    """What this attempt has sent, paid for and found, kept outside the `try` so that a failure still has it: a
    Voyage call that answered reports its tokens, one that failed reports none, and with no key there is no
    request at all (`requested` False: nothing to record)."""

    requested: bool = False
    embed_tokens: int = 0
    rerank_tokens: int = 0
    latency_ms: int = 0
    vector_hits: int = 0
    sent: int = 0
    integrity_failed: list[str] = field(default_factory=list)

    @property
    def paid(self) -> bool:
        return self.embed_tokens > 0 or self.rerank_tokens > 0

    def gate(self) -> dict[str, Any]:
        return {
            "integrity_failed": list(self.integrity_failed),
            "vector_hits": self.vector_hits,
            "candidates": self.sent,
        }


def _record_run(
    conn: psycopg.Connection,
    cfg: config.Config,
    subject: Subject,
    fp: Fingerprint,
    attempt: _Attempt,
    *,
    stopped_by: str | None,
    ranked: list[dict[str, Any]] | None,
    rag_lookup_id: uuid.UUID | None,
) -> uuid.UUID:
    """This attempt's one `llm_runs` row (`rag_lookup` / `retriever`): no prompt, the fingerprint as the user
    message, the ranking as the result (None when the lookup failed), both calls' tokens and their cost at
    Voyage's prices. A failure still carries what was paid for."""
    return write_rag_run(
        conn,
        run_id=uuid.uuid4(),
        pipeline="rag_lookup",
        role="retriever",
        subject=subject,
        system_prompt="",
        user_message=fp.text,
        result=None if ranked is None else {"ranked": ranked},
        gate_result=attempt.gate(),
        injection_findings=None,  # no model reads these texts
        input_tokens=attempt.embed_tokens + attempt.rerank_tokens,
        output_tokens=0,
        latency_ms=attempt.latency_ms,
        model_id=f"{cfg.RAG_EMBED_MODEL}+{cfg.RAG_RERANK_MODEL}",
        prompt_version=RETRIEVAL_VERSION,
        cost_usd=voyage.cost_usd(attempt.embed_tokens, attempt.rerank_tokens, cfg),
        stopped_by=stopped_by,
        rag_lookup_id=rag_lookup_id,
    )


# ── the job ───────────────────────────────────────────────────────────────────────────────────


def _fingerprint_of(conn: psycopg.Connection, subject: Subject) -> Fingerprint:
    if subject.kind == "alert":
        return alert_fingerprint(conn, subject.id)
    return case_fingerprint(conn, subject.id)


def _over_budget(conn: psycopg.Connection, cfg: config.Config) -> bool:
    """Whether the RAG's month, or the whole month, has reached its cap; asked once, before any call."""
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


def _is_archived(conn: psycopg.Connection, subject: Subject) -> bool:
    """Whether the subject was set aside by the archive (INT-T03, DEC-212): an `archived` alert or case.
    One that is not there is not "archived": the fingerprint says so with its `PermanentError`."""
    if subject.kind == "alert":
        row = conn.execute(
            "SELECT status FROM alerts WHERE alert_id = %s", (subject.id,)
        ).fetchone()
    else:
        row = conn.execute("SELECT status FROM cases WHERE case_id = %s", (subject.id,)).fetchone()
    return row is not None and row[0] == "archived"


def _candidates_of(
    conn: psycopg.Connection,
    cfg: config.Config,
    fp: Fingerprint,
    exclusion: Exclusion,
    attempt: _Attempt,
    client: httpx.Client | None,
    vconn: Any | None,
) -> list[Entry]:
    """Spec §5.3 steps 2-4: the query embedded, the nearest entries asked of `vectordb`, read back from the
    main database, and merged with the database search. The schema is made when `vectordb` has none (a fresh
    volume, before the first approval): a search of a table that is not there would be a bug, not an
    unreachable server."""
    attempt.requested = voyage.has_key(cfg)
    vectors, usage = voyage.embed([fp.text], input_type="query", cfg=cfg, client=client)
    attempt.embed_tokens = usage.total_tokens
    attempt.latency_ms += usage.latency_ms
    opened = None
    try:
        if vconn is None:
            opened = vconn = vector_store.connect(cfg)
        vector_store.ensure_schema(vconn)
        hit_ids = vector_store.nearest(
            vconn, vectors[0], model=cfg.RAG_EMBED_MODEL, limit=VECTOR_HITS
        )
    finally:
        if opened is not None:
            opened.close()
    attempt.vector_hits = len(hit_ids)
    return hybrid(by_ids(conn, hit_ids, exclusion), candidates(conn, fp, exclusion))


def _intact(cands: Sequence[Entry], attempt: _Attempt) -> list[Entry]:
    """The candidates that pass V-R1 and A4 (module doc, 4); the ids of the others are noted on `attempt`,
    once each, for the events."""
    intact: list[Entry] = []
    for cand in cands:
        if sha256_text(cand.content) == cand.content_sha256 and file_matches(cand, KB_LEARNED_ROOT):
            intact.append(cand)
        elif cand.entry_id not in attempt.integrity_failed:
            attempt.integrity_failed.append(cand.entry_id)
    return intact


def _retrieve(
    conn: psycopg.Connection,
    cfg: config.Config,
    fp: Fingerprint,
    exclusion: Exclusion,
    attempt: _Attempt,
    client: httpx.Client | None,
    vconn: Any | None,
) -> tuple[list[Match], list[dict[str, Any]]]:
    """Module doc, 4-5: the matches kept and the ranking of every candidate that was scored, best first.
    `RagUnavailable` reaches the caller; `attempt` has what was paid for by then."""
    intact = _intact(_candidates_of(conn, cfg, fp, exclusion, attempt, client, vconn), attempt)
    attempt.sent = len(intact)
    if not intact:
        return [], []  # nothing to rerank: no call
    scored, usage = match.score(fp, intact, cfg=cfg, client=client)
    attempt.rerank_tokens = usage.total_tokens
    attempt.latency_ms += usage.latency_ms
    ranked = [{"entry_id": found.entry_id, "score": value} for found, value in scored]
    return match.keep(scored, cfg), ranked


def run_lookup_job(
    conn: psycopg.Connection,
    job: Job,
    *,
    client: httpx.Client | None = None,
    vconn: Any | None = None,
) -> None:
    """Run one lookup (module doc). `client` is the `httpx` client the Voyage calls go through and `vconn` the
    connection to the vector database; both default to ones of the job's own (a client per call, a
    connection opened and closed), and every test passes its own."""
    cfg = config.load()
    raise_idle_timeout(conn, cfg)

    try:
        subject = parse_subject(job.subject_id)
    except ValueError:
        raise PermanentError(
            "rag_lookup: the job's subject is neither 'alert:<id>' nor 'case:<uuid>'"
        ) from None

    if _is_archived(conn, subject):
        # DEC-212: the archive does not cancel the jobs it leaves behind. Nothing reads the lookup of an
        # archived alert or case, so no history, no candidates, no Voyage call and no row.
        _log({"rag_lookup": "skipped", "reason": "archived", "subject": subject.key})
        return

    if _triage_has_finished(conn, subject):
        # ① read the newest lookup when it ran, and it has run: this one could reach no prompt, and a Voyage
        # call would be paid for nothing (a lookup queued behind other jobs, or retried after a rate limit,
        # is how it comes to be late)
        _log({"rag_lookup": "skipped", "reason": "late", "subject": subject.key})
        return

    fp = _fingerprint_of(conn, subject)  # PermanentError when the subject is not there
    exclusion = self_exclusion(conn, subject)
    history = decision_history(conn, subject, cfg)
    lookup_id = uuid.uuid4()

    if _over_budget(conn, cfg):
        _store(conn, lookup_id, subject, "budget", history)
        return

    attempt = _Attempt()
    try:
        matches, ranked = _retrieve(conn, cfg, fp, exclusion, attempt, client, vconn)
    except RagUnavailable as exc:
        if exc.kind == "rate_limit" and job.attempts <= 1:
            # Spec §5.3: one retry for a 429, 10 s later (`JOB_BACKOFF`), which is inside the time ① waits.
            if attempt.paid:
                # the embedding was paid for and the worker will roll this transaction back
                _record_run(
                    conn,
                    cfg,
                    subject,
                    fp,
                    attempt,
                    stopped_by=exc.kind,
                    ranked=None,
                    rag_lookup_id=None,
                )
                conn.commit()
            raise TransientError(exc.kind) from None
        _write_integrity_events(conn, attempt.integrity_failed)
        # No request, no run: an empty key is `failed` / `auth` in `rag_results` and its event, and not a
        # null-result `llm_runs` row for a call that never happened (review I1)
        run_id = (
            _record_run(
                conn,
                cfg,
                subject,
                fp,
                attempt,
                stopped_by=exc.kind,
                ranked=None,
                rag_lookup_id=lookup_id,
            )
            if attempt.requested
            else None
        )
        _store_failed(conn, lookup_id, subject, history, exc.kind, run_id)
        return

    _write_integrity_events(conn, attempt.integrity_failed)
    run_id = _record_run(
        conn, cfg, subject, fp, attempt, stopped_by=None, ranked=ranked, rag_lookup_id=lookup_id
    )
    status = "ok" if matches or history.total > 0 else "empty"
    _store(
        conn, lookup_id, subject, status, history, matches=matches, ranked=ranked, llm_run_id=run_id
    )


# ── what ① and ② read ─────────────────────────────────────────────────────────────────────────


def latest_lookup(
    conn: psycopg.Connection, subject: Subject, *, statuses: Sequence[str] | None = None
) -> LookupResult | None:
    """The newest stored lookup of `subject`, or None. By default whatever its status, which is how ①
    reads it. With `statuses`, the newest row among those statuses: ② passes `USABLE_STATUSES` because
    spec §7.6 says it uses "the newest `ok` row", and a `budget` refresh written after one must not hide it
    (a `failed` one does: `lookup_failure` is asked first, DEC-213). An empty `statuses` matches nothing.
    """
    query = (
        "SELECT lookup_id, status, history, matches, created_at, failure_kind FROM rag_results"
        " WHERE subject_kind = %s AND subject_id = %s"
    )
    params: list[Any] = [subject.kind, subject.id]
    if statuses is not None:
        query += " AND status = ANY(%s)"
        params.append(list(statuses))
    row = conn.execute(query + " ORDER BY created_at DESC, lookup_id LIMIT 1", params).fetchone()
    if row is None:
        return None
    lookup_id, status, history, matches, created_at, failure_kind = row
    return LookupResult(
        lookup_id, status, _history_of(history), _matches_of(matches), created_at, failure_kind
    )


def latest_status(conn: psycopg.Connection, subject: Subject) -> tuple[str, str | None] | None:
    """The newest lookup's status and failure kind, or None when there is no lookup. The kind is None for
    every status but `failed`, and for a `failed` row that has none stored (older than migration 023).
    """
    row = conn.execute(
        "SELECT status, failure_kind FROM rag_results WHERE subject_kind = %s AND subject_id = %s"
        " ORDER BY created_at DESC, lookup_id LIMIT 1",
        (subject.kind, subject.id),
    ).fetchone()
    return None if row is None else (row[0], row[1])


def lookup_failure(conn: psycopg.Connection, subject: Subject) -> str | None:
    """The closed failure kind when the subject's newest lookup (whatever came before it) `failed`, else
    None: what ① and ② add to their warnings as `rag_not_applied:<kind>` (DEC-213, spec §5.3) and why they
    render no learned section. A `failed` row with no stored kind reads as `UNKNOWN_FAILURE_KIND`. Read in a
    savepoint like `lookup_material`: the notice is an extra, and a database error in the read is no notice,
    never a failed ① or ②. The caller reads this only when its switch is on."""
    try:
        with conn.transaction():
            found = latest_status(conn, subject)
    except psycopg.Error as exc:
        _log({"rag_lookup": "unreadable", "subject": subject.key, "error": type(exc).__name__})
        return None
    if found is None or found[0] != "failed":
        return None
    return found[1] or UNKNOWN_FAILURE_KIND


def lookup_material(
    conn: psycopg.Connection, subject: Subject, *, statuses: Sequence[str] | None = None
) -> PromptMaterial | None:
    """What ① or ② may put in a prompt for `subject`: `prompt_material` of `latest_lookup`, read inside a
    savepoint (`conn.transaction()` joins the job's open transaction as a `SAVEPOINT`), None when the
    database refuses (P13 fix wave, item 23, Minor 3). The lookup is an extra: ① and ② must run without
    it. Without the savepoint the one error of a read (the table a dump restored from before 020 does not
    have, a statement timeout) aborts the whole transaction of a job that only wanted a hint, and with
    the switches on over such a dump ingestion, decisions and escalations fail with it. The caller reads
    this only when its switch is on, so with the switch off not one statement is added."""
    try:
        with conn.transaction():
            return prompt_material(conn, latest_lookup(conn, subject, statuses=statuses))
    except psycopg.Error as exc:
        _log({"rag_lookup": "unreadable", "subject": subject.key, "error": type(exc).__name__})
        return None


def prompt_material(conn: psycopg.Connection, result: LookupResult | None) -> PromptMaterial | None:
    """What ① or ② may put in its prompt for `result`, or None when it may put nothing, not even the
    sentence that says nothing was found: no lookup, or one that `failed` or ran out of `budget`.

    For `empty`, and for an `ok` whose matches all fail the re-check and that has no history, the
    material is empty (`history_text=None`, `entries=()`): the prompt says so in a fixed sentence
    (Review Focus 1). A match is dropped unless its entry is active and `sha256(content)`, the
    entry's `content_sha256` and the hash stored with the match are one value."""
    if result is None or result.status not in USABLE_STATUSES:
        return None
    entries: list[tuple[KbLearnedLevel, int, str]] = []
    for found in result.matches[:MAX_MATCHES]:
        entry = entry_by_id(conn, found.entry_id)
        if entry is None or entry.status != "active":
            continue
        if not (sha256_text(entry.content) == entry.content_sha256 == found.content_sha256):
            continue
        entries.append((found.level, found.pct, entry.content))
    history_text = render_history(result.history) if result.history.total > 0 else None
    return PromptMaterial(result.lookup_id, history_text, tuple(entries))
