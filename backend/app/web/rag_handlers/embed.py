"""`knowledge_embed`'s handler: keep the vector database true to the main one (P14-T05, DEC-213, spec §5.2).

The job's subject is an entry's uuid as text. It is enqueued, in the same transaction, by every write that
changes an entry: an approval and a retirement (`rag.publish`) and a merge (`rag.draft`). Only `rag-worker`
claims and reclaims it (`web/rag_worker.py`). The job reads the entry in the main database, which is the only
source of its content, status and hash, and makes `entry_vectors` say the same:

* **active, and the stored row is missing or differs in hash, model or dims:** embed the entry's digest
  (`rag.match.entry_digest`: its closed fields, title and summary; spec §5.5, nothing else leaves) as a
  `document` and upsert the row with the entry's `content_sha256`;
* **active, and the row is current:** nothing, and no request (a merge enqueues the job and changes neither
  the content nor the hash);
* **not active, or not there at all:** delete the row (no Voyage call, so a retirement needs no key).

**Failures** are the closed kinds of `rag.failures` and nothing the provider wrote (Review Focus 2): a kind
a later attempt can cure (`rate_limit`, `timeout`, `provider_error`, `vectordb_unreachable`) raises
`TransientError(kind)`, which the worker retries with its backoff; `auth` (a key that is missing or refused)
and `quota` (402) raise `PermanentError(kind)`, because trying again cannot help and the Owner has to act.
The kind is the job's `last_error`. A failed job leaves the entry without a vector (or with the old one);
`python -m app.rag.vector_index --check` shows it, `--rebuild` repairs it, and a lookup re-checks every
vector it finds against the main database anyway (spec §5.1).

**No `llm_runs` row** (spec §5.6, Director's call): about 300 tokens an approval is under $0.01 for the
whole lab. The job logs the tokens, one JSON line.

**A change that lands while the job runs.** `enqueue` is single-flight over pending AND running jobs, so a
retirement committed while this job waits for Voyage enqueues nothing. The job therefore reads the entry
again under a share lock (`_state`, `FOR SHARE`) after the call, and on the unchanged path too, before it
stores or skips anything: if its status or hash is no longer what was read, nothing is stored and the job
asks to run once more (`Reschedule`), which then sees the new state. A retirement that starts after the lock
waits for this transaction to commit, and its own `enqueue` then succeeds: no change is lost either way.

**The transaction.** The worker runs the handler in one transaction of the main database; a Voyage call is
idle time to it, so the first statement raises `idle_in_transaction_session_timeout` to `JOB_LOCK_TIMEOUT_S`
(`infra.db.raise_idle_timeout`, which `rag.lookup` and `rag.draft` call too). The vector database is another connection, in autocommit, opened for
the job and closed after it unless the caller gives one.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import httpx
import psycopg

from app.infra import config
from app.infra.db import raise_idle_timeout
from app.infra.errors import PermanentError, TransientError
from app.infra.jobs import Job, Reschedule
from app.rag import match, vector_store, voyage
from app.rag.entries import entry_by_id
from app.rag.failures import TRANSIENT_KINDS, RagUnavailable

JOB_TYPE = "knowledge_embed"

#: How long the follow-up run waits after a change that landed during the call (a second is enough for the
#: change's own transaction to be over).
RESCHEDULE_S = 2.0


def _log(payload: dict[str, Any]) -> None:
    print(json.dumps(payload))


def _entry_id(job: Job) -> str:
    try:
        return str(uuid.UUID(job.subject_id))
    except ValueError:
        raise PermanentError("knowledge_embed: the job's subject is not an entry uuid") from None


def _job_error(kind: str) -> Exception:
    """`TransientError(kind)` for a kind that a later attempt can cure, `PermanentError(kind)` for one that
    needs a person (`auth`, `quota`). The message is the kind: it becomes the job's `last_error`."""
    return TransientError(kind) if kind in TRANSIENT_KINDS else PermanentError(kind)


def _state(conn: psycopg.Connection, entry_id: str) -> tuple[str, str] | None:
    """(status, content_sha256) of the entry now, or None, read `FOR SHARE`.

    The share lock is the point. `retire_published` locks the row `FOR UPDATE`, so a retirement either
    committed before this read (which then sees it) or waits for this transaction to commit, and its own
    `enqueue` then finds no live job and succeeds. Without the lock a retirement could commit just after
    the read, enqueue nothing (this job is still running) and be lost. The lock is taken after the Voyage
    call, never before it, so it is held for milliseconds, not for the length of a call."""
    row = conn.execute(
        "SELECT status, content_sha256 FROM knowledge_entries WHERE entry_id = %s FOR SHARE",
        (entry_id,),
    ).fetchone()
    return None if row is None else (row[0], row[1])


def _sync(
    conn: psycopg.Connection,
    vconn: Any,
    entry_id: str,
    cfg: config.Config,
    client: httpx.Client | None,
) -> Reschedule | None:
    entry = entry_by_id(conn, entry_id)
    vector_store.ensure_schema(vconn)

    if entry is None or entry.status != "active":
        vector_store.delete(vconn, entry_id)
        _log({"knowledge_embed": "deleted", "entry_id": entry_id})
        return None

    current = (entry.content_sha256, cfg.RAG_EMBED_MODEL, cfg.RAG_EMBED_DIMS)
    if vector_store.stored_one(vconn, entry_id) == current:
        if _state(conn, entry_id) != ("active", entry.content_sha256):
            _log({"knowledge_embed": "changed_before_the_check", "entry_id": entry_id})
            return Reschedule(RESCHEDULE_S)
        _log({"knowledge_embed": "unchanged", "entry_id": entry_id})
        return None

    vectors, usage = voyage.embed(
        [match.entry_digest(entry)], input_type="document", cfg=cfg, client=client
    )
    if _state(conn, entry_id) != ("active", entry.content_sha256):
        _log(
            {
                "knowledge_embed": "changed_during_the_call",
                "entry_id": entry_id,
                "tokens": usage.total_tokens,
            }
        )
        return Reschedule(RESCHEDULE_S)
    vector_store.upsert(
        vconn,
        entry_id=entry_id,
        content_sha256=entry.content_sha256,
        model=cfg.RAG_EMBED_MODEL,
        vector=vectors[0],
    )
    _log({"knowledge_embed": "embedded", "entry_id": entry_id, "tokens": usage.total_tokens})
    return None


def run_embed_job(
    conn: psycopg.Connection,
    job: Job,
    *,
    client: httpx.Client | None = None,
    vconn: Any | None = None,
) -> Reschedule | None:
    """Run one `knowledge_embed` job (module doc). `client` and `vconn` default to a Voyage client and a
    connection of its own; every test passes its own."""
    cfg = config.load()
    raise_idle_timeout(conn, cfg)
    entry_id = _entry_id(job)
    opened = None
    try:
        if vconn is None:
            opened = vconn = vector_store.connect(cfg)
        return _sync(conn, vconn, entry_id, cfg, client)
    except RagUnavailable as exc:
        raise _job_error(exc.kind) from None
    finally:
        if opened is not None:
            opened.close()


handle = run_embed_job
