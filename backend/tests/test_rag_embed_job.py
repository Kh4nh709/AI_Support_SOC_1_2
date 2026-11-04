"""P14-T05 / DEC-213, spec §5.2 — the `knowledge_embed` job: `web.rag_handlers.embed.run_embed_job`.

The job's subject is an entry's uuid. It makes the vector database say what the main database says:

    active, no stored row, or a row whose hash, model or dims differ   -> embed the entry's digest
                                                                          (`match.entry_digest`) as a
                                                                          `document`, upsert the row
    active, the row is current                                         -> nothing, and NO request
    retired, or not there at all                                       -> delete its row

Failures (Review Focus 2, the split of transient and permanent):

    rate_limit  timeout  provider_error  vectordb_unreachable   -> `TransientError(kind)`: retried
    auth  quota                                                  -> `PermanentError(kind)`: failed now

The job writes no `llm_runs` row (about 300 tokens a approval, spec §5.6); it logs the tokens only.

`store` runs every test over a dictionary (`memory`) and over a real pgvector (`pgvector`, skipped unless
`VECTOR_TEST_DATABASE_URL` is set): `tests/vector_data.py`. The enqueue sites are tested where the
writes are: `test_rag_publish.py` (approve and retire) and `test_rag_draft.py` (the merge).
"""

from __future__ import annotations

import dataclasses
import json
import threading
import time
import uuid
from contextlib import ExitStack

import httpx
import psycopg
import pytest
from app.infra import config
from app.infra.config import Config
from app.infra.errors import PermanentError, TransientError, classify
from app.infra.jobs import Job, Reschedule, claim_job, enqueue, finish_job
from app.infra.worker import run_forever
from app.rag import match, publish, vector_store
from app.rag.entries import enqueue_embed, entry_by_id, render_entry_markdown
from app.rag.failures import RagUnavailable
from app.web import rag_handlers
from app.web.rag_handlers import embed as embed_handler

from tests.scratch_db import insert_user, scratch_database
from tests.test_rag_publish import admin, decided_alert, pending_draft, root  # noqa: F401
from tests.test_rag_voyage import CFG, DIMS, KEY, PROVIDER_WORDS, Server, embed_reply
from tests.vector_data import STORE_KINDS, entry, make_store

JOB_CFG = dataclasses.replace(CFG, VECTOR_DATABASE_URL="", RAG_ENABLED=True)


@pytest.fixture(params=STORE_KINDS)
def store(request, monkeypatch):
    with ExitStack() as stack:
        yield make_store(request.param, monkeypatch, stack)


@pytest.fixture(autouse=True)
def job_config(monkeypatch):
    """The job reads `config.load()`: a key that is not real, 256 numbers a vector, the RAG on (the
    approvals and retirements of the end-to-end test enqueue the job only then)."""
    monkeypatch.setattr(config, "load", lambda *a, **kw: JOB_CFG)


def job_for(subject: str, *, attempts: int = 1) -> Job:
    return Job(job_id=1, job_type="knowledge_embed", subject_id=subject, attempts=attempts)


def run(db, store, subject: str, server: Server | None = None, **kw):
    server = server if server is not None else Server(embed_reply(1))
    return embed_handler.run_embed_job(
        db, job_for(subject), client=server.client, vconn=store.conn, **kw
    )


def sha_of(db, entry_id: str) -> str:
    return entry_by_id(db, entry_id).content_sha256


def jobs_of(db, job_type: str = "knowledge_embed") -> list[tuple[str, str]]:
    return db.execute(
        "SELECT subject_id, status FROM jobs WHERE job_type = %s ORDER BY job_id", (job_type,)
    ).fetchall()


# ── the handler is registered ─────────────────────────────────────────────────────────────────


def test_the_handler_module_follows_the_contract() -> None:
    assert embed_handler.JOB_TYPE == "knowledge_embed"
    assert embed_handler.handle is embed_handler.run_embed_job  # not wrapped: tests pass `client`
    assert rag_handlers.iter_handlers()["knowledge_embed"] is embed_handler.run_embed_job


# ── active: embed ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.db
def test_an_active_entry_with_no_row_is_embedded_as_a_document_and_stored(db, store) -> None:
    entry_id = entry(db)
    server = Server(embed_reply(1, tokens=44))

    assert run(db, store, entry_id, server) is None

    (request,) = server.requests
    assert str(request.url) == "https://voyage.test/v1/embeddings"
    body = server.body()
    assert body["input_type"] == "document" and body["model"] == "voyage-4"
    assert body["output_dimension"] == DIMS
    assert body["input"] == [match.entry_digest(entry_by_id(db, entry_id))]
    assert store.rows() == {entry_id: (sha_of(db, entry_id), "voyage-4", DIMS)}
    assert store.vector(entry_id) == pytest.approx([0.0] + [0.5] * (DIMS - 1))


@pytest.mark.db
def test_only_the_digest_leaves_never_the_whole_entry_or_the_key(db, store) -> None:
    """Spec §5.5: what goes to Voyage is the entry's digest (closed fields, title, summary)."""
    entry_id = entry(db)
    server = Server(embed_reply(1))
    run(db, store, entry_id, server)

    sent = server.requests[0].content.decode()
    assert "Quét cổng định kỳ" in sent and "port_scan" in sent  # the digest
    assert "SECTION-AFTER-THE-SUMMARY-NEVER-SENT" not in sent  # not the sections after the summary
    assert KEY not in sent and "Authorization" not in sent  # the key is a header, not a body
    assert server.requests[0].headers["authorization"] == f"Bearer {KEY}"


@pytest.mark.db
def test_a_current_row_is_left_alone_and_no_request_is_made(db, store) -> None:
    entry_id = entry(db)
    run(db, store, entry_id)
    before = store.rows()

    again = Server(embed_reply(1))
    run(db, store, entry_id, again)

    assert again.requests == []
    assert store.rows() == before


@pytest.mark.db
@pytest.mark.parametrize("what", ["hash", "model", "dims"])
def test_a_row_that_differs_in_hash_model_or_dims_is_embedded_again(db, store, what) -> None:
    entry_id = entry(db)
    sha = sha_of(db, entry_id)
    old = {
        "hash": ("f" * 64, "voyage-4", 3),
        "model": (sha, "voyage-3", 3),
        "dims": (sha, "voyage-4", 3),
    }[what]
    store.put(entry_id, old[0], old[1], [1.0, 0.0, 0.0])
    assert store.rows()[entry_id] == (old[0], old[1], 3)

    server = Server(embed_reply(1))
    run(db, store, entry_id, server)

    assert len(server.requests) == 1
    assert store.rows() == {entry_id: (sha, "voyage-4", DIMS)}


@pytest.mark.db
def test_an_edit_of_the_content_is_embedded_again_with_the_new_hash(db, store) -> None:
    entry_id = entry(db)
    run(db, store, entry_id)
    first = store.rows()[entry_id][0]

    new_content = render_entry_markdown(
        {
            "entry_id": entry_id,
            "version": 2,
            "title": "Tiêu đề mới",
            "conclusion": "closed_fp",
            "category": "recon",
            "summary": "Tóm tắt khác.",
        }
    )
    db.execute(
        "UPDATE knowledge_entries SET content = %s, content_sha256 = encode(sha256(%s::bytea),"
        " 'hex') WHERE entry_id = %s",
        (new_content, new_content.encode(), entry_id),
    )
    server = Server(embed_reply(1))
    run(db, store, entry_id, server)

    assert len(server.requests) == 1 and "Tiêu đề mới" in server.requests[0].content.decode()
    assert store.rows()[entry_id][0] == sha_of(db, entry_id) != first


@pytest.mark.db
def test_the_subject_may_be_written_in_upper_case(db, store) -> None:
    entry_id = entry(db)
    run(db, store, entry_id.upper())
    assert list(store.rows()) == [entry_id]


@pytest.mark.db
def test_the_schema_is_made_when_the_vector_database_has_none(db, store) -> None:
    """A fresh `vectordb` has no table: the first job makes it (spec §5.1, create-if-absent). M3: on the
    real pgvector too. The table is dropped first, and the job leaves a table with the entry's row.
    """
    entry_id = entry(db)
    store.drop_schema()
    assert not store.has_schema()

    run(db, store, entry_id)

    assert store.has_schema() and list(store.rows()) == [entry_id]


@pytest.mark.db
def test_a_one_entry_job_reads_one_row_not_the_table(db, store, monkeypatch) -> None:
    """M6."""
    entry_id = entry(db)
    other = entry(db)
    store.put(other, "e" * 64, "voyage-4", [0.5] * DIMS)

    def whole_table(vconn):
        raise AssertionError("the job read every row of entry_vectors")

    with monkeypatch.context() as patched:
        patched.setattr(vector_store, "stored", whole_table)
        run(db, store, entry_id)
        run(db, store, entry_id)  # the second finds its own row current
    assert sorted(store.rows()) == sorted([entry_id, other])


# ── not active, or not there: delete ──────────────────────────────────────────────────────────


@pytest.mark.db
@pytest.mark.parametrize("status", ["retired"])
def test_an_entry_that_is_not_active_loses_its_row_and_no_request_is_made(
    db, store, status
) -> None:
    entry_id = entry(db)
    run(db, store, entry_id)
    assert entry_id in store.rows()
    db.execute("UPDATE knowledge_entries SET status = %s WHERE entry_id = %s", (status, entry_id))

    server = Server(embed_reply(1))
    run(db, store, entry_id, server)

    assert store.rows() == {} and server.requests == []


@pytest.mark.db
def test_an_entry_that_is_not_in_the_main_database_loses_its_row(db, store) -> None:
    ghost = str(uuid.uuid4())
    store.put(ghost, "e" * 64, "voyage-4", [1.0, 0.0, 0.0])
    other = entry(db)
    run(db, store, other)

    server = Server(embed_reply(1))
    run(db, store, ghost, server)

    assert list(store.rows()) == [other] and server.requests == []


@pytest.mark.db
def test_deleting_what_is_not_stored_is_nothing(db, store) -> None:
    entry_id = entry(db, status="retired")
    server = Server(embed_reply(1))
    assert run(db, store, entry_id, server) is None
    assert store.rows() == {} and server.requests == []


@pytest.mark.db
def test_a_delete_needs_no_key(db, store, monkeypatch) -> None:
    """Retiring an entry must work on a deployment whose Voyage key is gone."""
    monkeypatch.setattr(
        config, "load", lambda *a, **kw: dataclasses.replace(JOB_CFG, VOYAGE_API_KEY="")
    )
    entry_id = entry(db, status="retired")
    store.put(entry_id, "e" * 64, "voyage-4", [1.0, 0.0])
    run(db, store, entry_id)
    assert store.rows() == {}


@pytest.mark.db
def test_a_subject_that_is_no_uuid_is_permanent_and_touches_nothing(db, store) -> None:
    server = Server(embed_reply(1))
    for subject in ("alert:123", "", "not-a-uuid", "1' OR '1'='1"):
        with pytest.raises(PermanentError, match="knowledge_embed"):
            run(db, store, subject, server)
    assert server.requests == [] and store.rows() == {}


# ── failures: the split (Review Focus 2) ──────────────────────────────────────────────────────

KINDS = [
    (429, "rate_limit", TransientError, "transient"),
    (500, "provider_error", TransientError, "transient"),
    (503, "provider_error", TransientError, "transient"),
    (400, "provider_error", TransientError, "transient"),
    (401, "auth", PermanentError, "permanent"),
    (403, "auth", PermanentError, "permanent"),
    (402, "quota", PermanentError, "permanent"),
]


@pytest.mark.db
@pytest.mark.parametrize(("status", "kind", "error", "outcome"), KINDS)
def test_each_http_failure_is_transient_or_permanent_by_its_kind(
    db, store, status, kind, error, outcome
) -> None:
    entry_id = entry(db)
    with pytest.raises(error) as caught:
        run(db, store, entry_id, Server({"detail": PROVIDER_WORDS}, status=status))
    exc = caught.value
    assert type(exc) is error and str(exc) == kind
    assert classify(exc) == outcome
    assert PROVIDER_WORDS not in str(exc) + repr(exc)
    assert store.rows() == {}  # nothing half-written


@pytest.mark.db
def test_a_timeout_is_transient(db, store) -> None:
    entry_id = entry(db)
    with pytest.raises(TransientError) as caught:
        run(db, store, entry_id, Server(httpx.ReadTimeout("slow")))
    assert str(caught.value) == "timeout" and classify(caught.value) == "transient"


@pytest.mark.db
def test_an_empty_key_is_permanent_auth_and_sends_nothing(db, store, monkeypatch) -> None:
    monkeypatch.setattr(
        config, "load", lambda *a, **kw: dataclasses.replace(JOB_CFG, VOYAGE_API_KEY="")
    )
    entry_id = entry(db)
    server = Server(embed_reply(1))
    with pytest.raises(PermanentError) as caught:
        run(db, store, entry_id, server)
    assert str(caught.value) == "auth" and classify(caught.value) == "permanent"
    assert server.requests == []


@pytest.mark.db
def test_an_answer_of_the_wrong_size_is_transient_and_stores_nothing(db, store) -> None:
    entry_id = entry(db)
    with pytest.raises(TransientError) as caught:
        run(db, store, entry_id, Server(embed_reply(1, dims=DIMS - 1)))
    assert str(caught.value) == "provider_error"
    assert store.rows() == {}


@pytest.mark.db
def test_a_vector_database_that_cannot_be_reached_is_transient(db, monkeypatch) -> None:
    """No `vconn` is given and `VECTOR_DATABASE_URL` is empty: `vector_store.connect` says so."""
    entry_id = entry(db)
    server = Server(embed_reply(1))
    with pytest.raises(TransientError) as caught:
        embed_handler.run_embed_job(db, job_for(entry_id), client=server.client)
    assert str(caught.value) == "vectordb_unreachable"
    assert classify(caught.value) == "transient"
    assert server.requests == []  # it is not asked to pay for an embedding it cannot store


@pytest.mark.db
def test_a_connection_that_is_lost_while_reading_is_transient(db, monkeypatch) -> None:
    entry_id = entry(db)

    def lost(vconn):
        raise RagUnavailable("vectordb_unreachable")

    monkeypatch.setattr(vector_store, "ensure_schema", lost)
    server = Server(embed_reply(1))
    with pytest.raises(TransientError) as caught:
        embed_handler.run_embed_job(db, job_for(entry_id), client=server.client, vconn=object())
    assert str(caught.value) == "vectordb_unreachable" and server.requests == []


@pytest.mark.db
def test_a_delete_that_cannot_reach_the_vector_database_is_transient(db, monkeypatch) -> None:
    entry_id = entry(db, status="retired")
    with pytest.raises(TransientError) as caught:
        embed_handler.run_embed_job(db, job_for(entry_id), client=Server(None).client)
    assert str(caught.value) == "vectordb_unreachable"


# ── what it opens it closes ───────────────────────────────────────────────────────────────────


@pytest.mark.db
def test_the_connection_the_job_opened_is_closed_after_success_and_after_failure(
    db, monkeypatch
) -> None:
    from tests.vector_data import MemoryStore

    store = MemoryStore(monkeypatch)
    monkeypatch.setattr(vector_store, "connect", lambda cfg: store.conn)
    entry_id = entry(db)

    embed_handler.run_embed_job(db, job_for(entry_id), client=Server(embed_reply(1)).client)
    assert store.conn.closed and list(store.rows()) == [entry_id]

    store.conn.closed = False
    other = entry(db)
    with pytest.raises(PermanentError):
        embed_handler.run_embed_job(
            db, job_for(other), client=Server({"detail": "x"}, status=401).client
        )
    assert store.conn.closed


@pytest.mark.db
def test_a_connection_that_was_given_is_not_closed(db, store) -> None:
    run(db, store, entry(db))
    assert not store.conn.closed


# ── the log, the budget, the transaction ──────────────────────────────────────────────────────


@pytest.mark.db
def test_it_logs_the_tokens_and_writes_no_llm_run(db, store, capsys) -> None:
    entry_id = entry(db)
    before = db.execute("SELECT count(*) FROM llm_runs").fetchone()[0]

    run(db, store, entry_id, Server(embed_reply(1, tokens=312)))

    assert db.execute("SELECT count(*) FROM llm_runs").fetchone()[0] == before
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.strip()]
    (embedded,) = [line for line in lines if line.get("knowledge_embed") == "embedded"]
    assert embedded["tokens"] == 312 and embedded["entry_id"] == entry_id
    assert KEY not in json.dumps(lines)


@pytest.mark.db
def test_the_log_of_a_skip_and_a_delete_names_them(db, store, capsys) -> None:
    entry_id = entry(db)
    run(db, store, entry_id)
    run(db, store, entry_id)
    db.execute("UPDATE knowledge_entries SET status = 'retired' WHERE entry_id = %s", (entry_id,))
    run(db, store, entry_id)

    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.strip()]
    assert [line["knowledge_embed"] for line in lines] == ["embedded", "unchanged", "deleted"]


@pytest.mark.db
def test_the_provider_words_are_not_logged(db, store, capsys) -> None:
    entry_id = entry(db)
    with pytest.raises(TransientError):
        run(db, store, entry_id, Server({"detail": PROVIDER_WORDS}, status=500))
    seen = capsys.readouterr()
    assert PROVIDER_WORDS not in seen.out + seen.err


@pytest.mark.db
def test_the_wait_for_voyage_is_not_killed_by_the_idle_in_transaction_timeout(db, store) -> None:
    """`infra.db.transaction()` allows 10 s idle in the transaction and a Voyage call may take 15:
    like the other RAG jobs, the first statement raises it to `JOB_LOCK_TIMEOUT_S`."""
    seen: list[bool] = []

    def handler(request: httpx.Request) -> httpx.Response:
        (ok,) = db.execute(
            "SELECT current_setting('idle_in_transaction_session_timeout')::interval"
            " = %s * interval '1 second'",
            (JOB_CFG.JOB_LOCK_TIMEOUT_S,),
        ).fetchone()
        seen.append(ok)
        return httpx.Response(200, json=embed_reply(1))

    entry_id = entry(db)
    embed_handler.run_embed_job(
        db,
        job_for(entry_id),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        vconn=store.conn,
    )
    assert seen == [True]


# ── an entry that changes while Voyage is answering ───────────────────────────────────────────


@pytest.mark.db
def test_an_entry_retired_during_the_call_is_not_stored_and_the_job_asks_to_run_again(
    db, store
) -> None:
    """`enqueue` is single-flight over pending AND running jobs, so a change that commits while this job
    runs enqueues nothing. The job looks again after the call: a changed entry is not stored and the
    worker runs the job once more (`Reschedule`), which then sees the new state."""
    entry_id = entry(db)

    def handler(request: httpx.Request) -> httpx.Response:
        db.execute(
            "UPDATE knowledge_entries SET status = 'retired' WHERE entry_id = %s", (entry_id,)
        )
        return httpx.Response(200, json=embed_reply(1))

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = embed_handler.run_embed_job(db, job_for(entry_id), client=client, vconn=store.conn)

    assert isinstance(result, Reschedule) and result.delay_s > 0
    assert store.rows() == {}

    again = Server(embed_reply(1))
    assert run(db, store, entry_id, again) is None  # retired: a delete, no request
    assert again.requests == [] and store.rows() == {}


@pytest.mark.db
def test_an_entry_edited_during_the_call_is_not_stored_with_the_old_hash(db, store) -> None:
    entry_id = entry(db)

    def handler(request: httpx.Request) -> httpx.Response:
        db.execute(
            "UPDATE knowledge_entries SET content_sha256 = %s WHERE entry_id = %s",
            ("c" * 64, entry_id),
        )
        return httpx.Response(200, json=embed_reply(1))

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = embed_handler.run_embed_job(db, job_for(entry_id), client=client, vconn=store.conn)

    assert isinstance(result, Reschedule) and store.rows() == {}


# ── the whole path: approve, run, retire, run ─────────────────────────────────────────────────


@pytest.mark.db
def test_approve_makes_a_row_and_retire_takes_it_away(db, store, root) -> None:  # noqa: F811
    admin_id = admin(db)
    draft_id = pending_draft(db, f"alert:{decided_alert(db)}")
    entry_id = str(publish.approve(db, draft_id, admin_id, root=root))

    job = claim_job(db, ["knowledge_embed"])
    assert job is not None and job.subject_id == entry_id
    embed_handler.run_embed_job(db, job, client=Server(embed_reply(1)).client, vconn=store.conn)
    finish_job(db, job, outcome="succeeded")
    assert store.rows() == {entry_id: (sha_of(db, entry_id), "voyage-4", DIMS)}

    publish.retire(db, entry_id, admin_id, "Không còn đúng", root=root)
    job = claim_job(db, ["knowledge_embed"])
    assert job is not None and job.subject_id == entry_id
    server = Server(embed_reply(1))
    embed_handler.run_embed_job(db, job, client=server.client, vconn=store.conn)
    finish_job(db, job, outcome="succeeded")

    assert store.rows() == {} and server.requests == []
    assert [status for _, status in jobs_of(db)] == ["succeeded", "succeeded"]


@pytest.mark.db
def test_the_job_type_is_one_the_database_accepts_and_one_the_rag_worker_claims(db) -> None:
    from app.web import rag_worker

    assert "knowledge_embed" in rag_worker.HANDLERS
    db.execute(
        "INSERT INTO jobs (job_type, subject_id) VALUES ('knowledge_embed', %s)",
        (str(uuid.uuid4()),),
    )
    assert claim_job(db, list(rag_worker.HANDLERS)) is not None


def test_the_config_double_is_not_the_real_one() -> None:
    """The tests above run with a key that is not real; nothing here may reach a real network."""
    assert KEY.startswith("test-key-not-a-real")
    assert isinstance(JOB_CFG, Config) and JOB_CFG.VOYAGE_BASE_URL == "https://voyage.test/v1"


# ── enqueueing is the RAG's: only with RAG_ENABLED (Director ruling a) ─────────────────────────


@pytest.mark.db
@pytest.mark.parametrize("enabled", [True, False])
def test_enqueue_embed_enqueues_only_with_the_rag_on(db, monkeypatch, enabled) -> None:
    """With the RAG off nothing needs vectors, and a stack with no `rag-worker` would keep a backlog."""
    monkeypatch.setattr(
        config, "load", lambda *a, **kw: dataclasses.replace(JOB_CFG, RAG_ENABLED=enabled)
    )
    entry_id = entry(db)
    enqueue_embed(db, entry_id)
    enqueue_embed(db, uuid.UUID(entry_id))  # an id of either type; single-flight: still one job
    assert jobs_of(db) == ([(entry_id, "pending")] if enabled else [])


# ── a retirement that races the job: two real connections (M1, M4) ─────────────────────────────
#
# `enqueue` is single-flight over pending AND running jobs, so a retirement committed while the job
# runs enqueues nothing. The job therefore re-reads the entry `FOR SHARE` (`retire_published` locks the
# row `FOR UPDATE`): the retirement either committed before that read (the job sees it and asks to run
# again) or waits until the job commits, and then its own enqueue succeeds. Neither loses the job.


@pytest.fixture(scope="module")
def scratch_dsn():
    with scratch_database("p14t05embed") as dsn:
        yield dsn


def committed_entry(dsn, store) -> tuple[str, str]:
    """An active entry in the scratch database, its embed job pending as the approval left it, and (when
    `store` is given) a current row for it in the vector database. Returns (entry id, an admin's id).
    """
    with psycopg.connect(dsn) as setup:
        entry_id = entry(setup)
        admin_id = insert_user(setup, "admin")
        enqueue(setup, "knowledge_embed", entry_id)
        (sha,) = setup.execute(
            "SELECT content_sha256 FROM knowledge_entries WHERE entry_id = %s", (entry_id,)
        ).fetchone()
        setup.commit()
    if store is not None:
        store.put(entry_id, sha, "voyage-4", [0.5] * DIMS)
    return entry_id, admin_id


def job_statuses(dsn, entry_id: str) -> list[str]:
    with psycopg.connect(dsn) as observer:
        return [
            status
            for (status,) in observer.execute(
                "SELECT status FROM jobs WHERE job_type = 'knowledge_embed' AND subject_id = %s"
                " ORDER BY job_id",
                (entry_id,),
            )
        ]


def cycle(dsn, store, client) -> None:
    """One cycle of the real worker loop on a connection of its own: claim, run, finish, reschedule."""
    handlers = {
        "knowledge_embed": lambda conn, job: embed_handler.run_embed_job(
            conn, job, client=client, vconn=store.conn
        )
    }
    conn = psycopg.connect(dsn)
    try:
        run_forever(lambda: conn, handlers, once=True)
    finally:
        conn.close()


def make_due(dsn, entry_id: str) -> None:
    with psycopg.connect(dsn) as conn:
        conn.execute(
            "UPDATE jobs SET scheduled_at = now() WHERE job_type = 'knowledge_embed'"
            " AND subject_id = %s AND status = 'pending'",
            (entry_id,),
        )
        conn.commit()


def retire_committed(dsn, entry_id: str, admin_id: str, kb_dir) -> None:
    """The admin's retirement, on a connection of its own, committed."""
    with psycopg.connect(dsn, options="-c lock_timeout=15000") as admin_conn:
        publish.retire_published(admin_conn, entry_id, admin_id, "lý do", root=kb_dir)
        admin_conn.commit()


@pytest.mark.db
def test_a_retirement_committed_during_the_call_leaves_no_vector_and_loses_no_job(
    scratch_dsn, store, tmp_path
) -> None:
    entry_id, admin_id = committed_entry(scratch_dsn, None)
    retired: list[bool] = []

    def voyage(request: httpx.Request) -> httpx.Response:
        # commits while the job waits for Voyage
        retire_committed(scratch_dsn, entry_id, admin_id, tmp_path)
        retired.append(True)
        return httpx.Response(200, json=embed_reply(1))

    cycle(scratch_dsn, store, httpx.Client(transport=httpx.MockTransport(voyage)))

    assert retired == [True]
    assert store.rows() == {}  # the retired entry was not stored
    # the retirement's own enqueue found the job running and did nothing; the job asked for the next run
    assert job_statuses(scratch_dsn, entry_id) == ["succeeded", "pending"]

    make_due(scratch_dsn, entry_id)
    later = Server(embed_reply(1))
    cycle(scratch_dsn, store, later.client)
    assert later.requests == [] and store.rows() == {}  # a retired entry: a delete, no request
    assert job_statuses(scratch_dsn, entry_id) == ["succeeded", "succeeded"]


@pytest.mark.db
def test_a_retirement_before_the_locked_read_of_an_unchanged_row_is_seen(
    scratch_dsn, store, tmp_path, monkeypatch
) -> None:
    """The unchanged path (the row is current, no request) re-reads under the same lock."""
    entry_id, admin_id = committed_entry(scratch_dsn, store)
    read_one = vector_store.stored_one

    def read_then_a_retirement(vconn, wanted):
        found = read_one(vconn, wanted)
        retire_committed(scratch_dsn, entry_id, admin_id, tmp_path)
        return found

    quiet = Server(embed_reply(1))
    with monkeypatch.context() as patched:
        patched.setattr(vector_store, "stored_one", read_then_a_retirement)
        cycle(scratch_dsn, store, quiet.client)

    assert quiet.requests == []
    assert list(store.rows()) == [entry_id]  # still there: the next run deletes it
    assert job_statuses(scratch_dsn, entry_id) == ["succeeded", "pending"]

    make_due(scratch_dsn, entry_id)
    cycle(scratch_dsn, store, quiet.client)
    assert store.rows() == {} and job_statuses(scratch_dsn, entry_id) == ["succeeded", "succeeded"]


def wait_for_a_lock_wait(dsn, timeout_s: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout_s
    with psycopg.connect(dsn, autocommit=True) as watcher:
        while time.monotonic() < deadline:
            (waiting,) = watcher.execute(
                "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock'"
                " AND datname = current_database()"
            ).fetchone()
            if waiting:
                return True
            time.sleep(0.05)
    return False


@pytest.mark.db
def test_a_retirement_that_starts_under_the_jobs_share_lock_waits_and_then_enqueues(
    scratch_dsn, store, tmp_path, monkeypatch
) -> None:
    entry_id, admin_id = committed_entry(scratch_dsn, store)
    real_state = embed_handler._state
    seen: dict = {"errors": []}

    def retire_in_a_thread() -> None:
        try:
            retire_committed(scratch_dsn, entry_id, admin_id, tmp_path)
        except Exception as exc:  # noqa: BLE001 - reported by the assertions below
            seen["errors"].append(repr(exc))

    thread = threading.Thread(target=retire_in_a_thread)

    def locked_then_a_retirement_starts(conn, wanted):
        state = real_state(conn, wanted)  # takes the share lock
        thread.start()
        seen["waited"] = wait_for_a_lock_wait(scratch_dsn)  # the retirement is blocked on it
        return state

    quiet = Server(embed_reply(1))
    with monkeypatch.context() as patched:
        patched.setattr(embed_handler, "_state", locked_then_a_retirement_starts)
        cycle(scratch_dsn, store, quiet.client)
    thread.join(timeout=20)

    assert seen["waited"] is True and not thread.is_alive() and seen["errors"] == []
    assert quiet.requests == []
    # the retirement committed after the job did, so its enqueue found no live job: not lost
    assert job_statuses(scratch_dsn, entry_id) == ["succeeded", "pending"]
    with psycopg.connect(scratch_dsn) as observer:
        (status,) = observer.execute(
            "SELECT status FROM knowledge_entries WHERE entry_id = %s", (entry_id,)
        ).fetchone()
    assert status == "retired" and list(store.rows()) == [entry_id]

    make_due(scratch_dsn, entry_id)
    cycle(scratch_dsn, store, quiet.client)
    assert store.rows() == {} and job_statuses(scratch_dsn, entry_id) == ["succeeded", "succeeded"]
