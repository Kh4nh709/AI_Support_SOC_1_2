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
import uuid
from contextlib import ExitStack

import httpx
import pytest
from app.infra import config
from app.infra.config import Config
from app.infra.errors import PermanentError, TransientError, classify
from app.infra.jobs import Job, Reschedule, claim_job, finish_job
from app.rag import match, publish, vector_store
from app.rag.entries import entry_by_id, render_entry_markdown
from app.rag.failures import RagUnavailable
from app.web import rag_handlers
from app.web.rag_handlers import embed as embed_handler

from tests.test_rag_publish import admin, decided_alert, pending_draft, root  # noqa: F401
from tests.test_rag_voyage import CFG, DIMS, KEY, PROVIDER_WORDS, Server, embed_reply
from tests.vector_data import STORE_KINDS, entry, make_store

JOB_CFG = dataclasses.replace(CFG, VECTOR_DATABASE_URL="")


@pytest.fixture(params=STORE_KINDS)
def store(request, monkeypatch):
    with ExitStack() as stack:
        yield make_store(request.param, monkeypatch, stack)


@pytest.fixture(autouse=True)
def job_config(monkeypatch):
    """The job reads `config.load()`: a key that is not real, 256 numbers a vector."""
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
def test_the_schema_is_made_before_the_first_read(db, store) -> None:
    """A fresh `vectordb` has no table: the first job makes it (spec §5.1, create-if-absent)."""
    entry_id = entry(db)
    run(db, store, entry_id)
    if store.kind == "memory":
        assert store.schema_calls == 1


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
