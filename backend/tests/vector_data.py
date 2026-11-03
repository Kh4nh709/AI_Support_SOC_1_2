"""A vector store for the P14-T05 tests that is either a dictionary or the real pgvector.

`test_rag_embed_job.py` and `test_rag_vector_index.py` test what a job or a command DECIDES (embed, skip,
delete, count), not the SQL of `rag.vector_store`, which `test_rag_vector_store.py` holds to a real
pgvector. So each of them runs every test twice through one fixture:

* `memory`: `vector_store.ensure_schema / stored / upsert / delete` are replaced by functions over a
  dictionary, and the "connection" is a `MemoryConn` that only remembers whether it was closed. It runs
  in `make test-db` on any PostgreSQL;
* `pgvector`: the real functions on a scratch database named by `VECTOR_TEST_DATABASE_URL` (skipped when
  it is unset), the table dropped first and last.

Both give the test the same three things: `conn` (what it passes as `vconn`), `rows()` (entry id ->
(hash, model, dims)) and `vector(entry_id)` (the stored numbers, or None).

P14-T06 adds `nearest` to the dictionary store (cosine distance, this model and this size only, like the
real query) and `VoyageRouter`, one `httpx.MockTransport` handler for both Voyage endpoints that the lookup
job calls (`/embeddings` and `/rerank`).
"""

from __future__ import annotations

import json
import math
import os
import uuid
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from typing import Any, Self

import httpx
import psycopg
import pytest
from app.rag import vector_store
from app.rag.entries import render_entry_markdown

from tests import conftest
from tests.rag_data import add_entry

VECTOR_DSN_VARIABLE = "VECTOR_TEST_DATABASE_URL"
STORE_KINDS = ("memory", "pgvector")


class MemoryConn:
    """Stands for a connection to the vector database: it can be closed, nothing else."""

    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class MemoryStore:
    """`vector_store` over a dictionary."""

    kind = "memory"

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.conn = MemoryConn()
        self.schema_calls = 0
        self._made = True  # like a database that has its table; `drop_schema()` takes it away
        self._rows: dict[str, tuple[str, str, int, list[float]]] = {}
        monkeypatch.setattr(vector_store, "ensure_schema", self._ensure_schema)
        monkeypatch.setattr(vector_store, "stored", self._stored)
        monkeypatch.setattr(vector_store, "stored_one", self._stored_one)
        monkeypatch.setattr(vector_store, "upsert", self._upsert)
        monkeypatch.setattr(vector_store, "delete", self._delete)
        monkeypatch.setattr(vector_store, "nearest", self._nearest)

    def _need_table(self) -> None:
        """What the real thing does without its table."""
        if not self._made:
            raise psycopg.errors.UndefinedTable('relation "entry_vectors" does not exist')

    def _ensure_schema(self, vconn) -> None:
        assert vconn is self.conn
        self.schema_calls += 1
        self._made = True

    def _stored(self, vconn) -> dict[str, tuple[str, str, int]]:
        assert vconn is self.conn
        self._need_table()
        return {k: (sha, model, dims) for k, (sha, model, dims, _) in self._rows.items()}

    def _stored_one(self, vconn, entry_id: str) -> tuple[str, str, int] | None:
        assert vconn is self.conn
        self._need_table()
        row = self._rows.get(entry_id)
        return None if row is None else (row[0], row[1], row[2])

    def _upsert(
        self, vconn, *, entry_id: str, content_sha256: str, model: str, vector: Sequence[float]
    ) -> None:
        assert vconn is self.conn
        self._need_table()
        self._rows[entry_id] = (content_sha256, model, len(vector), [float(x) for x in vector])

    def _delete(self, vconn, entry_id: str) -> None:
        assert vconn is self.conn
        self._need_table()
        self._rows.pop(entry_id, None)

    def _nearest(self, vconn, vector: Sequence[float], *, model: str, limit: int = 20) -> list[str]:
        """`vector_store.nearest` over the dictionary: this model and this size only, cosine distance
        ascending, ties in the order the rows were stored."""
        assert vconn is self.conn
        self._need_table()
        vector_store.vector_literal(vector)  # the same refusals as the real one
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit: must be an integer of at least 1")

        def distance(other: Sequence[float]) -> float:
            dot = sum(a * b for a, b in zip(vector, other, strict=True))
            norms = math.sqrt(sum(a * a for a in vector)) * math.sqrt(sum(b * b for b in other))
            return 1.0 - dot / norms

        rows = [
            (distance(row[3]), entry_id)
            for entry_id, row in self._rows.items()
            if row[1] == model and row[2] == len(vector)
        ]
        return [entry_id for _, entry_id in sorted(rows, key=lambda pair: pair[0])[:limit]]

    def drop_schema(self) -> None:
        """The vector database as a fresh `vectordb` is: no table."""
        self._made = False
        self._rows.clear()

    def has_schema(self) -> bool:
        return self._made

    def put(self, entry_id: str, content_sha256: str, model: str, vector: Sequence[float]) -> None:
        """A row that is there before the test starts."""
        self._upsert(
            self.conn, entry_id=entry_id, content_sha256=content_sha256, model=model, vector=vector
        )

    def rows(self) -> dict[str, tuple[str, str, int]]:
        return self._stored(self.conn)

    def vector(self, entry_id: str) -> list[float] | None:
        row = self._rows.get(entry_id)
        return None if row is None else row[3]


class PgvectorStore:
    """The real `vector_store` on the scratch pgvector."""

    kind = "pgvector"

    def __init__(self, conn: psycopg.Connection) -> None:
        self.conn = conn
        self.schema_calls = 0

    def put(self, entry_id: str, content_sha256: str, model: str, vector: Sequence[float]) -> None:
        vector_store.upsert(
            self.conn, entry_id=entry_id, content_sha256=content_sha256, model=model, vector=vector
        )

    def rows(self) -> dict[str, tuple[str, str, int]]:
        return vector_store.stored(self.conn)

    def drop_schema(self) -> None:
        self.conn.execute("DROP TABLE IF EXISTS entry_vectors")

    def has_schema(self) -> bool:
        (found,) = self.conn.execute("SELECT to_regclass('entry_vectors') IS NOT NULL").fetchone()
        return found

    def vector(self, entry_id: str) -> list[float] | None:
        row = self.conn.execute(
            "SELECT embedding::text FROM entry_vectors WHERE entry_id = %s::uuid", (entry_id,)
        ).fetchone()
        return None if row is None else [float(x) for x in row[0][1:-1].split(",")]


@contextmanager
def pgvector_connection() -> Iterator[psycopg.Connection]:
    """A connection to the scratch pgvector with an empty, existing `entry_vectors`; `pytest.skip`
    when `VECTOR_TEST_DATABASE_URL` is not set. The name must end in `_test`: the table is dropped.
    """
    value = os.environ.get(VECTOR_DSN_VARIABLE, "")
    if not value:
        pytest.skip(f"{VECTOR_DSN_VARIABLE} is not set (a PostgreSQL with pgvector)")
    dsn = conftest.require_test_dsn(value)
    conn = psycopg.connect(dsn, autocommit=True)
    try:
        conn.execute("DROP TABLE IF EXISTS entry_vectors")
        vector_store.ensure_schema(conn)
        yield conn
    finally:
        conn.execute("DROP TABLE IF EXISTS entry_vectors")
        conn.close()


def make_store(kind: str, monkeypatch: pytest.MonkeyPatch, stack) -> MemoryStore | PgvectorStore:
    """The store of `kind`; `stack` (an `ExitStack`) closes the real one at the end of the test."""
    if kind == "memory":
        return MemoryStore(monkeypatch)
    return PgvectorStore(stack.enter_context(pgvector_connection()))


def entry(
    db, *, title="Quét cổng định kỳ", summary="Máy giám sát quét cổng vào <HOST>.", **kw
) -> str:
    """An active entry whose Markdown is what `render_entry_markdown` writes (title and summary)."""
    entry_id = kw.pop("entry_id", None) or str(uuid.uuid4())
    kw.setdefault("tags", ("port_scan",))
    kw.setdefault("rule_ids", ("100190",))
    content = render_entry_markdown(
        {
            "entry_id": entry_id,
            "version": 1,
            "title": title,
            "conclusion": kw.get("conclusion", "closed_fp"),
            "category": kw.get("category", "recon"),
            "tags": list(kw["tags"]),
            "rule_ids": list(kw["rule_ids"]),
            "summary": summary,
            "distinguishing_signals": ["SECTION-AFTER-THE-SUMMARY-NEVER-SENT"],
        }
    )
    return add_entry(db, entry_id=entry_id, content=content, **kw)


# ── Voyage: both endpoints of the lookup ──────────────────────────────────────────────────────

Reply = dict | Exception | bytes | str | Callable[[dict], Any]


class VoyageRouter:
    """A `MockTransport` handler that answers `/embeddings` with `embed` and `/rerank` with `rerank`, and
    keeps every request. A reply is a JSON object, an `Exception` to raise (a transport error), raw
    bytes or text, or a function of the request's JSON body that returns one of those. `embed_status` and
    `rerank_status` are the HTTP status of each endpoint's answer."""

    def __init__(
        self,
        embed: Reply | None = None,
        rerank: Reply | None = None,
        *,
        embed_status: int = 200,
        rerank_status: int = 200,
    ) -> None:
        self.replies = {"/embeddings": (embed, embed_status), "/rerank": (rerank, rerank_status)}
        self.requests: list[httpx.Request] = []
        self._client: httpx.Client | None = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = "/" + request.url.path.rsplit("/", 1)[-1]
        reply, status = self.replies.get(path, (None, 404))
        if callable(reply) and not isinstance(reply, Exception):
            reply = reply(json.loads(request.content))
        if isinstance(reply, Exception):
            raise reply
        if isinstance(reply, (bytes, str)):
            return httpx.Response(status, content=reply)
        return httpx.Response(status, json=reply)

    @property
    def client(self) -> httpx.Client:
        """The router's one client, made the first time it is asked for (and again after `close()`): a
        lookup that is given it uses and does not close it, so whoever asked closes it (`close()`, or
        `with router:`). A client made on every access, as this used to, was never closed by anyone.
        """
        if self._client is None or self._client.is_closed:
            self._client = httpx.Client(transport=httpx.MockTransport(self))
        return self._client

    def close(self) -> None:
        """Close the client this router made, if it made one."""
        if self._client is not None:
            self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def paths(self) -> list[str]:
        """The endpoints called, in order: `["/embeddings", "/rerank"]` for a whole lookup."""
        return ["/" + request.url.path.rsplit("/", 1)[-1] for request in self.requests]

    def bodies(self, path: str) -> list[dict]:
        return [
            json.loads(request.content)
            for request in self.requests
            if request.url.path.endswith(path)
        ]
