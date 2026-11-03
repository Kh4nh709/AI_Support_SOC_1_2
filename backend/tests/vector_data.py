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
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager

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
        self._rows: dict[str, tuple[str, str, int, list[float]]] = {}
        monkeypatch.setattr(vector_store, "ensure_schema", self._ensure_schema)
        monkeypatch.setattr(vector_store, "stored", self._stored)
        monkeypatch.setattr(vector_store, "upsert", self._upsert)
        monkeypatch.setattr(vector_store, "delete", self._delete)

    def _ensure_schema(self, vconn) -> None:
        assert vconn is self.conn
        self.schema_calls += 1

    def _stored(self, vconn) -> dict[str, tuple[str, str, int]]:
        assert vconn is self.conn
        return {k: (sha, model, dims) for k, (sha, model, dims, _) in self._rows.items()}

    def _upsert(
        self, vconn, *, entry_id: str, content_sha256: str, model: str, vector: Sequence[float]
    ) -> None:
        assert vconn is self.conn
        self._rows[entry_id] = (content_sha256, model, len(vector), [float(x) for x in vector])

    def _delete(self, vconn, entry_id: str) -> None:
        assert vconn is self.conn
        self._rows.pop(entry_id, None)

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
