"""The independent vector database: one table, `entry_vectors` (P14-T05, DEC-213, spec §5.1).

`vectordb` is a plain pgvector server that only `rag-worker` can reach (`docker-compose.rag.yml`). It
holds a **derived index** of the approved entries and nothing else; the main database stays the only
source of an entry's content, status and hash, and every vector found here is re-checked against it before
it is used (spec §5.1). So a stale or orphan row costs a wasted candidate, never a wrong answer, and the
index needs no backup: `python -m app.rag.vector_index --rebuild` makes it again.

    entry_vectors(
      entry_id       uuid PRIMARY KEY,   -- knowledge_entries.entry_id in the main database
      content_sha256 text NOT NULL,      -- the entry's hash when it was embedded
      model          text NOT NULL,      -- e.g. voyage-4
      dims           int  NOT NULL,      -- the length of `embedding`
      embedding      vector NOT NULL,    -- untyped: the size is `dims`, not a column type
      embedded_at    timestamptz NOT NULL DEFAULT now())

The column is an untyped `vector`, so a change of `RAG_EMBED_DIMS` or `RAG_EMBED_MODEL` needs no `ALTER`:
old rows simply stop matching (`stored` shows them as stale, a rebuild replaces them). The corpus is tens to
hundreds of rows, so a search is an exact scan and there is no index (an HNSW index needs a typed column).

**Rows of two sizes or two models are never compared** (Review Focus 3). pgvector raises `different vector
dimensions` when asked to compare two sizes, and two models of one size are two unrelated spaces whose
distances mean nothing together. `nearest` therefore filters by `model` and `dims` before it orders; the
rows it filters out are never reached by the distance operator.

**No new Python dependency.** A vector goes in as pgvector's text form (`vector_literal`, `[0.1,0.2,...]`)
cast with `::vector`, never as an adapted list.

**Failures.** `connect` is the one place an address is used, and the address is never in a message: an
empty `VECTOR_DATABASE_URL` or any failure to connect is `RagUnavailable("vectordb_unreachable")` (raised
`from None`, so the library's text, which can name the host, goes nowhere). A connection that is lost
inside a call is the same kind (`_unreachable` says which errors those are). An error of a statement itself
(a missing table, a number pgvector refuses) is not hidden: it is a bug or a missing `ensure_schema`, not an
unreachable server.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Any

import psycopg

from app.infra.config import Config
from app.rag.failures import RagUnavailable

CONNECT_TIMEOUT_S = 5
#: A query on a table this small takes milliseconds; a server that does not answer in this long is as good
#: as down (the job holds a transaction of the main database while it waits).
STATEMENT_TIMEOUT_MS = 10_000

_CREATE_EXTENSION = "CREATE EXTENSION IF NOT EXISTS vector"
_CREATE_TABLE = """
    CREATE TABLE IF NOT EXISTS entry_vectors (
        entry_id uuid PRIMARY KEY,
        content_sha256 text NOT NULL,
        model text NOT NULL,
        dims int NOT NULL,
        embedding vector NOT NULL,
        embedded_at timestamptz NOT NULL DEFAULT now()
    )
    """
_UPSERT = """
    INSERT INTO entry_vectors (entry_id, content_sha256, model, dims, embedding, embedded_at)
    VALUES (%s::uuid, %s, %s, %s, %s::vector, now())
    ON CONFLICT (entry_id) DO UPDATE SET
        content_sha256 = EXCLUDED.content_sha256,
        model = EXCLUDED.model,
        dims = EXCLUDED.dims,
        embedding = EXCLUDED.embedding,
        embedded_at = now()
    """
_DELETE = "DELETE FROM entry_vectors WHERE entry_id = %s::uuid"
_STORED = "SELECT entry_id::text, content_sha256, model, dims FROM entry_vectors"
_STORED_ONE = "SELECT content_sha256, model, dims FROM entry_vectors WHERE entry_id = %s::uuid"
_NEAREST = """
    SELECT entry_id::text FROM entry_vectors
    WHERE model = %s AND dims = %s
    ORDER BY embedding <=> %s::vector
    LIMIT %s
    """


def vector_literal(vector: Sequence[float]) -> str:
    """pgvector's text form of `vector`: `[0.5,1.0,-2.25]`. `repr` of a float is the shortest text that
    reads back as the same number. Empty, not a number, NaN and infinity are `ValueError`: pgvector would
    refuse them, and a refusal here names the cause."""
    values = list(vector)
    if not values:
        raise ValueError("vector: must not be empty")
    parts = []
    for value in values:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(  # noqa: TRY004 — one error type for every bad input
                "vector: every item must be a number"
            )
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("vector: every number must be finite")
        parts.append(repr(number))
    return "[" + ",".join(parts) + "]"


def connect(cfg: Config) -> psycopg.Connection:
    """A connection to the vector database, in autocommit (each statement is its own transaction: the
    index is derived, and a half-done job is repaired by the next one). `RagUnavailable(
    "vectordb_unreachable")` for an empty address and for any failure to connect."""
    dsn = cfg.VECTOR_DATABASE_URL
    if not dsn:
        raise RagUnavailable("vectordb_unreachable")
    try:
        return psycopg.connect(
            dsn,
            autocommit=True,
            connect_timeout=CONNECT_TIMEOUT_S,
            options=f"-c statement_timeout={STATEMENT_TIMEOUT_MS}",
        )
    except psycopg.Error:
        raise RagUnavailable("vectordb_unreachable") from None


def _unreachable(exc: Exception) -> bool:
    """Whether `exc` says the server could not be reached or cut us off, as against a statement it
    refused. psycopg makes every error of SQLSTATE class 53, 54, 57 and 58 an `OperationalError`, and a
    number pgvector refuses (`ProgramLimitExceeded`, 54000) is a bug of the caller's, not a server that is
    down. So an error is 'unreachable' when libpq raised it with no SQLSTATE (a connection that was
    refused, reset or closed), or the server said it was going away or cancelled the statement (class 08
    connection exceptions, class 57 operator intervention: a shutdown, a statement timeout) or had no
    connection left (53300)."""
    state = getattr(exc, "sqlstate", None)
    return state is None or state.startswith(("08", "57")) or state == "53300"


def _run(vconn: Any, query: str, params: Sequence[Any] | None = None) -> None:
    try:
        vconn.execute(query, params)
    except (psycopg.OperationalError, psycopg.InterfaceError) as exc:
        if not _unreachable(exc):
            raise
        raise RagUnavailable("vectordb_unreachable") from None


def _fetch(vconn: Any, query: str, params: Sequence[Any] | None = None) -> list[tuple]:
    try:
        return list(vconn.execute(query, params).fetchall())
    except (psycopg.OperationalError, psycopg.InterfaceError) as exc:
        if not _unreachable(exc):
            raise
        raise RagUnavailable("vectordb_unreachable") from None


def ensure_schema(vconn: Any) -> None:
    """Create the extension and the table if they are not there. Safe to run any number of times, and
    `CREATE EXTENSION IF NOT EXISTS` needs no privilege when the extension exists."""
    _run(vconn, _CREATE_EXTENSION)
    _run(vconn, _CREATE_TABLE)


def upsert(
    vconn: Any, *, entry_id: str, content_sha256: str, model: str, vector: Sequence[float]
) -> None:
    """The row of `entry_id`, made or replaced whole; `dims` is the length of `vector`."""
    literal = vector_literal(vector)
    _run(vconn, _UPSERT, (entry_id, content_sha256, model, len(vector), literal))


def delete(vconn: Any, entry_id: str) -> None:
    """The row of `entry_id`, if there is one."""
    _run(vconn, _DELETE, (entry_id,))


def stored(vconn: Any) -> dict[str, tuple[str, str, int]]:
    """Every row as `{entry id: (content_sha256, model, dims)}`: what the index claims to hold, without
    the vectors."""
    return {
        entry_id: (content_sha256, model, dims)
        for entry_id, content_sha256, model, dims in _fetch(vconn, _STORED)
    }


def stored_one(vconn: Any, entry_id: str) -> tuple[str, str, int] | None:
    """What the index claims to hold for one entry, `(content_sha256, model, dims)`, or None when it has
    no row for it. A job about one entry reads this, not the whole table."""
    rows = _fetch(vconn, _STORED_ONE, (entry_id,))
    return None if not rows else (rows[0][0], rows[0][1], rows[0][2])


def nearest(vconn: Any, vector: Sequence[float], *, model: str, limit: int = 20) -> list[str]:
    """The ids of the `limit` rows nearest to `vector` by cosine distance, nearest first, among the rows of
    this `model` and of this size only (Review Focus 3)."""
    literal = vector_literal(vector)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("limit: must be an integer of at least 1")
    rows = _fetch(vconn, _NEAREST, (model, len(vector), literal, limit))
    return [entry_id for (entry_id,) in rows]
