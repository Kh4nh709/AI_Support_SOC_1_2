"""P14-T05 / DEC-213, spec §5.1 — `rag.vector_store`: the independent pgvector's one table
`entry_vectors` and the five things `rag-worker` does to it.

Two halves.

* Pure (`make test`): the module over a fake connection that records what it is asked. It holds the
  statements to their shape: `connect` is autocommit and never leaks the DSN; the column is an untyped
  `vector`; `nearest` filters by model and dims BEFORE it orders (Review Focus 3: two sizes or two models
  in one table must never be compared, pgvector raises on different sizes); the vector goes in as a text
  literal (`vector_literal`), so there is no new Python dependency.
* The database half (`pytest.mark.db`, skipped unless `VECTOR_TEST_DATABASE_URL` names a PostgreSQL with
  the pgvector extension and a database whose name ends in `_test`): the same functions on the real
  thing: upsert, the order of `nearest`, delete, and the isolation of dims and models.
"""

from __future__ import annotations

import math
import os
from collections.abc import Iterator

import psycopg
import pytest
from app.infra.config import Config
from app.rag import vector_store
from app.rag.failures import RagUnavailable

from tests import conftest

ENTRY_A = "0b1f6a54-3c1e-4a8b-9a53-1a2b3c4d5e01"
ENTRY_B = "0b1f6a54-3c1e-4a8b-9a53-1a2b3c4d5e02"
ENTRY_C = "0b1f6a54-3c1e-4a8b-9a53-1a2b3c4d5e03"
SHA = "a" * 64
DSN_WITH_SECRET = "postgresql://vector:s3cr3t-vector-pass@vectordb:5432/vectors"


class FakeCursor:
    def __init__(self, rows) -> None:
        self.rows = list(rows)

    def fetchall(self):
        return list(self.rows)

    def fetchone(self):
        return self.rows[0] if self.rows else None


class FakeConn:
    """What `vector_store` asks of a connection: `execute(query, params)` -> a cursor."""

    def __init__(self, rows=(), *, error: Exception | None = None) -> None:
        self.rows = rows
        self.error = error
        self.calls: list[tuple[str, tuple | None]] = []

    def execute(self, query, params=None) -> FakeCursor:
        self.calls.append((" ".join(str(query).split()), params))
        if self.error is not None:
            raise self.error
        return FakeCursor(self.rows)


# ── vector_literal ────────────────────────────────────────────────────────────────────────────


def parse(literal: str) -> list[float]:
    """The inverse: what pgvector reads of the text."""
    assert literal.startswith("[") and literal.endswith("]")
    return [float(part) for part in literal[1:-1].split(",")]


@pytest.mark.parametrize(
    "values",
    [
        [0.1, -2.5, 3.0],
        [1, 0, -1],
        [1e-7, 1.5e-300, 2.5e300],
        [0.1 + 0.2, 1 / 3, -1 / 7, math.pi],
        [0.0],
        [-0.0, 123456789.123456789],
    ],
)
def test_vector_literal_round_trips(values) -> None:
    literal = vector_store.vector_literal(values)
    assert parse(literal) == [float(v) for v in values]
    assert " " not in literal


def test_vector_literal_is_pgvectors_text_form() -> None:
    assert vector_store.vector_literal([0.5, 1, -2.25]) == "[0.5,1.0,-2.25]"


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_vector_literal_refuses_what_pgvector_would(bad) -> None:
    with pytest.raises(ValueError, match="finite"):
        vector_store.vector_literal([0.1, bad])


@pytest.mark.parametrize("bad", [[], (), [True], ["0.1"], [None], [[0.1]]])
def test_vector_literal_refuses_an_empty_vector_and_things_that_are_not_numbers(bad) -> None:
    with pytest.raises(ValueError):
        vector_store.vector_literal(bad)


# ── connect ───────────────────────────────────────────────────────────────────────────────────


def test_connect_without_an_address_is_vectordb_unreachable_and_tries_nothing(monkeypatch) -> None:
    def boom(*args, **kwargs):
        raise AssertionError("psycopg.connect was called with no address")

    monkeypatch.setattr(vector_store.psycopg, "connect", boom)
    with pytest.raises(RagUnavailable) as caught:
        vector_store.connect(Config(VECTOR_DATABASE_URL=""))
    assert (
        caught.value.kind == "vectordb_unreachable" and str(caught.value) == "vectordb_unreachable"
    )


def test_connect_is_autocommit_and_bounded(monkeypatch) -> None:
    seen = {}
    sentinel = object()

    def fake_connect(dsn, **kwargs):
        seen.update(dsn=dsn, kwargs=kwargs)
        return sentinel

    monkeypatch.setattr(vector_store.psycopg, "connect", fake_connect)
    result = vector_store.connect(Config(VECTOR_DATABASE_URL=DSN_WITH_SECRET))

    assert result is sentinel and seen["dsn"] == DSN_WITH_SECRET
    assert seen["kwargs"]["autocommit"] is True
    assert (
        isinstance(seen["kwargs"]["connect_timeout"], int) and seen["kwargs"]["connect_timeout"] > 0
    )


@pytest.mark.parametrize(
    "error",
    [
        psycopg.OperationalError(f"connection to {DSN_WITH_SECRET} refused"),
        psycopg.ProgrammingError(f"invalid dsn {DSN_WITH_SECRET}"),
        psycopg.InterfaceError(f"bad {DSN_WITH_SECRET}"),
    ],
)
def test_a_connection_that_fails_is_vectordb_unreachable_without_the_dsn(
    monkeypatch, error
) -> None:
    def fake_connect(dsn, **kwargs):
        raise error

    monkeypatch.setattr(vector_store.psycopg, "connect", fake_connect)
    with pytest.raises(RagUnavailable) as caught:
        vector_store.connect(Config(VECTOR_DATABASE_URL=DSN_WITH_SECRET))
    exc = caught.value
    assert exc.kind == "vectordb_unreachable"
    assert "s3cr3t" not in str(exc) + repr(exc)
    assert exc.__cause__ is None and exc.__suppress_context__


# ── the statements (pure) ─────────────────────────────────────────────────────────────────────


def test_ensure_schema_creates_the_extension_then_the_table_with_an_untyped_vector() -> None:
    conn = FakeConn()
    vector_store.ensure_schema(conn)

    statements = [call[0] for call in conn.calls]
    assert statements[0] == "CREATE EXTENSION IF NOT EXISTS vector"
    table = statements[1]
    assert table.startswith("CREATE TABLE IF NOT EXISTS entry_vectors (")
    for column in (
        "entry_id uuid PRIMARY KEY",
        "content_sha256 text NOT NULL",
        "model text NOT NULL",
        "dims int NOT NULL",
        "embedding vector NOT NULL",
        "embedded_at timestamptz NOT NULL DEFAULT now()",
    ):
        assert column in table
    assert (
        "vector(" not in table
    )  # untyped: the size is the `dims` column, the model the `model` one
    assert len(statements) == 2


def test_upsert_writes_the_row_with_dims_the_length_of_the_vector() -> None:
    conn = FakeConn()
    vector_store.upsert(
        conn, entry_id=ENTRY_A, content_sha256=SHA, model="voyage-4", vector=[0.5, 1.0, -2.0]
    )
    ((statement, params),) = conn.calls
    assert statement.startswith("INSERT INTO entry_vectors")
    assert "ON CONFLICT (entry_id) DO UPDATE SET" in statement
    for column in (
        "content_sha256 = EXCLUDED.content_sha256",
        "model = EXCLUDED.model",
        "dims = EXCLUDED.dims",
        "embedding = EXCLUDED.embedding",
    ):
        assert column in statement
    assert "embedded_at = now()" in statement
    assert tuple(params) == (ENTRY_A, SHA, "voyage-4", 3, "[0.5,1.0,-2.0]")


def test_upsert_refuses_a_vector_that_is_not_finite_before_it_asks_anything() -> None:
    conn = FakeConn()
    with pytest.raises(ValueError):
        vector_store.upsert(
            conn, entry_id=ENTRY_A, content_sha256=SHA, model="m", vector=[0.1, float("nan")]
        )
    assert conn.calls == []


def test_delete_removes_the_row_of_one_entry() -> None:
    conn = FakeConn()
    vector_store.delete(conn, ENTRY_A)
    ((statement, params),) = conn.calls
    assert statement.startswith("DELETE FROM entry_vectors WHERE entry_id = %s")
    assert tuple(params) == (ENTRY_A,)


def test_stored_maps_an_entry_id_to_hash_model_and_dims() -> None:
    conn = FakeConn([(ENTRY_A, SHA, "voyage-4", 1024), (ENTRY_B, "b" * 64, "voyage-4-lite", 512)])
    assert vector_store.stored(conn) == {
        ENTRY_A: (SHA, "voyage-4", 1024),
        ENTRY_B: ("b" * 64, "voyage-4-lite", 512),
    }
    assert conn.calls[0][0].startswith(
        "SELECT entry_id::text, content_sha256, model, dims FROM entry_vectors"
    )


def test_nearest_filters_by_model_and_dims_before_it_orders_by_cosine_distance() -> None:
    """Review Focus 3. The filter and its parameters, in the brief's shape."""
    conn = FakeConn([(ENTRY_B,), (ENTRY_A,)])
    found = vector_store.nearest(conn, [0.25, 0.5, 0.75], model="voyage-4", limit=7)

    assert found == [ENTRY_B, ENTRY_A]
    ((statement, params),) = conn.calls
    assert statement.endswith(
        "FROM entry_vectors WHERE model = %s AND dims = %s"
        " ORDER BY embedding <=> %s::vector LIMIT %s"
    )
    assert statement.startswith("SELECT entry_id::text")
    assert tuple(params) == ("voyage-4", 3, "[0.25,0.5,0.75]", 7)


def test_nearest_defaults_to_twenty() -> None:
    conn = FakeConn()
    vector_store.nearest(conn, [1.0, 2.0], model="m")
    assert conn.calls[0][1][-1] == 20


@pytest.mark.parametrize("limit", [0, -1, True, 2.5, None])
def test_nearest_refuses_a_limit_that_is_not_a_positive_integer(limit) -> None:
    conn = FakeConn()
    with pytest.raises(ValueError):
        vector_store.nearest(conn, [1.0], model="m", limit=limit)
    assert conn.calls == []


def test_the_vector_goes_in_as_a_text_literal_never_as_a_python_list() -> None:
    conn = FakeConn()
    vector_store.nearest(conn, [1, 2], model="m")
    params = conn.calls[0][1]
    assert params[2] == "[1.0,2.0]" and isinstance(params[2], str)


@pytest.mark.parametrize(
    "call",
    [
        lambda c: vector_store.ensure_schema(c),
        lambda c: vector_store.upsert(
            c, entry_id=ENTRY_A, content_sha256=SHA, model="m", vector=[1.0]
        ),
        lambda c: vector_store.delete(c, ENTRY_A),
        lambda c: vector_store.stored(c),
        lambda c: vector_store.nearest(c, [1.0], model="m"),
    ],
)
@pytest.mark.parametrize(
    "error",
    [
        psycopg.OperationalError("server closed the connection unexpectedly"),
        psycopg.InterfaceError("the connection is closed"),
    ],
)
def test_a_connection_lost_in_a_call_is_vectordb_unreachable(call, error) -> None:
    with pytest.raises(RagUnavailable) as caught:
        call(FakeConn(error=error))
    assert caught.value.kind == "vectordb_unreachable"
    assert str(caught.value) == "vectordb_unreachable"
    assert caught.value.__cause__ is None


@pytest.mark.parametrize(
    "error",
    [
        psycopg.errors.AdminShutdown("terminating connection due to administrator command"),
        psycopg.errors.CrashShutdown("the database system is in recovery mode"),
        psycopg.errors.CannotConnectNow("the database system is starting up"),
        psycopg.errors.QueryCanceled("canceling statement due to statement timeout"),
        psycopg.errors.ConnectionFailure("connection lost"),
        psycopg.errors.TooManyConnections("too many clients already"),
    ],
)
def test_a_server_that_goes_away_or_cuts_a_statement_off_is_vectordb_unreachable(error) -> None:
    with pytest.raises(RagUnavailable) as caught:
        vector_store.stored(FakeConn(error=error))
    assert caught.value.kind == "vectordb_unreachable"


@pytest.mark.parametrize(
    "error",
    [
        psycopg.errors.UndefinedTable("no such table"),
        psycopg.errors.ProgramLimitExceeded("vector cannot have more than 16000 dimensions"),
        psycopg.errors.DiskFull("no space left"),
        psycopg.errors.DataError("bad value"),
    ],
)
def test_an_error_of_the_statement_itself_is_not_hidden_as_unreachable(error) -> None:
    """psycopg makes classes 53, 54, 57 and 58 `OperationalError`s: a number pgvector refuses must not read
    as a server that is down (the first run of the database half found it)."""
    with pytest.raises(type(error)):
        vector_store.stored(FakeConn(error=error))


# ── the database half: a real pgvector ────────────────────────────────────────────────────────

VECTOR_DSN = os.environ.get("VECTOR_TEST_DATABASE_URL", "")
needs_pgvector = pytest.mark.skipif(
    not VECTOR_DSN, reason="VECTOR_TEST_DATABASE_URL is not set (a PostgreSQL with pgvector)"
)


@pytest.fixture
def vconn() -> Iterator[psycopg.Connection]:
    """A connection to the scratch pgvector, with an empty `entry_vectors` table. The table is dropped
    first and last, so the database name must end in `_test` (the rail every test database has)."""
    dsn = conftest.require_test_dsn(VECTOR_DSN)
    conn = psycopg.connect(dsn, autocommit=True)
    try:
        conn.execute("DROP TABLE IF EXISTS entry_vectors")
        vector_store.ensure_schema(conn)
        yield conn
    finally:
        conn.execute("DROP TABLE IF EXISTS entry_vectors")
        conn.close()


def put(conn, entry_id, vector, *, model="voyage-4", sha=SHA) -> None:
    vector_store.upsert(conn, entry_id=entry_id, content_sha256=sha, model=model, vector=vector)


@pytest.mark.db
@needs_pgvector
def test_ensure_schema_is_idempotent_and_makes_the_documented_table(vconn) -> None:
    vector_store.ensure_schema(vconn)
    vector_store.ensure_schema(vconn)
    columns = vconn.execute(
        "SELECT column_name, data_type, is_nullable FROM information_schema.columns"
        " WHERE table_name = 'entry_vectors' ORDER BY ordinal_position"
    ).fetchall()
    assert columns == [
        ("entry_id", "uuid", "NO"),
        ("content_sha256", "text", "NO"),
        ("model", "text", "NO"),
        ("dims", "integer", "NO"),
        ("embedding", "USER-DEFINED", "NO"),
        ("embedded_at", "timestamp with time zone", "NO"),
    ]
    typmod = vconn.execute(
        "SELECT atttypmod FROM pg_attribute WHERE attrelid = 'entry_vectors'::regclass"
        " AND attname = 'embedding'"
    ).fetchone()[0]
    assert typmod == -1  # an untyped `vector`: no size in the column


@pytest.mark.db
@needs_pgvector
def test_upsert_stores_and_replaces_one_row_per_entry(vconn) -> None:
    put(vconn, ENTRY_A, [1.0, 0.0, 0.0])
    assert vector_store.stored(vconn) == {ENTRY_A: (SHA, "voyage-4", 3)}

    put(vconn, ENTRY_A, [0.0, 1.0, 0.0, 0.0], model="voyage-4-lite", sha="b" * 64)
    assert vector_store.stored(vconn) == {ENTRY_A: ("b" * 64, "voyage-4-lite", 4)}
    (count,) = vconn.execute("SELECT count(*) FROM entry_vectors").fetchone()
    assert count == 1
    (stamped,) = vconn.execute("SELECT embedded_at IS NOT NULL FROM entry_vectors").fetchone()
    assert stamped is True


@pytest.mark.db
@needs_pgvector
def test_nearest_orders_by_cosine_distance(vconn) -> None:
    put(vconn, ENTRY_A, [1.0, 0.0, 0.0])
    put(vconn, ENTRY_B, [0.9, 0.1, 0.0])
    put(vconn, ENTRY_C, [0.0, 1.0, 0.0])

    assert vector_store.nearest(vconn, [1.0, 0.0, 0.0], model="voyage-4") == [
        ENTRY_A,
        ENTRY_B,
        ENTRY_C,
    ]
    assert vector_store.nearest(vconn, [0.0, 1.0, 0.1], model="voyage-4") == [
        ENTRY_C,
        ENTRY_B,
        ENTRY_A,
    ]
    assert vector_store.nearest(vconn, [1.0, 0.0, 0.0], model="voyage-4", limit=2) == [
        ENTRY_A,
        ENTRY_B,
    ]
    assert vector_store.nearest(vconn, [1.0, 0.0, 0.0], model="voyage-4", limit=1) == [ENTRY_A]


@pytest.mark.db
@needs_pgvector
def test_cosine_distance_ignores_the_length_of_a_vector(vconn) -> None:
    put(vconn, ENTRY_A, [100.0, 0.0])
    put(vconn, ENTRY_B, [0.6, 0.8])
    assert vector_store.nearest(vconn, [0.001, 0.0], model="voyage-4") == [ENTRY_A, ENTRY_B]


@pytest.mark.db
@needs_pgvector
def test_nearest_never_compares_vectors_of_another_size(vconn) -> None:
    """Review Focus 3, dims: a table with 3-number and 4-number rows answers a 3-number question with
    the 3-number rows only; pgvector raises `different vector dimensions` if it ever compares two sizes.
    """
    put(vconn, ENTRY_A, [1.0, 0.0, 0.0])
    put(vconn, ENTRY_B, [1.0, 0.0, 0.0, 0.0])
    put(vconn, ENTRY_C, [0.0, 1.0, 0.0])

    assert vector_store.nearest(vconn, [1.0, 0.0, 0.0], model="voyage-4") == [ENTRY_A, ENTRY_C]
    assert vector_store.nearest(vconn, [1.0, 0.0, 0.0, 0.0], model="voyage-4") == [ENTRY_B]
    assert vector_store.nearest(vconn, [1.0, 0.0], model="voyage-4") == []


@pytest.mark.db
@needs_pgvector
def test_nearest_never_returns_a_row_of_another_model(vconn) -> None:
    """Review Focus 3, model: two models of one size are two spaces; one question reaches one of them."""
    put(vconn, ENTRY_A, [1.0, 0.0, 0.0], model="voyage-4")
    put(vconn, ENTRY_B, [1.0, 0.0, 0.0], model="voyage-4-lite")

    assert vector_store.nearest(vconn, [1.0, 0.0, 0.0], model="voyage-4") == [ENTRY_A]
    assert vector_store.nearest(vconn, [1.0, 0.0, 0.0], model="voyage-4-lite") == [ENTRY_B]
    assert vector_store.nearest(vconn, [1.0, 0.0, 0.0], model="another") == []


@pytest.mark.db
@needs_pgvector
def test_delete_removes_the_row_and_a_missing_one_is_nothing(vconn) -> None:
    put(vconn, ENTRY_A, [1.0, 0.0])
    put(vconn, ENTRY_B, [0.0, 1.0])
    vector_store.delete(vconn, ENTRY_A)
    vector_store.delete(vconn, ENTRY_A)
    vector_store.delete(vconn, ENTRY_C)
    assert list(vector_store.stored(vconn)) == [ENTRY_B]
    assert vector_store.nearest(vconn, [1.0, 0.0], model="voyage-4") == [ENTRY_B]


@pytest.mark.db
@needs_pgvector
def test_stored_of_an_empty_table_is_empty_and_ids_come_back_as_text(vconn) -> None:
    assert vector_store.stored(vconn) == {}
    put(vconn, ENTRY_A.upper(), [1.0])
    assert list(vector_store.stored(vconn)) == [ENTRY_A]  # uuid's one spelling, lower case


@pytest.mark.db
@needs_pgvector
def test_a_vector_with_an_out_of_range_size_for_the_extension_is_a_database_error(vconn) -> None:
    """pgvector holds up to 16 000 numbers: the store does not hide a refusal of the database."""
    with pytest.raises(psycopg.Error):
        put(vconn, ENTRY_A, [0.5] * 16_001)
