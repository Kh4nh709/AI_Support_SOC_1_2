"""The psycopg 3 connection/pool wired to DATABASE_URL, connecting as the app_rw role.

No pooling library (planning decision 2, P2-tasks.md): one worker process and
one FastAPI process each hold a plain `psycopg.connect()` connection.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import psycopg
from psycopg import sql

from app.infra import config
from app.infra.errors import ConfigError


def connect(dsn: str | None = None) -> psycopg.Connection:
    """A new connection with autocommit off. `dsn` defaults to `Config.DATABASE_URL`
    (env/`.env`, §6.3) — a worktree has no `.env` and no such key, so tests always
    pass a DSN explicitly (the `db` fixture's) rather than relying on this default.
    """
    if dsn is None:
        dsn = config.load().DATABASE_URL
    if not dsn:
        raise ConfigError("DATABASE_URL: must be set to connect (no DSN was given)")
    return psycopg.connect(dsn, autocommit=False)


@contextmanager
def transaction(
    conn: psycopg.Connection, *, statement_timeout: str = "3s"
) -> Iterator[psycopg.Connection]:
    """`BEGIN`; `SET LOCAL statement_timeout`/`idle_in_transaction_session_timeout`;
    commit on normal exit; rollback and re-raise on exception.

    `SET LOCAL` is per-transaction and dies with it — that is the point; a bare
    `SET` would leak the timeout into whatever the connection does next. `SET`
    does not accept a bind parameter (Postgres rejects `SET ... = $1`), so the
    timeout is spliced in as a quoted SQL literal via `psycopg.sql.Literal`
    rather than passed as a query parameter.
    """
    conn.execute("BEGIN")
    conn.execute(sql.SQL("SET LOCAL statement_timeout = {}").format(sql.Literal(statement_timeout)))
    conn.execute("SET LOCAL idle_in_transaction_session_timeout = '10s'")
    try:
        yield conn
    except BaseException:
        conn.rollback()
        raise
    else:
        conn.commit()
