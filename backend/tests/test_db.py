"""Tests for app.infra.db — connect() and the transaction() context manager.

connect() is exercised both without a database (the ConfigError path needs no
server) and with one (a real round trip). transaction() is proven against a
real PostgreSQL server: SET LOCAL statement_timeout actually cancels a slow
statement (P2-tasks.md design note 2's "never SET without LOCAL" is tested by
checking the timeout reverts after commit, not merely assumed).
"""

from __future__ import annotations

import app.infra.db as infra_db
import psycopg
import pytest
from app.infra.errors import ConfigError


def test_connect_with_no_dsn_and_no_database_url_raises_config_error(monkeypatch, tmp_path):
    """Both tiers `config.load()` reads must be empty for this to prove anything.

    `load()` reads `.env` at a path relative to the process CWD, so deleting the
    environment variable alone leaves the file tier live: run from a checkout that
    has a `.env` (every developer machine and `main` itself — only a fresh
    worktree lacks one, DEC-010) `connect()` would pick that DSN up and open a
    real connection instead of raising. `chdir` into an empty directory makes the
    absence deliberate rather than an accident of where pytest was invoked.
    """
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.chdir(tmp_path)
    assert not (tmp_path / ".env").exists()
    with pytest.raises(ConfigError, match="DATABASE_URL"):
        infra_db.connect()


def test_connect_with_empty_explicit_dsn_raises_config_error():
    with pytest.raises(ConfigError, match="DATABASE_URL"):
        infra_db.connect("")


def test_connect_passes_a_connect_timeout_only_when_asked_to(monkeypatch):
    """P10-T05: the WebSocket's lookup asks for a bounded connect; everyone else keeps libpq's
    behaviour (no `connect_timeout` key at all, not `None`)."""
    seen: list[dict] = []
    monkeypatch.setattr(psycopg, "connect", lambda dsn, **kwargs: seen.append(kwargs))
    infra_db.connect("postgresql://x@127.0.0.1:9/x")
    infra_db.connect("postgresql://x@127.0.0.1:9/x", connect_timeout=10)
    assert seen == [{"autocommit": False}, {"autocommit": False, "connect_timeout": 10}]


@pytest.mark.db
def test_connect_with_explicit_dsn_returns_a_working_autocommit_off_connection(_test_database):
    conn = infra_db.connect(_test_database)
    try:
        assert conn.execute("SELECT 1").fetchone() == (1,)
        assert conn.autocommit is False
    finally:
        conn.rollback()
        conn.close()


@pytest.mark.db
def test_connect_reads_database_url_from_the_environment(monkeypatch, _test_database):
    monkeypatch.setenv("DATABASE_URL", _test_database)
    conn = infra_db.connect()
    try:
        assert conn.execute("SELECT 1").fetchone() == (1,)
    finally:
        conn.rollback()
        conn.close()


@pytest.mark.db
def test_transaction_commits_on_success(db, _test_database):
    with infra_db.transaction(db):
        db.execute("INSERT INTO jobs (job_type, subject_id) VALUES ('pipeline', 'txn-commit-1')")
    other = psycopg.connect(_test_database)
    try:
        row = other.execute("SELECT status FROM jobs WHERE subject_id = 'txn-commit-1'").fetchone()
        assert row == ("pending",)
    finally:
        other.execute("DELETE FROM jobs WHERE subject_id = 'txn-commit-1'")
        other.commit()
        other.close()


@pytest.mark.db
def test_transaction_rolls_back_and_reraises_on_exception(db):
    class Boom(Exception):
        pass

    with pytest.raises(Boom), infra_db.transaction(db):
        db.execute("INSERT INTO jobs (job_type, subject_id) VALUES ('pipeline', 'txn-rollback-1')")
        raise Boom("handler failed")

    # The connection must still be usable (a real rollback, not an aborted txn).
    count = db.execute("SELECT count(*) FROM jobs WHERE subject_id = 'txn-rollback-1'").fetchone()[
        0
    ]
    assert count == 0


@pytest.mark.db
def test_transaction_enforces_statement_timeout(db):
    """The real failing case: without SET LOCAL statement_timeout this never raises."""
    with (
        pytest.raises(psycopg.errors.QueryCanceled),
        infra_db.transaction(db, statement_timeout="200ms"),
    ):
        db.execute("SELECT pg_sleep(2)")
    # transaction() must have rolled back cleanly; connection still usable.
    assert db.execute("SELECT 1").fetchone() == (1,)


@pytest.mark.db
def test_transaction_sets_idle_in_transaction_session_timeout(db):
    with infra_db.transaction(db):
        value = db.execute("SHOW idle_in_transaction_session_timeout").fetchone()[0]
    assert value == "10s"


@pytest.mark.db
def test_transaction_timeout_is_local_and_does_not_leak_past_commit(db):
    """SET LOCAL dies with the transaction — the exact point of design note 2.

    Breaking this on purpose (swap SET LOCAL for a bare SET) makes the
    `after` assertion fail, since a bare SET would still show '222ms' once
    the transaction that set it has committed.
    """
    with infra_db.transaction(db, statement_timeout="222ms"):
        during = db.execute("SHOW statement_timeout").fetchone()[0]
    after = db.execute("SHOW statement_timeout").fetchone()[0]
    assert during == "222ms"
    assert after != "222ms"


@pytest.mark.db
def test_transaction_default_statement_timeout_is_3s(db):
    with infra_db.transaction(db):
        value = db.execute("SHOW statement_timeout").fetchone()[0]
    assert value == "3s"


# ── raise_idle_timeout: the one statement the RAG jobs share (P14-T06, P14-T05 review item 7) ──


@pytest.mark.db
def test_raise_idle_timeout_sets_the_job_lock_timeout_for_the_transaction(db):
    from app.infra.config import Config

    with infra_db.transaction(db):
        assert db.execute("SHOW idle_in_transaction_session_timeout").fetchone()[0] == "10s"
        infra_db.raise_idle_timeout(db, Config(JOB_LOCK_TIMEOUT_S=300))
        assert db.execute("SHOW idle_in_transaction_session_timeout").fetchone()[0] == "5min"
    assert db.execute("SHOW idle_in_transaction_session_timeout").fetchone()[0] != "5min"


def test_the_three_rag_jobs_use_the_one_helper_and_keep_no_copy_of_the_statement():
    """P14-T05 review item 7: `rag/lookup.py`, `rag/draft.py` and `web/rag_handlers/embed.py` each had their
    own `SET LOCAL idle_in_transaction_session_timeout` (a third copy of a statement that must change
    together). They call `infra.db.raise_idle_timeout` and spell the statement nowhere else."""
    from pathlib import Path

    app_root = Path(infra_db.__file__).resolve().parents[1]
    for relative in ("rag/lookup.py", "rag/draft.py", "web/rag_handlers/embed.py"):
        source = (app_root / relative).read_text(encoding="utf-8")
        assert "SET LOCAL idle_in_transaction_session_timeout" not in source, relative
        assert "raise_idle_timeout(conn, cfg)" in source, relative
        assert "def _raise_idle_timeout" not in source, relative
    assert (app_root / "infra/db.py").read_text(encoding="utf-8").count(
        "SET LOCAL idle_in_transaction_session_timeout"
    ) == 2  # transaction()'s 10 s and the helper's JOB_LOCK_TIMEOUT_S
