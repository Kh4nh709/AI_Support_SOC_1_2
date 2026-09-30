"""A scratch database that a test module builds, migrates and drops itself (P10-T05).

The real-time channel is tested against COMMITTED data: NOTIFY is delivered at COMMIT, so
a test that only ever sees the shared `db` fixture's open transaction proves nothing about
it (the same reason `test_auth.py` keeps its own scratch database). This helper is that
pattern in one place for the two modules that need it (`test_schema_v3_018.py`,
`test_live_ws.py`):

- the name is derived from TEST_DATABASE_URL's own name, `<name>_<suffix>_test`, so the
  `_test` rail of `conftest.require_test_dsn` holds and a Coder's run and a Reviewer's run
  on different DSNs cannot collide;
- it is built through the same `scripts/migrate.sh` the real database is built with, so the
  trigger under test is the file as it ships, not a copy;
- the DSN it returns is a `conftest.Dsn`: its repr is redacted, so a failing test never
  prints a password.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import urllib.parse
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

import psycopg
import pytest
from psycopg import sql

from tests import conftest


def _with_db(dsn: str, dbname: str) -> conftest.Dsn:
    parts = urllib.parse.urlsplit(dsn)
    query = f"?{parts.query}" if parts.query else ""
    return conftest.Dsn(f"{parts.scheme}://{parts.netloc}/{dbname}{query}")


@contextmanager
def scratch_database(suffix: str) -> Iterator[conftest.Dsn]:
    """Create, migrate, yield and drop `<TEST_DATABASE_URL's name>_<suffix>_test`.

    Skips (never passes) when the server or `psql` is unreachable, exactly as the
    shared `_test_database` fixture does.
    """
    session = conftest.require_test_dsn(
        os.environ.get("TEST_DATABASE_URL", conftest.DEFAULT_TEST_DATABASE_URL)
    )
    if shutil.which("psql") is None:
        pytest.skip(f"psql is not installed — cannot build the {suffix} scratch database")
    dbname = f"{conftest._dbname(session)}_{suffix}_test"
    dsn = _with_db(session, dbname)
    try:
        admin = psycopg.connect(conftest._maintenance_dsn(session), autocommit=True)
    except psycopg.OperationalError:
        pytest.skip(f"TEST_DATABASE_URL unreachable: {conftest.redact_dsn(session)}")
    try:
        admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(dbname)))
        result = subprocess.run(
            ["bash", "scripts/migrate.sh", str(dsn)],
            cwd=conftest.REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        # Plain values only: pytest explains `assert result.returncode == 0` by printing
        # `result`, argument list and DSN included (P5-T12's finding).
        if result.returncode != 0:
            pytest.fail(f"scratch migrate failed (exit {result.returncode}):\n{result.stderr}")
        yield dsn
    finally:
        admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))
        admin.close()


# One alert, every NOT NULL column named; `raw_payload` is a plain jsonb column on `alerts`.
INSERT_ALERT = (
    "INSERT INTO alerts (alert_id, rule_id, rule_level, severity, description, agent_name,"
    " alert_time, category, resolved_by, mapping_version, event_bucket_hash, raw_payload,"
    " raw_log, suggestion_visible, status) VALUES (%s, '5710', 5, 'medium', 'p10t05',"
    " 'p10t05-agent', now(), 'other', 'none', 'v1', encode(sha256(%s::bytea), 'hex'),"
    " '{}'::jsonb, %s, %s, %s)"
)


def insert_alert(
    conn: psycopg.Connection,
    alert_id: str,
    raw_log: str = "",
    *,
    suggestion_visible: bool = True,
    status: str = "received",
) -> None:
    """Insert one alert on `conn`; the caller commits or rolls back. `suggestion_visible`
    False is the blind arm (DEC-101)."""
    conn.execute(INSERT_ALERT, (alert_id, alert_id, raw_log, suggestion_visible, status))


def insert_user(conn: psycopg.Connection, role: str = "tier1") -> str:
    """One user row (`alerts.acknowledged_by` and `cases.created_by` are foreign keys to it);
    the caller commits or rolls back. Returns the new `user_id`."""
    (user_id,) = conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash)"
        " VALUES (gen_random_uuid(), %s, 'p10t05', %s, 'not-a-real-hash') RETURNING user_id",
        (f"p10t05-{uuid.uuid4().hex[:10]}", role),
    ).fetchone()
    return str(user_id)
