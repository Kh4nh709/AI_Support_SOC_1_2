"""Shared pytest fixtures.

Any test that requests the `db` fixture MUST be decorated `@pytest.mark.db`
(enforced below by an autouse check) — `make test` excludes `db`-marked tests,
so an undecorated test that needs a database would otherwise pass locally and
fail unexpectedly wherever `db` tests are actually run.

The `_test_database`/`db` fixtures cannot be proven end-to-end on every host:
see docs/plan/INBOX.md 2026-09-05 · P0 / P1 · BLOCKER. They fail loudly
(`pytest.skip` naming the unreachable DSN) rather than silently passing.
`require_test_dsn` and `redact_dsn` are the only parts of this file that do
not need a live server, and are unit-tested in test_conftest_helpers.py.
"""

import os
import shutil
import subprocess
import urllib.parse
from pathlib import Path

import psycopg
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TEST_DATABASE_URL = "postgresql://soc:soc@127.0.0.1:55432/soc_test"


def _dbname(dsn: str) -> str:
    return urllib.parse.urlparse(dsn).path.lstrip("/")


def require_test_dsn(dsn: str) -> str:
    """Return `dsn` unchanged, or `pytest.fail` if its database name doesn't end in
    `_test`. This fixture drops and recreates the database; this rail is what stops
    it from wiping a non-test database such as `soc`."""
    if not _dbname(dsn).endswith("_test"):
        pytest.fail(
            f"refusing {redact_dsn(dsn)}: TEST_DATABASE_URL's database name must end "
            "in '_test' (this fixture drops and recreates the database)"
        )
    return dsn


def redact_dsn(dsn: str) -> str:
    """`dsn` with its password, if any, replaced by '***'."""
    parsed = urllib.parse.urlsplit(dsn)
    if parsed.password is None:
        return dsn
    netloc = f"{parsed.username or ''}:***@{parsed.hostname or ''}"
    if parsed.port:
        netloc += f":{parsed.port}"
    return urllib.parse.urlunsplit(parsed._replace(netloc=netloc))


def _maintenance_dsn(dsn: str) -> str:
    """Same server and credentials as `dsn`, but the `postgres` maintenance database.

    Built manually rather than via urllib.parse.urlunsplit: urlunsplit only keeps the
    `//` authority separator when netloc is non-empty or the scheme is in its
    hardcoded uses_netloc registry, and 'postgresql' is in neither — so on the
    no-docker socket form `postgresql:///soc_test` (empty netloc) it collapses to
    `postgresql:/postgres`, which libpq rejects.
    """
    parsed = urllib.parse.urlsplit(dsn)
    suffix = f"?{parsed.query}" if parsed.query else ""
    suffix += f"#{parsed.fragment}" if parsed.fragment else ""
    return f"{parsed.scheme}://{parsed.netloc}/postgres{suffix}"


@pytest.fixture(scope="session")
def _test_database():
    dsn = require_test_dsn(os.environ.get("TEST_DATABASE_URL", DEFAULT_TEST_DATABASE_URL))

    if shutil.which("psql") is None:
        pytest.skip(
            f"TEST_DATABASE_URL unreachable: {redact_dsn(dsn)} — psql is not installed "
            "— see docs/plan/INBOX.md 2026-09-05 BLOCKER"
        )

    dbname = _dbname(dsn)
    try:
        conn = psycopg.connect(_maintenance_dsn(dsn), autocommit=True)
    except psycopg.OperationalError:
        pytest.skip(
            f"TEST_DATABASE_URL unreachable: {redact_dsn(dsn)} — see "
            "docs/plan/INBOX.md 2026-09-05 BLOCKER"
        )
    try:
        with conn.cursor() as cur:
            cur.execute(f'DROP DATABASE IF EXISTS "{dbname}"')
            cur.execute(f'CREATE DATABASE "{dbname}"')
    finally:
        conn.close()

    result = subprocess.run(
        ["bash", "scripts/migrate.sh", dsn],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert (
        result.returncode == 0
    ), f"scripts/migrate.sh failed for {redact_dsn(dsn)}:\n{result.stderr}"
    return dsn


@pytest.fixture(autouse=True)
def _require_db_marker(request):
    if "db" in request.fixturenames and request.node.get_closest_marker("db") is None:
        pytest.fail(f"{request.node.nodeid} uses the `db` fixture without @pytest.mark.db")
    yield


@pytest.fixture
def db(_test_database):
    conn = psycopg.connect(_test_database)
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()
