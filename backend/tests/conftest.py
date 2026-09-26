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

No failing test may print a database password (DEC-122, DEC-123, DEC-130). pytest
prints, for a failure, the arguments of the test and of the last frame, the operands
of a failed assert, and the captured output. Two layers stop a password there:
- every DSN this file hands out is a `Dsn`: still a `str` — psycopg.connect, f-strings
  and subprocess arguments get the real value — but its repr, which is what pytest
  prints for arguments, locals and assert operands, is `redact_dsn(self)`;
- `pytest_runtest_makereport` masks the environment's database passwords in every
  report, for what a repr cannot reach: psycopg's own `connect` frame (it rebinds
  its argument to a plain `host=… password=…` string before it fails), a `str()` or
  slice of a DSN, a text diff, a subprocess's arguments, captured output.
Both are proven by inner pytest runs in test_credential_hygiene.py.
"""

import importlib.util
import os
import re
import shutil
import subprocess
import urllib.parse
from pathlib import Path

import psycopg
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TEST_DATABASE_URL = "postgresql://soc:soc@127.0.0.1:55432/soc_test"

# A path no checkout can contain, for the autouse fixture below (DEC-047).
_NO_AMBIENT_ENV_FILE = Path(__file__).resolve().parent / "_no_such_dir" / ".env"


def _load_dsn_env():
    """scripts/dsn_env.py — the one redaction routine; `make test-db` runs the same file."""
    spec = importlib.util.spec_from_file_location(
        "_soc_dsn_env", REPO_ROOT / "scripts" / "dsn_env.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_dsn_env = _load_dsn_env()


def _dbname(dsn: str) -> str:
    return urllib.parse.urlparse(dsn).path.lstrip("/")


def redact_dsn(dsn: str) -> str:
    """`dsn` with every password in it replaced by '***' (`scripts/dsn_env.py --redact`).

    The whole password, whatever it contains: urllib.parse ends a URI's authority at the
    first `/`, `?` or `#`, so a password holding one came back unmasked, DSN and all."""
    return _dsn_env.redact(str(dsn))


class Dsn(str):
    """A DSN whose repr is redacted: pytest prints a failing test's arguments with repr()."""

    __slots__ = ()

    def __repr__(self) -> str:
        return repr(redact_dsn(self))


def require_test_dsn(dsn: str) -> Dsn:
    """Return `dsn` as a `Dsn`, or `pytest.fail` if its database name doesn't end in
    `_test`. This fixture drops and recreates the database; this rail is what stops
    it from wiping a non-test database such as `soc`."""
    dsn = Dsn(dsn)  # first: this frame's own argument is printed if the rail fires
    if not _dbname(dsn).endswith("_test"):
        pytest.fail(
            f"refusing {redact_dsn(dsn)}: TEST_DATABASE_URL's database name must end "
            "in '_test' (this fixture drops and recreates the database)"
        )
    return dsn


def _maintenance_dsn(dsn: str) -> Dsn:
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
    return Dsn(f"{parsed.scheme}://{parsed.netloc}/postgres{suffix}")


@pytest.fixture(autouse=True)
def _no_ambient_env_file(monkeypatch):
    """No test may read the repository's real `.env` unless it names it.

    WHY (DEC-047). `config.load()` defaults to `env_file=".env"`, resolved against
    the current working directory. Every agent works in a git worktree and `.env`
    is git-ignored, so a test that calls `load()` — or anything that falls back to
    it, like `db.connect()` with no DSN — sees no file for the Coder and no file
    for the Reviewer, and sees the real one on `main`. Green everywhere it is run
    and red exactly where it ships; it cost a merge and a revert once.

    Pointing the default at a path no checkout can contain makes the two
    environments identical by construction rather than by every author
    remembering. A test that wants a file passes `env_file=` explicitly and is
    untouched — `test_config.py` does exactly that on every one of its calls.
    """
    from app.infra import config

    monkeypatch.setitem(config.load.__kwdefaults__, "env_file", _NO_AMBIENT_ENV_FILE)


@pytest.fixture(scope="session")
def _test_database() -> Dsn:
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
    # Not `assert result.returncode == 0`: pytest explains that by printing `result` whole,
    # argument list and DSN included (P5-T12's finding at this line). Plain values only.
    if result.returncode != 0:
        pytest.fail(
            f"scripts/migrate.sh failed for {redact_dsn(dsn)} "
            f"(exit {result.returncode}):\n{result.stderr}"
        )
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


# --- the report layer (module docstring) ---------------------------------------------------

_DSN_VARIABLES = ("TEST_DATABASE_URL", "DATABASE_URL", "DATABASE_URL_OWNER")
_SHORTEST_SECRET = 4


def _secrets() -> list[str]:
    """Every form in which a database password from the environment can be printed.

    The password of each DSN variable, and PGPASSWORD (`make test-db` exports it); each
    as written and percent-decoded; each as libpq's conninfo quoting and Python's repr
    escape it; and each piece between URI delimiters, which libpq prints on its own when
    it splits a DSN with a raw `@` or `/` in the password its own way (`could not
    translate host name "…"`, `invalid integer value "…" for connection option "port"`).
    Anything shorter than _SHORTEST_SECRET is left alone: masking it everywhere would
    garble the report, and a password that short protects nothing. Longest first.
    """
    found = {os.environ.get("PGPASSWORD", "")}
    for name in _DSN_VARIABLES:
        found.update(_dsn_env.passwords(os.environ.get(name, "")))
    forms = set()
    for password in found:
        for form in (password, urllib.parse.unquote(password)):
            quoted = form.replace("\\", "\\\\").replace("'", "\\'")
            forms.update((form, quoted, repr(form)[1:-1], repr(quoted)[1:-1]))
            forms.update(re.split(r"[@:/?#]", form))
    return sorted((f for f in forms if len(f) >= _SHORTEST_SECRET), key=len, reverse=True)


def _mask(text: str, secrets: list[str]) -> str:
    if "..." in text:  # pytest cut a long repr short: one end of a password may sit at the cut
        for secret in secrets:
            for k in range(len(secret) - 1, 1, -1):
                text = text.replace(secret[:k] + "...", "***...")
                text = text.replace("..." + secret[-k:], "...***")
    for secret in secrets:
        text = text.replace(secret, "***")
    return text


def _mask_report(report, secrets: list[str]) -> None:
    longrepr = report.longrepr
    if isinstance(longrepr, tuple):  # a skip: (path, lineno, reason)
        report.longrepr = (*longrepr[:-1], _mask(str(longrepr[-1]), secrets))
    elif longrepr is not None:
        text = str(longrepr)
        masked = _mask(text, secrets)
        if masked != text:  # the report becomes plain text only when it held a password
            report.longrepr = masked
    report.sections = [(title, _mask(body, secrets)) for title, body in report.sections]
    if isinstance(getattr(report, "wasxfail", None), str):
        report.wasxfail = _mask(report.wasxfail, secrets)


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_makereport(item, call):
    """Mask the environment's database passwords in every test report (second layer)."""
    report = yield
    secrets = _secrets()
    if secrets:
        _mask_report(report, secrets)
    return report
