"""P8-T07 — `make test-db`'s mask, `make db-restore`'s pre-flight, and no password in a failing
test's output (DEC-122, DEC-123, DEC-130).

1. `make test-db` shows its DSN through `scripts/dsn_env.py --redact`, the routine
   `conftest.redact_dsn` also calls: the whole password becomes `***`, whatever it holds. The
   `sed` before it stopped at the first `@` and printed the rest (DEC-123).
2. `make db-restore` reads the dump with the pg_restore of the server's own major version before
   it stops app and worker or drops anything; a dump it cannot read exits 2 and the database is
   left as it was (DEC-130: PATH's pg_restore 18 against the 16 server left it empty).
3. A failing test cannot print a password: conftest's `Dsn` and its report hook, proven by inner
   pytest runs whose TEST_DATABASE_URL carries a fake password — the property is about pytest's
   own output, so only a real pytest run can show it.

Nothing here reads `.env` or names the live database. The db-marked tests use private
`<session database>_<role>_test` databases derived from TEST_DATABASE_URL. `make db-restore` runs
from a scratch directory whose `.env` names one of them (its password travels in PGPASSWORD, never
in a file), with COMPOSE and `docker` both replaced by a recorder, so no real service can be
stopped. Every password written in this file is fake.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import textwrap
import urllib.parse
from pathlib import Path

import psycopg
import pytest
from psycopg import sql

from tests import conftest

REPO_ROOT = conftest.REPO_ROOT
MAKEFILE = REPO_ROOT / "Makefile"
DSN_ENV = REPO_ROOT / "scripts" / "dsn_env.py"
BACKUP = REPO_ROOT / "scripts" / "backup.sh"
MIGRATIONS = len(list((REPO_ROOT / "docs" / "Schema").glob("[0-9][0-9][0-9]_*.sql")))

_spec = importlib.util.spec_from_file_location("dsn_env", DSN_ENV)
dsn_env = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dsn_env)

# Fake passwords made of tokens found nowhere else: when no 3-character piece of any token is in
# an output, no fragment of the password survived.
TOKENS = ("Wq9Zk", "Jx4Vm", "Pb7Ty", "Lc2Hn", "Rd5Gs", "Fh8Kw")
PASSWORDS = {
    "at-signs": "Wq9Zk@Jx4Vm@Pb7Ty",  # DEC-123: the old mask printed what followed the first @
    "colons": "Wq9Zk:Jx4Vm:Pb7Ty",
    "slashes": "Wq9Zk/Jx4Vm/Pb7Ty",
    "hashes": "Wq9Zk#Jx4Vm#Pb7Ty",
    "percent-escapes": "Wq9Zk%40Jx4Vm%3APb7Ty%2FLc2Hn%23Rd5Gs",
    "all-of-them": "Wq9Zk@Jx4Vm:Pb7Ty/Lc2Hn#Rd5Gs%40Fh8Kw",
}
NOWHERE = "postgresql://soc:{}@127.0.0.1:9/nowhere_test"  # port 9: nothing listens there
MASKED = NOWHERE.format("***")
# The inner runs' DSN: urllib and libpq both parse it (its `@` is escaped), so psycopg gets as far
# as connecting — and failing — with the fake password in hand.
INNER_DSN = NOWHERE.format("Wq9Zk%40Jx4Vm:Pb7Ty%2FLc2Hn%23Rd5Gs")

# Never inherited by a subprocess here: the live DSNs, the real test password, and make's and
# pytest's own settings from the run this test is part of.
_SCRUBBED = {
    "DATABASE_URL",
    "DATABASE_URL_OWNER",
    "TEST_DATABASE_URL",
    "PGPASSWORD",
    "PGHOST",
    "PGPORT",
    "PGUSER",
    "PGDATABASE",
    "PGSERVICE",
    "MAKEFLAGS",
    "MFLAGS",
    "MAKELEVEL",
    "PYTEST_ADDOPTS",
}


class _Env(dict):
    """A subprocess environment; its repr is only its size, since it may hold PGPASSWORD."""

    def __repr__(self) -> str:
        return f"<environment of {len(self)} variables>"


def _env(**extra: str) -> _Env:
    env = _Env((k, v) for k, v in os.environ.items() if k not in _SCRUBBED)
    env.update(extra)
    return env


def _run(args, *, env: _Env, cwd: Path = REPO_ROOT) -> tuple[int, str]:
    """(exit code, stdout + stderr) as plain values: no CompletedProcess reaches an assert."""
    proc = subprocess.run(
        [str(a) for a in args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def _fragments(text: str) -> list[str]:
    """Every 3-character piece of a fake-password token that occurs in `text`."""
    return sorted({t[i : i + 3] for t in TOKENS for i in range(len(t) - 2) if t[i : i + 3] in text})


# --- 1 · one redaction routine, the whole password -----------------------------------------


@pytest.mark.parametrize("password", list(PASSWORDS.values()), ids=list(PASSWORDS))
def test_redact_masks_the_whole_password(password):
    shown = dsn_env.redact(NOWHERE.format(password))

    assert shown == MASKED
    assert _fragments(shown) == []


@pytest.mark.parametrize("password", list(PASSWORDS.values()), ids=list(PASSWORDS))
def test_the_command_line_and_conftest_redact_alike(password):
    dsn = NOWHERE.format(password)

    rc, out = _run([sys.executable, DSN_ENV, "--redact", dsn], env=_env())

    assert (rc, out) == (0, MASKED + "\n")
    assert conftest.redact_dsn(dsn) == MASKED


@pytest.mark.parametrize(
    ("dsn", "shown"),
    [
        ("postgresql:///soc_test", "postgresql:///soc_test"),
        ("postgresql://soc@127.0.0.1:9/nowhere_test", "postgresql://soc@127.0.0.1:9/nowhere_test"),
        ("postgresql://soc:@127.0.0.1:9/nowhere_test", MASKED),
        (
            "postgresql://soc@127.0.0.1:9/nowhere_test?password=Wq9Zk&sslmode=disable",
            "postgresql://soc@127.0.0.1:9/nowhere_test?password=***&sslmode=disable",
        ),
        (
            "host=127.0.0.1 port=9 user=soc password=Wq9Zk dbname=nowhere_test",
            "host=127.0.0.1 port=9 user=soc password=*** dbname=nowhere_test",
        ),
        (
            "host=127.0.0.1 password='Wq9Zk Jx4\\'Vm' dbname=nowhere_test",
            "host=127.0.0.1 password=*** dbname=nowhere_test",
        ),
    ],
    ids=["socket", "no-password", "empty-password", "query", "keyword", "keyword-quoted"],
)
def test_redact_handles_every_dsn_shape(dsn, shown):
    assert dsn_env.redact(dsn) == shown


@pytest.mark.parametrize("password", list(PASSWORDS.values()), ids=list(PASSWORDS))
def test_make_test_db_shows_the_dsn_with_the_whole_password_masked(password):
    """The real target, on a server that is not there: it prints the DSN, masked, and stops
    before pytest (TESTS names nothing, in case it ever got that far)."""
    rc, out = _run(
        [
            "make",
            "--no-print-directory",
            "-C",
            REPO_ROOT,
            "test-db",
            f"PY={sys.executable}",
            "TESTS=backend/tests/_no_such_test_file.py",
        ],
        env=_env(TEST_DATABASE_URL=NOWHERE.format(password)),
    )

    assert rc == 2 and "test-db] Error 1" in out, out  # the recipe's exit 1; make's own is 2
    assert f"test-db: TEST_DATABASE_URL is set but its server is unreachable: {MASKED}\n" in out
    assert _fragments(out) == [], out


# The export line `make test-db` and every card's preamble eval: byte for byte what the base
# (130b10a) printed for these DSNs.
@pytest.mark.parametrize(
    ("dsn", "line"),
    [
        (
            "postgresql://soc:s3cret@127.0.0.1:55432/soc_test",
            "export PGHOST=127.0.0.1 PGPORT=55432 PGUSER=soc PGPASSWORD=s3cret",
        ),
        ("postgresql:///soc_test", "export PGHOST='' PGPORT='' PGUSER='' PGPASSWORD=''"),
        (
            "postgresql://so%40c:p%40ss%3Aw%2Fx@db.example:5432/soc_test?sslmode=disable",
            "export PGHOST=db.example PGPORT=5432 PGUSER=so@c PGPASSWORD=p@ss:w/x",
        ),
        (
            "postgresql://soc:it%27s%20a%20pw@127.0.0.1:55432/soc_test",
            "export PGHOST=127.0.0.1 PGPORT=55432 PGUSER=soc PGPASSWORD='it'\"'\"'s a pw'",
        ),
        (
            "postgresql://soc@127.0.0.1/soc_test",
            "export PGHOST=127.0.0.1 PGPORT='' PGUSER=soc PGPASSWORD=''",
        ),
    ],
    ids=["tcp", "socket", "escapes", "shell-quoting", "no-password"],
)
def test_the_export_line_is_unchanged(dsn, line):
    rc, out = _run([sys.executable, DSN_ENV, dsn], env=_env())

    assert (rc, out) == (0, line + "\n")


@pytest.mark.parametrize("args", [[], ["--redact"], ["a", "b"], ["--redact", "a", "b"]])
def test_a_wrong_argument_count_is_a_usage_error(args):
    rc, out = _run([sys.executable, DSN_ENV, *args], env=_env())

    assert rc == 2
    assert out.startswith("usage: dsn_env.py <dsn>")


# --- 3 · no password in a failing test's output ----------------------------------------------

# The inner run's conftest: conftest.py's own `_test_database`, with nothing behind it. The
# fixture's code runs as written; only the three calls that would reach a server are answered.
_INNER_CONFTEST = """
from types import SimpleNamespace

import tests.conftest as real
from tests.conftest import _test_database  # noqa: F401 — the fixture under test
{hook_import}


class _Cursor:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, query):
        pass


class _Connection:
    def cursor(self):
        return _Cursor()

    def close(self):
        pass


real.shutil = SimpleNamespace(which=lambda name: "/usr/bin/" + name)
real.psycopg = SimpleNamespace(
    connect=lambda *args, **kwargs: _Connection(), OperationalError=real.psycopg.OperationalError
)
real.subprocess = SimpleNamespace(
    run=lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr="")
)
"""
_HOOK_IMPORT = "from tests.conftest import pytest_runtest_makereport  # noqa: F401"


def _inner_pytest(tmp_path: Path, tests: str, *, with_hook: bool) -> tuple[int, str]:
    """Run `tests` in a pytest of its own, TEST_DATABASE_URL = INNER_DSN (fake password)."""
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    (tmp_path / "conftest.py").write_text(
        _INNER_CONFTEST.format(hook_import=_HOOK_IMPORT if with_hook else ""), encoding="utf-8"
    )
    (tmp_path / "test_inner.py").write_text(textwrap.dedent(tests), encoding="utf-8")
    return _run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "--color=no", "test_inner.py"],
        cwd=tmp_path,
        env=_env(PYTHONPATH=str(REPO_ROOT / "backend"), TEST_DATABASE_URL=INNER_DSN, COLUMNS="160"),
    )


def test_a_failing_test_prints_the_dsn_fixture_redacted(tmp_path):
    """First layer: pytest prints a failing test's arguments and assert operands with repr(),
    and the fixture's value is a `Dsn`. The report hook is left out of this run on purpose."""
    rc, out = _inner_pytest(
        tmp_path,
        """
        def test_takes_the_dsn(_test_database):
            assert _test_database.endswith("_never_test")
        """,
        with_hook=False,
    )

    assert rc == 1 and "1 failed" in out, out
    assert f"_test_database = '{MASKED}'" in out, out
    assert f"= '{MASKED}'.endswith" in out, out
    assert _fragments(out) == [], out


def test_the_report_hook_masks_what_a_repr_cannot_reach(tmp_path):
    """Second layer: the five routes a `Dsn` repr does not cover, each shown masked — psycopg's
    own frame, a text diff, a subprocess's arguments, captured output, and a long repr that
    pytest cut inside the password (DEC-122's leak was such a truncated prefix)."""
    rc, out = _inner_pytest(
        tmp_path,
        """
        import os
        import subprocess

        import psycopg

        DSN = os.environ["TEST_DATABASE_URL"]


        def test_psycopg_rebinds_its_argument():
            psycopg.connect(DSN)


        def test_a_text_diff(_test_database):
            assert str(_test_database) == "postgresql://soc@127.0.0.1:9/nowhere_test"


        def test_a_subprocess_argument():
            result = subprocess.run(["true", DSN])
            assert result.returncode == 1


        def test_captured_output():
            print("connecting to", DSN)
            assert False


        def _check(blob):
            assert not blob


        def test_a_repr_cut_inside_the_password():
            # pytest keeps the first 118 characters of a long repr, then "...": six characters
            # of the password make it before the cut.
            _check("x" * (117 - len("postgresql://soc:") - 6) + DSN + "y" * 300)
        """,
        with_hook=True,
    )

    assert rc == 1 and "5 failed" in out, out
    assert "password=*** " in out, out  # psycopg's conninfo string
    assert f"+ {MASKED}" in out, out  # the diff
    assert f"CompletedProcess(args=['true', '{MASKED}']" in out, out
    assert f"connecting to {MASKED}" in out, out
    assert "soc:***..." in out, out  # the cut
    assert _fragments(out) == [], out


# --- 2 · make db-restore reads the dump before it stops or drops anything ----------------------


def _with_db(dsn: str, dbname: str) -> conftest.Dsn:
    parts = urllib.parse.urlsplit(dsn)
    query = f"?{parts.query}" if parts.query else ""
    return conftest.Dsn(f"{parts.scheme}://{parts.netloc}/{dbname}{query}")


def _derived(session_dsn: str, role: str) -> str:
    """`<session database>_<role>_test`: private to this session, and under the `_test` rail."""
    name = f"{conftest._dbname(session_dsn)}_{role}_test"
    conftest.require_test_dsn(_with_db(session_dsn, name))
    return name


def _admin(session_dsn: str, statement: sql.Composable) -> None:
    with psycopg.connect(conftest._maintenance_dsn(session_dsn), autocommit=True) as conn:
        conn.execute(statement)


def _database_oid(session_dsn: str, name: str) -> int | None:
    with psycopg.connect(conftest._maintenance_dsn(session_dsn)) as conn:
        row = conn.execute("SELECT oid FROM pg_database WHERE datname = %s", (name,)).fetchone()
    return row[0] if row else None


def _server_major(session_dsn: str) -> int:
    with psycopg.connect(session_dsn) as conn:
        return int(conn.execute("SHOW server_version_num").fetchone()[0]) // 10000


def _split_password(dsn: str) -> tuple[str, str]:
    """(`dsn` without its password, the password decoded): the password goes to PGPASSWORD,
    never into a file."""
    (password,) = dsn_env.passwords(dsn) or [""]
    if not password:
        return str(dsn), ""
    return str(dsn).replace(f":{password}@", "@", 1), urllib.parse.unquote(password)


@pytest.fixture
def standin(_test_database):
    """A private database with a marker table of 3 rows: what `make db-restore` would replace."""
    name = _derived(_test_database, "standin")
    _admin(_test_database, sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(name)))
    _admin(_test_database, sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    dsn = _with_db(_test_database, name)
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("CREATE TABLE restore_marker (n int)")
        conn.execute("INSERT INTO restore_marker SELECT generate_series(1, 3)")
    try:
        yield name, dsn
    finally:
        _admin(_test_database, sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(name)))


def _make_db_restore(
    tmp_path: Path, target_dsn: str, dump: Path, *make_vars: str, path_pg_restore: int = 0
):
    """`make db-restore` run from a scratch directory whose `.env` names `target_dsn`.

    COMPOSE is a recorder, and so is `docker` on PATH as a second net: whatever the target
    tries to stop or start is written to `calls`, and nothing real is touched. With
    `path_pg_restore`, PATH's `pg_restore` also reports that major version and hands every
    other call to the real one: a host whose PATH client differs from the server, simulated
    without installing anything. Returns (exit code, output, the recorded calls)."""
    work = tmp_path / "work"
    fakebin = work / "bin"
    fakebin.mkdir(parents=True)
    calls = work / "calls"
    scripts = {tool: f'echo "$*" >> "{calls}"\n' for tool in ("compose", "docker")}
    if path_pg_restore:
        scripts["pg_restore"] = (
            f'[ "$1" = --version ] && {{ echo "pg_restore (PostgreSQL) {path_pg_restore}.0"; '
            f'exit 0; }}\nexec "{shutil.which("pg_restore")}" "$@"\n'
        )
    for tool, body in scripts.items():
        (fakebin / tool).write_text("#!/bin/sh\n" + body, encoding="utf-8")
        (fakebin / tool).chmod(0o755)
    shown_dsn, password = _split_password(target_dsn)
    (work / ".env").write_text(f"DATABASE_URL_OWNER={shown_dsn}\n", encoding="utf-8")
    rc, out = _run(
        [
            "make",
            "--no-print-directory",
            "-C",
            work,
            "-f",
            MAKEFILE,
            "db-restore",
            f"FILE={dump}",
            f"COMPOSE={fakebin / 'compose'}",
            *make_vars,
        ],
        cwd=work,
        env=_env(PATH=f"{fakebin}:{os.environ['PATH']}", PGPASSWORD=password),
    )
    recorded = calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []
    return rc, out, recorded


def _marker_rows(dsn: str) -> int:
    with psycopg.connect(dsn) as conn:
        return conn.execute("SELECT count(*) FROM restore_marker").fetchone()[0]


def _unreadable_dump(tmp_path: Path) -> Path:
    dump = tmp_path / "unreadable.dump"
    dump.write_bytes(b"not a pg_dump archive\n" * 64)
    return dump


def _readable_dump(tmp_path: Path, session_dsn: str) -> Path:
    """A dump of the session database, made by backup.sh (the server-major pg_dump)."""
    source, password = _split_password(session_dsn)
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    rc, out = _run(
        ["bash", BACKUP, "--quiet"],
        cwd=backup_dir,
        env=_env(DATABASE_URL_OWNER=source, PGPASSWORD=password),
    )
    assert rc == 0, out
    (dump,) = sorted((backup_dir / "backups").glob("soc-*.dump"))
    return dump


def _assert_refused_untouched(rc, out, calls, session_dsn, name, oid, dsn) -> None:
    assert rc == 2 and "db-restore] Error 2" in out, out  # the recipe's own exit 2
    assert "nothing was stopped or dropped" in out, out
    assert calls == [], out  # neither stopped nor restarted
    assert _database_oid(session_dsn, name) == oid  # not dropped and recreated
    assert _marker_rows(dsn) == 3
    assert "://" not in out, out  # no DSN printed, masked or not


@pytest.mark.db
def test_db_restore_refuses_an_unreadable_dump_before_it_stops_or_drops_anything(
    _test_database, standin, tmp_path
):
    name, dsn = standin
    oid = _database_oid(_test_database, name)
    dump = _unreadable_dump(tmp_path)
    major = _server_major(_test_database)
    server_major = Path(f"/usr/lib/postgresql/{major}/bin/pg_restore")
    assert server_major.exists(), f"no PostgreSQL {major} client here: backup.sh needs it too"

    rc, out, calls = _make_db_restore(tmp_path, dsn, dump)

    _assert_refused_untouched(rc, out, calls, _test_database, name, oid, dsn)
    assert f"db-restore: server {major}, {server_major}\n" in out, out
    assert f"REFUSED — {server_major} cannot read {dump}" in out, out
    assert "warning" not in out, out


@pytest.mark.db
def test_db_restore_falls_back_to_path_with_a_warning_and_still_reads_the_dump_first(
    _test_database, standin, tmp_path
):
    name, dsn = standin
    oid = _database_oid(_test_database, name)
    dump = _unreadable_dump(tmp_path)
    major = _server_major(_test_database)
    nowhere = tmp_path / "no_postgresql"

    rc, out, calls = _make_db_restore(
        tmp_path, dsn, dump, f"PG_LIB={nowhere}", path_pg_restore=major
    )

    _assert_refused_untouched(rc, out, calls, _test_database, name, oid, dsn)
    assert f"warning — no PostgreSQL {major} client under {nowhere}; using " in out, out
    assert f"cannot read {dump}" in out, out


@pytest.mark.db
def test_db_restore_refuses_a_pg_restore_newer_than_the_server(_test_database, standin, tmp_path):
    """A newer pg_restore reads the dump (--list passes) and then fails into the older server
    on `SET transaction_timeout` — after the drop (P5-T12's measurement, 18 into 16). So it is
    refused before anything, whatever the dump."""
    name, dsn = standin
    oid = _database_oid(_test_database, name)
    dump = _readable_dump(tmp_path, _test_database)
    major = _server_major(_test_database)

    rc, out, calls = _make_db_restore(
        tmp_path, dsn, dump, f"PG_LIB={tmp_path / 'no_postgresql'}", path_pg_restore=major + 2
    )

    _assert_refused_untouched(rc, out, calls, _test_database, name, oid, dsn)
    assert f"is PostgreSQL {major + 2}, the server {major}" in out, out


@pytest.mark.db
def test_db_restore_replaces_the_database_from_a_readable_dump(_test_database, standin, tmp_path):
    """The target's meaning is kept: stop, drop and recreate, restore, restart — and on this
    host (server 16, PATH 18) the restore now succeeds."""
    name, dsn = standin
    dump = _readable_dump(tmp_path, _test_database)

    rc, out, calls = _make_db_restore(tmp_path, dsn, dump)

    assert rc == 0, out
    assert calls == ["stop app worker", "up -d app worker"], out
    assert f"db-restore: {dump} → {name} ({MIGRATIONS} migrations)\n" in out, out
    with psycopg.connect(dsn) as conn:
        assert conn.execute("SELECT to_regclass('public.restore_marker')").fetchone()[0] is None
        assert conn.execute("SELECT count(*) FROM schema_migrations").fetchone()[0] == MIGRATIONS
    assert "://" not in out, out


@pytest.mark.db
def test_the_session_fixture_hands_out_a_redacting_dsn(request):
    """The fixture on the real server (the inner runs stub the server out). The value is
    fetched, never a test argument, and only booleans reach the asserts: no failure here can
    print it."""
    value = request.getfixturevalue("_test_database")
    is_a_dsn = type(value) is conftest.Dsn
    repr_hides_the_password = all(p not in repr(value) for p in dsn_env.passwords(value))

    assert is_a_dsn
    assert repr_hides_the_password
