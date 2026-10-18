"""`scripts/migrate.sh` when a `schema_migrations` lookup FAILS (P11-T20 row 3).

The script decides "applied or not" by asking `schema_migrations`. It used to read the answer of
`psql` inside `$(...)` as text, so a lookup that failed (permission denied, a lost connection)
looked the same as "no such row": the script then announced `applying 001_bang_nen` for a
database that already held every migration, and stopped on `relation "assets" already exists`.
Loud, but wrong, and it would have applied an unrecorded migration over a database it could not
read. Now a failed lookup is a clear error, exit 3, before anything is applied.

The normal paths keep their output lines (the runbooks quote them): `test_schema_v3_019.py`
asserts `migrate: applying …`, `N applied, M already present` and the absent-table line's
effects on every run.

Both tests build a scratch database and drop it (and the one scratch role) afterwards.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import psycopg
import pytest
from psycopg import sql

from tests import conftest
from tests.scratch_db import _with_db, scratch_database

pytestmark = pytest.mark.db


def _run_migrate(dsn, **env: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "scripts/migrate.sh", str(dsn)],
        cwd=conftest.REPO_ROOT,
        env={**os.environ, **env},
        capture_output=True,
        text=True,
        check=False,
    )


def _session_dsn():
    session = conftest.require_test_dsn(
        os.environ.get("TEST_DATABASE_URL", conftest.DEFAULT_TEST_DATABASE_URL)
    )
    if shutil.which("psql") is None:
        pytest.skip("psql is not installed")
    return session


def test_a_role_that_cannot_read_schema_migrations_stops_the_run_with_a_clear_error():
    """A migrated scratch database, and a scratch role with no SELECT on `schema_migrations`
    (NOSUPERUSER, NOLOGIN; the script runs as it through `PGOPTIONS=-c role=...`, the way
    `test_schema_v3_019.py` applies a migration as another role). Every migration is recorded, so
    the right answer is `0 applied`; the wrong one is to think none is. Expected: exit 3, the new
    error on stderr, no `applying` line, nothing changed in `schema_migrations`."""
    session = _session_dsn()
    with scratch_database("migsel") as dsn:
        role = f"{conftest._dbname(session)}_migsel"  # roles are cluster-global
        admin = psycopg.connect(conftest._maintenance_dsn(session), autocommit=True)
        try:
            (superuser,) = admin.execute(
                "SELECT rolsuper FROM pg_roles WHERE rolname = current_user"
            ).fetchone()
            if not superuser:
                pytest.skip("TEST_DATABASE_URL's role cannot create the scratch role")
            admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
            admin.execute(
                sql.SQL("CREATE ROLE {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOLOGIN").format(
                    sql.Identifier(role)
                )
            )
            with psycopg.connect(dsn) as conn:
                (before,) = conn.execute("SELECT count(*) FROM schema_migrations").fetchone()
                # The premise: as that role the lookup really is refused (and nothing else is).
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    conn.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(role)))
                    conn.execute("SELECT 1 FROM schema_migrations WHERE version = '001_bang_nen'")
                conn.rollback()
            assert before > 0

            run = _run_migrate(dsn, PGOPTIONS=f"-c role={role}")

            # Plain values only (no `assert run.returncode`, no `run.stderr` in an assert):
            # pytest explains those by printing `run` whole, argument list and DSN included.
            code, out, err = run.returncode, run.stdout, run.stderr
            if code != 3:
                pytest.fail(f"migrate.sh exit {code}, expected 3:\n{err}")
            assert "permission denied for table schema_migrations" in err
            assert "migrate: cannot read schema_migrations (looking up 001_bang_nen)" in err, err
            assert "nothing applied" in err
            assert "applying" not in out, out
            assert "migrate:" not in out, out  # no "N applied, M already present" either
            with psycopg.connect(dsn) as conn:
                (after,) = conn.execute("SELECT count(*) FROM schema_migrations").fetchone()
                assert after == before
        finally:
            try:
                admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
            finally:
                admin.close()


def test_a_database_that_cannot_be_asked_stops_the_run_instead_of_applying_the_base_schema():
    """The first lookup (`to_regclass`) fails too when the database cannot be reached: here a
    database that does not exist. It used to read as "schema_migrations absent" and go on to
    apply `schema.sql`; now it stops with exit 3 before it prints that line."""
    session = _session_dsn()
    try:
        admin = psycopg.connect(conftest._maintenance_dsn(session), autocommit=True)
    except psycopg.OperationalError:
        pytest.skip(f"TEST_DATABASE_URL unreachable: {conftest.redact_dsn(session)}")
    admin.close()
    missing = _with_db(session, f"{conftest._dbname(session)}_migmissing_test")

    run = _run_migrate(missing)

    code, out, err = run.returncode, run.stdout, run.stderr
    if code != 3:
        pytest.fail(f"migrate.sh exit {code}, expected 3:\n{err}")
    assert "does not exist" in err  # psql's own error, passed through
    assert "migrate: cannot look up whether schema_migrations exists" in err, err
    assert "absent" not in out and "applying" not in out, out


# A `psql` that behaves as the real one, except for ONE statement, the count of the base
# migrations the script has just recorded (`scripts/migrate.sh` after the base schema, P11-T20
# row 37): that one is refused, as a lost connection or a missing SELECT would refuse it.
_PSQL_THAT_CANNOT_COUNT = """#!/usr/bin/env bash
for arg in "$@"; do
  case "$arg" in
    *"count(*) FROM schema_migrations"*)
      echo "psql: error: simulated failure of the count lookup" >&2
      exit 2
      ;;
  esac
done
exec {real_psql} "$@"
"""


def test_a_failed_count_after_the_base_schema_stops_the_run_instead_of_printing_an_empty_count(
    tmp_path,
):
    """Row 37 (P11-T20 review n3). The last lookup of the script was the one left unguarded: the
    `$(psql ...)` sat inside an `echo`, so a failure printed `recorded  base migrations` (an empty
    count) and the run went on as if nothing had happened. Now it is the same exit 3 as the other
    lookups, with the base schema (applied and recorded by then) left as it is and a message that
    says so: `nothing applied` would be false here. A second run, with the real psql, finishes."""
    session = _session_dsn()
    try:
        admin = psycopg.connect(conftest._maintenance_dsn(session), autocommit=True)
    except psycopg.OperationalError:
        pytest.skip(f"TEST_DATABASE_URL unreachable: {conftest.redact_dsn(session)}")
    name = f"{conftest._dbname(session)}_migcount_test"
    dsn = _with_db(session, name)
    real_psql = shutil.which("psql")
    assert real_psql is not None  # `_session_dsn` skipped otherwise
    shim = tmp_path / "psql"
    shim.write_text(_PSQL_THAT_CANNOT_COUNT.format(real_psql=real_psql), encoding="utf-8")
    shim.chmod(0o755)
    try:
        admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(name)))
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))

        run = _run_migrate(dsn, PATH=f"{tmp_path}{os.pathsep}{os.environ['PATH']}")

        code, out, err = run.returncode, run.stdout, run.stderr
        if code != 3:
            pytest.fail(f"migrate.sh exit {code}, expected 3:\n{out}\n{err}")
        assert "simulated failure of the count lookup" in err  # psql's own error, passed through
        assert "migrate: cannot count the base migrations" in err, err
        assert "the base schema is applied and recorded" in err
        assert "nothing applied" not in err  # it would be false: the base schema went in
        assert "schema_migrations absent" in out  # the base schema was applied, then the stop
        assert "recorded" not in out and "already present" not in out, out
        with psycopg.connect(dsn) as conn:
            (recorded,) = conn.execute("SELECT count(*) FROM schema_migrations").fetchone()
        assert recorded > 0  # recorded before the lookup that failed

        again = _run_migrate(dsn)  # the real psql: the loop finds everything present
        code, out = again.returncode, again.stdout
        if code != 0:
            pytest.fail(f"migrate.sh exit {code}, expected 0:\n{again.stderr}")
        assert f"migrate: 0 applied, {recorded} already present" in out, out
    finally:
        admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(name)))
        admin.close()
