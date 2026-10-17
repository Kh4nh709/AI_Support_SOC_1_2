"""Migration 019 — the admin console's schema (P11-T01, DEC-200).

Three changes, each on trial here against the migrated test database:

* `settings`: the three LLM limits the admin may edit on the web. Only those three keys, only a
  positive integer, and always who changed it. `app_rw` reads and writes it (migration 017's
  default privileges cover a table created after it).
* `users.last_login_at`: stamped by `infra/auth.login` on success (P11-T02), NULL until then.
* `admin.settings_changed`: the 28th name of `ck_audit_event_type`.

Each statement expected to fail runs in its own savepoint, so the next one still runs; the `db`
fixture rolls everything back at the end.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import uuid

import psycopg
import pytest
from app.audit import events
from app.infra import auth
from psycopg import sql

from tests import conftest
from tests.scratch_db import _with_db

pytestmark = pytest.mark.db

KEYS = ("LLM_MONTHLY_USD_CAP", "ANALYZE_QUOTA_PER_USER_DAY", "LLM_TIMEOUT_S")


def _user(db) -> str:
    return auth.create_user(
        db,
        username=f"p11t01-{uuid.uuid4().hex[:8]}",
        display_name="P11-T01",
        role="admin",
        password="unused-unused",
    )


def _insert(db, key: str, value: object, updated_by: object) -> None:
    db.execute(
        "INSERT INTO settings (key, value, updated_by) VALUES (%s, %s, %s)",
        (key, value, updated_by),
    )


def test_019_records_itself(db):
    """The row is there in the shared test database. That is all this test can show: the
    database is built from `schema.sql`, and `migrate.sh` records every version named in that
    file's source banners, so the row exists even when the 019 FILE has no
    `INSERT INTO schema_migrations`. Whether the file records itself is the upgrade test's job
    (its third `migrate.sh` run)."""
    row = db.execute(
        "SELECT 1 FROM schema_migrations WHERE version = '019_admin_console'"
    ).fetchone()
    assert row is not None, "019_admin_console is not in the test database's schema_migrations"


def test_settings_has_the_four_columns_with_their_types(db):
    rows = db.execute(
        "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
        "WHERE table_name = 'settings' ORDER BY ordinal_position"
    ).fetchall()
    assert rows == [
        ("key", "text", "NO"),
        ("value", "integer", "NO"),
        ("updated_at", "timestamp with time zone", "NO"),
        ("updated_by", "uuid", "NO"),
    ]


@pytest.mark.parametrize("key", KEYS)
def test_settings_accepts_each_of_the_three_keys(db, key):
    _insert(db, key, 30, _user(db))
    (value,) = db.execute("SELECT value FROM settings WHERE key = %s", (key,)).fetchone()
    assert value == 30


def test_ck_settings_key_admits_exactly_the_three_keys(db):
    """The refused keys below are four samples; a fourth key admitted by the CHECK would leave
    them all refused. The names are read from the constraint itself."""
    (definition,) = db.execute(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
        "WHERE conname = 'ck_settings_key' AND conrelid = 'settings'::regclass"
    ).fetchone()
    assert sorted(re.findall(r"'([^']*)'", definition)) == sorted(KEYS), definition


@pytest.mark.parametrize("key", ["JWT_SECRET", "LLM_API_KEY", "llm_monthly_usd_cap", ""])
def test_settings_refuses_any_other_key(db, key):
    user_id = _user(db)
    with pytest.raises(psycopg.errors.CheckViolation), db.transaction():
        _insert(db, key, 30, user_id)


@pytest.mark.parametrize("value", [0, -1])
def test_settings_refuses_a_value_that_is_not_positive(db, value):
    user_id = _user(db)
    with pytest.raises(psycopg.errors.CheckViolation), db.transaction():
        _insert(db, "LLM_TIMEOUT_S", value, user_id)


def test_settings_refuses_a_change_nobody_made(db):
    # A statement first: it opens the fixture's outer transaction, so the two blocks below are
    # savepoints. As the first statement, `db.transaction()` would be the outermost one and COMMIT
    # a stray row into the session database whenever the schema stopped refusing it.
    _user(db)
    with pytest.raises(psycopg.errors.NotNullViolation), db.transaction():
        _insert(db, "LLM_TIMEOUT_S", 90, None)
    with pytest.raises(psycopg.errors.ForeignKeyViolation), db.transaction():
        _insert(db, "LLM_TIMEOUT_S", 90, str(uuid.uuid4()))


def test_settings_key_is_unique(db):
    user_id = _user(db)
    _insert(db, "LLM_TIMEOUT_S", 90, user_id)
    with pytest.raises(psycopg.errors.UniqueViolation), db.transaction():
        _insert(db, "LLM_TIMEOUT_S", 60, user_id)


def test_app_rw_reads_and_upserts_settings(db):
    user_id = _user(db)
    with db.transaction():
        db.execute("SET LOCAL ROLE app_rw")
        for value in (40, 45):
            db.execute(
                "INSERT INTO settings (key, value, updated_by) VALUES ('LLM_MONTHLY_USD_CAP', %s, %s) "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, "
                "updated_at = now(), updated_by = EXCLUDED.updated_by",
                (value, user_id),
            )
        (value,) = db.execute(
            "SELECT value FROM settings WHERE key = 'LLM_MONTHLY_USD_CAP'"
        ).fetchone()
    assert value == 45


def test_users_last_login_at_is_a_nullable_timestamptz_null_for_a_new_user(db):
    data_type, nullable = db.execute(
        "SELECT data_type, is_nullable FROM information_schema.columns "
        "WHERE table_name = 'users' AND column_name = 'last_login_at'"
    ).fetchone()
    assert (data_type, nullable) == ("timestamp with time zone", "YES")
    user_id = _user(db)
    (stamp,) = db.execute(
        "SELECT last_login_at FROM users WHERE user_id = %s", (user_id,)
    ).fetchone()
    assert stamp is None


def test_019_applies_on_a_database_at_018_the_way_make_migrate_runs_it(tmp_path):
    """The live database is at 018: `make migrate` applies the 019 FILE to it, never
    `schema.sql`. The shared fixture builds from `schema.sql`, so on its own it would not
    notice a 019 that differs from what `schema.sql` holds. Here a database is built from a
    copy of `docs/Schema` without 019 (so at 018, through the same `migrate.sh`), and the
    real `migrate.sh` then applies the real 019 file to it."""
    session = conftest.require_test_dsn(
        os.environ.get("TEST_DATABASE_URL", conftest.DEFAULT_TEST_DATABASE_URL)
    )
    if shutil.which("psql") is None:
        pytest.skip("psql is not installed")
    schema_dir = conftest.REPO_ROOT / "docs" / "Schema"
    at_018 = tmp_path / "Schema"
    at_018.mkdir()
    for path in schema_dir.glob("[0-9][0-9][0-9]_*.sql"):
        if not path.name.startswith("019_"):
            shutil.copy(path, at_018)
    shutil.copy(schema_dir / "build_schema.py", at_018)
    # Counts come from the files, never a literal: the next migration must not turn this red.
    stems = {path.stem for path in schema_dir.glob("[0-9][0-9][0-9]_*.sql")}
    total = len(stems)  # 19 today
    before = total - 1  # every migration before 019 (18 today)
    assert len(list(at_018.glob("[0-9][0-9][0-9]_*.sql"))) == before
    built = subprocess.run(
        ["python3", str(at_018 / "build_schema.py")], capture_output=True, text=True, check=False
    )
    if built.returncode != 0:
        pytest.fail(f"build_schema.py exit {built.returncode}:\n{built.stderr}")

    dbname = f"{conftest._dbname(session)}_019up_test"
    dsn = _with_db(session, dbname)
    admin = psycopg.connect(conftest._maintenance_dsn(session), autocommit=True)
    try:
        admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(dbname)))
        runs = []
        # Three runs: the base at 018; the real tree (applies 019); the real tree again, which
        # is where a 019 that forgot its `INSERT INTO schema_migrations` shows (it would be
        # re-applied and stop on "relation settings already exists").
        for mig_dir in (at_018, schema_dir, schema_dir):
            run = subprocess.run(
                ["bash", "scripts/migrate.sh", str(dsn)],
                cwd=conftest.REPO_ROOT,
                env={**os.environ, "MIGRATIONS_DIR": str(mig_dir)},
                capture_output=True,
                text=True,
                check=False,
            )
            # Plain values only, and not `assert run.returncode == 0`: pytest explains that by
            # printing `run` whole, argument list and DSN included (P5-T12; conftest.py does the same).
            if run.returncode != 0:
                pytest.fail(f"migrate.sh exit {run.returncode}:\n{run.stderr}")
            runs.append(run.stdout)
        assert "019_admin_console" not in runs[0]
        assert f"migrate: 0 applied, {before} already present" in runs[0]
        assert "migrate: applying 019_admin_console" in runs[1]
        assert f"migrate: 1 applied, {before} already present" in runs[1]
        assert f"migrate: 0 applied, {total} already present" in runs[2]
        assert "migrate: applying" not in runs[2]
        with psycopg.connect(dsn) as conn:
            recorded = {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}
            assert recorded == stems
            user_id = conn.execute(
                "INSERT INTO users (user_id, username, display_name, role, password_hash) "
                "VALUES (gen_random_uuid(), 'p11t01-up', 'up', 'admin', 'x') RETURNING user_id"
            ).fetchone()[0]
            conn.execute(
                "INSERT INTO settings (key, value, updated_by) VALUES ('LLM_TIMEOUT_S', 90, %s)",
                (user_id,),
            )
            conn.execute(
                "INSERT INTO audit_events (event_type, subject_id, actor_id, actor_role) "
                "VALUES ('admin.settings_changed', 'LLM_TIMEOUT_S', %s, 'admin')",
                (user_id,),
            )
            (last_login,) = conn.execute(
                "SELECT last_login_at FROM users WHERE user_id = %s", (user_id,)
            ).fetchone()
            assert last_login is None
            conn.rollback()
    finally:
        admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))
        admin.close()


def test_admin_settings_changed_is_the_28th_event_type(db):
    user_id = _user(db)
    audit_id = events.write_event(
        db,
        "admin.settings_changed",
        "LLM_TIMEOUT_S",
        "admin",
        actor_id=user_id,
        payload={"changes": [{"key": "LLM_TIMEOUT_S", "old": 120, "new": 90}]},
    )
    assert audit_id
    with pytest.raises(psycopg.errors.CheckViolation), db.transaction():
        db.execute(
            "INSERT INTO audit_events (event_type, subject_id, actor_id, actor_role) "
            "VALUES ('admin.nonsense', 'x', %s, 'admin')",
            (user_id,),
        )
