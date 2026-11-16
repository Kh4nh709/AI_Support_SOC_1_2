"""Migration 025 — the SOAR review tickets on the web (spec 2026-11-16 §6).

One migration: one table and one constraint, each on trial here against the migrated test database.

* `soar_reviews`: the ticket n8n pushes and the analyst decides on. The closed sets (`kind`, `status` with
  the web's own `processing`, `severity`, `action_type`, `action_via`, `prev_status`) are CHECKs, and a
  `processing` row has to name who locked it, since when, and the state it had before;
* three indexes: `(status)`, `(created_at DESC)`, `(case_number)`;
* rights: `app_rw` reads, inserts and updates and nothing more (a ticket is never deleted);
* `ck_audit_event_type` takes `soar.review_received` and `soar.review_decided` (40 -> 42; the 40 before
  them stay first, in 024's order).

025 stands on 024: it replaces the CHECK 024 left, and touches no other table. The upgrade tests build a
scratch database from the migrations numbered 24 and below and apply the real file to it.

Each statement expected to fail runs in its own savepoint, so the next one still runs; the `db` fixture
rolls everything back at the end.
"""

from __future__ import annotations

import shutil
import uuid
from datetime import UTC, datetime
from pathlib import Path

import psycopg
import pytest
from psycopg import sql

from tests import conftest
from tests.scratch_db import _schema_tree_through, _with_db, insert_alert, insert_user
from tests.test_migration_020 import (
    _constraint_def,
    _migrate,
    _quoted,
    _refused,
    _session_dsn,
)
from tests.test_migration_024 import EVENTS_BEFORE_024, EVENTS_IN_024

pytestmark = pytest.mark.db

SCHEMA_DIR = conftest.REPO_ROOT / "docs" / "Schema"
MIGRATION_FILE = SCHEMA_DIR / "025_soar_reviews.sql"
MIGRATION_FILES = "[0-9][0-9][0-9]_*.sql"

EVENTS_IN_025 = ["soar.review_received", "soar.review_decided"]
EVENTS_BEFORE_025 = EVENTS_BEFORE_024 + EVENTS_IN_024

T0 = datetime(2026, 11, 16, 9, 0, tzinfo=UTC)

#: The columns of the table, in the spec's order, with the type each is stored as.
COLUMNS = [
    ("id", "text"),
    ("kind", "text"),
    ("status", "text"),
    ("severity", "text"),
    ("title", "text"),
    ("simulated", "boolean"),
    ("case_id", "text"),
    ("case_number", "bigint"),
    ("action_type", "text"),
    ("action_text", "text"),
    ("action_target", "text"),
    ("action_via", "text"),
    ("action_agent", "text"),
    ("host", "text"),
    ("agent_id", "text"),
    ("user_name", "text"),
    ("src_ip", "text"),
    ("domain", "text"),
    ("scenario_id", "text"),
    ("scenario_name", "text"),
    ("score", "integer"),
    ("note", "text"),
    ("buttons", "jsonb"),
    ("created_at", "timestamp with time zone"),
    ("auto_expire_at", "timestamp with time zone"),
    ("remind_every_minutes", "integer"),
    ("next_remind_at", "timestamp with time zone"),
    ("decided_by", "text"),
    ("decided_at", "timestamp with time zone"),
    ("result", "text"),
    ("last_error", "text"),
    ("locked_by", "text"),
    ("locked_at", "timestamp with time zone"),
    ("prev_status", "text"),
    ("last_sent_at", "timestamp with time zone"),
    ("received_at", "timestamp with time zone"),
    ("raw", "jsonb"),
    ("updated_at", "timestamp with time zone"),
]


def _review(db, **over) -> str:
    """One `soar_reviews` row on `db` (the caller rolls back); its id."""
    row = {
        "id": f"m25-{uuid.uuid4().hex[:10]}",
        "kind": "review",
        "status": "open",
        "created_at": T0,
        "last_sent_at": T0,
        "raw": "{}",
    }
    row.update(over)
    columns = ", ".join(row)
    marks = ", ".join(["%s"] * len(row))
    db.execute(f"INSERT INTO soar_reviews ({columns}) VALUES ({marks})", list(row.values()))
    return row["id"]


def _constraint_of(error: psycopg.Error) -> str | None:
    return error.diag.constraint_name


# ── the migration records itself ────────────────────────────────────────────────────────────


def test_025_records_itself(db):
    row = db.execute(
        "SELECT 1 FROM schema_migrations WHERE version = '025_soar_reviews'"
    ).fetchone()
    assert row is not None, "025_soar_reviews is not in the test database's schema_migrations"


def test_a_second_apply_is_refused_by_schema_migrations(db):
    db.execute("SELECT 1")
    with pytest.raises(psycopg.errors.UniqueViolation), db.transaction():
        db.execute("INSERT INTO schema_migrations (version) VALUES ('025_soar_reviews')")


# ── the table ───────────────────────────────────────────────────────────────────────────────


def test_the_table_has_the_spec_columns_in_the_spec_order(db):
    rows = db.execute(
        "SELECT column_name, data_type FROM information_schema.columns "
        "WHERE table_schema = 'public' AND table_name = 'soar_reviews' ORDER BY ordinal_position"
    ).fetchall()
    assert rows == COLUMNS


def test_the_id_is_the_primary_key(db):
    key = db.execute(
        "SELECT a.attname FROM pg_index i JOIN pg_attribute a "
        "ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) "
        "WHERE i.indrelid = 'soar_reviews'::regclass AND i.indisprimary"
    ).fetchall()
    assert key == [("id",)]


def test_a_second_row_with_the_same_id_is_refused(db):
    first = _review(db)
    error = _refused(db, psycopg.errors.UniqueViolation, lambda: _review(db, id=first))
    assert _constraint_of(error) == "soar_reviews_pkey"


def test_only_the_columns_n8n_always_sends_are_required(db):
    """`id`, `kind`, `status`, the two instants and the body as sent: a notice or a review with every other
    field null is storable, and the defaults are the ones the spec names."""
    review_id = _review(db)
    row = db.execute(
        "SELECT severity, simulated, buttons, remind_every_minutes, updated_at IS NOT NULL, "
        "case_number, locked_at, prev_status FROM soar_reviews WHERE id = %s",
        (review_id,),
    ).fetchone()
    assert row == ("info", False, [], 0, True, None, None, None)


def test_received_at_is_the_databases_clock_at_the_insert_and_never_null(db):
    """The web's own arrival time (the new-ticket signal): n8n's `created_at` can be older than a ticket already shown."""
    review_id = _review(db, created_at=T0)  # a ticket n8n created long ago, delivered now
    received, now = db.execute(
        "SELECT received_at, now() FROM soar_reviews WHERE id = %s", (review_id,)
    ).fetchone()
    assert received == now and received > T0
    error = _refused(db, psycopg.errors.NotNullViolation, lambda: _review(db, received_at=None))
    assert error.diag.column_name == "received_at"


@pytest.mark.parametrize(
    "column", ["id", "kind", "status", "severity", "created_at", "last_sent_at", "raw"]
)
def test_a_required_column_refuses_null(db, column):
    if column == "id":
        statement = lambda: db.execute(
            "INSERT INTO soar_reviews (id, kind, status, created_at, last_sent_at, raw) "
            "VALUES (NULL, 'review', 'open', %s, %s, '{}')",
            (T0, T0),
        )
    else:
        statement = lambda: _review(db, **{column: None})
    error = _refused(db, psycopg.errors.NotNullViolation, statement)
    assert error.diag.column_name == column


def test_the_raw_body_and_the_buttons_are_jsonb(db):
    review_id = _review(
        db,
        raw='{"a": [1, {"b": null}]}',
        buttons='[{"decision": "keep", "label": "Giữ"}]',
    )
    row = db.execute("SELECT raw, buttons FROM soar_reviews WHERE id = %s", (review_id,)).fetchone()
    assert row == ({"a": [1, {"b": None}]}, [{"decision": "keep", "label": "Giữ"}])


def test_a_case_number_is_a_bigint(db):
    review_id = _review(db, case_number=2**40)
    assert db.execute(
        "SELECT case_number FROM soar_reviews WHERE id = %s", (review_id,)
    ).fetchone() == (2**40,)


# ── the closed sets ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("kind", ["review", "notice"])
def test_the_two_kinds_are_accepted(db, kind):
    _review(db, kind=kind, status="info" if kind == "notice" else "open")


@pytest.mark.parametrize("kind", ["Review", "ticket", "", "review ", "notice\n"])
def test_any_other_kind_is_refused(db, kind):
    error = _refused(db, psycopg.errors.CheckViolation, lambda: _review(db, kind=kind))
    assert _constraint_of(error) == "ck_soar_reviews_kind"


@pytest.mark.parametrize("status", ["open", "kept", "undone", "false_positive", "expired", "info"])
def test_the_six_n8n_statuses_are_accepted(db, status):
    _review(db, status=status)


def test_processing_is_accepted_with_its_lock(db):
    _review(db, status="processing", locked_by="alice", locked_at=T0, prev_status="open")


@pytest.mark.parametrize(
    "status", ["Open", "closed", "decided", "", "open ", "processing "], ids=repr
)
def test_any_other_status_is_refused(db, status):
    error = _refused(
        db,
        psycopg.errors.CheckViolation,
        lambda: _review(db, status=status, locked_by="a", locked_at=T0, prev_status="open"),
    )
    assert _constraint_of(error) == "ck_soar_reviews_status"


@pytest.mark.parametrize("severity", ["info", "warning", "error"])
def test_the_three_severities_are_accepted(db, severity):
    _review(db, severity=severity)


@pytest.mark.parametrize("severity", ["critical", "Info", "", "warn", "error "])
def test_any_other_severity_is_refused(db, severity):
    error = _refused(db, psycopg.errors.CheckViolation, lambda: _review(db, severity=severity))
    assert _constraint_of(error) == "ck_soar_reviews_severity"


@pytest.mark.parametrize(
    "action_type",
    [
        None,
        "block_ip",
        "sinkhole_domain",
        "isolate_host",
        "disable_user",
        "disable_xp_cmdshell",
        "kill_process",
    ],
)
def test_the_six_action_types_and_none_are_accepted(db, action_type):
    _review(db, action_type=action_type)


@pytest.mark.parametrize("action_type", ["block", "Block_IP", "", "delete_host", "kill_process "])
def test_any_other_action_type_is_refused(db, action_type):
    error = _refused(
        db, psycopg.errors.CheckViolation, lambda: _review(db, action_type=action_type)
    )
    assert _constraint_of(error) == "ck_soar_reviews_action_type"


@pytest.mark.parametrize("via", [None, "pfsense", "wazuh"])
def test_the_two_channels_and_none_are_accepted(db, via):
    _review(db, action_via=via)


@pytest.mark.parametrize("via", ["PFSENSE", "n8n", "", "wazuh "])
def test_any_other_channel_is_refused(db, via):
    error = _refused(db, psycopg.errors.CheckViolation, lambda: _review(db, action_via=via))
    assert _constraint_of(error) == "ck_soar_reviews_action_via"


@pytest.mark.parametrize(
    "prev", [None, "open", "kept", "undone", "false_positive", "expired", "info"]
)
def test_a_previous_status_is_one_of_the_six_or_none(db, prev):
    _review(db, prev_status=prev)


@pytest.mark.parametrize("prev", ["processing", "closed", ""])
def test_a_previous_status_is_never_processing(db, prev):
    """A lock is released to the state the row had; that state is never itself a lock."""
    error = _refused(db, psycopg.errors.CheckViolation, lambda: _review(db, prev_status=prev))
    assert _constraint_of(error) == "ck_soar_reviews_prev_status"


# ── a processing row is locked by someone, since when, and has a state to go back to ─────────

LOCK = {"locked_by": "alice", "locked_at": T0, "prev_status": "open"}


@pytest.mark.parametrize("missing", sorted(LOCK))
def test_a_processing_row_without_one_of_its_three_lock_columns_is_refused(db, missing):
    fields = {**LOCK, missing: None}
    error = _refused(
        db, psycopg.errors.CheckViolation, lambda: _review(db, status="processing", **fields)
    )
    assert _constraint_of(error) == "ck_soar_reviews_processing_lock"


def test_a_row_can_be_locked_by_an_update_and_released_by_one(db):
    review_id = _review(db)
    db.execute(
        "UPDATE soar_reviews SET status = 'processing', prev_status = status, "
        "locked_by = 'alice', locked_at = now() WHERE id = %s",
        (review_id,),
    )
    error = _refused(
        db,
        psycopg.errors.CheckViolation,
        lambda: db.execute("UPDATE soar_reviews SET locked_by = NULL WHERE id = %s", (review_id,)),
    )
    assert _constraint_of(error) == "ck_soar_reviews_processing_lock"
    db.execute(
        "UPDATE soar_reviews SET status = prev_status, locked_by = NULL, locked_at = NULL, "
        "prev_status = NULL WHERE id = %s",
        (review_id,),
    )


# ── the indexes ─────────────────────────────────────────────────────────────────────────────


def test_the_table_has_exactly_its_key_and_the_three_indexes(db):
    rows = db.execute(
        "SELECT indexname, indexdef FROM pg_indexes "
        "WHERE schemaname = 'public' AND tablename = 'soar_reviews' ORDER BY indexname"
    ).fetchall()
    names = [name for name, _ in rows]
    assert names == [
        "ix_soar_reviews_case_number",
        "ix_soar_reviews_created_at",
        "ix_soar_reviews_status",
        "soar_reviews_pkey",
    ]
    definitions = dict(rows)
    assert "(status)" in definitions["ix_soar_reviews_status"]
    assert "(created_at DESC)" in definitions["ix_soar_reviews_created_at"]
    assert "(case_number)" in definitions["ix_soar_reviews_case_number"]


# ── the rights of app_rw ────────────────────────────────────────────────────────────────────


def _privileges(db, table: str) -> dict[str, bool]:
    return {
        right: db.execute(
            "SELECT has_table_privilege('app_rw', %s, %s)", (table, right)
        ).fetchone()[0]
        for right in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")
    }


def test_app_rw_reads_inserts_and_updates_tickets_and_nothing_more(db):
    assert _privileges(db, "soar_reviews") == {
        "SELECT": True,
        "INSERT": True,
        "UPDATE": True,
        "DELETE": False,
        "TRUNCATE": False,
    }


def test_app_rw_really_does_what_the_grants_say(db):
    db.execute("SELECT 1")  # open the fixture's outer transaction: the blocks below are savepoints
    with db.transaction(force_rollback=True):
        db.execute("SET LOCAL ROLE app_rw")
        review_id = _review(db)
        db.execute("UPDATE soar_reviews SET note = 'x' WHERE id = %s", (review_id,))
        for statement in ("DELETE FROM soar_reviews WHERE id = %s", "TRUNCATE soar_reviews"):
            with (
                db.transaction(force_rollback=True),
                pytest.raises(psycopg.errors.InsufficientPrivilege),
            ):
                db.execute(statement, (review_id,) if "%s" in statement else None)


# ── audit events ────────────────────────────────────────────────────────────────────────────


def _event_names(db) -> list[str]:
    return _quoted(_constraint_def(db, "audit_events", "ck_audit_event_type"))


def test_the_event_constraint_holds_42_names_the_40_first_in_order(db):
    names = _event_names(db)
    assert len(names) == len(set(names)) == 42
    assert names[:40] == EVENTS_BEFORE_025
    assert names[40:] == EVENTS_IN_025


def test_the_python_event_types_are_the_constraints_names(db):
    from app.audit import events

    assert set(_event_names(db)) == set(events.EVENT_TYPES)


def test_a_received_ticket_is_a_system_event(db):
    db.execute(
        "INSERT INTO audit_events (event_type, subject_id, actor_role, payload) "
        "VALUES ('soar.review_received', 'K7QM2XHP', 'system', '{}'::jsonb)"
    )


def test_a_decision_is_an_analysts_event_with_its_actor(db):
    analyst = insert_user(db, "tier2")
    db.execute(
        "INSERT INTO audit_events (event_type, subject_id, actor_role, actor_id, payload) "
        "VALUES ('soar.review_decided', 'K7QM2XHP', 'analyst', %s, '{}'::jsonb)",
        (analyst,),
    )


@pytest.mark.parametrize(
    "name",
    [
        "soar.review_receive",
        "soar.review_decide",
        "soar.review_decided ",
        "soar.notice_received",
        "soar",
        "soar.review_received.",
    ],
)
def test_a_near_miss_of_the_new_names_is_refused(db, name):
    error = _refused(
        db,
        psycopg.errors.CheckViolation,
        lambda: db.execute(
            "INSERT INTO audit_events (event_type, subject_id, actor_role) "
            "VALUES (%s, 'K7QM2XHP', 'system')",
            (name,),
        ),
    )
    assert _constraint_of(error) == "ck_audit_event_type"


# ── upgrade, the way `make migrate` runs it ─────────────────────────────────────────────────


def _tree_plus_025(tree: Path, tmp_path: Path) -> Path:
    with_025 = tmp_path / f"{tree.name}_plus_025"
    shutil.copytree(tree, with_025)
    shutil.copy(MIGRATION_FILE, with_025)
    return with_025


def _scratch(suffix: str):
    session = _session_dsn()
    dbname = f"{conftest._dbname(session)}_{suffix}_test"
    admin = psycopg.connect(conftest._maintenance_dsn(session), autocommit=True)
    admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))
    admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(dbname)))
    return admin, dbname, _with_db(session, dbname)


def test_025_applies_on_a_database_below_it_the_way_make_migrate_runs_it(tmp_path):
    """The live database is below 025: `make migrate` applies the 025 FILE to it, never `schema.sql`. The
    shared fixture builds from `schema.sql`, so on its own it would not notice a 025 that differs from what
    `schema.sql` holds. A database is built from the tree below 025, then the real `migrate.sh` applies the
    real file, and a third run shows `schema_migrations` refuses a second apply."""
    if shutil.which("psql") is None:
        pytest.skip("psql is not installed")
    below = _schema_tree_through(24, tmp_path)
    with_025 = _tree_plus_025(below, tmp_path)
    before = len(list(below.glob(MIGRATION_FILES)))
    assert not list(below.glob("025_*.sql")) and before >= 24
    assert len(list(with_025.glob(MIGRATION_FILES))) == before + 1

    admin, dbname, dsn = _scratch("025up")
    try:
        runs = [_migrate(dsn, mig_dir) for mig_dir in (below, with_025, with_025)]
        assert "025_soar_reviews" not in runs[0]
        assert f"migrate: 0 applied, {before} already present" in runs[0]
        assert "migrate: applying 025_soar_reviews" in runs[1]
        assert f"migrate: 1 applied, {before} already present" in runs[1]
        assert f"migrate: 0 applied, {before + 1} already present" in runs[2]
        assert "migrate: applying" not in runs[2]
        with psycopg.connect(dsn) as conn:
            recorded = {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}
            assert recorded == {p.stem for p in with_025.glob(MIGRATION_FILES)}
            names = _quoted(_constraint_def(conn, "audit_events", "ck_audit_event_type"))
            assert names == EVENTS_BEFORE_025 + EVENTS_IN_025
            _review(conn, id="mig25-up")
            conn.execute(
                "INSERT INTO audit_events (event_type, subject_id, actor_role) "
                "VALUES ('soar.review_received', 'mig25-up', 'system')"
            )
            assert conn.execute("SELECT count(*) FROM soar_reviews").fetchone() == (1,)
            conn.rollback()
    finally:
        admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))
        admin.close()


def _everything(dsn) -> dict:
    """Every row of the tables 025 stands next to, whole, as JSON: the comparison names no column."""
    order = {"audit_events": "audit_id", "alerts": "alert_id", "users": "user_id"}
    with psycopg.connect(dsn) as conn:
        return {
            table: conn.execute(f"SELECT to_jsonb(t) FROM {table} t ORDER BY {key}").fetchall()
            for table, key in order.items()
        }


def test_025_applies_cleanly_on_rows_of_every_old_event_type_and_leaves_every_one_unchanged(
    tmp_path,
):
    """A new CHECK is validated against every existing row, under an exclusive lock (the lesson of
    021's Minor 2). Here the database is at 024, holds an audit row of each of the 40 old names, a user and
    alerts, and only then takes 025: it must apply, and nothing it seeded may move."""
    if shutil.which("psql") is None:
        pytest.skip("psql is not installed")
    below = _schema_tree_through(24, tmp_path)
    with_025 = _tree_plus_025(below, tmp_path)
    admin, dbname, dsn = _scratch("025seed")
    try:
        assert "migrate: applying 025_soar_reviews" not in _migrate(dsn, below)
        with psycopg.connect(dsn) as conn:
            insert_user(conn, "admin")
            for i in range(3):
                insert_alert(conn, f"mig25-seed-{i}")
            for name in EVENTS_BEFORE_025:
                conn.execute(
                    "INSERT INTO audit_events (event_type, subject_id, actor_role) "
                    "VALUES (%s, %s, 'system')",
                    (name, f"seed-{name}"),
                )
            conn.commit()
        seeded = _everything(dsn)
        assert len(seeded["audit_events"]) >= 40 and len(seeded["alerts"]) == 3

        applied = _migrate(dsn, with_025)

        assert "migrate: applying 025_soar_reviews" in applied
        assert _everything(dsn) == seeded
        with psycopg.connect(dsn) as conn:
            assert conn.execute("SELECT count(*) FROM soar_reviews").fetchone() == (0,)
    finally:
        admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))
        admin.close()
