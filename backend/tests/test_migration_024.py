"""Migration 024 — the lab runs and the lab labels (P14-T09, DEC-213, spec §6).

One migration: two tables and one constraint, each on trial here against the migrated test database.

* `lab_runs`: a name (1..80 characters, unique), a purpose (`kb` or `test`), a window
  `[starts_at, ends_at)` that must be a real interval (`ends_at > starts_at`) and may not overlap another
  run's window (an exclusion constraint on the half-open range), and who recorded it;
* `lab_labels`: one row per alert, in one run, labelled `true_positive` or `false_positive` by an admin;
* `ck_audit_event_type` takes `lab.run_created` and `lab.labeled` (38 -> 40; the 38 before them stay first,
  in 021's order);
* rights: `app_rw` reads and inserts `lab_runs` and nothing more (a run is a record the labels stand on,
  no route edits or deletes one); it reads, inserts, updates and deletes `lab_labels` (a label is set,
  changed and cleared). TRUNCATE is granted on neither.

024 stands on 021 alone: another card writes 022 and 023 is P14-T04's, and 024 neither reads nor changes
anything they do. The upgrade tests below build their scratch database from the migrations numbered 21
(no 022, no 023) and 23, and apply the real file to it.

Each statement expected to fail runs in its own savepoint, so the next one still runs; the `db` fixture
rolls everything back at the end.
"""

from __future__ import annotations

import shutil
import uuid
from datetime import UTC, datetime, timedelta
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
from tests.test_migration_021 import EVENTS_BEFORE_021, EVENTS_IN_021

pytestmark = pytest.mark.db

SCHEMA_DIR = conftest.REPO_ROOT / "docs" / "Schema"
MIGRATION_FILE = SCHEMA_DIR / "024_lab.sql"
MIGRATION_FILES = "[0-9][0-9][0-9]_*.sql"

EVENTS_IN_024 = ["lab.run_created", "lab.labeled"]
EVENTS_BEFORE_024 = EVENTS_BEFORE_021 + EVENTS_IN_021

T0 = datetime(2026, 11, 5, 9, 0, tzinfo=UTC)


def _at(hours: float) -> datetime:
    return T0 + timedelta(hours=hours)


def _run(db, user_id: str, **over) -> str:
    row = {
        "run_id": str(uuid.uuid4()),
        "name": f"run-{uuid.uuid4().hex[:10]}",
        "purpose": "test",
        "starts_at": _at(0),
        "ends_at": _at(1),
        "created_by": user_id,
    }
    row.update(over)
    columns = ", ".join(row)
    marks = ", ".join(["%s"] * len(row))
    db.execute(f"INSERT INTO lab_runs ({columns}) VALUES ({marks})", list(row.values()))
    return row["run_id"]


def _label(db, alert_id: str, run_id: str, user_id: str, **over) -> None:
    row = {
        "alert_id": alert_id,
        "run_id": run_id,
        "label": "true_positive",
        "labeled_by": user_id,
    }
    row.update(over)
    columns = ", ".join(row)
    marks = ", ".join(["%s"] * len(row))
    db.execute(f"INSERT INTO lab_labels ({columns}) VALUES ({marks})", list(row.values()))


def _constraint_of(error: psycopg.Error) -> str | None:
    return error.diag.constraint_name


# ── the migration records itself ────────────────────────────────────────────────────────────


def test_024_records_itself(db):
    row = db.execute("SELECT 1 FROM schema_migrations WHERE version = '024_lab'").fetchone()
    assert row is not None, "024_lab is not in the test database's schema_migrations"


def test_a_second_apply_is_refused_by_schema_migrations(db):
    db.execute("SELECT 1")
    with pytest.raises(psycopg.errors.UniqueViolation), db.transaction():
        db.execute("INSERT INTO schema_migrations (version) VALUES ('024_lab')")


# ── lab_runs ────────────────────────────────────────────────────────────────────────────────


def test_a_run_is_stored_with_a_generated_id_and_a_creation_time(db):
    admin = insert_user(db, "admin")
    db.execute(
        "INSERT INTO lab_runs (name, purpose, starts_at, ends_at, created_by) "
        "VALUES ('r', 'kb', %s, %s, %s)",
        (_at(0), _at(1), admin),
    )
    row = db.execute("SELECT run_id, created_at, purpose FROM lab_runs WHERE name = 'r'").fetchone()
    assert row[0] is not None and row[1] is not None and row[2] == "kb"


@pytest.mark.parametrize("purpose", ["kb", "test"])
def test_the_two_purposes_are_accepted(db, purpose):
    _run(db, insert_user(db, "admin"), purpose=purpose)


@pytest.mark.parametrize("purpose", ["train", "KB", "Test", "", " kb", "kb ", "calibration"])
def test_an_unknown_purpose_is_refused(db, purpose):
    admin = insert_user(db, "admin")
    error = _refused(db, psycopg.errors.CheckViolation, lambda: _run(db, admin, purpose=purpose))
    assert _constraint_of(error) == "ck_lab_runs_purpose"


def test_a_missing_purpose_is_refused(db):
    admin = insert_user(db, "admin")
    error = _refused(
        db,
        psycopg.errors.NotNullViolation,
        lambda: db.execute(
            "INSERT INTO lab_runs (name, starts_at, ends_at, created_by) VALUES ('p', %s, %s, %s)",
            (_at(0), _at(1), admin),
        ),
    )
    assert error.diag.column_name == "purpose"


def test_an_end_equal_to_the_start_is_refused(db):
    admin = insert_user(db, "admin")
    error = _refused(
        db,
        psycopg.errors.CheckViolation,
        lambda: _run(db, admin, starts_at=_at(2), ends_at=_at(2)),
    )
    assert _constraint_of(error) == "ck_lab_runs_ends_after_starts"


def test_an_end_before_the_start_is_refused(db):
    admin = insert_user(db, "admin")
    error = _refused(
        db,
        psycopg.errors.CheckViolation,
        lambda: _run(db, admin, starts_at=_at(2), ends_at=_at(1)),
    )
    assert _constraint_of(error) == "ck_lab_runs_ends_after_starts"


def test_a_window_of_one_microsecond_is_a_window(db):
    admin = insert_user(db, "admin")
    _run(db, admin, starts_at=_at(0), ends_at=_at(0) + timedelta(microseconds=1))


@pytest.mark.parametrize("name", ["", "x" * 81, "y" * 200])
def test_a_name_outside_one_to_eighty_characters_is_refused(db, name):
    admin = insert_user(db, "admin")
    error = _refused(db, psycopg.errors.CheckViolation, lambda: _run(db, admin, name=name))
    assert _constraint_of(error) == "ck_lab_runs_name_length"


@pytest.mark.parametrize("name", ["x", "x" * 80, "Lần 1 - brute force SSH", "é" * 80])
def test_a_name_of_one_to_eighty_characters_is_accepted(db, name):
    _run(db, insert_user(db, "admin"), name=name)


def test_a_name_is_unique(db):
    admin = insert_user(db, "admin")
    _run(db, admin, name="same", starts_at=_at(0), ends_at=_at(1))
    error = _refused(
        db,
        psycopg.errors.UniqueViolation,
        lambda: _run(db, admin, name="same", starts_at=_at(5), ends_at=_at(6)),
    )
    assert _constraint_of(error) == "lab_runs_name_key"


def test_a_run_needs_a_user_who_exists(db):
    error = _refused(
        db,
        psycopg.errors.ForeignKeyViolation,
        lambda: _run(db, str(uuid.uuid4())),
    )
    assert _constraint_of(error) == "lab_runs_created_by_fkey"


# ── the exclusion: no two windows overlap ───────────────────────────────────────────────────


def _overlap(db, admin: str, first: tuple[float, float], second: tuple[float, float]):
    _run(db, admin, starts_at=_at(first[0]), ends_at=_at(first[1]))
    return _refused(
        db,
        psycopg.errors.ExclusionViolation,
        lambda: _run(db, admin, starts_at=_at(second[0]), ends_at=_at(second[1])),
    )


@pytest.mark.parametrize(
    "first,second",
    [
        ((0, 4), (2, 6)),  # the second starts inside the first
        ((2, 6), (0, 4)),  # the second ends inside the first
        ((0, 6), (2, 4)),  # the second lies inside the first
        ((2, 4), (0, 6)),  # the second holds the first
        ((0, 4), (0, 4)),  # the same window
        ((0, 4), (0, 2)),  # the same start
        ((0, 4), (2, 4)),  # the same end
        ((0, 4), (3.999, 5)),  # a sliver of overlap
    ],
    ids=[
        "starts-inside",
        "ends-inside",
        "inside",
        "holds",
        "same",
        "same-start",
        "same-end",
        "sliver",
    ],
)
def test_two_windows_that_share_any_time_are_refused(db, first, second):
    error = _overlap(db, insert_user(db, "admin"), first, second)
    assert _constraint_of(error) == "ex_lab_runs_no_overlap"


@pytest.mark.parametrize(
    "first,second",
    [((0, 4), (4, 6)), ((4, 6), (0, 4)), ((0, 1), (2, 3)), ((0, 4), (10, 11))],
    ids=["abut", "abut-reversed", "gap", "far"],
)
def test_windows_that_do_not_share_time_are_accepted_the_range_is_half_open(db, first, second):
    admin = insert_user(db, "admin")
    _run(db, admin, starts_at=_at(first[0]), ends_at=_at(first[1]))
    _run(db, admin, starts_at=_at(second[0]), ends_at=_at(second[1]))


def test_the_exclusion_does_not_depend_on_the_time_zone_a_value_is_written_in(db):
    admin = insert_user(db, "admin")
    _run(db, admin, starts_at="2026-11-05 09:00:00+00", ends_at="2026-11-05 11:00:00+00")
    error = _refused(
        db,
        psycopg.errors.ExclusionViolation,
        # 17:00+07 = 10:00 UTC: inside the first window
        lambda: _run(
            db, admin, starts_at="2026-11-05 17:00:00+07", ends_at="2026-11-05 19:00:00+07"
        ),
    )
    assert _constraint_of(error) == "ex_lab_runs_no_overlap"


# ── lab_labels ──────────────────────────────────────────────────────────────────────────────


def test_a_label_is_stored_with_who_and_when(db):
    admin = insert_user(db, "admin")
    run = _run(db, admin)
    insert_alert(db, "m24-a")
    _label(db, "m24-a", run, admin, label="false_positive")
    row = db.execute(
        "SELECT run_id::text, label, labeled_by::text, labeled_at IS NOT NULL "
        "FROM lab_labels WHERE alert_id = 'm24-a'"
    ).fetchone()
    assert row == (run, "false_positive", admin, True)


@pytest.mark.parametrize("label", ["true_positive", "false_positive"])
def test_the_two_labels_are_accepted(db, label):
    admin = insert_user(db, "admin")
    insert_alert(db, "m24-b")
    _label(db, "m24-b", _run(db, admin), admin, label=label)


@pytest.mark.parametrize(
    "label",
    ["benign", "escalate", "tp", "fp", "True_Positive", "", "true_positive ", "needs_review"],
)
def test_any_other_label_is_refused(db, label):
    admin = insert_user(db, "admin")
    run = _run(db, admin)
    insert_alert(db, "m24-c")
    error = _refused(
        db, psycopg.errors.CheckViolation, lambda: _label(db, "m24-c", run, admin, label=label)
    )
    assert _constraint_of(error) == "ck_lab_labels_label"


def test_an_alert_has_one_label(db):
    admin = insert_user(db, "admin")
    run = _run(db, admin)
    insert_alert(db, "m24-d")
    _label(db, "m24-d", run, admin)
    error = _refused(
        db,
        psycopg.errors.UniqueViolation,
        lambda: _label(db, "m24-d", run, admin, label="false_positive"),
    )
    assert _constraint_of(error) == "lab_labels_pkey"


def test_a_label_needs_an_alert_a_run_and_a_user_that_exist(db):
    admin = insert_user(db, "admin")
    run = _run(db, admin)
    insert_alert(db, "m24-e")
    no_alert = _refused(
        db, psycopg.errors.ForeignKeyViolation, lambda: _label(db, "m24-nobody", run, admin)
    )
    assert _constraint_of(no_alert) == "lab_labels_alert_id_fkey"
    no_run = _refused(
        db,
        psycopg.errors.ForeignKeyViolation,
        lambda: _label(db, "m24-e", str(uuid.uuid4()), admin),
    )
    assert _constraint_of(no_run) == "lab_labels_run_id_fkey"
    no_user = _refused(
        db, psycopg.errors.ForeignKeyViolation, lambda: _label(db, "m24-e", run, str(uuid.uuid4()))
    )
    assert _constraint_of(no_user) == "lab_labels_labeled_by_fkey"


def test_a_run_with_labels_cannot_be_deleted_by_the_owner(db):
    admin = insert_user(db, "admin")
    run = _run(db, admin)
    insert_alert(db, "m24-f")
    _label(db, "m24-f", run, admin)
    _refused(
        db,
        psycopg.errors.ForeignKeyViolation,
        lambda: db.execute("DELETE FROM lab_runs WHERE run_id = %s", (run,)),
    )


# ── the rights of app_rw ────────────────────────────────────────────────────────────────────


def _privileges(db, table: str) -> dict[str, bool]:
    return {
        right: db.execute(
            "SELECT has_table_privilege('app_rw', %s, %s)", (table, right)
        ).fetchone()[0]
        for right in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")
    }


def test_app_rw_reads_and_inserts_runs_and_nothing_more(db):
    assert _privileges(db, "lab_runs") == {
        "SELECT": True,
        "INSERT": True,
        "UPDATE": False,
        "DELETE": False,
        "TRUNCATE": False,
    }


def test_app_rw_sets_changes_and_clears_labels_but_cannot_truncate(db):
    assert _privileges(db, "lab_labels") == {
        "SELECT": True,
        "INSERT": True,
        "UPDATE": True,
        "DELETE": True,
        "TRUNCATE": False,
    }


def test_app_rw_really_does_what_the_grants_say(db):
    admin = insert_user(db, "admin")
    insert_alert(db, "m24-g")
    db.execute("SELECT 1")  # open the fixture's outer transaction: the blocks below are savepoints
    with db.transaction(force_rollback=True):
        db.execute("SET LOCAL ROLE app_rw")
        run = _run(db, admin, name="as-app-rw")
        _label(db, "m24-g", run, admin)
        db.execute("UPDATE lab_labels SET label = 'false_positive' WHERE alert_id = 'm24-g'")
        db.execute("DELETE FROM lab_labels WHERE alert_id = 'm24-g'")
        for statement in (
            "UPDATE lab_runs SET name = 'renamed' WHERE run_id = %s",
            "DELETE FROM lab_runs WHERE run_id = %s",
        ):
            with (
                db.transaction(force_rollback=True),
                pytest.raises(psycopg.errors.InsufficientPrivilege),
            ):
                db.execute(statement, (run,))
        with (
            db.transaction(force_rollback=True),
            pytest.raises(psycopg.errors.InsufficientPrivilege),
        ):
            db.execute("TRUNCATE lab_labels")
        with (
            db.transaction(force_rollback=True),
            pytest.raises(psycopg.errors.InsufficientPrivilege),
        ):
            db.execute("TRUNCATE lab_runs")


# ── audit events ────────────────────────────────────────────────────────────────────────────


def _event_names(db) -> list[str]:
    return _quoted(_constraint_def(db, "audit_events", "ck_audit_event_type"))


def test_the_event_constraint_holds_40_names_the_38_first_in_order(db):
    """The shared database is migrated to the end, so a later migration's names (025: `soar.review_received`,
    `soar.review_decided`) follow the 40: they only ever append."""
    names = _event_names(db)
    assert len(names) == len(set(names)) >= 40
    assert names[:38] == EVENTS_BEFORE_024
    assert names[38:40] == EVENTS_IN_024


@pytest.mark.parametrize("name", EVENTS_IN_024)
def test_each_new_event_is_accepted_from_an_admin_with_an_actor(db, name):
    admin = insert_user(db, "admin")
    db.execute(
        "INSERT INTO audit_events (event_type, subject_id, actor_role, actor_id, payload) "
        "VALUES (%s, 'mig24-subject', 'admin', %s, '{}'::jsonb)",
        (name, admin),
    )


@pytest.mark.parametrize(
    "name",
    ["lab.run_create", "lab.label", "lab.labeled ", "lab.labelled", "lab", "lab.run_created."],
)
def test_a_near_miss_of_the_new_names_is_refused(db, name):
    error = _refused(
        db,
        psycopg.errors.CheckViolation,
        lambda: db.execute(
            "INSERT INTO audit_events (event_type, subject_id, actor_role) "
            "VALUES (%s, 'mig24-subject', 'system')",
            (name,),
        ),
    )
    assert _constraint_of(error) == "ck_audit_event_type"


# ── upgrade, the way `make migrate` runs it ─────────────────────────────────────────────────

#: The trees 024 is applied to: the one at 021 alone (no 022, no 023: 024 reads neither), and the one
#: at 023 (every file written so far below 024; 022 is in it once that card has merged).
TREES = [
    pytest.param(21, (), id="at-021"),
    pytest.param(23, (22,), id="at-023-without-022"),
    pytest.param(23, (), id="at-023"),
]


def _tree_plus_024(tree: Path, tmp_path: Path) -> Path:
    with_024 = tmp_path / f"{tree.name}_plus_024"
    shutil.copytree(tree, with_024)
    shutil.copy(MIGRATION_FILE, with_024)
    return with_024


def _scratch(suffix: str):
    session = _session_dsn()
    dbname = f"{conftest._dbname(session)}_{suffix}_test"
    admin = psycopg.connect(conftest._maintenance_dsn(session), autocommit=True)
    admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))
    admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(dbname)))
    return admin, dbname, _with_db(session, dbname)


@pytest.mark.parametrize("through,skip", TREES)
def test_024_applies_on_a_database_below_it_the_way_make_migrate_runs_it(tmp_path, through, skip):
    """The live database is below 024: `make migrate` applies the 024 FILE to it, never `schema.sql`. The
    shared fixture builds from `schema.sql`, so on its own it would not notice a 024 that differs from what
    `schema.sql` holds. A database is built from the tree below 024, then the real `migrate.sh` applies the
    real file, and a third run shows `schema_migrations` refuses a second apply."""
    if shutil.which("psql") is None:
        pytest.skip("psql is not installed")
    below = _schema_tree_through(through, tmp_path, skip=skip)
    with_024 = _tree_plus_024(below, tmp_path)
    before = len(list(below.glob(MIGRATION_FILES)))
    assert not list(below.glob("024_*.sql")) and before >= 21
    assert len(list(with_024.glob(MIGRATION_FILES))) == before + 1

    admin, dbname, dsn = _scratch(f"024up{through}{len(skip)}")
    try:
        runs = [_migrate(dsn, mig_dir) for mig_dir in (below, with_024, with_024)]
        assert "024_lab" not in runs[0]
        assert f"migrate: 0 applied, {before} already present" in runs[0]
        assert "migrate: applying 024_lab" in runs[1]
        assert f"migrate: 1 applied, {before} already present" in runs[1]
        assert f"migrate: 0 applied, {before + 1} already present" in runs[2]
        assert "migrate: applying" not in runs[2]
        with psycopg.connect(dsn) as conn:
            recorded = {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}
            assert recorded == {p.stem for p in with_024.glob(MIGRATION_FILES)}
            if 22 in skip:
                assert "022_true_positive" not in recorded
            names = _quoted(_constraint_def(conn, "audit_events", "ck_audit_event_type"))
            assert names == EVENTS_BEFORE_024 + EVENTS_IN_024
            user = insert_user(conn, "admin")
            insert_alert(conn, "mig24-up")
            run = _run(conn, user)
            _label(conn, "mig24-up", run, user)
            conn.execute(
                "INSERT INTO audit_events (event_type, subject_id, actor_role, actor_id) "
                "VALUES ('lab.labeled', 'mig24-up', 'admin', %s)",
                (user,),
            )
            conn.rollback()
    finally:
        admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))
        admin.close()


def _everything(dsn) -> dict:
    """Every row of the tables 024 touches or stands next to, whole, as JSON: the comparison names no
    column."""
    order = {"audit_events": "audit_id", "alerts": "alert_id", "users": "user_id"}
    with psycopg.connect(dsn) as conn:
        return {
            table: conn.execute(f"SELECT to_jsonb(t) FROM {table} t ORDER BY {key}").fetchall()
            for table, key in order.items()
        }


def test_024_applies_cleanly_on_rows_of_every_old_event_type_and_leaves_every_one_unchanged(
    tmp_path,
):
    """A new CHECK is validated against every existing row, under an exclusive lock (the lesson of
    021's Minor 2). Here the database is at 023, holds an audit row of each of the 38 old names, an
    admin and alerts, and only then takes 024: it must apply, and nothing it seeded may move."""
    if shutil.which("psql") is None:
        pytest.skip("psql is not installed")
    below = _schema_tree_through(23, tmp_path)
    with_024 = _tree_plus_024(below, tmp_path)
    admin, dbname, dsn = _scratch("024seed")
    try:
        assert "migrate: applying 024_lab" not in _migrate(dsn, below)
        with psycopg.connect(dsn) as conn:
            insert_user(conn, "admin")
            for i in range(3):
                insert_alert(conn, f"mig24-seed-{i}")
            for name in EVENTS_BEFORE_024:
                conn.execute(
                    "INSERT INTO audit_events (event_type, subject_id, actor_role) "
                    "VALUES (%s, %s, 'system')",
                    (name, f"seed-{name}"),
                )
            conn.commit()
        seeded = _everything(dsn)
        assert len(seeded["audit_events"]) >= 38 and len(seeded["alerts"]) == 3

        applied = _migrate(dsn, with_024)

        assert "migrate: applying 024_lab" in applied
        assert _everything(dsn) == seeded
        with psycopg.connect(dsn) as conn:
            assert conn.execute("SELECT count(*) FROM lab_runs").fetchone() == (0,)
            assert conn.execute("SELECT count(*) FROM lab_labels").fetchone() == (0,)
    finally:
        admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))
        admin.close()
