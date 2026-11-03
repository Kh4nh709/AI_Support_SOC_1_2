"""Migration 021 — the `archived` terminal status (INT-T03, DEC-212).

One migration, five constraint changes, each on trial here against the migrated test database:

* `ck_alerts_status` takes `archived`;
* `ck_alerts_g3_terminal_phai_co_closed_at` and `ck_alerts_h2_dong_boi_nguoi_phai_seal` take it too:
  an archived alert has `closed_at` AND `sealed_at`;
* `ck_cases_status` takes `archived`, and `ck_cases_ket_luan_phai_co_moc` lets an archived case have
  no `concluded_by` (nobody concluded it) while the three human conclusions keep their rule;
* `ck_audit_event_type` takes `alert.archived` and `case.archived` (36 -> 38).

Each statement expected to fail runs in its own savepoint, so the next one still runs; the `db`
fixture rolls everything back at the end.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path

import psycopg
import pytest
from psycopg import sql

from tests import conftest
from tests.scratch_db import INSERT_ALERT, _with_db, insert_user
from tests.test_archive import _put_alert, _put_case
from tests.test_migration_020 import EVENTS_BEFORE_020, EVENTS_IN_020

pytestmark = pytest.mark.db

SCHEMA_DIR = conftest.REPO_ROOT / "docs" / "Schema"
MIGRATION_FILES = "[0-9][0-9][0-9]_*.sql"

EVENTS_BEFORE_021 = EVENTS_BEFORE_020 + EVENTS_IN_020
EVENTS_IN_021 = ["alert.archived", "case.archived"]

HUMAN_CONCLUSIONS = ("concluded_fp", "concluded_policy_violation", "confirmed_incident")


# ── helpers ─────────────────────────────────────────────────────────────────────────────────


def _alert(db) -> str:
    """One alert in status `received`; the test then UPDATEs it, so the CHECK under trial is what
    the statement hits."""
    alert_id = f"mig21-{uuid.uuid4().hex[:12]}"
    db.execute(INSERT_ALERT, (alert_id, alert_id, "", True, "received"))
    return alert_id


def _case_insert(db, user_id: str, **over) -> str:
    row = {
        "case_id": str(uuid.uuid4()),
        "title": "mig21",
        "status": "investigating",
        "severity": "medium",
        "created_by": user_id,
    }
    row.update(over)
    columns = ", ".join(row)
    marks = ", ".join(["%s"] * len(row))
    db.execute(f"INSERT INTO cases ({columns}) VALUES ({marks})", list(row.values()))
    return row["case_id"]


def _refused(db, constraint: str, statement, params=()) -> None:
    """Run `statement` expecting a CHECK violation of exactly `constraint`."""
    db.execute("SELECT 1")  # open the fixture's outer transaction: the next one is a savepoint
    with pytest.raises(psycopg.errors.CheckViolation) as caught, db.transaction():
        db.execute(statement, params)
    assert caught.value.diag.constraint_name == constraint


def _constraint_names(db, name: str) -> list[str]:
    definition = db.execute(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = %s", (name,)
    ).fetchone()[0]
    return re.findall(r"'([^']+)'::text", definition)


def _schema_below(tmp_path: Path, below: int) -> Path:
    """A copy of `docs/Schema` with only the migrations numbered below `below`, and a `schema.sql` the
    real `build_schema.py` builds from them: the tree as it stood just before migration `below`
    (21: at 020; 22: through 021). The later migration tests build their own trees with it."""
    tree = tmp_path / f"Schema_below_{below:03d}"
    tree.mkdir()
    for path in SCHEMA_DIR.glob(MIGRATION_FILES):
        if int(path.name[:3]) < below:
            shutil.copy(path, tree)
    shutil.copy(SCHEMA_DIR / "build_schema.py", tree)
    built = subprocess.run(
        ["python3", str(tree / "build_schema.py")], capture_output=True, text=True, check=False
    )
    if built.returncode != 0:
        pytest.fail(f"build_schema.py exit {built.returncode}:\n{built.stderr}")
    return tree


def _migrate_run(dsn, mig_dir) -> subprocess.CompletedProcess:
    """`scripts/migrate.sh` over `mig_dir`, whatever it exits with (a refusal is a test's subject)."""
    return subprocess.run(
        ["bash", "scripts/migrate.sh", str(dsn)],
        cwd=conftest.REPO_ROOT,
        env={**os.environ, "MIGRATIONS_DIR": str(mig_dir)},
        capture_output=True,
        text=True,
        check=False,
    )


def _migrate(dsn, mig_dir) -> str:
    run = _migrate_run(dsn, mig_dir)
    if run.returncode != 0:
        pytest.fail(f"migrate.sh exit {run.returncode}:\n{run.stderr}")
    return run.stdout


# ── the migration records itself ────────────────────────────────────────────────────────────


def test_021_records_itself(db):
    row = db.execute("SELECT 1 FROM schema_migrations WHERE version = '021_archive'").fetchone()
    assert row is not None, "021_archive is not in the test database's schema_migrations"


def test_a_second_apply_is_refused_by_schema_migrations(db):
    db.execute("SELECT 1")
    with pytest.raises(psycopg.errors.UniqueViolation), db.transaction():
        db.execute("INSERT INTO schema_migrations (version) VALUES ('021_archive')")


# ── alerts ──────────────────────────────────────────────────────────────────────────────────


def test_the_status_constraint_names_eleven_statuses_archived_last(db):
    names = _constraint_names(db, "ck_alerts_status")
    assert len(names) == len(set(names)) == 11
    assert names[-1] == "archived"
    assert set(names[:-1]) == {
        "received",
        "duplicate",
        "auto_closed",
        "enriching",
        "queued_tier1",
        "tier1_active",
        "escalated_tier2",
        "closed_fp",
        "closed_benign",
        "closed_confirmed",
    }


def test_an_archived_alert_with_closed_at_and_sealed_at_is_accepted(db):
    alert_id = _alert(db)
    db.execute(
        "UPDATE alerts SET status = 'archived', closed_at = now(), sealed_at = now(), "
        "close_reason = 'DEC-212' WHERE alert_id = %s",
        (alert_id,),
    )
    assert db.execute("SELECT status FROM alerts WHERE alert_id = %s", (alert_id,)).fetchone() == (
        "archived",
    )


def test_an_archived_alert_without_closed_at_is_refused_by_g3(db):
    alert_id = _alert(db)
    _refused(
        db,
        "ck_alerts_g3_terminal_phai_co_closed_at",
        "UPDATE alerts SET status = 'archived', sealed_at = now() WHERE alert_id = %s",
        (alert_id,),
    )


def test_an_archived_alert_with_closed_at_but_not_sealed_is_refused_by_h2(db):
    alert_id = _alert(db)
    _refused(
        db,
        "ck_alerts_h2_dong_boi_nguoi_phai_seal",
        "UPDATE alerts SET status = 'archived', closed_at = now() WHERE alert_id = %s",
        (alert_id,),
    )


def test_an_archived_alert_with_neither_is_refused(db):
    alert_id = _alert(db)
    _refused(
        db,
        "ck_alerts_g3_terminal_phai_co_closed_at",
        "UPDATE alerts SET status = 'archived' WHERE alert_id = %s",
        (alert_id,),
    )


def test_a_status_outside_the_eleven_is_still_refused(db):
    alert_id = _alert(db)
    _refused(
        db,
        "ck_alerts_status",
        "UPDATE alerts SET status = 'archive', closed_at = now(), sealed_at = now() "
        "WHERE alert_id = %s",
        (alert_id,),
    )


def test_the_old_rules_are_not_loosened(db):
    """`escalated_tier2` still refuses `sealed_at`, and the three human closes still need both."""
    alert_id = _alert(db)
    _refused(
        db,
        "ck_alerts_h3_escalate_khong_seal",
        "UPDATE alerts SET status = 'escalated_tier2', sealed_at = now() WHERE alert_id = %s",
        (alert_id,),
    )
    for status in ("closed_fp", "closed_benign", "closed_confirmed"):
        _refused(
            db,
            "ck_alerts_h2_dong_boi_nguoi_phai_seal",
            f"UPDATE alerts SET status = '{status}', closed_at = now() WHERE alert_id = %s",
            (alert_id,),
        )
    _refused(
        db,
        "ck_alerts_g3_terminal_phai_co_closed_at",
        "UPDATE alerts SET status = 'auto_closed' WHERE alert_id = %s",
        (alert_id,),
    )


# ── cases ───────────────────────────────────────────────────────────────────────────────────


def test_the_case_status_constraint_names_the_old_four_and_archived(db):
    assert _constraint_names(db, "ck_cases_status") == [
        "investigating",
        "concluded_fp",
        "concluded_policy_violation",
        "confirmed_incident",
        "archived",
    ]


def test_an_archived_case_needs_no_concluded_by(db):
    user_id = insert_user(db, "tier2")
    case_id = _case_insert(
        db,
        user_id,
        status="archived",
        concluded_at="2026-10-30T20:15:00+07:00",
        conclusion_reason="DEC-212",
    )
    assert db.execute(
        "SELECT status, concluded_by FROM cases WHERE case_id = %s", (case_id,)
    ).fetchone() == ("archived", None)


def test_an_archived_case_may_name_who_archived_it(db):
    user_id = insert_user(db, "tier2")
    _case_insert(
        db,
        user_id,
        status="archived",
        concluded_at="2026-10-30T20:15:00+07:00",
        conclusion_reason="r",
        concluded_by=user_id,
    )


@pytest.mark.parametrize("missing", ["concluded_at", "conclusion_reason"])
def test_an_archived_case_needs_its_moment_and_its_reason(db, missing):
    user_id = insert_user(db, "tier2")
    over = {"concluded_at": "2026-10-30T20:15:00+07:00", "conclusion_reason": "r"}
    del over[missing]
    db.execute("SELECT 1")
    with pytest.raises(psycopg.errors.CheckViolation) as caught, db.transaction():
        _case_insert(db, user_id, status="archived", **over)
    assert caught.value.diag.constraint_name == "ck_cases_ket_luan_phai_co_moc"


@pytest.mark.parametrize("conclusion", HUMAN_CONCLUSIONS)
def test_the_three_human_conclusions_still_need_who_concluded(db, conclusion):
    user_id = insert_user(db, "tier2")
    db.execute("SELECT 1")
    with pytest.raises(psycopg.errors.CheckViolation) as caught, db.transaction():
        _case_insert(
            db,
            user_id,
            status=conclusion,
            concluded_at="2026-10-30T20:15:00+07:00",
            conclusion_reason="r",
        )
    assert caught.value.diag.constraint_name == "ck_cases_ket_luan_phai_co_moc"


@pytest.mark.parametrize("conclusion", HUMAN_CONCLUSIONS)
def test_a_human_conclusion_with_all_three_columns_is_accepted(db, conclusion):
    user_id = insert_user(db, "tier2")
    _case_insert(
        db,
        user_id,
        status=conclusion,
        concluded_at="2026-10-30T20:15:00+07:00",
        concluded_by=user_id,
        conclusion_reason="r",
    )


def test_an_investigating_case_needs_none_of_them(db):
    _case_insert(db, insert_user(db, "tier2"))


def test_a_case_status_outside_the_five_is_still_refused(db):
    user_id = insert_user(db, "tier2")
    db.execute("SELECT 1")
    with pytest.raises(psycopg.errors.CheckViolation) as caught, db.transaction():
        _case_insert(
            db,
            user_id,
            status="closed_fp",
            concluded_at="2026-10-30T20:15:00+07:00",
            concluded_by=user_id,
            conclusion_reason="r",
        )
    assert caught.value.diag.constraint_name == "ck_cases_status"


# ── audit events ────────────────────────────────────────────────────────────────────────────


def test_the_event_constraint_holds_38_names_the_36_first_in_order(db):
    names = _constraint_names(db, "ck_audit_event_type")
    assert len(names) == len(set(names)) == 38
    assert names[:36] == EVENTS_BEFORE_021
    assert names[36:] == EVENTS_IN_021


@pytest.mark.parametrize("name", EVENTS_IN_021)
def test_each_new_event_is_accepted_from_the_system_with_no_actor(db, name):
    db.execute(
        "INSERT INTO audit_events (event_type, subject_id, actor_role, payload) "
        "VALUES (%s, 'mig21-subject', 'system', '{}'::jsonb)",
        (name,),
    )


@pytest.mark.parametrize("name", ["alert.archive", "case.archived ", "alert.archived.", "archived"])
def test_a_near_miss_of_the_new_names_is_refused(db, name):
    db.execute("SELECT 1")
    with pytest.raises(psycopg.errors.CheckViolation) as caught, db.transaction():
        db.execute(
            "INSERT INTO audit_events (event_type, subject_id, actor_role) "
            "VALUES (%s, 'mig21-subject', 'system')",
            (name,),
        )
    assert caught.value.diag.constraint_name == "ck_audit_event_type"


# ── upgrade from 020 ────────────────────────────────────────────────────────────────────────


def _session_dsn():
    return conftest.require_test_dsn(
        os.environ.get("TEST_DATABASE_URL", conftest.DEFAULT_TEST_DATABASE_URL)
    )


def test_021_applies_on_a_database_at_020_the_way_make_migrate_runs_it(tmp_path):
    """The live database is at 020: `make migrate` applies the 021 FILE to it, never `schema.sql`.
    The shared fixture builds from `schema.sql`, so on its own it would not notice a 021 that
    differs from what `schema.sql` holds. A database is built from a copy of `docs/Schema` without
    021 (so at 020, through the same `migrate.sh`), then the real `migrate.sh` applies the real
    file, and a third run shows `schema_migrations` refuses a second apply."""
    session = _session_dsn()
    if shutil.which("psql") is None:
        pytest.skip("psql is not installed")
    at_020 = _schema_below(tmp_path, 21)
    through_021 = _schema_below(tmp_path, 22)  # 022 comes after 021
    stems = {path.stem for path in SCHEMA_DIR.glob(MIGRATION_FILES) if int(path.name[:3]) <= 21}
    total = len(stems)
    before = len(list(at_020.glob(MIGRATION_FILES)))
    # 021 is no longer the last migration (022 and 023 follow it): the tree at 020 is every file below
    # 21, the tree through 021 every file below 22, and the real `migrate.sh` applies the second to the
    # first, so this test pins 021 alone whatever comes after it.
    assert before == total - 1 == len({s for s in stems if int(s[:3]) < 21})
    assert len(list(through_021.glob(MIGRATION_FILES))) == total

    dbname = f"{conftest._dbname(session)}_021up_test"
    dsn = _with_db(session, dbname)
    admin = psycopg.connect(conftest._maintenance_dsn(session), autocommit=True)
    try:
        admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(dbname)))
        runs = [_migrate(dsn, mig_dir) for mig_dir in (at_020, through_021, through_021)]
        assert "021_archive" not in runs[0]
        assert f"migrate: 0 applied, {before} already present" in runs[0]
        assert "migrate: applying 021_archive" in runs[1]
        assert f"migrate: 1 applied, {before} already present" in runs[1]
        assert f"migrate: 0 applied, {total} already present" in runs[2]
        assert "migrate: applying" not in runs[2]
        with psycopg.connect(dsn) as conn:
            recorded = {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}
            assert recorded == stems
            names = re.findall(
                r"'([^']+)'::text",
                conn.execute(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conname = 'ck_audit_event_type'"
                ).fetchone()[0],
            )
            assert names == EVENTS_BEFORE_021 + EVENTS_IN_021
            conn.execute(
                "INSERT INTO audit_events (event_type, subject_id, actor_role) "
                "VALUES ('alert.archived', 'mig21-up', 'system')"
            )
            conn.execute(
                "INSERT INTO alerts (alert_id, rule_id, rule_level, severity, description, "
                "agent_name, alert_time, category, resolved_by, mapping_version, "
                "event_bucket_hash, raw_payload, status, closed_at, sealed_at) VALUES "
                "('mig21-up', '5710', 5, 'medium', 'd', 'a', now(), 'other', 'none', 'v1', "
                "encode(sha256('x'::bytea), 'hex'), '{}'::jsonb, 'archived', now(), now())"
            )
            conn.rollback()
    finally:
        admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))
        admin.close()


# ── upgrade from 020, on rows of the live shapes ────────────────────────────────────────────

#: What the live database holds when 021 is applied to it (30/10/2026): the heads of the queue, the
#: closes of the three analyst decisions, an auto-closed head (closed, never sealed), a duplicate, a
#: concluded case with the person who concluded it, and an investigating case whose alert is
#: `escalated_tier2` (the one status kept unsealed, `ck_alerts_h3_escalate_khong_seal`).
LIVE_SHAPE_STATUSES = {
    "received",
    "queued_tier1",
    "tier1_active",
    "escalated_tier2",
    "auto_closed",
    "duplicate",
    "closed_fp",
    "closed_benign",
    "closed_confirmed",
}


def _seed_live_shapes(conn) -> None:
    """One row of each shape above, built the way `test_archive` builds the same shapes, on a DB at 020."""
    tier1 = insert_user(conn, "tier1")
    tier2 = insert_user(conn, "tier2")
    _put_alert(conn, "m21-received", status="received", triage_status="pending", triaged_count=0)
    queued = _put_alert(conn, "m21-queued", status="queued_tier1")
    _put_alert(conn, "m21-active", status="tier1_active", acknowledged_by=tier1)
    _put_alert(conn, "m21-auto", status="auto_closed", close_reason="autoclose rule")
    _put_alert(conn, "m21-dup", status="duplicate", duplicate_of=queued)
    for status in ("closed_fp", "closed_benign", "closed_confirmed"):
        _put_alert(
            conn, f"m21-{status}", status=status, acknowledged_by=tier1, close_reason="analyst"
        )
    escalated = _put_alert(conn, "m21-escalated", status="escalated_tier2", acknowledged_by=tier1)
    _put_case(conn, tier2, [escalated])  # investigating: no concluded_at, no concluded_by
    concluded = _put_alert(conn, "m21-concluded", status="closed_fp", acknowledged_by=tier1)
    _put_case(conn, tier2, [concluded], status="concluded_fp", head_status="closed_fp")


def _everything(dsn) -> dict:
    """Every row of the tables the seed wrote, whole, as JSON: the comparison names no column, it
    compares all of them."""
    with psycopg.connect(dsn) as conn:
        return {
            table: conn.execute(
                f"SELECT to_jsonb(t) FROM {table} t ORDER BY to_jsonb(t)::text"
            ).fetchall()
            for table in ("alerts", "cases", "case_alerts", "users", "audit_events")
        }


def test_021_applies_cleanly_on_rows_of_the_live_shapes_and_leaves_every_one_unchanged(tmp_path):
    """Review of INT-T03, Minor 2: the test above applies 021 to an EMPTY database at 020, so it does
    not show that the five `ADD CONSTRAINT` validations pass on rows like the live ones (a new CHECK is
    validated against every existing row, under an exclusive lock). Here the database is at 020, holds a
    row of each live shape, and only then takes 021: it must apply, and nothing it seeded may move.
    """
    session = _session_dsn()
    if shutil.which("psql") is None:
        pytest.skip("psql is not installed")
    at_020 = _schema_below(tmp_path, 21)
    dbname = f"{conftest._dbname(session)}_021seed_test"
    dsn = _with_db(session, dbname)
    admin = psycopg.connect(conftest._maintenance_dsn(session), autocommit=True)
    try:
        admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(dbname)))
        assert "migrate: applying 021_archive" not in _migrate(dsn, at_020)
        with psycopg.connect(dsn) as conn:
            _seed_live_shapes(conn)
            conn.commit()
        seeded = _everything(dsn)
        assert {row[0]["status"] for row in seeded["alerts"]} == LIVE_SHAPE_STATUSES
        assert {row[0]["status"] for row in seeded["cases"]} == {"investigating", "concluded_fp"}
        assert any(row[0]["concluded_by"] for row in seeded["cases"])  # the concluded case has one
        assert len(seeded["alerts"]) == 10 and len(seeded["case_alerts"]) == 2

        applied = _migrate(dsn, SCHEMA_DIR)

        assert "migrate: applying 021_archive" in applied
        assert _everything(dsn) == seeded
        with psycopg.connect(dsn) as conn:
            recorded = conn.execute(
                "SELECT 1 FROM schema_migrations WHERE version = '021_archive'"
            ).fetchone()
        assert recorded is not None
    finally:
        admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))
        admin.close()
