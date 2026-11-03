"""Migration 023 — the contracts of Part B, Voyage embeddings in an independent pgvector (P14-T04, DEC-213).

One migration, three changes and nothing else (no table, no index, no right, no row), each on trial
here against the migrated test database:

* `ck_jobs_job_type` takes `knowledge_embed` (8 -> 9 types; 020's eight stay first, in 020's order);
* `rag_results.failure_kind text NULL`, with `ck_rag_results_failure_kind`: it is NULL, or the lookup
  `failed` for one of the six closed kinds (`rate_limit | timeout | auth | quota | provider_error |
  vectordb_unreachable`). An `ok`, `empty` or `budget` row never carries one;
* `rag_results.ranked jsonb NULL`: the list of `{entry_id, score}` the rerank gave, which the admin
  page shows.

023 stands on 021 alone. Another card writes 022 (`022_true_positive.sql`) in parallel and this
migration neither reads nor changes anything 022 does, so the upgrade tests below build their scratch
database from the migrations numbered 21 and below, with no 022, and apply 023 to it.

Each statement expected to fail runs in its own savepoint, so the next one still runs; the `db`
fixture rolls everything back at the end.
"""

from __future__ import annotations

import shutil
import subprocess
import uuid
from pathlib import Path

import psycopg
import pytest
from app.infra import jobs
from psycopg import sql
from psycopg.types.json import Jsonb

from tests import conftest
from tests.scratch_db import _with_db
from tests.test_migration_020 import (
    RESULT_COLUMNS,
    _columns,
    _constraint_def,
    _migrate,
    _quoted,
    _refused,
    _session_dsn,
)

pytestmark = pytest.mark.db

SCHEMA_DIR = conftest.REPO_ROOT / "docs" / "Schema"
MIGRATION_FILE = SCHEMA_DIR / "023_vector_rag.sql"
MIGRATION_FILES = "[0-9][0-9][0-9]_*.sql"

#: 020's eight types in 020's order, then the one 023 adds.
JOB_TYPES_BEFORE_023 = [
    "pipeline",
    "triage",
    "investigate",
    "digest",
    "health",
    "pull",
    "rag_lookup",
    "knowledge_draft",
]
#: Global Constraints, in the plan's order: what `rag_results.failure_kind` may say.
FAILURE_KINDS = [
    "rate_limit",
    "timeout",
    "auth",
    "quota",
    "provider_error",
    "vectordb_unreachable",
]
NOT_FAILED = ("ok", "empty", "budget")


def _result(db, **over) -> str:
    row = {
        "lookup_id": str(uuid.uuid4()),
        "subject_kind": "alert",
        "subject_id": f"gl-{uuid.uuid4().hex}",
        "status": "ok",
    }
    row.update(over)
    for key in ("history", "matches", "match_notes", "ranked"):
        if key in row and row[key] is not None:
            row[key] = Jsonb(row[key])
    columns = ", ".join(row)
    marks = ", ".join(["%s"] * len(row))
    db.execute(f"INSERT INTO rag_results ({columns}) VALUES ({marks})", list(row.values()))
    return row["lookup_id"]


def _refused_by(db, constraint: str, **over) -> None:
    error = _refused(db, psycopg.errors.CheckViolation, lambda: _result(db, **over))
    assert error.diag.constraint_name == constraint


# ── the migration records itself ────────────────────────────────────────────────────────────


def test_023_records_itself(db):
    row = db.execute("SELECT 1 FROM schema_migrations WHERE version = '023_vector_rag'").fetchone()
    assert row is not None, "023_vector_rag is not in the test database's schema_migrations"


def test_a_second_apply_is_refused_by_schema_migrations(db):
    db.execute("SELECT 1")
    with pytest.raises(psycopg.errors.UniqueViolation), db.transaction():
        db.execute("INSERT INTO schema_migrations (version) VALUES ('023_vector_rag')")


def test_the_file_changes_three_things_and_touches_no_row():
    """No old row is rewritten or deleted (Global Constraints): the only INSERT is its own record."""
    text = MIGRATION_FILE.read_text(encoding="utf-8")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("--"))
    statements = [s.strip() for s in code.split(";") if s.strip()]
    kinds = [" ".join(s.split()[:3]).upper() for s in statements]
    assert kinds == [
        "BEGIN",
        "ALTER TABLE JOBS",  # DROP CONSTRAINT ck_jobs_job_type
        "ALTER TABLE JOBS",  # ADD CONSTRAINT ck_jobs_job_type
        "ALTER TABLE RAG_RESULTS",  # ADD COLUMN failure_kind
        "ALTER TABLE RAG_RESULTS",  # ADD COLUMN ranked
        "ALTER TABLE RAG_RESULTS",  # ADD CONSTRAINT ck_rag_results_failure_kind
        "INSERT INTO SCHEMA_MIGRATIONS",
        "COMMIT",
    ], kinds
    for word in ("UPDATE ", "DELETE ", "TRUNCATE ", "CREATE ", "GRANT ", "REVOKE ", "DROP TABLE"):
        assert word not in code.upper(), word


# ── jobs ────────────────────────────────────────────────────────────────────────────────────


def test_the_jobs_constraint_names_nine_types_020s_eight_first_in_order(db):
    names = _quoted(_constraint_def(db, "jobs", "ck_jobs_job_type"))
    assert len(names) == len(set(names)) == 9
    assert names[:8] == JOB_TYPES_BEFORE_023
    assert names[8:] == ["knowledge_embed"]
    assert set(names) == set(jobs.JOB_TYPES)


def test_a_knowledge_embed_job_is_accepted(db):
    db.execute(
        "INSERT INTO jobs (job_type, subject_id) VALUES ('knowledge_embed', %s)",
        (str(uuid.uuid4()),),
    )
    row = db.execute(
        "SELECT status, attempts FROM jobs WHERE job_type = 'knowledge_embed'"
    ).fetchone()
    assert row == ("pending", 0)


def test_enqueue_admits_knowledge_embed_and_is_single_flight_per_entry(db):
    entry_id = str(uuid.uuid4())
    first = jobs.enqueue(db, "knowledge_embed", entry_id)
    again = jobs.enqueue(db, "knowledge_embed", entry_id)
    other = jobs.enqueue(db, "knowledge_embed", str(uuid.uuid4()))
    assert first is not None and again is None and other is not None


@pytest.mark.parametrize(
    "job_type", ["knowledge_embedd", "knowledge_embeds", "embed", "KNOWLEDGE_EMBED"]
)
def test_a_near_miss_of_the_new_type_is_refused(db, job_type):
    error = _refused(
        db,
        psycopg.errors.CheckViolation,
        lambda: db.execute("INSERT INTO jobs (job_type, subject_id) VALUES (%s, 'x')", (job_type,)),
    )
    assert error.diag.constraint_name == "ck_jobs_job_type"


@pytest.mark.parametrize("job_type", JOB_TYPES_BEFORE_023)
def test_the_eight_old_types_are_still_accepted(db, job_type):
    db.execute(
        "INSERT INTO jobs (job_type, subject_id) VALUES (%s, %s)", (job_type, f"x-{job_type}")
    )


# ── rag_results: the two columns ────────────────────────────────────────────────────────────


def test_the_table_has_exactly_its_eleven_columns(db):
    """020's nine, then `failure_kind` and `ranked` (`RESULT_COLUMNS` is the one frozen list)."""
    columns = _columns(db, "rag_results")
    assert columns == RESULT_COLUMNS
    assert len(columns) == 11
    assert columns["failure_kind"] == ("text", False)
    assert columns["ranked"] == ("jsonb", False)


def test_neither_new_column_has_a_default_so_an_old_style_insert_leaves_both_null(db):
    lookup_id = _result(db)
    row = db.execute(
        "SELECT failure_kind, ranked FROM rag_results WHERE lookup_id = %s", (lookup_id,)
    ).fetchone()
    assert row == (None, None)


def test_the_check_is_named_and_is_a_check_of_the_right_kind(db):
    kind = db.execute(
        "SELECT contype FROM pg_constraint WHERE conname = 'ck_rag_results_failure_kind' "
        "AND conrelid = 'rag_results'::regclass"
    ).fetchone()
    assert kind == ("c",)


def test_ranked_holds_the_list_of_entry_id_and_score(db):
    ranked = [
        {"entry_id": str(uuid.uuid4()), "score": 0.87},
        {"entry_id": str(uuid.uuid4()), "score": 0.52},
    ]
    lookup_id = _result(db, ranked=ranked, matches=[], status="ok")
    stored = db.execute("SELECT ranked FROM rag_results WHERE lookup_id = %s", (lookup_id,))
    assert stored.fetchone()[0] == ranked


def test_ranked_may_be_an_empty_list_on_an_empty_lookup(db):
    lookup_id = _result(db, status="empty", ranked=[])
    stored = db.execute("SELECT ranked FROM rag_results WHERE lookup_id = %s", (lookup_id,))
    assert stored.fetchone()[0] == []


# ── rag_results: failure_kind ───────────────────────────────────────────────────────────────


def test_the_constraint_names_the_six_kinds_in_the_plans_order(db):
    definition = _constraint_def(db, "rag_results", "ck_rag_results_failure_kind")
    assert _quoted(definition)[:1] == ["failed"]
    assert _quoted(definition)[1:] == FAILURE_KINDS


@pytest.mark.parametrize("kind", FAILURE_KINDS)
def test_a_failed_lookup_with_each_closed_kind_is_accepted(db, kind):
    lookup_id = _result(db, status="failed", failure_kind=kind)
    stored = db.execute(
        "SELECT status, failure_kind FROM rag_results WHERE lookup_id = %s", (lookup_id,)
    )
    assert stored.fetchone() == ("failed", kind)


def test_the_brief_case_failed_with_rate_limit_is_accepted(db):
    _result(db, status="failed", failure_kind="rate_limit")


def test_a_failed_lookup_with_no_kind_is_accepted_the_rows_020_wrote_are_such(db):
    lookup_id = _result(db, status="failed")
    stored = db.execute("SELECT failure_kind FROM rag_results WHERE lookup_id = %s", (lookup_id,))
    assert stored.fetchone() == (None,)


@pytest.mark.parametrize("status", NOT_FAILED)
def test_a_kind_on_a_row_that_did_not_fail_is_refused(db, status):
    _refused_by(db, "ck_rag_results_failure_kind", status=status, failure_kind="timeout")


def test_the_brief_case_a_kind_on_an_ok_row_is_refused(db):
    _refused_by(db, "ck_rag_results_failure_kind", status="ok", failure_kind="rate_limit")


@pytest.mark.parametrize("status", NOT_FAILED)
def test_a_row_that_did_not_fail_carries_no_kind_and_is_accepted(db, status):
    _result(db, status=status)


@pytest.mark.parametrize(
    "kind",
    [
        "network",
        "rate-limit",
        "RATE_LIMIT",
        "rate_limit ",
        "timed_out",
        "unreachable",
        "vectordb",
        "",
        "voyage_error",
    ],
)
def test_an_unknown_kind_on_a_failed_row_is_refused(db, kind):
    _refused_by(db, "ck_rag_results_failure_kind", status="failed", failure_kind=kind)


def test_the_other_checks_of_the_table_still_hold(db):
    _refused_by(db, "ck_rag_results_status", status="partial")
    _refused_by(db, "ck_rag_results_subject_kind", subject_kind="entry")


# ── rights: 020's, unchanged ────────────────────────────────────────────────────────────────


def test_app_rw_can_still_only_select_and_insert_the_table(db):
    held = {
        privilege: db.execute(
            "SELECT has_table_privilege('app_rw', 'rag_results', %s)", (privilege,)
        ).fetchone()[0]
        for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")
    }
    assert held == {
        "SELECT": True,
        "INSERT": True,
        "UPDATE": False,
        "DELETE": False,
        "TRUNCATE": False,
    }


def test_app_rw_writes_and_reads_both_new_columns_but_cannot_change_them_later(db):
    ranked = [{"entry_id": str(uuid.uuid4()), "score": 0.71}]
    lookup_id = str(uuid.uuid4())
    db.execute("SELECT 1")  # open the fixture's outer transaction: the blocks below are savepoints
    with db.transaction(force_rollback=True):
        db.execute("SET LOCAL ROLE app_rw")
        _result(db, lookup_id=lookup_id, status="failed", failure_kind="auth", ranked=ranked)
        stored = db.execute(
            "SELECT failure_kind, ranked FROM rag_results WHERE lookup_id = %s", (lookup_id,)
        )
        assert stored.fetchone() == ("auth", ranked)
    _result(db, lookup_id=lookup_id, status="failed", failure_kind="auth", ranked=ranked)
    for statement in (
        "UPDATE rag_results SET failure_kind = 'quota' WHERE lookup_id = %s",
        "UPDATE rag_results SET ranked = '[]'::jsonb WHERE lookup_id = %s",
    ):
        with db.transaction(force_rollback=True):
            db.execute("SET LOCAL ROLE app_rw")
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                db.execute(statement, (lookup_id,))


# ── upgrade from 021, with no 022 ───────────────────────────────────────────────────────────


def _tree_at_021(tmp_path: Path) -> Path:
    """A copy of `docs/Schema` with only the migrations numbered 21 and below, and a `schema.sql` the
    real `build_schema.py` builds from them: the tree as it stood at 021. Number 22 is left out even when
    the repository has a 022 (another card's): 023 must apply without it."""
    at_021 = tmp_path / "Schema_at_021"
    at_021.mkdir()
    for path in SCHEMA_DIR.glob(MIGRATION_FILES):
        if int(path.name[:3]) <= 21:
            shutil.copy(path, at_021)
    shutil.copy(SCHEMA_DIR / "build_schema.py", at_021)
    built = subprocess.run(
        ["python3", str(at_021 / "build_schema.py")], capture_output=True, text=True, check=False
    )
    if built.returncode != 0:
        pytest.fail(f"build_schema.py exit {built.returncode}:\n{built.stderr}")
    return at_021


def _tree_at_021_plus_023(at_021: Path, tmp_path: Path) -> Path:
    with_023 = tmp_path / "Schema_at_021_plus_023"
    shutil.copytree(at_021, with_023)
    shutil.copy(MIGRATION_FILE, with_023)
    return with_023


def _scratch(suffix: str):
    session = _session_dsn()
    dbname = f"{conftest._dbname(session)}_{suffix}_test"
    admin = psycopg.connect(conftest._maintenance_dsn(session), autocommit=True)
    admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))
    admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(dbname)))
    return admin, dbname, _with_db(session, dbname)


def test_023_applies_on_a_database_at_021_the_way_make_migrate_runs_it(tmp_path):
    """The live database is at 021: `make migrate` applies the 023 FILE to it, never `schema.sql`. The
    shared fixture builds from `schema.sql`, so on its own it would not notice a 023 that differs from
    what `schema.sql` holds. A database is built from the tree at 021 (no 022), then the real
    `migrate.sh` applies the real file, and a third run shows `schema_migrations` refuses a second apply.
    """
    if shutil.which("psql") is None:
        pytest.skip("psql is not installed")
    at_021 = _tree_at_021(tmp_path)
    with_023 = _tree_at_021_plus_023(at_021, tmp_path)
    before = len(list(at_021.glob(MIGRATION_FILES)))
    assert before == 21 and not list(at_021.glob("022_*.sql"))
    assert len(list(with_023.glob(MIGRATION_FILES))) == before + 1

    admin, dbname, dsn = _scratch("023up")
    try:
        runs = [_migrate(dsn, mig_dir) for mig_dir in (at_021, with_023, with_023)]
        assert "023_vector_rag" not in runs[0]
        assert f"migrate: 0 applied, {before} already present" in runs[0]
        assert "migrate: applying 023_vector_rag" in runs[1]
        assert f"migrate: 1 applied, {before} already present" in runs[1]
        assert f"migrate: 0 applied, {before + 1} already present" in runs[2]
        assert "migrate: applying" not in runs[2]
        with psycopg.connect(dsn) as conn:
            recorded = {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}
            assert recorded == {p.stem for p in with_023.glob(MIGRATION_FILES)}
            assert "022_true_positive" not in recorded
            names = _quoted(_constraint_def(conn, "jobs", "ck_jobs_job_type"))
            assert names == JOB_TYPES_BEFORE_023 + ["knowledge_embed"]
            conn.execute(
                "INSERT INTO jobs (job_type, subject_id) VALUES ('knowledge_embed', %s)",
                (str(uuid.uuid4()),),
            )
            conn.execute(
                "INSERT INTO rag_results (lookup_id, subject_kind, subject_id, status, "
                "failure_kind, ranked) VALUES (gen_random_uuid(), 'alert', 'gl-up', 'failed', "
                "'rate_limit', '[]'::jsonb)"
            )
            conn.rollback()
    finally:
        admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))
        admin.close()


#: What the live (trial) database holds in `rag_results` when 023 is applied: a lookup of each status,
#: and a `failed` one that 020 wrote before the column existed.
OLD_SHAPES = [
    ("ok", {"history": {"n": 2}, "matches": [{"entry_id": "e1"}], "match_notes": ["why"]}),
    ("empty", {"history": {"n": 0}, "matches": [], "match_notes": []}),
    ("failed", {}),
    ("budget", {}),
]


def _everything(dsn) -> dict:
    """Every row of the tables 023 touches, whole, as JSON: the comparison names no column."""
    order = {"rag_results": "subject_id", "jobs": "job_id"}
    with psycopg.connect(dsn) as conn:
        return {
            table: conn.execute(f"SELECT to_jsonb(t) FROM {table} t ORDER BY {key}").fetchall()
            for table, key in order.items()
        }


def test_023_applies_cleanly_on_rows_of_the_old_shapes_and_leaves_every_one_unchanged(tmp_path):
    """A new CHECK is validated against every existing row, under an exclusive lock (the lesson of
    021's Minor 2). Here the database is at 021, holds a lookup of every status and a job of every old
    type, and only then takes 023: it must apply, and nothing it seeded may move; the two new columns
    are NULL on all of it."""
    if shutil.which("psql") is None:
        pytest.skip("psql is not installed")
    at_021 = _tree_at_021(tmp_path)
    with_023 = _tree_at_021_plus_023(at_021, tmp_path)
    admin, dbname, dsn = _scratch("023seed")
    try:
        assert "migrate: applying 023_vector_rag" not in _migrate(dsn, at_021)
        with psycopg.connect(dsn) as conn:
            for status, extra in OLD_SHAPES:
                conn.execute(
                    "INSERT INTO rag_results (lookup_id, subject_kind, subject_id, status, "
                    "history, matches, match_notes) VALUES (gen_random_uuid(), 'alert', %s, %s, "
                    "%s, %s, %s)",
                    (
                        f"gl-{status}",
                        status,
                        Jsonb(extra["history"]) if "history" in extra else None,
                        Jsonb(extra["matches"]) if "matches" in extra else None,
                        Jsonb(extra["match_notes"]) if "match_notes" in extra else None,
                    ),
                )
            for job_type in JOB_TYPES_BEFORE_023:
                conn.execute(
                    "INSERT INTO jobs (job_type, subject_id) VALUES (%s, %s)",
                    (job_type, f"old-{job_type}"),
                )
            conn.commit()
        seeded = _everything(dsn)
        assert len(seeded["rag_results"]) == len(OLD_SHAPES) == 4
        assert len(seeded["jobs"]) == len(JOB_TYPES_BEFORE_023) == 8

        applied = _migrate(dsn, with_023)

        assert "migrate: applying 023_vector_rag" in applied
        after = _everything(dsn)
        assert after["jobs"] == seeded["jobs"]
        # the same rows, with the two new keys NULL; nothing else moved
        for (old,), (new,) in zip(seeded["rag_results"], after["rag_results"], strict=True):
            assert new.pop("failure_kind") is None and new.pop("ranked") is None
            assert new == old
        with psycopg.connect(dsn) as conn:
            assert conn.execute(
                "SELECT count(*) FROM rag_results WHERE failure_kind IS NOT NULL"
            ).fetchone() == (0,)
    finally:
        admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))
        admin.close()


def test_the_regenerated_schema_sql_carries_023_after_021_and_is_what_the_fixture_builds_from():
    text = (SCHEMA_DIR / "schema.sql").read_text(encoding="utf-8")
    assert "migrations/023_vector_rag.sql" in text
    assert text.index("migrations/021_archive.sql") < text.index("migrations/023_vector_rag.sql")
    assert "ck_rag_results_failure_kind" in text
    built = subprocess.run(
        ["python3", str(SCHEMA_DIR / "build_schema.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stdout[-400:]
