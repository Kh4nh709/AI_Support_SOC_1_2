"""Migration 022 - ①'s stored verdict is strict (P14-T01, DEC-213).

One constraint changes: `ck_llm_runs_suggested_action` goes from `false_positive | needs_review |
escalate` to `false_positive | needs_review | true_positive`. ①'s `escalate` is renamed
`true_positive`; the database that held the old name is wiped before the build is deployed
(spec 4.1, Owner 03/11), so nothing is rewritten. The migration REFUSES, changing nothing, while a
`triage` run still says `escalate` (the wipe was skipped, or an alert arrived between the wipe and
the deploy; Review Focus 4).

Three layers, each on trial here:

* the migrated test database (the `db` fixture, built from `schema.sql`): the new constraint;
* a scratch database at 021, `make migrate` applying the 022 FILE the way the live database takes it
  (the fixture builds from `schema.sql`, which on its own would not notice a 022 that differs from
  what `schema.sql` holds), over rows of every verdict that may exist;
* a scratch database at 021 holding one `escalate` run: 022 raises its message, the old constraint
  stays, the row is untouched, and 022 is not recorded.

Each statement expected to fail runs in its own savepoint; the `db` fixture rolls everything back.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Self

import psycopg
import pytest
from psycopg import sql
from psycopg.types.json import Jsonb

from tests import conftest
from tests.scratch_db import _with_db
from tests.test_migration_021 import _refused

pytestmark = pytest.mark.db

SCHEMA_DIR = conftest.REPO_ROOT / "docs" / "Schema"
MIGRATION_FILE = SCHEMA_DIR / "022_true_positive.sql"
MIGRATION_FILES = "[0-9][0-9][0-9]_*.sql"
CONSTRAINT = "ck_llm_runs_suggested_action"

REFUSAL = (
    "022: {n} triage runs still say escalate — wipe the trial database first (spec §11); "
    "nothing changed"
)


# ── helpers ─────────────────────────────────────────────────────────────────────────────────


def _allowed(definition: str) -> list[str]:
    """The values of the `IN (...)` list of a CHECK, as `pg_get_constraintdef` deparses it: the
    `ARRAY['a'::text, ...]` after `= ANY`. The text before it also holds quoted names
    (`pipeline <> 'triage'::text`, the JSON key), which are not values."""
    listed = definition.split("ARRAY[", 1)[1]
    return re.findall(r"'([^']*)'::text", listed)


def _names(db, constraint: str) -> list[str]:
    definition = db.execute(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = %s", (constraint,)
    ).fetchone()[0]
    return _allowed(definition)


def _insert_run(conn, pipeline: str, result: dict | None) -> uuid.UUID:
    run_id = uuid.uuid4()
    conn.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt, "
        "user_message, result) VALUES (%s, %s, %s, %s, 'p', 'u', %s)",
        (
            run_id,
            pipeline,
            "alert" if pipeline == "triage" else "case",
            f"mig22-{run_id.hex[:10]}",
            None if result is None else Jsonb(result),
        ),
    )
    return run_id


def _triage(db, result: dict | None) -> None:
    _insert_run(db, "triage", result)


def _session_dsn():
    return conftest.require_test_dsn(
        os.environ.get("TEST_DATABASE_URL", conftest.DEFAULT_TEST_DATABASE_URL)
    )


def _schema_without_022(tmp_path: Path) -> Path:
    """A copy of `docs/Schema` with only the migrations numbered below 022, and a `schema.sql` the
    real `build_schema.py` builds from them: the tree as it stood at 021."""
    at_021 = tmp_path / "Schema"
    at_021.mkdir()
    for path in SCHEMA_DIR.glob(MIGRATION_FILES):
        if int(path.name[:3]) < 22:
            shutil.copy(path, at_021)
    shutil.copy(SCHEMA_DIR / "build_schema.py", at_021)
    built = subprocess.run(
        ["python3", str(at_021 / "build_schema.py")], capture_output=True, text=True, check=False
    )
    if built.returncode != 0:
        pytest.fail(f"build_schema.py exit {built.returncode}:\n{built.stderr}")
    return at_021


def _migrate(dsn, mig_dir) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "scripts/migrate.sh", str(dsn)],
        cwd=conftest.REPO_ROOT,
        env={**os.environ, "MIGRATIONS_DIR": str(mig_dir)},
        capture_output=True,
        text=True,
        check=False,
    )


def _migrated(dsn, mig_dir) -> str:
    run = _migrate(dsn, mig_dir)
    if run.returncode != 0:
        pytest.fail(f"migrate.sh exit {run.returncode}:\n{run.stderr}")
    return run.stdout


class _Scratch:
    """A database at 021, dropped at the end."""

    def __init__(self, tmp_path: Path, suffix: str) -> None:
        self.session = _session_dsn()
        if shutil.which("psql") is None:
            pytest.skip("psql is not installed")
        self.at_021 = _schema_without_022(tmp_path)
        self.name = f"{conftest._dbname(self.session)}_{suffix}_test"
        self.dsn = _with_db(self.session, self.name)

    def __enter__(self) -> Self:
        self.admin = psycopg.connect(conftest._maintenance_dsn(self.session), autocommit=True)
        self.admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(self.name)))
        self.admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(self.name)))
        out = _migrated(self.dsn, self.at_021)
        assert "022_true_positive" not in out
        return self

    def __exit__(self, *exc) -> None:
        self.admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(self.name)))
        self.admin.close()

    def constraint(self) -> list[str]:
        with psycopg.connect(self.dsn) as conn:
            definition = conn.execute(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = %s",
                (CONSTRAINT,),
            ).fetchone()[0]
        return _allowed(definition)

    def recorded(self) -> set[str]:
        with psycopg.connect(self.dsn) as conn:
            return {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}

    def runs(self) -> list:
        with psycopg.connect(self.dsn) as conn:
            return conn.execute(
                "SELECT to_jsonb(t) FROM llm_runs t ORDER BY to_jsonb(t)::text"
            ).fetchall()


# ── the file ────────────────────────────────────────────────────────────────────────────────


def test_the_file_is_one_transaction_that_refuses_before_it_touches_the_constraint():
    text = MIGRATION_FILE.read_text("utf-8")
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("--"))
    statements = [ln.strip() for ln in code.splitlines() if ln.strip()]
    assert statements[0] == "BEGIN;"
    assert statements[-1] == "COMMIT;"
    assert code.count("BEGIN;") == 1 and code.count("COMMIT;") == 1  # one transaction, no more
    assert code.index("RAISE EXCEPTION") < code.index(f"DROP CONSTRAINT {CONSTRAINT}")
    assert code.index(f"DROP CONSTRAINT {CONSTRAINT}") < code.index("ADD CONSTRAINT")
    assert "INSERT INTO schema_migrations (version) VALUES ('022_true_positive');" in code
    # The refusal reads the model's stored answer of `triage` runs, nothing else.
    assert "pipeline = 'triage'" in code
    assert "result->>'suggested_action' = 'escalate'" in code
    # Nothing is rewritten or deleted: no data statement, no other constraint.
    assert not re.search(r"\b(UPDATE|DELETE|TRUNCATE)\b", code)
    assert code.count("ALTER TABLE") == 2


def test_the_file_carries_the_message_the_card_names():
    text = MIGRATION_FILE.read_text("utf-8")
    assert (
        "'022: % triage runs still say escalate — wipe the trial database first "
        "(spec §11); nothing changed'"
    ) in text


# ── the constraint, on the migrated test database ───────────────────────────────────────────


def test_022_records_itself(db):
    row = db.execute(
        "SELECT 1 FROM schema_migrations WHERE version = '022_true_positive'"
    ).fetchone()
    assert row is not None, "022_true_positive is not in the test database's schema_migrations"


def test_the_constraint_names_exactly_the_three_gated_values(db):
    assert _names(db, CONSTRAINT) == ["false_positive", "needs_review", "true_positive"]


@pytest.mark.parametrize("action", ["false_positive", "needs_review", "true_positive"])
def test_a_triage_run_with_a_gated_verdict_is_accepted(db, action):
    _triage(db, {"suggested_action": action, "confidence": "high"})
    count = db.execute(
        "SELECT count(*) FROM llm_runs WHERE result->>'suggested_action' = %s", (action,)
    ).fetchone()[0]
    assert count == 1


@pytest.mark.parametrize(
    "action", ["escalate", "maybe", "close", "True_Positive", "true_positive ", ""]
)
def test_a_triage_run_saying_anything_else_is_refused(db, action):
    _refused(
        db,
        CONSTRAINT,
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt, "
        "user_message, result) VALUES (gen_random_uuid(), 'triage', 'alert', 'mig22-x', 'p', "
        "'u', jsonb_build_object('suggested_action', %s::text))",
        (action,),
    )


def test_a_triage_run_with_no_result_or_no_suggestion_is_still_accepted(db):
    """The `unavailable` shape has no result, and a result may carry no `suggested_action`."""
    _triage(db, None)
    _triage(db, {})
    _triage(db, {"confidence": "low"})


def test_the_constraint_judges_triage_runs_only(db):
    """② has its own vocabulary (`suggested_conclusion`, four values) and its own constraint;
    022 leaves it alone, and `investigate` rows are not held to ①'s."""
    assert _names(db, "ck_llm_runs_suggested_conclusion") == [
        "false_positive",
        "policy_violation",
        "confirmed_incident",
        "need_more_data",
    ]
    _insert_run(db, "investigate", {"suggested_action": "escalate"})
    _insert_run(db, "investigate", {"suggested_conclusion": "confirmed_incident"})
    _refused(
        db,
        "ck_llm_runs_suggested_conclusion",
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt, "
        "user_message, result) VALUES (gen_random_uuid(), 'investigate', 'case', 'mig22-y', 'p', "
        "'u', '{\"suggested_conclusion\": \"true_positive\"}'::jsonb)",
    )


# ── 021 -> 022, the way `make migrate` runs it ──────────────────────────────────────────────

#: Every shape ①'s stored answer can have when 022 arrives on a wiped, then re-used database.
OLD_SHAPES = (
    ("triage", {"suggested_action": "false_positive", "confidence": "high"}),
    ("triage", {"suggested_action": "needs_review", "confidence": "low"}),
    ("triage", None),  # the `unavailable` shape
    ("triage", {}),
    # An `escalate` that is not ①'s stored answer: the model's own claim, held by the gate, lives in
    # `gate_result` (`proposer_raw`); the stored `result` says needs_review.
    ("triage", {"suggested_action": "needs_review", "confidence": "medium"}),
    ("investigate", {"suggested_conclusion": "confirmed_incident"}),
    # `escalate` in a pipeline the refusal does not read.
    ("investigate", {"suggested_action": "escalate"}),
)


def test_022_applies_on_a_database_at_021_and_leaves_every_row_unchanged(tmp_path):
    with _Scratch(tmp_path, "022up") as scratch:
        stems = {path.stem for path in SCHEMA_DIR.glob(MIGRATION_FILES)}
        before = len(list(scratch.at_021.glob(MIGRATION_FILES)))
        assert before == len(stems) - 1 and "022_true_positive" in stems
        assert scratch.constraint() == ["false_positive", "needs_review", "escalate"]
        with psycopg.connect(scratch.dsn) as conn:
            for pipeline, result in OLD_SHAPES:
                _insert_run(conn, pipeline, result)
            conn.commit()
        seeded = scratch.runs()
        assert len(seeded) == len(OLD_SHAPES)

        applied = _migrated(scratch.dsn, SCHEMA_DIR)

        assert "migrate: applying 022_true_positive" in applied
        assert f"migrate: 1 applied, {before} already present" in applied
        assert scratch.runs() == seeded
        assert scratch.constraint() == ["false_positive", "needs_review", "true_positive"]
        assert scratch.recorded() == stems
        # A second run applies nothing: schema_migrations refuses a second apply.
        again = _migrated(scratch.dsn, SCHEMA_DIR)
        assert f"migrate: 0 applied, {len(stems)} already present" in again
        assert "migrate: applying" not in again
        # The new constraint is live on this database, and the old name is gone.
        with psycopg.connect(scratch.dsn) as conn:
            _triage(conn, {"suggested_action": "true_positive"})
            with pytest.raises(psycopg.errors.CheckViolation) as caught:
                _triage(conn, {"suggested_action": "escalate"})
            assert caught.value.diag.constraint_name == CONSTRAINT
            conn.rollback()


def test_022_on_a_database_with_no_runs_at_all_applies(tmp_path):
    with _Scratch(tmp_path, "022empty") as scratch:
        out = _migrated(scratch.dsn, SCHEMA_DIR)
        assert "migrate: applying 022_true_positive" in out
        assert scratch.constraint() == ["false_positive", "needs_review", "true_positive"]


# ── 022 on a database that still holds the old name (Review Focus 4) ────────────────────────


@pytest.mark.parametrize("count", [1, 3])
def test_022_refuses_while_a_triage_run_says_escalate_and_changes_nothing(tmp_path, count):
    with _Scratch(tmp_path, f"022ref{count}") as scratch:
        with psycopg.connect(scratch.dsn) as conn:
            for _ in range(count):
                _triage(conn, {"suggested_action": "escalate", "confidence": "high"})
            _triage(conn, {"suggested_action": "false_positive", "confidence": "low"})
            _insert_run(conn, "investigate", {"suggested_conclusion": "confirmed_incident"})
            conn.commit()
        seeded = scratch.runs()
        recorded_before = scratch.recorded()
        assert scratch.constraint() == ["false_positive", "needs_review", "escalate"]

        run = _migrate(scratch.dsn, SCHEMA_DIR)

        assert run.returncode != 0
        assert REFUSAL.format(n=count) in run.stderr
        assert "migrate: applying 022_true_positive" in run.stdout
        # Nothing changed: the old constraint is in place, no row moved, 022 is not recorded.
        assert scratch.constraint() == ["false_positive", "needs_review", "escalate"]
        assert scratch.runs() == seeded
        assert scratch.recorded() == recorded_before
        assert "022_true_positive" not in scratch.recorded()
        # ... so the database still takes the old name, and a second try refuses the same way.
        with psycopg.connect(scratch.dsn) as conn:
            _triage(conn, {"suggested_action": "escalate"})
            conn.commit()
        second = _migrate(scratch.dsn, SCHEMA_DIR)
        assert second.returncode != 0
        assert REFUSAL.format(n=count + 1) in second.stderr
        assert scratch.constraint() == ["false_positive", "needs_review", "escalate"]
