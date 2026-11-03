"""Migration 022 - ①'s stored verdict is strict (P14-T01, DEC-213).

One constraint changes: `ck_llm_runs_suggested_action` goes from `false_positive | needs_review |
escalate` to `false_positive | needs_review | true_positive`. ①'s `escalate` is renamed
`true_positive`; the database that held the old name is wiped before the build is deployed
(spec 4.1, Owner 03/11), so nothing is rewritten and nothing reads a stored `escalate`. The migration
REFUSES, changing nothing, while a `triage` run still holds the old name in the four places the
Director's ruling names: the stored answer (`result.suggested_action`), the verifier's
(`result.structured_only_verdict`), the model's own claim (`gate_result.proposed_verdict`) or the gated
verdict (`gate_result.final_verdict`). Other copies (`gate_result.proposer_raw`,
`gate_result.compared_to`, `verifier_result`, `gate_result.verifier_verdict`) are not read. The wipe was
skipped, or an alert arrived between the wipe and the deploy (Review Focus 4); the tracked
`backups/latest.dump` has six rows that hold it, of the four places, only in
`gate_result.proposed_verdict`.

Three layers, each on trial here:

* the migrated test database (the `db` fixture, built from `schema.sql`): the new constraint;
* a scratch database at 021, `make migrate` applying the 022 FILE the way the live database takes it
  (the fixture builds from `schema.sql`, which on its own would not notice a 022 that differs from
  what `schema.sql` holds), over rows of every verdict that may exist. The tree applied is the one
  THROUGH 022 (`scratch_db._schema_tree_through`), so a later migration does not change what is shown;
* a scratch database at 021 holding one `escalate` run, one per path: 022 raises its message, the old
  constraint stays, the row is untouched, and 022 is not recorded.

Each statement expected to fail runs in its own savepoint; the `db` fixture rolls everything back.
"""

from __future__ import annotations

import re
import shutil
import uuid
from pathlib import Path
from typing import Self

import psycopg
import pytest
from psycopg import sql
from psycopg.types.json import Jsonb

from tests import conftest
from tests.scratch_db import _schema_tree_through, _with_db
from tests.test_migration_021 import (
    _migrate,
    _migrate_run,
    _refused,
    _session_dsn,
)

pytestmark = pytest.mark.db

SCHEMA_DIR = conftest.REPO_ROOT / "docs" / "Schema"
MIGRATION_FILE = SCHEMA_DIR / "022_true_positive.sql"
MIGRATION_FILES = "[0-9][0-9][0-9]_*.sql"
CONSTRAINT = "ck_llm_runs_suggested_action"

#: The four places the Director's ruling names (DEC-213: nothing reads a stored `escalate`). The name
#: also sits in other copies of a run, which are not read and are not tested for.
PATHS = (
    "result->>'suggested_action'",
    "result->>'structured_only_verdict'",
    "gate_result->>'proposed_verdict'",
    "gate_result->>'final_verdict'",
)

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


def _insert_run(
    conn,
    pipeline: str,
    result: dict | None,
    *,
    gate_result: dict | None = None,
    role: str | None = None,
) -> uuid.UUID:
    run_id = uuid.uuid4()
    conn.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, role, system_prompt, "
        "user_message, result, gate_result) VALUES (%s, %s, %s, %s, %s, 'p', 'u', %s, %s)",
        (
            run_id,
            pipeline,
            "alert" if pipeline == "triage" else "case",
            f"mig22-{run_id.hex[:10]}",
            role,
            None if result is None else Jsonb(result),
            None if gate_result is None else Jsonb(gate_result),
        ),
    )
    return run_id


def _triage(db, result: dict | None) -> None:
    _insert_run(db, "triage", result)


class _Scratch:
    """A database at 021, dropped at the end. `through_022` is the tree a test applies to it: every
    file up to and including 022, never the whole of `docs/Schema` (023 and later are not 022's)."""

    def __init__(self, tmp_path: Path, suffix: str) -> None:
        self.session = _session_dsn()
        if shutil.which("psql") is None:
            pytest.skip("psql is not installed")
        self.at_021 = _schema_tree_through(21, tmp_path)
        self.through_022 = _schema_tree_through(22, tmp_path)
        self.name = f"{conftest._dbname(self.session)}_{suffix}_test"
        self.dsn = _with_db(self.session, self.name)
        self.admin: psycopg.Connection | None = None

    def __enter__(self) -> Self:
        self.admin = psycopg.connect(conftest._maintenance_dsn(self.session), autocommit=True)
        try:
            self.admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(self._ident()))
            self.admin.execute(sql.SQL("CREATE DATABASE {}").format(self._ident()))
            out = _migrate(self.dsn, self.at_021)
            assert "022_true_positive" not in out
        except BaseException:
            self.__exit__()  # a failed build leaks neither the connection nor the database
            raise
        return self

    def __exit__(self, *exc) -> None:
        if self.admin is not None:
            try:
                self.admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(self._ident()))
            finally:
                self.admin.close()
                self.admin = None

    def _ident(self) -> sql.Identifier:
        return sql.Identifier(self.name)

    def stems(self) -> set[str]:
        """The migrations through 022, by the files of `docs/Schema`."""
        return {path.stem for path in SCHEMA_DIR.glob(MIGRATION_FILES) if int(path.name[:3]) <= 22}

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
    # The refusal reads `triage` runs only, and the four places the ruling names.
    assert "pipeline = 'triage'" in code
    for path in PATHS:
        assert path in code, path
    assert "'escalate'" in code.split("RAISE EXCEPTION")[0]
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

#: Every shape ①'s stored answer can have when 022 arrives on a wiped, then re-used database. None
#: holds `escalate` in a `triage` run.
OLD_SHAPES = (
    ("triage", {"suggested_action": "false_positive", "confidence": "high"}, None, "proposer"),
    ("triage", {"suggested_action": "needs_review", "confidence": "low"}, None, "proposer"),
    ("triage", None, None, "proposer"),  # the `unavailable` shape
    ("triage", {}, None, "proposer"),
    (
        "triage",
        {"agree": True, "structured_only_verdict": "true_positive", "reason": "r"},
        {"final_verdict": "true_positive", "proposed_verdict": "true_positive"},
        "verifier",
    ),
    ("investigate", {"suggested_conclusion": "confirmed_incident"}, None, None),
    # `escalate` in a pipeline the refusal does not read, on every path it reads.
    (
        "investigate",
        {"suggested_action": "escalate", "structured_only_verdict": "escalate"},
        {"proposed_verdict": "escalate", "final_verdict": "escalate"},
        None,
    ),
)


def test_022_applies_on_a_database_at_021_and_leaves_every_row_unchanged(tmp_path):
    with _Scratch(tmp_path, "022up") as scratch:
        stems = scratch.stems()
        before = len(list(scratch.at_021.glob(MIGRATION_FILES)))
        assert before == len(stems) - 1 and "022_true_positive" in stems
        assert len(list(scratch.through_022.glob(MIGRATION_FILES))) == len(stems)
        assert scratch.constraint() == ["false_positive", "needs_review", "escalate"]
        with psycopg.connect(scratch.dsn) as conn:
            for pipeline, result, gate_result, role in OLD_SHAPES:
                _insert_run(conn, pipeline, result, gate_result=gate_result, role=role)
            conn.commit()
        seeded = scratch.runs()
        assert len(seeded) == len(OLD_SHAPES)

        applied = _migrate(scratch.dsn, scratch.through_022)

        assert "migrate: applying 022_true_positive" in applied
        assert f"migrate: 1 applied, {before} already present" in applied
        assert scratch.runs() == seeded
        assert scratch.constraint() == ["false_positive", "needs_review", "true_positive"]
        assert scratch.recorded() == stems
        # A second run applies nothing: schema_migrations refuses a second apply.
        again = _migrate(scratch.dsn, scratch.through_022)
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
        out = _migrate(scratch.dsn, scratch.through_022)
        assert "migrate: applying 022_true_positive" in out
        assert scratch.constraint() == ["false_positive", "needs_review", "true_positive"]


def test_a_failed_build_leaks_neither_the_connection_nor_the_database(tmp_path, monkeypatch):
    """`__enter__` creates the database and then migrates it; if the migration fails, the database
    is dropped and the admin connection closed, not left for the next run to trip over."""
    scratch = _Scratch(tmp_path, "022leak")
    monkeypatch.setattr(
        "tests.test_migration_022._migrate", lambda *a, **k: pytest.fail("boom: the build failed")
    )
    with pytest.raises(pytest.fail.Exception, match="boom"):
        scratch.__enter__()
    assert scratch.admin is None
    with psycopg.connect(conftest._maintenance_dsn(scratch.session), autocommit=True) as admin:
        found = admin.execute(
            "SELECT 1 FROM pg_database WHERE datname = %s", (scratch.name,)
        ).fetchone()
    assert found is None


# ── 022 on a database that still holds the old name (Review Focus 4) ────────────────────────

#: One row per place a `triage` run keeps ①'s verdict. Each is a database 022 must refuse. The third
#: is the shape of the six rows of the tracked `backups/latest.dump`: the gate held the model's
#: `escalate`, so the stored answer says `needs_review` and only `gate_result` remembers the claim.
ESCALATE_PATHS = {
    "suggested_action": (
        "proposer",
        {"suggested_action": "escalate", "confidence": "high"},
        None,
    ),
    "structured_only_verdict": (
        "verifier",
        {"agree": True, "structured_only_verdict": "escalate", "reason": "r"},
        None,
    ),
    "proposed_verdict": (
        "proposer",
        {"suggested_action": "needs_review", "confidence": "low"},
        {"proposed_verdict": "escalate", "final_verdict": "needs_review", "forced": True},
    ),
    "final_verdict": (
        "proposer",
        {"suggested_action": "needs_review", "confidence": "low"},
        {"proposed_verdict": "needs_review", "final_verdict": "escalate"},
    ),
}


def _seed_other_rows(conn) -> None:
    """Rows that must not count: ①'s other answers (this database is at 021, whose CHECK has no
    `true_positive` yet), an unavailable run, and ②'s."""
    _triage(conn, {"suggested_action": "false_positive", "confidence": "low"})
    _insert_run(
        conn,
        "triage",
        {"suggested_action": "needs_review"},
        gate_result={"proposed_verdict": "false_positive", "final_verdict": "needs_review"},
        role="proposer",
    )
    _triage(conn, None)
    _insert_run(conn, "investigate", {"suggested_conclusion": "confirmed_incident"})
    _insert_run(  # `escalate` in a pipeline the refusal does not read
        conn,
        "investigate",
        {"suggested_action": "escalate"},
        gate_result={"proposed_verdict": "escalate", "final_verdict": "escalate"},
    )


@pytest.mark.parametrize("path", list(ESCALATE_PATHS))
@pytest.mark.parametrize("count", [1, 3])
def test_022_refuses_while_a_triage_run_says_escalate_and_changes_nothing(tmp_path, path, count):
    role, result, gate_result = ESCALATE_PATHS[path]
    with _Scratch(tmp_path, f"022ref{path[:3]}{count}") as scratch:
        with psycopg.connect(scratch.dsn) as conn:
            for _ in range(count):
                _insert_run(conn, "triage", result, gate_result=gate_result, role=role)
            _seed_other_rows(conn)
            conn.commit()
        seeded = scratch.runs()
        recorded_before = scratch.recorded()
        assert scratch.constraint() == ["false_positive", "needs_review", "escalate"]

        run = _migrate_run(scratch.dsn, scratch.through_022)

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
        second = _migrate_run(scratch.dsn, scratch.through_022)
        assert second.returncode != 0
        assert REFUSAL.format(n=count + 1) in second.stderr
        assert scratch.constraint() == ["false_positive", "needs_review", "escalate"]


def test_022_counts_a_run_once_however_many_places_hold_escalate(tmp_path):
    with _Scratch(tmp_path, "022all") as scratch:
        with psycopg.connect(scratch.dsn) as conn:
            _insert_run(  # one run, escalate in all four places: counted once
                conn,
                "triage",
                {"suggested_action": "escalate", "structured_only_verdict": "escalate"},
                gate_result={"proposed_verdict": "escalate", "final_verdict": "escalate"},
                role="proposer",
            )
            for role, result, gate_result in ESCALATE_PATHS.values():  # four more, one each
                _insert_run(conn, "triage", result, gate_result=gate_result, role=role)
            _seed_other_rows(conn)
            conn.commit()

        run = _migrate_run(scratch.dsn, scratch.through_022)

        assert run.returncode != 0
        assert REFUSAL.format(n=5) in run.stderr
        assert scratch.constraint() == ["false_positive", "needs_review", "escalate"]
