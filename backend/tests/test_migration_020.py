"""Migration 020 — the learned-knowledge schema (P13-T01, DEC-210).

One migration carries every schema change of the feature (spec §6, §7.2), each on trial here
against the migrated test database:

* three tables: `knowledge_drafts` (what the model proposes from a conclusion), `knowledge_entries`
  (what an admin approved: the Markdown, its hash, its path, a `simple`-configuration tsvector
  with a GIN index) and `rag_results` (one stored lookup per alert or case);
* `llm_runs`: `rag_lookup_id`; the two new pipelines `rag_lookup` and `knowledge_draft`, each of
  which may run on an `alert` or a `case` (① stays on `alert`, ② on `case`); the two new roles
  `retriever` and `drafter`;
* `jobs`: the two new job types; `audit_events`: the eight new event types (28 -> 36);
* the expression index `ix_alerts_soar_dedup_key` the history query uses;
* `app_rw`'s rights on the three tables, granted by 020 itself (the way 019 does it).

Each statement expected to fail runs in its own savepoint, so the next one still runs; the `db`
fixture rolls everything back at the end.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path

import psycopg
import pytest
from app.audit import events
from app.infra import auth, jobs
from psycopg import sql
from psycopg.types.json import Jsonb

from tests import conftest
from tests.scratch_db import _with_db

pytestmark = pytest.mark.db

SCHEMA_DIR = conftest.REPO_ROOT / "docs" / "Schema"
MIGRATION_FILES = "[0-9][0-9][0-9]_*.sql"
SHA = hashlib.sha256(b"entry").hexdigest()

CONCLUSIONS = (
    "closed_fp",
    "closed_benign",
    "concluded_fp",
    "concluded_policy_violation",
    "confirmed_incident",
)

# 019's 28 names, in 019's order, then the eight of 020 in DEC-210's order.
EVENTS_BEFORE_020 = [
    "alert.received",
    "alert.duplicate_merged",
    "alert.auto_closed",
    "alert.autoclose_blocked_critical",
    "alert.enrich_started",
    "alert.enriched",
    "alert.reopened",
    "job.exhausted",
    "triage.suggested",
    "alert.acknowledged",
    "tier1.decided",
    "tier1.escalated",
    "case.opened",
    "case.truncated",
    "case.analyzed",
    "tier2.concluded",
    "authz.denied",
    "admin.user_created",
    "admin.user_updated",
    "admin.job_retried",
    "admin.autoclose_rule_toggled",
    "autoclose.reviewed",
    "rule.suspected_wrong",
    "llm.gate_forced",
    "llm.builder_violation",
    "health.alarm",
    "label.created",
    "admin.settings_changed",
]
EVENTS_IN_020 = [
    "knowledge.drafted",
    "knowledge.approved",
    "knowledge.rejected",
    "knowledge.retired",
    "knowledge.merged",
    "rag.lookup_failed",
    "rag.integrity_failed",
    "knowledge.redraft_requested",  # added in the P13 fix wave (item 20): 020 is applied nowhere yet
]

TABLES = ("knowledge_drafts", "knowledge_entries", "rag_results")

# column -> (type as `format_type` prints it, NOT NULL)
DRAFT_COLUMNS = {
    "draft_id": ("uuid", True),
    "source_kind": ("text", True),
    "source_id": ("text", True),
    "conclusion": ("text", True),
    "status": ("text", True),
    "draft": ("jsonb", True),
    "warnings": ("jsonb", True),
    "llm_run_id": ("uuid", False),
    "duplicate_of_entry": ("uuid", False),
    "conflict_with_entry": ("uuid", False),
    "created_at": ("timestamp with time zone", True),
    "reviewed_by": ("uuid", False),
    "reviewed_at": ("timestamp with time zone", False),
    "review_note": ("text", False),
}
ENTRY_COLUMNS = {
    "entry_id": ("uuid", True),
    "version": ("integer", True),
    "status": ("text", True),
    "conclusion": ("text", True),
    "category": ("text", True),
    "mitre_ids": ("text[]", True),
    "tags": ("text[]", True),
    "soar_scenario": ("text", False),
    "rule_ids": ("text[]", True),
    "log_source": ("text", False),
    "fingerprint": ("text", True),
    "fingerprint_tsv": ("tsvector", False),
    "content": ("text", True),
    "content_sha256": ("text", True),
    "file_path": ("text", True),
    "source_alert_ids": ("text[]", True),
    "source_case_ids": ("uuid[]", True),
    "evidence": ("jsonb", True),
    "approved_by": ("uuid", False),
    "approved_at": ("timestamp with time zone", False),
    "supersedes_entry": ("uuid", False),
}
RESULT_COLUMNS = {
    "lookup_id": ("uuid", True),
    "subject_kind": ("text", True),
    "subject_id": ("text", True),
    "status": ("text", True),
    "history": ("jsonb", False),
    "matches": ("jsonb", False),
    "match_notes": ("jsonb", False),
    "llm_run_id": ("uuid", False),
    "created_at": ("timestamp with time zone", True),
}
CONSTRAINTS = {
    "knowledge_drafts": {
        "knowledge_drafts_pkey": "p",
        "ux_knowledge_drafts_source": "u",
        "ck_knowledge_drafts_source_kind": "c",
        "ck_knowledge_drafts_conclusion": "c",
        "ck_knowledge_drafts_status": "c",
        "fk_knowledge_drafts_reviewer": "f",
        "fk_knowledge_drafts_duplicate_of": "f",
        "fk_knowledge_drafts_conflict_with": "f",
    },
    "knowledge_entries": {
        "knowledge_entries_pkey": "p",
        "ck_knowledge_entries_status": "c",
        "ck_knowledge_entries_conclusion": "c",
        "ck_knowledge_entries_version_duong": "c",
        "ck_knowledge_entries_content_sha256": "c",
        "fk_knowledge_entries_approver": "f",
        "fk_knowledge_entries_supersedes": "f",
    },
    "rag_results": {
        "rag_results_pkey": "p",
        "ck_rag_results_subject_kind": "c",
        "ck_rag_results_status": "c",
    },
}


# ── helpers ─────────────────────────────────────────────────────────────────────────────────


def _user(db) -> str:
    return auth.create_user(
        db,
        username=f"p13t01-{uuid.uuid4().hex[:8]}",
        display_name="P13-T01",
        role="admin",
        password="unused-unused",
    )


def _columns(db, table: str) -> dict[str, tuple[str, bool]]:
    rows = db.execute(
        "SELECT a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull "
        "FROM pg_attribute a WHERE a.attrelid = %s::regclass AND a.attnum > 0 "
        "AND NOT a.attisdropped",
        (table,),
    ).fetchall()
    return {name: (type_, notnull) for name, type_, notnull in rows}


def _constraint_def(db, table: str, name: str) -> str:
    row = db.execute(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
        "WHERE conname = %s AND conrelid = %s::regclass",
        (name, table),
    ).fetchone()
    assert row is not None, f"{table} has no constraint {name}"
    return row[0]


def _quoted(definition: str) -> list[str]:
    return re.findall(r"'([^']*)'", definition)


def _draft(db, **over) -> str:
    row = {
        "source_kind": "alert",
        "source_id": f"gl-{uuid.uuid4().hex}",
        "conclusion": "closed_fp",
    }
    row.update(over)
    columns = ", ".join(row)
    marks = ", ".join(["%s"] * len(row))
    return db.execute(
        f"INSERT INTO knowledge_drafts ({columns}) VALUES ({marks}) RETURNING draft_id",
        list(row.values()),
    ).fetchone()[0]


def _entry(db, **over) -> str:
    entry_id = over.pop("entry_id", str(uuid.uuid4()))
    row = {
        "entry_id": entry_id,
        "conclusion": "closed_fp",
        "category": "ssh_brute_force",
        "fingerprint": "ssh brute force closed false positive",
        "content": "---\nentry_id: x\n---\nbody\n",
        "content_sha256": SHA,
        "file_path": f"kb_learned/entries/ssh_brute_force/{entry_id}.md",
    }
    row.update(over)
    columns = ", ".join(row)
    marks = ", ".join(["%s"] * len(row))
    db.execute(f"INSERT INTO knowledge_entries ({columns}) VALUES ({marks})", list(row.values()))
    return entry_id


def _result(db, **over) -> str:
    lookup_id = over.pop("lookup_id", str(uuid.uuid4()))
    row = {
        "lookup_id": lookup_id,
        "subject_kind": "alert",
        "subject_id": f"gl-{uuid.uuid4().hex}",
        "status": "ok",
    }
    row.update(over)
    columns = ", ".join(row)
    marks = ", ".join(["%s"] * len(row))
    db.execute(f"INSERT INTO rag_results ({columns}) VALUES ({marks})", list(row.values()))
    return lookup_id


def _llm_run(db, **over) -> None:
    row = {
        "run_id": str(uuid.uuid4()),
        "pipeline": "rag_lookup",
        "subject_type": "alert",
        "subject_id": "gl-x",
        "system_prompt": "s",
        "user_message": "u",
    }
    row.update(over)
    columns = ", ".join(row)
    marks = ", ".join(["%s"] * len(row))
    db.execute(f"INSERT INTO llm_runs ({columns}) VALUES ({marks})", list(row.values()))


def _refused(db, error, statement) -> psycopg.Error:
    """Run `statement()` expecting `error`; its own savepoint keeps the connection usable.

    A statement first: it opens the fixture's outer transaction, so `db.transaction()` below is a
    savepoint. As the first thing on a connection it would be the outermost one and COMMIT a stray
    row into the session database whenever the schema stopped refusing the statement."""
    db.execute("SELECT 1")
    with pytest.raises(error) as caught, db.transaction():
        statement()
    return caught.value


def _schema_without_020(tmp_path: Path) -> Path:
    """A copy of `docs/Schema` with only the migrations numbered below 020, and a `schema.sql`
    the real `build_schema.py` builds from them: the tree as it stood at 019."""
    at_019 = tmp_path / "Schema"
    at_019.mkdir()
    for path in SCHEMA_DIR.glob(MIGRATION_FILES):
        if int(path.name[:3]) < 20:
            shutil.copy(path, at_019)
    shutil.copy(SCHEMA_DIR / "build_schema.py", at_019)
    built = subprocess.run(
        ["python3", str(at_019 / "build_schema.py")], capture_output=True, text=True, check=False
    )
    if built.returncode != 0:
        pytest.fail(f"build_schema.py exit {built.returncode}:\n{built.stderr}")
    return at_019


def _migrate(dsn, mig_dir, **env: str) -> str:
    """`scripts/migrate.sh` against `dsn` over the tree `mig_dir`; its stdout. Plain values
    only, never `assert run.returncode == 0`: pytest would print `run` whole, DSN included."""
    run = subprocess.run(
        ["bash", "scripts/migrate.sh", str(dsn)],
        cwd=conftest.REPO_ROOT,
        env={**os.environ, "MIGRATIONS_DIR": str(mig_dir), **env},
        capture_output=True,
        text=True,
        check=False,
    )
    if run.returncode != 0:
        pytest.fail(f"migrate.sh exit {run.returncode}:\n{run.stderr}")
    return run.stdout


def _session_dsn():
    return conftest.require_test_dsn(
        os.environ.get("TEST_DATABASE_URL", conftest.DEFAULT_TEST_DATABASE_URL)
    )


# ── the migration records itself ────────────────────────────────────────────────────────────


def test_020_records_itself(db):
    """All this test can show: the shared database is built from `schema.sql`, and `migrate.sh`
    records every version named in that file's banners. Whether the FILE records itself is the
    upgrade test's job (its third `migrate.sh` run)."""
    row = db.execute(
        "SELECT 1 FROM schema_migrations WHERE version = '020_learned_knowledge'"
    ).fetchone()
    assert row is not None, "020_learned_knowledge is not in the test database's schema_migrations"


def test_a_second_apply_is_refused_by_schema_migrations(db):
    with pytest.raises(psycopg.errors.UniqueViolation), db.transaction():
        db.execute("INSERT INTO schema_migrations (version) VALUES ('020_learned_knowledge')")


# ── the three tables ────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("table", "expected"),
    [
        ("knowledge_drafts", DRAFT_COLUMNS),
        ("knowledge_entries", ENTRY_COLUMNS),
        ("rag_results", RESULT_COLUMNS),
    ],
)
def test_each_table_has_exactly_its_columns_with_their_types_and_nullability(db, table, expected):
    assert _columns(db, table) == expected


@pytest.mark.parametrize("table", TABLES)
def test_each_table_has_its_named_constraints_of_the_right_kind(db, table):
    rows = db.execute(
        "SELECT conname, contype FROM pg_constraint WHERE conrelid = %s::regclass "
        "AND contype IN ('p', 'u', 'c', 'f')",
        (table,),
    ).fetchall()
    assert dict(rows) == CONSTRAINTS[table]


def test_the_primary_keys_are_the_uuid_ids(db):
    keys = dict(
        db.execute(
            "SELECT conrelid::regclass::text, (SELECT a.attname FROM pg_attribute a "
            "WHERE a.attrelid = c.conrelid AND a.attnum = c.conkey[1]) "
            "FROM pg_constraint c WHERE c.contype = 'p' "
            "AND c.conrelid = ANY (ARRAY['knowledge_drafts', 'knowledge_entries', "
            "'rag_results']::regclass[])"
        ).fetchall()
    )
    assert keys == {
        "knowledge_drafts": "draft_id",
        "knowledge_entries": "entry_id",
        "rag_results": "lookup_id",
    }


def test_the_unique_constraint_is_on_source_kind_and_source_id_in_that_order(db):
    definition = _constraint_def(db, "knowledge_drafts", "ux_knowledge_drafts_source")
    assert definition == "UNIQUE (source_kind, source_id)"


# ── knowledge_drafts ────────────────────────────────────────────────────────────────────────


def test_a_draft_takes_its_defaults(db):
    draft_id = _draft(db)
    row = db.execute(
        "SELECT status, draft, warnings, llm_run_id, duplicate_of_entry, conflict_with_entry, "
        "reviewed_by, reviewed_at, review_note, created_at IS NOT NULL "
        "FROM knowledge_drafts WHERE draft_id = %s",
        (draft_id,),
    ).fetchone()
    assert row == ("pending", {}, [], None, None, None, None, None, None, True)


def test_draft_ids_are_generated_by_the_database(db):
    assert _draft(db) != _draft(db)


def test_one_draft_per_source(db):
    _draft(db, source_kind="alert", source_id="gl-same")
    error = _refused(
        db,
        psycopg.errors.UniqueViolation,
        lambda: _draft(db, source_kind="alert", source_id="gl-same", conclusion="closed_benign"),
    )
    assert error.diag.constraint_name == "ux_knowledge_drafts_source"


def test_the_same_id_may_be_both_an_alert_and_a_case_source(db):
    _draft(db, source_kind="alert", source_id="same")
    _draft(db, source_kind="case", source_id="same", conclusion="confirmed_incident")


@pytest.mark.parametrize("kind", ["alert", "case"])
def test_a_draft_source_kind_is_alert_or_case(db, kind):
    _draft(db, source_kind=kind)


@pytest.mark.parametrize("kind", ["user", "Alert", ""])
def test_a_draft_refuses_any_other_source_kind(db, kind):
    error = _refused(db, psycopg.errors.CheckViolation, lambda: _draft(db, source_kind=kind))
    assert error.diag.constraint_name == "ck_knowledge_drafts_source_kind"


@pytest.mark.parametrize("conclusion", CONCLUSIONS)
def test_a_draft_takes_each_of_the_five_conclusions(db, conclusion):
    _draft(db, conclusion=conclusion)


@pytest.mark.parametrize("conclusion", ["false_positive", "closed", "needs_review", ""])
def test_a_draft_refuses_any_other_conclusion(db, conclusion):
    error = _refused(db, psycopg.errors.CheckViolation, lambda: _draft(db, conclusion=conclusion))
    assert error.diag.constraint_name == "ck_knowledge_drafts_conclusion"


@pytest.mark.parametrize("status", ["pending", "approved", "rejected", "merged"])
def test_a_draft_takes_each_of_the_four_statuses(db, status):
    _draft(db, status=status)


@pytest.mark.parametrize("status", ["draft", "retired", "active", ""])
def test_a_draft_refuses_any_other_status(db, status):
    error = _refused(db, psycopg.errors.CheckViolation, lambda: _draft(db, status=status))
    assert error.diag.constraint_name == "ck_knowledge_drafts_status"


def test_a_draft_names_a_real_reviewer(db):
    user = _user(db)
    _draft(db, reviewed_by=user)
    _refused(
        db, psycopg.errors.ForeignKeyViolation, lambda: _draft(db, reviewed_by=str(uuid.uuid4()))
    )


def test_a_draft_names_real_entries_for_duplicate_and_conflict(db):
    entry = _entry(db)
    _draft(db, duplicate_of_entry=entry, conflict_with_entry=entry)
    missing = str(uuid.uuid4())
    _refused(db, psycopg.errors.ForeignKeyViolation, lambda: _draft(db, duplicate_of_entry=missing))
    _refused(
        db, psycopg.errors.ForeignKeyViolation, lambda: _draft(db, conflict_with_entry=missing)
    )


@pytest.mark.parametrize("column", ["source_kind", "source_id", "conclusion", "status"])
def test_a_draft_requires_its_identity_columns(db, column):
    _refused(db, psycopg.errors.NotNullViolation, lambda: _draft(db, **{column: None}))


# ── knowledge_entries ───────────────────────────────────────────────────────────────────────


def test_an_entry_takes_its_defaults(db):
    entry_id = _entry(db)
    row = db.execute(
        "SELECT version, status, mitre_ids, tags, rule_ids, source_alert_ids, source_case_ids, "
        "evidence, soar_scenario, log_source, approved_by, approved_at, supersedes_entry "
        "FROM knowledge_entries WHERE entry_id = %s",
        (entry_id,),
    ).fetchone()
    assert row == (1, "active", [], [], [], [], [], [], None, None, None, None, None)


def test_an_entry_holds_every_list_field(db):
    case_id = str(uuid.uuid4())
    entry_id = _entry(
        db,
        mitre_ids=["T1110", "T1110.001"],
        tags=["ssh", "brute_force"],
        rule_ids=["5710", "5712"],
        source_alert_ids=["gl-a", "gl-b"],
        source_case_ids=[case_id],
        evidence=Jsonb([{"kind": "alert", "id": "gl-a"}]),
        soar_scenario="ssh_bruteforce_lab",
        log_source="sshd",
    )
    row = db.execute(
        "SELECT mitre_ids, tags, rule_ids, source_alert_ids, source_case_ids::text[], evidence, "
        "soar_scenario, log_source FROM knowledge_entries WHERE entry_id = %s",
        (entry_id,),
    ).fetchone()
    assert row == (
        ["T1110", "T1110.001"],
        ["ssh", "brute_force"],
        ["5710", "5712"],
        ["gl-a", "gl-b"],
        [case_id],
        [{"kind": "alert", "id": "gl-a"}],
        "ssh_bruteforce_lab",
        "sshd",
    )


def test_the_fingerprint_tsv_is_generated_from_the_fingerprint_in_the_simple_configuration(db):
    """`simple`: lower-cased tokens, no stemming, no stop words. `Running` stays `running`, so a
    Vietnamese or mixed log-source fingerprint is matched as written, never by an English stemmer.
    """
    entry_id = _entry(db, fingerprint="Running the BRUTE force")
    (tsv,) = db.execute(
        "SELECT fingerprint_tsv::text FROM knowledge_entries WHERE entry_id = %s", (entry_id,)
    ).fetchone()
    assert tsv == "'brute':3 'force':4 'running':1 'the':2"


def test_the_fingerprint_tsv_follows_an_update_of_the_fingerprint(db):
    entry_id = _entry(db, fingerprint="alpha")
    db.execute(
        "UPDATE knowledge_entries SET fingerprint = 'beta gamma' WHERE entry_id = %s", (entry_id,)
    )
    (tsv,) = db.execute(
        "SELECT fingerprint_tsv::text FROM knowledge_entries WHERE entry_id = %s", (entry_id,)
    ).fetchone()
    assert tsv == "'beta':1 'gamma':2"


def test_the_fingerprint_tsv_cannot_be_written_directly(db):
    _refused(
        db,
        psycopg.errors.GeneratedAlways,
        lambda: db.execute(
            "INSERT INTO knowledge_entries (entry_id, conclusion, category, fingerprint, "
            "fingerprint_tsv, content, content_sha256, file_path) VALUES (gen_random_uuid(), "
            "'closed_fp', 'x', 'a', to_tsvector('simple', 'b'), 'c', %s, 'p')",
            (SHA,),
        ),
    )


def test_a_full_text_query_finds_an_entry_by_its_fingerprint(db):
    wanted = _entry(db, fingerprint="sshd failed password root 203.0.113.9")
    _entry(db, fingerprint="windows rdp logon failure")
    found = db.execute(
        "SELECT entry_id FROM knowledge_entries "
        "WHERE fingerprint_tsv @@ to_tsquery('simple', 'sshd & root')"
    ).fetchall()
    assert [str(row[0]) for row in found] == [wanted]


def test_the_fingerprint_tsv_has_a_gin_index(db):
    definition = db.execute(
        "SELECT indexdef FROM pg_indexes WHERE tablename = 'knowledge_entries' "
        "AND indexname = 'ix_knowledge_entries_fingerprint_tsv'"
    ).fetchone()
    assert definition is not None, "no index ix_knowledge_entries_fingerprint_tsv"
    assert "USING gin (fingerprint_tsv)" in definition[0]


@pytest.mark.parametrize("status", ["active", "retired"])
def test_an_entry_is_active_or_retired(db, status):
    _entry(db, status=status)


@pytest.mark.parametrize("status", ["pending", "approved", ""])
def test_an_entry_refuses_any_other_status(db, status):
    error = _refused(db, psycopg.errors.CheckViolation, lambda: _entry(db, status=status))
    assert error.diag.constraint_name == "ck_knowledge_entries_status"


@pytest.mark.parametrize("conclusion", CONCLUSIONS)
def test_an_entry_takes_each_of_the_five_conclusions(db, conclusion):
    _entry(db, conclusion=conclusion)


@pytest.mark.parametrize("conclusion", ["false_positive", "merged", ""])
def test_an_entry_refuses_any_other_conclusion(db, conclusion):
    error = _refused(db, psycopg.errors.CheckViolation, lambda: _entry(db, conclusion=conclusion))
    assert error.diag.constraint_name == "ck_knowledge_entries_conclusion"


@pytest.mark.parametrize("version", [0, -1])
def test_an_entry_version_starts_at_one(db, version):
    error = _refused(db, psycopg.errors.CheckViolation, lambda: _entry(db, version=version))
    assert error.diag.constraint_name == "ck_knowledge_entries_version_duong"


@pytest.mark.parametrize("sha", ["", "abc", "Z" * 64, SHA.upper(), SHA + "0"])
def test_an_entry_hash_is_64_lower_case_hex(db, sha):
    error = _refused(db, psycopg.errors.CheckViolation, lambda: _entry(db, content_sha256=sha))
    assert error.diag.constraint_name == "ck_knowledge_entries_content_sha256"


@pytest.mark.parametrize(
    "column", ["conclusion", "category", "fingerprint", "content", "content_sha256", "file_path"]
)
def test_an_entry_requires_its_content_and_identity_columns(db, column):
    _refused(db, psycopg.errors.NotNullViolation, lambda: _entry(db, **{column: None}))


def test_an_entry_supersedes_a_real_entry_and_is_approved_by_a_real_user(db):
    old = _entry(db)
    _entry(db, supersedes_entry=old, version=2, approved_by=_user(db))
    _refused(
        db,
        psycopg.errors.ForeignKeyViolation,
        lambda: _entry(db, supersedes_entry=str(uuid.uuid4())),
    )
    _refused(
        db,
        psycopg.errors.ForeignKeyViolation,
        lambda: _entry(db, approved_by=str(uuid.uuid4())),
    )


# ── rag_results ─────────────────────────────────────────────────────────────────────────────


def test_a_result_takes_its_defaults_and_leaves_the_json_fields_empty(db):
    lookup_id = _result(db)
    row = db.execute(
        "SELECT history, matches, match_notes, llm_run_id, created_at IS NOT NULL "
        "FROM rag_results WHERE lookup_id = %s",
        (lookup_id,),
    ).fetchone()
    assert row == (None, None, None, None, True)


@pytest.mark.parametrize("status", ["ok", "empty", "failed", "budget"])
def test_a_result_takes_each_of_the_four_statuses(db, status):
    _result(db, status=status)


@pytest.mark.parametrize("status", ["pending", "error", ""])
def test_a_result_refuses_any_other_status(db, status):
    error = _refused(db, psycopg.errors.CheckViolation, lambda: _result(db, status=status))
    assert error.diag.constraint_name == "ck_rag_results_status"


@pytest.mark.parametrize("kind", ["alert", "case"])
def test_a_result_subject_is_an_alert_or_a_case(db, kind):
    _result(db, subject_kind=kind)


@pytest.mark.parametrize("kind", ["user", "entry", ""])
def test_a_result_refuses_any_other_subject_kind(db, kind):
    error = _refused(db, psycopg.errors.CheckViolation, lambda: _result(db, subject_kind=kind))
    assert error.diag.constraint_name == "ck_rag_results_subject_kind"


def test_a_subject_may_have_several_results_over_time(db):
    """A case is looked up again after `RAG_CASE_REFRESH_H`: the table keeps every lookup, and the
    index below serves "the newest one for this subject"."""
    _result(db, subject_id="gl-again")
    _result(db, subject_id="gl-again")
    (count,) = db.execute(
        "SELECT count(*) FROM rag_results WHERE subject_id = 'gl-again'"
    ).fetchone()
    assert count == 2


def test_a_result_stores_the_matches_as_json(db):
    entry = str(uuid.uuid4())
    matches = [{"entry_id": entry, "level": "giong", "content_sha256": SHA}]
    lookup_id = _result(
        db,
        matches=Jsonb(matches),
        history=Jsonb({"level0": []}),
        match_notes=Jsonb([{"entry_id": entry, "reason": "same rule"}]),
    )
    (stored,) = db.execute(
        "SELECT matches FROM rag_results WHERE lookup_id = %s", (lookup_id,)
    ).fetchone()
    assert stored == matches


def test_the_result_index_is_subject_kind_subject_id_created_at_descending(db):
    (definition,) = db.execute(
        "SELECT indexdef FROM pg_indexes WHERE tablename = 'rag_results' "
        "AND indexname = 'ix_rag_results_subject'"
    ).fetchone()
    assert "(subject_kind, subject_id, created_at DESC)" in definition


# ── llm_runs ────────────────────────────────────────────────────────────────────────────────


def test_llm_runs_gains_a_nullable_rag_lookup_id(db):
    row = db.execute(
        "SELECT format_type(atttypid, atttypmod), attnotnull FROM pg_attribute "
        "WHERE attrelid = 'llm_runs'::regclass AND attname = 'rag_lookup_id'"
    ).fetchone()
    assert row == ("uuid", False)


def test_a_run_may_carry_the_lookup_it_belongs_to(db):
    lookup_id = str(uuid.uuid4())
    run_id = str(uuid.uuid4())
    _llm_run(db, run_id=run_id, rag_lookup_id=lookup_id)
    (stored,) = db.execute(
        "SELECT rag_lookup_id::text FROM llm_runs WHERE run_id = %s", (run_id,)
    ).fetchone()
    assert stored == lookup_id


@pytest.mark.parametrize("pipeline", ["rag_lookup", "knowledge_draft"])
@pytest.mark.parametrize("subject_type", ["alert", "case"])
def test_each_new_pipeline_runs_on_an_alert_or_a_case(db, pipeline, subject_type):
    _llm_run(db, pipeline=pipeline, subject_type=subject_type)


def test_a_triage_run_on_a_case_is_still_refused(db):
    error = _refused(
        db,
        psycopg.errors.CheckViolation,
        lambda: _llm_run(db, pipeline="triage", subject_type="case"),
    )
    assert error.diag.constraint_name == "ck_llm_runs_pipeline_khop_subject"


def test_an_investigate_run_on_an_alert_is_still_refused(db):
    error = _refused(
        db,
        psycopg.errors.CheckViolation,
        lambda: _llm_run(db, pipeline="investigate", subject_type="alert"),
    )
    assert error.diag.constraint_name == "ck_llm_runs_pipeline_khop_subject"


def test_the_two_old_pipelines_still_run_on_their_own_subject(db):
    _llm_run(db, pipeline="triage", subject_type="alert")
    _llm_run(db, pipeline="investigate", subject_type="case")


@pytest.mark.parametrize("pipeline", ["rag_lookup", "knowledge_draft"])
def test_a_new_pipeline_does_not_open_the_door_to_another_subject_type(db, pipeline):
    """Two CHECKs refuse it and Postgres reports the first by name (the pairing one sorts before
    `ck_llm_runs_subject_type`); either is the right answer."""
    error = _refused(
        db,
        psycopg.errors.CheckViolation,
        lambda: _llm_run(db, pipeline=pipeline, subject_type="user"),
    )
    assert error.diag.constraint_name in {
        "ck_llm_runs_pipeline_khop_subject",
        "ck_llm_runs_subject_type",
    }


def test_an_unknown_pipeline_is_refused(db):
    error = _refused(db, psycopg.errors.CheckViolation, lambda: _llm_run(db, pipeline="rag"))
    assert error.diag.constraint_name == "ck_llm_runs_pipeline"


def test_the_pipeline_constraint_names_exactly_four_pipelines(db):
    definition = _constraint_def(db, "llm_runs", "ck_llm_runs_pipeline")
    assert sorted(_quoted(definition)) == sorted(
        ["triage", "investigate", "rag_lookup", "knowledge_draft"]
    )


@pytest.mark.parametrize(
    "role", [None, "proposer", "verifier", "investigator", "retriever", "drafter"]
)
def test_the_role_may_be_null_or_one_of_five(db, role):
    _llm_run(db, pipeline="triage", role=role)


@pytest.mark.parametrize("role", ["reviewer", "ranker", ""])
def test_any_other_role_is_refused(db, role):
    error = _refused(db, psycopg.errors.CheckViolation, lambda: _llm_run(db, role=role))
    assert error.diag.constraint_name == "ck_llm_runs_role"


def test_llm_runs_stays_append_only(db):
    run_id = str(uuid.uuid4())
    _llm_run(db, run_id=run_id)
    _refused(
        db,
        psycopg.Error,
        lambda: db.execute(
            "UPDATE llm_runs SET rag_lookup_id = gen_random_uuid() WHERE run_id = %s", (run_id,)
        ),
    )


# ── jobs and events ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("job_type", sorted(jobs.JOB_TYPES))
def test_the_jobs_constraint_admits_every_python_job_type(db, job_type):
    db.execute(
        "INSERT INTO jobs (job_type, subject_id) VALUES (%s, %s)", (job_type, f"x-{job_type}")
    )


def test_the_jobs_constraint_names_exactly_the_python_job_types(db):
    definition = _constraint_def(db, "jobs", "ck_jobs_job_type")
    assert set(_quoted(definition)) == set(jobs.JOB_TYPES)
    assert {"rag_lookup", "knowledge_draft"} <= set(_quoted(definition))


@pytest.mark.parametrize("job_type", ["enrich", "rag", "knowledge", ""])
def test_the_jobs_constraint_refuses_any_other_type(db, job_type):
    error = _refused(
        db,
        psycopg.errors.CheckViolation,
        lambda: db.execute("INSERT INTO jobs (job_type, subject_id) VALUES (%s, 'x')", (job_type,)),
    )
    assert error.diag.constraint_name == "ck_jobs_job_type"


def _event_names(db) -> list[str]:
    return _quoted(_constraint_def(db, "audit_events", "ck_audit_event_type"))


def test_the_event_constraint_holds_36_names_the_28_first_in_order(db):
    names = _event_names(db)
    assert len(names) == len(set(names)) == 36
    assert names[:28] == EVENTS_BEFORE_020
    assert names[28:] == EVENTS_IN_020


def test_the_event_constraint_is_the_python_event_types(db):
    assert set(_event_names(db)) == set(events.EVENT_TYPES)


@pytest.mark.parametrize("name", EVENTS_IN_020)
def test_each_new_event_type_is_written(db, name):
    assert events.write_event(db, name, "alert:gl-x", "system")


def test_a_misspelt_new_event_type_is_refused_by_the_database(db):
    error = _refused(
        db,
        psycopg.errors.CheckViolation,
        lambda: db.execute(
            "INSERT INTO audit_events (event_type, subject_id, actor_role) "
            "VALUES ('knowledge.approve', 'x', 'system')"
        ),
    )
    assert error.diag.constraint_name == "ck_audit_event_type"


# ── the expression index ────────────────────────────────────────────────────────────────────


def test_the_dedup_key_expression_index_exists_on_the_exact_expression(db):
    (definition,) = db.execute(
        "SELECT indexdef FROM pg_indexes WHERE tablename = 'alerts' "
        "AND indexname = 'ix_alerts_soar_dedup_key'"
    ).fetchone()
    assert "(raw_payload #>> '{enrichment,case,dedup_key}'::text[])" in definition


def test_the_history_query_can_use_the_expression_index(db):
    """The index only helps a query that writes the expression the way it was indexed. Sequential
    scans are switched off so the planner shows the choice it would make on a large table."""
    db.execute("SET LOCAL enable_seqscan = off")
    plan = "\n".join(
        row[0]
        for row in db.execute(
            "EXPLAIN SELECT alert_id FROM alerts "
            "WHERE (raw_payload #>> '{enrichment,case,dedup_key}') = 'case-key-1'"
        ).fetchall()
    )
    assert "ix_alerts_soar_dedup_key" in plan, plan


# ── grants ──────────────────────────────────────────────────────────────────────────────────


#: `rag_results` is append-only (P13 fix wave, item 27): a lookup is stored once and read, nothing updates it.
APPEND_ONLY = "rag_results"


@pytest.mark.parametrize("table", [t for t in TABLES if t != APPEND_ONLY])
def test_app_rw_holds_select_insert_update(db, table):
    held = {
        privilege: db.execute(
            "SELECT has_table_privilege('app_rw', %s, %s)", (table, privilege)
        ).fetchone()[0]
        for privilege in ("SELECT", "INSERT", "UPDATE")
    }
    assert held == {"SELECT": True, "INSERT": True, "UPDATE": True}


def test_app_rw_holds_select_and_insert_on_rag_results_and_nothing_that_changes_a_row(db):
    held = {
        privilege: db.execute(
            "SELECT has_table_privilege('app_rw', %s, %s)", (APPEND_ONLY, privilege)
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


def test_app_rw_cannot_update_or_delete_a_stored_lookup(db):
    lookup_id = str(uuid.uuid4())
    _result(db, lookup_id=lookup_id)
    for statement in (
        "UPDATE rag_results SET status = 'failed' WHERE lookup_id = %s",
        "DELETE FROM rag_results WHERE lookup_id = %s",
    ):
        with db.transaction(force_rollback=True):
            db.execute("SET LOCAL ROLE app_rw")
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                db.execute(statement, (lookup_id,))
    assert (
        db.execute(
            "SELECT count(*) FROM rag_results WHERE lookup_id = %s", (lookup_id,)
        ).fetchone()[0]
        == 1
    )


def test_020_says_what_rag_lookup_id_is_and_when_it_is_null():
    """P13 fix wave, item 12 (T07): the comment said NULL for every run that is not a lookup's own, but
    ① and ② rows carry the lookup their prompt held. The migration is unapplied on any live host, so its
    comment is corrected where it stands."""
    text = (SCHEMA_DIR / "020_learned_knowledge.sql").read_text(encoding="utf-8")
    assert "NULL for every run that is not a lookup's own" not in text
    comment = text[text.index("`llm_runs`: `rag_lookup_id`") :].split("\n--   3.", 1)[0]
    comment = re.sub(r"\s*\n--\s*", " ", comment)  # the comment as one line
    for phrase in (
        "run's own lookup",  # a rag_lookup run
        "on a ① or ② row",  # the proposer / investigator rows
        "learned section reached the prompt",  # set only when the section was in the prompt
        "token budget cut the whole section",  # and NULL when it was all cut
        "RAG is off",
    ):
        assert phrase in comment, phrase


def test_app_rw_reads_and_writes_all_three_tables_and_updates_two(db):
    user_id = _user(db)
    entry_id = str(uuid.uuid4())
    lookup_id = str(uuid.uuid4())
    with db.transaction():
        db.execute("SET LOCAL ROLE app_rw")
        _entry(db, entry_id=entry_id)
        draft_id = _draft(db)
        _result(db, lookup_id=lookup_id)
        db.execute(
            "UPDATE knowledge_drafts SET status = 'approved', reviewed_by = %s WHERE draft_id = %s",
            (user_id, draft_id),
        )
        db.execute(
            "UPDATE knowledge_entries SET status = 'retired' WHERE entry_id = %s", (entry_id,)
        )
        counts = [db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] for table in TABLES]
    assert all(count >= 1 for count in counts)


# ── upgrade from 019 ────────────────────────────────────────────────────────────────────────


def test_020_applies_on_a_database_at_019_the_way_make_migrate_runs_it(tmp_path):
    """The live database is at 019: `make migrate` applies the 020 FILE to it, never `schema.sql`.
    The shared fixture builds from `schema.sql`, so on its own it would not notice a 020 that
    differs from what `schema.sql` holds. A database is built from a copy of `docs/Schema` without
    020 (so at 019, through the same `migrate.sh`), then the real `migrate.sh` applies the real
    file, and a third run shows `schema_migrations` refuses a second apply."""
    session = _session_dsn()
    if shutil.which("psql") is None:
        pytest.skip("psql is not installed")
    at_019 = _schema_without_020(tmp_path)
    stems = {path.stem for path in SCHEMA_DIR.glob(MIGRATION_FILES)}
    total = len(stems)
    before = len(list(at_019.glob(MIGRATION_FILES)))
    assert before == len({stem for stem in stems if int(stem[:3]) < 20})
    assert 0 < before < total

    dbname = f"{conftest._dbname(session)}_020up_test"
    dsn = _with_db(session, dbname)
    admin = psycopg.connect(conftest._maintenance_dsn(session), autocommit=True)
    try:
        admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(dbname)))
        runs = [_migrate(dsn, mig_dir) for mig_dir in (at_019, SCHEMA_DIR, SCHEMA_DIR)]
        assert "020_learned_knowledge" not in runs[0]
        assert f"migrate: 0 applied, {before} already present" in runs[0]
        assert "migrate: applying 020_learned_knowledge" in runs[1]
        assert f"migrate: {total - before} applied, {before} already present" in runs[1]
        assert f"migrate: 0 applied, {total} already present" in runs[2]
        assert "migrate: applying" not in runs[2]
        with psycopg.connect(dsn) as conn:
            recorded = {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}
            assert recorded == stems
            conn.execute(
                "INSERT INTO knowledge_drafts (source_kind, source_id, conclusion) "
                "VALUES ('alert', 'gl-up', 'closed_fp')"
            )
            conn.execute(
                "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt, "
                "user_message, role) VALUES (gen_random_uuid(), 'knowledge_draft', 'case', 'c', "
                "'s', 'u', 'drafter')"
            )
            conn.execute(
                "INSERT INTO jobs (job_type, subject_id) VALUES ('rag_lookup', 'alert:gl-up')"
            )
            conn.execute(
                "INSERT INTO audit_events (event_type, subject_id, actor_role) "
                "VALUES ('rag.integrity_failed', 'gl-up', 'system')"
            )
            names = _quoted(
                conn.execute(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conname = 'ck_audit_event_type'"
                ).fetchone()[0]
            )
            assert names == EVENTS_BEFORE_020 + EVENTS_IN_020
            conn.rollback()
    finally:
        admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))
        admin.close()


def test_app_rw_holds_the_three_tables_when_020_is_applied_by_another_role(tmp_path):
    """Why 020 grants the rights itself (019's lesson, P11-T01 review finding 5): 017's
    `ALTER DEFAULT PRIVILEGES` binds only the role that ran 017, so a table created by any other
    role would leave `app_rw` with nothing, and the lookup and the draft job would die on
    `permission denied`.

    The scenario, on a scratch database: 001-019 are applied as a scratch role (NOSUPERUSER, the
    database's owner; `PGOPTIONS=-c role=...`), so 017's default privileges name that role; 020
    is applied as the session role, a superuser, which owns the three tables and has no default
    ACL here. No DELETE and no TRUNCATE: nothing deletes a draft, an entry or a result."""
    session = _session_dsn()
    if shutil.which("psql") is None:
        pytest.skip("psql is not installed")
    try:
        admin = psycopg.connect(conftest._maintenance_dsn(session), autocommit=True)
    except psycopg.OperationalError:
        pytest.skip(f"TEST_DATABASE_URL unreachable: {conftest.redact_dsn(session)}")
    (superuser,) = admin.execute(
        "SELECT rolsuper FROM pg_roles WHERE rolname = current_user"
    ).fetchone()
    if not superuser:
        admin.close()
        pytest.skip("TEST_DATABASE_URL's role is not a superuser: the test creates a scratch role")

    at_019 = _schema_without_020(tmp_path)
    base = conftest._dbname(session)
    dbname = f"{base}_020own_test"
    owner = f"{base}_020own"  # roles are cluster-global: named from the session database's name
    dsn = _with_db(session, dbname)
    try:
        admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))
        admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(owner)))
        admin.execute(
            "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_rw') "
            "THEN CREATE ROLE app_rw NOLOGIN; END IF; END $$"
        )
        admin.execute(
            sql.SQL("CREATE ROLE {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOLOGIN").format(
                sql.Identifier(owner)
            )
        )
        admin.execute(
            sql.SQL("CREATE DATABASE {} OWNER {}").format(
                sql.Identifier(dbname), sql.Identifier(owner)
            )
        )
        _migrate(dsn, at_019, PGOPTIONS=f"-c role={owner}")
        assert "migrate: applying 020_learned_knowledge" in _migrate(dsn, SCHEMA_DIR)
        with psycopg.connect(dsn) as conn:
            (applier,) = conn.execute("SELECT current_user").fetchone()
            owners = {
                row[0]
                for row in conn.execute(
                    "SELECT tableowner FROM pg_tables WHERE tablename = ANY(%s)",
                    (list(TABLES),),
                )
            }
            default_acl_roles = {
                row[0]
                for row in conn.execute("SELECT pg_get_userbyid(defaclrole) FROM pg_default_acl")
            }
            # The premise, so the test cannot pass through default privileges.
            assert (owners, owner in default_acl_roles, applier in default_acl_roles) == (
                {applier},
                True,
                False,
            )
            for table in TABLES:
                held = {
                    privilege: conn.execute(
                        "SELECT has_table_privilege('app_rw', %s, %s)", (table, privilege)
                    ).fetchone()[0]
                    for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")
                }
                assert held == {
                    "SELECT": True,
                    "INSERT": True,
                    "UPDATE": table != APPEND_ONLY,
                    "DELETE": False,
                    "TRUNCATE": False,
                }, table
    finally:
        try:
            admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))
        finally:
            try:
                admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(owner)))
            finally:
                admin.close()
