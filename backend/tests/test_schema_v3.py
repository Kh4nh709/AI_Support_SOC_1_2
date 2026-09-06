"""The phase-level schema test — context pack §6.1 walked as a checklist.

The five migration tasks each ship a `test_schema_v3_0NN.py` covering their own DDL in
detail (nullability, defaults, CHECK vocabularies, rejection behaviour). This file
repeats none of that. It asserts the **end state** P1 is supposed to leave behind, one
assertion per §6.1 clause, so a future contract change surfaces as a named failing test
rather than as a count mismatch nobody can localise.

Which migrations are on disk is **read from `docs/Schema/`, never hard-coded**. P1-T04's
`015_labels_reviews_notes_eval_health` left the P1 exit gate (DEC-029) and may be absent,
and P1-T06's `017_append_only_and_roles` merges independently of the other four. A clause
whose migration is not on disk is therefore *not collected at all* — never `xfail`, never
`skipif`. A skipped append-only test that later silently stays skipped is exactly how G2
and G11 stop being enforced.

Every test runs against the database the `db` fixture migrates, so each one asserts on the
schema as `scripts/migrate.sh` actually applies it, not on the text of any file.
"""

from pathlib import Path

import pytest

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "docs" / "Schema"

# The generated `schema.sql` is not a migration and does not match the NNN_ pattern.
MIGRATIONS_ON_DISK = sorted(p.stem for p in SCHEMA_DIR.glob("[0-9][0-9][0-9]_*.sql"))
P1_MIGRATIONS = sorted(p.stem for p in SCHEMA_DIR.glob("01[3-7]_*.sql"))

# §6.1 "v1 tables kept" — thirteen names, in the order §6.1 lists them.
V1_TABLES_KEPT = [
    "alerts",
    "cases",
    "case_alerts",
    "jobs",
    "audit_events",
    "llm_runs",
    "users",
    "autoclose_rules",
    "assets",
    "identities",
    "iocs",
    "rejected_alerts",
    "schema_migrations",
]

# §6.1 "v3 new" — eight tables, each mapped to the migration that creates it, so an
# absent migration removes its tables from the expected list instead of failing the run.
V3_NEW_TABLES = {
    "intake": "014_intake_cursor_heartbeat",
    "source_cursor": "014_intake_cursor_heartbeat",
    "source_heartbeat": "014_intake_cursor_heartbeat",
    "triage_labels": "015_labels_reviews_notes_eval_health",
    "autoclose_reviews": "015_labels_reviews_notes_eval_health",
    "case_notes": "015_labels_reviews_notes_eval_health",
    "eval_runs": "015_labels_reviews_notes_eval_health",
    "system_health": "015_labels_reviews_notes_eval_health",
}

EXPECTED_V3_NEW = [t for t, m in sorted(V3_NEW_TABLES.items()) if m in MIGRATIONS_ON_DISK]

# §6.1 "v3 altered" — every column the clause names, on the table it names it on.
# `alerts.source`, `jobs.job_type`, `audit_events.event_type` and `assets.criticality`
# are v1 columns whose CHECK vocabulary §6.1 changes; the vocabularies themselves are
# each sibling's business, this file only holds the columns to the checklist.
V3_ALTERED_COLUMNS = [
    ("alerts", "manager_id"),
    ("alerts", "origin_host"),
    ("alerts", "source"),
    ("alerts", "suggestion_visible"),
    ("jobs", "job_type"),
    ("llm_runs", "role"),
    ("llm_runs", "model_id"),
    ("llm_runs", "prompt_version"),
    ("llm_runs", "gate_result"),
    ("llm_runs", "verifier_result"),
    ("llm_runs", "evidence_check"),
    ("llm_runs", "cost_usd"),
    ("llm_runs", "stopped_by"),
    ("users", "sessions_invalid_before"),
    ("users", "failed_logins"),
    ("users", "locked_until"),
    ("assets", "source"),
    ("assets", "loaded_at"),
    ("assets", "active"),
    ("assets", "owner"),
    ("assets", "role"),
    ("assets", "criticality"),
    ("identities", "source"),
    ("identities", "loaded_at"),
    ("identities", "active"),
    ("iocs", "source"),
    ("iocs", "loaded_at"),
    ("iocs", "active"),
    ("audit_events", "event_type"),
]

# §6.1 "Append-only enforcement", layer 2 — migration 017's two functions and the seven
# triggers they back. Collected only when 017 is on disk.
APPEND_ONLY_FUNCTIONS = ["raise_immutable", "intake_pin_receipt"]

APPEND_ONLY_TRIGGERS = [
    ("audit_events", "trg_audit_events_immutable"),
    ("audit_events", "trg_audit_events_no_truncate"),
    ("llm_runs", "trg_llm_runs_immutable"),
    ("llm_runs", "trg_llm_runs_no_truncate"),
    ("intake", "trg_intake_pin_receipt"),
    ("intake", "trg_intake_immutable"),
    ("intake", "trg_intake_no_truncate"),
]


def relation(db, name):
    """The OID name of `public.<name>`, or None when no such relation exists."""
    with db.cursor() as cur:
        cur.execute("SELECT to_regclass(%s)", (f"public.{name}",))
        (found,) = cur.fetchone()
    return found


def columns_of(db, table):
    with db.cursor() as cur:
        cur.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = %s",
            (table,),
        )
        return {row[0] for row in cur.fetchall()}


# ── §6.1 · "v1 tables kept" ────────────────────────────────────────────────────────


@pytest.mark.db
@pytest.mark.parametrize("table", V1_TABLES_KEPT)
def test_v1_table_kept_by_v3_still_exists(db, table):
    assert relation(db, table) is not None


# ── §6.1 · "Dropped from v3", and the one drop inside "v3 altered" ─────────────────


@pytest.mark.db
def test_enrich_cache_is_gone(db):
    assert relation(db, "enrich_cache") is None


@pytest.mark.db
def test_prompt_versions_is_gone(db):
    # §6.1 lists it as dropped; it has never existed. Absent is absent either way.
    assert relation(db, "prompt_versions") is None


@pytest.mark.db
def test_alerts_carries_no_sampled_for_control(db):
    # DEC-022: the drop is a documented no-op — no such column has ever existed — but
    # §6.1 keeps the clause, so the checklist checks it.
    assert "sampled_for_control" not in columns_of(db, "alerts")


# ── §6.1 · "v3 new" ────────────────────────────────────────────────────────────────


@pytest.mark.db
@pytest.mark.parametrize("table", EXPECTED_V3_NEW)
def test_v3_new_table_exists(db, table):
    assert relation(db, table) is not None


@pytest.mark.db
def test_intake_raw_text_is_the_received_bytes_and_raw_payload_is_generated_from_it(db):
    # DEC-023 item 5: G9 cannot hold on jsonb, so `raw_text` holds the document and
    # `raw_payload` is derived. `is_generated` is what separates the two.
    with db.cursor() as cur:
        cur.execute(
            "SELECT column_name, data_type, is_generated FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = 'intake' "
            "AND column_name IN ('raw_text', 'raw_payload') ORDER BY 1",
            (),
        )
        found = cur.fetchall()

    assert found == [
        ("raw_payload", "jsonb", "ALWAYS"),
        ("raw_text", "text", "NEVER"),
    ]


# ── §6.1 · "v3 altered" ────────────────────────────────────────────────────────────


@pytest.mark.db
@pytest.mark.parametrize(
    "table,column", V3_ALTERED_COLUMNS, ids=[f"{t}.{c}" for t, c in V3_ALTERED_COLUMNS]
)
def test_v3_altered_column_exists(db, table, column):
    assert column in columns_of(db, table)


# ── The migration ledger ───────────────────────────────────────────────────────────


@pytest.mark.db
def test_schema_migrations_records_every_migration_on_disk(db):
    with db.cursor() as cur:
        cur.execute("SELECT version FROM schema_migrations")
        recorded = {row[0] for row in cur.fetchall()}

    assert sorted(recorded) == MIGRATIONS_ON_DISK


@pytest.mark.db
@pytest.mark.parametrize("version", P1_MIGRATIONS)
def test_p1_migration_is_recorded_exactly_once(db, version):
    with db.cursor() as cur:
        cur.execute("SELECT count(*) FROM schema_migrations WHERE version = %s", (version,))
        (count,) = cur.fetchone()

    # Without its row the migration re-applies on every scripts/migrate.sh run.
    assert count == 1


# ── §6.1 · "Append-only enforcement", layer 2 — migration 017 only ─────────────────
#
# Collected only when 017 is on disk. Omitted entirely otherwise, rather than xfailed
# or skipped: the P1 exit gate is not met while 017 is absent, and that is the report's
# job to say — not a silently green test's.

if "017_append_only_and_roles" in MIGRATIONS_ON_DISK:

    @pytest.mark.db
    @pytest.mark.parametrize("function", APPEND_ONLY_FUNCTIONS)
    def test_append_only_trigger_function_exists(db, function):
        with db.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'public' AND p.proname = %s",
                (function,),
            )
            (count,) = cur.fetchone()

        assert count == 1

    @pytest.mark.db
    @pytest.mark.parametrize(
        "table,trigger",
        APPEND_ONLY_TRIGGERS,
        ids=[f"{t}.{g}" for t, g in APPEND_ONLY_TRIGGERS],
    )
    def test_append_only_trigger_is_attached(db, table, trigger):
        with db.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM pg_trigger "
                "WHERE NOT tgisinternal AND tgrelid = %s::regclass AND tgname = %s",
                (f"public.{table}", trigger),
            )
            (count,) = cur.fetchone()

        assert count == 1
