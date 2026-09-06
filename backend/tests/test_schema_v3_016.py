"""Migration 016 — the v3 columns and CHECK sets on `alerts`, `jobs`, `llm_runs`,
`users` and `audit_events` (context pack §6.1).

Every test runs against the database the `db` fixture migrates, so each one
asserts on the migration as `scripts/migrate.sh` actually applies it, not on the
text of the file.

Three things §6.1 says that the v1 database contradicted, all measured before
this file was written and all settled the same way — the database wins on what
exists, §6.1 wins on what the set should be:

* `alerts.source` was already there (`002_alerts.sql`, `NOT NULL DEFAULT
  'wazuh'`) with no CHECK, so 016 adds `ck_alerts_source` and no column.
* `alerts.sampled_for_control` never existed — it is a jsonb payload key, not a
  column (DEC-022) — so the `DROP COLUMN IF EXISTS` that states the contract is
  a no-op. `test_alerts_has_no_sampled_for_control_column` is the assertion that
  the end state is what §6.1 asked for, whichever way it got there.
* `ck_jobs_job_type` was `('enrich','triage')`. §6.1's six values win (§0
  precedence), so `pull` becomes legal and `enrich` stops being legal — the
  exact inversion of the v1 database.
"""

import uuid

import psycopg
import pytest

HASH64 = "0" * 64

# §6.1, in the order 008 froze them: 21 v1 names, then the six v3 additions.
EVENT_TYPES_V1 = [
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
]
EVENT_TYPES_V3 = [
    "autoclose.reviewed",
    "rule.suspected_wrong",
    "llm.gate_forced",
    "llm.builder_violation",
    "health.alarm",
    "label.created",
]
EVENT_TYPES = EVENT_TYPES_V1 + EVENT_TYPES_V3

JOB_TYPES = ["pipeline", "triage", "investigate", "digest", "health", "pull"]
ALERT_SOURCES = ["wazuh", "lab", "replay"]
LLM_ROLES = ["proposer", "verifier", "investigator"]

LLM_RUNS_V3_COLUMNS = [
    "cost_usd",
    "evidence_check",
    "gate_result",
    "model_id",
    "prompt_version",
    "role",
    "stopped_by",
    "verifier_result",
]

INSERT_AUDIT = (
    "INSERT INTO audit_events (event_type, subject_id, actor_role) VALUES (%s, 'a-1', 'system')"
)
INSERT_JOB = "INSERT INTO jobs (job_type, subject_id) VALUES (%s, %s)"


def rejects(db, sql, params=None):
    """Run `sql` expecting the database to reject it; return the psycopg error.

    The statement is wrapped in a savepoint so the caller's connection stays
    usable afterwards — several tests assert a rejection and then an acceptance.
    """
    with db.cursor() as cur:
        cur.execute("SAVEPOINT expect_rejection")
        try:
            cur.execute(sql, params)
        except psycopg.Error as exc:
            cur.execute("ROLLBACK TO SAVEPOINT expect_rejection")
            return exc
    raise AssertionError(f"statement was accepted but should have been rejected: {sql}")


def insert_alert(cur, alert_id, **overrides):
    """INSERT one row into `alerts` filling every NOT NULL column v1 requires."""
    row = {
        "alert_id": alert_id,
        "rule_id": "40112",
        "rule_level": 12,
        "severity": "critical",
        "description": "x",
        "agent_name": "a1",
        "alert_time": "2026-09-06T00:00:00+00:00",
        "category": "ssh_brute_force",
        "resolved_by": "mitre",
        "mapping_version": "v1",
        "event_bucket_hash": HASH64,
        "raw_payload": "{}",
    }
    row.update(overrides)
    columns = ", ".join(row)
    placeholders = ", ".join(["%s"] * len(row))
    cur.execute(f"INSERT INTO alerts ({columns}) VALUES ({placeholders})", list(row.values()))


def insert_llm_run(cur, **overrides):
    """INSERT one ① run into `llm_runs`; `pipeline`/`subject_type` must stay paired."""
    row = {
        "run_id": str(uuid.uuid4()),
        "pipeline": "triage",
        "subject_type": "alert",
        "subject_id": "a-1",
        "system_prompt": "s",
        "user_message": "u",
    }
    row.update(overrides)
    columns = ", ".join(row)
    placeholders = ", ".join(["%s"] * len(row))
    cur.execute(f"INSERT INTO llm_runs ({columns}) VALUES ({placeholders})", list(row.values()))


def columns_present(db, table, names):
    with db.cursor() as cur:
        cur.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = %s AND column_name = ANY(%s) ORDER BY 1",
            (table, list(names)),
        )
        return [name for (name,) in cur.fetchall()]


@pytest.mark.db
def test_migration_016_records_itself_in_schema_migrations(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM schema_migrations "
            "WHERE version = '016_alter_alerts_jobs_llm_runs_users'"
        )
        (count,) = cur.fetchone()

    assert count == 1


# ── alerts ──────────────────────────────────────────────────────────────────


@pytest.mark.db
def test_alerts_gains_manager_id_origin_host_and_suggestion_visible(db):
    found = columns_present(db, "alerts", ["manager_id", "origin_host", "suggestion_visible"])

    assert found == ["manager_id", "origin_host", "suggestion_visible"]


@pytest.mark.db
def test_alerts_has_no_sampled_for_control_column(db):
    assert columns_present(db, "alerts", ["sampled_for_control"]) == []


@pytest.mark.db
def test_suggestion_visible_is_not_null_and_defaults_to_true(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT column_default, is_nullable FROM information_schema.columns "
            "WHERE table_name = 'alerts' AND column_name = 'suggestion_visible'"
        )
        default, nullable = cur.fetchone()

    assert (default, nullable) == ("true", "NO")


@pytest.mark.db
def test_manager_id_and_origin_host_stay_nullable(db):
    with db.cursor() as cur:
        insert_alert(cur, "a-nullable")
        cur.execute(
            "SELECT manager_id, origin_host, suggestion_visible FROM alerts WHERE alert_id = %s",
            ("a-nullable",),
        )
        row = cur.fetchone()

    assert row == (None, None, True)


@pytest.mark.db
def test_ck_alerts_source_admits_the_three_v3_sources(db):
    with db.cursor() as cur:
        for source in ALERT_SOURCES:
            insert_alert(cur, f"a-{source}", source=source)
        cur.execute("SELECT source FROM alerts ORDER BY source")
        stored = [value for (value,) in cur.fetchall()]

    assert stored == sorted(ALERT_SOURCES)


@pytest.mark.db
def test_ck_alerts_source_rejects_a_fourth_source(db):
    columns = "alert_id, rule_id, rule_level, severity, description, agent_name, alert_time, "
    columns += "category, resolved_by, mapping_version, event_bucket_hash, raw_payload, source"
    sql = (
        f"INSERT INTO alerts ({columns}) VALUES ('a-x', '40112', 12, 'critical', 'x', 'a1', "
        f"now(), 'ssh_brute_force', 'mitre', 'v1', '{HASH64}', '{{}}', 'siem')"
    )

    error = rejects(db, sql)

    assert "ck_alerts_source" in str(error)


# ── jobs ────────────────────────────────────────────────────────────────────


@pytest.mark.db
def test_ck_jobs_job_type_admits_the_six_v3_types(db):
    # One distinct subject_id per value: 012's partial unique index
    # ux_jobs_mot_job_song_moi_subject forbids two live jobs on the same pair,
    # and a duplicate-key failure would say nothing about the CHECK.
    with db.cursor() as cur:
        for job_type in JOB_TYPES:
            cur.execute(INSERT_JOB, (job_type, f"x-{job_type}"))
        cur.execute("SELECT count(*) FROM jobs")
        (count,) = cur.fetchone()

    assert count == len(JOB_TYPES)


@pytest.mark.db
def test_ck_jobs_job_type_rejects_enrich(db):
    error = rejects(db, INSERT_JOB, ("enrich", "x-enrich"))

    assert "ck_jobs_job_type" in str(error)


# ── llm_runs ────────────────────────────────────────────────────────────────


@pytest.mark.db
def test_llm_runs_gains_the_eight_v3_columns(db):
    found = columns_present(db, "llm_runs", LLM_RUNS_V3_COLUMNS)

    assert found == LLM_RUNS_V3_COLUMNS


@pytest.mark.db
def test_cost_usd_is_numeric_10_5(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT data_type, numeric_precision, numeric_scale "
            "FROM information_schema.columns "
            "WHERE table_name = 'llm_runs' AND column_name = 'cost_usd'"
        )
        row = cur.fetchone()

    assert row == ("numeric", 10, 5)


@pytest.mark.db
def test_cost_usd_stores_a_real_per_call_cost_rounded_to_five_places(db):
    # Measured: one trivial deepseek-v4-flash call costs about $0.0000287. The
    # contract's scale keeps $0.00003 of it, so P3 must sum tokens, not costs,
    # when precision matters.
    with db.cursor() as cur:
        insert_llm_run(cur, run_id="11111111-1111-1111-1111-111111111111", cost_usd="0.0000287")
        cur.execute("SELECT cost_usd FROM llm_runs")
        (stored,) = cur.fetchone()

    assert str(stored) == "0.00003"


@pytest.mark.db
def test_ck_llm_runs_role_admits_null_and_the_three_roles(db):
    with db.cursor() as cur:
        insert_llm_run(cur)  # role omitted entirely — v1 rows carry no role
        for role in LLM_ROLES:
            insert_llm_run(cur, role=role)
        cur.execute("SELECT count(*) FROM llm_runs WHERE role IS NULL")
        (without_role,) = cur.fetchone()
        cur.execute("SELECT role FROM llm_runs WHERE role IS NOT NULL ORDER BY role")
        stored = [value for (value,) in cur.fetchall()]

    assert without_role == 1
    assert stored == sorted(LLM_ROLES)


@pytest.mark.db
def test_ck_llm_runs_role_rejects_a_fourth_role(db):
    sql = (
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt, "
        "user_message, role) VALUES (gen_random_uuid(), 'triage', 'alert', 'a-1', 's', 'u', "
        "'reviewer')"
    )

    error = rejects(db, sql)

    assert "ck_llm_runs_role" in str(error)


@pytest.mark.db
def test_stopped_by_is_free_text_with_no_closed_set(db):
    # §6.1 gives `stopped_by` no closed set, so 016 must not invent one.
    with db.cursor() as cur:
        insert_llm_run(cur, stopped_by="whatever-p3-decides-to-write-here")
        cur.execute(
            "SELECT count(*) FROM pg_constraint "
            "WHERE conrelid = 'llm_runs'::regclass "
            "AND pg_get_constraintdef(oid) LIKE '%stopped_by%'"
        )
        (constraints,) = cur.fetchone()

    assert constraints == 0


# ── users ───────────────────────────────────────────────────────────────────


@pytest.mark.db
def test_users_gains_the_three_v3_columns(db):
    found = columns_present(
        db, "users", ["sessions_invalid_before", "failed_logins", "locked_until"]
    )

    assert found == ["failed_logins", "locked_until", "sessions_invalid_before"]


@pytest.mark.db
def test_failed_logins_is_not_null_and_defaults_to_zero(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT column_default, is_nullable FROM information_schema.columns "
            "WHERE table_name = 'users' AND column_name = 'failed_logins'"
        )
        default, nullable = cur.fetchone()
        # `password_hash` is NOT NULL since 011_auth.sql; it is not this
        # migration's business, only the reason a bare INSERT needs it.
        cur.execute(
            "INSERT INTO users (user_id, username, display_name, role, password_hash) "
            "VALUES (gen_random_uuid(), 'u1', 'U One', 'tier1', 'x')"
        )
        cur.execute(
            "SELECT failed_logins, locked_until, sessions_invalid_before FROM users "
            "WHERE username = 'u1'"
        )
        row = cur.fetchone()

    assert (default, nullable) == ("0", "NO")
    assert row == (0, None, None)


# ── audit_events ────────────────────────────────────────────────────────────


@pytest.mark.db
def test_ck_audit_event_type_names_exactly_27_events(db):
    # The character class must be [a-z0-9_]: a plain [a-z] misses tier1.decided,
    # tier1.escalated and tier2.concluded and silently reports 18.
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM pg_constraint c, "
            "regexp_matches(pg_get_constraintdef(c.oid), '''[a-z0-9_]+\\.[a-z0-9_]+''', 'g') m "
            "WHERE c.conname = 'ck_audit_event_type'"
        )
        (count,) = cur.fetchone()

    assert count == 27


@pytest.mark.db
def test_all_27_event_types_are_accepted(db):
    with db.cursor() as cur:
        for event_type in EVENT_TYPES:
            cur.execute(INSERT_AUDIT, (event_type,))
        cur.execute("SELECT count(DISTINCT event_type) FROM audit_events")
        (stored,) = cur.fetchone()

    assert stored == 27


@pytest.mark.db
def test_the_six_new_event_types_are_the_six_named_in_section_6_1(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT array_agg(m[1] ORDER BY m[1]) FROM pg_constraint c, "
            "regexp_matches(pg_get_constraintdef(c.oid), '''([a-z0-9_]+\\.[a-z0-9_]+)''', 'g') m "
            "WHERE c.conname = 'ck_audit_event_type'"
        )
        (named,) = cur.fetchone()

    assert sorted(set(named) - set(EVENT_TYPES_V1)) == sorted(EVENT_TYPES_V3)
    assert sorted(named) == sorted(EVENT_TYPES)


@pytest.mark.db
def test_ck_audit_event_type_rejects_an_unknown_name(db):
    error = rejects(db, INSERT_AUDIT, ("nope.nope",))

    assert "ck_audit_event_type" in str(error)
