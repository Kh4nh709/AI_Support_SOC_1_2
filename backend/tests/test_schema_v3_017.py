"""Migration 017 — append-only enforcement and the `app_rw` privilege list (§6.1, DEC-023).

Every test runs against the database the `db` fixture migrates, so each one asserts
on the migration as `scripts/migrate.sh` actually applies it, not on the text of the
file.

Two enforcement layers are on trial, and they answer in a fixed order:

* **Layer 1 — privileges.** `REVOKE UPDATE, DELETE, TRUNCATE … FROM app_rw, PUBLIC`,
  then a column-level `GRANT UPDATE (processed_at, outcome, error) ON intake`. This
  layer binds the application role and answers *before* any trigger runs, so an
  `app_rw` attempt on a revoked verb fails with `permission denied` (SQLSTATE 42501)
  and never reaches layer 2.
* **Layer 2 — triggers.** `raise_immutable()` and `intake_pin_receipt()`, which bind
  the owner as well, whom the REVOKE does not constrain. These raise SQLSTATE P0001.

The invariants under test: **G2** (audit events are never rewritten), **G9**
(`intake.raw_text` holds the received bytes unchanged — here defended at the
privilege layer), **G11** (an `llm_runs` row is never rewritten after its
`gate_result`) and **G12** (the one completion write on `intake` is still possible).

Every expected failure aborts the current transaction, so each attempt is wrapped in
a SAVEPOINT (design note 7). `SET ROLE app_rw` is transactional and is undone by the
rollback to the savepoint; `_run` resets it explicitly anyway so a *successful*
attempt cannot leak the role into the next statement.
"""

import psycopg
import pytest

APP_ROLE = "app_rw"

INSERT_AUDIT = (
    "INSERT INTO audit_events (event_type, subject_id, actor_role) "
    "VALUES ('alert.received', %s, 'system')"
)
INSERT_LLM_RUN = (
    "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt, "
    "user_message) VALUES (gen_random_uuid(), 'triage', 'alert', %s, 's', 'u')"
)
# `raw_payload` is never named: it is GENERATED ALWAYS and an INSERT that names it is
# rejected with `cannot insert a non-DEFAULT value into column "raw_payload"`.
INSERT_INTAKE = (
    "INSERT INTO intake (manager_id, source_alert_id, raw_text, via) "
    "VALUES ('IA1803', %s, '{\"b\":1,\"a\":2}', 'pull')"
)

SEEDS = {
    "audit_events": INSERT_AUDIT,
    "llm_runs": INSERT_LLM_RUN,
    "intake": INSERT_INTAKE,
}

APPEND_ONLY_TABLES = ["audit_events", "llm_runs", "intake"]

# The UPDATE that layer 1 must refuse on each table. On `intake` it has to name a
# column outside the three-column completion grant, or the grant would answer first.
REVOKED_UPDATE = {
    "audit_events": "UPDATE audit_events SET subject_id = 'z'",
    "llm_runs": "UPDATE llm_runs SET subject_id = 'z'",
    "intake": "UPDATE intake SET via = 'webhook'",
}

EXPECTED_TRIGGERS = [
    "trg_audit_events_immutable",
    "trg_audit_events_no_truncate",
    "trg_intake_immutable",
    "trg_intake_no_truncate",
    "trg_intake_pin_receipt",
    "trg_llm_runs_immutable",
    "trg_llm_runs_no_truncate",
]

PERMISSION_DENIED = "42501"
RAISE_EXCEPTION = "P0001"


def _run(db, sql, params=None, role=None):
    """Run `sql` (as `role`, if given) inside a savepoint; return the error or None.

    The savepoint is what keeps the caller's connection usable after a rejection —
    several tests assert a rejection and then an acceptance on the same connection.
    """
    with db.cursor() as cur:
        cur.execute("SAVEPOINT attempt")
        try:
            if role is not None:
                cur.execute(f"SET ROLE {role}")
            cur.execute(sql, params)
        except psycopg.Error as exc:
            cur.execute("ROLLBACK TO SAVEPOINT attempt")
            return exc
        cur.execute("RESET ROLE")
        return None


def rejects(db, sql, params=None, role=None):
    """Expect `sql` to be rejected; return the psycopg error it raised."""
    error = _run(db, sql, params, role)
    if error is None:
        raise AssertionError(f"statement was accepted but should have been rejected: {sql}")
    return error


def accepts(db, sql, params=None, role=None):
    """Expect `sql` to be accepted; fail with the error it raised otherwise."""
    error = _run(db, sql, params, role)
    if error is not None:
        raise AssertionError(
            f"statement was rejected but should have been accepted: {sql}\n{error}"
        )


def seed(db, table, subject_id):
    """Insert one row into `table` as the owner, so a later attempt has something to hit."""
    accepts(db, SEEDS[table], (subject_id,))


def seed_as_app_rw(db, table, subject_id):
    """Seed as `app_rw`, which is what makes the denial tests discriminating.

    Before 017 the role holds no privilege at all on these tables, so a test that
    only asserted `permission denied` would pass against an unmigrated database and
    prove nothing (DEC-025). Seeding through the same role first pins the claim down
    to the verb: `app_rw` reaches this table and may append to it — what it may not do
    is rewrite it.
    """
    accepts(db, SEEDS[table], (subject_id,), role=APP_ROLE)


def count(db, table):
    with db.cursor() as cur:
        cur.execute(f"SELECT count(*) FROM {table}")
        return cur.fetchone()[0]


# --------------------------------------------------------------------------------------
# The migration recorded itself, and built what §6.1 names
# --------------------------------------------------------------------------------------


@pytest.mark.db
def test_migration_017_records_itself_in_schema_migrations(db):
    with db.cursor() as cur:
        cur.execute("SELECT 1 FROM schema_migrations WHERE version = '017_append_only_and_roles'")
        assert cur.fetchone() is not None, "017 did not record itself; migrate.sh will re-apply it"


@pytest.mark.db
def test_the_seven_append_only_triggers_exist(db):
    with db.cursor() as cur:
        cur.execute("SELECT tgname FROM pg_trigger WHERE NOT tgisinternal ORDER BY 1")
        assert [r[0] for r in cur.fetchall()] == EXPECTED_TRIGGERS


@pytest.mark.db
def test_both_trigger_functions_exist(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT proname FROM pg_proc "
            "WHERE proname IN ('raise_immutable', 'intake_pin_receipt') ORDER BY 1"
        )
        assert [r[0] for r in cur.fetchall()] == ["intake_pin_receipt", "raise_immutable"]


@pytest.mark.db
def test_the_truncate_guard_is_a_statement_trigger_because_row_triggers_miss_truncate(db):
    """DEC-016's finding: a FOR EACH ROW trigger does not fire on TRUNCATE."""
    with db.cursor() as cur:
        cur.execute(
            "SELECT tgname FROM pg_trigger "
            "WHERE NOT tgisinternal AND tgname LIKE '%%no_truncate' AND (tgtype & 1) = 0 "
            "ORDER BY 1"
        )
        assert [r[0] for r in cur.fetchall()] == [
            "trg_audit_events_no_truncate",
            "trg_intake_no_truncate",
            "trg_llm_runs_no_truncate",
        ]


# --------------------------------------------------------------------------------------
# Layer 1 — the privilege list granted to app_rw
# --------------------------------------------------------------------------------------


@pytest.mark.db
def test_app_rw_holds_an_explicit_privilege_list_that_never_includes_truncate(db):
    """`GRANT ALL PRIVILEGES` would carry TRUNCATE; the explicit list never does."""
    with db.cursor() as cur:
        cur.execute(
            "SELECT table_name, string_agg(privilege_type, ' ' ORDER BY privilege_type) "
            "FROM information_schema.role_table_grants "
            "WHERE grantee = 'app_rw' AND table_name IN "
            "  ('audit_events', 'llm_runs', 'intake', 'alerts', 'schema_migrations') "
            "GROUP BY 1 ORDER BY 1"
        )
        assert cur.fetchall() == [
            ("alerts", "DELETE INSERT SELECT UPDATE"),
            ("audit_events", "INSERT SELECT"),
            ("intake", "INSERT SELECT"),
            ("llm_runs", "INSERT SELECT"),
            ("schema_migrations", "SELECT"),
        ]


@pytest.mark.db
def test_the_intake_column_grant_is_exactly_the_three_receipt_columns(db):
    """G12's completion write, and nothing wider — the table-level REVOKE came first."""
    with db.cursor() as cur:
        cur.execute(
            "SELECT string_agg(column_name, ' ' ORDER BY column_name) "
            "FROM information_schema.column_privileges "
            "WHERE grantee = 'app_rw' AND table_name = 'intake' AND privilege_type = 'UPDATE'"
        )
        assert cur.fetchone()[0] == "error outcome processed_at"


@pytest.mark.db
def test_app_rw_cannot_write_the_migrators_bookkeeping_table(db):
    accepts(db, "SELECT count(*) FROM schema_migrations", role=APP_ROLE)
    error = rejects(
        db,
        "INSERT INTO schema_migrations (version) VALUES ('999_forged')",
        role=APP_ROLE,
    )
    assert error.sqlstate == PERMISSION_DENIED
    assert "permission denied for table schema_migrations" in str(error)


@pytest.mark.db
def test_default_privileges_reach_a_table_created_after_017(db):
    """P2's tables need no grants migration of their own (design note 5)."""
    accepts(db, "CREATE TABLE p1t06_probe (id int)")
    with db.cursor() as cur:
        cur.execute(
            "SELECT has_table_privilege('app_rw', 'p1t06_probe', 'INSERT'), "
            "       has_table_privilege('app_rw', 'p1t06_probe', 'TRUNCATE')"
        )
        assert cur.fetchone() == (True, False)


@pytest.mark.parametrize("table", APPEND_ONLY_TABLES)
@pytest.mark.db
def test_app_rw_may_still_insert_into(db, table):
    """Append-only means append: the REVOKE took UPDATE, DELETE and TRUNCATE, not INSERT."""
    before = count(db, table)
    accepts(db, SEEDS[table], ("9.1",), role=APP_ROLE)
    assert count(db, table) == before + 1


@pytest.mark.parametrize("table", APPEND_ONLY_TABLES)
@pytest.mark.db
def test_app_rw_may_still_select_from(db, table):
    seed(db, table, "9.2")
    accepts(db, f"SELECT count(*) FROM {table}", role=APP_ROLE)


@pytest.mark.parametrize("table", APPEND_ONLY_TABLES)
@pytest.mark.db
def test_app_rw_cannot_update(db, table):
    seed_as_app_rw(db, table, "3.1")
    error = rejects(db, REVOKED_UPDATE[table], role=APP_ROLE)
    assert error.sqlstate == PERMISSION_DENIED
    assert f"permission denied for table {table}" in str(error)
    assert count(db, table) == 1


@pytest.mark.parametrize("table", APPEND_ONLY_TABLES)
@pytest.mark.db
def test_app_rw_cannot_delete(db, table):
    seed_as_app_rw(db, table, "3.2")
    error = rejects(db, f"DELETE FROM {table}", role=APP_ROLE)
    assert error.sqlstate == PERMISSION_DENIED
    assert f"permission denied for table {table}" in str(error)
    assert count(db, table) == 1


@pytest.mark.parametrize("table", APPEND_ONLY_TABLES)
@pytest.mark.db
def test_app_rw_cannot_truncate(db, table):
    seed_as_app_rw(db, table, "3.3")
    error = rejects(db, f"TRUNCATE {table}", role=APP_ROLE)
    assert error.sqlstate == PERMISSION_DENIED
    assert f"permission denied for table {table}" in str(error)
    assert count(db, table) == 1


@pytest.mark.db
def test_app_rw_cannot_rewrite_intake_raw_text(db):
    """G9 at the privilege layer: the column grant does not cover the received bytes."""
    seed_as_app_rw(db, "intake", "3.4")
    error = rejects(db, "UPDATE intake SET raw_text = '{}'", role=APP_ROLE)
    assert error.sqlstate == PERMISSION_DENIED
    assert "permission denied for table intake" in str(error)
    with db.cursor() as cur:
        cur.execute("SELECT raw_text FROM intake WHERE source_alert_id = '3.4'")
        assert cur.fetchone()[0] == '{"b":1,"a":2}'


# --------------------------------------------------------------------------------------
# G12 — the one completion write app_rw is allowed, and the pin that follows it
# --------------------------------------------------------------------------------------


@pytest.mark.db
def test_app_rw_may_write_the_g12_completion_receipt(db):
    seed(db, "intake", "5.1")
    accepts(
        db,
        "UPDATE intake SET processed_at = now(), outcome = 'alert' WHERE source_alert_id = '5.1'",
        role=APP_ROLE,
    )
    with db.cursor() as cur:
        cur.execute(
            "SELECT processed_at IS NOT NULL, outcome FROM intake WHERE source_alert_id = '5.1'"
        )
        assert cur.fetchone() == (True, "alert")


@pytest.mark.db
def test_a_second_receipt_write_is_pinned_once_the_column_is_set(db):
    seed(db, "intake", "5.2")
    accepts(
        db,
        "UPDATE intake SET processed_at = now(), outcome = 'alert' WHERE source_alert_id = '5.2'",
        role=APP_ROLE,
    )
    error = rejects(
        db,
        "UPDATE intake SET outcome = 'duplicate' WHERE source_alert_id = '5.2'",
        role=APP_ROLE,
    )
    assert error.sqlstate == RAISE_EXCEPTION
    assert "receipt columns are pinned once set" in str(error)
    with db.cursor() as cur:
        cur.execute("SELECT outcome FROM intake WHERE source_alert_id = '5.2'")
        assert cur.fetchone()[0] == "alert"


@pytest.mark.db
def test_a_still_null_receipt_column_may_be_filled_after_an_error_was_recorded(db):
    """A retried job may still complete: `error` is set, `processed_at`/`outcome` are not."""
    seed(db, "intake", "5.3")
    accepts(
        db,
        "UPDATE intake SET error = 'boom' WHERE source_alert_id = '5.3'",
        role=APP_ROLE,
    )
    accepts(
        db,
        "UPDATE intake SET processed_at = now(), outcome = 'alert' WHERE source_alert_id = '5.3'",
        role=APP_ROLE,
    )
    error = rejects(
        db,
        "UPDATE intake SET error = 'boom again' WHERE source_alert_id = '5.3'",
        role=APP_ROLE,
    )
    assert error.sqlstate == RAISE_EXCEPTION
    assert "receipt columns are pinned once set" in str(error)


# --------------------------------------------------------------------------------------
# Layer 2 — the triggers, which bind the owner the REVOKE does not constrain
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("table", ["audit_events", "llm_runs"])
@pytest.mark.db
def test_the_row_trigger_stops_the_owner_updating(db, table):
    seed(db, table, "7.1")
    error = rejects(db, f"UPDATE {table} SET subject_id = 'z'")
    assert error.sqlstate == RAISE_EXCEPTION
    assert f"append-only table: {table} is immutable" in str(error)
    assert count(db, table) == 1


@pytest.mark.parametrize("table", APPEND_ONLY_TABLES)
@pytest.mark.db
def test_the_row_trigger_stops_the_owner_deleting(db, table):
    seed(db, table, "7.2")
    error = rejects(db, f"DELETE FROM {table}")
    assert error.sqlstate == RAISE_EXCEPTION
    assert f"append-only table: {table} is immutable" in str(error)
    assert count(db, table) == 1


@pytest.mark.parametrize("table", APPEND_ONLY_TABLES)
@pytest.mark.db
def test_the_statement_trigger_stops_the_owner_truncating(db, table):
    seed(db, table, "8.1")
    error = rejects(db, f"TRUNCATE {table}")
    assert error.sqlstate == RAISE_EXCEPTION
    assert f"append-only table: {table} is immutable" in str(error)
    assert count(db, table) == 1, "TRUNCATE wiped the table the trigger was meant to protect"


@pytest.mark.db
def test_the_pin_trigger_stops_the_owner_rewriting_an_intake_payload_column(db):
    seed(db, "intake", "7.3")
    error = rejects(db, "UPDATE intake SET via = 'webhook' WHERE source_alert_id = '7.3'")
    assert error.sqlstate == RAISE_EXCEPTION
    assert "payload columns are immutable" in str(error)
    with db.cursor() as cur:
        cur.execute("SELECT via FROM intake WHERE source_alert_id = '7.3'")
        assert cur.fetchone()[0] == "pull"


@pytest.mark.db
def test_the_pin_trigger_stops_the_owner_rewriting_the_received_bytes(db):
    """G9 against the owner, whom the privilege layer does not constrain."""
    seed(db, "intake", "7.4")
    error = rejects(db, "UPDATE intake SET raw_text = '{}' WHERE source_alert_id = '7.4'")
    assert error.sqlstate == RAISE_EXCEPTION
    assert "payload columns are immutable" in str(error)
    with db.cursor() as cur:
        cur.execute("SELECT raw_text FROM intake WHERE source_alert_id = '7.4'")
        assert cur.fetchone()[0] == '{"b":1,"a":2}'


@pytest.mark.db
def test_the_owner_may_still_write_the_completion_receipt_once(db):
    """Layer 2 pins the receipt for everyone, but does not close G12's write.

    The second write moves the timestamp deliberately. `now()` is the *transaction*
    timestamp, so writing `now()` twice on this connection would set the identical
    value and the pin would — correctly — not fire; see the test below.
    """
    seed(db, "intake", "7.5")
    accepts(db, "UPDATE intake SET processed_at = now() WHERE source_alert_id = '7.5'")
    error = rejects(
        db,
        "UPDATE intake SET processed_at = now() + interval '1 hour' "
        "WHERE source_alert_id = '7.5'",
    )
    assert error.sqlstate == RAISE_EXCEPTION
    assert "receipt columns are pinned once set" in str(error)


@pytest.mark.db
def test_rewriting_a_receipt_column_with_the_value_it_already_holds_is_not_a_change(db):
    """`IS DISTINCT FROM` pins the value, not the statement — found while writing these
    tests, and it is the behaviour P2 wants: a job retried after an ambiguous failure can
    re-assert the receipt it already wrote without tripping append-only. Only a receipt
    that would actually *differ* is refused."""
    seed(db, "intake", "7.6")
    accepts(
        db,
        "UPDATE intake SET processed_at = now(), outcome = 'alert' WHERE source_alert_id = '7.6'",
        role=APP_ROLE,
    )
    accepts(
        db,
        "UPDATE intake SET processed_at = now(), outcome = 'alert' WHERE source_alert_id = '7.6'",
        role=APP_ROLE,
    )
    with db.cursor() as cur:
        cur.execute("SELECT outcome FROM intake WHERE source_alert_id = '7.6'")
        assert cur.fetchone()[0] == "alert"
