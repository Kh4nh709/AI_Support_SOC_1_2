"""Migration 014 — `intake`, `source_cursor`, `source_heartbeat` (context pack §6.1).

Every test here runs against the database the `db` fixture migrates, so each one
asserts on the migration as `scripts/migrate.sh` actually applies it, not on the
text of the file.

Two invariants are on trial:

* **G9** (as re-worded by DEC-023) — `intake.raw_text` is the received document
  unchanged; `raw_payload` is derived from it and may be normalised. The
  byte-compare test carries the control assertion that proves a plain `jsonb`
  column could not have passed it.
* **G12** — every row gets `processed_at` or `error`. That is a health check in
  P5, not a DB constraint, which is why `outcome` and `processed_at` are
  nullable here and `ck_intake_outcome` has to admit NULL.
"""

from pathlib import Path

import psycopg
import pytest

FIXTURES = Path(__file__).resolve().parent / "fixtures"

INTAKE_COLUMNS = [
    "error",
    "intake_id",
    "manager_id",
    "outcome",
    "processed_at",
    "raw_payload",
    "raw_text",
    "received_at",
    "sort_key",
    "source_alert_id",
    "via",
]

OUTCOMES = ["alert", "duplicate", "auto_closed", "heartbeat", "rejected"]

INSERT_INTAKE = (
    "INSERT INTO intake (manager_id, source_alert_id, raw_text, via) VALUES (%s, %s, %s, %s)"
)


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


@pytest.mark.db
def test_the_three_tables_of_section_6_1_exist(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT to_regclass('public.intake'), to_regclass('public.source_cursor'), "
            "to_regclass('public.source_heartbeat')"
        )
        found = cur.fetchone()

    assert found == ("intake", "source_cursor", "source_heartbeat")


@pytest.mark.db
def test_migration_014_records_itself_in_schema_migrations(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM schema_migrations WHERE version = '014_intake_cursor_heartbeat'"
        )
        (count,) = cur.fetchone()

    # Without the row the migration re-applies on every scripts/migrate.sh run.
    assert count == 1


@pytest.mark.db
def test_intake_id_is_an_identity_column_and_not_a_serial(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT is_identity, identity_generation, column_default "
            "FROM information_schema.columns "
            "WHERE table_name = 'intake' AND column_name = 'intake_id'"
        )
        is_identity, generation, default = cur.fetchone()

    # Both forms own a sequence named intake_intake_id_seq (measured), so the
    # sequence is not the tell. A bigserial reads is_identity 'NO' with a
    # nextval() default; as app_rw it then fails with "permission denied for
    # sequence" under the grants 017 issues, which no owner-run test would catch.
    assert (is_identity, generation, default) == ("YES", "BY DEFAULT", None)


@pytest.mark.db
def test_intake_has_exactly_the_eleven_columns_of_section_6_1(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'intake' ORDER BY 1"
        )
        columns = [row[0] for row in cur.fetchall()]

    assert columns == INTAKE_COLUMNS


@pytest.mark.db
def test_only_the_four_deliberately_nullable_intake_columns_are_nullable(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'intake' AND is_nullable = 'YES' ORDER BY 1"
        )
        nullable = [row[0] for row in cur.fetchall()]

    # `raw_payload` is NOT NULL even though it is generated.
    assert nullable == ["error", "outcome", "processed_at", "sort_key"]


@pytest.mark.db
def test_a_double_pull_of_one_alert_violates_uq_intake_manager_source(db):
    with db.cursor() as cur:
        cur.execute(INSERT_INTAKE, ("IA1803", "1.1", "{}", "pull"))

    exc = rejects(db, INSERT_INTAKE, ("IA1803", "1.1", "{}", "pull"))

    assert exc.diag.constraint_name == "uq_intake_manager_source"


@pytest.mark.db
def test_the_same_source_alert_id_under_another_manager_is_accepted(db):
    with db.cursor() as cur:
        cur.execute(INSERT_INTAKE, ("IA1803", "1.1", "{}", "pull"))
        cur.execute(INSERT_INTAKE, ("IA9999", "1.1", "{}", "pull"))
        cur.execute("SELECT count(*) FROM intake WHERE source_alert_id = '1.1'")
        (count,) = cur.fetchone()

    # The UNIQUE is on the pair: `source_alert_id` alone is not unique across managers.
    assert count == 2


@pytest.mark.db
@pytest.mark.parametrize("via", ["ftp", "PULL", "", "pull "])
def test_ck_intake_via_rejects_a_value_outside_the_closed_set(db, via):
    exc = rejects(db, INSERT_INTAKE, ("IA1803", f"via-{via!r}", "{}", via))

    assert exc.diag.constraint_name == "ck_intake_via"


@pytest.mark.db
@pytest.mark.parametrize("via", ["pull", "webhook"])
def test_ck_intake_via_accepts_both_intake_paths(db, via):
    with db.cursor() as cur:
        cur.execute(INSERT_INTAKE, ("IA1803", f"via-{via}", "{}", via))
        cur.execute("SELECT via FROM intake WHERE source_alert_id = %s", (f"via-{via}",))
        (stored,) = cur.fetchone()

    assert stored == via


@pytest.mark.db
def test_ck_intake_outcome_rejects_a_value_outside_the_closed_set(db):
    with db.cursor() as cur:
        cur.execute(INSERT_INTAKE, ("IA1803", "1.1", "{}", "pull"))

    exc = rejects(db, "UPDATE intake SET outcome = 'nonsense' WHERE source_alert_id = '1.1'")

    assert exc.diag.constraint_name == "ck_intake_outcome"


@pytest.mark.db
@pytest.mark.parametrize("outcome", OUTCOMES)
def test_ck_intake_outcome_accepts_each_member_of_the_closed_set(db, outcome):
    with db.cursor() as cur:
        cur.execute(INSERT_INTAKE, ("IA1803", "1.1", "{}", "pull"))
        cur.execute(
            "UPDATE intake SET outcome = %s, processed_at = now() WHERE source_alert_id = '1.1'",
            (outcome,),
        )
        assert cur.rowcount == 1


@pytest.mark.db
def test_a_freshly_read_row_is_accepted_with_no_outcome_and_no_receipt(db):
    with db.cursor() as cur:
        cur.execute(INSERT_INTAKE, ("IA1803", "1.1", "{}", "pull"))
        cur.execute(
            "SELECT outcome, processed_at, error, received_at <= now() "
            "FROM intake WHERE source_alert_id = '1.1'"
        )
        outcome, processed_at, error, received = cur.fetchone()

    # G12 forces a value within 60 s and is a health check in P5, not a constraint:
    # a row is inserted the moment it is read and only later resolved.
    assert (outcome, processed_at, error) == (None, None, None)
    assert received is True


@pytest.mark.db
def test_intake_carries_no_foreign_key(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM pg_constraint WHERE conrelid = 'intake'::regclass "
            "AND contype = 'f'"
        )
        (foreign_keys,) = cur.fetchone()
        cur.execute(
            "SELECT count(*) FROM pg_constraint WHERE confrelid = 'intake'::regclass "
            "AND contype = 'f'"
        )
        (referencing,) = cur.fetchone()

    # §6.1 gives `alerts` no `intake_id` and `intake` no `alert_id`; the link is
    # carried by jobs('pipeline', intake_id). An FK either way would extend §6.1.
    assert (foreign_keys, referencing) == (0, 0)


@pytest.mark.db
def test_raw_payload_is_generated_always_from_raw_text(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT is_generated, generation_expression FROM information_schema.columns "
            "WHERE table_name = 'intake' AND column_name = 'raw_payload'"
        )
        is_generated, expression = cur.fetchone()

    assert (is_generated, expression) == ("ALWAYS", "(raw_text)::jsonb")


@pytest.mark.db
def test_raw_payload_cannot_be_written_by_the_application(db):
    exc = rejects(
        db,
        "INSERT INTO intake (manager_id, source_alert_id, raw_text, via, raw_payload) "
        "VALUES ('IA1803', '1.1', '{}', 'pull', '{\"forged\": true}')",
    )

    assert "raw_payload" in str(exc)


@pytest.mark.db
@pytest.mark.parametrize("fixture", ["indexer_sample_rule5503.json", "archive_line_5503.json"])
def test_raw_text_round_trips_byte_identical(db, fixture):
    raw = (FIXTURES / fixture).read_bytes()
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO intake (manager_id, source_alert_id, raw_text, via) "
            "VALUES ('m', %s, %s, 'pull') RETURNING intake_id",
            (fixture, raw.decode("utf-8")),
        )
        (intake_id,) = cur.fetchone()
        cur.execute(
            "SELECT raw_text, raw_payload::text FROM intake WHERE intake_id = %s", (intake_id,)
        )
        raw_text, payload_text = cur.fetchone()

    assert raw_text.encode("utf-8") == raw  # the claim
    assert payload_text != raw_text  # the control: jsonb DID rewrite this fixture, so a
    # jsonb column could not have passed the line above


@pytest.mark.db
def test_jsonb_reorders_keys_and_collapses_whitespace_that_raw_text_keeps(db):
    received = '{"b":1,"a":2,  "c":3}'
    with db.cursor() as cur:
        cur.execute(INSERT_INTAKE, ("IA1803", "9.1", received, "pull"))
        cur.execute(
            "SELECT raw_text, raw_payload::text, raw_payload->>'a' "
            "FROM intake WHERE source_alert_id = '9.1'"
        )
        raw_text, payload_text, a = cur.fetchone()

    assert raw_text == received
    assert payload_text == '{"a": 2, "b": 1, "c": 3}'
    assert a == "2"


@pytest.mark.db
def test_raw_text_that_is_not_json_is_rejected(db):
    exc = rejects(db, INSERT_INTAKE, ("IA1803", "9.2", "not json", "pull"))

    # The generated column doubles as the well-formedness check.
    assert "invalid input syntax for type json" in str(exc)


@pytest.mark.db
def test_sort_key_is_nullable_and_does_not_identify_a_row(db):
    with db.cursor() as cur:
        # A live row carries the indexer's `sort`; a replay row has none until P2
        # computes epoch-millis of the alert's own timestamp (DEC-019).
        cur.execute(
            "INSERT INTO intake (manager_id, source_alert_id, raw_text, via, sort_key) "
            "VALUES ('IA1803', 'live', '{}', 'pull', 1788340536255)"
        )
        cur.execute(
            "INSERT INTO intake (manager_id, source_alert_id, raw_text, via, sort_key) "
            "VALUES ('IA1803', 'twin', '{}', 'pull', 1788340536255)"
        )
        cur.execute(INSERT_INTAKE, ("IA1803", "replay", "{}", "pull"))
        cur.execute("SELECT count(*) FROM intake WHERE sort_key IS NULL")
        (unsorted,) = cur.fetchone()
        cur.execute("SELECT count(*) FROM intake WHERE sort_key = 1788340536255")
        (repeated,) = cur.fetchone()

    assert (unsorted, repeated) == (1, 2)


@pytest.mark.db
@pytest.mark.parametrize("table", ["source_cursor", "source_heartbeat"])
def test_the_puller_state_tables_are_keyed_by_manager_id_alone(db, table):
    with db.cursor() as cur:
        cur.execute(
            "SELECT a.attname FROM pg_constraint c "
            "JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey) "
            "WHERE c.conrelid = %s::regclass AND c.contype = 'p'",
            (table,),
        )
        key = [row[0] for row in cur.fetchall()]

    assert key == ["manager_id"]


@pytest.mark.db
def test_source_cursor_holds_the_cursor_the_puller_resumes_from(db):
    with db.cursor() as cur:
        cur.execute("INSERT INTO source_cursor (manager_id) VALUES ('IA1803')")
        cur.execute(
            "SELECT last_sort, last_pull_at, last_error FROM source_cursor "
            "WHERE manager_id = 'IA1803'"
        )
        fresh = cur.fetchone()
        cur.execute(
            "UPDATE source_cursor SET last_sort = 1788340536255, last_pull_at = now() "
            "WHERE manager_id = 'IA1803' RETURNING last_sort"
        )
        (last_sort,) = cur.fetchone()

    # Every column but the key is nullable: a manager is registered before its
    # first pull has produced anything to resume from.
    assert fresh == (None, None, None)
    assert last_sort == 1788340536255


@pytest.mark.db
def test_source_heartbeat_separates_last_seen_from_last_alert(db):
    with db.cursor() as cur:
        cur.execute("INSERT INTO source_heartbeat (manager_id) VALUES ('IA1803')")
        cur.execute(
            "UPDATE source_heartbeat SET last_seen_at = now() WHERE manager_id = 'IA1803' "
            "RETURNING last_seen_at IS NOT NULL, last_alert_at IS NULL"
        )
        seen, no_alert_yet = cur.fetchone()

    # A manager that answers but sends nothing is seen without an alert: that gap
    # is what the heartbeat detection in P2 reads.
    assert (seen, no_alert_yet) == (True, True)
