"""Proves the two conftest.py helpers that can be verified without a live database,
and (␣@pytest.mark.db) proves the `db` fixture end-to-end where one is reachable.
This is the only file that may carry a `db`-marked test (see P0-T03 card, acceptance 3)."""

import pytest

from tests.conftest import REPO_ROOT, _maintenance_dsn, redact_dsn, require_test_dsn


def test_require_test_dsn_accepts_a_test_suffixed_database():
    dsn = "postgresql://soc:soc@127.0.0.1:55432/soc_test"

    assert require_test_dsn(dsn) == dsn


def test_require_test_dsn_rejects_a_non_test_database():
    with pytest.raises(pytest.fail.Exception, match="_test"):
        require_test_dsn("postgresql://soc:soc@h/soc")


def test_redact_dsn_leaves_no_password_in_output():
    dsn = "postgresql://appuser:s3cr3tpw@127.0.0.1:5432/soc_test"

    redacted = redact_dsn(dsn)

    assert "s3cr3tpw" not in redacted
    assert redacted == "postgresql://appuser:***@127.0.0.1:5432/soc_test"


def test_redact_dsn_is_a_no_op_when_there_is_no_password():
    dsn = "postgresql:///soc_test"

    assert redact_dsn(dsn) == dsn


def test_maintenance_dsn_preserves_the_socket_form_triple_slash():
    # urllib.parse.urlunsplit collapses '//' when netloc is empty and the scheme
    # isn't in its hardcoded uses_netloc registry ('postgresql' isn't), which would
    # otherwise turn the no-docker DSN postgresql:///soc_test into postgresql:/postgres.
    assert _maintenance_dsn("postgresql:///soc_test") == "postgresql:///postgres"


def test_maintenance_dsn_preserves_host_and_credentials():
    dsn = "postgresql://soc:soc@127.0.0.1:55432/soc_test"

    assert _maintenance_dsn(dsn) == "postgresql://soc:soc@127.0.0.1:55432/postgres"


@pytest.mark.db
def test_db_fixture_hands_out_a_connection_to_a_migrated_database(db):
    with db.cursor() as cur:
        cur.execute("SELECT count(*) FROM schema_migrations")
        (count,) = cur.fetchone()

    # One row per NNN_*.sql in docs/Schema — never a literal, so a new migration
    # does not turn this red (DEC-023).
    assert count == len(list((REPO_ROOT / "docs" / "Schema").glob("[0-9][0-9][0-9]_*.sql")))


@pytest.mark.db
def test_db_fixture_transaction_is_rolled_back_after_the_test_a(db):
    with db.cursor() as cur:
        cur.execute("CREATE TABLE test_p0_t03_probe (id int)")
        cur.execute("SELECT to_regclass('public.test_p0_t03_probe')")
        (created,) = cur.fetchone()

    assert created == "test_p0_t03_probe"


@pytest.mark.db
def test_db_fixture_transaction_is_rolled_back_after_the_test_b(db):
    with db.cursor() as cur:
        cur.execute("SELECT to_regclass('public.test_p0_t03_probe')")
        (leftover,) = cur.fetchone()

    assert leftover is None
