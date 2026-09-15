"""P2-T08 — `enrichment.inventory.load()`.

Every test here needs a migrated database, so every one is `@pytest.mark.db`.
Files are written by each test into `tmp_path` in the `.example` shape and
passed via `paths=` — never `conf/*.yaml` (design note 6: the real files are
git-ignored and a worktree has none of them).

`load()` never commits or rolls back (design note 1: "one transaction the
caller owns"), and the `db` fixture rolls its connection back at teardown, so
every test below reads its own uncommitted writes and leaves no state behind —
no manual cleanup needed.
"""

from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent

import pytest
from app.enrichment.inventory import LoadReport, load
from app.infra.errors import PermanentError


def _write(tmp_path: Path, name: str, text: str) -> str:
    path = tmp_path / name
    path.write_text(dedent(text).lstrip("\n"), encoding="utf-8")
    return str(path)


def _default_files(tmp_path: Path) -> list[str]:
    assets = _write(
        tmp_path,
        "inventory.yaml",
        """
        version: 1
        assets:
          - hostname: host-a
            criticality: high
            owner: "Team A"
            role: "server"
          - hostname: host-b
            criticality: unknown
        """,
    )
    identities = _write(
        tmp_path,
        "identities.yaml",
        """
        version: 1
        identities:
          - username: alice
            is_privileged: true
          - username: bob
        """,
    )
    iocs = _write(
        tmp_path,
        "iocs.csv",
        """
        value,reputation,expires_at,source
        203.0.113.10,malicious,2030-01-01T00:00:00Z,manual
        203.0.113.20,clean,2030-01-01T00:00:00Z,
        """,
    )
    return [assets, identities, iocs]


# --------------------------------------------------------------------------
# the happy path
# --------------------------------------------------------------------------


@pytest.mark.db
def test_load_upserts_all_three_files_and_returns_counts(db, tmp_path: Path) -> None:
    report = load(db, _default_files(tmp_path))
    assert report == LoadReport(assets=2, identities=2, iocs=2, deactivated=0, warnings=[])


@pytest.mark.db
def test_load_writes_source_loaded_at_and_active_on_assets(db, tmp_path: Path) -> None:
    load(db, _default_files(tmp_path))
    row = db.execute(
        "SELECT criticality, owner, role, source, active, loaded_at IS NOT NULL "
        "FROM assets WHERE hostname = 'host-a'"
    ).fetchone()
    assert row == ("high", "Team A", "server", "inventory.yaml", True, True)


@pytest.mark.db
def test_load_asset_with_no_owner_or_role_stores_null(db, tmp_path: Path) -> None:
    load(db, _default_files(tmp_path))
    row = db.execute(
        "SELECT criticality, owner, role FROM assets WHERE hostname = 'host-b'"
    ).fetchone()
    assert row == ("unknown", None, None)


@pytest.mark.db
def test_load_identities_default_is_privileged_false_when_absent(db, tmp_path: Path) -> None:
    load(db, _default_files(tmp_path))
    alice = db.execute(
        "SELECT is_privileged, source FROM identities WHERE username = 'alice'"
    ).fetchone()
    bob = db.execute("SELECT is_privileged FROM identities WHERE username = 'bob'").fetchone()
    assert alice == (True, "identities.yaml")
    assert bob == (False,)


@pytest.mark.db
def test_load_iocs_default_source_is_internal_when_the_csv_column_is_empty(
    db, tmp_path: Path
) -> None:
    load(db, _default_files(tmp_path))
    manual = db.execute(
        "SELECT reputation, source FROM iocs WHERE value = '203.0.113.10'"
    ).fetchone()
    defaulted = db.execute(
        "SELECT reputation, source FROM iocs WHERE value = '203.0.113.20'"
    ).fetchone()
    assert manual == ("malicious", "manual")
    assert defaulted == ("clean", "internal")


@pytest.mark.db
def test_load_does_not_write_the_filename_into_iocs_source(db, tmp_path: Path) -> None:
    # iocs.source is the indicator's own provenance column, not the loader's
    # file name — unlike assets/identities, whose `source` IS the basename.
    load(db, _default_files(tmp_path))
    sources = {row[0] for row in db.execute("SELECT source FROM iocs").fetchall()}
    assert "iocs.csv" not in sources
    assert sources == {"manual", "internal"}


# --------------------------------------------------------------------------
# idempotency and deactivation
# --------------------------------------------------------------------------


@pytest.mark.db
def test_load_twice_with_no_changes_is_idempotent(db, tmp_path: Path) -> None:
    files = _default_files(tmp_path)
    first = load(db, files)
    second = load(db, files)
    assert first == second
    assert second.deactivated == 0


@pytest.mark.db
def test_load_deactivates_a_vanished_asset_but_never_deletes_it(db, tmp_path: Path) -> None:
    files = _default_files(tmp_path)
    load(db, files)
    # host-b vanishes from the file on the second load.
    _write(
        tmp_path,
        "inventory.yaml",
        """
        version: 1
        assets:
          - hostname: host-a
            criticality: high
        """,
    )
    report = load(db, files)
    assert report.deactivated == 1
    row = db.execute("SELECT active, source FROM assets WHERE hostname = 'host-b'").fetchone()
    assert row == (False, "inventory.yaml")  # still present, just inactive
    count = db.execute("SELECT count(*) FROM assets").fetchone()[0]
    assert count == 2  # nothing was deleted


@pytest.mark.db
def test_load_deactivates_a_vanished_identity_but_never_deletes_it(db, tmp_path: Path) -> None:
    files = _default_files(tmp_path)
    load(db, files)
    _write(
        tmp_path,
        "identities.yaml",
        """
        version: 1
        identities:
          - username: alice
            is_privileged: true
        """,
    )
    report = load(db, files)
    assert report.deactivated == 1
    row = db.execute("SELECT active FROM identities WHERE username = 'bob'").fetchone()
    assert row == (False,)
    count = db.execute("SELECT count(*) FROM identities").fetchone()[0]
    assert count == 2


@pytest.mark.db
def test_load_deactivates_an_ioc_pair_absent_from_the_file(db, tmp_path: Path) -> None:
    files = _default_files(tmp_path)
    load(db, files)
    _write(
        tmp_path,
        "iocs.csv",
        """
        value,reputation,expires_at,source
        203.0.113.10,malicious,2030-01-01T00:00:00Z,manual
        """,
    )
    report = load(db, files)
    assert report.deactivated == 1
    row = db.execute(
        "SELECT active FROM iocs WHERE value = '203.0.113.20' AND source = 'internal'"
    ).fetchone()
    assert row == (False,)
    count = db.execute("SELECT count(*) FROM iocs").fetchone()[0]
    assert count == 2


@pytest.mark.db
def test_load_reactivates_a_row_that_reappears(db, tmp_path: Path) -> None:
    files = _default_files(tmp_path)
    load(db, files)
    _write(
        tmp_path,
        "inventory.yaml",
        """
        version: 1
        assets:
          - hostname: host-a
            criticality: high
        """,
    )
    load(db, files)  # host-b deactivated
    # host-b comes back.
    _write(
        tmp_path,
        "inventory.yaml",
        """
        version: 1
        assets:
          - hostname: host-a
            criticality: high
          - hostname: host-b
            criticality: unknown
        """,
    )
    report = load(db, files)
    assert report.deactivated == 0
    row = db.execute("SELECT active FROM assets WHERE hostname = 'host-b'").fetchone()
    assert row == (True,)


@pytest.mark.db
def test_load_deactivation_is_scoped_to_the_files_own_source(db, tmp_path: Path) -> None:
    """The card's named failing case: an `UPDATE ... WHERE active AND hostname <>
    ALL(...)` with no `source = %s` clause would deactivate a second file's rows
    too. Reloading `site-a.yaml` must never touch `site-b.yaml`'s host."""
    file_a = _write(
        tmp_path,
        "site-a.yaml",
        """
        version: 1
        assets:
          - hostname: only-in-a
            criticality: low
        """,
    )
    file_b = _write(
        tmp_path,
        "site-b.yaml",
        """
        version: 1
        assets:
          - hostname: only-in-b
            criticality: low
        """,
    )
    load(db, [file_a])
    load(db, [file_b])
    load(db, [file_a])  # reload of A only — B must stay untouched
    row_a = db.execute("SELECT active FROM assets WHERE hostname = 'only-in-a'").fetchone()
    row_b = db.execute("SELECT active FROM assets WHERE hostname = 'only-in-b'").fetchone()
    assert row_a == (True,)
    assert row_b == (True,)


@pytest.mark.db
def test_load_with_an_empty_assets_list_deactivates_every_row_from_that_source(
    db, tmp_path: Path
) -> None:
    # Regression guard: an empty candidate list must still cast cleanly to
    # `text[]` rather than erroring or vacuously matching nothing.
    files = _default_files(tmp_path)
    load(db, files)
    _write(tmp_path, "inventory.yaml", "version: 1\nassets: []\n")
    report = load(db, files)
    assert report.assets == 0
    assert report.deactivated == 2
    count_active = db.execute("SELECT count(*) FROM assets WHERE active").fetchone()[0]
    assert count_active == 0


# --------------------------------------------------------------------------
# validation aborts the load
# --------------------------------------------------------------------------


@pytest.mark.db
def test_load_aborts_with_permanent_error_and_writes_nothing(db, tmp_path: Path) -> None:
    files = _default_files(tmp_path)
    _write(
        tmp_path,
        "inventory.yaml",
        """
        version: 1
        assets:
          - hostname: host-a
            criticality: severe
        """,
    )
    before = db.execute("SELECT count(*) FROM assets").fetchone()[0]
    with pytest.raises(PermanentError) as excinfo:
        load(db, files)
    assert "severe" in str(excinfo.value)
    assert "inventory.yaml" in str(excinfo.value)
    after = db.execute("SELECT count(*) FROM assets").fetchone()[0]
    assert after == before == 0


@pytest.mark.db
def test_load_warning_only_problems_do_not_abort_but_are_reported(db, tmp_path: Path) -> None:
    files = _default_files(tmp_path)
    _write(
        tmp_path,
        "iocs.csv",
        """
        value,reputation,expires_at,source
        203.0.113.10,malicious,2020-01-01T00:00:00Z,manual
        """,
    )
    report = load(db, files)
    assert report.iocs == 1
    assert len(report.warnings) == 1
    assert report.warnings[0].startswith("warning: ")
    assert "203.0.113.10" in report.warnings[0]
    row = db.execute("SELECT active FROM iocs WHERE value = '203.0.113.10'").fetchone()
    assert row == (True,)  # loaded anyway — expires_at > now() is what hides it


# --------------------------------------------------------------------------
# default paths from INVENTORY_PATHS
# --------------------------------------------------------------------------


@pytest.mark.db
def test_load_with_no_paths_argument_reads_inventory_paths_from_the_environment(
    db, tmp_path: Path, monkeypatch
) -> None:
    files = _default_files(tmp_path)
    monkeypatch.setenv("INVENTORY_PATHS", json.dumps(files))
    report = load(db)
    assert report == LoadReport(assets=2, identities=2, iocs=2, deactivated=0, warnings=[])
