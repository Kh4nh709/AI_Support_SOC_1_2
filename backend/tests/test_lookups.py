"""P2-T08 — `enrichment.lookups`: three deterministic, read-only lookups.

Every test here needs a migrated database, so every one is `@pytest.mark.db`.
Rows are inserted directly with SQL (not through `load()`, which is tested on
its own in `test_inventory_load.py`) so each scenario controls `active`,
`criticality` and `expires_at` precisely. The `db` fixture rolls back at
teardown, so nothing needs manual cleanup.
"""

from __future__ import annotations

import psycopg
import pytest
from app.enrichment import lookups


def _insert_asset(
    conn: psycopg.Connection,
    hostname: str,
    criticality: str = "high",
    owner: str | None = None,
    role: str | None = None,
    active: bool = True,
) -> None:
    conn.execute(
        "INSERT INTO assets (hostname, criticality, owner, role, active) "
        "VALUES (%s, %s, %s, %s, %s)",
        (hostname, criticality, owner, role, active),
    )


def _insert_identity(
    conn: psycopg.Connection, username: str, is_privileged: bool = False, active: bool = True
) -> None:
    conn.execute(
        "INSERT INTO identities (username, is_privileged, active) VALUES (%s, %s, %s)",
        (username, is_privileged, active),
    )


def _insert_ioc(
    conn: psycopg.Connection,
    value: str,
    reputation: str,
    source: str = "manual",
    expires_at: str = "2030-01-01T00:00:00Z",
    active: bool = True,
) -> None:
    conn.execute(
        "INSERT INTO iocs (value, reputation, source, expires_at, active) "
        "VALUES (%s, %s, %s, %s, %s)",
        (value, reputation, source, expires_at, active),
    )


# --------------------------------------------------------------------------
# lookup_asset
# --------------------------------------------------------------------------


@pytest.mark.db
def test_lookup_asset_found_by_agent_name(db) -> None:
    _insert_asset(db, "host-a", criticality="medium", owner="A team", role="server")
    result = lookups.lookup_asset(db, "host-a", None)
    assert result == {
        "status": "found",
        "present": True,
        "criticality": "medium",
        "owner": "A team",
        "role": "server",
    }


@pytest.mark.db
def test_lookup_asset_falls_back_to_origin_host_when_agent_name_misses(db) -> None:
    _insert_asset(db, "real-host", criticality="high")
    result = lookups.lookup_asset(db, "agent-name-unmatched", "real-host")
    assert result["status"] == "found"
    assert result["criticality"] == "high"


@pytest.mark.db
def test_lookup_asset_prefers_agent_name_over_origin_host_when_both_present(db) -> None:
    _insert_asset(db, "host-a", criticality="high")
    _insert_asset(db, "host-b", criticality="low")
    result = lookups.lookup_asset(db, "host-a", "host-b")
    assert result["criticality"] == "high"


@pytest.mark.db
def test_lookup_asset_not_found_when_absent_from_both_names(db) -> None:
    result = lookups.lookup_asset(db, "ghost", "also-ghost")
    assert result == {
        "status": "not_found",
        "present": False,
        "criticality": "unknown",
        "owner": None,
        "role": None,
    }


@pytest.mark.db
def test_lookup_asset_does_not_crash_when_origin_host_is_none(db) -> None:
    result = lookups.lookup_asset(db, "ghost", None)
    assert result["status"] == "not_found"


@pytest.mark.db
def test_lookup_asset_present_true_with_unknown_criticality_differs_from_absent(db) -> None:
    """`inventory-format.md` §1: `unknown`-and-present must not read like absent."""
    _insert_asset(db, "assessed-later", criticality="unknown")
    present = lookups.lookup_asset(db, "assessed-later", None)
    absent = lookups.lookup_asset(db, "never-listed", None)
    assert present["criticality"] == absent["criticality"] == "unknown"
    assert present["present"] is True
    assert absent["present"] is False
    assert present != absent


@pytest.mark.db
def test_lookup_asset_ignores_inactive_rows(db) -> None:
    _insert_asset(db, "gone-from-inventory", criticality="high", active=False)
    result = lookups.lookup_asset(db, "gone-from-inventory", None)
    assert result["status"] == "not_found"
    assert result["present"] is False


# --------------------------------------------------------------------------
# lookup_identity
# --------------------------------------------------------------------------


@pytest.mark.db
def test_lookup_identity_skipped_when_username_is_none(db) -> None:
    assert lookups.lookup_identity(db, None) == {"status": "skipped", "is_privileged": None}


@pytest.mark.db
def test_lookup_identity_found_privileged(db) -> None:
    _insert_identity(db, "root", is_privileged=True)
    assert lookups.lookup_identity(db, "root") == {"status": "found", "is_privileged": True}


@pytest.mark.db
def test_lookup_identity_found_not_privileged(db) -> None:
    _insert_identity(db, "user1", is_privileged=False)
    assert lookups.lookup_identity(db, "user1") == {"status": "found", "is_privileged": False}


@pytest.mark.db
def test_lookup_identity_not_found(db) -> None:
    assert lookups.lookup_identity(db, "nobody") == {"status": "not_found", "is_privileged": None}


@pytest.mark.db
def test_lookup_identity_ignores_inactive_rows(db) -> None:
    _insert_identity(db, "left-the-org", is_privileged=True, active=False)
    assert lookups.lookup_identity(db, "left-the-org") == {
        "status": "not_found",
        "is_privileged": None,
    }


# --------------------------------------------------------------------------
# lookup_ioc
# --------------------------------------------------------------------------


@pytest.mark.db
def test_lookup_ioc_skipped_when_both_ips_are_private(db) -> None:
    result = lookups.lookup_ioc(
        db, "10.0.0.1", "192.168.1.1", srcip_is_private=True, dstip_is_private=True
    )
    assert result == {"status": "skipped", "reputation": "skipped"}


@pytest.mark.db
def test_lookup_ioc_skipped_when_both_ips_are_empty(db) -> None:
    result = lookups.lookup_ioc(db, "", "", srcip_is_private=None, dstip_is_private=None)
    assert result == {"status": "skipped", "reputation": "skipped"}


@pytest.mark.db
def test_lookup_ioc_excludes_only_the_private_ip_not_both(db) -> None:
    _insert_ioc(db, "203.0.113.10", "malicious")
    result = lookups.lookup_ioc(
        db, "10.0.0.1", "203.0.113.10", srcip_is_private=True, dstip_is_private=False
    )
    assert result == {"status": "found", "reputation": "malicious"}


@pytest.mark.db
def test_lookup_ioc_unknown_private_flag_is_treated_as_not_private(db) -> None:
    _insert_ioc(db, "203.0.113.10", "malicious")
    result = lookups.lookup_ioc(
        db, "203.0.113.10", "", srcip_is_private=None, dstip_is_private=None
    )
    assert result == {"status": "found", "reputation": "malicious"}


@pytest.mark.db
def test_lookup_ioc_found_clean(db) -> None:
    _insert_ioc(db, "198.51.100.7", "clean")
    result = lookups.lookup_ioc(
        db, "198.51.100.7", "", srcip_is_private=False, dstip_is_private=None
    )
    assert result == {"status": "found", "reputation": "clean"}


@pytest.mark.db
def test_lookup_ioc_not_found(db) -> None:
    result = lookups.lookup_ioc(db, "8.8.8.8", "", srcip_is_private=False, dstip_is_private=None)
    assert result == {"status": "not_found", "reputation": "not_found"}


@pytest.mark.db
def test_lookup_ioc_worst_reputation_wins_across_both_ips(db) -> None:
    _insert_ioc(db, "203.0.113.10", "suspicious")
    _insert_ioc(db, "203.0.113.20", "malicious")
    result = lookups.lookup_ioc(
        db,
        "203.0.113.10",
        "203.0.113.20",
        srcip_is_private=False,
        dstip_is_private=False,
    )
    assert result == {"status": "found", "reputation": "malicious"}


@pytest.mark.db
def test_lookup_ioc_expired_row_is_invisible(db) -> None:
    _insert_ioc(db, "203.0.113.10", "malicious", expires_at="2020-01-01T00:00:00Z")
    result = lookups.lookup_ioc(
        db, "203.0.113.10", "", srcip_is_private=False, dstip_is_private=None
    )
    assert result == {"status": "not_found", "reputation": "not_found"}


@pytest.mark.db
def test_lookup_ioc_inactive_row_is_invisible(db) -> None:
    _insert_ioc(db, "203.0.113.10", "malicious", active=False)
    result = lookups.lookup_ioc(
        db, "203.0.113.10", "", srcip_is_private=False, dstip_is_private=None
    )
    assert result == {"status": "not_found", "reputation": "not_found"}


@pytest.mark.db
def test_lookup_ioc_reputation_matches_status_for_not_found_and_skipped(db) -> None:
    # §6.2's ioc_reputation vocabulary lives on `reputation`, not just `status`,
    # so gate step 2 (P3) can compare it directly with no mapping.
    not_found = lookups.lookup_ioc(db, "8.8.8.8", "", srcip_is_private=False, dstip_is_private=None)
    skipped = lookups.lookup_ioc(db, "", "", srcip_is_private=None, dstip_is_private=None)
    assert not_found["reputation"] == not_found["status"] == "not_found"
    assert skipped["reputation"] == skipped["status"] == "skipped"
