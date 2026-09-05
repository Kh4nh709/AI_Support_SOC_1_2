"""Migration 013 — the enrichment tables carry §6.2's criticality vocabulary (DEC-004)
and the `source` / `loaded_at` / `active` columns the P2 inventory loader upserts,
and §6.1's one dropped v3 table is gone.

Every test here needs a migrated database, so every one is `@pytest.mark.db`.
`iocs.source` is deliberately *not* added by 013 — `006_chot_hop_dong.sql:54` added it
and line 56 made it half of `iocs_pkey`; these tests assert that key is undisturbed.
"""

import psycopg
import pytest

EXPECTED_CRITICALITY_CHECK = (
    "CHECK ((criticality = ANY (ARRAY['high'::text, 'medium'::text, "
    "'low'::text, 'unknown'::text])))"
)


@pytest.mark.db
def test_ck_assets_criticality_carries_the_section_6_2_vocabulary(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conname = 'ck_assets_criticality'"
        )
        rows = cur.fetchall()

    assert rows == [(EXPECTED_CRITICALITY_CHECK,)]


@pytest.mark.db
def test_assets_accepts_every_section_6_2_criticality(db):
    with db.cursor() as cur:
        for value in ("high", "medium", "low", "unknown"):
            cur.execute(
                "INSERT INTO assets (hostname, criticality) VALUES (%s, %s)", (value, value)
            )
        cur.execute("SELECT count(*) FROM assets")
        (count,) = cur.fetchone()

    assert count == 4


@pytest.mark.db
def test_assets_rejects_the_v1_crown_jewel_vocabulary(db):
    with pytest.raises(psycopg.errors.CheckViolation) as excinfo, db.cursor() as cur:
        cur.execute("INSERT INTO assets (hostname, criticality) VALUES ('h', 'crown_jewel')")

    assert "ck_assets_criticality" in str(excinfo.value)


@pytest.mark.db
def test_assets_rejects_the_v1_normal_vocabulary(db):
    with pytest.raises(psycopg.errors.CheckViolation) as excinfo, db.cursor() as cur:
        cur.execute("INSERT INTO assets (hostname, criticality) VALUES ('h', 'normal')")

    assert "ck_assets_criticality" in str(excinfo.value)


@pytest.mark.db
def test_assets_carries_owner_role_and_the_inventory_provenance_columns(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'assets' "
            "AND column_name IN ('owner', 'role', 'source', 'loaded_at', 'active') "
            "ORDER BY 1"
        )
        names = [row[0] for row in cur.fetchall()]

    assert names == ["active", "loaded_at", "owner", "role", "source"]


@pytest.mark.db
def test_assets_owner_and_role_are_nullable_text(db):
    # §7.1 reads both only inside an <untrusted_data> block; the DB holds them as
    # plain nullable text — an asset with no inventory row has neither.
    with db.cursor() as cur:
        cur.execute(
            "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
            "WHERE table_name = 'assets' AND column_name IN ('owner', 'role') ORDER BY 1"
        )
        rows = cur.fetchall()

    assert rows == [("owner", "text", "YES"), ("role", "text", "YES")]


@pytest.mark.db
def test_identities_and_iocs_carry_the_three_inventory_columns(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT table_name, count(*) FROM information_schema.columns "
            "WHERE table_name IN ('identities', 'iocs') "
            "AND column_name IN ('source', 'loaded_at', 'active') GROUP BY 1 ORDER BY 1"
        )
        rows = cur.fetchall()

    assert rows == [("identities", 3), ("iocs", 3)]


@pytest.mark.db
def test_active_is_not_null_and_defaults_to_true_on_all_three_tables(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT table_name, is_nullable, column_default FROM information_schema.columns "
            "WHERE table_name IN ('assets', 'identities', 'iocs') AND column_name = 'active' "
            "ORDER BY 1"
        )
        rows = cur.fetchall()

    assert rows == [
        ("assets", "NO", "true"),
        ("identities", "NO", "true"),
        ("iocs", "NO", "true"),
    ]


@pytest.mark.db
def test_a_row_inserted_without_active_comes_back_active(db):
    with db.cursor() as cur:
        cur.execute("INSERT INTO assets (hostname, criticality) VALUES ('h', 'high')")
        cur.execute("INSERT INTO identities (username) VALUES ('u')")
        cur.execute(
            "INSERT INTO iocs (value, reputation, expires_at) "
            "VALUES ('1.2.3.4', 'clean', now() + interval '1 hour')"
        )
        cur.execute(
            "SELECT (SELECT active FROM assets), (SELECT active FROM identities), "
            "(SELECT active FROM iocs)"
        )
        rows = cur.fetchone()

    assert rows == (True, True, True)


@pytest.mark.db
def test_source_and_loaded_at_stay_nullable_and_undefaulted(db):
    # docs/inventory-format.md §4: P2 always writes the real file name and time.
    # NULL is the honest "this row did not come from an inventory file"; a
    # DEFAULT would manufacture a provenance nobody can trust.
    with db.cursor() as cur:
        cur.execute(
            "SELECT table_name, column_name, is_nullable, column_default "
            "FROM information_schema.columns "
            "WHERE table_name IN ('assets', 'identities') "
            "AND column_name IN ('source', 'loaded_at') ORDER BY 1, 2"
        )
        rows = cur.fetchall()
        cur.execute("INSERT INTO assets (hostname, criticality) VALUES ('h', 'high')")
        cur.execute("SELECT source, loaded_at FROM assets")
        unloaded = cur.fetchone()

    assert rows == [
        ("assets", "loaded_at", "YES", None),
        ("assets", "source", "YES", None),
        ("identities", "loaded_at", "YES", None),
        ("identities", "source", "YES", None),
    ]
    assert unloaded == (None, None)


@pytest.mark.db
def test_iocs_primary_key_is_undisturbed(db):
    # 013 must not re-add `iocs.source`: 006 added it and made it half the key.
    with db.cursor() as cur:
        cur.execute(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'iocs_pkey'"
        )
        rows = cur.fetchall()
        cur.execute(
            "SELECT is_nullable, column_default FROM information_schema.columns "
            "WHERE table_name = 'iocs' AND column_name = 'source'"
        )
        source = cur.fetchone()

    assert rows == [("PRIMARY KEY (value, source)",)]
    assert source == ("NO", "'internal'::text")


@pytest.mark.db
def test_enrich_cache_is_dropped_with_its_indexes(db):
    with db.cursor() as cur:
        cur.execute("SELECT to_regclass('public.enrich_cache')")
        (table,) = cur.fetchone()
        cur.execute("SELECT count(*) FROM pg_indexes WHERE tablename = 'enrich_cache'")
        (indexes,) = cur.fetchone()

    assert table is None
    assert indexes == 0


@pytest.mark.db
def test_the_migration_records_itself_exactly_once(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM schema_migrations WHERE version = '013_assets_enrichment'"
        )
        (count,) = cur.fetchone()

    assert count == 1
