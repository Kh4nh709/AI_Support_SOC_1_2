"""Tests for app.ingest.dedup — the advisory lock, the six predicates, `bump_parent`.

Every test here needs a real PostgreSQL: the whole module under test is SQL, and
the three things it has to get right (a lock that actually blocks a second
session, a predicate that actually reaches the partial index, a timestamp that
actually comes from the database clock) are invisible to a mock. Hence the
module-level `pytestmark` — `make test` deselects the file, `make test-db` runs
it.

THE FIXTURE MAY SET CLOCKS; THE PRODUCT CODE MAY NOT. To exercise `IDLE_GAP`,
`MAX_AGE` and the 30-minute auto-closed cap without sleeping for hours,
`_insert_alert` writes `first_seen_at` / `last_seen_at` as raw SQL expressions
(`now() - interval '16 minutes'`). That is the test acting as the owner of its
own data. In `bump_parent` the same thing is forbidden (D9) and
`test_khong_truyen_moc_thoi_gian_vao_last_seen_at` below greps the module to
prove it stayed forbidden.

THE THREE SOURCE-SCAN GUARDS at the bottom (`IS NOT DISTINCT FROM`, the lock
subject, the D9 timestamp) each fail if the corresponding line in `dedup.py` is
edited back to the shape phase-2 warns about; all three were watched red before
being reported green (DEC-027 — a guard nobody has seen fail is an untested
test).
"""

from __future__ import annotations

import pathlib
import re
import threading
import time
import uuid
from concurrent import futures
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from app.domain.alert import Alert, compute_event_bucket_hash
from app.infra.errors import PermanentError
from app.ingest import dedup
from psycopg import sql
from psycopg.types.json import Json

pytestmark = pytest.mark.db

DEDUP_SOURCE = (
    pathlib.Path(__file__).resolve().parents[1] / "app" / "ingest" / "dedup.py"
).read_text(encoding="utf-8")

#: The cluster key every helper below defaults to, so a test only names the
#: column it is actually varying.
KEY_RULE_ID = "5710"
KEY_SRCIP = "203.0.113.7"
KEY_DSTIP = "10.10.0.9"
KEY_AGENT = "web-01"

#: Terminal statuses owe `closed_at` (ck_alerts_g3_terminal_phai_co_closed_at);
#: the three human ones and `duplicate` also owe `sealed_at`
#: (ck_alerts_h2_dong_boi_nguoi_phai_seal, ck_alerts_ban_sao_phai_seal_va_tro_goc).
_TERMINAL = frozenset(
    {"duplicate", "auto_closed", "closed_fp", "closed_benign", "closed_confirmed"}
)
_SEALED_ON_INSERT = frozenset({"duplicate", "closed_fp", "closed_benign", "closed_confirmed"})


def _insert_alert(conn, *, ts_sql=None, **overrides) -> str:
    """Insert one `alerts` row and return its `alert_id`.

    The twelve `NOT NULL`-without-default columns (`alert_id, rule_id,
    rule_level, severity, description, agent_name, alert_time, category,
    resolved_by, mapping_version, event_bucket_hash, raw_payload`) always get a
    value; everything else falls back to the column default unless named.

    `ts_sql` maps a timestamp column to a **raw SQL expression** rather than a
    parameter, because "16 minutes ago on the database's clock" cannot be
    written as a Python value without dragging the test host's clock into the
    comparison. Defaults are chosen so the row is always insertable:
    `last_seen_at` falls back to `now()`, `first_seen_at` falls back to
    whatever `last_seen_at` is (`ck_alerts_last_seen_khong_lui` requires
    `last_seen_at >= first_seen_at`), and a terminal status gets the
    `closed_at`/`sealed_at` its CHECK constraint demands.
    """
    ts_sql = dict(ts_sql or {})
    last_seen = ts_sql.pop("last_seen_at", "now()")
    first_seen = ts_sql.pop("first_seen_at", last_seen)

    values: dict[str, object] = {
        "alert_id": uuid.uuid4().hex,
        "rule_id": KEY_RULE_ID,
        "rule_level": 5,
        "severity": "medium",
        "description": "sshd: authentication failed",
        "agent_name": KEY_AGENT,
        "alert_time": datetime(2026, 9, 15, 10, 0, tzinfo=UTC),
        "category": "brute_force",
        "resolved_by": "rule_groups",
        "mapping_version": "2026-09-01",
        "event_bucket_hash": "a" * 64,
        "raw_payload": Json({"rule": {"id": KEY_RULE_ID}}),
        "srcip": KEY_SRCIP,
        "dstip": KEY_DSTIP,
        "status": "received",
        "occurrence_count": 1,
        "triaged_count": 0,
    }
    values.update(overrides)

    exprs = {"first_seen_at": first_seen, "last_seen_at": last_seen}
    if values["status"] in _TERMINAL:
        exprs["closed_at"] = ts_sql.pop("closed_at", "now()")
    if values["status"] in _SEALED_ON_INSERT:
        exprs["sealed_at"] = ts_sql.pop("sealed_at", "now()")
    exprs.update(ts_sql)

    statement = sql.SQL("INSERT INTO alerts ({cols}) VALUES ({vals})").format(
        cols=sql.SQL(", ").join(sql.Identifier(c) for c in (*values, *exprs)),
        vals=sql.SQL(", ").join(
            [sql.Placeholder() for _ in values] + [sql.SQL(e) for e in exprs.values()]
        ),
    )
    conn.execute(statement, list(values.values()))
    return values["alert_id"]  # type: ignore[return-value]


def _probe(**overrides) -> Alert:
    """An `Alert` to look a cluster up with. Only the four key columns matter to
    `find_open_cluster`; the rest are filled so the dataclass can be built."""
    fields: dict[str, object] = {
        "alert_id": uuid.uuid4().hex,
        "manager_id": "IA1803",
        "rule_id": KEY_RULE_ID,
        "description": "sshd: authentication failed",
        "agent_name": KEY_AGENT,
        "agent_id": "001",
        "agent_ip": "10.10.0.9",
        "origin_host": "wazuh-manager",
        "alert_time": datetime(2026, 9, 15, 10, 0, tzinfo=UTC),
        "event_time": None,
        "srcip": KEY_SRCIP,
        "dstip": KEY_DSTIP,
        "src_port": 44321,
        "dst_port": 22,
        "alert_user": None,
        "decoder": "sshd",
        "mitre_ids": ("T1110",),
        "rule_groups": ("sshd", "authentication_failed"),
        "rule_level": 5,
        "severity": "medium",
        "category": "brute_force",
        "categories": ("brute_force",),
        "resolved_by": "rule_groups",
        "mapping_version": "2026-09-01",
        "srcip_is_private": False,
        "dstip_is_private": True,
        "raw_log": "",
        "raw_log_truncated": False,
        "event_bucket_hash": "a" * 64,
        "raw_payload": {},
    }
    fields.update(overrides)
    return Alert(**fields)  # type: ignore[arg-type]


def _key_of(alert: Alert) -> tuple[str, str, str, str]:
    """The `cluster_lock` argument tuple for `alert`, in the card's order."""
    return (alert.rule_id, alert.srcip, alert.dstip, alert.agent_name)


@contextmanager
def _committed_alert(dsn: str, **kwargs):
    """An `alerts` row visible to *other* connections, removed on the way out.

    The `db` fixture never commits, so a row it inserts is invisible to the
    second session a `FOR UPDATE` test needs. This commits one and cleans up.
    """
    conn = psycopg.connect(dsn)
    alert_id = None
    try:
        alert_id = _insert_alert(conn, **kwargs)
        conn.commit()
        yield alert_id
    finally:
        try:
            if alert_id is not None:
                conn.rollback()
                conn.execute("DELETE FROM alerts WHERE alert_id = %s", (alert_id,))
                conn.commit()
        finally:
            conn.close()


# ── 1 · the cluster key — four columns, plain `=` (B1) ───────────────────────


def test_hai_alert_cach_2_phut_thi_gop(db):
    """Two alerts of one key, two minutes apart, land in one cluster."""
    parent = _insert_alert(db, ts_sql={"last_seen_at": "now() - interval '2 minutes'"})
    head = dedup.find_open_cluster(db, _probe())
    assert head is not None and head.alert_id == parent


def test_khac_rule_id_thi_khong_gop(db):
    _insert_alert(db, rule_id="5711")
    assert dedup.find_open_cluster(db, _probe(rule_id=KEY_RULE_ID)) is None


def test_khac_srcip_thi_khong_gop(db):
    """A5 — a different source address is a different cluster."""
    _insert_alert(db, srcip="203.0.113.8")
    assert dedup.find_open_cluster(db, _probe(srcip=KEY_SRCIP)) is None


def test_khac_dstip_thi_khong_gop(db):
    _insert_alert(db, dstip="10.10.0.10")
    assert dedup.find_open_cluster(db, _probe(dstip=KEY_DSTIP)) is None


def test_khac_agent_name_thi_khong_gop(db):
    _insert_alert(db, agent_name="db-02")
    assert dedup.find_open_cluster(db, _probe(agent_name=KEY_AGENT)) is None


def test_khac_user_van_gop(db):
    """A4 — `alert_user` is deliberately NOT part of the cluster key: one
    brute-force run against five accounts is one cluster, and the account list
    is read off the children."""
    parent = _insert_alert(db, alert_user="root")
    head = dedup.find_open_cluster(db, _probe(alert_user="admin"))
    assert head is not None and head.alert_id == parent


def test_alert_srcip_rong_van_gop_duoc_voi_nhau(db):
    """B1 — `srcip`/`dstip` are `NOT NULL DEFAULT ''`, so two alerts with no
    source address compare equal under plain `=` and merge. This is the case
    the null-safe operator used to be there for."""
    parent = _insert_alert(db, srcip="", dstip="")
    head = dedup.find_open_cluster(db, _probe(srcip="", dstip=""))
    assert head is not None and head.alert_id == parent


# ── 2 · "still absorbing" — closed_at IS NULL OR sealed_at IS NULL ───────────


def test_goc_auto_closed_THI_GOP(db):
    """D-C6, inverted against the previous spec: an `auto_closed` head has
    `closed_at` set but `sealed_at` NULL, so it keeps absorbing. This is what
    turns 5,000 scanner alerts into one row with `occurrence_count = 5000`."""
    parent = _insert_alert(db, status="auto_closed")
    head = dedup.find_open_cluster(db, _probe())
    assert head is not None and head.alert_id == parent
    assert head.status == "auto_closed"


def test_goc_escalated_tier2_van_gop(db):
    """D-C5 — a head under Tier-2 investigation still absorbs; the UI has to
    show a counter that moves."""
    parent = _insert_alert(db, status="escalated_tier2")
    head = dedup.find_open_cluster(db, _probe())
    assert head is not None and head.alert_id == parent


def test_goc_closed_fp_thi_khong_gop_mo_cum_moi(db):
    """A human verdict seals the cluster: "the attacker came back after we
    closed the ticket" is exactly what the analyst must be told."""
    _insert_alert(db, status="closed_fp", close_reason="analyst: known scanner")
    assert dedup.find_open_cluster(db, _probe()) is None


def test_goc_closed_confirmed_thi_khong_gop(db):
    _insert_alert(db, status="closed_confirmed", close_reason="analyst: confirmed")
    assert dedup.find_open_cluster(db, _probe()) is None


def test_cum_bi_niem_sealed_at_thi_ngung_hut(db):
    """B4 — phase-3's sweeper seals every cluster opened by a rule the analyst
    has just switched off. `closed_at` stays where it was; `sealed_at` is what
    stops the absorbing."""
    _insert_alert(db, status="auto_closed", ts_sql={"sealed_at": "now()"})
    assert dedup.find_open_cluster(db, _probe()) is None


# ── 3 · status <> 'duplicate' ────────────────────────────────────────────────


def test_ban_sao_khong_the_lam_goc(db):
    """D2 — a duplicate never becomes a head, so duplicate chains cannot form."""
    parent = _insert_alert(db, status="closed_fp")
    _insert_alert(db, status="duplicate", duplicate_of=parent)
    assert dedup.find_open_cluster(db, _probe()) is None


def test_status_khac_duplicate_la_lop_chan_thu_hai(db):
    """`status <> 'duplicate'` has to hold on its own, so this test removes the
    layer in front of it.

    Measured while writing this file: delete `AND status <> 'duplicate'` from
    `dedup.py` and every other test here stays green. The predicate is
    unreachable under the schema as it stands, because the first layer already
    excludes every duplicate — `ck_alerts_ban_sao_phai_seal_va_tro_goc` will
    not let a `duplicate` row exist without both `closed_at` and `sealed_at`,
    so it can never satisfy "still absorbing". A test that cannot go red is not
    a test, and phase-2 calls this predicate the *second* layer, which means it
    is meant to hold when the first one does not.

    So: drop that CHECK inside this transaction (DDL is transactional in
    PostgreSQL and the `db` fixture rolls back), insert the unsealed duplicate
    the constraint would have refused, prove it passes the still-absorbing
    layer, and assert the query still refuses to make it a head. That is D2 —
    no duplicate chains, whatever upstream does.
    """
    db.execute("ALTER TABLE alerts DROP CONSTRAINT ck_alerts_ban_sao_phai_seal_va_tro_goc")
    parent = _insert_alert(db, status="closed_fp")
    child = _insert_alert(db, status="duplicate", duplicate_of=parent, ts_sql={"sealed_at": "NULL"})

    still_absorbing = db.execute(
        "SELECT alert_id FROM alerts "
        "WHERE rule_id = %s AND srcip = %s AND agent_name = %s AND dstip = %s "
        "AND (closed_at IS NULL OR sealed_at IS NULL)",
        (KEY_RULE_ID, KEY_SRCIP, KEY_AGENT, KEY_DSTIP),
    ).fetchall()
    assert [row[0] for row in still_absorbing] == [child], "the duplicate must reach layer two"

    assert dedup.find_open_cluster(db, _probe()) is None


# ── 4 · IDLE_GAP — the sliding window on last_seen_at ────────────────────────


def test_cum_im_lang_14_phut_van_gop(db):
    """Inside `DEDUP_IDLE_GAP_MINUTES = 15`."""
    parent = _insert_alert(db, ts_sql={"last_seen_at": "now() - interval '14 minutes'"})
    head = dedup.find_open_cluster(db, _probe())
    assert head is not None and head.alert_id == parent


def test_cum_im_lang_16_phut_thi_khong_gop(db):
    """Outside it. The window is anchored on `last_seen_at`, not on the first
    alert — sessionization: a burst ends when it goes quiet, not on a timer."""
    _insert_alert(db, ts_sql={"last_seen_at": "now() - interval '16 minutes'"})
    assert dedup.find_open_cluster(db, _probe()) is None


def test_im_lang_20_phut_roi_tan_cong_lai_ra_2_cum(db):
    """A6 — the same key, quiet for twenty minutes, opens a second cluster
    while the first one stays in the table untouched."""
    first = _insert_alert(
        db,
        ts_sql={
            "first_seen_at": "now() - interval '25 minutes'",
            "last_seen_at": "now() - interval '20 minutes'",
        },
    )
    assert dedup.find_open_cluster(db, _probe()) is None
    second = _insert_alert(db)
    head = dedup.find_open_cluster(db, _probe())
    assert head is not None and head.alert_id == second and second != first


# ── 5 · MAX_AGE — first_seen_at, with a shorter ceiling for auto_closed ──────


def test_cum_3h59_van_gop(db):
    """Inside `MAX_CLUSTER_AGE_HOURS = 4`."""
    parent = _insert_alert(db, ts_sql={"first_seen_at": "now() - interval '3 hours 59 minutes'"})
    head = dedup.find_open_cluster(db, _probe())
    assert head is not None and head.alert_id == parent


def test_cum_cham_tran_4_gio_thi_mo_cum_moi(db):
    """A7 — four hours and a minute old, still being fed, and still cut off:
    the age ceiling is what stops one cluster growing all day."""
    _insert_alert(db, ts_sql={"first_seen_at": "now() - interval '4 hours 1 minute'"})
    assert dedup.find_open_cluster(db, _probe()) is None


def test_cum_auto_closed_29_phut_van_gop(db):
    """B4 — inside `MAX_CLUSTER_AGE_AUTOCLOSED_MINUTES = 30`."""
    parent = _insert_alert(
        db, status="auto_closed", ts_sql={"first_seen_at": "now() - interval '29 minutes'"}
    )
    head = dedup.find_open_cluster(db, _probe())
    assert head is not None and head.alert_id == parent


def test_cum_auto_closed_cham_tran_30_phut(db):
    """B4 — nobody is watching an auto-closed cluster, so stretching it past
    half an hour buys nothing and costs latency when a rule is switched off."""
    _insert_alert(
        db, status="auto_closed", ts_sql={"first_seen_at": "now() - interval '31 minutes'"}
    )
    assert dedup.find_open_cluster(db, _probe()) is None


def test_goc_received_31_phut_khong_bi_tran_auto_closed_chan(db):
    """The `CASE` really does branch on `status`: the same 31-minute-old head,
    `received` instead of `auto_closed`, is still found. Without this the two
    ceilings could be one constant and the auto-closed tests would not notice."""
    parent = _insert_alert(db, ts_sql={"first_seen_at": "now() - interval '31 minutes'"})
    head = dedup.find_open_cluster(db, _probe())
    assert head is not None and head.alert_id == parent


# ── 6 · MAX_CLUSTER_SIZE ─────────────────────────────────────────────────────


def test_cum_999_alert_van_gop(db):
    parent = _insert_alert(db, occurrence_count=999)
    head = dedup.find_open_cluster(db, _probe())
    assert head is not None and head.alert_id == parent
    assert head.occurrence_count == 999


def test_cum_cham_1000_alert_thi_mo_cum_moi(db):
    """`occurrence_count < MAX_CLUSTER_SIZE`, so 1000 is already out."""
    _insert_alert(db, occurrence_count=1000)
    assert dedup.find_open_cluster(db, _probe()) is None


def test_cum_khong_co_srcip_van_bi_tran_chan(db):
    """The ceilings are not skipped for the empty-`srcip` cluster."""
    _insert_alert(db, srcip="", dstip="", occurrence_count=1000)
    assert dedup.find_open_cluster(db, _probe(srcip="", dstip="")) is None


# ── 7 · ordering, shape, row lock ────────────────────────────────────────────


def test_gop_vao_cum_last_seen_moi_nhat(db):
    """`ORDER BY last_seen_at DESC LIMIT 1` — with two live clusters on one key
    the alert joins the one that moved most recently."""
    _insert_alert(db, ts_sql={"last_seen_at": "now() - interval '10 minutes'"})
    recent = _insert_alert(db, ts_sql={"last_seen_at": "now() - interval '1 minute'"})
    head = dedup.find_open_cluster(db, _probe())
    assert head is not None and head.alert_id == recent


def test_cluster_head_mang_du_bon_truong(db):
    """The explicit column list, not `SELECT *`: four fields and no more."""
    parent = _insert_alert(db, status="escalated_tier2", occurrence_count=7, triaged_count=2)
    head = dedup.find_open_cluster(db, _probe())
    assert head == dedup.ClusterHead(
        alert_id=parent, occurrence_count=7, triaged_count=2, status="escalated_tier2"
    )


def test_find_open_cluster_khoa_dong_goc_bang_for_update(db, _test_database):
    """`FOR UPDATE` — the head is row-locked, so the `UPDATE` of step 3 cannot
    lose an update to a second session that read the same head."""
    with _committed_alert(_test_database) as parent:
        head = dedup.find_open_cluster(db, _probe())
        assert head is not None and head.alert_id == parent

        other = psycopg.connect(_test_database)
        try:
            with pytest.raises(psycopg.errors.LockNotAvailable):
                other.execute(
                    "SELECT alert_id FROM alerts WHERE alert_id = %s FOR UPDATE NOWAIT",
                    (parent,),
                ).fetchone()
        finally:
            other.rollback()
            other.close()
        db.rollback()


# ── 8 · the partial index (D7) ───────────────────────────────────────────────


def _explain(conn, alert: Alert) -> str:
    """`EXPLAIN` of the query `find_open_cluster` actually runs, with
    `enable_seqscan` off.

    Both halves matter. Using `dedup.find_open_cluster_query` rather than a
    retyped copy is what makes the test able to go red when the module's
    predicate stops matching the index. Turning off `enable_seqscan` is what
    makes it non-flaky: on a table with a handful of rows the planner prefers a
    sequential scan whatever indexes exist, so without it the test would be
    measuring table size. With it, the question asked is the one D7 asks — *is
    this index usable for this predicate at all?*
    """
    conn.execute("SET LOCAL enable_seqscan = off")
    statement, params = dedup.find_open_cluster_query(alert)
    rows = conn.execute("EXPLAIN " + statement, params).fetchall()
    return "\n".join(row[0] for row in rows)


def test_explain_dung_partial_index(db):
    """D7 — the query predicate matches the partial index syntactically.

    Assert on the index name in `Index Scan`, NOT on the absence of `Filter`:
    the rowmark `FOR UPDATE` creates makes PostgreSQL repeat the partial
    predicate in a `Filter` line even when the index is used correctly.
    """
    _insert_alert(db)
    plan = _explain(db, _probe())
    assert "Index Scan using ix_alerts_dedup" in plan, plan


def test_explain_ca_bon_cot_vao_index_cond(db):
    """B1 — all four key columns reach `Index Cond`. The null-safe operator
    dropped `srcip` to `Filter` and cost 154 buffers against 4."""
    _insert_alert(db)
    plan = _explain(db, _probe())
    cond = [line for line in plan.splitlines() if "Index Cond" in line]
    assert cond, plan
    joined = " ".join(cond)
    for column in ("rule_id", "srcip", "agent_name", "dstip"):
        assert column in joined, plan


def test_explain_khong_co_node_sort(db):
    """`last_seen_at DESC` is the index's own order, so `ORDER BY … LIMIT 1`
    needs no `Sort` node — that is why the column is the index's last key."""
    _insert_alert(db)
    plan = _explain(db, _probe())
    assert "Sort" not in plan, plan


# ── 9 · the advisory lock (D4) ───────────────────────────────────────────────


def _advisory_keys_held(conn) -> set[tuple[int, int]]:
    """`(classid, objid)` of every advisory lock this backend holds.

    A single-argument `pg_advisory_xact_lock(bigint)` is recorded split across
    the two columns: `classid` is the high 32 bits, `objid` the low ones.
    """
    rows = conn.execute(
        "SELECT classid, objid FROM pg_locks "
        "WHERE locktype = 'advisory' AND pid = pg_backend_pid()"
    ).fetchall()
    return {(int(c), int(o)) for c, o in rows}


def _split64(value: int) -> tuple[int, int]:
    unsigned = value & 0xFFFFFFFFFFFFFFFF
    return (unsigned >> 32, unsigned & 0xFFFFFFFF)


def test_advisory_lock_tinh_tren_cluster_key(db):
    """D4 — the lock subject is `hashtext(rule_id|srcip|dstip|agent_name)`, and
    it is NOT the 5-minute bucket column. Read straight out of `pg_locks`: the
    cluster-key lock is held, the bucket-column lock is not."""
    alert = _probe()
    dedup.cluster_lock(db, *_key_of(alert))

    cluster_key, bucket_key = db.execute(
        "SELECT hashtext(%s || '|' || %s || '|' || %s || '|' || %s), hashtext(%s)",
        (*_key_of(alert), alert.event_bucket_hash),
    ).fetchone()

    held = _advisory_keys_held(db)
    assert _split64(cluster_key) in held
    assert _split64(bucket_key) not in held


def test_cluster_lock_tu_nha_khi_transaction_ket_thuc(db):
    """`xact`-scoped: the lock dies with the caller's transaction, so nothing
    downstream has to remember to release it."""
    dedup.cluster_lock(db, KEY_RULE_ID, KEY_SRCIP, KEY_DSTIP, KEY_AGENT)
    assert _advisory_keys_held(db)
    db.rollback()
    assert _advisory_keys_held(db) == set()


def test_cluster_lock_tu_choi_gia_tri_null(db):
    """Edge case found while writing this: `hashtext(NULL)` is NULL and
    `pg_advisory_xact_lock(NULL)` takes no lock **and raises nothing** — the
    caller would run the whole dedup region unserialised believing it held a
    lock. The four values are `NOT NULL` by B1/D10, so a None here is a bug in
    the caller and is refused loudly."""
    with pytest.raises(PermanentError, match="NOT NULL"):
        dedup.cluster_lock(db, KEY_RULE_ID, None, KEY_DSTIP, KEY_AGENT)
    assert _advisory_keys_held(db) == set()


def _wait_for_lock(dsn: str, key_a, key_b, *, hold_s: float = 1.5, delay_s: float = 0.2) -> float:
    """Seconds session B waits for `key_b` while session A holds `key_a`.

    `time.perf_counter()` is deliberate: this clock measures the *test*, never
    the data — every timestamp the product compares still comes from the
    database.
    """
    ready = threading.Event()

    def hold() -> None:
        conn = psycopg.connect(dsn)
        try:
            conn.execute("BEGIN")
            dedup.cluster_lock(conn, *key_a)
            ready.set()
            conn.execute("SELECT pg_sleep(%s)", (hold_s,))
            conn.commit()
        finally:
            conn.close()

    # A future rather than a bare Thread plus a `try/except Exception`: anything
    # session A hits is re-raised here by `.result()`, at the right test, instead
    # of being swallowed into a thread nobody reads.
    with futures.ThreadPoolExecutor(max_workers=1) as pool:
        holder = pool.submit(hold)
        if not ready.wait(timeout=10):
            holder.result(timeout=5)
            raise AssertionError("session A never took its lock")
        time.sleep(delay_s)
        other = psycopg.connect(dsn)
        try:
            other.execute("BEGIN")
            started = time.perf_counter()
            dedup.cluster_lock(other, *key_b)
            waited = time.perf_counter() - started
        finally:
            other.rollback()
            other.close()
        holder.result(timeout=20)
    return waited


def test_hai_phien_cung_khoa_thi_tuan_tu(_test_database):
    """Two real sessions, one cluster key: B blocks until A commits."""
    key = (KEY_RULE_ID, KEY_SRCIP, KEY_DSTIP, KEY_AGENT)
    waited = _wait_for_lock(_test_database, key, key)
    print(f"[P2-T05] same key: session B waited {waited:.3f}s")
    assert waited >= 1.0


def test_hai_phien_khac_srcip_thi_khong_cho(_test_database):
    """…and only on the same key: a different `srcip` is a different cluster
    and runs straight through. A lock that blocked everything would pass the
    test above and destroy throughput."""
    key_a = (KEY_RULE_ID, KEY_SRCIP, KEY_DSTIP, KEY_AGENT)
    key_b = (KEY_RULE_ID, "203.0.113.99", KEY_DSTIP, KEY_AGENT)
    waited = _wait_for_lock(_test_database, key_a, key_b)
    print(f"[P2-T05] other srcip: session B waited {waited:.3f}s")
    assert waited < 0.3


def test_hai_alert_khac_bucket_cung_cum_van_bi_khoa(_test_database):
    """The trap phase-2 names. Two alerts of one cluster whose SIEM timestamps
    fall in different 5-minute buckets — different bucket hashes, proven below
    — still serialise, because the lock is on the key and not on the hash. Lock
    the hash instead and the race walks back in intact."""
    early = _probe(alert_time=datetime(2026, 9, 15, 10, 0, tzinfo=UTC))
    late = _probe(alert_time=datetime(2026, 9, 15, 10, 7, tzinfo=UTC))
    hashes = {
        compute_event_bucket_hash(a.rule_id, a.srcip, a.dstip, a.agent_name, a.alert_time)
        for a in (early, late)
    }
    assert len(hashes) == 2, "the two probes must fall in different 5-minute buckets"

    waited = _wait_for_lock(_test_database, _key_of(early), _key_of(late))
    print(f"[P2-T05] same key, other bucket: session B waited {waited:.3f}s")
    assert waited >= 1.0


# ── 10 · bump_parent — the database clock and nothing else (B2 / D9) ─────────


def test_bump_parent_tang_bo_dem_va_tra_ve_gia_tri_moi(db):
    parent = _insert_alert(db, occurrence_count=1)
    assert dedup.bump_parent(db, parent) == 2
    row = db.execute(
        "SELECT occurrence_count, last_seen_at >= first_seen_at FROM alerts WHERE alert_id = %s",
        (parent,),
    ).fetchone()
    assert row == (2, True)


def test_last_seen_at_luon_bang_now_cua_db(db):
    """D9 — the new `last_seen_at` is the database's `now()`.

    The measured failure this guards: a fast agent stretches the cluster by
    exactly its skew, and a slow agent puts every cluster outside its own
    window the moment it is created, which kills dedup 100% with no error
    anywhere. Anchor: the row's own `now()` at the moment of reading, not the
    test host's clock.

    The bound is two-sided on purpose. Written as `age < 1s` alone it passed
    against a deliberately broken `bump_parent` that wrote a *future* agent
    timestamp — a negative age is under one second too, and the fast-agent
    half of B2 is exactly the case that produces one.
    """
    parent = _insert_alert(db, ts_sql={"last_seen_at": "now() - interval '2 hours'"})
    dedup.bump_parent(db, parent)
    age, moved = db.execute(
        "SELECT now() - last_seen_at, last_seen_at > first_seen_at "
        "FROM alerts WHERE alert_id = %s",
        (parent,),
    ).fetchone()
    assert timedelta(0) <= age < timedelta(seconds=1), age
    assert moved is True


def test_last_seen_at_duoc_day_moi_lan_gop(db):
    """Every merge pushes the marker forward, which is what makes the window
    slide instead of expiring on the first alert."""
    parent = _insert_alert(db, ts_sql={"last_seen_at": "now() - interval '10 minutes'"})
    first = db.execute("SELECT last_seen_at FROM alerts WHERE alert_id = %s", (parent,)).fetchone()
    dedup.bump_parent(db, parent)
    second = db.execute("SELECT last_seen_at FROM alerts WHERE alert_id = %s", (parent,)).fetchone()
    dedup.bump_parent(db, parent)
    third = db.execute("SELECT last_seen_at FROM alerts WHERE alert_id = %s", (parent,)).fetchone()
    assert first[0] < second[0] <= third[0]


def test_last_seen_at_khong_lui_ve_qua_khu(db):
    """D6 — `now()` only moves forward, so `GREATEST(...)` is dead weight; the
    DB's own `ck_alerts_last_seen_khong_lui` is the backstop, and it bites."""
    parent = _insert_alert(db, ts_sql={"first_seen_at": "now() - interval '5 minutes'"})
    dedup.bump_parent(db, parent)
    with pytest.raises(psycopg.errors.CheckViolation, match="ck_alerts_last_seen_khong_lui"):
        db.execute(
            "UPDATE alerts SET last_seen_at = first_seen_at - interval '1 second' "
            "WHERE alert_id = %s",
            (parent,),
        )
    db.rollback()


def test_bump_parent_chi_doi_dong_duoc_chi_dinh(db):
    parent = _insert_alert(db, occurrence_count=1)
    bystander = _insert_alert(db, srcip="203.0.113.200", occurrence_count=1)
    dedup.bump_parent(db, parent)
    row = db.execute(
        "SELECT occurrence_count FROM alerts WHERE alert_id = %s", (bystander,)
    ).fetchone()
    assert row == (1,)


def test_bump_parent_khong_tim_thay_goc_thi_bao_loi(db):
    """A head that vanished between the `FOR UPDATE` read and the update is a
    bug in the caller, not something to retry: `PermanentError`, so the job
    fails now instead of three times."""
    with pytest.raises(PermanentError, match="no alerts row"):
        dedup.bump_parent(db, "khong-ton-tai")


# ── 11 · D10 and the three source-scan guards ────────────────────────────────


def test_srcip_khong_bao_gio_null(db):
    """D10 — the `=` comparison is safe because the DB enforces it, not because
    every future author remembers to call `coalesce()`."""
    rows = db.execute(
        "SELECT column_name, is_nullable, column_default FROM information_schema.columns "
        "WHERE table_name = 'alerts' AND column_name IN ('srcip', 'dstip') "
        "ORDER BY column_name"
    ).fetchall()
    assert rows == [
        ("dstip", "NO", "''::text"),
        ("srcip", "NO", "''::text"),
    ]


def test_khong_dung_is_not_distinct_from(db):
    """B1 — measured 154 buffers against 4; the operator never reaches
    `Index Cond` for a non-empty address, which is nearly all the traffic."""
    assert "IS NOT DISTINCT FROM" not in DEDUP_SOURCE.upper()


def test_khoa_tinh_tren_cluster_key_khong_phai_cot_bam(db):
    """D4/D8 — exactly one advisory lock, taken on the concatenated cluster
    key, and the bucket-hash column is not named anywhere in the module."""
    assert DEDUP_SOURCE.count("pg_advisory_xact_lock(hashtext(") == 1
    assert "event_bucket_hash" not in DEDUP_SOURCE


def test_khong_truyen_moc_thoi_gian_vao_last_seen_at(db):
    """D9 — no parameter placeholder is ever bound to `last_seen_at`, and the
    SIEM's own timestamp column is not named in the module at all, so there is
    nothing for a future edit to reach for."""
    assert re.search(r"last_seen_at\s*=\s*(%s|\$)", DEDUP_SOURCE) is None
    assert "alert_time" not in DEDUP_SOURCE
    assert "last_seen_at     = now()" in DEDUP_SOURCE
