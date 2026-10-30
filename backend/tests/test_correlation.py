"""DB tests for app.domain.correlation — summarize_for_prompt, correlated_cluster_ids.

Two read-only functions (phase-4 P4-2, phase-6 §Escalate): the grouped ±2h summary
P3's prompt builder renders, and the status-filtered cluster ids P2-T06's `escalate`
folds into a case. Every test here inserts its own fixture rows and reads them back
through the module under test — no mocking of the database (E4/E5 are properties of
real SQL, not of a stub). `TEST_DATABASE_URL=postgresql:///soc_p2t07_test` on every
invocation (DEC-023 item 8).
"""

from __future__ import annotations

import hashlib
import itertools
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from app.domain import correlation
from app.domain.alert import Alert
from app.ingest.category import PRIORITY as CATEGORY_PRIORITY

pytestmark = pytest.mark.db

_ALERT_TIME = datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC)

# docs/Schema/schema.sql ck_alerts_status, verbatim.
_STATUS_SET = frozenset(
    {
        "received",
        "duplicate",
        "auto_closed",
        "enriching",
        "queued_tier1",
        "tier1_active",
        "escalated_tier2",
        "closed_fp",
        "closed_benign",
        "closed_confirmed",
    }
)
# app.ingest.category.PRIORITY — the ten playbook categories plus 'unknown'.
_CATEGORY_SET = frozenset(CATEGORY_PRIORITY)

_counter = itertools.count()

# Who escalates, for the tests that do not care who holds what: no row is needed, because the
# sweep only compares `acknowledged_by` with it, and only on a `tier1_active` alert.
_ACTOR = "00000000-0000-4000-8000-0000000000a1"


def _user(conn: psycopg.Connection) -> str:
    """A `users` row: `alerts.acknowledged_by` is a foreign key, enforced on insert."""
    user_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash) "
        "VALUES (%s, %s, %s, 'tier1', 'x')",
        (user_id, f"user-{user_id[:8]}", "Test Analyst"),
    )
    return user_id


# ---------------------------------------------------------------------------
# Fixture helpers (pattern lifted from test_transitions.py's _make_alert /
# _insert_alert, adapted for correlation's agent_name/alert_user/srcip focus)
# ---------------------------------------------------------------------------


def _hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _make_alert(**overrides) -> Alert:
    n = next(_counter)
    alert_id = overrides.pop("alert_id", f"corr-{n}")
    defaults = {
        "alert_id": alert_id,
        "manager_id": "IA1803",
        "rule_id": "40112",
        "description": "SSH brute force",
        "agent_name": "agent-a",
        "agent_id": "001",
        "agent_ip": "10.0.0.5",
        "origin_host": "host-1",
        "alert_time": _ALERT_TIME,
        "event_time": None,
        "srcip": "203.0.113.9",
        "dstip": "10.0.0.5",
        "src_port": 22,
        "dst_port": 22,
        "alert_user": "root",
        "decoder": "sshd",
        "mitre_ids": ("T1110",),
        "rule_groups": ("authentication_failed",),
        "rule_level": 10,
        "severity": "high",
        "category": "ssh_brute_force",
        "categories": ("ssh_brute_force",),
        "resolved_by": "rule_groups",
        "mapping_version": "v1",
        "srcip_is_private": False,
        "dstip_is_private": True,
        "raw_log": "Failed password for root",
        "raw_log_truncated": False,
        "event_bucket_hash": _hash(alert_id),
        "raw_payload": {"rule": {"id": "40112"}},
    }
    defaults.update(overrides)
    return Alert(**defaults)


def _insert_alert(
    conn: psycopg.Connection,
    *,
    status: str = "queued_tier1",
    closed_at=None,
    sealed_at=None,
    close_reason: str | None = None,
    acknowledged_by: str | None = None,
    **overrides,
) -> str:
    """A direct INSERT bypassing domain/transitions.py, for setting up an
    arbitrary starting status. Covers the twelve NOT NULL-without-default
    columns (design note 6) plus whatever lifecycle columns a test needs."""
    alert = _make_alert(**overrides)
    columns = [
        "alert_id",
        "manager_id",
        "rule_id",
        "description",
        "agent_name",
        "agent_id",
        "agent_ip",
        "origin_host",
        "alert_time",
        "event_time",
        "srcip",
        "dstip",
        "src_port",
        "dst_port",
        "alert_user",
        "decoder",
        "mitre_ids",
        "rule_groups",
        "rule_level",
        "severity",
        "category",
        "categories",
        "resolved_by",
        "mapping_version",
        "srcip_is_private",
        "dstip_is_private",
        "raw_log",
        "raw_log_truncated",
        "event_bucket_hash",
        "raw_payload",
        "status",
        "duplicate_of",
        "occurrence_count",
        "case_id",
        "closed_at",
        "sealed_at",
        "close_reason",
        "acknowledged_by",
    ]
    from psycopg.types.json import Jsonb

    values = [
        alert.alert_id,
        alert.manager_id,
        alert.rule_id,
        alert.description,
        alert.agent_name,
        alert.agent_id,
        alert.agent_ip,
        alert.origin_host,
        alert.alert_time,
        alert.event_time,
        alert.srcip,
        alert.dstip,
        alert.src_port,
        alert.dst_port,
        alert.alert_user,
        alert.decoder,
        list(alert.mitre_ids),
        list(alert.rule_groups),
        alert.rule_level,
        alert.severity,
        alert.category,
        list(alert.categories),
        alert.resolved_by,
        alert.mapping_version,
        alert.srcip_is_private,
        alert.dstip_is_private,
        alert.raw_log,
        alert.raw_log_truncated,
        alert.event_bucket_hash,
        Jsonb(dict(alert.raw_payload)),
        status,
        alert.duplicate_of,
        alert.occurrence_count,
        alert.case_id,
        closed_at,
        sealed_at,
        close_reason,
        acknowledged_by,
    ]
    assert len(columns) == len(values)
    placeholders = ", ".join(["%s"] * len(columns))
    conn.execute(f"INSERT INTO alerts ({', '.join(columns)}) VALUES ({placeholders})", values)
    return alert.alert_id


@contextmanager
def _committed_alerts(dsn: str, rows: list[dict]):
    """Genuinely committed rows, visible to a fresh connection/transaction —
    needed for the READ ONLY proof, since the `db` fixture never commits.
    Cleans up on the way out."""
    conn = psycopg.connect(dsn)
    alert_ids: list[str] = []
    try:
        for row in rows:
            alert_ids.append(_insert_alert(conn, **row))
        conn.commit()
        yield alert_ids
    finally:
        try:
            conn.rollback()
            if alert_ids:
                conn.execute(
                    "DELETE FROM alerts WHERE alert_id = ANY(%s)",
                    (alert_ids,),
                )
                conn.commit()
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# 1 · the three-way OR predicate
# ---------------------------------------------------------------------------


def test_correlation_theo_agent_name(db):
    subject = _make_alert(agent_name="shared-agent", alert_user=None, srcip="")
    other = _insert_alert(db, agent_name="shared-agent", alert_user="someone-else", srcip="9.9.9.9")
    summary = correlation.summarize_for_prompt(db, subject)
    assert [r.rule_id for r in summary.rows] == ["40112"]
    ids = correlation.correlated_cluster_ids(db, subject, actor_id=_ACTOR)
    assert ids == [other]


def test_correlation_theo_alert_user(db):
    subject = _make_alert(agent_name="agent-x", alert_user="alice", srcip="")
    other = _insert_alert(db, agent_name="agent-y", alert_user="alice", srcip="9.9.9.9")
    ids = correlation.correlated_cluster_ids(db, subject, actor_id=_ACTOR)
    assert ids == [other]


def test_correlation_theo_srcip(db):
    subject = _make_alert(agent_name="agent-x", alert_user=None, srcip="198.51.100.7")
    other = _insert_alert(db, agent_name="agent-y", alert_user="bob", srcip="198.51.100.7")
    ids = correlation.correlated_cluster_ids(db, subject, actor_id=_ACTOR)
    assert ids == [other]


def test_srcip_rong_khong_tuong_quan_srcip_rong_khac(db):
    """An empty srcip (FIM/rootcheck's default) must not correlate every other
    empty-srcip alert in the window — measured, phase-4 design note."""
    subject = _make_alert(agent_name="agent-x", alert_user=None, srcip="")
    _insert_alert(db, agent_name="agent-y", alert_user="nobody", srcip="")
    ids = correlation.correlated_cluster_ids(db, subject, actor_id=_ACTOR)
    assert ids == []
    summary = correlation.summarize_for_prompt(db, subject)
    assert summary.rows == ()
    assert summary.samples == ()


def test_khong_khop_thi_khong_tuong_quan(db):
    subject = _make_alert(agent_name="agent-x", alert_user="alice", srcip="203.0.113.1")
    _insert_alert(db, agent_name="agent-z", alert_user="bob", srcip="203.0.113.99")
    assert correlation.correlated_cluster_ids(db, subject, actor_id=_ACTOR) == []
    assert correlation.summarize_for_prompt(db, subject).rows == ()


# ---------------------------------------------------------------------------
# 2 · the ±2h window
# ---------------------------------------------------------------------------


def test_cua_so_ngoai_2h_khong_duoc_tinh(db):
    subject = _make_alert(agent_name="agent-w", alert_user=None, srcip="")
    _insert_alert(
        db,
        agent_name="agent-w",
        alert_time=_ALERT_TIME - timedelta(hours=2, seconds=1),
    )
    _insert_alert(
        db,
        agent_name="agent-w",
        alert_time=_ALERT_TIME + timedelta(hours=2, seconds=1),
    )
    assert correlation.correlated_cluster_ids(db, subject, actor_id=_ACTOR) == []
    assert correlation.summarize_for_prompt(db, subject).rows == ()


def test_cua_so_dung_bien_2h_duoc_tinh(db):
    """`BETWEEN` is inclusive — exactly ±2h still counts."""
    subject = _make_alert(agent_name="agent-w", alert_user=None, srcip="")
    early = _insert_alert(db, agent_name="agent-w", alert_time=_ALERT_TIME - timedelta(hours=2))
    late = _insert_alert(db, agent_name="agent-w", alert_time=_ALERT_TIME + timedelta(hours=2))
    ids = set(correlation.correlated_cluster_ids(db, subject, actor_id=_ACTOR))
    assert ids == {early, late}


# ---------------------------------------------------------------------------
# 3 · exclusions common to both functions
# ---------------------------------------------------------------------------


def test_correlation_loai_chinh_alert_dang_xet(db):
    """The alert under consideration never correlates with itself, even
    though it trivially matches its own agent_name/srcip/window."""
    subject_id = _insert_alert(db, agent_name="agent-self", alert_id="self-1")
    subject = _make_alert(alert_id="self-1", agent_name="agent-self")
    assert subject_id == "self-1"
    assert correlation.correlated_cluster_ids(db, subject, actor_id=_ACTOR) == []
    summary = correlation.summarize_for_prompt(db, subject)
    assert summary.rows == ()
    assert summary.samples == ()


def test_correlation_loai_ban_sao(db):
    """`duplicate_of IS NOT NULL` rows (status='duplicate') never appear in
    either function's output — design note 6."""
    subject = _make_alert(agent_name="agent-d", alert_user=None, srcip="")
    parent = _insert_alert(db, agent_name="agent-d", status="queued_tier1")
    _insert_alert(
        db,
        agent_name="agent-d",
        status="duplicate",
        duplicate_of=parent,
        closed_at=_ALERT_TIME,
        sealed_at=_ALERT_TIME,
    )
    ids = correlation.correlated_cluster_ids(db, subject, actor_id=_ACTOR)
    assert ids == [parent]
    summary = correlation.summarize_for_prompt(db, subject)
    assert {r.cluster_count for r in summary.rows} == {1}
    sample_ids = {s["alert_id"] for s in summary.samples}
    assert sample_ids == {parent}


def _insert_archived(db, **overrides) -> str:
    """An alert the archive (INT-T03, DEC-212) closed out: sealed, with a reason, never a decision."""
    return _insert_alert(
        db,
        status="archived",
        closed_at=_ALERT_TIME,
        sealed_at=_ALERT_TIME,
        close_reason="DEC-212",
        **overrides,
    )


def test_correlation_loai_alert_da_luu_tru(db):
    """INT-T03 / DEC-212: an archived alert is neither in ①'s grouped rows nor among its samples.
    `status` of a row is rendered as an `AlertStatus` fact, which has no `archived`; and an archived
    alert is not "in play" for the analyst the prompt describes. It has the highest
    `occurrence_count`, so it would head both lists if it were let in."""
    subject = _make_alert(agent_name="agent-arch", alert_user=None, srcip="")
    kept = _insert_alert(db, agent_name="agent-arch", status="queued_tier1")
    _insert_archived(db, agent_name="agent-arch", occurrence_count=5000, rule_id="99999")
    _insert_archived(db, agent_name="agent-arch", alert_user="someone")

    summary = correlation.summarize_for_prompt(db, subject)

    assert [(r.rule_id, r.status, r.cluster_count) for r in summary.rows] == [
        ("40112", "queued_tier1", 1)
    ]
    assert {s["alert_id"] for s in summary.samples} == {kept}
    assert all(s["status"] != "archived" for s in summary.samples)


def test_correlation_ca_ba_dong_deu_luu_tru_thi_khong_con_gi(db):
    """The window holds nothing but archived alerts: the summary is empty, as for a quiet agent."""
    subject = _make_alert(agent_name="agent-arch2", alert_user=None, srcip="")
    _insert_archived(db, agent_name="agent-arch2")
    summary = correlation.summarize_for_prompt(db, subject)
    assert summary.rows == () and summary.samples == ()


def test_correlated_cluster_ids_khong_tra_alert_da_luu_tru(db):
    """`escalate` folds only open heads into a case: an archived one is never swept in, however busy
    (A11b already takes only `queued_tier1` / `tier1_active`; this pins that it stays so)."""
    subject = _make_alert(agent_name="agent-arch3", alert_user=None, srcip="")
    me = _user(db)
    kept = _insert_alert(db, agent_name="agent-arch3", status="tier1_active", acknowledged_by=me)
    _insert_archived(db, agent_name="agent-arch3", occurrence_count=5000)
    _insert_archived(db, agent_name="agent-arch3", acknowledged_by=me)
    assert correlation.correlated_cluster_ids(db, subject, actor_id=me) == [kept]


def test_correlation_loai_duplicate_of_rieng_biet_voi_status(db):
    """`duplicate_of IS NULL` is its own clause, not just a restatement of
    `status <> 'duplicate'` — a row with `duplicate_of` set but a
    non-'duplicate' status (not a shape the real pipeline produces, but not
    forbidden by the DB CHECKs either) must still be excluded by it. Without
    this clause in the predicate, `test_correlation_loai_ban_sao` above would
    still pass (its duplicate row is *also* caught by the status filters),
    which is exactly the kind of guard-that-cannot-fail DEC-027 warns about."""
    subject = _make_alert(agent_name="agent-dd", alert_user=None, srcip="")
    parent = _insert_alert(db, agent_name="agent-dd", status="queued_tier1")
    _insert_alert(
        db,
        agent_name="agent-dd",
        status="queued_tier1",  # deliberately NOT 'duplicate'
        duplicate_of=parent,
    )
    assert correlation.correlated_cluster_ids(db, subject, actor_id=_ACTOR) == [parent]
    summary = correlation.summarize_for_prompt(db, subject)
    assert {r.cluster_count for r in summary.rows} == {1}


# ---------------------------------------------------------------------------
# 4 · summarize_for_prompt — grouping, cap, ordering, samples
# ---------------------------------------------------------------------------


def _busy_agent(db) -> tuple[Alert, list[str]]:
    """25 distinct (rule_id, category, status) groups on one busy agent — the
    top 5 split into two alerts each (cluster_count=2) so aggregation is
    exercised too — for 30 heads total across >=3 rules (design note 6), plus
    a handful of duplicate rows folded under one of the heads."""
    subject = _make_alert(agent_name="busy-agent", alert_user=None, srcip="")
    categories = list(CATEGORY_PRIORITY)
    all_ids: list[str] = []
    for i in range(25):
        target_sum = i + 1
        rule_id = f"rule-{i:03d}"
        category = categories[i % len(categories)]
        if i >= 20:  # top five groups by alert_count: two alerts each
            first_count = target_sum - 1
            all_ids.append(
                _insert_alert(
                    db,
                    agent_name="busy-agent",
                    rule_id=rule_id,
                    category=category,
                    categories=(category,),
                    occurrence_count=first_count,
                    status="queued_tier1",
                )
            )
            all_ids.append(
                _insert_alert(
                    db,
                    agent_name="busy-agent",
                    rule_id=rule_id,
                    category=category,
                    categories=(category,),
                    occurrence_count=1,
                    status="queued_tier1",
                )
            )
        else:
            all_ids.append(
                _insert_alert(
                    db,
                    agent_name="busy-agent",
                    rule_id=rule_id,
                    category=category,
                    categories=(category,),
                    occurrence_count=target_sum,
                    status="queued_tier1",
                )
            )
    # duplicates folded under the very first head — must never appear anywhere.
    dup_parent = all_ids[0]
    for _ in range(3):
        _insert_alert(
            db,
            agent_name="busy-agent",
            rule_id="rule-000",
            category=categories[0],
            categories=(categories[0],),
            status="duplicate",
            duplicate_of=dup_parent,
            occurrence_count=999,
            closed_at=_ALERT_TIME,
            sealed_at=_ALERT_TIME,
        )
    return subject, all_ids


def test_tom_tat_gop_khong_qua_20_dong(db):
    """E5 — the grouped summary never exceeds 20 rows, even with 25 candidate
    groups and 30+ heads on one busy agent."""
    subject, _ = _busy_agent(db)
    summary = correlation.summarize_for_prompt(db, subject)
    assert len(summary.rows) == 20


def test_tom_tat_gop_thu_tu_giam_dan_theo_so_alert(db):
    subject, _ = _busy_agent(db)
    summary = correlation.summarize_for_prompt(db, subject)
    sums = [r.alert_count for r in summary.rows]
    assert sums == sorted(sums, reverse=True)
    # groups 0..4 (alert_count 1..5) are the ones LIMIT 20 must drop.
    assert min(sums) == 6
    assert max(sums) == 25


def test_tom_tat_gop_cluster_count_dung(db):
    subject, _ = _busy_agent(db)
    summary = correlation.summarize_for_prompt(db, subject)
    by_sum = {r.alert_count: r.cluster_count for r in summary.rows}
    assert by_sum[25] == 2  # a top-five group: two alerts, occurrence_count 24+1
    assert by_sum[10] == 1  # a non-split group: one alert, occurrence_count 10


def test_tom_tat_hang_la_tap_dong_status_va_category(db):
    """Acceptance 7 — every returned row's `status`/`category` is in the
    DB-CHECKed / closed-set vocabulary; free text lives only in samples."""
    subject, _ = _busy_agent(db)
    summary = correlation.summarize_for_prompt(db, subject)
    assert summary.rows, "fixture must produce at least one row"
    for row in summary.rows:
        assert row.status in _STATUS_SET, row.status
        assert row.category in _CATEGORY_SET, row.category
    assert not hasattr(summary.rows[0], "description")
    assert not hasattr(summary.rows[0], "raw_log")


def test_tom_tat_mau_toi_da_5_va_thu_tu(db):
    """Up to 5 samples, ordered by occurrence_count desc then alert_time desc
    (design note 1: 'newest heads with the highest occurrence_count')."""
    subject, _ = _busy_agent(db)
    summary = correlation.summarize_for_prompt(db, subject)
    assert len(summary.samples) == 5
    counts = [s["occurrence_count"] for s in summary.samples]
    assert counts == sorted(counts, reverse=True)
    assert counts[0] == 24  # highest single occurrence_count in the fixture


def test_tom_tat_mau_co_cot_ro_rang(db):
    subject = _make_alert(agent_name="agent-cols", alert_user=None, srcip="")
    _insert_alert(db, agent_name="agent-cols", description="d", raw_log="r")
    summary = correlation.summarize_for_prompt(db, subject)
    assert len(summary.samples) == 1
    assert set(summary.samples[0].keys()) == {
        "alert_id",
        "rule_id",
        "category",
        "severity",
        "status",
        "occurrence_count",
        "alert_time",
        "description",
        "raw_log",
    }
    assert summary.samples[0]["description"] == "d"
    assert summary.samples[0]["raw_log"] == "r"


# ---------------------------------------------------------------------------
# 5 · correlated_cluster_ids — the four status exclusions + the cap
# ---------------------------------------------------------------------------


def test_correlated_cluster_ids_tra_queued_tier1_va_tier1_active(db):
    subject = _make_alert(agent_name="agent-e", alert_user=None, srcip="")
    me = _user(db)
    a = _insert_alert(db, agent_name="agent-e", status="queued_tier1")
    b = _insert_alert(db, agent_name="agent-e", status="tier1_active", acknowledged_by=me)
    ids = set(correlation.correlated_cluster_ids(db, subject, actor_id=me))
    assert ids == {a, b}


def test_correlated_cluster_ids_khong_tra_auto_closed(db):
    subject = _make_alert(agent_name="agent-f", alert_user=None, srcip="")
    _insert_alert(
        db,
        agent_name="agent-f",
        status="auto_closed",
        closed_at=_ALERT_TIME,
        occurrence_count=5000,  # a busy scanner: must not out-rank real alerts
    )
    kept = _insert_alert(db, agent_name="agent-f", status="queued_tier1")
    assert correlation.correlated_cluster_ids(db, subject, actor_id=_ACTOR) == [kept]


def test_correlated_cluster_ids_khong_tra_alert_da_ket_luan(db):
    """closed_fp / closed_benign / closed_confirmed — another analyst's
    conclusion is never overwritten by a later escalate."""
    subject = _make_alert(agent_name="agent-g", alert_user=None, srcip="")
    for status in ("closed_fp", "closed_benign", "closed_confirmed"):
        _insert_alert(
            db,
            agent_name="agent-g",
            status=status,
            closed_at=_ALERT_TIME,
            sealed_at=_ALERT_TIME,
        )
    me = _user(db)
    kept = _insert_alert(db, agent_name="agent-g", status="tier1_active", acknowledged_by=me)
    assert correlation.correlated_cluster_ids(db, subject, actor_id=me) == [kept]


def test_correlated_cluster_ids_khong_tra_alert_chua_enrich(db):
    """`received`/`enriching` — a cluster still mid-pipeline is not yet a
    Tier-1 candidate; A5's single exit stays the only way out (kien-truc A5)."""
    subject = _make_alert(agent_name="agent-h", alert_user=None, srcip="")
    _insert_alert(db, agent_name="agent-h", status="received")
    _insert_alert(db, agent_name="agent-h", status="enriching")
    kept = _insert_alert(db, agent_name="agent-h", status="queued_tier1")
    assert correlation.correlated_cluster_ids(db, subject, actor_id=_ACTOR) == [kept]


def test_correlated_cluster_ids_khong_tra_alert_dang_o_case_khac(db):
    """escalated_tier2 (already claimed by another case) is never re-pulled —
    its `case_id` must not be stolen by a second escalate (N2)."""
    subject = _make_alert(agent_name="agent-i", alert_user=None, srcip="")
    _insert_alert(db, agent_name="agent-i", status="escalated_tier2")
    kept = _insert_alert(db, agent_name="agent-i", status="queued_tier1")
    assert correlation.correlated_cluster_ids(db, subject, actor_id=_ACTOR) == [kept]


def test_correlated_cluster_ids_thu_tu_giam_dan_theo_occurrence_count(db):
    subject = _make_alert(agent_name="agent-j", alert_user=None, srcip="")
    low = _insert_alert(db, agent_name="agent-j", status="queued_tier1", occurrence_count=1)
    high = _insert_alert(db, agent_name="agent-j", status="queued_tier1", occurrence_count=9)
    assert correlation.correlated_cluster_ids(db, subject, actor_id=_ACTOR) == [high, low]


def test_correlated_cluster_ids_gioi_han_max_alerts_per_case(db, monkeypatch):
    """Reads `Config.MAX_ALERTS_PER_CASE`, not a literal — the cut binds at
    whatever the environment sets it to."""
    monkeypatch.setenv("MAX_ALERTS_PER_CASE", "3")
    subject = _make_alert(agent_name="agent-k", alert_user=None, srcip="")
    ids = [
        _insert_alert(db, agent_name="agent-k", status="queued_tier1", occurrence_count=n)
        for n in range(1, 6)
    ]
    result = correlation.correlated_cluster_ids(db, subject, actor_id=_ACTOR)
    assert len(result) == 3
    # the cut keeps the highest occurrence_count heads, not an arbitrary three.
    assert set(result) == {ids[4], ids[3], ids[2]}


def test_correlated_cluster_ids_hoa_tie_break_chon_alert_moi_nhat_moi_lan_chay(db, monkeypatch):
    """DEC-165 tie-break. Five identical heads (same occurrence_count = 1, the
    shape every alert has with `DEDUP_ENABLED=false`), a cap of 2: the two
    NEWEST by `alert_time` are kept, in that order, on every run. They are
    inserted oldest-first so a physical-order pick (what an `ORDER BY
    occurrence_count DESC` alone gives on ties) would choose the two oldest."""
    monkeypatch.setenv("MAX_ALERTS_PER_CASE", "2")
    subject = _make_alert(agent_name="agent-tb", alert_user=None, srcip="")
    ids = [
        _insert_alert(
            db,
            alert_id=f"tb-time-{n}",
            agent_name="agent-tb",
            status="queued_tier1",
            occurrence_count=1,
            alert_time=_ALERT_TIME + timedelta(minutes=n),
        )
        for n in range(5)
    ]
    expected = [ids[4], ids[3]]
    for _ in range(5):
        assert correlation.correlated_cluster_ids(db, subject, actor_id=_ACTOR) == expected


def test_correlated_cluster_ids_hoa_tie_break_cuoi_cung_la_alert_id_tang_dan(db, monkeypatch):
    """Same `occurrence_count` AND same `alert_time`: `alert_id ASC` decides, so
    the choice never depends on heap order. Inserted in descending id order so
    that physical order is the opposite of the expected answer."""
    monkeypatch.setenv("MAX_ALERTS_PER_CASE", "2")
    subject = _make_alert(agent_name="agent-tb2", alert_user=None, srcip="")
    for n in (4, 3, 2, 1, 0):
        _insert_alert(
            db,
            alert_id=f"tb-id-{n}",
            agent_name="agent-tb2",
            status="queued_tier1",
            occurrence_count=1,
            alert_time=_ALERT_TIME,
        )
    for _ in range(5):
        assert correlation.correlated_cluster_ids(db, subject, actor_id=_ACTOR) == [
            "tb-id-0",
            "tb-id-1",
        ]


def test_cluster_ids_query_order_by_la_occurrence_time_roi_alert_id():
    """The statement itself carries the full deterministic order (DEC-165) — a
    text-level pin so a revert is caught even where a small seed happens to
    return the right rows by luck."""
    subject = _make_alert(agent_name="agent-tb3", alert_user=None, srcip="")
    sql, _params = correlation.cluster_ids_query(subject, 2, actor_id=_ACTOR)
    normalized = " ".join(sql.split())
    assert "ORDER BY occurrence_count DESC, alert_time DESC, alert_id ASC LIMIT" in normalized


# ---------------------------------------------------------------------------
# 5b · DEC-166 — a `tier1_active` alert another analyst holds is never swept
# ---------------------------------------------------------------------------


def test_correlated_cluster_ids_khong_tra_alert_nguoi_khac_dang_giu(db):
    """The sweep folds `queued_tier1` and the alerts the escalating analyst holds, and leaves
    alone an alert another analyst acknowledged: escalating must not take it out of their hands."""
    subject = _make_alert(agent_name="agent-held", alert_user=None, srcip="")
    me, other = _user(db), _user(db)
    queued = _insert_alert(db, agent_name="agent-held", status="queued_tier1")
    mine = _insert_alert(db, agent_name="agent-held", status="tier1_active", acknowledged_by=me)
    _insert_alert(db, agent_name="agent-held", status="tier1_active", acknowledged_by=other)
    assert set(correlation.correlated_cluster_ids(db, subject, actor_id=me)) == {queued, mine}


def test_correlated_cluster_ids_nguoi_giu_la_nguoi_leo_thang_thi_van_quet(db):
    """The exclusion is by holder, not by status: the same alert is swept for its own holder and
    left alone for anyone else."""
    subject = _make_alert(agent_name="agent-held2", alert_user=None, srcip="")
    holder, stranger = _user(db), _user(db)
    held = _insert_alert(
        db, agent_name="agent-held2", status="tier1_active", acknowledged_by=holder
    )
    assert correlation.correlated_cluster_ids(db, subject, actor_id=holder) == [held]
    assert correlation.correlated_cluster_ids(db, subject, actor_id=stranger) == []


def test_correlated_cluster_ids_tier1_active_khong_ro_nguoi_giu_thi_khong_quet(db):
    """A `tier1_active` row with no recorded holder (A7 always records one, the schema does not
    insist) is not provably the escalating analyst's: it is left alone, the conservative side."""
    subject = _make_alert(agent_name="agent-held3", alert_user=None, srcip="")
    _insert_alert(db, agent_name="agent-held3", status="tier1_active", acknowledged_by=None)
    assert correlation.correlated_cluster_ids(db, subject, actor_id=_user(db)) == []


def test_alert_nguoi_khac_giu_khong_chiem_cho_trong_gioi_han(db, monkeypatch):
    """The exclusion is in the SQL, before the cap: a held-by-other alert that would out-rank
    every candidate does not use up a place at `MAX_ALERTS_PER_CASE`."""
    monkeypatch.setenv("MAX_ALERTS_PER_CASE", "2")
    subject = _make_alert(agent_name="agent-held4", alert_user=None, srcip="")
    me, other = _user(db), _user(db)
    _insert_alert(
        db,
        agent_name="agent-held4",
        status="tier1_active",
        acknowledged_by=other,
        occurrence_count=50,
    )
    kept = [
        _insert_alert(db, agent_name="agent-held4", status="queued_tier1", occurrence_count=n)
        for n in (3, 2)
    ]
    assert correlation.correlated_cluster_ids(db, subject, actor_id=me) == kept


def test_cluster_ids_query_loai_alert_nguoi_khac_giu_va_buoc_actor_id():
    """A text-level pin, as for the order: the statement carries the exclusion and binds the
    actor, and the actor is required (a caller that forgets it is a `TypeError`, never a sweep
    that quietly takes another analyst's alert)."""
    subject = _make_alert(agent_name="agent-tb4", alert_user=None, srcip="")
    sql, params = correlation.cluster_ids_query(subject, 2, actor_id=_ACTOR)
    normalized = " ".join(sql.split())
    assert (
        "AND NOT (status = 'tier1_active' AND acknowledged_by IS DISTINCT FROM "
        "%(actor_id)s::uuid)" in normalized
    )
    assert params["actor_id"] == _ACTOR
    with pytest.raises(TypeError):
        correlation.cluster_ids_query(subject, 2)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        correlation.correlated_cluster_ids(None, subject)  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# 6 · E4 — read-only, enforced
# ---------------------------------------------------------------------------


def test_correlation_khong_ghi_xuong_bang_nao(_test_database):
    """Both functions run to completion inside a `READ ONLY` transaction — a
    write would raise `psycopg.errors.ReadOnlySqlTransaction` (E4 as a test,
    not only a review note)."""
    with _committed_alerts(
        _test_database,
        [
            {"agent_name": "ro-agent", "status": "queued_tier1"},
            {"agent_name": "ro-agent", "status": "queued_tier1", "occurrence_count": 2},
        ],
    ) as alert_ids:
        subject = _make_alert(agent_name="ro-agent", alert_user=None, srcip="")
        conn = psycopg.connect(_test_database)
        try:
            conn.execute("SET TRANSACTION READ ONLY")
            summary = correlation.summarize_for_prompt(conn, subject)
            ids = correlation.correlated_cluster_ids(conn, subject, actor_id=_ACTOR)
            conn.rollback()
        finally:
            conn.close()
        assert set(ids) == set(alert_ids)
        assert {s["alert_id"] for s in summary.samples} == set(alert_ids)


# ---------------------------------------------------------------------------
# 7 · EXPLAIN — the three v1 correlation indexes carry the query
# ---------------------------------------------------------------------------

_INDEX_NAMES = ("ix_alerts_corr_agent", "ix_alerts_corr_srcip", "ix_alerts_corr_user")


@contextmanager
def _seeded_correlation_table(dsn: str, seed: int):
    """200 rows, independently and reproducibly scattered (a fixed-seed local
    `Random`, not the global module) across 20 distinct values per column —
    phase-4's own 'agent bận' scenario at a size pytest can afford.

    Genuinely `COMMIT`ted, then `ANALYZE`d, on purpose: PostgreSQL's ANALYZE
    updates `pg_class.reltuples`/`relpages` via an in-place write that survives
    a later `ROLLBACK` of the transaction that issued it (measured) — so
    calling it inside the `db` fixture's never-committed transaction would
    leave *permanent*, data-less statistics behind for whatever test runs
    next. Committing first, and re-`ANALYZE`ing after cleanup, keeps this
    test's plan choice deterministic without leaking a stale table-size guess
    into any other test's.
    """
    import random

    conn = psycopg.connect(dsn)
    rnd = random.Random(seed)
    agents = [f"agent-{i}" for i in range(20)]
    users = [f"user-{i}" for i in range(20)]
    ips = [f"10.0.{i}.5" for i in range(20)]
    alert_ids: list[str] = []
    try:
        for _ in range(200):
            alert_ids.append(
                _insert_alert(
                    conn,
                    agent_name=rnd.choice(agents),
                    alert_user=rnd.choice(users),
                    srcip=rnd.choice(ips),
                    status="queued_tier1",
                )
            )
        conn.commit()
        conn.execute("ANALYZE alerts")
        conn.commit()
        yield conn
    finally:
        try:
            conn.rollback()
            if alert_ids:
                conn.execute("DELETE FROM alerts WHERE alert_id = ANY(%s)", (alert_ids,))
                conn.commit()
                conn.execute("ANALYZE alerts")
                conn.commit()
        finally:
            conn.close()


def _explain(conn, sql: str, params: dict) -> str:
    conn.execute("SET LOCAL enable_seqscan = off")
    rows = conn.execute("EXPLAIN " + sql, params).fetchall()
    return "\n".join(row[0] for row in rows)


def test_explain_dung_bitmapor_ba_index(_test_database):
    """Phase-4 measured a `BitmapOr` over the three indexes at 3,000 rows;
    design note 4 says not to trust a literal near-empty table (there the
    planner's plan choice is an artifact of missing statistics, not a real
    answer — measured: it flips between a `BitmapOr` and a plain single-index
    scan depending on incidental table statistics, not on index-ability). So
    this seeds a real, committed, `ANALYZE`d table and asks the one question
    that matters under `enable_seqscan = off`: are the three predicates
    index-able at all."""
    with _seeded_correlation_table(_test_database, seed=42) as conn:
        subject = _make_alert(agent_name="agent-1", alert_user="user-1", srcip="10.0.1.5")
        sql, params = correlation.cluster_ids_query(subject, 200, actor_id=_ACTOR)
        plan = _explain(conn, sql, params)
        assert "BitmapOr" in plan, plan
        for name in _INDEX_NAMES:
            assert name in plan, plan


def test_explain_bien_the_received_at_khong_dung_index(_test_database):
    """Red demonstration for design note 4/P4-5: swap `alert_time` for
    `received_at` in the same predicate, on the same seeded+analyzed table,
    and the three index names disappear (the planner reaches for
    `ix_alerts_received_at` instead) — proving the real module (which uses
    `alert_time`) is the reason they show up in the test above, not an
    artifact of the table's other indexes."""
    with _seeded_correlation_table(_test_database, seed=42) as conn:
        subject = _make_alert(agent_name="agent-1", alert_user="user-1", srcip="10.0.1.5")
        sql, params = correlation.cluster_ids_query(subject, 200, actor_id=_ACTOR)
        bad_sql = sql.replace("alert_time BETWEEN", "received_at BETWEEN")
        assert bad_sql != sql
        plan = _explain(conn, bad_sql, params)
        for name in _INDEX_NAMES:
            assert name not in plan, plan
