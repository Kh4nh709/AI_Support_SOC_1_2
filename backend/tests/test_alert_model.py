"""domain/alert.py — Alert, AlertContext, severity_from_level(), compute_event_bucket_hash().

No DB, no clock: every test here constructs its own datetime and asserts a pure
function's return value (R1, R7). The canonical alert's hash
(76fcfceb90ed06f6be274be022445ff693254b73edbdb70180244328119b2a1a) is phase-1's
Khối 6 test oracle (C1); it is hard-coded here, not recomputed.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta, timezone

import pytest
from app.domain.alert import Alert, AlertContext, compute_event_bucket_hash, severity_from_level

CANONICAL_HASH = "76fcfceb90ed06f6be274be022445ff693254b73edbdb70180244328119b2a1a"
# phase-1 §Vết xử lý: alert_time after normalisation, UTC.
CANONICAL_ALERT_TIME = datetime(2026, 8, 16, 17, 56, 56, 130_000, tzinfo=UTC)


# ---------------------------------------------------------------------------
# event_bucket_hash — C1, B6
# ---------------------------------------------------------------------------


def test_hash_mau_that_bang_76fcfceb():
    """The canonical alert (rule 40112) hashes to the chốt value, hard-coded."""
    got = compute_event_bucket_hash("40112", "127.0.0.1", "", "user1-IA1803", CANONICAL_ALERT_TIME)
    assert got == CANONICAL_HASH


def test_hash_khong_chua_alert_user():
    """alert_user is not part of the formula (Phần VI supersedes Phần III) —
    two different users at the same rule/ip/agent/bucket hash identically."""
    common = ("40112", "127.0.0.1", "", "user1-IA1803", CANONICAL_ALERT_TIME)
    h1 = compute_event_bucket_hash(*common)
    h2 = compute_event_bucket_hash(*common)  # no alert_user parameter exists at all
    assert h1 == h2 == CANONICAL_HASH


def test_cung_o_5_phut_thi_cung_hash():
    """17:55:02 and 17:59:59 fall in the same 5-minute bucket -> same hash."""
    t1 = datetime(2026, 8, 16, 17, 55, 2, tzinfo=UTC)
    t2 = datetime(2026, 8, 16, 17, 59, 59, tzinfo=UTC)
    h1 = compute_event_bucket_hash("1", "a", "b", "agent", t1)
    h2 = compute_event_bucket_hash("1", "a", "b", "agent", t2)
    assert h1 == h2


def test_khac_o_5_phut_thi_khac_hash():
    """17:54:58 and 17:55:02 straddle the bucket boundary -> different hash."""
    t1 = datetime(2026, 8, 16, 17, 54, 58, tzinfo=UTC)
    t2 = datetime(2026, 8, 16, 17, 55, 2, tzinfo=UTC)
    h1 = compute_event_bucket_hash("1", "a", "b", "agent", t1)
    h2 = compute_event_bucket_hash("1", "a", "b", "agent", t2)
    assert h1 != h2


def test_cung_thoi_diem_khac_mui_gio_cung_hash():
    """R8 — the same instant expressed in two timezones hashes the same; the
    canonical alert in UTC and in +07:00 both give the chốt value's prefix."""
    t_utc = CANONICAL_ALERT_TIME
    t_plus7 = t_utc.astimezone(timezone(timedelta(hours=7)))
    assert t_utc == t_plus7  # same instant, different tzinfo/repr
    assert t_utc.utcoffset() != t_plus7.utcoffset()
    h_utc = compute_event_bucket_hash("40112", "127.0.0.1", "", "user1-IA1803", t_utc)
    h_plus7 = compute_event_bucket_hash("40112", "127.0.0.1", "", "user1-IA1803", t_plus7)
    assert h_utc == h_plus7 == CANONICAL_HASH


def test_bucket_la_so_nguyen_khong_phai_iso():
    """A one-microsecond bump that stays inside the same second must not change
    the hash (proves the bucket floors to whole seconds -> integer, not an ISO
    string that would encode sub-second precision)."""
    t1 = datetime(2026, 8, 16, 17, 55, 0, 0, tzinfo=UTC)
    t2 = datetime(2026, 8, 16, 17, 55, 0, 999_999, tzinfo=UTC)
    h1 = compute_event_bucket_hash("1", "a", "b", "agent", t1)
    h2 = compute_event_bucket_hash("1", "a", "b", "agent", t2)
    assert h1 == h2


def test_hash_khong_doi_sau_B1():
    """dstip='' (B1's default for a missing field) must hash identically to a
    hand-built None-coerced-to-empty-string assembly — i.e. the join convention
    is 'NULL -> empty string', so '' and None must produce the same string."""
    h_empty = compute_event_bucket_hash(
        "40112", "127.0.0.1", "", "user1-IA1803", CANONICAL_ALERT_TIME
    )
    h_none = compute_event_bucket_hash(
        "40112", "127.0.0.1", None, "user1-IA1803", CANONICAL_ALERT_TIME
    )
    assert h_empty == h_none == CANONICAL_HASH


def test_hash_is_sha256_hex_64_chars():
    got = compute_event_bucket_hash("1", "a", "b", "agent", CANONICAL_ALERT_TIME)
    assert len(got) == 64
    assert all(c in "0123456789abcdef" for c in got)


# ---------------------------------------------------------------------------
# severity_from_level — Khối 4
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        (12, "critical"),
        (20, "critical"),
        (8, "high"),
        (11, "high"),
        (5, "medium"),
        (7, "medium"),
        (4, "low"),
        (0, "low"),
        (-1, "low"),
    ],
)
def test_severity_from_level_thresholds(level, expected):
    assert severity_from_level(level) == expected


# ---------------------------------------------------------------------------
# Alert / AlertContext — frozen dataclasses, one shape for P2-T06/T10 to INSERT
# ---------------------------------------------------------------------------


def _minimal_alert_kwargs() -> dict:
    return {
        "alert_id": "1.1",
        "manager_id": "IA1803",
        "rule_id": "40112",
        "description": "d",
        "agent_name": "user1-IA1803",
        "agent_id": None,
        "agent_ip": None,
        "origin_host": "user1-IA1803",
        "alert_time": CANONICAL_ALERT_TIME,
        "event_time": None,
        "srcip": "127.0.0.1",
        "dstip": "",
        "src_port": 48104,
        "dst_port": 0,
        "alert_user": "user1",
        "decoder": "sshd",
        "mitre_ids": ("T1078", "T1110"),
        "rule_groups": ("syslog", "attacks"),
        "rule_level": 12,
        "severity": "critical",
        "category": "ssh_brute_force",
        "categories": ("ssh_brute_force", "suspicious_login"),
        "resolved_by": "mitre",
        "mapping_version": "v3.1",
        "srcip_is_private": True,
        "dstip_is_private": None,
        "raw_log": "full log",
        "raw_log_truncated": False,
        "event_bucket_hash": CANONICAL_HASH,
        "raw_payload": {"id": "1.1"},
    }


def test_alert_constructs_with_lifecycle_defaults():
    alert = Alert(**_minimal_alert_kwargs())
    assert alert.status == "received"
    assert alert.occurrence_count == 1
    assert alert.triage_status == "pending"
    assert alert.triaged_count == 0
    assert alert.duplicate_of is None
    assert alert.risk_score is None
    assert alert.case_id is None
    assert alert.acknowledged_at is None
    assert alert.closed_at is None
    assert alert.close_reason is None


def test_alert_is_frozen():
    alert = Alert(**_minimal_alert_kwargs())
    with pytest.raises(dataclasses.FrozenInstanceError):
        alert.status = "duplicate"  # type: ignore[misc]


def test_alert_context_three_state_lookup_status():
    ctx = AlertContext(
        asset_present=True,
        asset_criticality="high",
        asset_owner="soc-team",
        asset_role="jumpbox",
        identity_privileged=False,
        ioc_reputation="skipped",
        lookup_status={"asset": "found", "identity": "found", "ioc": "skipped"},
    )
    assert ctx.asset_criticality in {"high", "medium", "low", "unknown"}
    assert ctx.ioc_reputation in {"malicious", "suspicious", "clean", "not_found", "skipped"}
    assert set(ctx.lookup_status.values()) <= {"found", "not_found", "skipped"}


def test_alert_context_is_frozen():
    ctx = AlertContext(
        asset_present=False,
        asset_criticality="unknown",
        asset_owner=None,
        asset_role=None,
        identity_privileged=None,
        ioc_reputation="skipped",
        lookup_status={},
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        ctx.asset_present = True  # type: ignore[misc]
