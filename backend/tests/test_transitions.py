"""The 18-edge matrix for app.domain.transitions (P2 exit-gate "18 transitions tested").

`test_A<id>_ok` / `test_A<id>_fail` for every one of the 18 edges (A01-A17,
A11b) — 36 tests minimum, each `ok` case asserting the row's new status, the
columns the edge sets, and exactly the audit rows it writes; each `fail` case
asserting `StaleState` and, inside a psycopg savepoint (`conn.transaction()`),
that nothing changed. `correlation.correlated_cluster_ids` (P2-T07) does not
exist yet on this branch — every escalate test that exercises `escalate()`'s
own guard logic monkeypatches it to a fixed list, and the two tests that would
instead prove the real predicate integrates correctly are `skip`ped, named,
per the card.
"""

from __future__ import annotations

import itertools
import uuid
from datetime import UTC, datetime

import psycopg
import pytest
from app.domain import correlation
from app.domain.alert import Alert, AlertContext
from app.domain.transitions import (
    AutocloseMatch,
    IllegalTransition,
    StaleState,
    acknowledge,
    conclude_case,
    decide,
    escalate,
    finish_enrichment,
    open_alert,
    reopen,
    start_enrichment,
)
from app.infra.jobs import JOB_TYPES  # noqa: F401  (sanity: "triage" must exist)
from psycopg.types.json import Jsonb

pytestmark = pytest.mark.db

_ALERT_TIME = datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC)
_PAST = datetime(2026, 1, 1, tzinfo=UTC)

_EMPTY_CONTEXT = AlertContext(
    asset_present=False,
    asset_criticality="unknown",
    asset_owner=None,
    asset_role=None,
    identity_privileged=None,
    ioc_reputation="skipped",
    lookup_status={},
)
_SAMPLE_CONTEXT = AlertContext(
    asset_present=True,
    asset_criticality="medium",
    asset_owner="team-a",
    asset_role="workstation",
    identity_privileged=False,
    ioc_reputation="clean",
    lookup_status={"asset": "found", "ioc": "skipped"},
)

_counter = itertools.count()


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _hash(seed: str) -> str:
    import hashlib

    return hashlib.sha256(seed.encode()).hexdigest()


def _make_alert(**overrides) -> Alert:
    n = next(_counter)
    alert_id = overrides.pop("alert_id", f"alert-{n}")
    defaults = {
        "alert_id": alert_id,
        "manager_id": "IA1803",
        "rule_id": "40112",
        "description": "SSH brute force",
        "agent_name": "user1-IA1803",
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
        "category": "brute_force",
        "categories": ("brute_force",),
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
    status: str = "received",
    closed_at=None,
    sealed_at=None,
    close_reason: str | None = None,
    acknowledged_at=None,
    acknowledged_by: str | None = None,
    autoclose_rule_id: str | None = None,
    **overrides,
) -> str:
    """A direct INSERT bypassing open_alert, for setting up an arbitrary
    starting status. Covers the twelve NOT NULL-without-default columns plus
    whatever lifecycle columns the test needs."""
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
        "risk_score",
        "triage_status",
        "triaged_count",
        "case_id",
        "closed_at",
        "sealed_at",
        "close_reason",
        "acknowledged_at",
        "acknowledged_by",
        "autoclose_rule_id",
    ]
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
        alert.risk_score,
        alert.triage_status,
        alert.triaged_count,
        alert.case_id,
        closed_at,
        sealed_at,
        close_reason,
        acknowledged_at,
        acknowledged_by,
        autoclose_rule_id,
    ]
    assert len(columns) == len(values)
    placeholders = ", ".join(["%s"] * len(columns))
    conn.execute(f"INSERT INTO alerts ({', '.join(columns)}) VALUES ({placeholders})", values)
    return alert.alert_id


def _make_user(conn: psycopg.Connection, *, role: str = "tier1") -> str:
    user_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash) "
        "VALUES (%s, %s, %s, %s, 'x')",
        (user_id, f"user-{user_id[:8]}", "Test Analyst", role),
    )
    return user_id


def _make_autoclose_rule(conn: psycopg.Connection, user_id: str, **overrides) -> str:
    rule_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO autoclose_rules (autoclose_rule_id, name, match, reason, created_by) "
        "VALUES (%s, %s, %s, %s, %s)",
        (
            rule_id,
            overrides.get("name", "known-scanner"),
            Jsonb(overrides.get("match", {})),
            overrides.get("reason", "matches the known-scanner rule"),
            user_id,
        ),
    )
    return rule_id


def _make_case(
    conn: psycopg.Connection,
    user_id: str,
    *,
    status: str = "investigating",
    severity: str = "high",
    title: str = "case",
    concluded_at=None,
    concluded_by=None,
    conclusion_reason=None,
) -> str:
    case_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO cases (case_id, title, status, severity, created_by, concluded_at, "
        "concluded_by, conclusion_reason) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (case_id, title, status, severity, user_id, concluded_at, concluded_by, conclusion_reason),
    )
    return case_id


def _stringify_uuids(row):
    """psycopg returns a `uuid` column as `uuid.UUID`, not `str` — every id this
    test file hands around (user_id, case_id, autoclose_rule_id, actor_id) is a
    `str`, so every fetch normalises back to `str` to make `== some_id` mean
    what it looks like it means."""
    if row is None:
        return None
    return tuple(str(v) if isinstance(v, uuid.UUID) else v for v in row)


def _fetch(conn: psycopg.Connection, table: str, id_col: str, id_val, *cols):
    row = conn.execute(
        f"SELECT {', '.join(cols)} FROM {table} WHERE {id_col} = %s", (id_val,)
    ).fetchone()
    return _stringify_uuids(row)


def _fetch_alert(conn, alert_id, *cols):
    return _fetch(conn, "alerts", "alert_id", alert_id, *cols)


def _fetch_case(conn, case_id, *cols):
    return _fetch(conn, "cases", "case_id", case_id, *cols)


def _audit_rows(conn: psycopg.Connection, subject_id) -> list[tuple]:
    rows = conn.execute(
        "SELECT event_type, actor_role, actor_id, payload FROM audit_events "
        "WHERE subject_id = %s ORDER BY audit_id",
        (subject_id,),
    ).fetchall()
    return [_stringify_uuids(row) for row in rows]


def _pending_job(conn: psycopg.Connection, job_type: str, subject_id: str) -> int:
    return conn.execute(
        "SELECT count(*) FROM jobs WHERE job_type = %s AND subject_id = %s AND status = 'pending'",
        (job_type, subject_id),
    ).fetchone()[0]


def _no_correlation(monkeypatch):
    monkeypatch.setattr(
        correlation, "correlated_cluster_ids", lambda conn, alert: [], raising=False
    )


# ---------------------------------------------------------------------------
# A01 — open_alert(kind="received")
# ---------------------------------------------------------------------------


def test_A01_ok(db):
    alert = _make_alert()
    returned = open_alert(db, alert, kind="received", source="wazuh", suggestion_visible=True)
    assert returned == alert.alert_id
    status, closed_at, duplicate_of = _fetch_alert(
        db, alert.alert_id, "status", "closed_at", "duplicate_of"
    )
    assert status == "received"
    assert closed_at is None
    assert duplicate_of is None
    rows = _audit_rows(db, alert.alert_id)
    assert [r[0] for r in rows] == ["alert.received"]
    assert rows[0][1] == "system"
    assert rows[0][2] is None


def test_A01_fail(db):
    alert = _make_alert()
    open_alert(db, alert, kind="received", source="wazuh", suggestion_visible=True)
    with pytest.raises(StaleState), db.transaction():
        open_alert(db, alert, kind="received", source="wazuh", suggestion_visible=True)
    rows = _audit_rows(db, alert.alert_id)
    assert [r[0] for r in rows] == ["alert.received"]  # only the first insert's row


# ---------------------------------------------------------------------------
# A02 — open_alert(kind="duplicate")
# ---------------------------------------------------------------------------


def test_A02_ok(db):
    parent = _make_alert()
    open_alert(db, parent, kind="received", source="wazuh", suggestion_visible=True)
    db.execute(
        "UPDATE alerts SET occurrence_count = occurrence_count + 1 WHERE alert_id = %s",
        (parent.alert_id,),
    )
    child = _make_alert()
    open_alert(
        db,
        child,
        kind="duplicate",
        source="wazuh",
        suggestion_visible=True,
        duplicate_of=parent.alert_id,
    )
    status, dup_of, closed_at, sealed_at = _fetch_alert(
        db, child.alert_id, "status", "duplicate_of", "closed_at", "sealed_at"
    )
    assert status == "duplicate"
    assert dup_of == parent.alert_id
    assert closed_at is not None
    assert sealed_at is not None
    rows = _audit_rows(db, child.alert_id)
    assert [r[0] for r in rows] == ["alert.duplicate_merged"]
    assert rows[0][3] == {"parent": parent.alert_id, "occurrence": 2}


def test_A02_fail(db):
    parent = _make_alert()
    open_alert(db, parent, kind="received", source="wazuh", suggestion_visible=True)
    child = _make_alert()
    open_alert(
        db,
        child,
        kind="duplicate",
        source="wazuh",
        suggestion_visible=True,
        duplicate_of=parent.alert_id,
    )
    with pytest.raises(StaleState), db.transaction():
        open_alert(
            db,
            child,
            kind="duplicate",
            source="wazuh",
            suggestion_visible=True,
            duplicate_of=parent.alert_id,
        )
    assert len(_audit_rows(db, child.alert_id)) == 1


def test_open_alert_duplicate_requires_duplicate_of(db):
    alert = _make_alert()
    with pytest.raises(ValueError):
        open_alert(db, alert, kind="duplicate", source="wazuh", suggestion_visible=True)
    assert _fetch_alert(db, alert.alert_id, "status") is None


# ---------------------------------------------------------------------------
# A03 — open_alert(kind="auto_closed")
# ---------------------------------------------------------------------------


def test_A03_ok(db):
    user = _make_user(db)
    rule_row_id = _make_autoclose_rule(db, user, name="scanner", reason="matches known scanner")
    match = AutocloseMatch(rule_id=rule_row_id, name="scanner", reason="matches known scanner")
    alert = _make_alert()
    open_alert(
        db,
        alert,
        kind="auto_closed",
        source="wazuh",
        suggestion_visible=True,
        rule=match,
        context=_SAMPLE_CONTEXT,
        risk_score=5,
        risk_components={"base": 5},
    )
    status, closed_at, sealed_at, close_reason, ar_id, risk_score, asset_ctx = _fetch_alert(
        db,
        alert.alert_id,
        "status",
        "closed_at",
        "sealed_at",
        "close_reason",
        "autoclose_rule_id",
        "risk_score",
        "asset_context",
    )
    assert status == "auto_closed"
    assert closed_at is not None
    assert sealed_at is None  # M4: cluster keeps absorbing
    assert close_reason == "matches known scanner"
    assert ar_id == rule_row_id
    assert risk_score == 5
    assert asset_ctx == {
        "present": True,
        "criticality": "medium",
        "owner": "team-a",
        "role": "workstation",
    }
    rows = _audit_rows(db, alert.alert_id)
    assert [r[0] for r in rows] == ["alert.auto_closed"]
    assert rows[0][3] == {
        "rule_id": rule_row_id,
        "rule_name": "scanner",
        "reason": "matches known scanner",
    }
    assert _pending_job(db, "triage", alert.alert_id) == 1


def test_A03_fail(db):
    user = _make_user(db)
    rule_row_id = _make_autoclose_rule(db, user)
    match = AutocloseMatch(rule_id=rule_row_id, name="scanner", reason="matches known scanner")
    alert = _make_alert()
    open_alert(
        db,
        alert,
        kind="auto_closed",
        source="wazuh",
        suggestion_visible=True,
        rule=match,
    )
    with pytest.raises(StaleState), db.transaction():
        open_alert(
            db,
            alert,
            kind="auto_closed",
            source="wazuh",
            suggestion_visible=True,
            rule=match,
        )
    assert _pending_job(db, "triage", alert.alert_id) == 1  # only the first call's job


def test_open_alert_auto_closed_requires_rule(db):
    alert = _make_alert()
    with pytest.raises(ValueError):
        open_alert(db, alert, kind="auto_closed", source="wazuh", suggestion_visible=True)
    assert _fetch_alert(db, alert.alert_id, "status") is None


# ---------------------------------------------------------------------------
# A04 — start_enrichment
# ---------------------------------------------------------------------------


def test_A04_ok(db):
    alert_id = _insert_alert(db, status="received")
    start_enrichment(db, alert_id)
    assert _fetch_alert(db, alert_id, "status")[0] == "enriching"
    rows = _audit_rows(db, alert_id)
    assert [r[0] for r in rows] == ["alert.enrich_started"]
    assert rows[0][1] == "system"


def test_A04_fail(db):
    alert_id = _insert_alert(db, status="queued_tier1")
    with pytest.raises(StaleState), db.transaction():
        start_enrichment(db, alert_id)
    assert _fetch_alert(db, alert_id, "status")[0] == "queued_tier1"
    assert _audit_rows(db, alert_id) == []


# ---------------------------------------------------------------------------
# A05 — finish_enrichment (normal)
# ---------------------------------------------------------------------------


def test_A05_ok(db):
    alert_id = _insert_alert(db, status="enriching")
    finish_enrichment(
        db,
        alert_id,
        context=_SAMPLE_CONTEXT,
        risk_score=42,
        risk_components={"asset": 30, "ioc": 12},
    )
    status, risk_score, lookup_status, ioc_ctx = _fetch_alert(
        db, alert_id, "status", "risk_score", "lookup_status", "ioc_context"
    )
    assert status == "queued_tier1"
    assert risk_score == 42
    assert lookup_status == {"asset": "found", "ioc": "skipped"}
    assert ioc_ctx == {"reputation": "clean"}
    rows = _audit_rows(db, alert_id)
    assert [r[0] for r in rows] == ["alert.enriched"]
    assert _pending_job(db, "triage", alert_id) == 1


def test_A05_fail(db):
    alert_id = _insert_alert(db, status="received")
    with pytest.raises(StaleState), db.transaction():
        finish_enrichment(db, alert_id, context=_SAMPLE_CONTEXT, risk_score=1, risk_components={})
    assert _fetch_alert(db, alert_id, "status")[0] == "received"
    assert _audit_rows(db, alert_id) == []
    assert _pending_job(db, "triage", alert_id) == 0


# ---------------------------------------------------------------------------
# A06 — finish_enrichment (exhausted, empty context)
# ---------------------------------------------------------------------------


def test_A06_ok(db):
    alert_id = _insert_alert(db, status="enriching")
    finish_enrichment(
        db,
        alert_id,
        context=_EMPTY_CONTEXT,
        risk_score=0,
        risk_components={},
        exhausted=True,
    )
    status, risk_score = _fetch_alert(db, alert_id, "status", "risk_score")
    assert status == "queued_tier1"
    assert risk_score == 0
    rows = _audit_rows(db, alert_id)
    assert [r[0] for r in rows] == ["alert.enriched"]
    assert rows[0][3]["exhausted"] is True
    assert _pending_job(db, "triage", alert_id) == 1


def test_A06_fail(db):
    alert_id = _insert_alert(db, status="queued_tier1")  # already past enriching
    with pytest.raises(StaleState), db.transaction():
        finish_enrichment(
            db,
            alert_id,
            context=_EMPTY_CONTEXT,
            risk_score=0,
            risk_components={},
            exhausted=True,
        )
    assert _fetch_alert(db, alert_id, "status")[0] == "queued_tier1"
    assert _audit_rows(db, alert_id) == []


# ---------------------------------------------------------------------------
# A07 — acknowledge
# ---------------------------------------------------------------------------


def test_A07_ok(db):
    user = _make_user(db)
    alert_id = _insert_alert(db, status="queued_tier1")
    acknowledge(db, alert_id, user)
    status, ack_at, ack_by = _fetch_alert(
        db, alert_id, "status", "acknowledged_at", "acknowledged_by"
    )
    assert status == "tier1_active"
    assert ack_at is not None
    assert ack_by == user
    rows = _audit_rows(db, alert_id)
    assert [r[0] for r in rows] == ["alert.acknowledged"]
    assert rows[0][1] == "analyst"
    assert rows[0][2] == user


def test_A07_fail(db):
    """P6-2: the second acknowledger gets StaleState; the first's stamp stands."""
    user1 = _make_user(db)
    user2 = _make_user(db)
    alert_id = _insert_alert(db, status="queued_tier1")
    acknowledge(db, alert_id, user1)
    with pytest.raises(StaleState), db.transaction():
        acknowledge(db, alert_id, user2)
    status, ack_by = _fetch_alert(db, alert_id, "status", "acknowledged_by")
    assert status == "tier1_active"
    assert ack_by == user1
    assert len(_audit_rows(db, alert_id)) == 1


# ---------------------------------------------------------------------------
# A08 — decide(closed_fp)
# ---------------------------------------------------------------------------


def test_A08_ok(db):
    user = _make_user(db)
    alert_id = _insert_alert(db, status="tier1_active", occurrence_count=25)
    decide(
        db,
        alert_id,
        user,
        decision="closed_fp",
        reason="benign scanner",
        seen_occurrence_count=5,  # delta = 20, exactly the tolerance boundary
        llm_suggestion="false_positive",
        llm_confidence="high",
    )
    status, closed_at, sealed_at, close_reason, triaged_count = _fetch_alert(
        db, alert_id, "status", "closed_at", "sealed_at", "close_reason", "triaged_count"
    )
    assert status == "closed_fp"
    assert closed_at is not None
    assert sealed_at is not None
    assert close_reason == "benign scanner"
    assert triaged_count == 25
    rows = _audit_rows(db, alert_id)
    assert [r[0] for r in rows] == ["tier1.decided"]
    assert rows[0][3]["occurrence_count"] == 25
    assert rows[0][3]["llm_suggestion"] == "false_positive"


def test_A08_fail(db):
    """delta > REVIEW_DELTA_TOLERANCE (20) → StaleState carrying the current count."""
    user = _make_user(db)
    alert_id = _insert_alert(db, status="tier1_active", occurrence_count=26)
    with pytest.raises(StaleState, match="26") as exc_info, db.transaction():
        decide(
            db,
            alert_id,
            user,
            decision="closed_fp",
            reason="x",
            seen_occurrence_count=5,  # delta = 21
            llm_suggestion=None,
            llm_confidence=None,
        )
    assert "26" in str(exc_info.value)
    status = _fetch_alert(db, alert_id, "status")[0]
    assert status == "tier1_active"
    assert _audit_rows(db, alert_id) == []


# ---------------------------------------------------------------------------
# A09 — decide(closed_benign)
# ---------------------------------------------------------------------------


def test_A09_ok(db):
    user = _make_user(db)
    alert_id = _insert_alert(db, status="tier1_active", occurrence_count=3)
    decide(
        db,
        alert_id,
        user,
        decision="closed_benign",
        reason="expected activity",
        seen_occurrence_count=3,
        llm_suggestion="needs_review",
        llm_confidence="medium",
    )
    status = _fetch_alert(db, alert_id, "status")[0]
    assert status == "closed_benign"
    rows = _audit_rows(db, alert_id)
    assert [r[0] for r in rows] == ["tier1.decided"]
    assert rows[0][3]["decision"] == "closed_benign"


def test_A09_fail(db):
    """Guard fail via status: someone already decided (or moved) this alert."""
    user = _make_user(db)
    alert_id = _insert_alert(db, status="closed_fp", closed_at=_PAST, sealed_at=_PAST)
    with pytest.raises(StaleState), db.transaction():
        decide(
            db,
            alert_id,
            user,
            decision="closed_benign",
            reason="x",
            seen_occurrence_count=1,
            llm_suggestion=None,
            llm_confidence=None,
        )
    assert _fetch_alert(db, alert_id, "status")[0] == "closed_fp"
    assert _audit_rows(db, alert_id) == []


# ---------------------------------------------------------------------------
# A10 — decide's fan-out to every duplicate
# ---------------------------------------------------------------------------


def test_A10_ok(db):
    user = _make_user(db)
    root = _insert_alert(db, status="tier1_active", occurrence_count=3)
    dups = [
        _insert_alert(db, status="duplicate", duplicate_of=root, closed_at=_PAST, sealed_at=_PAST)
        for _ in range(3)
    ]
    decide(
        db,
        root,
        user,
        decision="closed_fp",
        reason="scanner",
        seen_occurrence_count=3,
        llm_suggestion=None,
        llm_confidence=None,
    )
    for dup in dups:
        status, closed_at, sealed_at, close_reason = _fetch_alert(
            db, dup, "status", "closed_at", "sealed_at", "close_reason"
        )
        assert status == "closed_fp"
        assert closed_at is not None
        assert sealed_at is not None
        assert close_reason == "scanner"
    # exactly ONE audit row for the whole cluster, not one per duplicate
    assert len(_audit_rows(db, root)) == 1
    for dup in dups:
        assert _audit_rows(db, dup) == []


def test_A10_fail(db):
    """A guard fail on the root must leave every duplicate untouched."""
    user = _make_user(db)
    root = _insert_alert(db, status="tier1_active", occurrence_count=50)
    dup = _insert_alert(db, status="duplicate", duplicate_of=root, closed_at=_PAST, sealed_at=_PAST)
    with pytest.raises(StaleState), db.transaction():
        decide(
            db,
            root,
            user,
            decision="closed_fp",
            reason="x",
            seen_occurrence_count=1,  # delta 49, way past tolerance
            llm_suggestion=None,
            llm_confidence=None,
        )
    status = _fetch_alert(db, dup, "status")[0]
    assert status == "duplicate"


# ---------------------------------------------------------------------------
# A11 — escalate (the trigger alert itself)
# ---------------------------------------------------------------------------


def test_A11_ok(db, monkeypatch):
    _no_correlation(monkeypatch)
    user = _make_user(db)
    trigger = _insert_alert(db, status="tier1_active")
    case_id = escalate(db, trigger, user, title="brute force", severity="high")

    status, sealed_at, case_id_col = _fetch_alert(db, trigger, "status", "sealed_at", "case_id")
    assert status == "escalated_tier2"
    assert sealed_at is None  # H3
    assert case_id_col == case_id

    case_status = _fetch_case(db, case_id, "status")[0]
    assert case_status == "investigating"

    heads = {
        r[0]
        for r in db.execute(
            "SELECT alert_id FROM case_alerts WHERE case_id = %s", (case_id,)
        ).fetchall()
    }
    assert heads == {trigger}

    rows = _audit_rows(db, trigger)
    assert [r[0] for r in rows] == ["tier1.escalated"]
    case_rows = _audit_rows(db, case_id)
    assert [r[0] for r in case_rows] == ["case.opened"]


def test_A11_fail(db, monkeypatch):
    """A second escalate on an alert already in a case → StaleState via the unique index."""
    _no_correlation(monkeypatch)
    user = _make_user(db)
    trigger = _insert_alert(db, status="tier1_active")
    first_case_id = escalate(db, trigger, user, title="t1", severity="high")

    with pytest.raises(StaleState), db.transaction():
        escalate(db, trigger, user, title="t2", severity="high")

    other_cases = db.execute(
        "SELECT count(*) FROM cases WHERE case_id != %s", (first_case_id,)
    ).fetchone()[0]
    assert other_cases == 0
    case_alerts_count = db.execute(
        "SELECT count(*) FROM case_alerts WHERE alert_id = %s", (trigger,)
    ).fetchone()[0]
    assert case_alerts_count == 1
    assert len(_audit_rows(db, trigger)) == 1  # only the first escalate's row


# ---------------------------------------------------------------------------
# A11b — escalate's correlated heads
# ---------------------------------------------------------------------------


def test_A11b_ok(db, monkeypatch):
    user = _make_user(db)
    trigger = _insert_alert(db, status="tier1_active")
    head2 = _insert_alert(db, status="queued_tier1")
    monkeypatch.setattr(
        correlation, "correlated_cluster_ids", lambda conn, alert: [head2], raising=False
    )

    case_id = escalate(db, trigger, user, title="t", severity="high")

    heads = {
        r[0]
        for r in db.execute(
            "SELECT alert_id FROM case_alerts WHERE case_id = %s", (case_id,)
        ).fetchall()
    }
    assert heads == {trigger, head2}
    for alert_id in (trigger, head2):
        status, sealed_at, case_id_col = _fetch_alert(
            db, alert_id, "status", "sealed_at", "case_id"
        )
        assert status == "escalated_tier2"
        assert sealed_at is None
        assert case_id_col == case_id


def test_A11b_fail(db, monkeypatch):
    """Rowcount race (N2): a correlated head's case_id is already set by
    another (simulated concurrent) transaction → StaleState, and the whole
    escalate rolls back — no new case, no case_alerts row, no audit row."""
    user = _make_user(db)
    trigger = _insert_alert(db, status="tier1_active")
    head2 = _insert_alert(db, status="queued_tier1")
    monkeypatch.setattr(
        correlation, "correlated_cluster_ids", lambda conn, alert: [head2], raising=False
    )

    other_case_id = _make_case(db, user, title="other")
    db.execute("UPDATE alerts SET case_id = %s WHERE alert_id = %s", (other_case_id, head2))

    with pytest.raises(StaleState), db.transaction():
        escalate(db, trigger, user, title="t", severity="high")

    assert db.execute("SELECT count(*) FROM cases").fetchone()[0] == 1  # only "other"
    assert db.execute("SELECT count(*) FROM case_alerts").fetchone()[0] == 0
    assert _audit_rows(db, trigger) == []
    status, case_id_col = _fetch_alert(db, trigger, "status", "case_id")
    assert status == "tier1_active"
    assert case_id_col is None
    assert _fetch_alert(db, head2, "case_id")[0] == other_case_id  # untouched


# ---------------------------------------------------------------------------
# A12 — escalate's duplicates get case_id only
# ---------------------------------------------------------------------------


def test_A12_ok(db, monkeypatch):
    """Acceptance 4: a cluster of three (trigger + two duplicates) escalates
    without violating H3 — the exact case phase-6's original ② would have
    broken (a duplicate always has sealed_at, escalated_tier2 forbids it)."""
    _no_correlation(monkeypatch)
    user = _make_user(db)
    trigger = _insert_alert(db, status="tier1_active", occurrence_count=3)
    dup1 = _insert_alert(
        db, status="duplicate", duplicate_of=trigger, closed_at=_PAST, sealed_at=_PAST
    )
    dup2 = _insert_alert(
        db, status="duplicate", duplicate_of=trigger, closed_at=_PAST, sealed_at=_PAST
    )

    case_id = escalate(db, trigger, user, title="t", severity="high")

    heads = {
        r[0]
        for r in db.execute(
            "SELECT alert_id FROM case_alerts WHERE case_id = %s", (case_id,)
        ).fetchall()
    }
    assert heads == {trigger}  # case_alerts holds heads only

    trig_status, trig_sealed = _fetch_alert(db, trigger, "status", "sealed_at")
    assert trig_status == "escalated_tier2"
    assert trig_sealed is None

    for dup in (dup1, dup2):
        dup_status, dup_case = _fetch_alert(db, dup, "status", "case_id")
        assert dup_status == "duplicate"  # A12: status untouched
        assert dup_case == case_id  # A12: case_id attached


def test_A12_fail(db, monkeypatch):
    """A failed escalate must not touch the trigger's duplicates."""
    _no_correlation(monkeypatch)
    user = _make_user(db)
    trigger = _insert_alert(db, status="tier1_active")
    dup = _insert_alert(
        db, status="duplicate", duplicate_of=trigger, closed_at=_PAST, sealed_at=_PAST
    )
    case_id = escalate(db, trigger, user, title="t", severity="high")
    assert _fetch_alert(db, dup, "case_id")[0] == case_id

    with pytest.raises(StaleState), db.transaction():
        escalate(db, trigger, user, title="t2", severity="high")

    assert _fetch_alert(db, dup, "case_id")[0] == case_id  # unchanged


def test_escalate_truncates_at_max_alerts_per_case(db, monkeypatch):
    monkeypatch.setenv("MAX_ALERTS_PER_CASE", "2")
    user = _make_user(db)
    trigger = _insert_alert(db, status="tier1_active")
    extra = [_insert_alert(db, status="queued_tier1") for _ in range(3)]
    monkeypatch.setattr(
        correlation, "correlated_cluster_ids", lambda conn, alert: extra, raising=False
    )

    case_id = escalate(db, trigger, user, title="t", severity="high")

    heads = {
        r[0]
        for r in db.execute(
            "SELECT alert_id FROM case_alerts WHERE case_id = %s", (case_id,)
        ).fetchall()
    }
    assert len(heads) == 2
    assert trigger in heads
    rows = _audit_rows(db, case_id)
    truncated = [r for r in rows if r[0] == "case.truncated"]
    assert len(truncated) == 1
    assert truncated[0][3] == {"dropped": 2}


# ---------------------------------------------------------------------------
# A13 — conclude_case(concluded_fp)
# ---------------------------------------------------------------------------


def test_A13_ok(db):
    user = _make_user(db)
    case_id = _make_case(db, user)
    head = _insert_alert(db, status="escalated_tier2", case_id=case_id)
    conclude_case(db, case_id, user, conclusion="concluded_fp", reason="false positive scanner")

    status, concluded_at, concluded_by, reason = _fetch_case(
        db, case_id, "status", "concluded_at", "concluded_by", "conclusion_reason"
    )
    assert status == "concluded_fp"
    assert concluded_at is not None
    assert concluded_by == user
    assert reason == "false positive scanner"

    head_status, head_closed, head_sealed = _fetch_alert(
        db, head, "status", "closed_at", "sealed_at"
    )
    assert head_status == "closed_fp"
    assert head_closed is not None
    assert head_sealed is not None
    rows = _audit_rows(db, case_id)
    assert [r[0] for r in rows] == ["tier2.concluded"]


def test_A13_fail(db):
    user = _make_user(db)
    case_id = _make_case(
        db,
        user,
        status="concluded_fp",
        concluded_at=_PAST,
        concluded_by=user,
        conclusion_reason="prior",
    )
    with pytest.raises(StaleState), db.transaction():
        conclude_case(db, case_id, user, conclusion="concluded_fp", reason="x")
    assert _fetch_case(db, case_id, "conclusion_reason")[0] == "prior"
    assert _audit_rows(db, case_id) == []


# ---------------------------------------------------------------------------
# A14 — conclude_case(concluded_policy_violation)
# ---------------------------------------------------------------------------


def test_A14_ok(db):
    user = _make_user(db)
    case_id = _make_case(db, user)
    head = _insert_alert(db, status="escalated_tier2", case_id=case_id)
    conclude_case(
        db, case_id, user, conclusion="concluded_policy_violation", reason="policy breach"
    )
    assert _fetch_case(db, case_id, "status")[0] == "concluded_policy_violation"
    assert _fetch_alert(db, head, "status")[0] == "closed_benign"


def test_A14_fail(db):
    user = _make_user(db)
    case_id = _make_case(
        db,
        user,
        status="confirmed_incident",
        concluded_at=_PAST,
        concluded_by=user,
        conclusion_reason="prior",
    )
    with pytest.raises(StaleState), db.transaction():
        conclude_case(db, case_id, user, conclusion="concluded_policy_violation", reason="x")
    assert _fetch_case(db, case_id, "status")[0] == "confirmed_incident"


# ---------------------------------------------------------------------------
# A15 — conclude_case(confirmed_incident)
# ---------------------------------------------------------------------------


def test_A15_ok(db):
    user = _make_user(db)
    case_id = _make_case(db, user)
    head = _insert_alert(db, status="escalated_tier2", case_id=case_id)
    conclude_case(db, case_id, user, conclusion="confirmed_incident", reason="real intrusion")
    assert _fetch_case(db, case_id, "status")[0] == "confirmed_incident"
    assert _fetch_alert(db, head, "status")[0] == "closed_confirmed"


def test_A15_fail(db):
    user = _make_user(db)
    case_id = _make_case(
        db,
        user,
        status="concluded_fp",
        concluded_at=_PAST,
        concluded_by=user,
        conclusion_reason="prior",
    )
    with pytest.raises(StaleState), db.transaction():
        conclude_case(db, case_id, user, conclusion="confirmed_incident", reason="x")
    assert _fetch_case(db, case_id, "status")[0] == "concluded_fp"


# ---------------------------------------------------------------------------
# A16 — conclude_case's fan-out to every duplicate of every head
# ---------------------------------------------------------------------------


def test_A16_ok(db):
    user = _make_user(db)
    case_id = _make_case(db, user)
    head = _insert_alert(db, status="escalated_tier2", case_id=case_id)
    dups = [
        _insert_alert(
            db,
            status="duplicate",
            duplicate_of=head,
            case_id=case_id,
            closed_at=_PAST,
            sealed_at=_PAST,
        )
        for _ in range(2)
    ]
    conclude_case(db, case_id, user, conclusion="concluded_fp", reason="scanner cluster")
    for dup in dups:
        status, closed_at, sealed_at = _fetch_alert(db, dup, "status", "closed_at", "sealed_at")
        assert status == "closed_fp"
        assert closed_at is not None
        assert sealed_at is not None


def test_A16_fail(db):
    user = _make_user(db)
    case_id = _make_case(
        db,
        user,
        status="concluded_fp",
        concluded_at=_PAST,
        concluded_by=user,
        conclusion_reason="prior",
    )
    head = _insert_alert(db, status="closed_fp", case_id=case_id, closed_at=_PAST, sealed_at=_PAST)
    dup = _insert_alert(
        db,
        status="duplicate",
        duplicate_of=head,
        case_id=case_id,
        closed_at=_PAST,
        sealed_at=_PAST,
    )
    with pytest.raises(StaleState), db.transaction():
        conclude_case(db, case_id, user, conclusion="concluded_policy_violation", reason="x")
    assert _fetch_alert(db, dup, "status")[0] == "duplicate"


# ---------------------------------------------------------------------------
# A17 — reopen
# ---------------------------------------------------------------------------


def test_A17_ok(db):
    user = _make_user(db)
    rule_row_id = _make_autoclose_rule(db, user)
    alert_id = _insert_alert(
        db,
        status="auto_closed",
        closed_at=_PAST,
        close_reason="matched scanner",
        autoclose_rule_id=rule_row_id,
    )
    reopen(db, alert_id, user, reason="analyst found it was not noise")
    status, closed_at, close_reason, ar_id = _fetch_alert(
        db, alert_id, "status", "closed_at", "close_reason", "autoclose_rule_id"
    )
    assert status == "queued_tier1"
    assert closed_at is None
    assert close_reason == "analyst found it was not noise"
    assert ar_id == rule_row_id  # kept (architecture §3.4)
    rows = _audit_rows(db, alert_id)
    assert [r[0] for r in rows] == ["alert.reopened"]
    assert rows[0][3] == {"reason": "analyst found it was not noise"}
    assert _pending_job(db, "triage", alert_id) == 0  # D8: ① already ran, no new job


def test_A17_fail(db):
    user = _make_user(db)
    alert_id = _insert_alert(db, status="received")
    with pytest.raises(StaleState), db.transaction():
        reopen(db, alert_id, user, reason="x")
    assert _fetch_alert(db, alert_id, "status")[0] == "received"
    assert _audit_rows(db, alert_id) == []


def test_reopen_requires_reason(db):
    user = _make_user(db)
    alert_id = _insert_alert(db, status="auto_closed", closed_at=_PAST)
    with pytest.raises(ValueError):
        reopen(db, alert_id, user, reason="")
    assert _fetch_alert(db, alert_id, "status")[0] == "auto_closed"
    assert _audit_rows(db, alert_id) == []


# ---------------------------------------------------------------------------
# IllegalTransition — a pair not in the table
# ---------------------------------------------------------------------------


def test_decide_illegal_transition(db):
    user = _make_user(db)
    alert_id = _insert_alert(db, status="tier1_active")
    with pytest.raises(IllegalTransition), db.transaction():
        decide(
            db,
            alert_id,
            user,
            decision="closed_confirmed",  # type: ignore[arg-type]
            reason="x",
            seen_occurrence_count=1,
            llm_suggestion=None,
            llm_confidence=None,
        )
    assert _fetch_alert(db, alert_id, "status")[0] == "tier1_active"


def test_conclude_case_illegal_transition(db):
    user = _make_user(db)
    case_id = _make_case(db, user)
    with pytest.raises(IllegalTransition), db.transaction():
        conclude_case(db, case_id, user, conclusion="bogus", reason="x")  # type: ignore[arg-type]
    assert _fetch_case(db, case_id, "status")[0] == "investigating"


# ---------------------------------------------------------------------------
# H7 — triaged_count set at decide, still 0 after acknowledge
# ---------------------------------------------------------------------------


def test_triaged_count_set_at_decide_not_acknowledge(db):
    user = _make_user(db)
    alert_id = _insert_alert(db, status="queued_tier1", occurrence_count=7)
    acknowledge(db, alert_id, user)
    assert _fetch_alert(db, alert_id, "triaged_count")[0] == 0
    decide(
        db,
        alert_id,
        user,
        decision="closed_fp",
        reason="x",
        seen_occurrence_count=7,
        llm_suggestion=None,
        llm_confidence=None,
    )
    assert _fetch_alert(db, alert_id, "triaged_count")[0] == 7


# ---------------------------------------------------------------------------
# The `triage` job exists after finish_enrichment / open_alert("auto_closed"),
# and does not after open_alert("received") / reopen.
# ---------------------------------------------------------------------------


def test_triage_job_exists_after_finish_enrichment(db):
    alert_id = _insert_alert(db, status="enriching")
    finish_enrichment(db, alert_id, context=_SAMPLE_CONTEXT, risk_score=1, risk_components={})
    assert _pending_job(db, "triage", alert_id) == 1


def test_triage_job_exists_after_auto_closed(db):
    user = _make_user(db)
    rule_row_id = _make_autoclose_rule(db, user)
    match = AutocloseMatch(rule_id=rule_row_id, name="scanner", reason="noise")
    alert = _make_alert()
    open_alert(db, alert, kind="auto_closed", source="wazuh", suggestion_visible=True, rule=match)
    assert _pending_job(db, "triage", alert.alert_id) == 1


def test_no_triage_job_after_received(db):
    alert = _make_alert()
    open_alert(db, alert, kind="received", source="wazuh", suggestion_visible=True)
    assert _pending_job(db, "triage", alert.alert_id) == 0


def test_no_triage_job_after_reopen(db):
    user = _make_user(db)
    alert_id = _insert_alert(db, status="auto_closed", closed_at=_PAST)
    reopen(db, alert_id, user, reason="reviewed, was noise")
    assert _pending_job(db, "triage", alert_id) == 0


# ---------------------------------------------------------------------------
# P2-T07 integration — skipped until domain/correlation.py merges (see report)
# ---------------------------------------------------------------------------


@pytest.mark.skip(reason="P2-T07 not merged")
def test_escalate_pulls_in_real_correlated_alerts(db):
    """Without mocking correlated_cluster_ids: an alert on the same agent
    within +/-2h should be pulled into the case as a correlated head. Proves
    the real predicate integrates once domain/correlation.py exists."""
    user = _make_user(db)
    trigger = _insert_alert(db, status="tier1_active", agent_name="shared-agent")
    _insert_alert(db, status="queued_tier1", agent_name="shared-agent")
    case_id = escalate(db, trigger, user, title="t", severity="high")
    heads = {
        r[0]
        for r in db.execute(
            "SELECT alert_id FROM case_alerts WHERE case_id = %s", (case_id,)
        ).fetchall()
    }
    assert len(heads) == 2


@pytest.mark.skip(reason="P2-T07 not merged")
def test_escalate_truncates_real_correlated_alerts_at_cap(db, monkeypatch):
    """Same as test_escalate_truncates_at_max_alerts_per_case, but against the
    real correlation query instead of a mocked return value."""
    monkeypatch.setenv("MAX_ALERTS_PER_CASE", "2")
    user = _make_user(db)
    trigger = _insert_alert(db, status="tier1_active", agent_name="busy-agent")
    for _ in range(3):
        _insert_alert(db, status="queued_tier1", agent_name="busy-agent")
    case_id = escalate(db, trigger, user, title="t", severity="high")
    heads = {
        r[0]
        for r in db.execute(
            "SELECT alert_id FROM case_alerts WHERE case_id = %s", (case_id,)
        ).fetchall()
    }
    assert len(heads) == 2
