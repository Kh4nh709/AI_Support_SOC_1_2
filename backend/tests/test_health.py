"""`backend/tests/test_health.py` — P5-T11, `app.infra.health` + the `health`
handler + `GET /health`.

Design note 7: each of the ten §3.9 checks simulated on both sides (a
"fire" test and a "pass" test — twenty cases), `notify.send` faked via
monkeypatch so no test here reaches a real Telegram bot API. `checked_at`
is read through `check()`'s injectable `clock` seam
(`infra/health.py`'s own docstring explains why: Postgres's `now()` cannot be
frozen from a test without a server-side extension, and the 17:00/08:05
local-time boundaries need to be deterministic on both sides).
"""

from __future__ import annotations

import hashlib
import itertools
import os
import shutil
import subprocess
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import psycopg
import pytest
from app.infra import auth, health, notify
from app.infra.config import Config
from app.infra.jobs import JOB_TYPES, Job
from app.web import deps, main
from app.web.handlers import health as health_handler
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from tests import conftest

pytestmark = pytest.mark.db

REPO_ROOT = Path(__file__).resolve().parents[2]

_alert_seq = itertools.count()

# A fixed local morning (Asia/Ho_Chi_Minh, UTC+7) well before both gates
# (17:00 digest, 08:05 summary) unless a test moves it on purpose.
_MORNING_UTC = datetime(2026, 9, 29, 0, 30, 0, tzinfo=UTC)  # 07:30 local — before both gates


def _cfg(**overrides) -> Config:
    return replace(Config(), **overrides)


def _clock_at(dt: datetime):
    return lambda conn: dt


def _by_name(report: health.HealthReport) -> dict[str, health.CheckResult]:
    return {c.name: c for c in report.checks}


def _fake_notify(monkeypatch) -> list[tuple[str, str]]:
    calls: list[tuple[str, str]] = []

    def fake_send(level: str, text: str, **kwargs) -> bool:
        calls.append((level, text))
        return True

    monkeypatch.setattr(notify, "send", fake_send)
    return calls


def _levels(sent: list[tuple[str, str]]) -> list[str]:
    return [level for level, _ in sent]


def _seed_asset(conn, hostname: str = "host-ok") -> None:
    conn.execute(
        "INSERT INTO assets (hostname, criticality) VALUES (%s, 'low') "
        "ON CONFLICT (hostname) DO NOTHING",
        (hostname,),
    )


def _seed_heartbeat(conn, *, minutes_ago: float, manager_id: str = "indexer") -> None:
    conn.execute(
        """
        INSERT INTO source_heartbeat (manager_id, last_seen_at)
        VALUES (%s, now() - (%s * interval '1 minute'))
        ON CONFLICT (manager_id) DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at
        """,
        (manager_id, minutes_ago),
    )


def _write_backup(backups_dir: Path, *, name: str = "soc-20260929T000000Z.dump") -> Path:
    backups_dir.mkdir(parents=True, exist_ok=True)
    path = backups_dir / name
    path.write_bytes(b"pg_dump placeholder")
    return path


def _seed_all_ok(conn, backups_dir: Path) -> None:
    """Every one of the ten checks passes: fresh heartbeat, no intake/job
    backlog rows, no `llm_runs`, a fresh backup file, one asset. Callers pass
    `clock=_clock_at(_MORNING_UTC)` (or later) so check 9 stays gated off."""
    _seed_heartbeat(conn, minutes_ago=1)
    _seed_asset(conn)
    _write_backup(backups_dir)


def _insert_alert(conn, **overrides) -> str:
    """The columns `alerts` needs with no default (`test_transitions.py`'s
    `_insert_alert` is the full-column precedent this trims to what checks 5
    and 9 read: `triage_status`, `received_at`, `status`, `closed_at`)."""
    n = next(_alert_seq)
    alert_id = overrides.pop("alert_id", f"health-alert-{n}")
    received_at = overrides.pop("received_at", None)
    closed_at = overrides.pop("closed_at", None)
    fields = {
        "alert_id": alert_id,
        "rule_id": "40112",
        "rule_level": 10,
        "severity": "high",
        "description": "test alert",
        "agent_name": "host-1",
        "alert_time": datetime.now(UTC),
        "category": "brute_force",
        "resolved_by": "rule_groups",
        "mapping_version": "v1",
        "event_bucket_hash": hashlib.sha256(alert_id.encode()).hexdigest(),
        "raw_payload": Jsonb({}),
        "status": "received",
        "triage_status": "pending",
    }
    fields.update(overrides)
    columns = list(fields)
    values = list(fields.values())
    if received_at is not None:
        columns.append("received_at")
        values.append(received_at)
    if closed_at is not None:
        columns.append("closed_at")
        values.append(closed_at)
    placeholders = ", ".join(["%s"] * len(columns))
    conn.execute(f"INSERT INTO alerts ({', '.join(columns)}) VALUES ({placeholders})", values)
    return alert_id


def _insert_llm_run(
    conn, *, created_at: datetime, result=None, cost_usd=None, subject_id="a1"
) -> None:
    conn.execute(
        """
        INSERT INTO llm_runs
          (run_id, pipeline, subject_type, subject_id, system_prompt, user_message,
           result, cost_usd, created_at)
        VALUES (%s, 'triage', 'alert', %s, 's', 'u', %s, %s, %s)
        """,
        (
            str(uuid.uuid4()),
            subject_id,
            Jsonb(result) if result is not None else None,
            cost_usd,
            created_at,
        ),
    )


def _insert_pending_job(conn, *, minutes_ago: float, subject_id: str | None = None) -> None:
    conn.execute(
        """
        INSERT INTO jobs (job_type, subject_id, status, scheduled_at)
        VALUES ('health', %s, 'pending', now() - (%s * interval '1 minute'))
        """,
        (subject_id or f"job-{next(_alert_seq)}", minutes_ago),
    )


def _insert_intake_pending(conn, *, minutes_ago: float) -> None:
    conn.execute(
        """
        INSERT INTO intake (manager_id, source_alert_id, raw_text, via, received_at)
        VALUES ('IA1803', %s, '{}', 'pull', now() - (%s * interval '1 minute'))
        """,
        (f"intake-{next(_alert_seq)}", minutes_ago),
    )


def _insert_autoclose_review(conn, alert_id: str) -> None:
    conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash) "
        "VALUES (gen_random_uuid(), %s, 'Reviewer', 'admin', 'x') "
        "ON CONFLICT (username) DO NOTHING RETURNING user_id",
        (f"reviewer-{next(_alert_seq)}",),
    )
    (reviewer_id,) = conn.execute("SELECT user_id FROM users LIMIT 1").fetchone()
    conn.execute(
        "INSERT INTO autoclose_reviews (alert_id, reviewer_id, verdict) VALUES (%s, %s, 'correct')",
        (alert_id, reviewer_id),
    )


# ===========================================================================
# the ten checks — fire / pass, twenty cases (design note 7)
# ===========================================================================


# 1 · heartbeat ---------------------------------------------------------------


@pytest.mark.db
def test_heartbeat_fires_when_stale(db, tmp_path):
    _seed_heartbeat(db, minutes_ago=45)
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    assert _by_name(report)["heartbeat"].ok is False


@pytest.mark.db
def test_heartbeat_passes_when_fresh(db, tmp_path):
    _seed_heartbeat(db, minutes_ago=1)
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    assert _by_name(report)["heartbeat"].ok is True


@pytest.mark.db
def test_heartbeat_fires_when_never_recorded(db, tmp_path):
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    check = _by_name(report)["heartbeat"]
    assert check.ok is False
    assert "no heartbeat" in check.detail


# 2 · intake_backlog -----------------------------------------------------------


@pytest.mark.db
def test_intake_backlog_fires_when_old(db, tmp_path):
    _insert_intake_pending(db, minutes_ago=12)
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    assert _by_name(report)["intake_backlog"].ok is False


@pytest.mark.db
def test_intake_backlog_passes_when_fresh_or_empty(db, tmp_path):
    _insert_intake_pending(db, minutes_ago=0.1)
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    assert _by_name(report)["intake_backlog"].ok is True


# 3 · job_backlog ---------------------------------------------------------------


@pytest.mark.db
def test_job_backlog_fires_when_old(db, tmp_path):
    _insert_pending_job(db, minutes_ago=15)
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    assert _by_name(report)["job_backlog"].ok is False


@pytest.mark.db
def test_job_backlog_passes_when_fresh_or_empty(db, tmp_path):
    _insert_pending_job(db, minutes_ago=1)
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    assert _by_name(report)["job_backlog"].ok is True


# 4 · llm_null_ratio -------------------------------------------------------------


@pytest.mark.db
def test_llm_null_ratio_fires_over_30_percent(db, tmp_path):
    # The check's SQL window is `now() - interval '1 hour'` — the database's
    # own real clock, unaffected by `check()`'s injected `clock` (that seam
    # only feeds the local-time decisions, checks 4-8 stay real-clock SQL).
    recent = datetime.now(UTC) - timedelta(minutes=5)
    _insert_llm_run(db, created_at=recent, result=None)
    _insert_llm_run(db, created_at=recent, result=None)
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    assert _by_name(report)["llm_null_ratio"].ok is False


@pytest.mark.db
def test_llm_null_ratio_passes_under_30_percent(db, tmp_path):
    recent = datetime.now(UTC) - timedelta(minutes=5)
    _insert_llm_run(db, created_at=recent, result={})
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    assert _by_name(report)["llm_null_ratio"].ok is True


@pytest.mark.db
def test_llm_null_ratio_zero_rows_is_ok_not_a_division_by_zero(db, tmp_path):
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    check = _by_name(report)["llm_null_ratio"]
    assert check.ok is True
    assert check.value == 0.0


# 5 · triage_unavailable ---------------------------------------------------------


@pytest.mark.db
def test_triage_unavailable_fires_over_10_percent(db, tmp_path):
    # Same real-clock SQL window as check 4 (`now() - interval '24 hours'`).
    recent = datetime.now(UTC) - timedelta(hours=1)
    _insert_alert(db, triage_status="unavailable", received_at=recent)
    _insert_alert(db, triage_status="unavailable", received_at=recent)
    _insert_alert(db, triage_status="ready", received_at=recent)
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    assert _by_name(report)["triage_unavailable"].ok is False


@pytest.mark.db
def test_triage_unavailable_passes_under_10_percent(db, tmp_path):
    recent = datetime.now(UTC) - timedelta(hours=1)
    for _ in range(9):
        _insert_alert(db, triage_status="ready", received_at=recent)
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    assert _by_name(report)["triage_unavailable"].ok is True


# 6 · monthly_cost -----------------------------------------------------------------


@pytest.mark.db
def test_monthly_cost_fires_over_80_percent_of_the_cap(db, tmp_path):
    # The check's SQL window is `date_trunc('month', now())` — this month, by
    # the database's real clock.
    this_month = datetime.now(UTC)
    _insert_llm_run(db, created_at=this_month, result=None, cost_usd="27.00")
    report = health.check(
        db, _cfg(LLM_MONTHLY_USD_CAP=30), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path
    )
    assert _by_name(report)["monthly_cost"].ok is False


@pytest.mark.db
def test_monthly_cost_passes_under_80_percent_of_the_cap(db, tmp_path):
    this_month = datetime.now(UTC)
    _insert_llm_run(db, created_at=this_month, result=None, cost_usd="1.00")
    report = health.check(
        db, _cfg(LLM_MONTHLY_USD_CAP=30), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path
    )
    assert _by_name(report)["monthly_cost"].ok is True


# 7 · backup_age -------------------------------------------------------------------


@pytest.mark.db
def test_backup_age_fires_with_an_empty_backups_directory(db, tmp_path):
    empty_dir = tmp_path / "empty-backups"
    empty_dir.mkdir()
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=empty_dir)
    check = _by_name(report)["backup_age"]
    assert check.ok is False
    assert "no backup file" in check.detail


@pytest.mark.db
def test_backup_age_fires_when_the_newest_dump_is_over_36h_old(db, tmp_path):
    import os
    import time

    old_dump = _write_backup(tmp_path)
    old_mtime = time.time() - 40 * 3600
    os.utime(old_dump, (old_mtime, old_mtime))
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    check = _by_name(report)["backup_age"]
    assert check.ok is False
    assert "no backup file" not in check.detail


@pytest.mark.db
def test_backup_age_passes_with_a_fresh_dump(db, tmp_path):
    _write_backup(tmp_path)
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    assert _by_name(report)["backup_age"].ok is True


# 8 · inventory_empty ---------------------------------------------------------------


@pytest.mark.db
def test_inventory_empty_fires_with_no_assets(db, tmp_path):
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    assert _by_name(report)["inventory_empty"].ok is False


@pytest.mark.db
def test_inventory_empty_passes_with_one_asset(db, tmp_path):
    _seed_asset(db)
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    assert _by_name(report)["inventory_empty"].ok is True


# 9 · digest_unreviewed ----------------------------------------------------------


@pytest.mark.db
def test_digest_unreviewed_is_ok_before_17_00_local_even_with_a_miss(db, tmp_path):
    before_1700_utc = datetime(2026, 9, 29, 5, 0, 0, tzinfo=UTC)  # 12:00 local
    yesterday = before_1700_utc - timedelta(days=1)
    alert_id = _insert_alert(db, status="auto_closed", closed_at=yesterday, received_at=yesterday)
    report = health.check(db, _cfg(), clock=_clock_at(before_1700_utc), backups_dir=tmp_path)
    check = _by_name(report)["digest_unreviewed"]
    assert check.ok is True
    assert "not evaluated" in check.detail
    assert alert_id  # the row exists — this is the gate, not an empty-table pass


@pytest.mark.db
def test_digest_unreviewed_fires_after_17_00_with_an_unreviewed_yesterday_alert(db, tmp_path):
    after_1700_utc = datetime(2026, 9, 29, 11, 0, 0, tzinfo=UTC)  # 18:00 local
    yesterday_local_afternoon = after_1700_utc - timedelta(days=1)
    _insert_alert(
        db,
        status="auto_closed",
        closed_at=yesterday_local_afternoon,
        received_at=yesterday_local_afternoon,
    )
    report = health.check(db, _cfg(), clock=_clock_at(after_1700_utc), backups_dir=tmp_path)
    assert _by_name(report)["digest_unreviewed"].ok is False


@pytest.mark.db
def test_digest_unreviewed_passes_after_17_00_when_reviewed(db, tmp_path):
    after_1700_utc = datetime(2026, 9, 29, 11, 0, 0, tzinfo=UTC)
    yesterday_local_afternoon = after_1700_utc - timedelta(days=1)
    alert_id = _insert_alert(
        db,
        status="auto_closed",
        closed_at=yesterday_local_afternoon,
        received_at=yesterday_local_afternoon,
    )
    _insert_autoclose_review(db, alert_id)
    report = health.check(db, _cfg(), clock=_clock_at(after_1700_utc), backups_dir=tmp_path)
    assert _by_name(report)["digest_unreviewed"].ok is True


# 10 · disk_free -------------------------------------------------------------------


@pytest.mark.db
def test_disk_free_passes_on_the_real_filesystem(db, tmp_path):
    """The real host is nowhere near 80% used (P5-tasks.md §1: 26% used,
    23/09) — this pins the pass side; the fire side is `monkeypatch`ed below,
    since no test may fill the real disk."""
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    assert _by_name(report)["disk_free"].ok is True


@pytest.mark.db
def test_disk_free_fires_when_free_fraction_is_low(db, tmp_path, monkeypatch):
    import shutil as shutil_module

    fake_usage = shutil_module.disk_usage("/")._make((100, 95, 5))  # 5% free
    monkeypatch.setattr(health.shutil, "disk_usage", lambda path: fake_usage)
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    assert _by_name(report)["disk_free"].ok is False


# ===========================================================================
# one row per run, and the state-change notification rule (design notes 3, 4)
# ===========================================================================


@pytest.mark.db
def test_first_ever_run_all_ok_sends_nothing(db, tmp_path, monkeypatch):
    """No previous row at all defaults to "previously ok" (design note 4 read
    together with acceptance 2: a fresh alarm on the very first run DOES send
    — see the gate test below — so a fresh *ok* run must not, or the two
    together would mean every fresh deployment sends on its first tick)."""
    sent = _fake_notify(monkeypatch)
    _seed_all_ok(db, tmp_path)
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    assert report.ok is True
    assert sent == []


@pytest.mark.db
def test_alarm_then_no_resend_while_it_stays_alarm_then_one_send_on_recovery(
    db, tmp_path, monkeypatch
):
    sent = _fake_notify(monkeypatch)
    _seed_all_ok(db, tmp_path)
    cfg = _cfg()
    t0 = _MORNING_UTC

    r1 = health.check(db, cfg, clock=_clock_at(t0), backups_dir=tmp_path)
    assert r1.ok is True
    assert sent == []

    db.execute(
        "UPDATE source_heartbeat SET last_seen_at = now() - interval '45 minutes' "
        "WHERE manager_id = 'indexer'"
    )
    t1 = t0 + timedelta(minutes=5)
    r2 = health.check(db, cfg, clock=_clock_at(t1), backups_dir=tmp_path)
    assert r2.ok is False
    assert _levels(sent) == ["alarm"]

    t2 = t1 + timedelta(minutes=5)
    r3 = health.check(db, cfg, clock=_clock_at(t2), backups_dir=tmp_path)  # still broken
    assert r3.ok is False
    assert _levels(sent) == ["alarm"]  # no second send while it stays an alarm

    db.execute(
        "UPDATE source_heartbeat SET last_seen_at = now() - interval '1 minute' "
        "WHERE manager_id = 'indexer'"
    )
    t3 = t2 + timedelta(minutes=5)
    r4 = health.check(db, cfg, clock=_clock_at(t3), backups_dir=tmp_path)
    assert r4.ok is True
    assert _levels(sent) == ["alarm", "ok"]  # one send on recovery


@pytest.mark.db
def test_previous_state_is_read_from_the_table_not_from_process_memory(db, tmp_path, monkeypatch):
    """A worker restart must not re-alarm: this constructs the "previous"
    `system_health` row directly (never through a prior `check()` call in
    this process), simulating a fresh worker starting up already alarming."""
    sent = _fake_notify(monkeypatch)
    _seed_all_ok(db, tmp_path)
    db.execute(
        "UPDATE source_heartbeat SET last_seen_at = now() - interval '45 minutes' "
        "WHERE manager_id = 'indexer'"
    )
    previous_checked_at = _MORNING_UTC - timedelta(minutes=5)
    db.execute(
        "INSERT INTO system_health (checked_at, checks, ok) VALUES (%s, %s, false)",
        (
            previous_checked_at,
            Jsonb(
                [
                    {
                        "name": "heartbeat",
                        "ok": False,
                        "value": 45.0,
                        "threshold": 30,
                        "detail": "stale",
                    }
                ]
            ),
        ),
    )

    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)

    assert report.ok is False
    assert sent == []  # already alarming per the table — a restart must not re-send


# ===========================================================================
# the daily 08:05 summary (design note 4)
# ===========================================================================


def test_is_daily_summary_due_pure_boundary():
    tz = "Asia/Ho_Chi_Minh"
    at_0804 = datetime(2026, 9, 29, 8, 4, 0, tzinfo=ZoneInfo(tz))
    at_0805 = datetime(2026, 9, 29, 8, 5, 0, tzinfo=ZoneInfo(tz))
    at_1400 = datetime(2026, 9, 29, 14, 0, 0, tzinfo=ZoneInfo(tz))

    assert health._is_daily_summary_due(at_0804, None, tz) is False  # too early, no previous row
    assert health._is_daily_summary_due(at_0805, None, tz) is True  # first run at/after 08:05
    assert health._is_daily_summary_due(at_0805, at_0804.astimezone(UTC), tz) is True
    assert (
        health._is_daily_summary_due(at_1400, at_0805.astimezone(UTC), tz) is False
    )  # already sent today


@pytest.mark.db
def test_daily_summary_fires_once_at_08_05_and_not_again_that_day(db, tmp_path, monkeypatch):
    sent = _fake_notify(monkeypatch)
    _seed_all_ok(db, tmp_path)
    cfg = _cfg()
    # 08:05 local = 01:05 UTC (Asia/Ho_Chi_Minh, UTC+7)
    at_0805 = datetime(2026, 9, 29, 1, 5, 0, tzinfo=UTC)
    at_1400 = datetime(2026, 9, 29, 7, 0, 0, tzinfo=UTC)  # 14:00 local, same day

    r1 = health.check(db, cfg, clock=_clock_at(at_0805), backups_dir=tmp_path)
    assert r1.ok is True
    assert _levels(sent) == ["ok"]  # the summary, sent as an "ok" level (no alarm active)

    r2 = health.check(db, cfg, clock=_clock_at(at_1400), backups_dir=tmp_path)
    assert r2.ok is True
    assert _levels(sent) == ["ok"]  # not sent again the same day


# ===========================================================================
# system_health.checked_at collision (migration 015 note 5, design note 3)
# ===========================================================================


@pytest.mark.db
def test_checked_at_collision_is_caught_and_this_tick_is_skipped(db, tmp_path, monkeypatch):
    sent = _fake_notify(monkeypatch)
    _seed_all_ok(db, tmp_path)
    cfg = _cfg()
    t0 = _MORNING_UTC

    r1 = health.check(db, cfg, clock=_clock_at(t0), backups_dir=tmp_path)
    assert r1.checked_at == t0
    (count_before,) = db.execute("SELECT count(*) FROM system_health").fetchone()

    db.execute(
        "UPDATE source_heartbeat SET last_seen_at = now() - interval '45 minutes' "
        "WHERE manager_id = 'indexer'"
    )
    r2 = health.check(db, cfg, clock=_clock_at(t0), backups_dir=tmp_path)  # same checked_at

    assert r2.checked_at is None  # the collision, caught
    (count_after,) = db.execute("SELECT count(*) FROM system_health").fetchone()
    assert count_after == count_before  # no second row landed
    assert sent == []  # this tick's notification is skipped too, not retried
    # the caller's transaction survives the collision (the savepoint's whole point):
    (still_usable,) = db.execute("SELECT 1").fetchone()
    assert still_usable == 1


# ===========================================================================
# the exit-gate item — "health alarm fires with the indexer unreachable"
# ===========================================================================


@pytest.mark.db
def test_gate_health_alarm_fires_with_the_indexer_unreachable(db, tmp_path, monkeypatch):
    """Acceptance 2. No command here touches the indexer (DEC-106): a stale
    `source_heartbeat` row *is* what "the source stopped sending" means in
    this system."""
    sent = _fake_notify(monkeypatch)
    db.execute(
        "INSERT INTO source_heartbeat (manager_id, last_seen_at) "
        "VALUES ('indexer', now() - interval '45 minutes')"
    )

    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)

    assert _by_name(report)["heartbeat"].ok is False
    assert report.ok is False

    (row_ok,) = db.execute(
        "SELECT ok FROM system_health WHERE checked_at = %s", (report.checked_at,)
    ).fetchone()
    assert row_ok is False

    assert len(sent) == 1
    assert sent[0][0] == "alarm"

    (audit_count,) = db.execute(
        "SELECT count(*) FROM audit_events WHERE event_type = 'health.alarm'"
    ).fetchone()
    assert audit_count == 1


# ===========================================================================
# `health` is a registered job type (the card's explicit ask)
# ===========================================================================


def test_health_is_in_job_types():
    assert "health" in JOB_TYPES


# ===========================================================================
# the `health` handler module — JOB_TYPE, handle, Reschedule (P5-tasks.md
# planning decision 1)
# ===========================================================================


def test_handler_exposes_job_type_and_reschedules_every_5_minutes(monkeypatch):
    calls: list[tuple[object, object]] = []
    monkeypatch.setattr(health_handler.health, "check", lambda conn, cfg: calls.append((conn, cfg)))

    job = Job(job_id=1, job_type="health", subject_id="system", attempts=1)
    result = health_handler.handle("CONN", job, cfg=_cfg())

    assert health_handler.JOB_TYPE == "health"
    assert not hasattr(health_handler, "STATEMENT_TIMEOUT")
    assert result.delay_s == 300
    assert calls == [("CONN", _cfg())]


# ===========================================================================
# GET /health — loopback open, admin otherwise (design note 6)
#
# `require_role`'s 403 path commits `authz.denied` directly on whatever `conn`
# it is given (planning decision 3: "commit before raise") — a real effect of
# the app, not a test bug. Pointed at the shared `db` fixture (a `soc_p5t11_test`
# connection never meant to see a real commit), that write leaked into the
# session database and outlived the test — a sibling card hit exactly this.
# Every test below that can reach a 403 (all four: even the 200 tests share
# this fixture for symmetry) instead runs against its own scratch database
# (`sdb`/`scratch_dsn`, `test_webhook.py`'s precedent, itself following
# `test_auth.py`) — a `dropdb`/`createdb` this module owns and drops when it
# is done, so a commit here can never reach `soc_p5t11_test`.
# ===========================================================================


def _scratch_dbname() -> str:
    session = os.environ.get("TEST_DATABASE_URL", conftest.DEFAULT_TEST_DATABASE_URL)
    return f"{conftest._dbname(session)}_health_test"


@pytest.fixture(scope="module")
def scratch_dsn():
    if shutil.which("psql") is None or shutil.which("createdb") is None:
        pytest.skip("psql/createdb not on PATH — cannot build the health scratch database")
    dbname = _scratch_dbname()
    subprocess.run(["dropdb", "--if-exists", dbname], check=True, capture_output=True)
    subprocess.run(["createdb", dbname], check=True, capture_output=True)
    dsn = f"postgresql:///{dbname}"
    result = subprocess.run(
        ["bash", "scripts/migrate.sh", dsn],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"scratch migrate failed:\n{result.stderr}"
    try:
        yield dsn
    finally:
        subprocess.run(["dropdb", "--if-exists", dbname], check=False, capture_output=True)


@pytest.fixture
def sdb(scratch_dsn):
    conn = psycopg.connect(scratch_dsn)
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


def _override(conn, cfg):
    main.app.dependency_overrides[deps.get_conn] = lambda: conn
    main.app.dependency_overrides[deps.get_config] = lambda: cfg


def _clear_overrides():
    main.app.dependency_overrides.pop(deps.get_conn, None)
    main.app.dependency_overrides.pop(deps.get_config, None)


@pytest.mark.db
def test_health_route_is_registered_in_openapi():
    assert "/health" in sorted(main.app.openapi()["paths"])


@pytest.mark.db
def test_get_health_from_loopback_without_a_session_is_200(sdb, tmp_path, monkeypatch):
    monkeypatch.setattr(notify, "send", lambda *a, **k: True)
    health.check(sdb, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    cfg = _cfg(JWT_SECRET="p5t11-test-secret")
    _override(sdb, cfg)
    try:
        client = TestClient(main.app, client=("127.0.0.1", 51234))
        response = client.get("/health")
    finally:
        _clear_overrides()
        sdb.rollback()

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"checked_at", "checks", "ok"}
    for check in body["checks"]:
        assert "://" not in check["detail"]  # no DSN
        assert not check["detail"].startswith("/")  # no absolute filesystem path


@pytest.mark.db
def test_get_health_from_non_loopback_without_a_session_is_403(sdb, tmp_path, monkeypatch):
    monkeypatch.setattr(notify, "send", lambda *a, **k: True)
    health.check(sdb, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    cfg = _cfg(JWT_SECRET="p5t11-test-secret")
    _override(sdb, cfg)
    try:
        client = TestClient(main.app, client=("203.0.113.9", 51234))
        response = client.get("/health")
    finally:
        _clear_overrides()
        sdb.rollback()

    assert response.status_code == 403


@pytest.mark.db
def test_get_health_from_non_loopback_with_a_non_admin_session_is_403(sdb, tmp_path, monkeypatch):
    monkeypatch.setattr(notify, "send", lambda *a, **k: True)
    health.check(sdb, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    cfg = _cfg(JWT_SECRET="p5t11-test-secret")
    auth.create_user(sdb, username="p5t11-tier1", display_name="Tier1", role="tier1", password="x")
    claims = auth.login(sdb, "p5t11-tier1", "x", cfg)
    token = auth.issue_token(claims, cfg)
    _override(sdb, cfg)
    try:
        client = TestClient(main.app, client=("203.0.113.9", 51234))
        response = client.get("/health", headers={"Authorization": f"Bearer {token}"})
    finally:
        _clear_overrides()
        sdb.rollback()

    assert response.status_code == 403


@pytest.mark.db
def test_get_health_from_non_loopback_with_an_admin_session_is_200(sdb, tmp_path, monkeypatch):
    monkeypatch.setattr(notify, "send", lambda *a, **k: True)
    health.check(sdb, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    cfg = _cfg(JWT_SECRET="p5t11-test-secret")
    auth.create_user(sdb, username="p5t11-admin", display_name="Admin", role="admin", password="x")
    claims = auth.login(sdb, "p5t11-admin", "x", cfg)
    token = auth.issue_token(claims, cfg)
    _override(sdb, cfg)
    try:
        client = TestClient(main.app, client=("203.0.113.9", 51234))
        response = client.get("/health", headers={"Authorization": f"Bearer {token}"})
    finally:
        _clear_overrides()
        sdb.rollback()

    assert response.status_code == 200
