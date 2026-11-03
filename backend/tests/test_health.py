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

import contextlib
import hashlib
import itertools
import json
import os
import shutil
import subprocess
import time
import urllib.parse
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import httpx
import psycopg
import pytest
from app.infra import auth, health, intake, notify
from app.infra.config import Config
from app.infra.jobs import JOB_TYPES, Job
from app.tier1 import digest
from app.web import deps, main
from app.web.handlers import health as health_handler
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from tests import conftest
from tests.rag_data import add_entry

# Review round 1, N9: no module-level `pytestmark` — every `db`/`sdb`-using
# test below carries its own `@pytest.mark.db` explicitly; the three pure
# tests (`test_is_daily_summary_due_pure_boundary`, `test_health_is_in_job_types`,
# `test_handler_exposes_job_type_and_reschedules_every_5_minutes`) carry none,
# so they run in the fast `make test` suite instead of only under `test-db`.

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


def _seed_webhook_heartbeat(
    conn,
    *,
    seen_minutes_ago: float | None,
    alert_minutes_ago: float | None,
    manager_id: str = "webhook",
) -> None:
    """A `source_heartbeat` row as DEC-207 leaves it with the pull off: every accepted
    webhook alert stamps both columns, a rule-100999 document stamps `last_seen_at` only,
    and a row with a null `last_alert_at` is a system that has heard no alert yet."""
    conn.execute(
        """
        INSERT INTO source_heartbeat (manager_id, last_seen_at, last_alert_at)
        VALUES (
            %s,
            now() - (%s * interval '1 minute'),
            now() - (%s * interval '1 minute')
        )
        ON CONFLICT (manager_id) DO UPDATE SET
            last_seen_at = EXCLUDED.last_seen_at, last_alert_at = EXCLUDED.last_alert_at
        """,
        (manager_id, seen_minutes_ago, alert_minutes_ago),
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


@pytest.mark.db
def test_heartbeat_at_exact_threshold_is_ok(db, tmp_path):
    """N8, mutant M4 (`<=` -> `<`): `last_seen_at` and the check's own `now()`
    read are set in the SAME uncommitted transaction, so Postgres's `now()`
    (transaction-stable, not wall-clock-per-statement) makes the age compute
    to *exactly* `HEARTBEAT_MAX_AGE_MIN` — deterministic, no timing jitter."""
    cfg = _cfg()
    db.execute(
        "INSERT INTO source_heartbeat (manager_id, last_seen_at) "
        "VALUES ('indexer', now() - (%s * interval '1 minute'))",
        (cfg.HEARTBEAT_MAX_AGE_MIN,),
    )
    report = health.check(db, cfg, clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    check = _by_name(report)["heartbeat"]
    assert check.value == cfg.HEARTBEAT_MAX_AGE_MIN
    assert check.ok is True  # exactly at the threshold is still ok (`<=`)


# 1b · heartbeat, the two branches of PULL_ENABLED (S7) --------------------------
#
# Pull on: the puller owns `last_seen_at`, a 30-minute keepalive window. Pull off: the
# SIEM no longer sends rule 100999, the webhook is the only source, and "a real alert
# within WEBHOOK_SOURCE_MAX_AGE_H hours" is the judgement — a quiet webhook-only system
# must not alarm continuously.


@pytest.mark.db
def test_heartbeat_pull_on_stale_last_seen_alarms_even_with_a_recent_alert(db, tmp_path):
    """Pull on is the old rule byte for byte: it reads `last_seen_at` against
    HEARTBEAT_MAX_AGE_MIN and never looks at `last_alert_at`."""
    _seed_webhook_heartbeat(db, seen_minutes_ago=45, alert_minutes_ago=1)
    cfg = _cfg(PULL_ENABLED=True)
    check = _by_name(health.check(db, cfg, clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path))[
        "heartbeat"
    ]
    assert check.ok is False
    assert check.threshold == cfg.HEARTBEAT_MAX_AGE_MIN
    assert "the source stopped sending" in check.detail


@pytest.mark.db
def test_heartbeat_pull_on_recent_last_seen_is_ok_with_no_alert_ever(db, tmp_path):
    _seed_webhook_heartbeat(db, seen_minutes_ago=1, alert_minutes_ago=None)
    cfg = _cfg(PULL_ENABLED=True)
    check = _by_name(health.check(db, cfg, clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path))[
        "heartbeat"
    ]
    assert check.ok is True
    assert check.threshold == cfg.HEARTBEAT_MAX_AGE_MIN
    assert check.detail.startswith("last heartbeat ")


@pytest.mark.db
def test_heartbeat_pull_off_recent_alert_is_ok_beyond_the_old_30_minute_window(db, tmp_path):
    """The point of the card: 5 h since the last real alert is a quiet night, not a dead
    source. The old rule (HEARTBEAT_MAX_AGE_MIN = 30 min) would have alarmed on it, on
    both columns (a webhook-only row has `last_seen_at` = `last_alert_at`)."""
    _seed_webhook_heartbeat(db, seen_minutes_ago=300, alert_minutes_ago=300)
    cfg = _cfg(PULL_ENABLED=False)
    assert 300 > cfg.HEARTBEAT_MAX_AGE_MIN and 300 < cfg.WEBHOOK_SOURCE_MAX_AGE_H * 60
    check = _by_name(health.check(db, cfg, clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path))[
        "heartbeat"
    ]
    assert check.ok is True
    assert check.detail.startswith("last webhook alert ")
    assert check.threshold == cfg.WEBHOOK_SOURCE_MAX_AGE_H


@pytest.mark.db
def test_heartbeat_pull_off_five_minutes_ago_is_ok(db, tmp_path):
    _seed_webhook_heartbeat(db, seen_minutes_ago=5, alert_minutes_ago=5)
    check = _by_name(
        health.check(
            db, _cfg(PULL_ENABLED=False), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path
        )
    )["heartbeat"]
    assert check.ok is True
    assert "5 min ago" in check.detail


@pytest.mark.db
def test_heartbeat_pull_off_judges_the_last_alert_not_the_last_keepalive(db, tmp_path):
    """A rule-100999 document (if one still arrives) stamps `last_seen_at` only; it is a
    keepalive, not an alert, and must not hide a source whose alerts stopped."""
    _seed_webhook_heartbeat(db, seen_minutes_ago=1, alert_minutes_ago=60 * 30)
    cfg = _cfg(PULL_ENABLED=False)
    check = _by_name(health.check(db, cfg, clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path))[
        "heartbeat"
    ]
    assert check.ok is False


@pytest.mark.db
def test_heartbeat_pull_off_stale_alert_alarms_with_the_webhook_detail(db, tmp_path):
    cfg = _cfg(PULL_ENABLED=False, WEBHOOK_SOURCE_MAX_AGE_H=24)
    _seed_webhook_heartbeat(db, seen_minutes_ago=25 * 60, alert_minutes_ago=25 * 60)
    check = _by_name(health.check(db, cfg, clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path))[
        "heartbeat"
    ]
    assert check.ok is False
    assert check.detail == "no webhook alert in over 24 h — the source may have stopped"
    assert check.threshold == 24
    assert check.value == 25.0


@pytest.mark.db
def test_heartbeat_pull_off_window_follows_the_config_key(db, tmp_path):
    _seed_webhook_heartbeat(db, seen_minutes_ago=25 * 60, alert_minutes_ago=25 * 60)
    check = _by_name(
        health.check(
            db,
            _cfg(PULL_ENABLED=False, WEBHOOK_SOURCE_MAX_AGE_H=48),
            clock=_clock_at(_MORNING_UTC),
            backups_dir=tmp_path,
        )
    )["heartbeat"]
    assert check.ok is True


@pytest.mark.db
def test_heartbeat_pull_off_no_row_is_ok_not_an_alarm(db, tmp_path):
    check = _by_name(
        health.check(
            db, _cfg(PULL_ENABLED=False), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path
        )
    )["heartbeat"]
    assert check.ok is True
    assert check.value is None
    assert check.detail == "no webhook alert yet"


@pytest.mark.db
def test_heartbeat_pull_off_null_last_alert_is_ok_not_an_alarm(db, tmp_path):
    """Only keepalives so far (or a pull-era row): no real alert yet is not a dead source."""
    _seed_webhook_heartbeat(db, seen_minutes_ago=2, alert_minutes_ago=None)
    check = _by_name(
        health.check(
            db, _cfg(PULL_ENABLED=False), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path
        )
    )["heartbeat"]
    assert check.ok is True
    assert check.detail == "no webhook alert yet"


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


@pytest.mark.db
def test_job_backlog_counts_only_due_jobs_a_month_ahead_is_not_a_backlog(db, tmp_path):
    """P13 fix wave, item 20 (I1): a `knowledge_draft` job rescheduled to the start of next month is a
    `pending` row whose time has not come. It is waiting, not stuck: the check reads `scheduled_at <= now()`.
    """
    db.execute(
        "INSERT INTO jobs (job_type, subject_id, status, scheduled_at)"
        " VALUES ('knowledge_draft', 'alert:backlog-future', 'pending', now() + interval '30 days')"
    )
    db.execute(
        "INSERT INTO jobs (job_type, subject_id, status, scheduled_at)"
        " VALUES ('knowledge_draft', 'alert:backlog-soon', 'pending', now() + interval '1 minute')"
    )
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    check = _by_name(report)["job_backlog"]
    assert check.ok is True and "no due pending jobs" in check.detail


@pytest.mark.db
def test_job_backlog_alarms_once_the_rescheduled_job_is_due_and_nobody_claims_it(db, tmp_path):
    db.execute(
        "INSERT INTO jobs (job_type, subject_id, status, scheduled_at)"
        " VALUES ('knowledge_draft', 'alert:backlog-due', 'pending', now() - interval '15 minutes')"
    )
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    assert _by_name(report)["job_backlog"].ok is False


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


@pytest.mark.db
def test_llm_null_ratio_leaves_out_the_rag_lookups_runs_whatever_their_result(db, tmp_path):
    """Review I1 (P14-T06): a failed lookup writes a `rag_lookup` run with a NULL result (Voyage or `vectordb`
    was down), and DeepSeek is not. `rag_lookup_failures` owns that signal, so the "Model API down" ratio
    neither counts those runs as nulls nor lets the good ones dilute the real failures."""
    for _ in range(8):
        _insert_rag_run(db, pipeline="rag_lookup", cost_usd="0.00001", result=None)
    check = _run_check(db, tmp_path)["llm_null_ratio"]
    assert check.ok is True and check.detail == "no llm_runs in the last hour"


@pytest.mark.db
def test_llm_null_ratio_is_not_diluted_by_good_rag_lookups(db, tmp_path):
    recent = datetime.now(UTC) - timedelta(minutes=5)
    _insert_llm_run(db, created_at=recent, result=None)  # the only run that counts, and it failed
    for _ in range(20):
        _insert_rag_run(db, pipeline="rag_lookup", cost_usd="0.00001", result={"ranked": []})
    check = _run_check(db, tmp_path)["llm_null_ratio"]
    assert check.ok is False and check.value == 100.0
    assert check.detail == "1/1 llm_runs with a null result in the last hour"


@pytest.mark.db
def test_llm_null_ratio_still_counts_the_other_pipelines_runs_with_no_result(db, tmp_path):
    recent = datetime.now(UTC) - timedelta(minutes=5)
    _insert_rag_run(db, pipeline="knowledge_draft", cost_usd="0.001", result=None)
    _insert_llm_run(db, created_at=recent, result=None)
    check = _run_check(db, tmp_path)["llm_null_ratio"]
    assert check.ok is False and check.detail == "2/2 llm_runs with a null result in the last hour"


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


def _web_limit(conn, key: str, value: int) -> None:
    """One `settings` row, as the admin's `PUT /api/admin/llm/limits` writes it."""
    user_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash) "
        "VALUES (%s, %s, 'Admin', 'admin', 'x')",
        (user_id, f"user-{user_id[:8]}"),
    )
    conn.execute(
        "INSERT INTO settings (key, value, updated_by) VALUES (%s, %s, %s)",
        (key, value, user_id),
    )


@pytest.mark.db
def test_monthly_cost_uses_the_cap_the_admin_saved_on_the_web(db, tmp_path):
    """P11-T03: 27 USD is 90 % of the `.env` cap of 30 (fires) but 27 % of a web cap of 100."""
    _insert_llm_run(db, created_at=datetime.now(UTC), result=None, cost_usd="27.00")
    clock = _clock_at(_MORNING_UTC)
    over = health.check(db, _cfg(LLM_MONTHLY_USD_CAP=30), clock=clock, backups_dir=tmp_path)
    assert _by_name(over)["monthly_cost"].ok is False

    _web_limit(db, "LLM_MONTHLY_USD_CAP", 100)
    under = health.check(db, _cfg(LLM_MONTHLY_USD_CAP=30), clock=clock, backups_dir=tmp_path)

    check = _by_name(under)["monthly_cost"]
    assert check.ok is True
    assert check.value == 27.0
    assert "$100 monthly cap" in check.detail


@pytest.mark.db
def test_monthly_cost_fails_when_the_limits_cannot_be_read(db, tmp_path):
    """Fail closed (DEC-200 item 3): no `settings` table — the code ran before `make migrate`.
    The check fails with a detail that says why, never a pass on the `.env` cap, and the rest
    of the run is unharmed (the savepoint keeps the transaction usable, so the report is still
    written)."""
    db.execute("DROP TABLE settings")  # rolled back with the test's transaction

    report = health.check(
        db, _cfg(LLM_MONTHLY_USD_CAP=30), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path
    )

    check = _by_name(report)["monthly_cost"]
    assert check.ok is False
    assert "không đọc được hạn mức" in check.detail
    assert check.value is None
    assert report.checked_at is not None  # the system_health row was inserted after the failure
    assert _by_name(report)["intake_backlog"].ok is True  # the other checks still ran


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


@pytest.mark.db
def test_backup_age_falls_back_to_latest_dump_when_present(db, tmp_path):
    """S6, mutant M12: no `soc-*.dump` at all, only `backups/latest.dump` —
    the fallback (§3.9) must be read, not treated as "no backup file"."""
    latest = tmp_path / "latest.dump"
    latest.write_bytes(b"pg_dump placeholder")
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    check = _by_name(report)["backup_age"]
    assert check.ok is True
    assert "no backup file" not in check.detail


@pytest.mark.db
def test_backup_age_picks_the_newest_of_several_dumps(db, tmp_path):
    """S6, mutant M13: two `soc-*.dump` files, the older one alone would fail
    the 36h threshold — the newest one's mtime must be what is judged."""
    old_dump = _write_backup(tmp_path, name="soc-20260101T000000Z.dump")
    new_dump = _write_backup(tmp_path, name="soc-20260929T000000Z.dump")
    old_mtime = time.time() - 40 * 3600  # 40h old — would fail on its own
    os.utime(old_dump, (old_mtime, old_mtime))
    # new_dump keeps its just-written (fresh) mtime.
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    check = _by_name(report)["backup_age"]
    assert check.ok is True  # the newest dump wins, not the oldest
    assert new_dump.name in check.detail
    assert old_dump.name not in check.detail


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


# P12-T01 / DEC-207 — ENRICHMENT_ENABLED=false: the inventory is not read, so its being empty is
# no alarm. The control is the test above (and the explicit `True` below): an empty `assets`
# table with the flag on is still a failing check.


class _Untouchable:
    """Stands in for the connection: any attribute read fails the test."""

    def __getattr__(self, name: str):
        raise AssertionError(f"_check_inventory_empty reached the connection ({name})")


def test_inventory_empty_with_enrichment_off_is_ok_not_applicable_and_runs_no_sql():
    result = health._check_inventory_empty(_Untouchable(), _cfg(ENRICHMENT_ENABLED=False))
    assert result.name == "inventory_empty"
    assert result.ok is True
    assert result.detail == "n/a — enrichment off"
    assert result.value is None


@pytest.mark.db
def test_inventory_empty_is_ok_when_enrichment_is_off_and_the_table_is_empty(db, tmp_path):
    report = health.check(
        db,
        _cfg(ENRICHMENT_ENABLED=False),
        clock=_clock_at(_MORNING_UTC),
        backups_dir=tmp_path,
    )
    check = _by_name(report)["inventory_empty"]
    assert (check.ok, check.detail) == (True, "n/a — enrichment off")


@pytest.mark.db
def test_inventory_empty_still_fires_when_enrichment_is_explicitly_on(db, tmp_path):
    report = health.check(
        db, _cfg(ENRICHMENT_ENABLED=True), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path
    )
    check = _by_name(report)["inventory_empty"]
    assert check.ok is False
    assert check.detail == "assets table is empty"


@pytest.mark.db
def test_inventory_empty_with_enrichment_off_does_not_alarm_the_report(db, tmp_path):
    """The whole report: with the inventory empty and enrichment off, the only thing that
    can still fail the report is something else — here nothing does."""
    _seed_heartbeat(db, minutes_ago=1)
    _write_backup(tmp_path)
    report = health.check(
        db,
        _cfg(ENRICHMENT_ENABLED=False),
        clock=_clock_at(_MORNING_UTC),
        backups_dir=tmp_path,
    )
    assert _by_name(report)["inventory_empty"].ok is True
    failing = [c.name for c in report.checks if not c.ok]
    assert "inventory_empty" not in failing


# P12-T01 / DEC-207 item 2 — with the pull off, an accepted webhook alert is what keeps the
# `heartbeat` check green. (S7: the window is `WEBHOOK_SOURCE_MAX_AGE_H` hours on `last_alert_at`,
# no longer the 30-minute keepalive window, so "the source looks lost" is a 25-hour-old alert.)


@pytest.mark.db
def test_heartbeat_check_goes_from_stale_to_ok_on_a_webhook_alert_with_the_pull_off(db, tmp_path):
    cfg = _cfg(PULL_ENABLED=False, WEBHOOK_API_KEY="k")
    _seed_webhook_heartbeat(db, seen_minutes_ago=25 * 60, alert_minutes_ago=25 * 60)
    first = health.check(db, cfg, clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    assert _by_name(first)["heartbeat"].ok is False  # the source looks lost

    alert = json.loads((REPO_ROOT / "backend/tests/fixtures/alert_40112.json").read_text("utf-8"))
    body = alert["_source"]
    body["id"] = "1790120001.120001"  # the Wazuh form: the webhook refuses any other (INT-T02)
    intake.receive(db, json.dumps(body).encode("utf-8"), "127.0.0.1", cfg)

    second = health.check(
        db, cfg, clock=_clock_at(_MORNING_UTC + timedelta(minutes=1)), backups_dir=tmp_path
    )
    assert _by_name(second)["heartbeat"].ok is True


@pytest.mark.db
def test_heartbeat_check_stays_red_on_a_webhook_alert_with_the_pull_on(db, tmp_path):
    """The control of the test above, and the behaviour of before DEC-207: with the pull on, a
    pull that died still turns the alarm red beside a webhook that keeps receiving alerts."""
    cfg = _cfg(WEBHOOK_API_KEY="k")  # PULL_ENABLED left at its default, true
    _seed_heartbeat(db, minutes_ago=45)
    alert = json.loads((REPO_ROOT / "backend/tests/fixtures/alert_40112.json").read_text("utf-8"))
    body = alert["_source"]
    body["id"] = "1790120002.120002"  # the Wazuh form: the webhook refuses any other (INT-T02)
    intake.receive(db, json.dumps(body).encode("utf-8"), "127.0.0.1", cfg)

    report = health.check(db, cfg, clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)

    assert _by_name(report)["heartbeat"].ok is False


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


@pytest.mark.db
def test_digest_unreviewed_is_evaluated_at_exactly_17_00_local(db, tmp_path):
    """N8, mutant M5 (`<` -> `<=`): at exactly local 17:00, `now_local.hour <
    17` is False, so the check must run (not read as "not evaluated yet")."""
    at_1700_sharp_utc = datetime(2026, 9, 29, 10, 0, 0, tzinfo=UTC)  # 17:00:00 local exactly
    yesterday = at_1700_sharp_utc - timedelta(days=1)
    _insert_alert(db, status="auto_closed", closed_at=yesterday, received_at=yesterday)
    report = health.check(db, _cfg(), clock=_clock_at(at_1700_sharp_utc), backups_dir=tmp_path)
    check = _by_name(report)["digest_unreviewed"]
    assert check.ok is False  # evaluated, not gated off — the unreviewed alert fires
    assert "not evaluated" not in check.detail


@pytest.mark.db
def test_digest_unreviewed_boundary_pins_the_local_day_edges(db, tmp_path):
    """S6, mutant M1: judged at 18:00 local on day D, an alert auto-closed at
    00:30 local on D must NOT count (it is in *today's* window, not
    yesterday's), and one at 00:30 local on D-1 MUST count (just inside
    yesterday's window) — pins both edges of the `>=`/`<` local-day bounds."""
    at_1800_local_d = datetime(2026, 9, 29, 11, 0, 0, tzinfo=UTC)  # 18:00 local, day D (9/29)
    at_0030_local_d = datetime(2026, 9, 28, 17, 30, 0, tzinfo=UTC)  # 00:30 local, day D
    at_0030_local_d_minus_1 = datetime(2026, 9, 27, 17, 30, 0, tzinfo=UTC)  # 00:30 local, D-1

    must_not_count = _insert_alert(
        db, status="auto_closed", closed_at=at_0030_local_d, received_at=at_0030_local_d
    )
    must_count = _insert_alert(
        db,
        status="auto_closed",
        closed_at=at_0030_local_d_minus_1,
        received_at=at_0030_local_d_minus_1,
    )

    report = health.check(db, _cfg(), clock=_clock_at(at_1800_local_d), backups_dir=tmp_path)

    check = _by_name(report)["digest_unreviewed"]
    assert check.ok is False
    assert check.value == 1  # only the D-1 00:30 alert counts, not D's own 00:30
    assert (
        must_not_count and must_count
    )  # both rows exist — the count, not their absence, is the proof


@pytest.mark.db
def test_digest_unreviewed_matches_unreviewed_count(db, tmp_path):
    """Cross-check with `tier1.digest.unreviewed_count` (round 1 addendum):
    both sides read `DISPLAY_TZ` local-day bounds independently — check 9 in
    Python (`infra` imports nothing, design note 1(a)), `unreviewed_count` in
    SQL (`_DAY_LOWER`/`_DAY_UPPER`) — and must agree on the same fixture as
    the M1 boundary pair above: one alert auto-closed at 00:30 local on D-1
    (counts on both sides), one at 00:30 local on D (counts on neither), and
    — round 1 addendum's own note — one *synthetic* alert inside D-1's window
    (excluded on both sides: `unreviewed_count` is the reference for the
    `NOT a.is_synthetic` predicate check 9 gained to match it)."""
    at_1800_local_d = datetime(2026, 9, 29, 11, 0, 0, tzinfo=UTC)  # 18:00 local, day D (9/29)
    at_0030_local_d = datetime(2026, 9, 28, 17, 30, 0, tzinfo=UTC)  # 00:30 local, day D
    at_0030_local_d_minus_1 = datetime(2026, 9, 27, 17, 30, 0, tzinfo=UTC)  # 00:30 local, D-1
    day_minus_1 = (
        "2026-09-28"  # D-1 as YYYY-MM-DD, the date `at_0030_local_d_minus_1` falls on locally
    )

    _insert_alert(db, status="auto_closed", closed_at=at_0030_local_d, received_at=at_0030_local_d)
    _insert_alert(
        db,
        status="auto_closed",
        closed_at=at_0030_local_d_minus_1,
        received_at=at_0030_local_d_minus_1,
    )
    _insert_alert(
        db,
        status="auto_closed",
        closed_at=at_0030_local_d_minus_1,
        received_at=at_0030_local_d_minus_1,
        is_synthetic=True,
    )

    report = health.check(db, _cfg(), clock=_clock_at(at_1800_local_d), backups_dir=tmp_path)
    check = _by_name(report)["digest_unreviewed"]

    reference = digest.unreviewed_count(db, day_minus_1, tz=_cfg().DISPLAY_TZ)

    assert check.value == reference
    assert reference == 1  # the one real D-1 00:30 alert — not D's, not the synthetic one


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


@pytest.mark.db
def test_disk_free_at_exact_threshold_is_ok(db, tmp_path, monkeypatch):
    """N8, mutant M14 (`>=` -> `>`): exactly 20% free must still be ok."""
    import shutil as shutil_module

    fake_usage = shutil_module.disk_usage("/")._make((100, 80, 20))  # exactly 20% free
    monkeypatch.setattr(health.shutil, "disk_usage", lambda path: fake_usage)
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    check = _by_name(report)["disk_free"]
    assert check.value == 20.0
    assert check.ok is True


# ===========================================================================
# the three checks of the learned knowledge (P13-T05, DEC-210) — SQL only, `infra` imports no `rag`
# ===========================================================================


def _insert_draft(conn, *, status: str = "pending") -> None:
    n = next(_alert_seq)
    conn.execute(
        "INSERT INTO knowledge_drafts (source_kind, source_id, conclusion, status)"
        " VALUES ('alert', %s, 'closed_fp', %s)",
        (f"health-draft-{n}", status),
    )


def _insert_integrity_failure(
    conn, *, entry_id: str, hours_ago: float, entry_status: str | None = "active"
) -> None:
    """A `rag.integrity_failed` event for `entry_id`, whose entry row is made with `entry_status` unless it
    has one already (`None`: there is no such entry at all)."""
    if (
        entry_status is not None
        and not conn.execute(
            "SELECT 1 FROM knowledge_entries WHERE entry_id = %s", (entry_id,)
        ).fetchone()
    ):
        add_entry(conn, entry_id=entry_id, status=entry_status)
    conn.execute(
        "INSERT INTO audit_events (event_type, subject_id, actor_role, payload, created_at)"
        " VALUES ('rag.integrity_failed', %s, 'system', %s, now() - (%s * interval '1 hour'))",
        (entry_id, Jsonb({"entry_id": entry_id}), hours_ago),
    )


def _insert_rag_run(
    conn, *, pipeline: str, cost_usd: str, days_ago: float = 0, result: dict | None = None
) -> None:
    role = "retriever" if pipeline == "rag_lookup" else "drafter"
    conn.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, role, system_prompt,"
        " user_message, cost_usd, result, created_at)"
        " VALUES (%s, %s, 'alert', %s, %s, 's', 'u', %s, %s, now() - (%s * interval '1 day'))",
        (
            str(uuid.uuid4()),
            pipeline,
            f"rag-run-{next(_alert_seq)}",
            role,
            cost_usd,
            None if result is None else Jsonb(result),
            days_ago,
        ),
    )


def _run_check(db, tmp_path, cfg=None) -> dict[str, health.CheckResult]:
    return _by_name(
        health.check(db, cfg or _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    )


@pytest.mark.db
def test_the_report_has_the_three_knowledge_checks_after_the_ten_and_the_lookup_failures_last(
    db, tmp_path
):
    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    names = [c.name for c in report.checks]
    assert names[-4:] == [
        "knowledge_queue",
        "knowledge_integrity",
        "rag_budget",
        "rag_lookup_failures",
    ]
    assert len(names) == 14


@pytest.mark.db
def test_a_store_with_nothing_in_it_is_green_on_all_four(db, tmp_path):
    """The first day: no draft, no failed entry, no spend, no failed lookup."""
    checks = _run_check(db, tmp_path)
    for name in ("knowledge_queue", "knowledge_integrity", "rag_budget", "rag_lookup_failures"):
        assert checks[name].ok is True, name


# 11 · knowledge_queue ---------------------------------------------------------------------


@pytest.mark.db
def test_knowledge_queue_fires_above_the_maximum(db, tmp_path):
    for _ in range(3):
        _insert_draft(db)
    check = _run_check(db, tmp_path, _cfg(KNOWLEDGE_QUEUE_MAX=2))["knowledge_queue"]
    assert check.ok is False
    assert (check.value, check.threshold) == (3, 2)


@pytest.mark.db
def test_knowledge_queue_at_the_maximum_is_ok(db, tmp_path):
    """The alarm is "above" `KNOWLEDGE_QUEUE_MAX`, not "at" it."""
    for _ in range(2):
        _insert_draft(db)
    check = _run_check(db, tmp_path, _cfg(KNOWLEDGE_QUEUE_MAX=2))["knowledge_queue"]
    assert check.ok is True
    assert check.value == 2


@pytest.mark.db
def test_knowledge_queue_counts_only_the_drafts_waiting_for_an_admin(db, tmp_path):
    _insert_draft(db)
    for status in ("approved", "rejected", "merged", "merged"):
        _insert_draft(db, status=status)
    check = _run_check(db, tmp_path, _cfg(KNOWLEDGE_QUEUE_MAX=1))["knowledge_queue"]
    assert check.ok is True
    assert check.value == 1


# 12 · knowledge_integrity -----------------------------------------------------------------


@pytest.mark.db
def test_knowledge_integrity_fires_on_a_failure_in_the_last_24_hours(db, tmp_path):
    _insert_integrity_failure(db, entry_id=str(uuid.uuid4()), hours_ago=2)
    check = _run_check(db, tmp_path)["knowledge_integrity"]
    assert check.ok is False
    assert (check.value, check.threshold) == (1, 0)


@pytest.mark.db
def test_knowledge_integrity_passes_when_the_failure_is_older_than_24_hours(db, tmp_path):
    _insert_integrity_failure(db, entry_id=str(uuid.uuid4()), hours_ago=25)
    assert _run_check(db, tmp_path)["knowledge_integrity"].ok is True


@pytest.mark.db
def test_knowledge_integrity_is_an_aggregate_duplicates_are_one_entry(db, tmp_path):
    """Every lookup that meets a changed entry writes an event: five events for one entry are one
    entry to repair, and the detail says how many events there were."""
    bad = str(uuid.uuid4())
    for hours in (1, 2, 3, 4, 5):
        _insert_integrity_failure(db, entry_id=bad, hours_ago=hours)
    _insert_integrity_failure(db, entry_id=str(uuid.uuid4()), hours_ago=1)
    check = _run_check(db, tmp_path)["knowledge_integrity"]
    assert check.ok is False
    assert check.value == 2
    assert "6" in check.detail and "2" in check.detail


@pytest.mark.db
def test_knowledge_integrity_counts_only_entries_that_are_still_active(db, tmp_path):
    """P13 fix wave, item 5 (T05 M2): a retire that races a lookup leaves an event for an entry that is
    gone from the lookups for good, and `--rebuild` skips retired entries, so nothing would clear the
    alarm before 24 hours. Only an entry that can still be retrieved is an entry to repair."""
    _insert_integrity_failure(db, entry_id=str(uuid.uuid4()), hours_ago=1, entry_status="retired")
    _insert_integrity_failure(db, entry_id=str(uuid.uuid4()), hours_ago=1, entry_status=None)
    assert _run_check(db, tmp_path)["knowledge_integrity"].ok is True
    live, gone = str(uuid.uuid4()), str(uuid.uuid4())
    _insert_integrity_failure(db, entry_id=live, hours_ago=2)
    _insert_integrity_failure(db, entry_id=live, hours_ago=3)
    _insert_integrity_failure(db, entry_id=gone, hours_ago=2, entry_status="retired")
    check = _run_check(db, tmp_path)["knowledge_integrity"]
    assert check.ok is False and check.value == 1
    assert (
        "1 entry" in check.detail and "(2 event" in check.detail
    )  # the events of the live entry only


@pytest.mark.db
def test_knowledge_integrity_clears_when_the_failing_entry_is_retired(db, tmp_path):
    entry = str(uuid.uuid4())
    _insert_integrity_failure(db, entry_id=entry, hours_ago=1)
    assert _run_check(db, tmp_path)["knowledge_integrity"].ok is False
    db.execute("UPDATE knowledge_entries SET status = 'retired' WHERE entry_id = %s", (entry,))
    assert _run_check(db, tmp_path)["knowledge_integrity"].ok is True


@pytest.mark.db
def test_knowledge_integrity_ignores_other_events(db, tmp_path):
    db.execute(
        "INSERT INTO audit_events (event_type, subject_id, actor_role, payload)"
        " VALUES ('rag.lookup_failed', 'x', 'system', '{}')"
    )
    assert _run_check(db, tmp_path)["knowledge_integrity"].ok is True


# 13 · rag_budget --------------------------------------------------------------------------


@pytest.mark.db
def test_rag_budget_fires_when_the_months_spend_reaches_the_cap(db, tmp_path):
    _insert_rag_run(db, pipeline="rag_lookup", cost_usd="1.00")
    _insert_rag_run(db, pipeline="knowledge_draft", cost_usd="2.00")
    check = _run_check(db, tmp_path, _cfg(RAG_ENABLED=True, RAG_MONTHLY_USD_CAP=3))["rag_budget"]
    assert check.ok is False  # exactly the cap is the cap: the adapter stops at it
    assert (check.value, check.threshold) == (3.0, 3)


@pytest.mark.db
def test_rag_budget_passes_under_the_cap(db, tmp_path):
    _insert_rag_run(db, pipeline="rag_lookup", cost_usd="1.00")
    _insert_rag_run(db, pipeline="knowledge_draft", cost_usd="1.50")
    check = _run_check(db, tmp_path, _cfg(RAG_ENABLED=True, RAG_MONTHLY_USD_CAP=3))["rag_budget"]
    assert check.ok is True
    assert check.value == 2.5


@pytest.mark.db
def test_rag_budget_counts_the_rag_pipelines_and_this_month_only(db, tmp_path):
    _insert_llm_run(db, created_at=datetime.now(UTC), cost_usd="25.00")  # ①: not the RAG's
    _insert_rag_run(db, pipeline="rag_lookup", cost_usd="1.00")
    # `now() - 40 days` is never in the current month
    _insert_rag_run(db, pipeline="rag_lookup", cost_usd="50.00", days_ago=40)
    check = _run_check(db, tmp_path, _cfg(RAG_ENABLED=True, RAG_MONTHLY_USD_CAP=3))["rag_budget"]
    assert check.ok is True
    assert check.value == 1.0


@pytest.mark.db
def test_rag_budget_ignores_a_run_with_no_cost(db, tmp_path):
    db.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, role, system_prompt,"
        " user_message) VALUES (%s, 'rag_lookup', 'alert', 'free', 'retriever', 's', 'u')",
        (str(uuid.uuid4()),),
    )
    check = _run_check(db, tmp_path, _cfg(RAG_ENABLED=True))["rag_budget"]
    assert check.ok is True
    assert check.value == 0.0


@pytest.mark.db
@pytest.mark.parametrize("cap", [0, 3])
def test_rag_budget_is_not_applicable_with_both_switches_off(db, tmp_path, cap):
    """With `RAG_ENABLED` and `KNOWLEDGE_DRAFT_ENABLED` both false nothing spends on the RAG, so
    nothing alarms, whatever the cap (a cap of 0 would otherwise read 0 >= 0 for ever) and whatever
    was spent before the switches went off."""
    _insert_rag_run(db, pipeline="rag_lookup", cost_usd="50.00")
    check = _run_check(db, tmp_path, _cfg(RAG_MONTHLY_USD_CAP=cap))["rag_budget"]
    assert check.ok is True
    assert check.detail == "n/a — RAG off"
    assert (check.value, check.threshold) == (None, cap)


@pytest.mark.db
@pytest.mark.parametrize(
    "switches",
    [
        {"RAG_ENABLED": True},
        {"KNOWLEDGE_DRAFT_ENABLED": True},
        {"RAG_ENABLED": True, "KNOWLEDGE_DRAFT_ENABLED": True},
    ],
    ids=["lookup-only", "draft-only", "both"],
)
def test_rag_budget_with_either_switch_on_and_a_cap_of_zero_is_an_alarm(db, tmp_path, switches):
    """Cap 0 means nothing may be spent; with a RAG switch on the check says so (0 >= 0)."""
    check = _run_check(db, tmp_path, _cfg(RAG_MONTHLY_USD_CAP=0, **switches))["rag_budget"]
    assert check.ok is False
    assert (check.value, check.threshold) == (0.0, 0)


# 14 · rag_lookup_failures -----------------------------------------------------------------


def _insert_lookup(conn, *, status="failed", kind="timeout", minutes_ago: float = 0) -> None:
    conn.execute(
        "INSERT INTO rag_results (lookup_id, subject_kind, subject_id, status, failure_kind,"
        " created_at) VALUES (%s, 'alert', %s, %s, %s, now() - (%s * interval '1 minute'))",
        (str(uuid.uuid4()), f"lookup-{next(_alert_seq)}", status, kind, minutes_ago),
    )


def _failures(db, tmp_path, **switches) -> health.CheckResult:
    cfg = _cfg(**({"RAG_ENABLED": True} | switches))
    return _run_check(db, tmp_path, cfg)["rag_lookup_failures"]


@pytest.mark.db
def test_rag_lookup_failures_is_red_at_five_failed_lookups_in_the_last_hour(db, tmp_path):
    for _ in range(5):
        _insert_lookup(db, minutes_ago=10)
    check = _failures(db, tmp_path)
    assert check.ok is False
    assert (check.value, check.threshold) == (5, 5)


@pytest.mark.db
def test_rag_lookup_failures_is_green_at_four(db, tmp_path):
    for _ in range(4):
        _insert_lookup(db, minutes_ago=10)
    check = _failures(db, tmp_path)
    assert check.ok is True
    assert (check.value, check.threshold) == (4, 5)


@pytest.mark.db
def test_rag_lookup_failures_counts_only_the_last_sixty_minutes(db, tmp_path):
    for minutes in (1, 30, 59):
        _insert_lookup(db, minutes_ago=minutes)
    for minutes in (61, 120, 60 * 24):  # outside the hour: not counted, however many
        _insert_lookup(db, minutes_ago=minutes)
    check = _failures(db, tmp_path)
    assert check.ok is True and check.value == 3


@pytest.mark.db
def test_rag_lookup_failures_ignores_every_status_but_failed(db, tmp_path):
    for status in ("ok", "empty", "budget"):
        for _ in range(4):
            _insert_lookup(db, status=status, kind=None, minutes_ago=5)
    for _ in range(4):
        _insert_lookup(db, minutes_ago=5)
    check = _failures(db, tmp_path)
    assert check.ok is True and check.value == 4


@pytest.mark.db
def test_rag_lookup_failures_says_which_kinds_failed(db, tmp_path):
    for kind, n in (("auth", 3), ("rate_limit", 2), ("timeout", 1)):
        for _ in range(n):
            _insert_lookup(db, kind=kind, minutes_ago=2)
    _insert_lookup(db, kind=None, minutes_ago=2)  # a failed row older than migration 023 has none
    check = _failures(db, tmp_path)
    assert check.ok is False and check.value == 7
    assert (
        "auth 3" in check.detail and "rate_limit 2" in check.detail and "timeout 1" in check.detail
    )
    assert "unknown 1" in check.detail
    assert check.detail.index("auth 3") < check.detail.index("rate_limit 2")  # the most first


@pytest.mark.db
def test_rag_lookup_failures_clears_when_the_failures_age_out(db, tmp_path):
    for _ in range(6):
        _insert_lookup(db, minutes_ago=59.9)
    assert _failures(db, tmp_path).ok is False
    db.execute("UPDATE rag_results SET created_at = created_at - interval '1 hour'")
    assert _failures(db, tmp_path).ok is True


@pytest.mark.db
def test_rag_lookup_failures_is_not_applicable_with_the_rag_off(db, tmp_path):
    """With `RAG_ENABLED` false no lookup runs, so a failure left from before the switch went off must not
    alarm for an hour after it."""
    for _ in range(9):
        _insert_lookup(db, minutes_ago=1)
    check = _run_check(db, tmp_path, _cfg(RAG_ENABLED=False))["rag_lookup_failures"]
    assert check.ok is True
    assert check.detail == "n/a — RAG off"
    assert (check.value, check.threshold) == (None, 5)


@pytest.mark.db
def test_rag_lookup_failures_does_not_follow_the_draft_switch(db, tmp_path):
    """Only the lookup can fail a lookup: `KNOWLEDGE_DRAFT_ENABLED` alone does not make the check live."""
    for _ in range(9):
        _insert_lookup(db, minutes_ago=1)
    check = _run_check(db, tmp_path, _cfg(RAG_ENABLED=False, KNOWLEDGE_DRAFT_ENABLED=True))[
        "rag_lookup_failures"
    ]
    assert check.ok is True and check.detail == "n/a — RAG off"


def test_rag_lookup_failures_off_runs_no_sql():
    conn = _Refusing()
    result = health._check_rag_lookup_failures(conn, _cfg())
    assert result.ok is True and result.detail == "n/a — RAG off"
    assert conn.savepoints == 0


@pytest.mark.db
def test_a_burst_of_failed_lookups_alarms_the_report_and_writes_health_alarm(
    db, tmp_path, monkeypatch
):
    sent = _fake_notify(monkeypatch)
    _seed_all_ok(db, tmp_path)
    for _ in range(5):
        _insert_lookup(db, kind="auth", minutes_ago=3)

    report = health.check(
        db, _cfg(RAG_ENABLED=True), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path
    )

    assert report.ok is False
    assert _levels(sent) == ["alarm"] and "rag_lookup_failures" in sent[0][1]
    (payload,) = db.execute(
        "SELECT payload FROM audit_events WHERE event_type = 'health.alarm'"
    ).fetchone()
    assert payload == {"failing": ["rag_lookup_failures"], "new": ["rag_lookup_failures"]}


def test_rag_budget_off_runs_no_sql():
    conn = _Refusing()  # every statement would raise, and a savepoint would be counted
    result = health._check_rag_budget(conn, _cfg())
    assert result.ok is True and result.detail == "n/a — RAG off"
    assert conn.savepoints == 0


@pytest.mark.db
def test_a_table_the_queue_check_cannot_read_fails_that_check_alone(db, tmp_path):
    """The code deployed before migration 020: the missing table fails its own check, closed, with
    a detail that says why; the other checks are unharmed and the `system_health` row is written
    (the savepoint keeps the run's transaction usable)."""
    db.execute("ALTER TABLE knowledge_drafts RENAME TO knowledge_drafts_gone")  # rolled back

    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)

    checks = _by_name(report)
    assert checks["knowledge_queue"].ok is False and checks["knowledge_queue"].value is None
    assert "migration 020" in checks["knowledge_queue"].detail
    assert report.checked_at is not None
    assert checks["disk_free"].ok is True and checks["rag_budget"].ok is True


class _Refusing:
    """A connection whose every statement fails, as one without migration 020's tables does."""

    def __init__(self) -> None:
        self.savepoints = 0

    def execute(self, *args, **kwargs):
        raise psycopg.errors.UndefinedTable('relation "x" does not exist: SECRET-SQL-TEXT')

    def transaction(self):
        self.savepoints += 1
        return contextlib.nullcontext()


@pytest.mark.parametrize(
    ("check", "name"),
    [
        (lambda c: health._check_knowledge_queue(c, _cfg()), "knowledge_queue"),
        (lambda c: health._check_knowledge_integrity(c), "knowledge_integrity"),
        (lambda c: health._check_rag_budget(c, _cfg(RAG_ENABLED=True)), "rag_budget"),
        (
            lambda c: health._check_rag_lookup_failures(c, _cfg(RAG_ENABLED=True)),
            "rag_lookup_failures",
        ),
    ],
)
def test_each_knowledge_check_fails_closed_without_the_driver_text(check, name):
    conn = _Refusing()

    result = check(conn)

    assert (result.name, result.ok, result.value) == (name, False, None)
    assert "migration 020" in result.detail and "SECRET-SQL-TEXT" not in result.detail
    assert conn.savepoints == 1


@pytest.mark.db
def test_the_knowledge_checks_alarm_the_report_and_write_health_alarm(db, tmp_path, monkeypatch):
    sent = _fake_notify(monkeypatch)
    _seed_all_ok(db, tmp_path)
    _insert_integrity_failure(db, entry_id=str(uuid.uuid4()), hours_ago=1)

    report = health.check(db, _cfg(), clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)

    assert report.ok is False
    assert _levels(sent) == ["alarm"]
    assert "knowledge_integrity" in sent[0][1]
    (payload,) = db.execute(
        "SELECT payload FROM audit_events WHERE event_type = 'health.alarm'"
    ).fetchone()
    assert payload == {"failing": ["knowledge_integrity"], "new": ["knowledge_integrity"]}


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


@pytest.mark.db
def test_alarm_set_change_tracks_multiple_failing_checks_independently(db, tmp_path, monkeypatch):
    """Review round 1, S3's probe scenario: a check that stays failing (here
    `backup_age`, an empty `backups_dir` from the start) no longer masks a
    later, *different* check (`heartbeat`) starting to fail — and a
    recovery-only change (heartbeat fixed, backup_age still failing) sends
    but writes no second `health.alarm`."""
    sent = _fake_notify(monkeypatch)
    _seed_heartbeat(db, minutes_ago=1)  # starts fresh/ok
    _seed_asset(db)
    # `tmp_path` stays empty on purpose: backup_age fails from t0 onward.
    cfg = _cfg()
    t0 = _MORNING_UTC

    def alarm_payloads():
        rows = db.execute(
            "SELECT payload FROM audit_events WHERE event_type = 'health.alarm' ORDER BY audit_id"
        ).fetchall()
        return [row[0] for row in rows]

    r1 = health.check(db, cfg, clock=_clock_at(t0), backups_dir=tmp_path)
    assert r1.ok is False
    assert _by_name(r1)["backup_age"].ok is False
    assert _levels(sent) == ["alarm"]
    payloads = alarm_payloads()
    assert len(payloads) == 1
    assert sorted(payloads[0]["failing"]) == ["backup_age"]
    assert sorted(payloads[0]["new"]) == ["backup_age"]

    # heartbeat ALSO goes stale — backup_age is still failing throughout.
    db.execute(
        "UPDATE source_heartbeat SET last_seen_at = now() - interval '45 minutes' "
        "WHERE manager_id = 'indexer'"
    )
    t1 = t0 + timedelta(minutes=5)
    r2 = health.check(db, cfg, clock=_clock_at(t1), backups_dir=tmp_path)
    assert r2.ok is False
    assert _levels(sent) == ["alarm", "alarm"]  # a second send
    payloads = alarm_payloads()
    assert len(payloads) == 2  # a second health.alarm
    assert sorted(payloads[1]["failing"]) == ["backup_age", "heartbeat"]
    assert sorted(payloads[1]["new"]) == ["heartbeat"]

    # heartbeat recovers; backup_age still failing — a recovery-only change.
    db.execute(
        "UPDATE source_heartbeat SET last_seen_at = now() - interval '1 minute' "
        "WHERE manager_id = 'indexer'"
    )
    t2 = t1 + timedelta(minutes=5)
    r3 = health.check(db, cfg, clock=_clock_at(t2), backups_dir=tmp_path)
    assert r3.ok is False  # backup_age alone still fails
    assert _levels(sent) == ["alarm", "alarm", "alarm"]  # a send (the set changed)
    assert len(alarm_payloads()) == 2  # but no new health.alarm — nothing new joined


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


@pytest.mark.db
def test_daily_summary_alone_never_writes_health_alarm(db, tmp_path, monkeypatch):
    """N8, mutant M2: a daily summary with no state change must send through
    `notify.send` but must never write `health.alarm` — that event is only
    for a name newly joining the failing set (S3)."""
    sent = _fake_notify(monkeypatch)
    _seed_all_ok(db, tmp_path)
    cfg = _cfg()
    at_0805 = datetime(2026, 9, 29, 1, 5, 0, tzinfo=UTC)  # 08:05 local, first run, all ok

    report = health.check(db, cfg, clock=_clock_at(at_0805), backups_dir=tmp_path)

    assert report.ok is True
    assert _levels(sent) == ["ok"]  # the summary did send
    (count,) = db.execute(
        "SELECT count(*) FROM audit_events WHERE event_type = 'health.alarm'"
    ).fetchone()
    assert count == 0


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


@pytest.mark.db
def test_token_never_reaches_a_persisted_row(db, tmp_path, monkeypatch):
    """Review round 1, S4: even with Telegram configured and its send
    failing, the token must never land in a persisted row — not
    `system_health.checks`, not `audit_events.payload`. `notify._build_client`
    is monkeypatched to a `MockTransport` (no real network) that always
    fails, so the real `notify.send` runs its real Telegram branch end to
    end, through the real `check()`."""
    token = "123456:AA-super-secret-token-for-health-test"

    def fail_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("boom", request=request)

    monkeypatch.setattr(
        notify, "_build_client", lambda: httpx.Client(transport=httpx.MockTransport(fail_handler))
    )
    cfg = _cfg(NOTIFY_TELEGRAM_BOT_TOKEN=token, NOTIFY_TELEGRAM_CHAT_ID="-1")
    db.execute(
        "INSERT INTO source_heartbeat (manager_id, last_seen_at) "
        "VALUES ('indexer', now() - interval '45 minutes')"
    )

    report = health.check(db, cfg, clock=_clock_at(_MORNING_UTC), backups_dir=tmp_path)
    assert report.ok is False

    (checks_text,) = db.execute(
        "SELECT checks::text FROM system_health WHERE checked_at = %s", (report.checked_at,)
    ).fetchone()
    assert token not in checks_text

    rows = db.execute(
        "SELECT payload::text FROM audit_events WHERE event_type = 'health.alarm'"
    ).fetchall()
    assert rows  # the alarm row exists — this is a real assertion, not a vacuous pass
    assert all(token not in row[0] for row in rows)


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
    # B1 (review round 1): `handle()` now calls `_raise_idle_timeout(conn, cfg)`
    # — a real `conn.execute(...)` — as its first statement, before
    # `health.check`, so the fake `conn` here needs an `execute` and the
    # order of the two calls is itself part of what this test pins.
    order: list[str] = []

    def fake_check(conn, cfg):
        order.append("check")

    class _FakeConn:
        def execute(self, *args, **kwargs):
            order.append("execute")

    monkeypatch.setattr(health_handler.health, "check", fake_check)

    conn = _FakeConn()
    job = Job(job_id=1, job_type="health", subject_id="system", attempts=1)
    result = health_handler.handle(conn, job, cfg=_cfg())

    assert health_handler.JOB_TYPE == "health"
    assert not hasattr(health_handler, "STATEMENT_TIMEOUT")
    assert result.delay_s == 300
    assert order == ["execute", "check"]  # the idle-timeout raise runs before check()


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


def _scratch_source_parts() -> urllib.parse.SplitResult:
    session = os.environ.get("TEST_DATABASE_URL", conftest.DEFAULT_TEST_DATABASE_URL)
    return urllib.parse.urlsplit(session)


def _scratch_dbname() -> str:
    return f"{_scratch_source_parts().path.lstrip('/')}_health_test"


def _scratch_dsn(dbname: str) -> str:
    """A full DSN — scheme/host/port/user/password copied verbatim from
    `TEST_DATABASE_URL`, only the path (database name) replaced — never a
    bare `postgresql:///<name>`. `psycopg.connect` resolves a host-less DSN
    through this *process's* own `PGHOST`/`PGPORT`/`PGUSER` environment
    variables, and a bare `pytest -m db` invocation that only sets
    `TEST_DATABASE_URL` (`order_proof.sh`, unlike `make test-db`'s
    `scripts/dsn_env.py` export) never populates them — replacing only the
    path keeps this fixture correct either way."""
    return urllib.parse.urlunsplit(_scratch_source_parts()._replace(path=f"/{dbname}"))


def _scratch_subprocess_env(dsn: str) -> dict[str, str]:
    """`PGHOST`/`PGPORT`/`PGUSER`/`PGPASSWORD` for the bare `dropdb`/
    `createdb` commands below, derived from `dsn` itself for the same reason
    `_scratch_dsn` is a full DSN — never relied on from the ambient
    environment."""
    parts = urllib.parse.urlsplit(dsn)
    env = dict(os.environ)
    if parts.hostname:
        env["PGHOST"] = parts.hostname
    if parts.port:
        env["PGPORT"] = str(parts.port)
    if parts.username:
        env["PGUSER"] = urllib.parse.unquote(parts.username)
    if parts.password:
        env["PGPASSWORD"] = urllib.parse.unquote(parts.password)
    return env


@pytest.fixture(scope="module")
def scratch_dsn():
    if shutil.which("psql") is None or shutil.which("createdb") is None:
        pytest.skip("psql/createdb not on PATH — cannot build the health scratch database")
    dbname = _scratch_dbname()
    dsn = _scratch_dsn(dbname)
    env = _scratch_subprocess_env(dsn)
    subprocess.run(["dropdb", "--if-exists", dbname], check=True, capture_output=True, env=env)
    subprocess.run(["createdb", dbname], check=True, capture_output=True, env=env)
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
        subprocess.run(["dropdb", "--if-exists", dbname], check=False, capture_output=True, env=env)


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


# ===========================================================================
# B1 (review round 1, blocker) — a slow `notify.send` must not kill the
# worker's connection. `infra/db.py`'s `transaction()` (the real wrapper
# `infra.worker._run_claimed_job` runs every handler inside) sets
# `idle_in_transaction_session_timeout = '10s'`; this test compresses that to
# 1s on a real, commit-capable connection (`sdb`) — mimicking the worker's
# own wrapping transaction — then runs the real `handle()` with `notify.send`
# faked to sleep 1.5s. If `handle()`'s own `_raise_idle_timeout` did not run
# first, Postgres kills the idle session partway through that sleep and
# either the later `_insert_report` or the final `commit()` raises
# `psycopg.OperationalError` — the Reviewer's exact finding.
# ===========================================================================


@pytest.mark.db
def test_slow_notify_does_not_kill_the_connection_b1(sdb, tmp_path, monkeypatch):
    def slow_send(level: str, text: str, **kwargs) -> bool:
        time.sleep(1.5)
        return True

    monkeypatch.setattr(notify, "send", slow_send)
    # A stale heartbeat so `check()` has a state change to send on.
    sdb.execute(
        "INSERT INTO source_heartbeat (manager_id, last_seen_at) "
        "VALUES ('indexer', now() - interval '45 minutes')"
    )
    # The wrapping transaction() a real job runs inside, compressed to 1s so
    # the test is fast; `handle()`'s own SET LOCAL must override this before
    # `slow_send`'s sleep, or the session dies mid-sleep.
    sdb.execute("SET LOCAL idle_in_transaction_session_timeout = '1s'")

    cfg = _cfg(JOB_LOCK_TIMEOUT_S=300)
    job = Job(job_id=1, job_type="health", subject_id="system", attempts=1)

    health_handler.handle(sdb, job, cfg=cfg)  # must not raise
    sdb.commit()  # must succeed — proves the row is really committed, not just executed

    (count,) = sdb.execute("SELECT count(*) FROM system_health").fetchone()
    assert count == 1


@pytest.mark.db
def test_health_route_is_registered_in_openapi():
    assert "/health" in sorted(main.app.openapi()["paths"])


@pytest.mark.db
def test_get_health_from_loopback_without_a_session_is_200(sdb, tmp_path, monkeypatch):
    monkeypatch.setattr(notify, "send", lambda *a, **k: True)
    # N10: each router test gets its own clock — a distinct `checked_at`, so
    # this test's `system_health` row never collides with another's.
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
    health.check(
        sdb, _cfg(), clock=_clock_at(_MORNING_UTC + timedelta(minutes=1)), backups_dir=tmp_path
    )
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
    health.check(
        sdb, _cfg(), clock=_clock_at(_MORNING_UTC + timedelta(minutes=2)), backups_dir=tmp_path
    )
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
    health.check(
        sdb, _cfg(), clock=_clock_at(_MORNING_UTC + timedelta(minutes=3)), backups_dir=tmp_path
    )
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
