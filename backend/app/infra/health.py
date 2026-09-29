"""`infra.health` — the ten §3.9 thresholds, one `system_health` row per run,
`notify.send` only on a state change plus a daily 08:05 summary, and
`health.alarm` written on every `ok -> alarm` transition.

`infra` imports nothing (G1, context pack §4) and that decides three things
here (P5-tasks.md design note 1): (a) check 9 (`digest_unreviewed`) cannot
call `tier1.digest.unreviewed_count` and is three lines of SQL instead —
`alerts` with `status = 'auto_closed'` and `closed_at` in yesterday's local
window, `LEFT JOIN autoclose_reviews`, count the misses; (b) check 6
(`monthly_cost`) cannot call `audit.llm_runs.month_spend_usd` and sums
`llm_runs.cost_usd` for the current month itself; (c) `health.alarm` is
written with raw SQL, exactly as `infra/jobs.py:152` writes `job.exhausted`,
never through `app.audit.events.write_event`.

Each check is a small function returning the same shape (`CheckResult`):
`{name, ok, value, threshold, detail}`, so the report, the `system_health`
row and `GET /health` all read one structure.

`checked_at` comes from the database's own clock (§9), read once via
`SELECT now()` at the top of `check()` and reused for both the `system_health`
insert and every local-time decision below it (the daily 08:05 summary, the
17:00 gate on check 9) — never `datetime.now()`. `checked_at` is
`system_health`'s primary key (migration 015 note 5): two runs landing in the
same microsecond collide on insert. That is the contract's choice, not this
module's to fix, so the insert runs inside a savepoint (`conn.transaction()`,
`tier1/labels.py`'s precedent) and a `UniqueViolation` is caught, logged, and
this tick is skipped — never retried with a nudged timestamp. Recorded as a
P8 limitation in the task report.
"""

from __future__ import annotations

import dataclasses
import json
import shutil
import time
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import psycopg
from psycopg.types.json import Jsonb

from app.infra import notify
from app.infra.config import Config

# ── thresholds §3.9 gives no §6.3 key for (module constants, not Config) ────
_INTAKE_BACKLOG_MAX_MIN = 5
_JOB_BACKLOG_MAX_MIN = 10
_LLM_NULL_RATIO_MAX_PCT = 30
_TRIAGE_UNAVAILABLE_MAX_PCT = 10
_MONTHLY_COST_MAX_PCT = 80
_BACKUP_MAX_AGE_HOURS = 36
_DISK_FREE_MIN_FRACTION = 0.20
_DIGEST_GATE_HOUR = 17
_SUMMARY_HOUR = 8
_SUMMARY_MINUTE = 5


@dataclasses.dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    value: float | int | str | None
    threshold: float | int | str | None
    detail: str


@dataclasses.dataclass(frozen=True)
class HealthReport:
    checked_at: datetime | None  # None only when this tick's insert collided (design note 3)
    checks: list[CheckResult]
    ok: bool


def _db_now(conn: psycopg.Connection) -> datetime:
    return conn.execute("SELECT now()").fetchone()[0]


# ── the ten checks, in §3.9's order (design note 2) ─────────────────────────


def _check_heartbeat(conn: psycopg.Connection, cfg: Config) -> CheckResult:
    (age_min,) = conn.execute(
        "SELECT extract(epoch FROM (now() - max(last_seen_at))) / 60 FROM source_heartbeat"
    ).fetchone()
    if age_min is None:
        return CheckResult(
            "heartbeat",
            False,
            None,
            cfg.HEARTBEAT_MAX_AGE_MIN,
            "no heartbeat has ever been recorded",
        )
    ok = age_min <= cfg.HEARTBEAT_MAX_AGE_MIN
    detail = (
        f"last heartbeat {age_min:.1f} min ago"
        if ok
        else f"last heartbeat {age_min:.1f} min ago, over {cfg.HEARTBEAT_MAX_AGE_MIN} — the source stopped sending"
    )
    return CheckResult("heartbeat", ok, round(float(age_min), 1), cfg.HEARTBEAT_MAX_AGE_MIN, detail)


def _check_intake_backlog(conn: psycopg.Connection) -> CheckResult:
    (age_min,) = conn.execute(
        "SELECT extract(epoch FROM (now() - min(received_at))) / 60 "
        "FROM intake WHERE processed_at IS NULL AND error IS NULL"
    ).fetchone()
    if age_min is None:
        return CheckResult(
            "intake_backlog", True, 0.0, _INTAKE_BACKLOG_MAX_MIN, "no unprocessed intake rows"
        )
    ok = age_min <= _INTAKE_BACKLOG_MAX_MIN
    detail = f"oldest unprocessed intake row is {age_min:.1f} min old"
    return CheckResult(
        "intake_backlog", ok, round(float(age_min), 1), _INTAKE_BACKLOG_MAX_MIN, detail
    )


def _check_job_backlog(conn: psycopg.Connection) -> CheckResult:
    (age_min,) = conn.execute(
        "SELECT extract(epoch FROM (now() - min(scheduled_at))) / 60 "
        "FROM jobs WHERE status = 'pending' AND scheduled_at <= now()"
    ).fetchone()
    if age_min is None:
        return CheckResult("job_backlog", True, 0.0, _JOB_BACKLOG_MAX_MIN, "no due pending jobs")
    ok = age_min <= _JOB_BACKLOG_MAX_MIN
    detail = f"oldest due pending job is {age_min:.1f} min old"
    return CheckResult("job_backlog", ok, round(float(age_min), 1), _JOB_BACKLOG_MAX_MIN, detail)


def _check_llm_null_ratio(conn: psycopg.Connection) -> CheckResult:
    null_count, total = conn.execute(
        "SELECT count(*) FILTER (WHERE result IS NULL), count(*) "
        "FROM llm_runs WHERE created_at > now() - interval '1 hour'"
    ).fetchone()
    if total == 0:
        return CheckResult(
            "llm_null_ratio", True, 0.0, _LLM_NULL_RATIO_MAX_PCT, "no llm_runs in the last hour"
        )
    pct = 100.0 * null_count / total
    ok = pct <= _LLM_NULL_RATIO_MAX_PCT
    detail = f"{null_count}/{total} llm_runs with a null result in the last hour"
    return CheckResult("llm_null_ratio", ok, round(pct, 1), _LLM_NULL_RATIO_MAX_PCT, detail)


def _check_triage_unavailable(conn: psycopg.Connection) -> CheckResult:
    unavailable_count, total = conn.execute(
        "SELECT count(*) FILTER (WHERE triage_status = 'unavailable'), count(*) "
        "FROM alerts WHERE received_at > now() - interval '24 hours'"
    ).fetchone()
    if total == 0:
        return CheckResult(
            "triage_unavailable",
            True,
            0.0,
            _TRIAGE_UNAVAILABLE_MAX_PCT,
            "no alerts received in the last 24 hours",
        )
    pct = 100.0 * unavailable_count / total
    ok = pct <= _TRIAGE_UNAVAILABLE_MAX_PCT
    detail = f"{unavailable_count}/{total} alerts unavailable in the last 24 hours"
    return CheckResult("triage_unavailable", ok, round(pct, 1), _TRIAGE_UNAVAILABLE_MAX_PCT, detail)


def _check_monthly_cost(conn: psycopg.Connection, cfg: Config) -> CheckResult:
    (spend,) = conn.execute(
        "SELECT coalesce(sum(cost_usd), 0) FROM llm_runs "
        "WHERE date_trunc('month', created_at) = date_trunc('month', now())"
    ).fetchone()
    spend = float(spend)
    cap = cfg.LLM_MONTHLY_USD_CAP
    pct = (100.0 * spend / cap) if cap else 0.0
    ok = pct <= _MONTHLY_COST_MAX_PCT
    detail = f"${spend:.2f} of ${cap} monthly cap ({pct:.1f}%)"
    return CheckResult("monthly_cost", ok, round(pct, 1), _MONTHLY_COST_MAX_PCT, detail)


def _check_backup_age(backups_dir: Path | None = None) -> CheckResult:
    """The newest `backups/soc-*.dump`, falling back to `backups/latest.dump`
    (§3.9). `backups_dir` defaults to the repository's `backups/` (relative to
    the current directory, `scripts/backup.sh`'s own convention) and is
    overridable so a test never has to write into the tracked directory."""
    directory = backups_dir if backups_dir is not None else Path("backups")
    candidates = sorted(directory.glob("soc-*.dump")) if directory.is_dir() else []
    newest = max(candidates, key=lambda p: p.stat().st_mtime, default=None)
    if newest is None:
        fallback = directory / "latest.dump"
        newest = fallback if fallback.is_file() else None
    if newest is None:
        return CheckResult(
            "backup_age", False, None, _BACKUP_MAX_AGE_HOURS, "no backup file found under backups/"
        )
    age_hours = (time.time() - newest.stat().st_mtime) / 3600
    ok = age_hours <= _BACKUP_MAX_AGE_HOURS
    detail = (
        f"newest backup {newest.name} is {age_hours:.1f}h old"
        if ok
        else f"newest backup {newest.name} is {age_hours:.1f}h old, over {_BACKUP_MAX_AGE_HOURS}h"
    )
    return CheckResult("backup_age", ok, round(age_hours, 1), _BACKUP_MAX_AGE_HOURS, detail)


def _check_inventory_empty(conn: psycopg.Connection) -> CheckResult:
    (count,) = conn.execute("SELECT count(*) FROM assets").fetchone()
    ok = count > 0
    detail = f"{count} asset(s) in inventory" if ok else "assets table is empty"
    return CheckResult("inventory_empty", ok, count, 1, detail)


def _check_digest_unreviewed(conn: psycopg.Connection, now_local: datetime) -> CheckResult:
    """Design note 1(a) — three lines of SQL, not `tier1.digest`. Evaluated
    only from 17:00 local onward (`now_local`, derived from the database's own
    clock); `ok` before that, so the alarm reads as "nobody reviewed it
    today", never "it is 09:00"."""
    if now_local.hour < _DIGEST_GATE_HOUR:
        return CheckResult(
            "digest_unreviewed", True, None, 0, f"not evaluated before {_DIGEST_GATE_HOUR}:00 local"
        )
    today_local_midnight = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday_local_start = today_local_midnight - timedelta(days=1)
    (misses,) = conn.execute(
        """
        SELECT count(*)
        FROM alerts a
        LEFT JOIN autoclose_reviews r ON r.alert_id = a.alert_id
        WHERE a.status = 'auto_closed'
          AND a.closed_at >= %s AND a.closed_at < %s
          AND r.alert_id IS NULL
        """,
        (yesterday_local_start, today_local_midnight),
    ).fetchone()
    ok = misses == 0
    detail = (
        "all of yesterday's auto-closed alerts are reviewed, or there were none"
        if ok
        else f"{misses} auto-closed alert(s) from yesterday have no review"
    )
    return CheckResult("digest_unreviewed", ok, misses, 0, detail)


def _check_disk_free() -> CheckResult:
    usage = shutil.disk_usage(".")
    free_fraction = (usage.free / usage.total) if usage.total else 1.0
    ok = free_fraction >= _DISK_FREE_MIN_FRACTION
    pct = round(free_fraction * 100, 1)
    threshold_pct = _DISK_FREE_MIN_FRACTION * 100
    detail = f"{pct}% free" if ok else f"{pct}% free, under {threshold_pct:.0f}%"
    return CheckResult("disk_free", ok, pct, threshold_pct, detail)


# ── persistence and the state-change notification rule (design notes 3, 4) ──


def _read_latest(conn: psycopg.Connection) -> tuple[datetime, bool] | None:
    row = conn.execute(
        "SELECT checked_at, ok FROM system_health ORDER BY checked_at DESC LIMIT 1"
    ).fetchone()
    return (row[0], row[1]) if row else None


def _insert_report(
    conn: psycopg.Connection, checked_at: datetime, checks: list[CheckResult], ok: bool
) -> datetime | None:
    """One `system_health` row. `checked_at` is the primary key (migration
    015 note 5); a collision is caught on a savepoint (`tier1/labels.py`'s
    precedent for `conn.transaction()` as a savepoint) so the caller's own
    transaction stays usable — logged, and this tick's row/notification are
    both skipped, never retried with a nudged timestamp."""
    try:
        with conn.transaction():
            row = conn.execute(
                "INSERT INTO system_health (checked_at, checks, ok) VALUES (%s, %s, %s) "
                "RETURNING checked_at",
                (checked_at, Jsonb([dataclasses.asdict(c) for c in checks]), ok),
            ).fetchone()
    except psycopg.errors.UniqueViolation:
        print(json.dumps({"health": "system_health.checked_at collision — this tick skipped"}))
        return None
    return row[0]


def _write_alarm_event(conn: psycopg.Connection, checks: list[CheckResult]) -> None:
    """`health.alarm`, written with raw SQL — exactly `infra/jobs.py:152`'s
    precedent for `job.exhausted`, because `infra` imports nothing (G1) and
    cannot call `app.audit.events.write_event`. `actor_role='system'` requires
    `actor_id IS NULL` (`ck_audit_actor_id_theo_role`), so it is omitted, not
    passed as `None` — matching the precedent's own column list."""
    failing = [c.name for c in checks if not c.ok]
    conn.execute(
        "INSERT INTO audit_events (event_type, subject_id, actor_role, payload) "
        "VALUES (%s, %s, %s, %s)",
        ("health.alarm", "system", "system", Jsonb({"failing": failing})),
    )


def _is_daily_summary_due(
    now_local: datetime, previous_checked_at: datetime | None, tz_name: str
) -> bool:
    """True on the first run each day whose local time has reached 08:05
    (design note 4). "Already sent today" is read from the previous
    `system_health` row's own `checked_at` — not from process memory, exactly
    like the state-change rule it sits next to, so a worker restart does not
    re-send it either."""
    threshold_local = now_local.replace(
        hour=_SUMMARY_HOUR, minute=_SUMMARY_MINUTE, second=0, microsecond=0
    )
    if now_local < threshold_local:
        return False
    if previous_checked_at is not None:
        previous_local = previous_checked_at.astimezone(ZoneInfo(tz_name))
        if previous_local >= threshold_local:
            return False
    return True


def _format_message(ok: bool, checks: list[CheckResult], *, state_changed: bool) -> str:
    failing = ", ".join(c.name for c in checks if not c.ok)
    if state_changed:
        return "health: recovered — all checks ok" if ok else f"health: ALARM — {failing}"
    return (
        f"health: daily summary — alarm active: {failing}"
        if failing
        else "health: daily summary — all checks ok"
    )


# ── the entry point ──────────────────────────────────────────────────────────


def check(
    conn: psycopg.Connection,
    cfg: Config,
    *,
    clock: Callable[[psycopg.Connection], datetime] | None = None,
    backups_dir: Path | None = None,
) -> HealthReport:
    """Run all ten thresholds, write one `system_health` row, and
    `notify.send` only on a state change plus the daily 08:05 summary (design
    notes 2-4). `clock`/`backups_dir` are keyword-only test seams — production
    always reads the database's own clock (`_db_now`) and the real
    `backups/`; a test injects a fixed `(conn) -> datetime` to make the 17:00
    and 08:05 local-time boundaries deterministic, since Postgres's `now()`
    cannot be frozen from a test without a server-side extension.
    """
    read_now = clock or _db_now
    checked_at = read_now(conn)
    now_local = checked_at.astimezone(ZoneInfo(cfg.DISPLAY_TZ))

    checks = [
        _check_heartbeat(conn, cfg),
        _check_intake_backlog(conn),
        _check_job_backlog(conn),
        _check_llm_null_ratio(conn),
        _check_triage_unavailable(conn),
        _check_monthly_cost(conn, cfg),
        _check_backup_age(backups_dir),
        _check_inventory_empty(conn),
        _check_digest_unreviewed(conn, now_local),
        _check_disk_free(),
    ]
    ok = all(c.ok for c in checks)

    previous = _read_latest(conn)
    row_checked_at = _insert_report(conn, checked_at, checks, ok)

    if row_checked_at is not None:
        previous_ok = previous[1] if previous is not None else True
        previous_checked_at = previous[0] if previous is not None else None
        state_changed = previous_ok != ok
        summary_due = _is_daily_summary_due(now_local, previous_checked_at, cfg.DISPLAY_TZ)
        if state_changed or summary_due:
            text = _format_message(ok, checks, state_changed=state_changed)
            level = "alarm" if not ok else "ok"
            notify.send(level, text, cfg=cfg)
            if state_changed and not ok:
                _write_alarm_event(conn, checks)

    return HealthReport(checked_at=row_checked_at, checks=checks, ok=ok)
