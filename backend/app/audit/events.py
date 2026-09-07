"""Append an audit_events row for every human decision and lifecycle transition.

`EVENT_TYPES` mirrors the 27-name set `ck_audit_event_type` fixes (context pack
§6.1; migration 016 = 21 v1 names + 6 v3 names) — kept here so an unknown name is
a clear `PermanentError` before any SQL runs, rather than the DB CHECK's generic
constraint-violation message. `audit_events` is append-only (017); this module
never updates or deletes a row.
"""

from __future__ import annotations

from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from app.infra.errors import PermanentError

EVENT_TYPES = frozenset(
    {
        # 21 v1 names (008_audit_event_type.sql)
        "alert.received",
        "alert.duplicate_merged",
        "alert.auto_closed",
        "alert.autoclose_blocked_critical",
        "alert.enrich_started",
        "alert.enriched",
        "alert.reopened",
        "job.exhausted",
        "triage.suggested",
        "alert.acknowledged",
        "tier1.decided",
        "tier1.escalated",
        "case.opened",
        "case.truncated",
        "case.analyzed",
        "tier2.concluded",
        "authz.denied",
        "admin.user_created",
        "admin.user_updated",
        "admin.job_retried",
        "admin.autoclose_rule_toggled",
        # 6 v3 additions (016_alter_alerts_jobs_llm_runs_users.sql)
        "autoclose.reviewed",
        "rule.suspected_wrong",
        "llm.gate_forced",
        "llm.builder_violation",
        "health.alarm",
        "label.created",
    }
)


def write_event(
    conn: psycopg.Connection,
    event_type: str,
    subject_id: str,
    actor_role: str,
    *,
    actor_id: str | None = None,
    payload: dict[str, Any] | None = None,
) -> int:
    """Insert one `audit_events` row and return its `audit_id`.

    Two DB CHECKs are respected, not duplicated here: `ck_audit_actor_role` and
    `ck_audit_actor_id_theo_role` (`actor_role='system'` requires `actor_id IS
    NULL`; `'analyst'` requires it `NOT NULL`) — Postgres raises them, this
    function does not pre-validate `actor_role`/`actor_id` in Python.
    """
    if event_type not in EVENT_TYPES:
        raise PermanentError(f"event_type: not a recognised audit event type: {event_type!r}")
    row = conn.execute(
        """
        INSERT INTO audit_events (event_type, subject_id, actor_role, actor_id, payload)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING audit_id
        """,
        (
            event_type,
            subject_id,
            actor_role,
            actor_id,
            Jsonb(payload) if payload is not None else None,
        ),
    ).fetchone()
    return row[0]
