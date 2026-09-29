"""Record the Tier-1 decision (false_positive/benign/escalate) and fan it out to duplicates.

A thin, guarded layer over `domain.transitions` (P4-tasks.md planning decision
4): no function here writes `alerts.status` (G2 — only `domain/` does that);
each guard reads the row it needs, either `FOR UPDATE` (acknowledge, escalate —
`transitions.escalate` has no status guard on its trigger, §5 of the card's
index) or as part of `transitions.*`'s own guard, and converts a wrong-status
or stale-cluster refusal into a `DecisionConflict` whose `.body` is the 409
response `web/routers/tier1.py` returns as-is.

`DecisionConflict.body` is always built from the same six-column read
(`_conflict_row`) — reading is fine even though the write that follows (or
preceded) it is about to be rolled back (planning decision 3): nothing here
was meant to persist.
"""

from __future__ import annotations

import dataclasses
from typing import Literal

import psycopg

from app.domain import transitions
from app.infra import config
from app.tier1 import queue

_DISPLAY_NAME_SQL = "SELECT display_name FROM users WHERE user_id = %s"
_CONFLICT_ROW_SQL = (
    "SELECT status, occurrence_count, acknowledged_by, closed_at, close_reason, case_id "
    "FROM alerts WHERE alert_id = %s"
)

#: §6.4's decision verb -> `domain.transitions.decide`'s status literal.
_DECISION_MAP: dict[str, Literal["closed_fp", "closed_benign"]] = {
    "false_positive": "closed_fp",
    "benign": "closed_benign",
}

#: The initial escalate guard (design note 4): the trigger's own status decides
#: which of the three kinds a pre-existing refusal is (§5 — `transitions.escalate`
#: itself has no such guard). A status not listed here (received/enriching/
#: duplicate) falls back to "not_active".
_ESCALATE_GUARD_KIND: dict[str, str] = {
    "escalated_tier2": "already_in_case",
    "closed_fp": "already_decided",
    "closed_benign": "already_decided",
    "closed_confirmed": "already_decided",
    "auto_closed": "already_decided",
}


class NotFound(Exception):
    """No alert with the given id."""


class DecisionConflict(Exception):
    """A guard this module owns refused the call. `.body` is the 409 response,
    verbatim (`web/routers/tier1.py` never re-shapes it)."""

    def __init__(self, body: dict) -> None:
        self.body = body
        super().__init__(body["kind"])


@dataclasses.dataclass(frozen=True)
class Actor:
    user_id: str
    role: str


def _display_name(conn: psycopg.Connection, user_id: str | None) -> str | None:
    if user_id is None:
        return None
    row = conn.execute(_DISPLAY_NAME_SQL, (user_id,)).fetchone()
    return row[0] if row is not None else None


def _conflict_row(conn: psycopg.Connection, alert_id: str) -> tuple | None:
    return conn.execute(_CONFLICT_ROW_SQL, (alert_id,)).fetchone()


def _conflict_body(
    conn: psycopg.Connection,
    row: tuple | None,
    *,
    kind: str,
    seen_occurrence_count: int | None = None,
) -> dict:
    cfg = config.load()
    body: dict = {
        "kind": kind,
        "occurrence_count": None,
        "seen_occurrence_count": seen_occurrence_count,
        "delta": None,
        "tolerance": cfg.REVIEW_DELTA_TOLERANCE,
        "status": None,
        "decided_by": None,
        "decision": None,
        "decided_at": None,
        "acknowledged_by": None,
    }
    if row is None:
        return body
    status, occurrence_count, acknowledged_by, closed_at, _close_reason, _case_id = row
    decided = closed_at is not None
    acknowledged_by_name = _display_name(conn, acknowledged_by)
    body["occurrence_count"] = occurrence_count
    if seen_occurrence_count is not None:
        body["delta"] = occurrence_count - seen_occurrence_count
    body["status"] = status
    body["decided_by"] = acknowledged_by_name if decided else None
    body["decision"] = status if decided else None
    body["decided_at"] = closed_at.isoformat() if closed_at is not None else None
    body["acknowledged_by"] = acknowledged_by_name
    return body


def _conflict(
    conn: psycopg.Connection, alert_id: str, *, kind: str, seen_occurrence_count: int | None = None
) -> DecisionConflict:
    row = _conflict_row(conn, alert_id)
    return DecisionConflict(
        _conflict_body(conn, row, kind=kind, seen_occurrence_count=seen_occurrence_count)
    )


def acknowledge(conn: psycopg.Connection, alert_id: str, actor: Actor) -> dict:
    """A7 — idempotent (P6-2): the first `queued_tier1` caller wins; a second
    caller on an already-`tier1_active` alert gets the same, stored answer back,
    never a conflict. Any other status is `DecisionConflict("not_active")`."""
    row = conn.execute(
        "SELECT status, acknowledged_at, acknowledged_by FROM alerts WHERE alert_id = %s FOR UPDATE",
        (alert_id,),
    ).fetchone()
    if row is None:
        raise NotFound(f"alert_id={alert_id!r} does not exist")
    status, acknowledged_at, acknowledged_by = row
    if status == "queued_tier1":
        transitions.acknowledge(conn, alert_id, actor.user_id)
        acknowledged_at, acknowledged_by = conn.execute(
            "SELECT acknowledged_at, acknowledged_by FROM alerts WHERE alert_id = %s", (alert_id,)
        ).fetchone()
        first = True
    elif status == "tier1_active":
        first = False
    else:
        raise _conflict(conn, alert_id, kind="not_active")
    return {
        "alert_id": alert_id,
        "status": "tier1_active",
        "acknowledged_by": acknowledged_by,
        "acknowledged_by_name": _display_name(conn, acknowledged_by),
        "acknowledged_at": acknowledged_at,
        "first": first,
    }


def decide(
    conn: psycopg.Connection,
    alert_id: str,
    actor: Actor,
    *,
    decision: Literal["false_positive", "benign"],
    reason: str,
    seen_occurrence_count: int,
) -> dict:
    """A8/A9 (+ A10 fan-out), joined with ①'s latest suggestion for P8's
    evaluation payload. `SET LOCAL statement_timeout` is the first statement
    (phase-6: the fan-out is bounded — a `QueryCanceled` on a huge cluster is
    the route's 503, whole transaction rolled back, nothing written)."""
    if decision not in _DECISION_MAP:
        raise ValueError(f"decision: must be one of {sorted(_DECISION_MAP)}, got {decision!r}")
    reason = reason.strip()
    if not 1 <= len(reason) <= 500:
        raise ValueError("reason: must be 1-500 characters")

    conn.execute("SET LOCAL statement_timeout = '3s'")
    suggestion = queue.latest_suggestion(conn, alert_id)
    visible_row = conn.execute(
        "SELECT suggestion_visible FROM alerts WHERE alert_id = %s", (alert_id,)
    ).fetchone()
    suggestion_visible = visible_row[0] if visible_row is not None else None

    try:
        transitions.decide(
            conn,
            alert_id,
            actor.user_id,
            decision=_DECISION_MAP[decision],
            reason=reason,
            seen_occurrence_count=seen_occurrence_count,
            llm_suggestion=suggestion.suggested_action if suggestion else None,
            llm_confidence=suggestion.confidence if suggestion else None,
            gate_forced=suggestion.gate["forced"] if suggestion else None,
            suggestion_visible=suggestion_visible,
            llm_run_id=suggestion.run_id if suggestion else None,
        )
    except transitions.StaleState:
        row = _conflict_row(conn, alert_id)
        status = row[0] if row is not None else None
        closed_at = row[3] if row is not None else None
        if status != "tier1_active":
            kind = "already_decided" if closed_at is not None else "not_active"
        else:
            kind = "cluster_grew"
        raise DecisionConflict(
            _conflict_body(conn, row, kind=kind, seen_occurrence_count=seen_occurrence_count)
        ) from None

    closed_count = conn.execute(
        "SELECT count(*) FROM alerts WHERE alert_id = %s OR duplicate_of = %s",
        (alert_id, alert_id),
    ).fetchone()[0]
    return {
        "alert_id": alert_id,
        "status": _DECISION_MAP[decision],
        "closed_count": closed_count,
        "case_id": None,
    }


def escalate(
    conn: psycopg.Connection,
    alert_id: str,
    actor: Actor,
    *,
    title: str,
    severity: str | None = None,
) -> dict:
    """A11/A11b (+ A12), guarded before `transitions.escalate` — it has no
    status guard on the trigger (§5). `severity` defaults to the alert's own."""
    title = title.strip()
    if not 1 <= len(title) <= 200:
        raise ValueError("title: must be 1-200 characters")

    row = conn.execute(
        "SELECT status, severity FROM alerts WHERE alert_id = %s FOR UPDATE", (alert_id,)
    ).fetchone()
    if row is None:
        raise NotFound(f"alert_id={alert_id!r} does not exist")
    status, alert_severity = row
    if status not in ("queued_tier1", "tier1_active"):
        raise _conflict(conn, alert_id, kind=_ESCALATE_GUARD_KIND.get(status, "not_active"))
    if severity is None:
        severity = alert_severity

    try:
        case_id = transitions.escalate(
            conn, alert_id, actor.user_id, title=title, severity=severity
        )
    except transitions.StaleState:
        raise _conflict(conn, alert_id, kind="already_in_case") from None

    head_count = conn.execute(
        "SELECT count(*) FROM case_alerts WHERE case_id = %s", (case_id,)
    ).fetchone()[0]
    truncated = conn.execute(
        "SELECT EXISTS (SELECT 1 FROM audit_events WHERE event_type = 'case.truncated' "
        "AND subject_id = %s)",
        (case_id,),
    ).fetchone()[0]
    return {
        "alert_id": alert_id,
        "case_id": case_id,
        "status": "escalated_tier2",
        "head_count": head_count,
        "truncated": truncated,
    }


def reopen(conn: psycopg.Connection, alert_id: str, actor: Actor, *, reason: str) -> dict:
    """A17 — `auto_closed` only. `transitions.reopen`'s own `ValueError` (empty
    `reason`) propagates untouched."""
    try:
        transitions.reopen(conn, alert_id, actor.user_id, reason=reason)
    except transitions.StaleState:
        raise _conflict(conn, alert_id, kind="not_reopenable") from None
    return {"alert_id": alert_id, "status": "queued_tier1"}
