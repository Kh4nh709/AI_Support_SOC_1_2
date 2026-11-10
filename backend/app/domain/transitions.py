"""The single _apply() that changes alert/case status and writes its audit event atomically.

The only module that writes `alerts.status` / `cases.status` (G2). Nine public
functions, each one business event: `open_alert`, `start_enrichment`,
`finish_enrichment`, `acknowledge`, `decide`, `escalate`, `reopen`,
`conclude_case` and, since DEC-212, `archive_before`. Every guard lives in an `UPDATE ... WHERE status = ANY(from)`
(never a prior bare `SELECT`, so two concurrent callers cannot both pass a
guard read from a stale row) and every write is followed by its audit event in
the same transaction — the caller owns `BEGIN`/`COMMIT` (P2-T10, P4). The only
error surface is `StaleState` (409: wrong guard, row already elsewhere, or a
concurrent writer won the race) and `IllegalTransition` (500: the requested
edge does not exist). Every timestamp is the database's `now()`, written
inside the statement — never Python's clock (§9 "Time").

`_apply()` covers the four single-row alerts transitions whose guard is a
plain `status = ANY(from)` plus, for `acknowledge`, one extra column check
(A4, A5/A6, A7, A17). `open_alert` (A1-A3) is an INSERT, not an UPDATE, so its
guard is "no row with this id yet" — a `UniqueViolation` on the primary key is
the wrong-guard case, converted to `StaleState`. `decide` (A8-A10), `escalate`
(A11-A12) and `conclude_case` (A13-A16) each combine an optimistic-lock read
or a multi-statement fan-out with a rowcount check that does not reduce to a
single `_apply()` call without making that helper as large as the sum of
their direct SQL — they write the same guard-in-WHERE / audit-in-transaction
shape by hand instead.
"""

from __future__ import annotations

import dataclasses
import uuid
from datetime import datetime
from typing import Literal

import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb

from app.audit.events import write_event
from app.domain.alert import Alert, AlertContext
from app.infra import config
from app.infra.jobs import enqueue


class StaleState(Exception):
    """The row is in another status than the guard expects, does not exist,
    or was just claimed by a concurrent writer. Maps to HTTP 409 (P4)."""


class IllegalTransition(Exception):
    """The requested (from, to) pair is not one of the 18 edges. Maps to HTTP 500 (P4)."""


@dataclasses.dataclass(frozen=True)
class AutocloseMatch:
    """The autoclose_rules row that matched, carried into `open_alert(kind="auto_closed")`.

    Defined here, not in `ingest/`, so `ingest/autoclose.py` (P2-T09) can import
    it from `domain` without `domain` importing `ingest` (G1).
    """

    rule_id: str
    name: str
    reason: str


@dataclasses.dataclass(frozen=True)
class Edge:
    """One row of the module-level edge table `_apply()` looks up."""

    id: str
    from_states: tuple[str, ...]
    to_state: str
    event_type: str
    actor_role: Literal["system", "analyst"]


_EDGE_A4 = Edge("A4", ("received",), "enriching", "alert.enrich_started", "system")
_EDGE_A5_A6 = Edge("A5/A6", ("enriching",), "queued_tier1", "alert.enriched", "system")
_EDGE_A7 = Edge("A7", ("queued_tier1",), "tier1_active", "alert.acknowledged", "analyst")
_EDGE_A17 = Edge("A17", ("auto_closed",), "queued_tier1", "alert.reopened", "analyst")

# B3 mapping (kien-truc §B3): a case conclusion closes every head with this alerts.status.
_CONCLUSION_TO_ALERT_STATUS: dict[str, str] = {
    "concluded_fp": "closed_fp",
    "concluded_policy_violation": "closed_benign",
    "confirmed_incident": "closed_confirmed",
}


def _apply(
    conn: psycopg.Connection,
    edge: Edge,
    alert_id: str,
    *,
    extra_set: str = "",
    extra_params: tuple = (),
    extra_guard: str = "",
    payload: dict | None = None,
    actor_id: str | None = None,
) -> None:
    """`UPDATE alerts ... WHERE alert_id = %s AND status = ANY(from) <extra_guard>`,
    then `write_event` in the same transaction. `rowcount == 0` → `StaleState`,
    with one follow-up `SELECT status` so the message says which (does not
    exist, or exists in a different status)."""
    row = conn.execute(
        f"UPDATE alerts SET status = %s{extra_set} "
        f"WHERE alert_id = %s AND status = ANY(%s){extra_guard} "
        "RETURNING status",
        (edge.to_state, *extra_params, alert_id, list(edge.from_states)),
    ).fetchone()
    if row is None:
        current = conn.execute(
            "SELECT status FROM alerts WHERE alert_id = %s", (alert_id,)
        ).fetchone()
        if current is None:
            raise StaleState(f"{edge.id}: alert_id={alert_id!r} does not exist")
        raise StaleState(
            f"{edge.id}: alert_id={alert_id!r} is in status {current[0]!r}, "
            f"expected one of {edge.from_states}"
        )
    write_event(
        conn, edge.event_type, alert_id, edge.actor_role, actor_id=actor_id, payload=payload
    )


_COMMON_ALERT_COLUMNS = (
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
    "source",
    "suggestion_visible",
)


def _common_alert_values(alert: Alert, *, source: str, suggestion_visible: bool) -> tuple:
    return (
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
        source,
        suggestion_visible,
    )


def _enqueue_triage(conn: psycopg.Connection, alert_id: str) -> None:
    """Queue ① for an alert that is ready for it (the two places that do: `finish_enrichment` and the
    `auto_closed` branch of `open_alert`). Today's call, exactly: `enqueue(conn, "triage", alert_id)`.

    With `RAG_ENABLED` (DEC-210, spec §7.8) the learned-knowledge lookup is queued too, and ① is
    delayed by `RAG_TRIAGE_DELAY_S` seconds of the database's clock so the lookup has had time to
    land. ① never waits for it: at its time it reads whatever lookup exists and carries on without
    one. Both jobs are written in the caller's transaction. `domain` imports no `rag`, so the
    subject is spelled here as `rag.subject.Subject("alert", alert_id).key` spells it (a test pins
    the two to each other)."""
    cfg = config.load()
    if not cfg.RAG_ENABLED:
        enqueue(conn, "triage", alert_id)
        return
    enqueue(conn, "rag_lookup", f"alert:{alert_id}")
    enqueue(
        conn,
        "triage",
        alert_id,
        scheduled_at=sql.SQL("now() + {} * interval '1 second'").format(
            sql.Literal(cfg.RAG_TRIAGE_DELAY_S)
        ),
    )


def open_alert(
    conn: psycopg.Connection,
    alert: Alert,
    *,
    kind: Literal["received", "duplicate", "auto_closed"],
    source: str,
    suggestion_visible: bool,
    duplicate_of: str | None = None,
    rule: AutocloseMatch | None = None,
    context: AlertContext | None = None,
    risk_score: int | None = None,
    risk_components: dict | None = None,
) -> str:
    """A1/A2/A3 — the INSERT. `context`/`risk_score`/`risk_components` are used
    only for `kind="auto_closed"` (M1: an auto-closed alert keeps the internal
    context and risk score the pipeline computed before deciding); for
    `kind="received"` they are ignored, context arrives later with
    `finish_enrichment`. The guard is "no row with this `alert_id` yet" — a
    primary-key collision is the wrong-guard case, `StaleState`, not a bare
    `IntegrityError`.
    """
    if kind == "duplicate" and not duplicate_of:
        raise ValueError("duplicate_of: required when kind='duplicate'")
    if kind == "auto_closed" and rule is None:
        raise ValueError("rule: required when kind='auto_closed'")

    # Each tail item is (column, expr, value): expr is "%s" (value is bound) or a
    # literal SQL fragment such as "now()" (value is ignored). Building columns,
    # placeholders and values from the same list of triples — rather than three
    # hand-counted parallel sequences — is what keeps them from drifting apart.
    if kind == "duplicate":
        tail = [
            ("status", "%s", "duplicate"),
            ("duplicate_of", "%s", duplicate_of),
            ("closed_at", "now()", None),
            ("sealed_at", "now()", None),
        ]
    elif kind == "auto_closed":
        assert rule is not None  # narrowed above
        asset_context = identity_context = ioc_context = lookup_status_json = None
        if context is not None:
            asset_context = Jsonb(
                {
                    "present": context.asset_present,
                    "criticality": context.asset_criticality,
                    "owner": context.asset_owner,
                    "role": context.asset_role,
                }
            )
            identity_context = Jsonb({"privileged": context.identity_privileged})
            ioc_context = Jsonb({"reputation": context.ioc_reputation})
            lookup_status_json = Jsonb(dict(context.lookup_status))
        tail = [
            ("status", "%s", "auto_closed"),
            ("close_reason", "%s", rule.reason),
            ("closed_at", "now()", None),
            ("autoclose_rule_id", "%s", rule.rule_id),
            ("asset_context", "%s", asset_context),
            ("identity_context", "%s", identity_context),
            ("ioc_context", "%s", ioc_context),
            ("lookup_status", "%s", lookup_status_json),
            ("risk_score", "%s", risk_score),
            (
                "risk_score_components",
                "%s",
                Jsonb(risk_components) if risk_components is not None else None,
            ),
        ]
    else:  # received — status/closed_at/duplicate_of/sealed_at all take their column DEFAULT
        tail = []

    columns = list(_COMMON_ALERT_COLUMNS) + [c for c, _, _ in tail]
    values = list(_common_alert_values(alert, source=source, suggestion_visible=suggestion_visible))
    values += [v for _, expr, v in tail if expr == "%s"]
    placeholders = [*(["%s"] * len(_COMMON_ALERT_COLUMNS)), *(expr for _, expr, _ in tail)]
    query = f"INSERT INTO alerts ({', '.join(columns)}) VALUES ({', '.join(placeholders)})"

    try:
        conn.execute(query, values)
    except psycopg.errors.UniqueViolation as exc:
        raise StaleState(f"A1/A2/A3: alert_id={alert.alert_id!r} already exists") from exc

    if kind == "received":
        write_event(conn, "alert.received", alert.alert_id, "system")
    elif kind == "duplicate":
        occurrence = conn.execute(
            "SELECT occurrence_count FROM alerts WHERE alert_id = %s", (duplicate_of,)
        ).fetchone()[0]
        write_event(
            conn,
            "alert.duplicate_merged",
            alert.alert_id,
            "system",
            payload={"parent": duplicate_of, "occurrence": occurrence},
        )
    else:  # auto_closed
        assert rule is not None
        _enqueue_triage(conn, alert.alert_id)  # D8: ① runs on 100% of auto-closed alerts
        write_event(
            conn,
            "alert.auto_closed",
            alert.alert_id,
            "system",
            payload={"rule_id": rule.rule_id, "rule_name": rule.name, "reason": rule.reason},
        )
    return alert.alert_id


def start_enrichment(conn: psycopg.Connection, alert_id: str) -> None:
    """A4 — received -> enriching."""
    _apply(conn, _EDGE_A4, alert_id)


def finish_enrichment(
    conn: psycopg.Connection,
    alert_id: str,
    *,
    context: AlertContext,
    risk_score: int,
    risk_components: dict,
    exhausted: bool = False,
) -> None:
    """A5 (and A6 when `exhausted`, with an empty `context`) — enriching -> queued_tier1.
    The `triage` job (`_enqueue_triage`; with `RAG_ENABLED`, a `rag_lookup` job before it and a
    delayed `triage`) sits in the same transaction as the status write: that pairing is E6
    (phase-4), and it is what a worker-killed-mid-job test relies on (P2-T10)."""
    asset_context = {
        "present": context.asset_present,
        "criticality": context.asset_criticality,
        "owner": context.asset_owner,
        "role": context.asset_role,
    }
    identity_context = {"privileged": context.identity_privileged}
    ioc_context = {"reputation": context.ioc_reputation}
    _apply(
        conn,
        _EDGE_A5_A6,
        alert_id,
        extra_set=(
            ", asset_context = %s, identity_context = %s, ioc_context = %s, "
            "lookup_status = %s, risk_score = %s, risk_score_components = %s"
        ),
        extra_params=(
            Jsonb(asset_context),
            Jsonb(identity_context),
            Jsonb(ioc_context),
            Jsonb(dict(context.lookup_status)),
            risk_score,
            Jsonb(risk_components),
        ),
        payload={"risk_score": risk_score, "exhausted": exhausted},
    )
    _enqueue_triage(conn, alert_id)


def acknowledge(conn: psycopg.Connection, alert_id: str, user_id: str) -> None:
    """A7 — queued_tier1 -> tier1_active. `acknowledged_at IS NULL` is an extra
    guard column alongside the status check (P6-2: the first person wins)."""
    _apply(
        conn,
        _EDGE_A7,
        alert_id,
        extra_set=", acknowledged_at = now(), acknowledged_by = %s",
        extra_params=(user_id,),
        extra_guard=" AND acknowledged_at IS NULL",
        actor_id=user_id,
    )


def decide(
    conn: psycopg.Connection,
    alert_id: str,
    user_id: str,
    *,
    decision: Literal["closed_fp", "closed_benign"],
    reason: str,
    seen_occurrence_count: int,
    llm_suggestion: str | None,
    llm_confidence: str | None,
    gate_forced: bool | None = None,
    suggestion_visible: bool | None = None,
    llm_run_id: str | None = None,
) -> None:
    """A8/A9 (+ A10 fan-out) — tier1_active -> closed_fp|closed_benign, applied
    to the whole cluster in one transaction. P6-1's optimistic lock: the guard
    is read with `SELECT ... FOR UPDATE`, which is safe here (unlike a bare
    guard-then-UPDATE) because the row stays locked until this transaction
    ends, so no concurrent writer can move it out from under the later
    `UPDATE`s. The three keyword-only fields default to `None` and extend the
    `tier1.decided` payload for P8's evaluation join (P4-T03); existing callers
    and `test_transitions.py` are untouched."""
    if decision not in ("closed_fp", "closed_benign"):
        raise IllegalTransition(f"A08/A09: no edge for decision={decision!r}")

    row = conn.execute(
        "SELECT occurrence_count, status FROM alerts WHERE alert_id = %s FOR UPDATE",
        (alert_id,),
    ).fetchone()
    if row is None:
        raise StaleState(f"A08/A09: alert_id={alert_id!r} does not exist")
    occurrence_count, status = row
    if status != "tier1_active":
        raise StaleState(
            f"A08/A09: alert_id={alert_id!r} is in status {status!r}, expected 'tier1_active'"
        )
    delta = occurrence_count - seen_occurrence_count
    cfg = config.load()
    tolerance = cfg.REVIEW_DELTA_TOLERANCE
    if delta > tolerance:
        raise StaleState(
            f"A08/A09: occurrence_count is now {occurrence_count} (delta {delta} exceeds "
            f"REVIEW_DELTA_TOLERANCE={tolerance})",
        )

    conn.execute(
        "UPDATE alerts SET status = %s, closed_at = now(), sealed_at = now(), "
        "close_reason = %s, triaged_count = occurrence_count WHERE alert_id = %s",
        (decision, reason, alert_id),
    )
    conn.execute(
        "UPDATE alerts SET status = %s, closed_at = now(), sealed_at = now(), close_reason = %s "
        "WHERE duplicate_of = %s",
        (decision, reason, alert_id),
    )
    write_event(
        conn,
        "tier1.decided",
        alert_id,
        "analyst",
        actor_id=user_id,
        payload={
            "decision": decision,
            "reason": reason,
            "occurrence_count": occurrence_count,
            "llm_suggestion": llm_suggestion,
            "llm_confidence": llm_confidence,
            "gate_forced": gate_forced,
            "suggestion_visible": suggestion_visible,
            "llm_run_id": llm_run_id,
        },
    )
    if cfg.KNOWLEDGE_DRAFT_ENABLED:
        # DEC-210: an analyst's conclusion is what learned knowledge is drafted from. In this
        # transaction, so the job exists exactly when the decision does; the cluster's head is the
        # subject, its duplicates are not (a decision is made once).
        enqueue(conn, "knowledge_draft", f"alert:{alert_id}")


def escalate(
    conn: psycopg.Connection,
    alert_id: str,
    user_id: str,
    *,
    title: str,
    severity: str,
) -> str:
    """A11 (trigger) / A12 (its duplicates get `case_id` only) — read design note 4 of the card
    before touching this.

    The case holds **one alert**, the trigger (T2, DEC-215: the Owner, 11/11, reversing the sweep
    of DEC-165/166). The open alerts correlated with it (same agent / source IP / user within
    ±2 h) are not looked at: they keep their status and `case_id` and stay in the Tier-1 queue,
    to be decided one by one, so concluding the case closes the trigger and its own duplicates
    and nothing else. (The sweep took 14 alerts of 13 rules into one case on the trial, 07/11, and
    `tier2.concluded` closed all 14.) `case_alerts` gets one row; the table, its unique index and
    every reader of a case's heads are unchanged, a case just has one head.

    ③ is two statements, not one `OR`ed `UPDATE`: a duplicate always has `sealed_at` set and
    `escalated_tier2` forbids it, so one `UPDATE` touching both shapes would roll every cluster
    with a duplicate back on `ck_alerts_h3_escalate_khong_seal`. ③a's rowcount must be 1 — 0
    means a concurrent escalate claimed the trigger first (N2) — and
    `ux_case_alerts_mot_alert_mot_case` (UNIQUE on `alert_id`) is the second, DB-enforced layer
    of the same rule: an alert already in a case raises `psycopg.errors.UniqueViolation` here,
    converted to `StaleState`. The trigger's status is the caller's to guard (`tier1.decide`
    takes it `FOR UPDATE`, and accepts a `tier1_active` alert someone else holds): nothing here
    asks who holds it.

    With `RAG_ENABLED` (P13-T08) the case's learned-knowledge lookup is queued last, in this same
    transaction; with the switch off nothing else is queued, as before.
    """
    cfg = config.load()
    exists = conn.execute("SELECT 1 FROM alerts WHERE alert_id = %s", (alert_id,)).fetchone()
    if exists is None:
        raise StaleState(f"A11: alert_id={alert_id!r} does not exist")

    case_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO cases (case_id, title, status, severity, created_by) "
        "VALUES (%s, %s, 'investigating', %s, %s)",
        (case_id, title, severity, user_id),
    )
    try:
        conn.execute(
            "INSERT INTO case_alerts (case_id, alert_id, added_by) VALUES (%s, %s, %s)",
            (case_id, alert_id, user_id),
        )
    except psycopg.errors.UniqueViolation as exc:
        raise StaleState(f"A11: {alert_id!r} is already in another case") from exc

    touched = conn.execute(
        "UPDATE alerts SET status = 'escalated_tier2', case_id = %s "
        "WHERE alert_id = %s AND case_id IS NULL",
        (case_id, alert_id),
    )
    if touched.rowcount != 1:
        raise StaleState(
            f"A11: escalate rowcount mismatch ({touched.rowcount} of 1 alerts touched) — "
            "the trigger was claimed by another case after it was read"
        )

    conn.execute(
        "UPDATE alerts SET case_id = %s WHERE duplicate_of = %s",
        (case_id, alert_id),
    )

    write_event(
        conn,
        "tier1.escalated",
        alert_id,
        "analyst",
        actor_id=user_id,
        payload={"case_id": case_id, "alert_ids": [alert_id], "llm_suggestion": None},
    )
    write_event(
        conn,
        "case.opened",
        case_id,
        "analyst",
        actor_id=user_id,
        payload={
            "trigger_alert_id": alert_id,
            # The keys stay, as they were written before T2, so an old `case.opened` and a new one
            # read alike: a case is one alert now, and none was taken along.
            "alert_count": 1,
            "correlated_count": 0,
        },
    )
    if cfg.RAG_ENABLED:
        # DEC-210, spec §7.6: the learned-knowledge lookup of the new case, in the case's own
        # transaction (it lives and dies with the case). ② never waits for it - the investigation
        # reads whatever `latest_lookup` holds when it runs - and `escalate` delays nothing.
        # `domain` imports no `rag`, so the subject is spelled as `rag.subject.Subject("case", id).key`
        # spells it (`parse_subject` reads a case id in lower case; `uuid4()` writes one) - a test
        # pins the two to each other.
        enqueue(conn, "rag_lookup", f"case:{case_id}")
    return case_id


def reopen(conn: psycopg.Connection, alert_id: str, user_id: str, *, reason: str) -> None:
    """A17 — auto_closed -> queued_tier1 only. No new `triage` job: ① already
    ran on this alert under D8. Empty `reason` is a `ValueError` before any SQL."""
    if not reason:
        raise ValueError("reason: is mandatory for reopen")
    _apply(
        conn,
        _EDGE_A17,
        alert_id,
        extra_set=", closed_at = NULL, close_reason = %s",
        extra_params=(reason,),
        payload={"reason": reason},
        actor_id=user_id,
    )


def conclude_case(
    conn: psycopg.Connection,
    case_id: str,
    user_id: str,
    *,
    conclusion: Literal["concluded_fp", "concluded_policy_violation", "confirmed_incident"],
    reason: str,
) -> None:
    """A13-A15 (cases.status) + A16 fan-out (every duplicate of every head)."""
    if conclusion not in _CONCLUSION_TO_ALERT_STATUS:
        raise IllegalTransition(f"A13/A14/A15: no edge for conclusion={conclusion!r}")
    alert_status = _CONCLUSION_TO_ALERT_STATUS[conclusion]

    updated = conn.execute(
        "UPDATE cases SET status = %s, concluded_at = now(), concluded_by = %s, "
        "conclusion_reason = %s WHERE case_id = %s AND status = 'investigating' "
        "RETURNING case_id",
        (conclusion, user_id, reason, case_id),
    ).fetchone()
    if updated is None:
        current = conn.execute("SELECT status FROM cases WHERE case_id = %s", (case_id,)).fetchone()
        if current is None:
            raise StaleState(f"A13/A14/A15: case_id={case_id!r} does not exist")
        raise StaleState(
            f"A13/A14/A15: case_id={case_id!r} is in status {current[0]!r}, "
            "expected 'investigating'"
        )

    conn.execute(
        "UPDATE alerts SET status = %s, closed_at = now(), sealed_at = now() "
        "WHERE case_id = %s AND status = 'escalated_tier2'",
        (alert_status, case_id),
    )
    conn.execute(
        "UPDATE alerts SET status = %s, closed_at = now(), sealed_at = now() "
        "WHERE duplicate_of IN (SELECT alert_id FROM alerts WHERE case_id = %s "
        "AND duplicate_of IS NULL)",
        (alert_status, case_id),
    )
    write_event(
        conn,
        "tier2.concluded",
        case_id,
        "analyst",
        actor_id=user_id,
        payload={"conclusion": conclusion, "reason": reason},
    )
    if config.load().KNOWLEDGE_DRAFT_ENABLED:
        # DEC-210: one draft per concluded case, not one per alert; the same transaction as the
        # conclusion. `domain` may not import `rag`, so the subject is spelled as
        # `rag.subject.Subject("case", id).key` spells it (`parse_subject` reads a case id in lower
        # case).
        enqueue(conn, "knowledge_draft", f"case:{str(case_id).lower()}")


# ─────────────────────────────────────────────────────────────────────────────
# DEC-212 · archive the old queue
# ─────────────────────────────────────────────────────────────────────────────

#: The queue heads `archive_before` sets aside: the statuses an alert has before anyone has decided it.
_ARCHIVE_HEAD_STATUSES: tuple[str, ...] = ("received", "enriching", "queued_tier1", "tier1_active")
#: The audit payload's `decision`: the Owner ruling this transition carries out.
ARCHIVE_DECISION = "DEC-212"
_ARCHIVE_REASON_MAX = 500


@dataclasses.dataclass(frozen=True)
class ArchiveCounts:
    """What one `archive_before` run archived: the alerts per status they had before (`received`,
    `enriching`, `queued_tier1`, `tier1_active`, and `escalated_tier2` for the alerts of an archived case;
    all five keys are always there, 0 where nothing was archived), the cases, and the oldest and newest
    `received_at` among the archived alerts (None when there were none)."""

    by_status: dict[str, int]
    cases: int
    oldest_received_at: datetime | None
    newest_received_at: datetime | None

    @property
    def alerts(self) -> int:
        return sum(self.by_status.values())


def _archive_payload(before: datetime, reason: str, from_status: str, **extra: str) -> dict:
    return {
        "reason": reason,
        "before": before.isoformat(),
        "from_status": from_status,
        "decision": ARCHIVE_DECISION,
        **extra,
    }


def archive_before(conn: psycopg.Connection, *, before: datetime, reason: str) -> ArchiveCounts:
    """DEC-212 - close out, without review, everything that arrived before `before`: the Owner's fresh
    start. In the caller's transaction (it owns `BEGIN`/`COMMIT`, and a dry run is a rollback).

    Three steps, in this order:

    1. **Cases.** `investigating` and `created_at < before` become `archived` (`concluded_at = now()`,
       `conclusion_reason = reason`, `concluded_by` NULL: nobody concluded them).
    2. **Their alerts.** The `escalated_tier2` alerts of those cases become `archived`.
    3. **The queue heads.** `duplicate_of IS NULL`, status `received`, `enriching`, `queued_tier1` or
       `tier1_active`, and `received_at < before`, become `archived`.

    An archived alert has `closed_at = now()`, `sealed_at = now()` and `close_reason = reason`; every other
    column (`case_id`, `acknowledged_by`, `triage_status`, ...) stays. A `duplicate` row is already sealed
    and is not touched; neither is anything closed by a person or a rule (`closed_*`, `auto_closed`), a
    concluded case, or anything at or after `before`.

    Not a decision. The status is `archived`, never `closed_benign`: `rag/history.py`, the blind arm's
    reveal and the evaluation and agreement views read `closed_*` as an analyst's decision, and this is
    not one. Hence no `tier1.decided`, no `tier2.concluded`, no `label.created`, and no job of any kind
    (no `knowledge_draft`, no `rag_lookup`, no `triage`): one `alert.archived` per alert and one
    `case.archived` per case, `actor_role='system'`, no actor.

    Concurrency. Each step takes the rows `FOR UPDATE` and its `UPDATE` repeats the status condition. A
    row an analyst changed meanwhile (the SELECT waits for the analyst's commit and then re-reads the
    row) no longer matches and is skipped, never forced. Idempotent: a second run archives 0.

    `before` must carry a UTC offset (a naive one would be read in the session's time zone), and `reason`
    is 1-500 characters once stripped."""
    if before.tzinfo is None or before.utcoffset() is None:
        raise ValueError("before: needs a UTC offset (e.g. 2026-10-30T20:15:00+07:00)")
    reason = reason.strip()
    if not 1 <= len(reason) <= _ARCHIVE_REASON_MAX:
        raise ValueError(f"reason: must be 1-{_ARCHIVE_REASON_MAX} characters")

    # 1 · cases first. `FOR UPDATE` waits for a concurrent conclude and then re-checks the WHERE.
    locked_cases = [
        row[0]
        for row in conn.execute(
            "SELECT case_id FROM cases WHERE status = 'investigating' AND created_at < %s "
            "ORDER BY case_id FOR UPDATE",
            (before,),
        ).fetchall()
    ]
    archived_cases: list[uuid.UUID] = []
    if locked_cases:
        archived_cases = [
            row[0]
            for row in conn.execute(
                "UPDATE cases SET status = 'archived', concluded_at = now(), "
                "conclusion_reason = %s, concluded_by = NULL "
                "WHERE case_id = ANY(%s) AND status = 'investigating' RETURNING case_id",
                (reason, locked_cases),
            ).fetchall()
        ]
    for case_id in sorted(archived_cases, key=str):
        write_event(
            conn,
            "case.archived",
            str(case_id),
            "system",
            payload=_archive_payload(before, reason, "investigating"),
        )

    # 2 + 3 · the alerts: the archived cases' escalated alerts, then the queue heads.
    by_status = dict.fromkeys((*_ARCHIVE_HEAD_STATUSES, "escalated_tier2"), 0)
    received: list[datetime] = []

    def archive_alerts(select_sql: str, params: tuple, statuses: tuple[str, ...]) -> None:
        locked = conn.execute(select_sql, params).fetchall()
        if not locked:
            return
        moved = {
            row[0]
            for row in conn.execute(
                "UPDATE alerts SET status = 'archived', closed_at = now(), sealed_at = now(), "
                "close_reason = %s WHERE alert_id = ANY(%s) AND status = ANY(%s) "
                "AND duplicate_of IS NULL RETURNING alert_id",
                (reason, [row[0] for row in locked], list(statuses)),
            ).fetchall()
        }
        for alert_id, from_status, case_id, received_at in locked:
            if alert_id not in moved:
                continue
            extra = {"case_id": str(case_id)} if case_id is not None else {}
            write_event(
                conn,
                "alert.archived",
                alert_id,
                "system",
                payload=_archive_payload(before, reason, from_status, **extra),
            )
            by_status[from_status] += 1
            received.append(received_at)

    if archived_cases:
        archive_alerts(
            "SELECT alert_id, status, case_id, received_at FROM alerts "
            "WHERE case_id = ANY(%s) AND status = 'escalated_tier2' "
            "ORDER BY alert_id FOR UPDATE",
            (archived_cases,),
            ("escalated_tier2",),
        )
    archive_alerts(
        "SELECT alert_id, status, case_id, received_at FROM alerts "
        "WHERE duplicate_of IS NULL AND status = ANY(%s) AND received_at < %s "
        "ORDER BY alert_id FOR UPDATE",
        (list(_ARCHIVE_HEAD_STATUSES), before),
        _ARCHIVE_HEAD_STATUSES,
    )

    return ArchiveCounts(
        by_status=by_status,
        cases=len(archived_cases),
        oldest_received_at=min(received) if received else None,
        newest_received_at=max(received) if received else None,
    )
