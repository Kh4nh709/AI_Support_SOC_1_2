"""The single _apply() that changes alert/case status and writes its audit event atomically.

The only module that writes `alerts.status` / `cases.status` (G2). Eight public
functions, each one business event: `open_alert`, `start_enrichment`,
`finish_enrichment`, `acknowledge`, `decide`, `escalate`, `reopen`,
`conclude_case`. Every guard lives in an `UPDATE ... WHERE status = ANY(from)`
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
from typing import Literal

import psycopg
from psycopg.types.json import Jsonb

from app.audit.events import write_event
from app.domain import correlation
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
        enqueue(conn, "triage", alert.alert_id)  # D8: ① runs on 100% of auto-closed alerts
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
    `enqueue(conn, "triage", alert_id)` sits in the same transaction as the
    status write: that pairing is E6 (phase-4), and it is what a worker-killed-
    mid-job test relies on (P2-T10)."""
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
    enqueue(conn, "triage", alert_id)


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
) -> None:
    """A8/A9 (+ A10 fan-out) — tier1_active -> closed_fp|closed_benign, applied
    to the whole cluster in one transaction. P6-1's optimistic lock: the guard
    is read with `SELECT ... FOR UPDATE`, which is safe here (unlike a bare
    guard-then-UPDATE) because the row stays locked until this transaction
    ends, so no concurrent writer can move it out from under the later
    `UPDATE`s."""
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
    tolerance = config.load().REVIEW_DELTA_TOLERANCE
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
        },
    )


@dataclasses.dataclass(frozen=True)
class _CorrelationSubject:
    """Just enough of an alert for `correlation.correlated_cluster_ids()`'s
    predicate (agent_name/alert_user/srcip/alert_time) — `escalate` only has
    `alert_id`, not a full `Alert`."""

    alert_id: str
    agent_name: str
    alert_user: str | None
    srcip: str
    alert_time: object


def escalate(
    conn: psycopg.Connection,
    alert_id: str,
    user_id: str,
    *,
    title: str,
    severity: str,
) -> str:
    """A11 (trigger) / A11b (correlated heads) / A12 (their duplicates get
    `case_id` only) — read design note 4 of the card before touching this.

    `case_alerts` holds **heads only**: the trigger plus
    `correlated_cluster_ids(alert)` (already `duplicate_of IS NULL`), capped at
    `MAX_ALERTS_PER_CASE` with a `case.truncated` audit row when the cap cuts.
    ③ is two statements, not one `OR`ed `UPDATE`: a duplicate always has
    `sealed_at` set and `escalated_tier2` forbids it, so one `UPDATE` touching
    both shapes would roll every cluster with a duplicate back on
    `ck_alerts_h3_escalate_khong_seal`. ③a's rowcount is checked against the
    number of `case_alerts` rows just inserted — a mismatch means a
    concurrent escalate claimed a candidate first (N2) — and
    `ux_case_alerts_mot_alert_mot_case` (UNIQUE on `alert_id`) is the second,
    DB-enforced layer of the same rule: an alert already in a case raises
    `psycopg.errors.UniqueViolation` here, converted to `StaleState`.
    """
    cfg = config.load()
    trigger = conn.execute(
        "SELECT agent_name, alert_user, srcip, alert_time FROM alerts WHERE alert_id = %s",
        (alert_id,),
    ).fetchone()
    if trigger is None:
        raise StaleState(f"A11: alert_id={alert_id!r} does not exist")
    agent_name, alert_user, srcip, alert_time = trigger
    subject = _CorrelationSubject(
        alert_id=alert_id,
        agent_name=agent_name,
        alert_user=alert_user,
        srcip=srcip,
        alert_time=alert_time,
    )
    correlated_ids = [
        cid for cid in correlation.correlated_cluster_ids(conn, subject) if cid != alert_id
    ]

    head_ids = [alert_id, *correlated_ids]
    dropped = 0
    if len(head_ids) > cfg.MAX_ALERTS_PER_CASE:
        dropped = len(head_ids) - cfg.MAX_ALERTS_PER_CASE
        head_ids = head_ids[: cfg.MAX_ALERTS_PER_CASE]

    case_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO cases (case_id, title, status, severity, created_by) "
        "VALUES (%s, %s, 'investigating', %s, %s)",
        (case_id, title, severity, user_id),
    )
    try:
        for head_id in head_ids:
            conn.execute(
                "INSERT INTO case_alerts (case_id, alert_id, added_by) VALUES (%s, %s, %s)",
                (case_id, head_id, user_id),
            )
    except psycopg.errors.UniqueViolation as exc:
        raise StaleState(f"A11/A11b: {head_id!r} is already in another case") from exc

    touched = conn.execute(
        "UPDATE alerts SET status = 'escalated_tier2', case_id = %s "
        "WHERE alert_id IN (SELECT alert_id FROM case_alerts WHERE case_id = %s) "
        "AND case_id IS NULL",
        (case_id, case_id),
    )
    if touched.rowcount != len(head_ids):
        raise StaleState(
            f"A11b: escalate rowcount mismatch ({touched.rowcount} of {len(head_ids)} "
            "case_alerts rows touched) — a candidate was claimed by another case concurrently"
        )

    conn.execute(
        "UPDATE alerts SET case_id = %s "
        "WHERE duplicate_of IN (SELECT alert_id FROM case_alerts WHERE case_id = %s)",
        (case_id, case_id),
    )

    if dropped:
        write_event(
            conn,
            "case.truncated",
            case_id,
            "analyst",
            actor_id=user_id,
            payload={"dropped": dropped},
        )
    write_event(
        conn,
        "tier1.escalated",
        alert_id,
        "analyst",
        actor_id=user_id,
        payload={"case_id": case_id, "alert_ids": head_ids, "llm_suggestion": None},
    )
    write_event(
        conn,
        "case.opened",
        case_id,
        "analyst",
        actor_id=user_id,
        payload={
            "trigger_alert_id": alert_id,
            "alert_count": len(head_ids),
            "correlated_count": len(head_ids) - 1,
        },
    )
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
