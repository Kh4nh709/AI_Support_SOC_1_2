"""Tests for eval/ops_export.py — P8-T01's read-only operations export.

Every database test seeds its rows inside the `db` fixture's transaction and never commits. The
rows vanish with the fixture's rollback, including the append-only ones (`audit_events`,
`llm_runs`, `intake`), so nothing here leaves residue for another test file's exact counts. The
export runs on that same connection: `build_report(db, window)` directly, or `main()` with
`_readonly_connection` routed to it. Every seeded timestamp sits in a fixed 2011 window that no
other test writes into; the rows other test files commit carry `now()`.

Alerts are seeded through `domain.transitions.open_alert`, then placed in the window with an
`UPDATE` of `received_at` (`alerts` is not append-only). `llm_runs`, `jobs`, `intake` and
`audit_events` rows are direct `INSERT`s carrying known values and explicit timestamps.

eval/ is a composition root outside backend/ and not a package on sys.path; the module is loaded
by path, the way test_eval_report.py loads report.py. `app.*` resolves through pytest's
pythonpath.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import psycopg
import pytest
from app.domain.alert import Alert
from app.domain.transitions import AutocloseMatch, open_alert
from psycopg.types.json import Jsonb

REPO_ROOT = Path(__file__).resolve().parents[2]
EVAL_DIR = REPO_ROOT / "eval"
sys.path.insert(0, str(EVAL_DIR))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ops_export = _load("eval_ops_export", EVAL_DIR / "ops_export.py")

SINCE = datetime(2011, 3, 14, tzinfo=UTC)
UNTIL = datetime(2011, 3, 15, tzinfo=UTC)
TICK = timedelta(microseconds=1)
#: Seeded into every free-text column; it must never reach the output (card design note 4).
MARKER = "ZQXMARK-9f41c2"
#: Never connected to: every test that calls main() routes or refuses the connection first.
UNUSED_DSN = "postgresql:///ops_export_never_connected_test"

HUMAN_ROWS = (
    "Decisions by branch (blind / visible) and by person",
    "Median acknowledge → decide, by branch",
    "① agreement with human decisions, blind branch only",
    "Auto-close wrong-close rate from the digest, with its Wilson CI",
    "② usefulness, 1–5",
)
GATE_ROW = "Gate-forced `needs_review` rate"


def at(minutes: float) -> datetime:
    return SINCE + timedelta(minutes=minutes)


def _window():
    return ops_export.Window(SINCE, UNTIL)


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


# --- seeding helpers (all inside the caller's open transaction) ------------------------------


def _alert(alert_id: str, agent_name: str) -> Alert:
    return Alert(
        alert_id=alert_id,
        manager_id="IA1803",
        rule_id="5710",
        description=f"sshd attempt {MARKER}",
        agent_name=agent_name,
        agent_id="004",
        agent_ip="10.0.0.4",
        origin_host=f"origin-{MARKER}",
        alert_time=SINCE,
        event_time=None,
        srcip="203.0.113.7",
        dstip="10.0.0.4",
        src_port=0,
        dst_port=22,
        alert_user=f"user-{MARKER}",
        decoder="sshd",
        mitre_ids=("T1110",),
        rule_groups=("sshd",),
        rule_level=5,
        severity="medium",
        category="ssh_brute_force",
        categories=("ssh_brute_force",),
        resolved_by="rule_groups",
        mapping_version="v1",
        srcip_is_private=False,
        dstip_is_private=True,
        raw_log=f"Failed password {MARKER}",
        raw_log_truncated=False,
        event_bucket_hash=hashlib.sha256(alert_id.encode()).hexdigest(),
        raw_payload={"full_log": f"payload {MARKER}"},
    )


def _open(
    db,
    *,
    received_at: datetime,
    agent_name: str = "lab-host",
    source: str = "lab",
    visible: bool = True,
    kind: str = "received",
    duplicate_of: str | None = None,
    rule: AutocloseMatch | None = None,
    synthetic: bool = False,
    triage_status: str | None = None,
    occurrence_count: int | None = None,
) -> str:
    alert_id = _uid("ops")
    open_alert(
        db,
        _alert(alert_id, agent_name),
        kind=kind,
        source=source,
        suggestion_visible=visible,
        duplicate_of=duplicate_of,
        rule=rule,
    )
    db.execute(
        "UPDATE alerts SET received_at = %s, is_synthetic = %s WHERE alert_id = %s",
        (received_at, synthetic, alert_id),
    )
    if triage_status is not None:
        db.execute(
            "UPDATE alerts SET triage_status = %s WHERE alert_id = %s", (triage_status, alert_id)
        )
    if occurrence_count is not None:
        db.execute(
            "UPDATE alerts SET occurrence_count = %s WHERE alert_id = %s",
            (occurrence_count, alert_id),
        )
    return alert_id


def _user(db) -> str:
    user_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash) "
        "VALUES (%s, %s, %s, 'admin', %s)",
        (user_id, _uid("ops-user"), f"Name {MARKER}", f"$argon2id$v=19$x${MARKER}"),
    )
    return user_id


def _rule(db, user_id: str) -> AutocloseMatch:
    rule_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO autoclose_rules (autoclose_rule_id, name, enabled, match, reason, created_by) "
        "VALUES (%s, %s, true, %s, %s, %s)",
        (
            rule_id,
            f"rule {MARKER}",
            Jsonb([{"field": "rule_id", "op": "eq", "value": MARKER}]),
            f"reason {MARKER}",
            user_id,
        ),
    )
    return AutocloseMatch(rule_id=rule_id, name=f"rule {MARKER}", reason=f"close {MARKER}")


def _intake(
    db,
    received_at: datetime,
    *,
    latency_ms: int | None = None,
    outcome: str | None = None,
    via: str = "pull",
) -> None:
    processed_at = None if latency_ms is None else received_at + timedelta(milliseconds=latency_ms)
    db.execute(
        "INSERT INTO intake (manager_id, source_alert_id, raw_text, via, received_at, "
        "processed_at, outcome, error) VALUES ('IA1803', %s, %s, %s, %s, %s, %s, %s)",
        (
            _uid("src"),
            json.dumps({"full_log": f"raw {MARKER}"}),
            via,
            received_at,
            processed_at,
            outcome,
            f"error {MARKER}" if outcome == "rejected" else None,
        ),
    )


def _rejected(db, received_at: datetime) -> None:
    db.execute(
        "INSERT INTO rejected_alerts (raw_payload, reason, source_ip, received_at) "
        "VALUES (%s, %s, %s, %s)",
        (Jsonb({"raw": MARKER}), f"missing field {MARKER}", "198.51.100.9", received_at),
    )


def _job(db, scheduled_at: datetime, status: str, *, job_type="pull", subject="indexer") -> None:
    db.execute(
        "INSERT INTO jobs (job_type, subject_id, status, scheduled_at, created_at, last_error) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (
            job_type,
            subject,
            status,
            scheduled_at,
            scheduled_at,
            f"error {MARKER}" if status == "failed" else None,
        ),
    )


def _event(
    db,
    event_type: str,
    subject: str,
    created_at: datetime,
    *,
    actor_role: str = "system",
    actor_id: str | None = None,
    payload: dict | None = None,
) -> None:
    db.execute(
        "INSERT INTO audit_events (event_type, subject_id, actor_role, actor_id, payload, "
        "created_at) VALUES (%s, %s, %s, %s, %s, %s)",
        (
            event_type,
            subject,
            actor_role,
            actor_id,
            Jsonb(payload if payload is not None else {"note": MARKER}),
            created_at,
        ),
    )


def _gate(
    final: str,
    *,
    forced: bool,
    forced_by: tuple[str, ...] = (),
    hallucination: bool = False,
    step6: str = "agree",
    dropped: int = 0,
) -> dict:
    """A `gate.gate_result()`-shaped document; every free-text field carries the marker."""
    return {
        "version": 1,
        "proposed_verdict": "false_positive" if forced else final,
        "final_verdict": final,
        "forced": forced,
        "forced_by": list(forced_by),
        "steps": {"1": "ok", "2": "ok", "3": f"dropped:{dropped}", "6": step6, "7": "ok"},
        "hallucination_flag": hallucination,
        "mismatched_fields": [],
        "dropped_reasons": [{"index": i, "why": "not_substring"} for i in range(dropped)],
        "missing": [],
        "facts": {"note": MARKER},
        "warnings": [f"warning {MARKER}"],
        "verifier_verdict": final,
        "playbook_used_effective": None,
        "prompt_version": "pv-proposer",
        "proposer_raw": {"rationale": f"rationale {MARKER}"},
    }


def _result(final: str, reasons: int) -> dict:
    return {
        "suggested_action": final,
        "confidence": "medium",
        "rationale": f"why {MARKER}",
        "reasons": [
            {"source": "raw_log", "quote": f"quote {MARKER}", "claim": f"claim {MARKER}"}
            for _ in range(reasons)
        ],
    }


def _run(
    db,
    subject: str,
    created_at: datetime,
    *,
    role: str = "proposer",
    stopped_by: str | None = None,
    gate: dict | None = None,
    result: dict | None = None,
    latency_ms: int | None = None,
    cost: str | None = None,
    model_id: str | None = None,
) -> None:
    if gate is None:
        gate = {"error": stopped_by or "verifier", "message": f"msg {MARKER}", "facts": MARKER}
    verifier_result = {"agree": True, "note": f"verifier {MARKER}"} if role == "verifier" else None
    db.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, role, system_prompt, "
        "user_message, result, gate_result, verifier_result, injection_findings, "
        "citation_warnings, latency_ms, model_id, prompt_version, cost_usd, stopped_by, "
        "created_at) VALUES (%s, 'triage', 'alert', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
        "%s, %s, %s, %s, %s)",
        (
            uuid.uuid4(),
            subject,
            role,
            f"system {MARKER}",
            f"user {MARKER}",
            Jsonb(result) if result is not None else None,
            Jsonb(gate),
            Jsonb(verifier_result) if verifier_result is not None else None,
            Jsonb([{"pattern": "role_override", "matched_text": MARKER}]),
            Jsonb([f"citation {MARKER}"]),
            latency_ms,
            model_id,
            "pv-proposer" if role == "proposer" else "pv-verifier",
            Decimal(cost) if cost is not None else None,
            stopped_by,
            created_at,
        ),
    )


def _gated(db, subject, created_at, final, *, reasons=1, latency_ms=None, cost=None, **gate):
    _run(
        db,
        subject,
        created_at,
        gate=_gate(final, **gate),
        result=_result(final, reasons),
        latency_ms=latency_ms,
        cost=cost,
        model_id="model-p",
    )


def _seed_operations(db) -> dict:
    """The fixture behind the exact-figures, synthetic, free-text, identity and appendix tests.
    Every expected number in `test_figures_match_a_seeded_fixture` is derived in its comments."""
    user = _user(db)
    rule = _rule(db, user)

    # alerts: 5 in the window (3 heads, 2 duplicates), 1 synthetic, 2 outside
    h1 = _open(
        db,
        received_at=at(10),
        visible=False,
        triage_status="ready",
        occurrence_count=3,
    )
    _open(db, received_at=at(11), visible=False, kind="duplicate", duplicate_of=h1)
    _open(db, received_at=at(12), visible=False, kind="duplicate", duplicate_of=h1)
    h2 = _open(
        db,
        received_at=at(20),
        agent_name="bg-host",
        source="wazuh",
        triage_status="unavailable",
    )
    h3 = _open(
        db,
        received_at=at(30),
        agent_name="bg-host",
        source="wazuh",
        kind="auto_closed",
        rule=rule,
    )
    s1 = _open(
        db,
        received_at=at(40),
        agent_name="synthetic-agent",
        visible=False,
        synthetic=True,
        occurrence_count=9,
    )
    _open(db, received_at=SINCE - timedelta(minutes=5), agent_name="outside-agent")
    _open(db, received_at=UNTIL, agent_name="outside-agent")

    # intake: 6 in the window, 5 processed at 1500/200/61000/2000/0 ms
    _intake(db, at(10), latency_ms=1500, outcome="alert")
    _intake(db, at(11), latency_ms=200, outcome="duplicate")
    _intake(db, at(12), latency_ms=61000, outcome="duplicate")
    _intake(db, at(30), latency_ms=2000, outcome="auto_closed", via="webhook")
    _intake(db, at(50))
    _intake(db, at(55), latency_ms=0, outcome="heartbeat")
    _intake(db, SINCE - timedelta(minutes=1), latency_ms=90000, outcome="alert")
    _intake(db, UNTIL, latency_ms=90000, outcome="rejected")

    _rejected(db, at(13))
    _rejected(db, SINCE - timedelta(minutes=2))

    # pull jobs: succeeded 01:00, 01:01, 01:05 (largest gap 01:01 -> 01:05), failed 01:03
    for minute in (60, 61, 65):
        _job(db, at(minute), "succeeded")
    _job(db, at(63), "failed")
    _job(db, at(66), "pending", subject=_uid("ops-pending"))
    _job(db, at(62), "succeeded", job_type="triage", subject=h2)
    _job(db, SINCE - timedelta(minutes=10), "succeeded")

    mgr_ok, mgr_err = _uid("ops-mgr-ok"), _uid("ops-mgr-err")
    db.execute(
        "INSERT INTO source_cursor (manager_id, last_error) VALUES (%s, NULL), (%s, %s)",
        (mgr_ok, mgr_err, f"indexer said {MARKER}"),
    )

    _event(db, "job.exhausted", "indexer", at(64))
    _event(db, "job.exhausted", s1, at(41))
    _event(db, "job.exhausted", "indexer", SINCE - timedelta(minutes=3))

    # pipeline ①: 4 proposer rows where the gate ran, 3 stopped, 4 verifier rows
    _gated(
        db,
        h1,
        at(100),
        "needs_review",
        forced=True,
        forced_by=("step2", "step6"),
        hallucination=True,
        step6="disagree",
        reasons=1,
        dropped=1,
        latency_ms=1000,
        cost="0.00100",
    )
    _gated(db, h2, at(101), "escalate", forced=False, reasons=2, latency_ms=2000, cost="0.00200")
    _gated(
        db,
        h3,
        at(102),
        "needs_review",
        forced=True,
        forced_by=("step4",),
        reasons=3,
        dropped=1,
        latency_ms=3000,
        cost="0.00300",
    )
    _gated(
        db,
        h1,
        at(103),
        "needs_review",
        forced=True,
        forced_by=("step3", "step6"),
        step6="invalid",
        reasons=0,
        dropped=2,
        latency_ms=4000,
        cost="0.00400",
    )
    _run(db, h2, at(104), stopped_by="schema", latency_ms=500, cost="0.00050", model_id="model-p")
    _run(db, h3, at(105), stopped_by="cap")
    _run(db, h1, at(106), stopped_by="linter")
    for subject, minute, latency, cost in (
        (h1, 100, 100, "0.00010"),
        (h2, 101, 200, "0.00020"),
        (h3, 102, 300, "0.00030"),
    ):
        _run(
            db,
            subject,
            at(minute),
            role="verifier",
            latency_ms=latency,
            cost=cost,
            model_id="model-v",
        )
    _run(
        db,
        h1,
        at(103),
        role="verifier",
        stopped_by="schema",
        latency_ms=400,
        cost="0.00040",
        model_id="model-v",
    )
    # excluded: a synthetic subject, the `until` instant, before `since`
    _run(
        db,
        s1,
        at(107),
        gate=_gate("needs_review", forced=True, forced_by=("step4",)),
        result=_result("needs_review", 1),
        latency_ms=9000,
        cost="0.00900",
        model_id="model-synthetic",
    )
    _run(db, h2, UNTIL, stopped_by="transient")
    _run(db, h1, SINCE - TICK, role="verifier", latency_ms=7000, model_id="model-v")

    # auto-close events
    _event(db, "alert.auto_closed", h3, at(30))
    _event(db, "alert.autoclose_blocked_critical", h2, at(20))
    _event(db, "alert.auto_closed", s1, at(40))
    _event(db, "alert.auto_closed", h3, SINCE - timedelta(minutes=4))

    # P6 labelling: one gold_offline label and its event, one undo; one label on s1 (excluded)
    db.execute(
        "INSERT INTO triage_labels (alert_id, labeler_id, source, label, confidence, note, "
        "created_at) VALUES (%s, %s, 'gold_offline', 'escalate', '2', %s, %s), "
        "(%s, %s, 'gold_offline', 'benign', '3', %s, %s)",
        (h1, user, f"note {MARKER}", at(200), s1, user, f"note {MARKER}", at(202)),
    )
    _event(db, "label.created", h1, at(200), actor_role="admin", actor_id=user)
    _event(
        db,
        "label.created",
        h1,
        at(201),
        actor_role="admin",
        actor_id=user,
        payload={"undo": True, "note": MARKER},
    )
    _event(db, "label.created", s1, at(202), actor_role="admin", actor_id=user)

    return {
        "h1": h1,
        "h2": h2,
        "h3": h3,
        "s1": s1,
        "rule_id": rule.rule_id,
        "mgr_ok": mgr_ok,
        "mgr_err": mgr_err,
        "user": user,
    }


# --- reading the output ------------------------------------------------------------------------


def _section(text: str, heading: str) -> str:
    """The body of the `## <heading>` section, up to the next `## ` heading."""
    start = text.index(f"\n## {heading}")
    end = text.find("\n## ", start + 1)
    return text[start : end if end != -1 else len(text)]


def _section6_rows(text: str) -> dict[str, tuple[str, str]]:
    """Architecture §6's metric table as {metric: (value, basis)}; the 2-column branch table and
    the header rows are skipped."""
    rows = {}
    for line in _section(text, "6 · ").splitlines():
        if not line.startswith("| ") or line.startswith("| metric |"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split(" | ")]
        if len(cells) == 3:
            rows[cells[0]] = (cells[1], cells[2])
    return rows


def _appendix_sql(text: str) -> list[str]:
    return re.findall(r"```sql\n(.*?)\n```", _section(text, "8 · "), flags=re.DOTALL)


# --- the tests ---------------------------------------------------------------------------------


@pytest.mark.db
def test_figures_match_a_seeded_fixture(db):
    ids = _seed_operations(db)
    text = ops_export.build_report(db, _window())

    # section 2 — intake and dedup
    assert (
        "| via | outcome | rows |\n|---|---|---|\n"
        "| pull | (null) | 1 |\n"
        "| pull | alert | 1 |\n"
        "| pull | duplicate | 2 |\n"
        "| pull | heartbeat | 1 |\n"
        "| webhook | auto_closed | 1 |\n"
    ) in text
    # processed latencies 0, 200, 1500, 2000, 61000 ms: p50 is the 3rd (cume 0.6), p95 the 5th
    for line in (
        "- intake rows: 6",
        "- with `processed_at`: 5",
        "- without `processed_at` at the run: 1",
        "- p50: 1500 ms",
        "- p95: 61000 ms",
        "- max: 61000 ms",
        "- over 60 s (G12's bound): 1",
        "- `rejected_alerts` rows: 1",
        "- alerts: 5",
        "- heads (`duplicate_of IS NULL`): 3",
        "- duplicates merged (`duplicate_of IS NOT NULL`): 2",
        "- alerts per head: 1.667 (5 / 3)",
        "- max `occurrence_count` over the heads, the column at the run: 3",
    ):
        assert line in text, line
    assert (
        "| source | agent_name | alerts | heads |\n|---|---|---|---|\n"
        "| lab | lab-host | 3 | 1 |\n"
        "| wazuh | bg-host | 2 | 2 |\n"
    ) in text

    # section 3 — the pull loop
    assert (
        "| status | jobs |\n|---|---|\n| failed | 1 |\n| pending | 1 |\n| succeeded | 3 |\n"
    ) in text
    assert "- succeeded pull jobs: 3" in text
    assert "- largest gap: 240000 ms, from 2011-03-14T01:01:00Z to 2011-03-14T01:05:00Z" in text
    assert f"| {ids['mgr_ok']} | true |" in text
    assert f"| {ids['mgr_err']} | false |" in text
    assert "- `job.exhausted` events: 1" in text

    # section 4 — ① online
    assert (
        "| stopped_by | rows |\n|---|---|\n"
        "| NULL (the gate ran) | 4 |\n| cap | 1 |\n| linter | 1 |\n| schema | 1 |\n"
    ) in text
    assert "- proposer rows: 7" in text
    assert "| final_verdict | rows |\n|---|---|\n| escalate | 1 |\n| needs_review | 3 |\n" in text
    for line in (
        "- rows where the gate ran: 4",
        "- `forced = true`: 3",
        "- gate-forced rate: 0.750 (3 / 4)",
        "- `hallucination_flag = true`: 0.250 (1 / 4)",
        # surviving 1 + 2 + 3 + 0 = 6, dropped 1 + 0 + 1 + 2 = 4
        "- evidence-verified rate: 0.600 (6 / 10) ✗ target ≥ 0.90",
        # per alert: h1 1000 + 4000 + 100 + 400, h2 2000 + 500 + 200, h3 3000 + 300
        "- alerts: 3 · p50: 3300 ms · p95: 5500 ms",
        # 0.001 + 0.002 + 0.003 + 0.004 + 0.0005 + 0.0001 + 0.0002 + 0.0003 + 0.0004
        "- Σ `cost_usd`: 0.01150 USD",
        "- alerts with a run: 3",
        "- per alert: 0.00383 USD",
    ):
        assert line in text, line
    assert ops_export.SQUEEZE_SENTENCE in _section(text, "4 · ")
    assert "| step | rows |\n|---|---|\n| step2 | 1 |\n| step3 | 1 |\n| step4 | 1 |\n" in text
    assert "| step6 | 2 |\n" in text
    assert (
        "| step 6 | rows |\n|---|---|\n| agree | 2 |\n| disagree | 1 |\n| invalid | 1 |\n" in text
    )
    assert (
        "| role | rows with latency | p50 | p95 |\n|---|---|---|---|\n"
        "| proposer | 5 | 2000 ms | 4000 ms |\n"
        "| verifier | 4 | 200 ms | 400 ms |\n"
    ) in text
    assert (
        "| role | model_id | rows |\n|---|---|---|\n"
        "| proposer | (null) | 2 |\n| proposer | model-p | 5 |\n| verifier | model-v | 4 |\n"
    ) in text
    assert (
        "| role | prompt_version | rows |\n|---|---|---|\n"
        "| proposer | pv-proposer | 7 |\n| verifier | pv-verifier | 4 |\n"
    ) in text
    assert (
        "| triage_status | heads |\n|---|---|\n| pending | 1 |\n| ready | 1 |\n| unavailable | 1 |\n"
    ) in text

    # section 5 — auto-close
    assert "- `alert.auto_closed` events: 1" in text
    assert "- `alert.autoclose_blocked_critical` events: 1" in text
    assert "- heads with `autoclose_rule_id IS NOT NULL`: 1" in text
    assert f"| {ids['rule_id']} | 1 |" in text


@pytest.mark.db
def test_synthetic_rows_are_excluded_and_counted_once(db):
    _seed_operations(db)
    text = ops_export.build_report(db, _window())

    assert text.count("synthetic rows in the window, excluded:") == 1
    assert "- synthetic rows in the window, excluded: 1 (Q01)" in text
    # the synthetic alert's agent and model never appear, and no count moves because of it
    assert "synthetic-agent" not in text
    assert "model-synthetic" not in text
    for line in (
        "- alerts: 5",
        "- heads (`duplicate_of IS NULL`): 3",
        "- max `occurrence_count` over the heads, the column at the run: 3",
        "- proposer rows: 7",
        "- rows where the gate ran: 4",
        "- `job.exhausted` events: 1",
        "- `alert.auto_closed` events: 1",
        "- `label.created` events: 2, of which undo records: 1",
        "| blind (`suggestion_visible = false`) | 1 |",
    ):
        assert line in text, line
    assert "| source | `triage_labels` rows |\n|---|---|\n| gold_offline | 1 |\n" in text


@pytest.mark.db
def test_window_bounds_are_half_open(db):
    inside = [SINCE, UNTIL - TICK]
    outside = [SINCE - TICK, UNTIL]
    subject = None
    for when, agent in zip(inside + outside, ("in-a", "in-b", "out-a", "out-b"), strict=True):
        alert_id = _open(db, received_at=when, agent_name=agent)
        subject = subject or alert_id
    labeler = _user(db)
    sources = ("gold_offline", "digest", "disagreement", "lab")
    for when, source in zip(inside + outside, sources, strict=True):
        _intake(db, when, latency_ms=10, outcome="alert")
        _rejected(db, when)
        _job(db, when, "succeeded")
        _event(db, "job.exhausted", "indexer", when)
        _event(db, "tier1.decided", subject, when, actor_role="analyst", actor_id=labeler)
        _run(db, subject, when, stopped_by="cap")
        db.execute(
            "INSERT INTO triage_labels (alert_id, labeler_id, source, label, created_at) "
            "VALUES (%s, %s, %s, 'benign', %s)",
            (subject, labeler, source, when),
        )

    text = ops_export.build_report(db, _window())

    assert "| lab | in-a | 1 | 1 |" in text and "| lab | in-b | 1 | 1 |" in text
    assert "out-a" not in text and "out-b" not in text
    for line in (
        "- heads (`duplicate_of IS NULL`): 2",
        "- intake rows: 2",
        "- `rejected_alerts` rows: 2",
        "- succeeded pull jobs: 2",
        "- `job.exhausted` events: 2",
        "- proposer rows: 2",
    ):
        assert line in text, line
    assert (
        "| source | `triage_labels` rows |\n|---|---|\n| digest | 1 |\n| gold_offline | 1 |\n"
        in (text)
    )
    assert "`tier1.decided` = 2" in _section(text, "6 · ")


@pytest.mark.db
def test_forced_rate_denominator_is_rows_where_the_gate_ran(db):
    alert_id = _open(db, received_at=at(1))
    _gated(db, alert_id, at(2), "needs_review", forced=True, forced_by=("step4",))
    _gated(db, alert_id, at(3), "escalate", forced=False)
    for minute, stopped_by in ((4, "schema"), (5, "cap"), (6, "transient")):
        _run(db, alert_id, at(minute), stopped_by=stopped_by)
    for minute in (2, 3):
        _run(db, alert_id, at(minute), role="verifier", latency_ms=10, model_id="model-v")

    text = ops_export.build_report(db, _window())

    assert "- proposer rows: 5" in text
    assert "- rows where the gate ran: 2" in text
    assert "- gate-forced rate: 0.500 (1 / 2)" in text
    assert _section6_rows(text)[GATE_ROW][0] == "0.500 (1 / 2)"
    assert ops_export.SQUEEZE_SENTENCE not in text


@pytest.mark.db
@pytest.mark.parametrize(
    ("forced", "gated", "rate", "squeezed"),
    [
        (2, 3, "0.667 (2 / 3)", True),
        (3, 5, "0.600 (3 / 5)", False),  # exactly 0.60 does not exceed it
        (0, 0, "n/a (0 rows)", False),
    ],
)
def test_over_sixty_percent_prints_the_architecture_sentence(db, forced, gated, rate, squeezed):
    alert_id = _open(db, received_at=at(1))
    for i in range(gated):
        is_forced = i < forced
        _gated(
            db,
            alert_id,
            at(2 + i),
            "needs_review" if is_forced else "escalate",
            forced=is_forced,
            forced_by=("step4",) if is_forced else (),
        )
    _run(db, alert_id, at(30), stopped_by="schema")

    text = ops_export.build_report(db, _window())
    section4 = _section(text, "4 · ")
    value, basis = _section6_rows(text)[GATE_ROW]

    assert f"- gate-forced rate: {rate}" in section4
    assert value == rate
    assert basis.startswith("measured")
    assert (ops_export.SQUEEZE_SENTENCE in section4) is squeezed
    assert ("R5 (architecture §9)" in section4) is squeezed
    assert (ops_export.SQUEEZE_SENTENCE in basis) is squeezed


def _assert_never_not_measured_beside_a_count(rows: dict[str, tuple[str, str]]) -> None:
    for metric in HUMAN_ROWS:
        value, basis = rows[metric]
        counts = [int(n) for n in re.findall(r"= (\d+)", basis)]
        assert counts, (metric, basis)
        assert (value == "not measured") is (not any(counts)), (metric, value, basis)
        assert not re.search(r"\d\.\d", value), (metric, value)  # never a rate


@pytest.mark.db
def test_human_metrics_not_measured_when_zero_and_counted_when_not(db):
    head = _open(db, received_at=at(1), visible=False)

    # (a) no human evidence at all: five rows "not measured", each with its DEC and its zeros
    rows = _section6_rows(ops_export.build_report(db, _window()))
    assert set(rows) == {*HUMAN_ROWS, GATE_ROW}
    for metric in HUMAN_ROWS:
        assert rows[metric][0] == "not measured", metric
    decisions = rows[HUMAN_ROWS[0]][1]
    assert decisions.startswith(
        "no human-decision pilot ran: the Tier-1 console was deprioritized (DEC-116); "
        "`tier1.decided` = 0"
    )
    assert "`alert.acknowledged` = 0" in rows[HUMAN_ROWS[1]][1]
    assert "DEC-116" in rows[HUMAN_ROWS[2]][1]
    assert "DEC-116" in rows[HUMAN_ROWS[3]][1]
    assert "`autoclose.reviewed` = 0" in rows[HUMAN_ROWS[3]][1]
    assert "`autoclose_reviews` rows = 0" in rows[HUMAN_ROWS[3]][1]
    assert "DEC-097" in rows[HUMAN_ROWS[4]][1] and "DEC-111" in rows[HUMAN_ROWS[4]][1]
    assert "`case.opened` = 0" in rows[HUMAN_ROWS[4]][1]
    assert rows[GATE_ROW] == (
        "n/a (0 rows)",
        "measured: `forced = true` over the proposer rows where the gate ran (section 4, Q13)",
    )
    _assert_never_not_measured_beside_a_count(rows)
    text = ops_export.build_report(db, _window())
    assert "0.000" not in _section(text, "6 · ")
    assert "| blind (`suggestion_visible = false`) | 1 |" in text
    assert "| visible (`suggestion_visible = true`) | 0 |" in text

    # (b) one acknowledge, no decision yet: that row turns descriptive, the others stay
    analyst = _user(db)
    _event(db, "alert.acknowledged", head, at(2), actor_role="analyst", actor_id=analyst)
    rows = _section6_rows(ops_export.build_report(db, _window()))
    assert rows[HUMAN_ROWS[1]][0] == "descriptive, n = 0"
    assert "`alert.acknowledged` = 1" in rows[HUMAN_ROWS[1]][1]
    assert rows[HUMAN_ROWS[0]][0] == "not measured"
    _assert_never_not_measured_beside_a_count(rows)

    # (c) every piece of evidence present: every human row descriptive, with its count
    for minute in (3, 4):
        _event(db, "tier1.decided", head, at(minute), actor_role="analyst", actor_id=analyst)
    _event(db, "autoclose.reviewed", head, at(5), actor_role="admin", actor_id=analyst)
    db.execute(
        "INSERT INTO autoclose_reviews (alert_id, reviewer_id, verdict, reviewed_at) "
        "VALUES (%s, %s, 'correct', %s)",
        (head, analyst, at(5)),
    )
    _event(db, "case.opened", str(uuid.uuid4()), at(6), actor_role="analyst", actor_id=analyst)
    rows = _section6_rows(ops_export.build_report(db, _window()))
    assert rows[HUMAN_ROWS[0]][0] == "descriptive, n = 2"
    assert rows[HUMAN_ROWS[1]][0] == "descriptive, n = 2"
    assert rows[HUMAN_ROWS[2]][0] == "descriptive, n = 2"
    assert rows[HUMAN_ROWS[3]][0] == "descriptive, n = 1"
    assert rows[HUMAN_ROWS[4]][0] == "descriptive, n = 1"
    assert "`tier1.decided` = 2" in rows[HUMAN_ROWS[0]][1]
    assert "`autoclose_reviews` rows = 1" in rows[HUMAN_ROWS[3]][1]
    assert "`case.opened` = 1" in rows[HUMAN_ROWS[4]][1]
    _assert_never_not_measured_beside_a_count(rows)


#: (table, expression) pairs: every free-text column the export's tables carry, as seeded.
_FREE_TEXT_COLUMNS = (
    ("alerts", "description"),
    ("alerts", "raw_log"),
    ("alerts", "raw_payload::text"),
    ("alerts", "close_reason"),
    ("alerts", "origin_host"),
    ("alerts", "alert_user"),
    ("intake", "raw_text"),
    ("intake", "raw_payload::text"),
    ("intake", "error"),
    ("rejected_alerts", "raw_payload::text"),
    ("rejected_alerts", "reason"),
    ("jobs", "last_error"),
    ("source_cursor", "last_error"),
    ("llm_runs", "system_prompt"),
    ("llm_runs", "user_message"),
    ("llm_runs", "result::text"),
    ("llm_runs", "gate_result::text"),
    ("llm_runs", "verifier_result::text"),
    ("llm_runs", "injection_findings::text"),
    ("llm_runs", "citation_warnings::text"),
    ("audit_events", "payload::text"),
    ("triage_labels", "note"),
    ("autoclose_rules", "reason"),
    ("users", "display_name"),
)


@pytest.mark.db
def test_no_free_text_reaches_the_output(db):
    ids = _seed_operations(db)
    _event(db, "tier1.decided", ids["h1"], at(300), actor_role="analyst", actor_id=ids["user"])
    for table, expression in _FREE_TEXT_COLUMNS:
        seeded = db.execute(
            f"SELECT count(*) FROM {table} WHERE strpos({expression}, %s) > 0", (MARKER,)
        ).fetchone()[0]
        assert seeded > 0, f"{table}.{expression} does not carry the marker"

    text = ops_export.build_report(db, _window())

    assert MARKER not in text
    # not vacuous: the rows carrying the marker are the ones the figures count
    assert "- heads (`duplicate_of IS NULL`): 3" in text
    assert "- proposer rows: 7" in text
    assert "- `rejected_alerts` rows: 1" in text
    assert "`tier1.decided` = 1" in text


@pytest.mark.db
def test_output_is_byte_identical_for_the_same_window(db, monkeypatch, tmp_path):
    _seed_operations(db)
    first = ops_export.build_report(db, _window())
    second = ops_export.build_report(db, _window())
    assert first == second

    @contextmanager
    def _borrow(_dsn):
        yield db

    monkeypatch.setattr(ops_export, "_readonly_connection", _borrow)
    argv = ["--since", "2011-03-14T00:00:00Z", "--until", "2011-03-15T00:00:00Z"]
    for name in ("a.md", "b.md"):
        rc = ops_export.main([*argv, "--dsn", UNUSED_DSN, "--out", str(tmp_path / name)])
        assert rc == 0
    a_bytes = (tmp_path / "a.md").read_bytes()
    assert a_bytes == (tmp_path / "b.md").read_bytes()
    assert a_bytes == first.encode("utf-8")
    assert a_bytes.endswith(b"\n") and b"\r" not in a_bytes
    # the window is the identity: no run timestamp, host or path reaches the file
    assert str(tmp_path).encode() not in a_bytes
    assert datetime.now(UTC).strftime("%Y-%m-%d").encode() not in a_bytes


@pytest.mark.db
def test_every_query_in_the_appendix_is_the_one_that_ran(db, monkeypatch):
    _seed_operations(db)
    sent: list[str] = []
    real_execute = ops_export._execute

    def recording_execute(conn, sql, params):
        sent.append(sql)
        return real_execute(conn, sql, params)

    monkeypatch.setattr(ops_export, "_execute", recording_execute)
    text = ops_export.build_report(db, _window())

    assert sent, "no query reached the database"
    assert _appendix_sql(text) == sent
    assert sent == [q.sql for q in ops_export.QUERIES]
    ids = re.findall(r"^### (Q\d\d) · ", _section(text, "8 · "), flags=re.MULTILINE)
    assert ids == [q.qid for q in ops_export.QUERIES]
    assert ids == [f"Q{i:02d}" for i in range(1, len(ids) + 1)]  # numbered in the order run
    # every query id the body cites is one the appendix holds
    body = text[: text.index("\n## 8 · ")]
    assert set(re.findall(r"\bQ\d\d\b", body)) <= set(ids)
    assert "`%(since)s`" in _section(text, "8 · ") and "`%(until)s`" in _section(text, "8 · ")


@pytest.mark.db
def test_read_only_transaction(_test_database):
    conn = ops_export._connect_readonly(_test_database)
    try:
        text = ops_export.build_report(conn, _window())  # the export itself never writes
        assert "\n## 8 · Appendix: SQL" in text
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            conn.execute("INSERT INTO source_cursor (manager_id) VALUES (%s)", (_uid("ops-probe"),))
    finally:
        conn.rollback()
        conn.close()


def _refuse_connections(monkeypatch) -> None:
    def _no(*_args, **_kwargs):
        raise AssertionError("a usage error must exit before any DSN is read or connected")

    monkeypatch.setattr(ops_export, "_resolve_dsn", _no)
    monkeypatch.setattr(ops_export, "_readonly_connection", _no)
    monkeypatch.setattr(ops_export, "_connect_readonly", _no)


@pytest.mark.parametrize(
    "argv",
    [
        [],  # --until is required
        ["--until", "not-a-date"],
        ["--since", "2026-09-26", "--until", "2026-09-27T00:00:00Z"],  # no zone
        ["--until", "2026-09-27T00:00:00"],  # naive
        ["--until", "2026-09-27T07:00:00+07:00"],  # not UTC
        ["--since", "2026-09-27T00:00:00Z", "--until", "2026-09-26T00:00:00Z"],  # inverted
        ["--since", "2026-09-26T00:00:00Z", "--until", "2026-09-26T00:00:00Z"],  # empty
        ["--until", "2026-09-27T00:00:00Z", "--no-such-flag"],
    ],
)
def test_usage_errors_exit_2(monkeypatch, tmp_path, capsys, argv):
    _refuse_connections(monkeypatch)
    out = tmp_path / "o.md"
    assert ops_export.main([*argv, "--dsn", UNUSED_DSN, "--out", str(out)]) == 2
    assert not out.exists()
    captured = capsys.readouterr()
    assert captured.err.strip()
    assert UNUSED_DSN not in captured.err + captured.out


def test_unreadable_dsn_exits_4(monkeypatch, tmp_path, capsys):
    # the environment outranks --env-file in config.load(): make sure it names no database
    monkeypatch.delenv("DATABASE_URL", raising=False)
    empty_env = tmp_path / "empty.env"
    empty_env.write_text("# no DATABASE_URL here\n", encoding="utf-8")
    out = tmp_path / "o.md"
    window = ["--until", "2026-09-27T00:00:00Z", "--out", str(out)]

    def _no(*_args, **_kwargs):
        raise AssertionError("no DSN was found, so nothing may be connected")

    with monkeypatch.context() as patched:
        patched.setattr(ops_export, "_readonly_connection", _no)
        assert ops_export.main([*window, "--env-file", str(empty_env)]) == 4
    # a DSN libpq cannot parse fails before any socket is opened
    assert ops_export.main([*window, "--dsn", "not a dsn"]) == 4
    assert not out.exists()
    assert "not a dsn" not in capsys.readouterr().err


def test_help_lists_the_exit_codes():
    epilog = ops_export.build_parser().epilog
    assert "0 written" in epilog and "2 usage" in epilog and "4 the DSN is unreadable" in epilog
    doc = ops_export.__doc__
    assert "0 written" in doc and "2 usage" in doc and "4 the DSN is unreadable" in doc
