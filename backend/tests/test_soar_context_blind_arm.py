"""P12-T02 — with the context read from the SOAR payload, the blind arm and the admin console still hold.

`test_soar_intake_switches.py` (P12-T01) runs the Owner's stream with a Wazuh document that carries no
`enrichment`, so every alert there has the "unknown" context. This is the same scenario with the SOAR
team's own pfSense sample: its context is the payload's (`high` asset, `clean` address, no account),
its occurrence count is unknown, and ① 's `false_positive` is flagged at gate step 4 (the count
cannot satisfy a rule; the asset is `high`; DEC-217: a warning, the verdict stays). `triage.suggested` is
written for each alert, and the scenario adds the `llm.gate_forced` row an old run left (the job stopped
writing it): the two events whose bare presence under a blind alert would tell its verdict (DEC-206, as
amended).

Two alerts, one on each arm (`pipeline._suggestion_visible` decides, from the alert id), through
`intake.receive`, `run_pipeline_job` and `run_triage_job` with the four switches off and the fake model.
The visible alert is the control of every assertion about the blind one (DEC-025): the same route, the
same kind of row, shown whole. The database is a scratch one (`tests/scratch_db.py`).

Each alert keeps the shape of the sample's own Graylog id (`gl-<ULID>-<UUID>`, DEC-209): the last group of
the UUID is varied until one id of each arm is found, the rule being the pipeline's own.
"""

from __future__ import annotations

import copy
import dataclasses
import json
from types import SimpleNamespace

import psycopg
import pytest
from app.audit.events import write_event
from app.infra.auth import Claims
from app.infra.jobs import Job
from app.soar.pipeline import _suggestion_visible
from app.tier1 import queue, visibility
from app.tier1.triage import run_triage_job
from app.web import deps, main
from fastapi.testclient import TestClient

from tests.fakes.llm import TRIAGE_V4_FALSE_POSITIVE, FakeLLM
from tests.scratch_db import insert_user, scratch_database
from tests.soar_payloads import edit, receive_and_run, sc03, stream_config

HIDDEN_KEYS = {"triage.suggested", "llm.gate_forced"}
SC03_ID = sc03()["id"]


def _arm_ids() -> tuple[str, str]:
    """`(a blind alert id, a visible alert id)`, of the SOAR shape, found by the pipeline's own rule so the
    test never assumes which arm an id falls on. Called from the fixture, not at import: the rule
    reads the configuration, and a module-level call would read it before the autouse fixture that
    keeps a test off the real `.env` (DEC-047)."""
    blind = visible = None
    for n in range(400):
        alert_id = f"{SC03_ID[:-12]}{n:012x}"
        if _suggestion_visible(alert_id):
            visible = visible or alert_id
        else:
            blind = blind or alert_id
        if blind and visible:
            return blind, visible
    raise AssertionError("no id of one of the two arms in 400 tries")


@pytest.fixture(scope="module")
def scratch_dsn():
    with scratch_database("soar_context") as dsn:
        yield dsn


@pytest.fixture
def sdb(scratch_dsn):
    conn = psycopg.connect(scratch_dsn)
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


@pytest.fixture(autouse=True)
def _require_db_marker_for_scratch(request):
    uses = {"sdb", "scratch_dsn", "stream"} & set(request.fixturenames)
    if uses and request.node.get_closest_marker("db") is None:
        pytest.fail(f"{request.node.nodeid} uses {sorted(uses)} without @pytest.mark.db")


class _FakeComplete(FakeLLM):
    """`FakeLLM` plus the `model` keyword the real adapter's `complete()` takes."""

    def complete(self, *, system, user, response_format=None, timeout_s=None, model=None):
        return super().complete(
            system=system, user=user, response_format=response_format, timeout_s=timeout_s
        )


def _answers() -> list[dict]:
    """① says `false_positive`, its `structured_basis` equal to the facts the payload gave (a `high`
    asset, a `clean` address, no known account); the verifier answers `needs_review`."""
    proposal = copy.deepcopy(TRIAGE_V4_FALSE_POSITIVE)
    proposal["structured_basis"] = {
        "severity": "high",
        "ioc_reputation": "clean",
        "asset_criticality": "high",
        "identity_privileged": "unknown",
        "occurrence_count": 1,
        "playbook_rule_applied": "rec-1",
    }
    proposal["reasons"][0]["quote"] = "Port Scan: External Host Probing Many Ports (pfSense)"
    verifier = {
        "agree": True,
        "structured_only_verdict": "needs_review",
        "reason": "Structured facts alone give needs_review.",
    }
    return [proposal, verifier]


@pytest.fixture
def stream(sdb, monkeypatch):
    """The two alerts, after they have come through the whole stream with every switch off and
    the context read from the payload: `blind` and `visible` (their ids), `tc` (a `TestClient`,
    the caller an admin) and `db`."""
    blind, visible = _arm_ids()
    cfg = stream_config(monkeypatch)
    monkeypatch.setenv("LLM_MODEL_PROPOSER", "fake-deepseek")
    cfg = dataclasses.replace(cfg, LLM_MONTHLY_USD_CAP=30)
    for alert_id in (blind, visible):
        receive_and_run(sdb, cfg, edit(sc03(), "id", alert_id))
        run_triage_job(
            sdb,
            Job(job_id=-1, job_type="triage", subject_id=alert_id, attempts=1),
            adapter=_FakeComplete(responses=_answers()),
        )
        # DEC-217: the job no longer writes `llm.gate_forced` (nothing is forced). A run from before it did, and
        # its row must still stay off the page of an alert nobody has decided, so the scenario writes one, as
        # the old job did: the event whose bare presence tells the verdict.
        write_event(
            sdb,
            "llm.gate_forced",
            alert_id,
            "system",
            payload={
                "proposed": "false_positive",
                "final": "needs_review",
                "forced_by": ["step4"],
                "missing": ["asset_criticality"],
            },
        )
    admin_id = insert_user(sdb, "admin")
    claims = Claims(user_id=admin_id, username="p12t02-admin", role="admin", iat=0.0, exp=0.0)
    main.app.dependency_overrides[deps.get_conn] = lambda: sdb
    main.app.dependency_overrides[deps.get_config] = lambda: cfg
    main.app.dependency_overrides[deps.current_user] = lambda: claims
    try:
        yield SimpleNamespace(tc=TestClient(main.app), db=sdb, blind=blind, visible=visible)
    finally:
        for dep in (deps.get_conn, deps.get_config, deps.current_user):
            main.app.dependency_overrides.pop(dep, None)


@pytest.mark.db
def test_the_scenario_is_what_the_assertions_below_assume(stream) -> None:
    """The preconditions, each stated once: both alerts are undecided heads in the queue with the
    payload's context and no auto-close, one on each arm, and ① wrote both events for each."""
    db, blind, visible = stream.db, stream.blind, stream.visible
    fetched = db.execute(
        "SELECT alert_id, status, suggestion_visible, asset_context->>'criticality', "
        "ioc_context->>'reputation', lookup_status, autoclose_rule_id "
        "FROM alerts WHERE alert_id = ANY(%s)",
        ([blind, visible],),
    ).fetchall()
    rows = {record[0]: list(record[1:]) for record in fetched}
    lookups = {"asset": "found", "identity": "skipped", "ioc": "found"}
    assert rows[blind] == ["queued_tier1", False, "high", "clean", lookups, None]
    assert rows[visible] == ["queued_tier1", True, "high", "clean", lookups, None]
    for alert_id in (blind, visible):
        written = {
            event_type
            for (event_type,) in db.execute(
                "SELECT event_type FROM audit_events WHERE subject_id = %s", (alert_id,)
            ).fetchall()
        }
        assert HIDDEN_KEYS <= written, (alert_id, written)
        facts = db.execute(
            "SELECT gate_result->'facts' FROM llm_runs WHERE subject_id = %s AND role = 'proposer'",
            (alert_id,),
        ).fetchone()[0]
        assert facts["occurrence_count"] is None and facts["asset_criticality"] == "high"


@pytest.mark.db
def test_the_queue_and_the_alert_view_hide_the_suggestion_of_the_blind_alert(stream) -> None:
    db = stream.db
    by_id = {row["alert_id"]: row for row in queue.list_queue(db).rows}
    assert set(by_id) >= {stream.blind, stream.visible}
    assert visibility.ANALYST_HIDE.isdisjoint(by_id[stream.blind])  # not one suggestion key
    assert by_id[stream.visible]["suggested_action"] == "false_positive"  # the control: shown whole

    blind_view = queue.get_alert_view(db, stream.blind)
    visible_view = queue.get_alert_view(db, stream.visible)
    assert blind_view is not None and visible_view is not None
    assert visibility.ANALYST_HIDE.isdisjoint(blind_view)
    assert visible_view["suggestion"]["suggested_action"] == "false_positive"


@pytest.mark.db
def test_the_audit_list_leaves_out_the_blind_alerts_suggestion_events(stream) -> None:
    tc = stream.tc

    def listed(subject: str) -> set[str]:
        response = tc.get("/api/admin/audit", params={"subject": subject})
        assert response.status_code == 200, response.text
        return {event["event_type"] for event in response.json()["events"]}

    assert HIDDEN_KEYS.isdisjoint(listed(stream.blind))
    assert HIDDEN_KEYS <= listed(stream.visible)  # the control: the same events, shown
    assert listed(stream.blind) | listed(stream.visible)  # and the page itself renders


@pytest.mark.db
def test_the_usage_list_hides_the_outcome_and_subject_of_a_run_on_the_blind_alert(stream) -> None:
    tc, db, blind, visible = stream.tc, stream.db, stream.blind, stream.visible
    run_ids = {
        alert_id: [
            str(run_id)
            for (run_id,) in db.execute(
                "SELECT run_id FROM llm_runs WHERE subject_id = %s AND role = 'proposer'",
                (alert_id,),
            ).fetchall()
        ]
        for alert_id in (blind, visible)
    }
    assert all(len(ids) == 1 for ids in run_ids.values())

    response = tc.get("/api/admin/llm/usage")
    assert response.status_code == 200, response.text
    recent = {row["run_id"]: row for row in response.json()["recent"]}

    hidden = recent[run_ids[blind][0]]  # the run stays listed...
    assert hidden["outcome"] is None and hidden["subject_id"] is None  # ...without what ① said
    shown = recent[run_ids[visible][0]]  # the control
    assert shown["outcome"] == "false_positive" and shown["subject_id"] == visible
    assert blind not in json.dumps(recent)
