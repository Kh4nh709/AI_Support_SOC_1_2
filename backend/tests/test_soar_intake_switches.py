"""P12-T01 / DEC-207 item 7 — with every switch off, the blind arm and the admin console still hold.

The stream the Owner will run: alerts arrive on `POST /webhook/alerts` already enriched, grouped and
closed by SOAR, so `DEDUP_ENABLED`, `PULL_ENABLED`, `AUTOCLOSE_ENABLED` and `ENRICHMENT_ENABLED` are
all `false`. DEC-101 and DEC-206 must survive that unchanged: no ① suggestion shows on a blind,
undecided alert, in the queue, on the alert page, in the audit list or in the usage list; and the
overview and the digest answer and render with no auto-closed alert and no inventory.

One scenario, built the way the stream builds it and not row by row: two alerts through
`infra.intake.receive` (the webhook's own function), `run_pipeline_job` with the four switches read
from the environment, and `run_triage_job` with the fake adapter, one alert on the blind arm and one
on the visible arm (`pipeline._suggestion_visible` decides, from the alert id). The "unknown"
context makes gate step 4 flag ① 's `false_positive` (DEC-217: a warning, the verdict stays; `test_pipeline.py`),
so `triage.suggested` is written for each alert, and the scenario adds the `llm.gate_forced` row an old run
left (the job stopped writing it): the two events whose bare presence under a blind alert would tell its
verdict. The visible alert is the control of every assertion about the blind one (DEC-025): the same route,
the same kind of row, shown whole.

The database is a scratch one (`tests/scratch_db.py`) and each test rolls its connection back.
"""

from __future__ import annotations

import copy
import dataclasses
import json
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest
from app.audit.events import write_event
from app.infra import config, intake
from app.infra.auth import Claims
from app.infra.jobs import Job
from app.soar.pipeline import _suggestion_visible, run_pipeline_job
from app.tier1 import queue, visibility
from app.tier1.triage import run_triage_job
from app.web import deps, main
from fastapi.testclient import TestClient

from tests.fakes.llm import TRIAGE_V4_FALSE_POSITIVE, FakeLLM
from tests.scratch_db import insert_user, scratch_database

FIXTURES = Path(__file__).resolve().parent / "fixtures"
_SWITCHES = ("DEDUP_ENABLED", "PULL_ENABLED", "AUTOCLOSE_ENABLED", "ENRICHMENT_ENABLED")
HIDDEN_KEYS = {"triage.suggested", "llm.gate_forced"}


def _arm_ids() -> tuple[str, str]:
    """`(a blind alert id, a visible alert id)`: Wazuh-shaped (① takes no other), found by the
    pipeline's own rule so the test never assumes which arm an id falls on. Called from the
    `stream` fixture, not at import: the rule reads the configuration, and a module-level call
    would read it before the autouse fixture that keeps a test off the real `.env` (DEC-047)."""
    blind = visible = None
    for n in range(100_000, 100_400):
        alert_id = f"1789100000.{n}"
        if _suggestion_visible(alert_id):
            visible = visible or alert_id
        else:
            blind = blind or alert_id
        if blind and visible:
            return blind, visible
    raise AssertionError("no id of one of the two arms in 400 tries")


@pytest.fixture(scope="module")
def scratch_dsn():
    with scratch_database("soar_intake") as dsn:
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
    """① says `false_positive` under `sbf-1` on facts that are all "unknown" (what the pipeline
    wrote with enrichment off): step 4 flags it (DEC-217); the verifier answers `needs_review`, which step 6
    flags too."""
    proposal = copy.deepcopy(TRIAGE_V4_FALSE_POSITIVE)
    proposal["structured_basis"] = {
        "severity": "medium",
        "ioc_reputation": "skipped",
        "asset_criticality": "unknown",
        "identity_privileged": "unknown",
        "occurrence_count": 1,
        "playbook_rule_applied": "sbf-1",
    }
    proposal["reasons"][0]["quote"] = "PAM: User login failed."
    verifier = {
        "agree": True,
        "structured_only_verdict": "needs_review",
        "reason": "Structured facts alone give needs_review.",
    }
    return [proposal, verifier]


def _webhook_body(alert_id: str) -> bytes:
    hit = json.loads((FIXTURES / "indexer_sample_rule5503.json").read_text(encoding="utf-8"))
    alert = hit["_source"]
    alert["id"] = alert_id
    return json.dumps(alert).encode("utf-8")


@pytest.fixture
def stream(sdb, monkeypatch):
    """The two alerts, after they have come through the whole stream with every switch off:
    `blind` and `visible` (their ids), `tc` (a `TestClient`, the caller an admin) and `db`."""
    blind, visible = _arm_ids()
    for name in _SWITCHES:
        monkeypatch.setenv(name, "false")
    monkeypatch.setenv("LLM_MODEL_PROPOSER", "fake-deepseek")
    cfg = dataclasses.replace(
        config.load(env_file="/dev/null"), WEBHOOK_API_KEY="k", LLM_MONTHLY_USD_CAP=30
    )
    assert not any(getattr(cfg, name) for name in _SWITCHES)
    for alert_id in (blind, visible):
        receipt = intake.receive(sdb, _webhook_body(alert_id), "10.0.0.7", cfg)
        run_pipeline_job(
            sdb, Job(job_id=-1, job_type="pipeline", subject_id=str(receipt.intake_id), attempts=1)
        )
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
    claims = Claims(user_id=admin_id, username="p12t01-admin", role="admin", iat=0.0, exp=0.0)
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
    "unknown" context and no auto-close, one on each arm, and ① wrote both events for each."""
    db, blind, visible = stream.db, stream.blind, stream.visible
    fetched = db.execute(
        "SELECT alert_id, status, suggestion_visible, asset_context->>'criticality', "
        "lookup_status, autoclose_rule_id FROM alerts WHERE alert_id = ANY(%s)",
        ([blind, visible],),
    ).fetchall()
    rows = {record[0]: list(record[1:]) for record in fetched}
    assert rows[blind] == [
        "queued_tier1",
        False,
        "unknown",
        {"asset": "skipped", "identity": "skipped", "ioc": "skipped"},
        None,
    ]
    assert rows[visible] == [
        "queued_tier1",
        True,
        "unknown",
        {"asset": "skipped", "identity": "skipped", "ioc": "skipped"},
        None,
    ]
    for alert_id in (blind, visible):
        written = {
            event_type
            for (event_type,) in db.execute(
                "SELECT event_type FROM audit_events WHERE subject_id = %s", (alert_id,)
            ).fetchall()
        }
        assert HIDDEN_KEYS <= written, (alert_id, written)


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


@pytest.mark.db
def test_the_overview_and_the_digest_answer_with_no_auto_closed_alert_and_no_inventory(
    stream,
) -> None:
    tc = stream.tc

    overview = tc.get("/api/admin/overview")
    assert overview.status_code == 200, overview.text
    body = overview.json()
    assert body["errors"] == []  # every section computed
    assert body["inventory"] == {"assets": 0, "identities": 0, "iocs": 0, "loaded_at": None}
    assert body["funnel"]["by_status"] == {"queued_tier1": 2}  # nothing auto-closed
    assert body["waiting"]["count"] == 2

    digest = tc.get("/api/admin/digest")
    assert digest.status_code == 200, digest.text
    assert digest.json()["rows"] == []  # an empty digest, and a page that renders
    assert isinstance(digest.json()["rules_enabled"], bool)  # the rules page stays
