"""DEC-221, card AP-T3 - the Tier 2 case view and the run endpoint, through the routes, against a database.

What `test_panel_t2_pure.py` pins of a stored row, this pins of the case's own alerts and of what leaves the server:

* a timeline row's `time` is the `alert_time` of the alert it names (a head, or a duplicate absorbed into one); a row
  naming an alert of another case, or of none, is dropped - in the view and in the raw `result`, which
  `GET /api/tier2/runs/{id}` serves the same way;
* `scope.system` is what the case's alerts say, beside the model's own lists;
* `tech` carries the run's figures and not its model (G5: the walk below finds a distinctive `model_id` nowhere in
  what the case view and the run endpoints serve, at any depth);
* the view reads the case's alerts in ONE statement however many rows the timeline has, and only reads;
* an older run and a garbled one give less, never an error; the override of the conclusion is served as before.

No test makes a model call: every run and job row is inserted. No helper is imported from another test file (project
convention): the ones below are this file's own copies.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.infra import config
from app.infra.auth import Claims
from app.llm.builder import rag_not_applied_warning
from app.rag import entries
from app.rag.failures import FAILURE_KINDS
from app.tier2 import investigate as tier2_investigate
from app.tier2 import investigation_view as view
from app.web import deps, main
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from tests.fakes.llm import INVESTIGATE_V3_OK, INVESTIGATE_V4_OK
from tests.rag_data import add_entry

pytestmark = pytest.mark.db

_PAST = datetime(2026, 1, 1, tzinfo=UTC)
T0 = datetime(2026, 11, 15, 8, 0, tzinfo=UTC)

#: A model id no real answer, log or title holds: if it shows anywhere in what is served, the model's name is served.
MODEL_ID = "zz-distinctive-model-id-GLM-9.9-xq7"

#: Every field of the configuration that names a model, set to a value that holds `MODEL_ID`: the configuration the
#: routes are run with. A name served out of the configuration (not only out of `llm_runs.model_id`) would show.
MODEL_CONFIG = {
    field.name: f"{MODEL_ID}:{field.name}"
    for field in dataclasses.fields(config.Config)
    if "MODEL" in field.name
}


# ---------------------------------------------------------------------------
# Fixture helpers (this file's own copies)
# ---------------------------------------------------------------------------


def _make_user(conn) -> str:
    user_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash) "
        "VALUES (%s, %s, %s, 'tier2', 'x')",
        (user_id, f"user-{user_id[:8]}", "Test Analyst"),
    )
    return user_id


def _make_case(conn, user_id: str) -> str:
    case_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO cases (case_id, title, status, severity, created_by) "
        "VALUES (%s, 'case', 'investigating', 'high', %s)",
        (case_id, user_id),
    )
    return case_id


def _insert_alert(
    conn,
    *,
    alert_time: datetime = T0,
    agent_name: str = "host-a",
    alert_user: str | None = None,
    duplicate_of: str | None = None,
    case_id: str | None = None,
    raw_log: str = "",
) -> str:
    alert_id = f"ap3-{uuid.uuid4()}"
    status = "duplicate" if duplicate_of else "escalated_tier2"
    conn.execute(
        "INSERT INTO alerts (alert_id, rule_id, rule_level, severity, description, agent_name, alert_user, "
        "alert_time, category, resolved_by, mapping_version, event_bucket_hash, raw_payload, raw_log, status, "
        "duplicate_of, case_id, closed_at, sealed_at) "
        "VALUES (%s, '40112', 10, 'high', 'SSH brute force', %s, %s, %s, 'brute_force', 'rule_groups', 'v1', "
        "%s, '{}'::jsonb, %s, %s, %s, %s, %s, %s)",
        (
            alert_id,
            agent_name,
            alert_user,
            alert_time,
            hashlib.sha256(alert_id.encode()).hexdigest(),
            raw_log,
            status,
            duplicate_of,
            case_id,
            _PAST if duplicate_of else None,
            _PAST if duplicate_of else None,
        ),
    )
    return alert_id


def _add_head(conn, case_id: str, user_id: str, **kwargs) -> str:
    alert_id = _insert_alert(conn, case_id=case_id, **kwargs)
    conn.execute(
        "INSERT INTO case_alerts (case_id, alert_id, added_by) VALUES (%s, %s, %s)",
        (case_id, alert_id, user_id),
    )
    return alert_id


def _insert_job(conn, case_id: str, status: str = "succeeded") -> int:
    return conn.execute(
        "INSERT INTO jobs (job_type, subject_id, status, attempts) "
        "VALUES ('investigate', %s, %s, 1) RETURNING job_id",
        (case_id, status),
    ).fetchone()[0]


def _insert_run(
    conn,
    case_id: str,
    *,
    job_id: int | None = None,
    result: dict | None = None,
    evidence_check: dict | None = None,
    agent_trace: dict | None = None,
    stopped_by: str | None = None,
    model_id: str | None = MODEL_ID,
    input_tokens: int | None = 1200,
    output_tokens: int | None = 340,
    latency_ms: int | None = 5400,
    cost_usd: float | None = 0.00123,
    lookup_id: str | None = None,
    warnings: list[str] | None = None,
) -> uuid.UUID:
    run_id = tier2_investigate.run_id_for_job(job_id) if job_id is not None else uuid.uuid4()
    conn.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, role, system_prompt, user_message, "
        "agent_trace, result, evidence_check, stopped_by, model_id, input_tokens, output_tokens, latency_ms, "
        "cost_usd, rag_lookup_id, citation_warnings) VALUES (%s, 'investigate', 'case', %s, 'investigator', 's', "
        "'u', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (
            run_id,
            case_id,
            Jsonb(agent_trace) if agent_trace is not None else None,
            Jsonb(result) if result is not None else None,
            Jsonb(evidence_check) if evidence_check is not None else None,
            stopped_by,
            model_id,
            input_tokens,
            output_tokens,
            latency_ms,
            cost_usd,
            lookup_id,
            Jsonb(warnings) if warnings is not None else None,
        ),
    )
    return run_id


def _entry(conn, title: str, conclusion: str = "closed_fp") -> str:
    """A knowledge entry whose Markdown carries `title`, as the publisher writes it."""
    entry_id = str(uuid.uuid4())
    content = entries.render_entry_markdown(
        {
            "entry_id": entry_id,
            "version": 1,
            "title": title,
            "conclusion": conclusion,
            "category": "recon",
            "summary": "Tóm tắt.",
        }
    )
    add_entry(conn, entry_id=entry_id, conclusion=conclusion, content=content)
    return entry_id


def _lookup(conn, case_id: str, *, matches=(), ranked=None, status: str = "ok") -> str:
    """A `rag_results` row of the case: `matches` and `ranked` are `[(entry_id, score)]`."""
    lookup_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO rag_results (lookup_id, subject_kind, subject_id, status, matches, match_notes, ranked) "
        "VALUES (%s, 'case', %s, %s, %s, '{}'::jsonb, %s)",
        (
            lookup_id,
            case_id,
            status,
            Jsonb(
                [
                    {"entry_id": e, "level": "giong", "content_sha256": "0" * 64, "score": sc}
                    for e, sc in matches
                ]
            ),
            None if ranked is None else Jsonb([{"entry_id": e, "score": sc} for e, sc in ranked]),
        ),
    )
    return lookup_id


def _rows(*pairs: tuple[str, str]) -> list[dict]:
    return [
        {"alert_id": alert_id, "what": what, "tactic": "Execution", "technique": "T1059"}
        for alert_id, what in pairs
    ]


def _v4(**over) -> dict:
    return {**copy.deepcopy(INVESTIGATE_V4_OK), **over}


class _Client:
    def __init__(self, user_id: str, events: list[str]) -> None:
        self.http = TestClient(main.app, follow_redirects=False)
        self.user_id = user_id
        self.events = events

    def claims(self) -> Claims:
        return Claims(user_id=self.user_id, username=self.user_id, role="tier2", iat=0.0, exp=0.0)


@pytest.fixture
def client(db, monkeypatch):
    events: list[str] = []
    # no-ops that record: a real rollback would discard the rows seeded on this shared connection
    monkeypatch.setattr(db, "commit", lambda: events.append("commit"))
    monkeypatch.setattr(db, "rollback", lambda: events.append("rollback"))
    c = _Client(_make_user(db), events)

    def get_conn():
        try:
            yield db
        except BaseException:
            db.rollback()
            raise

    main.app.dependency_overrides[deps.get_conn] = get_conn
    main.app.dependency_overrides[deps.get_config] = lambda: config.Config(**MODEL_CONFIG)
    main.app.dependency_overrides[deps.current_user] = c.claims
    try:
        yield c
    finally:
        for dep in (deps.get_conn, deps.get_config, deps.current_user):
            main.app.dependency_overrides.pop(dep, None)


def _view(client: _Client, case_id: str) -> dict:
    resp = client.http.get(f"/api/tier2/cases/{case_id}/investigation")
    assert resp.status_code == 200, resp.text
    return resp.json()


def _raw_run(client: _Client, run_id) -> dict:
    resp = client.http.get(f"/api/tier2/runs/{run_id}")
    assert resp.status_code == 200, resp.text
    return resp.json()


def _at(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _case_with_two_heads(db, user_id):
    """A case of two heads and a duplicate absorbed into the first, and a head of another case."""
    case_id = _make_case(db, user_id)
    h1 = _add_head(
        db,
        case_id,
        user_id,
        alert_time=T0 + timedelta(minutes=30),
        agent_name="host-b",
        alert_user="root",
    )
    h2 = _add_head(
        db,
        case_id,
        user_id,
        alert_time=T0 + timedelta(minutes=10),
        agent_name="host-a",
        alert_user="alice",
    )
    dup = _insert_alert(
        db,
        alert_time=T0 + timedelta(minutes=20),
        agent_name="host-a",
        alert_user="alice",
        duplicate_of=h1,
        case_id=case_id,
    )
    other = _make_case(db, user_id)
    foreign = _add_head(
        db, other, user_id, alert_time=T0, agent_name="host-z", alert_user="mallory"
    )
    return case_id, h1, h2, dup, foreign


# ---------------------------------------------------------------------------
# The timeline's times come from the case's alerts
# ---------------------------------------------------------------------------


def test_the_timeline_takes_its_times_from_the_alerts_and_drops_what_is_not_the_cases(client, db):
    case_id, h1, h2, dup, foreign = _case_with_two_heads(db, client.user_id)
    orphan = _insert_alert(db)  # an alert of no case
    stored = _rows(
        (h1, "last"), (foreign, "foreign"), (h2, "first"), ("no-such-alert", "made up"), (dup, "middle"),
        (orphan, "orphan"),
    )  # fmt: skip
    job = _insert_job(db, case_id)
    _insert_run(db, case_id, job_id=job, result=_v4(timeline=stored))

    run = _view(client, case_id)["run"]

    assert [row["what"] for row in run["timeline"]] == ["first", "middle", "last"]
    assert [_at(row["time"]) for row in run["timeline"]] == [
        T0 + timedelta(minutes=10),
        T0 + timedelta(minutes=20),
        T0 + timedelta(minutes=30),
    ]
    assert [row["alert_id"] for row in run["timeline"]] == [h2, dup, h1]
    assert set(run["timeline"][0]) == {
        "alert_id",
        "time",
        "what",
        "tactic",
        "technique",
        "technique_name",  # DEC-223: the local ATT&CK reference's own name for the id the model wrote
        "technique_known",
    }
    assert (
        run["timeline"][0]["tactic"] == "Execution" and run["timeline"][0]["technique"] == "T1059"
    )
    assert run["timeline"][0]["technique_name"] == "Command and Scripting Interpreter"
    assert run["timeline"][0]["technique_known"] is True
    assert run["checks"] == {"technique_not_in_reference": 0}


def test_the_timeline_techniques_are_checked_against_the_local_reference_through_the_route(
    client, db
):
    """DEC-223: a technique the model wrote that the local ATT&CK reference does not hold is marked and counted; one
    it holds is served with MITRE's own name; the raw result is the stored shape, and `GET /runs/{id}` serves it as
    stored (no key of this check there)."""
    case_id, h1, h2, dup, _foreign = _case_with_two_heads(db, client.user_id)
    stored = _rows((h1, "a"), (h2, "b"), (dup, "c"))
    stored[1]["technique"] = "T9999"
    stored[2]["technique"] = "brute force"
    job = _insert_job(db, case_id)
    run_id = _insert_run(db, case_id, job_id=job, result=_v4(timeline=stored))

    body = _view(client, case_id)
    run = body["run"]

    # sorted by the alerts' own times: h2, the duplicate, h1
    assert [
        (r["technique"], r["technique_name"], r["technique_known"]) for r in run["timeline"]
    ] == [
        ("T9999", None, False),
        ("brute force", None, None),
        ("T1059", "Command and Scripting Interpreter", True),
    ]
    assert run["checks"] == {"technique_not_in_reference": 1}
    assert [set(r) for r in run["result"]["timeline"]] == [
        {"alert_id", "what", "tactic", "technique"}
    ] * 3
    raw = client.http.get(f"/api/tier2/runs/{run_id}").json()
    assert [set(r) for r in raw["result"]["timeline"]] == [
        {"alert_id", "what", "tactic", "technique"}
    ] * 3


def test_the_raw_result_of_the_view_carries_the_filtered_timeline_in_its_stored_shape(client, db):
    case_id, h1, h2, _dup, foreign = _case_with_two_heads(db, client.user_id)
    stored = _rows((h1, "late"), (foreign, "foreign"), (h2, "early"))
    _insert_run(db, case_id, job_id=_insert_job(db, case_id), result=_v4(timeline=stored))

    raw = _view(client, case_id)["run"]["result"]

    assert raw["timeline"] == [stored[2], stored[0]]
    assert foreign not in json.dumps(raw)
    assert {k: v for k, v in raw.items() if k != "timeline"} == {
        k: v for k, v in _v4().items() if k != "timeline"
    }


def test_the_run_endpoint_serves_the_same_filtered_timeline_and_the_rest_as_stored(client, db):
    case_id, h1, h2, _dup, foreign = _case_with_two_heads(db, client.user_id)
    stored = _rows((h1, "late"), (foreign, "foreign"), (h2, "early"))
    result = _v4(timeline=stored)
    run_id = _insert_run(db, case_id, job_id=_insert_job(db, case_id), result=result)

    body = _raw_run(client, run_id)

    assert body["status"] == "done"
    assert body["result"]["timeline"] == [stored[2], stored[0]]
    assert foreign not in json.dumps(body)
    assert {k: v for k, v in body["result"].items() if k != "timeline"} == {
        k: v for k, v in result.items() if k != "timeline"
    }
    assert set(body) == {"status", "result", "evidence_check", "citation_warnings", "stopped_by"}


def test_the_run_endpoint_serves_a_run_with_no_timeline_exactly_as_stored(client, db):
    case_id, *_ = _case_with_two_heads(db, client.user_id)
    result = copy.deepcopy(INVESTIGATE_V3_OK)
    run_id = _insert_run(db, case_id, result=result)

    assert _raw_run(client, run_id)["result"] == result


@pytest.mark.parametrize("garbled", ["soon", None, {"a": 1}, 3])
def test_the_run_endpoint_serves_a_garbled_timeline_as_an_empty_list(client, db, garbled):
    case_id, *_ = _case_with_two_heads(db, client.user_id)
    run_id = _insert_run(db, case_id, result=_v4(timeline=garbled))

    assert _raw_run(client, run_id)["result"]["timeline"] == []


def test_the_run_endpoint_reads_the_cases_alerts_only_when_the_timeline_names_some(
    client, db, monkeypatch
):
    case_id, h1, *_ = _case_with_two_heads(db, client.user_id)
    old = _insert_run(db, case_id, result=copy.deepcopy(INVESTIGATE_V3_OK))
    new = _insert_run(db, case_id, result=_v4(timeline=_rows((h1, "x"))))
    statements: list[str] = []
    real = db.execute

    def spy(query, *args, **kwargs):
        statements.append(" ".join(str(query).split()))
        return real(query, *args, **kwargs)

    monkeypatch.setattr(db, "execute", spy)

    _raw_run(client, old)
    assert len(statements) == 1  # the run's own row, nothing else
    statements.clear()
    _raw_run(client, new)
    assert len(statements) == 2  # the run's row and the case's alerts
    assert statements[1].startswith("WITH members AS")


def test_a_run_naming_a_case_that_is_not_a_uuid_gives_no_alert_and_no_error(client, db):
    """`served_result` reads the row's `subject_id` as it was stored: a value that is no uuid names no alert."""
    run_id = uuid.uuid4()
    db.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, role, system_prompt, user_message, result) "
        "VALUES (%s, 'investigate', 'case', 'not-a-uuid', 'investigator', 's', 'u', %s)",
        (run_id, Jsonb(_v4(timeline=_rows(("a-1", "x"))))),
    )
    assert _raw_run(client, run_id)["result"]["timeline"] == []


# ---------------------------------------------------------------------------
# scope.system
# ---------------------------------------------------------------------------


def test_scope_system_is_what_the_cases_alerts_say_beside_the_models_lists(client, db):
    case_id, *_ = _case_with_two_heads(db, client.user_id)
    _add_head(db, case_id, client.user_id, agent_name="host-c", alert_user=None)
    result = _v4(scope={"hosts": ["model-says-host"], "accounts": ["model-says-account"]})
    _insert_run(db, case_id, job_id=_insert_job(db, case_id), result=result)

    scope = _view(client, case_id)["run"]["scope"]

    assert scope["hosts"] == ["model-says-host"]
    assert scope["accounts"] == ["model-says-account"]
    assert scope["system"] == {
        "hosts": ["host-a", "host-b", "host-c"],
        "accounts": [
            "alice",
            "root",
        ],  # an alert with no account adds none; the foreign case's `mallory` is not here
        "alert_count": 4,  # 3 heads + 1 duplicate
    }


def test_scope_system_counts_the_alerts_as_the_current_numbers_do(client, db):
    case_id, *_ = _case_with_two_heads(db, client.user_id)
    snap = {"alert_count": 3, "total_occurrences": 3, "last_seen_at": None}
    _insert_run(db, case_id, job_id=_insert_job(db, case_id), result=_v4(), agent_trace=snap)

    body = _view(client, case_id)

    assert body["run"]["scope"]["system"]["alert_count"] == body["current"]["alert_count"] == 3


def test_a_case_with_no_alerts_has_an_empty_system_part(client, db):
    case_id = _make_case(db, client.user_id)
    _insert_run(db, case_id, job_id=_insert_job(db, case_id), result=_v4())

    run = _view(client, case_id)["run"]

    assert run["scope"]["system"] == {"hosts": [], "accounts": [], "alert_count": 0}
    assert run["timeline"] == []


# ---------------------------------------------------------------------------
# tech, evidence_summary, an older run, a garbled one
# ---------------------------------------------------------------------------


def test_tech_carries_the_figures_the_run_stored(client, db):
    case_id, *_ = _case_with_two_heads(db, client.user_id)
    trace = {"alert_count": 3, "total_occurrences": 3, "last_seen_at": None}
    run_id = _insert_run(
        db,
        case_id,
        job_id=_insert_job(db, case_id),
        result=_v4(playbook_used="brute_force"),
        agent_trace=trace,
    )

    run = _view(client, case_id)["run"]

    assert run["run_id"] == str(run_id)
    assert run["tech"] == {
        "input_tokens": 1200,
        "output_tokens": 340,
        "latency_ms": 5400,
        "cost_usd": 0.00123,
        "analysed_at": run["created_at"],
        "playbook": "brute_force",
        "alerts_read": 3,
    }
    assert isinstance(
        run["tech"]["cost_usd"], float
    )  # a JSON number, not the string a `numeric` could become


def test_tech_of_a_run_that_stored_no_figures_is_none(client, db):
    case_id, *_ = _case_with_two_heads(db, client.user_id)
    _insert_run(
        db,
        case_id,
        job_id=_insert_job(db, case_id),
        result=_v4(),
        input_tokens=None,
        output_tokens=None,
        latency_ms=None,
        cost_usd=None,
    )

    tech = _view(client, case_id)["run"]["tech"]

    assert [
        tech[k] for k in ("input_tokens", "output_tokens", "latency_ms", "cost_usd", "alerts_read")
    ] == [None] * 5


def test_evidence_summary_is_cited_and_verified_of_the_rows_the_view_builds(client, db):
    case_id = _make_case(db, client.user_id)
    head = _add_head(db, case_id, client.user_id, raw_log="Failed password for root from 10.0.0.9")
    evidence = [
        {"alert_id": head, "quote": "Failed password for root", "why": "w1"},
        {"alert_id": head, "quote": "this quote is not in the log", "why": "w2"},
        {"alert_id": head, "quote": "abc", "why": "w3"},
    ]
    parsed = _v4(evidence=evidence)
    check = tier2_investigate._check_evidence(db, case_id, parsed)  # the writer's own check
    _insert_run(db, case_id, job_id=_insert_job(db, case_id), result=parsed, evidence_check=check)

    run = _view(client, case_id)["run"]

    assert run["evidence_summary"] == {"cited": 3, "verified": 1}
    assert [row["verified"] for row in run["evidence"]] == [True, False, False]


def test_a_version_3_run_gives_less_and_no_error(client, db):
    case_id, *_ = _case_with_two_heads(db, client.user_id)
    result = copy.deepcopy(INVESTIGATE_V3_OK)
    _insert_run(db, case_id, job_id=_insert_job(db, case_id), result=result)

    resp = client.http.get(f"/api/tier2/cases/{case_id}/investigation")

    assert resp.status_code == 200
    run = resp.json()["run"]
    assert run["timeline"] == []
    assert run["scope"]["hosts"] == [] and run["scope"]["accounts"] == []
    assert run["scope"]["system"]["alert_count"] == 3
    assert [h["likelihood"] for h in run["hypotheses"]] == [None]
    assert run["next_steps_rows"] == [{"step": s, "priority": None} for s in result["next_steps"]]
    assert run["next_steps"] == result["next_steps"]
    assert run["result"] == result


@pytest.mark.parametrize(
    "result",
    [
        {},
        {"timeline": "x", "scope": 5, "gia_thuyet": "x", "next_steps": 7, "evidence": {}},
        {
            "timeline": [{"alert_id": 3}, None],
            "scope": {"hosts": 1},
            "gia_thuyet": [None, {"likelihood": 3}],
        },
    ],
)
def test_a_garbled_stored_result_gives_less_and_no_error(client, db, result):
    case_id, *_ = _case_with_two_heads(db, client.user_id)
    _insert_run(db, case_id, job_id=_insert_job(db, case_id), result=result)

    resp = client.http.get(f"/api/tier2/cases/{case_id}/investigation")

    assert resp.status_code == 200
    run = resp.json()["run"]
    assert run["timeline"] == [] and run["next_steps_rows"] == []
    assert run["evidence_summary"] == {"cited": 0, "verified": 0}


def test_a_run_that_stopped_carries_none_of_the_new_keys(client, db):
    case_id, *_ = _case_with_two_heads(db, client.user_id)
    _insert_run(db, case_id, job_id=_insert_job(db, case_id), result=None, stopped_by="schema")

    run = _view(client, case_id)["run"]

    assert set(run) == {"run_id", "created_at", "rag", "result", "stopped_text"}


def test_the_override_of_the_conclusion_is_served_exactly_as_today(client, db):
    """A conclusion the system changed to `need_more_data`: the same sentence, model conclusion, held reasons and
    unverified rows for a version 4 run as for its version 3 twin on a case alike."""
    served = {}
    for name, answer in (("v3", INVESTIGATE_V3_OK), ("v4", INVESTIGATE_V4_OK)):
        case_id = _make_case(db, client.user_id)
        head = _add_head(
            db, case_id, client.user_id, raw_log="Failed password for root from 10.0.0.9"
        )
        parsed = {
            **copy.deepcopy(answer),
            "suggested_conclusion": "need_more_data",
            "evidence": [{"alert_id": head, "quote": "this is not in the log", "why": "w"}],
        }
        check = tier2_investigate._check_evidence(db, case_id, parsed)
        check["model_conclusion"] = "false_positive"
        check["original_conclusion"] = "false_positive"
        _insert_run(
            db, case_id, job_id=_insert_job(db, case_id), result=parsed, evidence_check=check
        )
        run = _view(client, case_id)["run"]
        served[name] = {
            k: run[k]
            for k in ("conclusion", "conclusion_label", "overruled", "model_conclusion", "held_by")
        } | {
            # the rows of the two cases differ only in the alert each names
            "evidence": [
                {k: v for k, v in row.items() if k != "alert_id"} for row in run["evidence"]
            ],
        }
        assert [row["alert_id"] for row in run["evidence"]] == [head]
    assert served["v4"] == served["v3"]
    assert served["v4"]["held_by"] == ["no_verified_evidence"]
    assert served["v4"]["model_conclusion"] == "false_positive"
    assert served["v4"]["overruled"] is not None
    assert [row["verified"] for row in served["v4"]["evidence"]] == [False]
    assert served["v4"]["evidence"][0]["reason_text"] == view.REJECT_TEXT["quote_not_found"]


def test_every_old_key_of_a_run_keeps_its_value_when_the_run_is_version_4(client, db):
    """Besides the new keys, a version 4 run's view equals the view of the version 3 run it adds to."""
    runs = {}
    for name, answer in (("v3", INVESTIGATE_V3_OK), ("v4", INVESTIGATE_V4_OK)):
        case_id, *_ = _case_with_two_heads(db, client.user_id)
        _insert_run(db, case_id, job_id=_insert_job(db, case_id), result=copy.deepcopy(answer))
        run = _view(client, case_id)["run"]
        for key in (
            "run_id",
            "created_at",
            "result",
            "tech",
            "timeline",
            "scope",
            "next_steps_rows",
            "evidence_summary",
        ):
            run.pop(key)
        run["hypotheses"] = [
            {k: v for k, v in h.items() if k != "likelihood"} for h in run["hypotheses"]
        ]
        runs[name] = run
    assert runs["v4"] == runs["v3"]


# ---------------------------------------------------------------------------
# One statement for the case's alerts; read-only
# ---------------------------------------------------------------------------


def _statements(db, monkeypatch) -> list[str]:
    statements: list[str] = []
    real = db.execute

    def spy(query, *args, **kwargs):
        statements.append(" ".join(str(query).split()))
        return real(query, *args, **kwargs)

    monkeypatch.setattr(db, "execute", spy)
    return statements


def test_the_view_reads_the_cases_alerts_in_one_statement_whatever_the_rows(
    client, db, monkeypatch
):
    case_id, h1, h2, dup, foreign = _case_with_two_heads(db, client.user_id)
    snap = {"alert_count": 3, "total_occurrences": 3, "last_seen_at": None}
    big = _rows(*[(a, str(n)) for n, a in enumerate([h1, h2, dup, foreign, "x", h1, h2, dup] * 6)])
    _insert_run(
        db, case_id, job_id=_insert_job(db, case_id), result=_v4(timeline=big), agent_trace=snap
    )
    statements = _statements(db, monkeypatch)

    run = _view(client, case_id)["run"]

    assert len(run["timeline"]) == 36  # the foreign alert and "x" are dropped: 6 * 6
    # the cases status, the latest job, the run by its id, the numbers now, and the case's alerts
    assert len(statements) == 5, statements
    assert sum(sql.startswith("WITH members AS") for sql in statements) == 1
    for sql in statements:
        assert sql.upper().startswith(("SELECT", "WITH")), sql


def test_a_view_of_a_run_without_a_snapshot_runs_four_statements(client, db, monkeypatch):
    case_id, h1, *_ = _case_with_two_heads(db, client.user_id)
    _insert_run(db, case_id, job_id=_insert_job(db, case_id), result=_v4(timeline=_rows((h1, "x"))))
    statements = _statements(db, monkeypatch)

    _view(client, case_id)

    assert len(statements) == 4, statements  # before AP-T3: three


def test_a_view_with_no_result_reads_nothing_of_the_cases_alerts(client, db, monkeypatch):
    case_id, *_ = _case_with_two_heads(db, client.user_id)
    _insert_run(db, case_id, job_id=_insert_job(db, case_id), result=None, stopped_by="schema")
    statements = _statements(db, monkeypatch)

    _view(client, case_id)

    assert not any(sql.startswith("WITH members AS") for sql in statements)
    assert len(statements) == 3


# ---------------------------------------------------------------------------
# G5 - the model's name is nowhere in what is served
# ---------------------------------------------------------------------------


def _walk(value, path="$"):
    """Every key and every scalar of a JSON document, at every depth: `(path, text)`."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield f"{path}.{key}", str(key)
            yield from _walk(item, f"{path}.{key}")
    elif isinstance(value, list | tuple):
        for index, item in enumerate(value):
            yield from _walk(item, f"{path}[{index}]")
    else:
        yield path, str(value)


def _leaks(document, needle: str) -> list[str]:
    return [path for path, text in _walk(document) if needle.lower() in text.lower()]


def test_the_walk_finds_a_model_id_in_a_key_a_value_and_a_list():
    needle = "zz-find-me"
    assert _leaks({"a": 1}, needle) == []
    assert _leaks({"tech": {"model_id": needle}}, needle) == ["$.tech.model_id"]
    assert _leaks({"zz-find-me": 1}, needle) == ["$.zz-find-me"]
    assert _leaks({"rows": [{"x": [1, "has ZZ-FIND-ME inside"]}]}, needle) == ["$.rows[0].x[1]"]
    assert _leaks(None, needle) == [] and _leaks([], needle) == []


def test_the_walk_goes_red_when_the_tech_figures_leak_the_model(client, db, monkeypatch):
    """Not a check of the product: the walk is live. With `_tech` made to name the model, the same document that
    `test_no_endpoint_serves_the_model_id` walks is flagged at the key and at the value."""
    case_id, *_ = _case_with_two_heads(db, client.user_id)
    _insert_run(db, case_id, job_id=_insert_job(db, case_id), result=_v4())
    real = view._tech
    monkeypatch.setattr(view, "_tech", lambda *a, **k: {**real(*a, **k), "model_id": MODEL_ID})

    body = _view(client, case_id)

    assert _leaks(body, MODEL_ID) == ["$.run.tech.model_id"]


@pytest.mark.parametrize("field", sorted(MODEL_CONFIG))
def test_the_walk_goes_red_when_a_model_name_of_the_configuration_is_served(
    client, db, monkeypatch, field
):
    """C, the same for the configuration: a `tech` that carries any one model field of the configuration the routes
    run with (here a `RAG_MODEL`, an embedding model's name...) is flagged by the walk the test above makes.
    """
    case_id, *_ = _case_with_two_heads(db, client.user_id)
    _insert_run(db, case_id, job_id=_insert_job(db, case_id), result=_v4())
    real = view._tech
    served = config.Config(**MODEL_CONFIG)
    monkeypatch.setattr(
        view, "_tech", lambda *a, **k: {**real(*a, **k), "label": getattr(served, field)}
    )

    body = _view(client, case_id)

    assert _leaks(body, MODEL_CONFIG[field]) == ["$.run.tech.label"]


def test_no_endpoint_serves_the_model_id(client, db):
    """The case view and the Tier 2 run endpoints, for a case with a run (of version 4, a version 3 one and one that
    stopped) whose `model_id` is distinctive: the string is in no key and no value, at any depth. Found today, before
    this card: nothing - the view never selected the column."""
    case_id, h1, *_ = _case_with_two_heads(db, client.user_id)
    snap = {"alert_count": 3, "total_occurrences": 3, "last_seen_at": None}
    rid_new = _insert_run(
        db,
        case_id,
        job_id=_insert_job(db, case_id),
        result=_v4(timeline=_rows((h1, "x"))),
        agent_trace=snap,
    )
    rid_old = _insert_run(db, case_id, result=copy.deepcopy(INVESTIGATE_V3_OK))
    rid_stopped = _insert_run(db, case_id, result=None, stopped_by="schema")
    documents = {
        "investigation": _view(client, case_id),
        "case": client.http.get(f"/api/tier2/cases/{case_id}").json(),
        "cases": client.http.get("/api/tier2/cases").json(),
        **{f"run {name}": _raw_run(client, rid) for name, rid in
           (("v4", rid_new), ("v3", rid_old), ("stopped", rid_stopped))},
    }  # fmt: skip
    for name, document in documents.items():
        assert _leaks(document, MODEL_ID) == [], name
        assert _leaks(document, "GLM") == [], name
    # and the walk saw something: the view of the run is not an empty document
    assert any(path.startswith("$.run.tech") for path, _ in _walk(documents["investigation"]))
    assert json.dumps(documents["investigation"], default=str)


def test_tech_has_exactly_these_keys(client, db):
    case_id, *_ = _case_with_two_heads(db, client.user_id)
    _insert_run(db, case_id, job_id=_insert_job(db, case_id), result=_v4())

    tech = _view(client, case_id)["run"]["tech"]

    assert set(tech) == {
        "input_tokens",
        "output_tokens",
        "latency_ms",
        "cost_usd",
        "analysed_at",
        "playbook",
        "alerts_read",
    }


def test_the_configuration_the_routes_run_with_names_a_model_in_every_model_field():
    """The introspection is not vacuous: the fields of today's configuration that name a model are all in it."""
    assert {
        "LLM_MODEL_PROPOSER",
        "LLM_MODEL_VERIFIER",
        "RAG_MODEL",
        "RAG_EMBED_MODEL",
        "RAG_RERANK_MODEL",
    } <= set(MODEL_CONFIG)
    assert all(MODEL_ID in value for value in MODEL_CONFIG.values())


def test_the_model_fields_of_the_configuration_are_served_nowhere(client, db):
    """C: the walk also looks for what the configuration says (`MODEL_CONFIG`), through a view that lists knowledge
    candidates and a run endpoint; the view reads `RAG_MIN_SCORE` of that configuration and nothing named MODEL.
    """
    case_id, h1, *_ = _case_with_two_heads(db, client.user_id)
    entry = _entry(db, "Một quy tắc")
    lookup = _lookup(db, case_id, matches=[(entry, 0.9)], ranked=[(entry, 0.9)])
    rid = _insert_run(
        db,
        case_id,
        job_id=_insert_job(db, case_id),
        result=_v4(timeline=_rows((h1, "x"))),
        lookup_id=lookup,
    )
    documents = {"investigation": _view(client, case_id), "run": _raw_run(client, rid)}
    for name, document in documents.items():
        for value in MODEL_CONFIG.values():
            assert _leaks(document, value) == [], (name, value)
        assert _leaks(document, MODEL_ID) == [], name
    assert documents["investigation"]["run"]["knowledge"]["state"] == "matched"


# ---------------------------------------------------------------------------
# The raw timeline's four keys (D)
# ---------------------------------------------------------------------------


def test_a_hand_edited_timeline_row_carries_only_the_four_keys_through_both_routes(client, db):
    case_id, h1, *_ = _case_with_two_heads(db, client.user_id)
    row = {
        **_rows((h1, "x"))[0],
        "time": "1999-01-01T00:00:00Z",
        "model": MODEL_ID,
        "html": "<b>x</b>",
    }
    rid = _insert_run(db, case_id, job_id=_insert_job(db, case_id), result=_v4(timeline=[row]))

    served = _view(client, case_id)["run"]["result"]["timeline"]
    raw = _raw_run(client, rid)["result"]["timeline"]

    assert served == raw == _rows((h1, "x"))


# ---------------------------------------------------------------------------
# The knowledge candidates (A)
# ---------------------------------------------------------------------------


def test_knowledge_lists_the_best_candidates_with_the_title_and_conclusion_of_their_entries(
    client, db
):
    case_id, *_ = _case_with_two_heads(db, client.user_id)
    e1 = _entry(db, "Quét cổng từ máy nội bộ", "closed_fp")
    e2 = _entry(db, "Brute force SSH", "confirmed_incident")
    e3 = _entry(db, "Cập nhật phần mềm", "closed_fp")
    e4 = _entry(db, "Không được liệt kê", "closed_fp")
    lookup = _lookup(
        db,
        case_id,
        matches=[(e1, 0.87), (e2, 0.62)],
        ranked=[(e1, 0.87), (e2, 0.62), (e3, 0.31), (e4, 0.1)],
    )
    _insert_run(db, case_id, job_id=_insert_job(db, case_id), result=_v4(), lookup_id=lookup)

    run = _view(client, case_id)["run"]

    assert run["knowledge"] == {
        "state": "matched",
        "failure": None,
        "best_pct": 87,
        "floor_pct": 50,
        "threshold_pct": 0,
        "scored": 4,
        "candidates": [
            {"pct": 87, "title": "Quét cổng từ máy nội bộ", "conclusion": "closed_fp"},
            {"pct": 62, "title": "Brute force SSH", "conclusion": "confirmed_incident"},
            {"pct": 31, "title": "Cập nhật phần mềm", "conclusion": "closed_fp"},
        ],
    }
    # the pair the run already served is as it was and says the same number
    assert run["rag"] == {
        "best_pct": 87,
        "not_applied": None,
        "below_floor_pct": None,
        "floor_pct": None,
    }


def test_knowledge_of_a_run_under_the_floor_agrees_with_the_pair_and_is_cut_down(client, db):
    case_id, *_ = _case_with_two_heads(db, client.user_id)
    entry = _entry(db, "Gần mức tối thiểu")
    lookup = _lookup(db, case_id, matches=[], ranked=[(entry, 0.4999)])
    _insert_run(db, case_id, job_id=_insert_job(db, case_id), result=_v4(), lookup_id=lookup)

    run = _view(client, case_id)["run"]

    assert run["rag"]["below_floor_pct"] == 49 and run["rag"]["floor_pct"] == 50
    assert run["knowledge"]["state"] == "below_floor"
    assert run["knowledge"]["best_pct"] == run["rag"]["below_floor_pct"]
    assert run["knowledge"]["floor_pct"] == run["rag"]["floor_pct"]
    assert run["knowledge"]["candidates"] == [
        {"pct": 49, "title": "Gần mức tối thiểu", "conclusion": "closed_fp"}
    ]


@pytest.mark.parametrize(
    ("kind", "state"), [("empty", "no_candidate"), ("none", "no_lookup"), ("failed", "failed")]
)
def test_knowledge_of_a_run_without_candidates_reads_no_entry(client, db, monkeypatch, kind, state):
    case_id, *_ = _case_with_two_heads(db, client.user_id)
    lookup, warnings = None, None
    if kind == "empty":
        lookup = _lookup(db, case_id, matches=[], ranked=[])
    elif kind == "failed":
        lookup = _lookup(db, case_id, status="failed")
        warnings = [rag_not_applied_warning(FAILURE_KINDS[0])]
    _insert_run(
        db,
        case_id,
        job_id=_insert_job(db, case_id),
        result=_v4(),
        lookup_id=lookup,
        warnings=warnings,
    )
    statements = _statements(db, monkeypatch)

    run = _view(client, case_id)["run"]

    assert run["knowledge"]["state"] == state and run["knowledge"]["candidates"] == []
    assert run["knowledge"]["threshold_pct"] == 0
    assert not any("knowledge_entries" in sql for sql in statements)


def test_knowledge_adds_one_statement_and_only_when_a_candidate_is_listed(client, db, monkeypatch):
    case_id, h1, *_ = _case_with_two_heads(db, client.user_id)
    snap = {"alert_count": 3, "total_occurrences": 3, "last_seen_at": None}
    entry = _entry(db, "Một quy tắc")
    lookup = _lookup(db, case_id, matches=[(entry, 0.9)], ranked=[(entry, 0.9)])
    _insert_run(
        db,
        case_id,
        job_id=_insert_job(db, case_id),
        result=_v4(timeline=_rows((h1, "x"))),
        agent_trace=snap,
        lookup_id=lookup,
    )
    statements = _statements(db, monkeypatch)

    _view(client, case_id)

    # the case's status, the latest job, the run, the numbers now, the case's alerts, and the entries' titles
    assert len(statements) == 6, statements
    assert sum("knowledge_entries" in sql for sql in statements) == 1
    for sql in statements:
        assert sql.upper().startswith(("SELECT", "WITH")), sql


def test_knowledge_of_a_ranking_with_ids_that_are_no_entries_is_listed_without_titles(client, db):
    """An id that is not a UUID (a stored ranking's text) costs no statement; an id with no entry has no title."""
    case_id, *_ = _case_with_two_heads(db, client.user_id)
    gone = str(uuid.uuid4())
    lookup = _lookup(
        db, case_id, matches=[("not-a-uuid", 0.9)], ranked=[("not-a-uuid", 0.9), (gone, 0.8)]
    )
    _insert_run(db, case_id, job_id=_insert_job(db, case_id), result=_v4(), lookup_id=lookup)

    run = _view(client, case_id)["run"]

    assert run["knowledge"]["candidates"] == [
        {"pct": 90, "title": None, "conclusion": None},
        {"pct": 80, "title": None, "conclusion": None},
    ]


def test_a_run_that_stopped_has_no_knowledge(client, db):
    case_id, *_ = _case_with_two_heads(db, client.user_id)
    entry = _entry(db, "Một quy tắc")
    lookup = _lookup(db, case_id, matches=[(entry, 0.9)], ranked=[(entry, 0.9)])
    _insert_run(
        db,
        case_id,
        job_id=_insert_job(db, case_id),
        result=None,
        stopped_by="schema",
        lookup_id=lookup,
    )

    assert "knowledge" not in _view(client, case_id)["run"]


# ---------------------------------------------------------------------------
# The plan of the case's alerts read (B)
# ---------------------------------------------------------------------------

#: The statement as it was in the first version of this card: one `OR`ed `WHERE`, which no index can serve (a hashed
#: sub-plan on each side). Kept here to show the check below is live: it has a sequential scan of `alerts`.
_OR_FORM = """
    WITH members AS (
        SELECT alert_id, alert_time, agent_name, alert_user FROM alerts
        WHERE alert_id IN (SELECT alert_id FROM case_alerts WHERE case_id = %(case)s)
           OR duplicate_of IN (SELECT alert_id FROM case_alerts WHERE case_id = %(case)s)
    )
    SELECT (SELECT count(*) FROM members)
"""


def _plan_nodes(node):
    yield node
    for child in node.get("Plans", ()):
        yield from _plan_nodes(child)


def _scans(db, sql: str, params: dict) -> list[tuple[str, str | None, str | None]]:
    """`(node type, relation, index)` of every scan node in the plan of `sql`, with sequential scans switched off:
    on a table as small as the test database's, the planner would choose one whatever the statement says.
    """
    db.execute("SET LOCAL enable_seqscan = off")
    try:
        (plan,) = db.execute("EXPLAIN (FORMAT JSON) " + sql, params).fetchone()
    finally:
        db.execute("SET LOCAL enable_seqscan = on")
    return [
        (n["Node Type"], n.get("Relation Name"), n.get("Index Name"))
        for n in _plan_nodes(plan[0]["Plan"])
        if "Scan" in n["Node Type"]
    ]


_PARAMS = {"case": str(uuid.uuid4()), "cap": 100, "ids": ["a-1"]}


def test_the_or_form_reads_alerts_with_a_sequential_scan_so_the_plan_check_is_live(db):
    assert ("Seq Scan", "alerts", None) in _scans(db, _OR_FORM, _PARAMS)


def test_each_half_of_the_alerts_read_uses_its_own_index(db):
    scans = _scans(db, view._CASE_ALERTS_SQL, _PARAMS)

    assert not [s for s in scans if s[0] == "Seq Scan" and s[1] == "alerts"], scans
    # an index scan names its index and relation; a bitmap scan names the index on one node and the relation on the
    # heap scan above it: the indexes of the plan are those of every scan node
    indexes = {index for _kind, _relation, index in scans if index}
    assert {"alerts_pkey", "ix_alerts_duplicate_of"} <= indexes, scans
    assert not [s for s in scans if s[1] == "alerts" and s[0] in ("Seq Scan", "Sample Scan")], scans


def test_the_alerts_read_is_one_statement_of_two_union_all_halves():
    sql = " ".join(view._CASE_ALERTS_SQL.split())
    assert sql.count("UNION ALL") == 1
    assert sql.count("WITH members AS") == 1


def test_an_alert_that_is_a_head_and_a_duplicate_of_a_head_is_read_once(client, db):
    """The two halves must not read a row twice: the same rows as the `OR`ed form gave."""
    case_id = _make_case(db, client.user_id)
    h1 = _add_head(
        db, case_id, client.user_id, alert_time=T0, agent_name="host-a", alert_user="alice"
    )
    both = _add_head(
        db, case_id, client.user_id, alert_time=T0 + timedelta(minutes=5), agent_name="host-b"
    )
    db.execute("UPDATE alerts SET duplicate_of = %s WHERE alert_id = %s", (h1, both))
    _insert_run(
        db, case_id, job_id=_insert_job(db, case_id), result=_v4(timeline=_rows((both, "x")))
    )

    run = _view(client, case_id)["run"]

    assert run["scope"]["system"]["alert_count"] == 2
    assert [row["alert_id"] for row in run["timeline"]] == [both]
