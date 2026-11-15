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
import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.infra import config
from app.infra.auth import Claims
from app.tier2 import investigate as tier2_investigate
from app.tier2 import investigation_view as view
from app.web import deps, main
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from tests.fakes.llm import INVESTIGATE_V3_OK, INVESTIGATE_V4_OK

pytestmark = pytest.mark.db

_PAST = datetime(2026, 1, 1, tzinfo=UTC)
T0 = datetime(2026, 11, 15, 8, 0, tzinfo=UTC)

#: A model id no real answer, log or title holds: if it shows anywhere in what is served, the model's name is served.
MODEL_ID = "zz-distinctive-model-id-GLM-9.9-xq7"


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
) -> uuid.UUID:
    run_id = tier2_investigate.run_id_for_job(job_id) if job_id is not None else uuid.uuid4()
    conn.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, role, system_prompt, user_message, "
        "agent_trace, result, evidence_check, stopped_by, model_id, input_tokens, output_tokens, latency_ms, "
        "cost_usd) VALUES (%s, 'investigate', 'case', %s, 'investigator', 's', 'u', %s, %s, %s, %s, %s, %s, %s, "
        "%s, %s)",
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
        ),
    )
    return run_id


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
    main.app.dependency_overrides[deps.get_config] = lambda: config.Config()
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
    assert set(run["timeline"][0]) == {"alert_id", "time", "what", "tactic", "technique"}
    assert (
        run["timeline"][0]["tactic"] == "Execution" and run["timeline"][0]["technique"] == "T1059"
    )


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
