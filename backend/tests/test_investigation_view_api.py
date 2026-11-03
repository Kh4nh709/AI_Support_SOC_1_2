"""tier2/investigation_view.py + `GET /api/tier2/cases/{id}/investigation` — the ② view as
JSON (P10-T03), the route the React case page (P10-T11) reads.

The view is the code that P5-T05's Jinja investigation page rendered from, moved into
`app.tier2.investigation_view` unchanged; the page retired in P10-T13 and this JSON is now
its only reader. So this file pins what the JSON carries — the five states, the evidence marks
and their reasons, the overrule sentence, the `stopped_by` sentences, the snapshot against the
current values (`test_the_json_contract_of_a_done_run` and
`test_every_stopped_by_code_has_its_sentence` are what remained of the page-versus-JSON
comparison once the page was gone).

Every run and job row is inserted directly — no test makes a model call. Two hazards, as the
retired page's tests had them:

* `require_role` commits its `authz.denied` row itself, before it raises; the 403 test spies
  `db.commit` and reads the row at that moment, so nothing is really committed.
* The route ends on `conn.rollback()`. `db` is one shared connection, so a real rollback
  would discard the rows a test seeded before its second request: the `client` fixture
  records `commit` / `rollback` (no-ops) and `test_the_route_is_read_only_...` reads that
  record.

No helper is imported from another test file (project convention): the ones below are this
file's own copies.
"""

from __future__ import annotations

import hashlib
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

pytestmark = pytest.mark.db

_PAST = datetime(2026, 1, 1, tzinfo=UTC)

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _make_user(conn, *, role: str = "tier2") -> str:
    user_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash) "
        "VALUES (%s, %s, %s, %s, 'x')",
        (user_id, f"user-{user_id[:8]}", "Test Analyst", role),
    )
    return user_id


def _make_case(conn, user_id: str, *, status: str = "investigating") -> str:
    case_id = str(uuid.uuid4())
    concluded = status != "investigating"
    conn.execute(
        "INSERT INTO cases (case_id, title, status, severity, created_by, concluded_at, "
        "concluded_by, conclusion_reason) VALUES (%s, 'case', %s, 'high', %s, %s, %s, %s)",
        (
            case_id,
            status,
            user_id,
            _PAST if concluded else None,
            user_id if concluded else None,
            "x" if concluded else None,
        ),
    )
    return case_id


def _insert_alert(
    conn,
    *,
    status: str = "escalated_tier2",
    raw_log: str = "",
    duplicate_of: str | None = None,
    case_id: str | None = None,
) -> str:
    alert_id = f"p10t03-{uuid.uuid4()}"
    closed = _PAST if status != "escalated_tier2" else None
    conn.execute(
        "INSERT INTO alerts (alert_id, rule_id, rule_level, severity, description, "
        "agent_name, alert_time, category, resolved_by, mapping_version, "
        "event_bucket_hash, raw_payload, raw_log, status, duplicate_of, case_id, closed_at, "
        "sealed_at) "
        "VALUES (%s, '40112', 10, 'high', 'SSH brute force', 'agent-1', now(), 'brute_force', "
        "'rule_groups', 'v1', %s, '{}'::jsonb, %s, %s, %s, %s, %s, %s)",
        (
            alert_id,
            hashlib.sha256(alert_id.encode()).hexdigest(),
            raw_log,
            status,
            duplicate_of,
            case_id,
            closed,
            closed if status == "duplicate" else None,
        ),
    )
    return alert_id


def _add_head(conn, case_id: str, added_by: str, **alert_kwargs) -> str:
    alert_id = _insert_alert(conn, case_id=case_id, **alert_kwargs)
    conn.execute(
        "INSERT INTO case_alerts (case_id, alert_id, added_by) VALUES (%s, %s, %s)",
        (case_id, alert_id, added_by),
    )
    return alert_id


def _insert_job(
    conn,
    case_id: str,
    status: str,
    *,
    attempts: int = 1,
    scheduled_ago: timedelta | None = None,
    locked_ago: timedelta | None = None,
    created_ago: timedelta | None = None,
) -> int:
    """`*_ago` place the timestamps relative to the database's `now()` (the view measures a
    job's age by the database clock too); left out, `scheduled_at` and `created_at` keep
    `now()` and `locked_at` stays NULL."""
    row = conn.execute(
        "INSERT INTO jobs (job_type, subject_id, status, attempts, scheduled_at, locked_at, "
        "created_at) VALUES ('investigate', %s, %s, %s, now() - COALESCE(%s, interval '0'), "
        "CASE WHEN %s::interval IS NULL THEN NULL ELSE now() - %s::interval END, "
        "now() - COALESCE(%s, interval '0')) RETURNING job_id",
        (case_id, status, attempts, scheduled_ago, locked_ago, locked_ago, created_ago),
    ).fetchone()
    return row[0]


def _result(**overrides) -> dict:
    body = {
        "summary": "SUMMARY-TEXT",
        "attack_narrative": "NARRATIVE-TEXT",
        "suggested_conclusion": "confirmed_incident",
        "confidence": "high",
        "gia_thuyet": [
            {
                "noi_dung": "HYPOTHESIS-TEXT",
                "evidence_for": ["FOR-TEXT"],
                "evidence_against": ["AGAINST-TEXT"],
            }
        ],
        "evidence": [],
        "next_steps": ["STEP-TEXT"],
        "playbook_used": None,
    }
    body.update(overrides)
    return body


def _insert_run(
    conn,
    case_id: str,
    *,
    job_id: int | None = None,
    run_id: uuid.UUID | None = None,
    result: dict | None = None,
    evidence_check: dict | None = None,
    stopped_by: str | None = None,
    agent_trace: dict | None = None,
    created_at: datetime | None = None,
) -> uuid.UUID:
    if run_id is None:
        run_id = tier2_investigate.run_id_for_job(job_id) if job_id is not None else uuid.uuid4()
    conn.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, role, "
        "system_prompt, user_message, agent_trace, result, evidence_check, stopped_by, "
        "created_at) VALUES (%s, 'investigate', 'case', %s, 'investigator', 's', 'u', "
        "%s, %s, %s, %s, COALESCE(%s::timestamptz, now()))",
        (
            run_id,
            case_id,
            Jsonb(agent_trace) if agent_trace is not None else None,
            Jsonb(result) if result is not None else None,
            Jsonb(evidence_check) if evidence_check is not None else None,
            stopped_by,
            created_at,
        ),
    )
    return run_id


class _Client:
    """`TestClient` plus the user/role the overridden auth dependency answers as."""

    def __init__(self, user_id: str, events: list[str]) -> None:
        self.http = TestClient(main.app, follow_redirects=False)
        self.user_id = user_id
        self.role = "tier2"
        self.events = events  # "commit" / "rollback", in the order the route made them

    def claims(self) -> Claims:
        return Claims(user_id=self.user_id, username=self.user_id, role=self.role, iat=0.0, exp=0.0)


@pytest.fixture
def client(db, monkeypatch):
    events: list[str] = []
    # No-ops that record: a real rollback would discard the rows seeded on this shared
    # connection, and a real commit would leave them in the shared database for good.
    monkeypatch.setattr(db, "commit", lambda: events.append("commit"))
    monkeypatch.setattr(db, "rollback", lambda: events.append("rollback"))

    user_id = _make_user(db)
    c = _Client(user_id, events)

    def get_conn():
        # deps.get_conn's real shape: rollback on any exception, no implicit commit.
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


def _get(client: _Client, case_id: str, **params):
    return client.http.get(f"/api/tier2/cases/{case_id}/investigation", params=params)


def _snapshot_case(db, user_id: str):
    """A case with one head and two duplicates absorbed into it: 3 alerts, 20 occurrences."""
    case_id = _make_case(db, user_id)
    head = _add_head(db, case_id, user_id)
    for _ in range(2):
        _insert_alert(db, status="duplicate", duplicate_of=head, case_id=case_id)
    # `ck_alerts_last_seen_khong_lui`: last_seen_at >= first_seen_at (= the insert's now())
    seen = datetime.now(UTC).replace(microsecond=0) + timedelta(hours=1)
    db.execute(
        "UPDATE alerts SET occurrence_count = 20, last_seen_at = %s WHERE alert_id = %s",
        (seen, head),
    )
    return case_id, seen


# ---------------------------------------------------------------------------
# The five states
# ---------------------------------------------------------------------------


def test_idle_case_has_state_idle_and_no_run(client, db):
    case_id = _make_case(db, client.user_id)

    resp = _get(client, case_id)

    assert resp.status_code == 200
    assert resp.json() == {
        "state": "idle",
        "run_id": None,
        "minutes": None,
        "run": None,
        "current": None,
        "case_open": True,
    }


def test_running_job_is_running_with_run_id(client, db):
    case_id = _make_case(db, client.user_id)
    job_id = _insert_job(db, case_id, "running", locked_ago=timedelta(minutes=1))

    body = _get(client, case_id).json()

    assert body["state"] == "running"
    assert body["run_id"] == str(tier2_investigate.run_id_for_job(job_id))
    assert body["minutes"] is None
    assert body["run"] is None and body["current"] is None


def test_stalled_job_reports_minutes(client, db):
    """`scheduled_at` older than 2 x `JOB_LOCK_TIMEOUT_S` (300 s by default): stalled, and
    the age in whole minutes is what the page says."""
    case_id = _make_case(db, client.user_id)
    job_id = _insert_job(db, case_id, "pending", scheduled_ago=timedelta(minutes=11))

    body = _get(client, case_id).json()

    assert body["state"] == "stalled"
    assert body["minutes"] == 11
    assert body["run_id"] == str(tier2_investigate.run_id_for_job(job_id))
    assert body["run"] is None and body["current"] is None


def test_a_job_pending_for_less_than_the_bound_is_running_not_stalled(client, db):
    """The other side of the stall rule: nine minutes is inside 2 x 300 s."""
    case_id = _make_case(db, client.user_id)
    _insert_job(db, case_id, "pending", scheduled_ago=timedelta(minutes=9))

    assert _get(client, case_id).json()["state"] == "running"


def test_a_running_job_hides_the_previous_result(client, db):
    case_id = _make_case(db, client.user_id)
    old_job = _insert_job(db, case_id, "succeeded")
    _insert_run(db, case_id, job_id=old_job, result=_result(summary="PREVIOUS"))
    _insert_job(db, case_id, "pending")

    body = _get(client, case_id).json()

    assert body["state"] == "running"
    assert body["run"] is None
    assert "PREVIOUS" not in repr(body)


def test_a_failed_job_without_a_row_is_failed_with_no_run(client, db):
    case_id = _make_case(db, client.user_id)
    _insert_job(db, case_id, "failed")

    body = _get(client, case_id).json()

    assert body["state"] == "failed"
    assert body["run"] is None and body["current"] is None


def test_a_run_id_nobody_has_heard_of_is_failed_not_idle(client, db):
    """The 202's `run_id` with nothing behind it (no job, no row) is the API's 404 — shown
    as a failure, never as an idle screen."""
    case_id = _make_case(db, client.user_id)

    body = _get(client, case_id, run_id=str(uuid.uuid4())).json()

    assert body["state"] == "failed"
    assert body["run"] is None


def test_a_malformed_run_id_is_a_422(client, db):
    case_id = _make_case(db, client.user_id)

    assert _get(client, case_id, run_id="not-a-uuid").status_code == 422


def test_a_run_without_a_result_says_why(client, db):
    case_id = _make_case(db, client.user_id)
    _insert_run(db, case_id, stopped_by="cap")

    body = _get(client, case_id).json()

    assert body["state"] == "done"
    assert set(body["run"]) == {"run_id", "created_at", "result", "stopped_text"}
    assert body["run"]["result"] is None
    assert body["run"]["stopped_text"] == "đã chạm hạn mức chi phí LLM"


# ---------------------------------------------------------------------------
# The done run: labels, evidence marks, the overrule sentence
# ---------------------------------------------------------------------------


def test_done_run_has_evidence_marks_and_labels(client, db):
    from app.tier2.investigation_view import REJECT_TEXT

    case_id = _make_case(db, client.user_id)
    parsed = _result(
        evidence=[
            {"alert_id": "a-1", "quote": "QUOTE-ONE-OK", "why": "w1"},
            {"alert_id": "a-2", "quote": "QUOTE-TWO-BAD", "why": "w2"},
        ]
    )
    check = {
        "verified": [0],
        "rejected": [{"index": 1, "alert_id": "a-2", "reason": "quote_not_found"}],
    }
    job_id = _insert_job(db, case_id, "succeeded")
    run_id = _insert_run(db, case_id, job_id=job_id, result=parsed, evidence_check=check)

    body = _get(client, case_id).json()

    assert body["state"] == "done"
    assert body["run_id"] is None  # a done state carries the run under `run`, as the page does
    run = body["run"]
    assert set(run) == {
        "run_id",
        "created_at",
        "result",
        "conclusion",
        "conclusion_label",
        "confidence",
        "summary",
        "narrative",
        "hypotheses",
        "evidence",
        "next_steps",
        "playbook_used",
        "overruled",
        "model_conclusion",  # P14-T02
        "held_by",  # P14-T02
        "snapshot",
        "changed",
    }
    assert run["run_id"] == str(run_id)
    assert run["conclusion"] == "confirmed_incident"
    assert run["conclusion_label"] == "Là sự cố thật"
    assert (run["confidence"], run["summary"], run["narrative"]) == (
        "high",
        "SUMMARY-TEXT",
        "NARRATIVE-TEXT",
    )
    assert run["hypotheses"] == [
        {
            "text": "HYPOTHESIS-TEXT",
            "evidence_for": ["FOR-TEXT"],
            "evidence_against": ["AGAINST-TEXT"],
        }
    ]
    assert run["next_steps"] == ["STEP-TEXT"]
    verified, unverified = run["evidence"]
    assert verified == {
        "alert_id": "a-1",
        "quote": "QUOTE-ONE-OK",
        "why": "w1",
        "verified": True,
        "reason_text": None,
    }
    assert unverified["verified"] is False
    assert unverified["reason_text"] == REJECT_TEXT["quote_not_found"]
    assert unverified["reason_text"] == "trích dẫn không có trong log hay mô tả của alert"
    assert run["overruled"] is None
    assert run["snapshot"] is None and run["changed"] is False
    assert body["current"] is None  # no snapshot recorded: nothing to compare with


def test_an_item_the_check_does_not_vouch_for_is_never_verified(client, db):
    """A mark is never assumed: no check, or an index that is a string or out of range, and
    nothing is verified — the reason is the "not cross-checked" text."""
    case_id = _make_case(db, client.user_id)
    parsed = _result(evidence=[{"alert_id": "a-1", "quote": "SOME-QUOTE-HERE", "why": "w"}])
    _insert_run(db, case_id, result=parsed, evidence_check={"verified": ["0", 7], "rejected": []})

    (item,) = _get(client, case_id).json()["run"]["evidence"]

    assert item["verified"] is False
    assert item["reason_text"] == "chưa được đối chiếu với log của alert"


def test_overruled_run_has_the_overrule_sentence(client, db):
    case_id = _make_case(db, client.user_id)
    check = {"verified": [], "rejected": [], "original_conclusion": "false_positive"}
    _insert_run(
        db, case_id, result=_result(suggested_conclusion="need_more_data"), evidence_check=check
    )

    run = _get(client, case_id).json()["run"]

    assert run["conclusion"] == "need_more_data"
    assert run["conclusion_label"] == "Cần thêm dữ liệu"
    assert run["overruled"] == (
        "Mô hình đề xuất Không phải sự cố (false_positive) nhưng kết luận đã bị hạ xuống "
        "Cần thêm dữ liệu (need_more_data): "
        "không có bằng chứng nào kiểm chứng được với log của case."
    )


def test_a_forced_overrule_names_the_rule_not_the_missing_evidence(client, db):
    case_id = _make_case(db, client.user_id)
    check = {
        "verified": [0],
        "rejected": [],
        "forced_by": "high_severity_injection_finding",
        "original_conclusion": "false_positive",
    }
    _insert_run(
        db, case_id, result=_result(suggested_conclusion="need_more_data"), evidence_check=check
    )

    overruled = _get(client, case_id).json()["run"]["overruled"]

    assert overruled.startswith(
        "Mô hình đề xuất Không phải sự cố (false_positive) nhưng kết luận đã bị hạ xuống "
        "Cần thêm dữ liệu (need_more_data): "
    )
    assert "tiêm lệnh" in overruled
    assert "không có bằng chứng nào" not in overruled


# ---------------------------------------------------------------------------
# P14-T02 (DEC-213): the model's own conclusion, and why the system held it
# ---------------------------------------------------------------------------


def test_a_run_nothing_overruled_shows_the_models_conclusion_and_no_hold(client, db):
    case_id = _make_case(db, client.user_id)
    check = {"verified": [0], "rejected": [], "model_conclusion": "policy_violation"}
    _insert_run(
        db, case_id, result=_result(suggested_conclusion="policy_violation"), evidence_check=check
    )

    run = _get(client, case_id).json()["run"]

    assert run["conclusion"] == "policy_violation"
    assert run["model_conclusion"] == "policy_violation"
    assert run["held_by"] == []
    assert run["overruled"] is None


def test_zero_verified_evidence_is_held_by_no_verified_evidence(client, db):
    case_id = _make_case(db, client.user_id)
    check = {
        "verified": [],
        "rejected": [],
        "model_conclusion": "confirmed_incident",
        "original_conclusion": "confirmed_incident",
    }
    _insert_run(
        db, case_id, result=_result(suggested_conclusion="need_more_data"), evidence_check=check
    )

    run = _get(client, case_id).json()["run"]

    assert run["conclusion"] == "need_more_data"  # the final one, as before
    assert run["model_conclusion"] == "confirmed_incident"  # what the model itself said
    assert run["held_by"] == ["no_verified_evidence"]


def test_a_high_injection_finding_with_a_false_positive_is_held_by_it(client, db):
    case_id = _make_case(db, client.user_id)
    check = {
        "verified": [0],
        "rejected": [],
        "forced_by": "high_severity_injection_finding",
        "model_conclusion": "false_positive",
        "original_conclusion": "false_positive",
    }
    _insert_run(
        db, case_id, result=_result(suggested_conclusion="need_more_data"), evidence_check=check
    )

    run = _get(client, case_id).json()["run"]

    assert run["model_conclusion"] == "false_positive"
    assert run["held_by"] == ["high_severity_injection_finding"]


def test_a_check_carrying_both_causes_lists_both_in_a_fixed_order(client, db):
    case_id = _make_case(db, client.user_id)
    check = {
        "verified": [],
        "rejected": [],
        "forced_by": "high_severity_injection_finding",
        "model_conclusion": "false_positive",
        "original_conclusion": "false_positive",
    }
    _insert_run(
        db, case_id, result=_result(suggested_conclusion="need_more_data"), evidence_check=check
    )

    run = _get(client, case_id).json()["run"]

    assert run["held_by"] == ["no_verified_evidence", "high_severity_injection_finding"]


def test_held_by_holds_only_the_two_closed_values(client, db):
    assert view.HELD_BY == ("no_verified_evidence", "high_severity_injection_finding")
    case_id = _make_case(db, client.user_id)
    check = {
        "verified": [0],
        "rejected": [],
        "forced_by": "some_future_rule",  # unknown to the view: never passed through as a cause
        "model_conclusion": "false_positive",
        "original_conclusion": "false_positive",
    }
    _insert_run(
        db, case_id, result=_result(suggested_conclusion="need_more_data"), evidence_check=check
    )

    run = _get(client, case_id).json()["run"]

    assert run["held_by"] == []


def test_an_old_run_without_a_model_conclusion_gives_none_and_no_hold_and_no_error(client, db):
    """A run written before P14-T02 has `original_conclusion` (when it was overruled) and no
    `model_conclusion`. The view answers `None` and `[]` for it - it does not guess - and still
    says the overrule sentence it always said."""
    case_id = _make_case(db, client.user_id)
    check = {"verified": [], "rejected": [], "original_conclusion": "false_positive"}
    _insert_run(
        db, case_id, result=_result(suggested_conclusion="need_more_data"), evidence_check=check
    )

    resp = _get(client, case_id)

    assert resp.status_code == 200
    run = resp.json()["run"]
    assert run["model_conclusion"] is None
    assert run["held_by"] == []
    assert run["overruled"] == (
        "Mô hình đề xuất Không phải sự cố (false_positive) nhưng kết luận đã bị hạ xuống "
        "Cần thêm dữ liệu (need_more_data): "
        "không có bằng chứng nào kiểm chứng được với log của case."
    )


@pytest.mark.parametrize("evidence_check", [None, [], "x", {}, {"verified": []}])
def test_a_run_with_no_usable_check_gives_none_and_no_hold(client, db, evidence_check):
    case_id = _make_case(db, client.user_id)
    _insert_run(db, case_id, result=_result(), evidence_check=evidence_check)

    run = _get(client, case_id).json()["run"]

    assert run["model_conclusion"] is None
    assert run["held_by"] == []


@pytest.mark.parametrize(
    "stored", [7, True, ["false_positive"], {"a": 1}, "", "true_positive", "need_more_data"]
)
def test_a_model_conclusion_outside_the_closed_vocabulary_is_not_passed_through(client, db, stored):
    case_id = _make_case(db, client.user_id)
    check = {"verified": [], "rejected": [], "model_conclusion": stored}
    _insert_run(
        db, case_id, result=_result(suggested_conclusion="need_more_data"), evidence_check=check
    )

    run = _get(client, case_id).json()["run"]

    assert run["model_conclusion"] is None
    assert run["held_by"] == []  # no valid model conclusion, no claim about holding it


def test_a_run_that_stopped_has_neither_field(client, db):
    case_id = _make_case(db, client.user_id)
    _insert_run(db, case_id, result=None, stopped_by="schema")

    run = _get(client, case_id).json()["run"]

    assert "model_conclusion" not in run and "held_by" not in run  # no result, no conclusion


def test_a_result_without_a_conclusion_is_labelled_unknown(client, db):
    """`llm_runs` only stores the four conclusions (`ck_llm_runs_suggested_conclusion`), so a
    value the label table lacks cannot be seeded; a result that carries none can. It is
    labelled, never dropped and never a 500 (Review Focus 5)."""
    case_id = _make_case(db, client.user_id)
    result = _result()
    del result["suggested_conclusion"]
    _insert_run(db, case_id, result=result)

    run = _get(client, case_id).json()["run"]

    assert run["conclusion"] is None
    assert run["conclusion_label"] == "Chưa rõ kết luận"


# ---------------------------------------------------------------------------
# The snapshot beside the current values
# ---------------------------------------------------------------------------


def test_changed_flag_when_heads_grew_since_the_snapshot(client, db):
    case_id, seen = _snapshot_case(db, client.user_id)
    unchanged = {"alert_count": 3, "total_occurrences": 20, "last_seen_at": seen.isoformat()}
    _insert_run(db, case_id, result=_result(), agent_trace=unchanged)

    body = _get(client, case_id).json()

    assert body["current"]["alert_count"] == 3
    assert body["current"]["total_occurrences"] == 20
    assert body["run"]["snapshot"]["alert_count"] == 3
    assert body["run"]["changed"] is False

    # The heads grew since the run recorded its snapshot: the run below records one alert
    # fewer and 8 occurrences fewer than the case now holds.
    other_case, other_seen = _snapshot_case(db, client.user_id)
    older = {"alert_count": 2, "total_occurrences": 12, "last_seen_at": other_seen.isoformat()}
    _insert_run(db, other_case, result=_result(), agent_trace=older)

    grown = _get(client, other_case).json()

    assert grown["run"]["snapshot"]["alert_count"] == 2
    assert grown["run"]["snapshot"]["total_occurrences"] == 12
    assert grown["current"]["alert_count"] == 3
    assert grown["current"]["total_occurrences"] == 20
    assert datetime.fromisoformat(grown["current"]["last_seen_at"]) == other_seen
    assert grown["run"]["changed"] is True


def test_a_run_without_a_recorded_snapshot_has_no_comparison(client, db):
    case_id, _ = _snapshot_case(db, client.user_id)
    _insert_run(db, case_id, result=_result(), agent_trace=None)

    body = _get(client, case_id).json()

    assert body["run"]["snapshot"] is None
    assert body["run"]["changed"] is False
    assert body["current"] is None


# ---------------------------------------------------------------------------
# case_open, unknown cases, access, and the transaction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "open_"),
    [
        ("investigating", True),
        ("concluded_fp", False),
        ("concluded_policy_violation", False),
        ("confirmed_incident", False),
        ("archived", False),  # INT-T03 / DEC-212: set aside by the archive, never active
    ],
)
def test_case_open_follows_the_case_status(client, db, status, open_):
    case_id = _make_case(db, client.user_id, status=status)
    _insert_run(db, case_id, result=_result())

    body = _get(client, case_id).json()

    assert body["case_open"] is open_
    assert body["state"] == "done"  # a concluded case still shows its last result


def test_unknown_case_is_404(client):
    resp = _get(client, str(uuid.uuid4()))

    assert resp.status_code == 404
    assert resp.json() == {"detail": "case not found"}
    assert "commit" not in client.events
    assert client.events[-1] == "rollback"


def test_tier1_gets_403(client, db, monkeypatch):
    """`require_role` commits `authz.denied` before it raises. The commit is spied (and the
    row read at that moment) so nothing really lands in the shared database."""
    client.role = "tier1"
    case_id = _make_case(db, client.user_id)
    seen: list[list[str]] = []

    def _spy_commit() -> None:
        rows = db.execute(
            "SELECT event_type FROM audit_events WHERE actor_id = %s ORDER BY audit_id",
            (client.user_id,),
        ).fetchall()
        seen.append([r[0] for r in rows])

    monkeypatch.setattr(db, "commit", _spy_commit)

    resp = _get(client, case_id)

    assert resp.status_code == 403
    assert seen == [["authz.denied"]]


def test_admin_is_allowed(client, db):
    client.role = "admin"
    case_id = _make_case(db, client.user_id)

    assert _get(client, case_id).status_code == 200


def test_the_route_is_read_only_and_ends_on_a_rollback(client, db, monkeypatch):
    """`get_conn` commits whatever a returned response left in the transaction, so a route
    that only reads must end on its own rollback — after the reads it answers from. The
    statement log makes "only reads" discriminating: every statement is a SELECT / WITH."""
    case_id, seen = _snapshot_case(db, client.user_id)
    _insert_run(
        db,
        case_id,
        result=_result(),
        agent_trace={"alert_count": 3, "total_occurrences": 20, "last_seen_at": seen.isoformat()},
    )
    _insert_job(db, case_id, "succeeded")
    statements: list[str] = []
    real_execute = db.execute

    def _spy_execute(query, *args, **kwargs):
        statements.append(str(query))
        return real_execute(query, *args, **kwargs)

    monkeypatch.setattr(db, "execute", _spy_execute)
    client.events.clear()

    resp = _get(client, case_id)

    assert resp.status_code == 200
    assert statements, "the route read nothing"
    for sql in statements:
        assert sql.lstrip().upper().startswith(("SELECT", "WITH")), sql
    assert "commit" not in client.events
    assert client.events[-1] == "rollback"


# ---------------------------------------------------------------------------
# The JSON contract — what the React case page (P10-T11) reads. The Jinja page that used to
# be compared with it (`test_json_and_html_agree`) retired in P10-T13; what that test pinned
# about the view itself is asserted here on the JSON alone.
# ---------------------------------------------------------------------------

_BODY_KEYS = {"state", "run_id", "minutes", "run", "current", "case_open"}
_DONE_RUN_KEYS = {
    "run_id",
    "created_at",
    "result",
    "conclusion",
    "conclusion_label",
    "confidence",
    "summary",
    "narrative",
    "hypotheses",
    "evidence",
    "next_steps",
    "playbook_used",
    "overruled",
    "model_conclusion",
    "held_by",
    "snapshot",
    "changed",
}


def test_the_json_contract_of_a_done_run(client, db):
    """`state`, `run_id`, the run's fields, the evidence marks and each rejected item's own
    reason text, the conclusion label, the summary and the overrule sentence — for one run
    whose evidence the writer's own `_check_evidence` marked."""
    case_id = _make_case(db, client.user_id)
    head = _add_head(db, case_id, client.user_id, raw_log="Failed password for root from 10.0.0.9")
    other = _make_case(db, client.user_id)
    foreign = _add_head(db, other, client.user_id, raw_log="unrelated log line of another case")
    evidence = [
        {"alert_id": head, "quote": "Failed password for root", "why": "WHY-VERIFIED"},
        {"alert_id": head, "quote": "this quote is not in the log", "why": "WHY-NOT-FOUND"},
        {"alert_id": head, "quote": "abc", "why": "WHY-TOO-SHORT"},
        {"alert_id": foreign, "quote": "unrelated log line of another case", "why": "WHY-FOREIGN"},
    ]
    # The check is the writer's own function, so a shape change on the T04 side turns this red.
    parsed = _result(evidence=evidence, suggested_conclusion="need_more_data")
    check = tier2_investigate._check_evidence(db, case_id, parsed)
    check["original_conclusion"] = "false_positive"
    job_id = _insert_job(db, case_id, "succeeded")
    run_id = _insert_run(db, case_id, job_id=job_id, result=parsed, evidence_check=check)

    resp = _get(client, case_id)

    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == _BODY_KEYS
    assert body["state"] == "done"
    assert body["run_id"] is None  # `run_id` is the live job's; a finished run carries its own
    assert body["minutes"] is None
    assert body["case_open"] is True
    run = body["run"]
    assert set(run) == _DONE_RUN_KEYS
    assert run["run_id"] == str(run_id)
    assert run["result"] == parsed
    assert run["conclusion"] == "need_more_data"
    assert run["conclusion_label"] == view.CONCLUSION_LABELS["need_more_data"]
    assert run["summary"] == "SUMMARY-TEXT"
    assert run["narrative"] == "NARRATIVE-TEXT"
    # this check carries no `model_conclusion` (a run from before P14-T02): both are empty, no error
    assert run["model_conclusion"] is None
    assert run["held_by"] == []

    items = run["evidence"]
    assert [i["verified"] for i in items] == [True, False, False, False]
    assert [i["why"] for i in items] == [
        "WHY-VERIFIED",
        "WHY-NOT-FOUND",
        "WHY-TOO-SHORT",
        "WHY-FOREIGN",
    ]
    # not_found, too_short and not_in_case each say their own reason; a verified item says none.
    assert [i["reason_text"] for i in items] == [
        None,
        view.REJECT_TEXT["quote_not_found"],
        view.REJECT_TEXT["quote_too_short"],
        view.REJECT_TEXT["not_in_case"],
    ]
    # The overrule sentence names both conclusions (label and code) and the cause.
    overruled = run["overruled"]
    assert overruled == view.overrule_text(parsed, check)
    assert view.labelled("false_positive") in overruled
    assert view.labelled("need_more_data") in overruled
    assert view.OVERRULE_NO_EVIDENCE in overruled


@pytest.mark.parametrize(
    ("stopped_by", "sentence"),
    [(code, text) for code, text in view.STOPPED_TEXT.items()]
    + [
        ("<b>weird</b>", "dừng ở bước <b>weird</b>"),  # unknown: its raw code, never dropped
        (None, "không rõ lý do"),
    ],
)
def test_every_stopped_by_code_has_its_sentence(client, db, stopped_by, sentence):
    """A run without a result says why in `run.stopped_text`: `STOPPED_TEXT`'s sentence for
    each of P5-T04's five codes, the raw code for one the view has no words for (verbatim: the
    JSON is data, the React page renders it as text), and a fixed sentence for none at all."""
    case_id = _make_case(db, client.user_id)
    job_id = _insert_job(db, case_id, "failed" if stopped_by == "transient" else "succeeded")
    _insert_run(db, case_id, job_id=job_id, stopped_by=stopped_by)

    body = _get(client, case_id).json()

    assert body["state"] == "done"
    assert set(body["run"]) == {"run_id", "created_at", "result", "stopped_text"}
    assert body["run"]["result"] is None
    assert body["run"]["stopped_text"] == sentence
    assert set(view.STOPPED_TEXT) == {"cap", "permanent", "linter", "schema", "transient"}


def test_a_permanent_stop_is_worded_as_the_providers_or_the_models_refusal():
    """INT-T02 / DEC-211 R6: a provider 402 is `permanent` for ② (R4, `LLMUnavailable` is an
    `LLMPermanent`), so the sentence may not read as the model alone refusing. The React page shows
    this text as the server sends it, and `strings.test.ts` holds `S.ai2.stoppedBy` equal to it."""
    sentence = view.STOPPED_TEXT["permanent"]
    assert sentence == (
        "nhà cung cấp hoặc mô hình từ chối yêu cầu (ví dụ hết số dư, 402), không thử lại"
    )
    assert view.stopped_text("permanent") == sentence
    assert "lỗi không thể thử lại" not in sentence
    # the other four are what they were
    assert view.STOPPED_TEXT["cap"] == "đã chạm hạn mức chi phí LLM"
    assert view.STOPPED_TEXT["transient"] == "mô hình không phản hồi sau nhiều lần thử"


# ---------------------------------------------------------------------------
# The view's own rules, kept from the retired page's tests (P10-T13)
#
# `test_pages_investigation.py` pinned these through the HTML page. The rules live in
# `derive_view` / `build_investigation`, which the JSON route returns unchanged, so each one is
# asserted here on the JSON the React page reads.
# ---------------------------------------------------------------------------


def test_a_transient_attempt_row_between_attempts_is_not_a_result(client, db):
    """A non-final failed attempt writes `stopped_by='transient'` under an attempt-scoped id
    while the job is still live. It is not an outcome: the view stays `running` and shows
    nothing of it."""
    case_id = _make_case(db, client.user_id)
    job_id = _insert_job(db, case_id, "pending", attempts=1)
    _insert_run(
        db,
        case_id,
        run_id=tier2_investigate.attempt_run_id(job_id, 1),
        stopped_by="transient",
    )

    body = _get(client, case_id).json()

    assert body["state"] == "running"
    assert body["run_id"] == str(tier2_investigate.run_id_for_job(job_id))
    assert body["run"] is None


@pytest.mark.parametrize(
    ("minutes", "state"),
    [(1, "running"), (9, "running"), (11, "stalled"), (25, "stalled")],
)
def test_a_pending_job_is_stalled_only_past_twice_the_lock_timeout(client, db, minutes, state):
    """`JOB_LOCK_TIMEOUT_S` is 300 in the fixture's config: the bound is 2 x 300 s = 10 minutes,
    and a stall reports the job's actual age, not the bound."""
    case_id = _make_case(db, client.user_id)
    _insert_job(db, case_id, "pending", scheduled_ago=timedelta(minutes=minutes))

    body = _get(client, case_id).json()

    assert body["state"] == state
    assert body["minutes"] == (minutes if state == "stalled" else None)


def test_a_running_job_locked_eleven_minutes_ago_is_stalled(client, db):
    case_id = _make_case(db, client.user_id)
    job_id = _insert_job(
        db,
        case_id,
        "running",
        scheduled_ago=timedelta(minutes=12),
        locked_ago=timedelta(minutes=11),
    )

    body = _get(client, case_id).json()

    assert body["state"] == "stalled"
    assert body["minutes"] == 11  # from the lock, not from the 12 minutes it was scheduled
    assert body["run_id"] == str(tier2_investigate.run_id_for_job(job_id))


def test_a_running_job_is_measured_from_its_lock_not_from_how_long_it_queued(client, db):
    """It waited 30 minutes in the queue but a worker locked it a minute ago: it is running."""
    case_id = _make_case(db, client.user_id)
    _insert_job(
        db,
        case_id,
        "running",
        scheduled_ago=timedelta(minutes=30),
        locked_ago=timedelta(minutes=1),
    )

    assert _get(client, case_id).json()["state"] == "running"


def test_a_pending_job_is_measured_from_scheduled_at_not_created_at(client, db):
    """A retry's backoff moves `scheduled_at`: created an hour ago, due only now, is not
    stalled. The same job scheduled into the future (a backoff still counting down) is not
    stalled either."""
    case_id = _make_case(db, client.user_id)
    _insert_job(db, case_id, "pending", created_ago=timedelta(hours=1))
    assert _get(client, case_id).json()["state"] == "running"

    other = _make_case(db, client.user_id)
    _insert_job(db, other, "pending", scheduled_ago=timedelta(minutes=-5))
    assert _get(client, other).json()["state"] == "running"


def test_the_stall_bound_follows_job_lock_timeout_s(client, db):
    """Nothing is hard-coded to ten minutes: with a 60 s lock timeout, three minutes is a
    stall."""
    case_id = _make_case(db, client.user_id)
    _insert_job(db, case_id, "pending", scheduled_ago=timedelta(minutes=3))
    assert _get(client, case_id).json()["state"] == "running"  # 180 s < 2 x 300 s

    main.app.dependency_overrides[deps.get_config] = lambda: config.Config(
        ANALYZE_QUOTA_PER_USER_DAY=2, JOB_LOCK_TIMEOUT_S=60
    )

    body = _get(client, case_id).json()
    assert body["state"] == "stalled"  # 180 s > 2 x 60 s
    assert body["minutes"] == 3


def test_a_stalled_job_that_did_write_its_row_is_done(client, db):
    """The final row wins over the job's age, as it does over a live job's status."""
    case_id = _make_case(db, client.user_id)
    job_id = _insert_job(db, case_id, "pending", scheduled_ago=timedelta(minutes=30))
    _insert_run(db, case_id, job_id=job_id, result=_result(summary="LATE-BUT-HERE"))

    body = _get(client, case_id).json()

    assert body["state"] == "done"
    assert body["run"]["summary"] == "LATE-BUT-HERE"
    assert body["minutes"] is None


def test_a_stalled_job_hides_the_previous_result_like_a_running_one(client, db):
    case_id = _make_case(db, client.user_id)
    old_job = _insert_job(db, case_id, "succeeded")
    _insert_run(db, case_id, job_id=old_job, result=_result(summary="PREVIOUS"), created_at=_PAST)
    _insert_job(db, case_id, "pending", scheduled_ago=timedelta(minutes=11))

    body = _get(client, case_id).json()

    assert body["state"] == "stalled"
    assert body["run"] is None and body["current"] is None
    assert "PREVIOUS" not in repr(body)


def test_the_recheck_gets_the_live_state_once_the_worker_has_finished(client, db):
    """The React page's "Kiểm tra lại" is the same GET: once the job has finished the answer is
    the result."""
    case_id = _make_case(db, client.user_id)
    job_id = _insert_job(db, case_id, "pending", scheduled_ago=timedelta(minutes=11))
    run_id = str(tier2_investigate.run_id_for_job(job_id))
    assert _get(client, case_id, run_id=run_id).json()["state"] == "stalled"

    _insert_run(db, case_id, job_id=job_id, result=_result(summary="FINISHED-AFTER-ALL"))
    db.execute("UPDATE jobs SET status = 'succeeded' WHERE job_id = %s", (job_id,))
    body = _get(client, case_id, run_id=run_id).json()

    assert body["state"] == "done"
    assert body["run"]["summary"] == "FINISHED-AFTER-ALL"


def test_the_newest_job_wins_and_older_runs_stay_out_of_the_way(client, db):
    case_id = _make_case(db, client.user_id)
    older = _insert_job(db, case_id, "succeeded")
    _insert_run(
        db, case_id, job_id=older, result=_result(summary="OLDER-SUMMARY"), created_at=_PAST
    )
    newer = _insert_job(db, case_id, "succeeded")
    _insert_run(db, case_id, job_id=newer, result=_result(summary="NEWER-SUMMARY"))

    body = _get(client, case_id).json()

    assert body["run"]["summary"] == "NEWER-SUMMARY"
    assert "OLDER-SUMMARY" not in repr(body)


def test_a_run_of_another_case_is_never_shown(client, db):
    """The request itself names case B's run (`?run_id=<B's run>`) on case A's view, and
    nothing of B comes back — not its text, not its run id. The hint is not a lookup key: with
    nothing of A's own behind it the answer is `failed`, as for any `run_id` this case has no
    trace of."""
    case_a = _make_case(db, client.user_id)
    case_b = _make_case(db, client.user_id)
    job_b = _insert_job(db, case_b, "succeeded")
    run_b = _insert_run(
        db,
        case_b,
        job_id=job_b,
        result=_result(summary="CASE-B-SUMMARY", attack_narrative="CASE-B-NARRATIVE"),
        agent_trace={"alert_count": 77, "total_occurrences": 777},
    )

    resp = _get(client, case_a, run_id=str(run_b))

    assert resp.status_code == 200
    body = resp.json()
    assert body["state"] == "failed"
    assert body["run"] is None and body["current"] is None
    for b_only in ("CASE-B-SUMMARY", "CASE-B-NARRATIVE", str(run_b)):
        assert b_only not in resp.text


def test_a_run_of_another_case_never_replaces_this_cases_own_result(client, db):
    case_a = _make_case(db, client.user_id)
    case_b = _make_case(db, client.user_id)
    job_a = _insert_job(db, case_a, "succeeded")
    _insert_run(db, case_a, job_id=job_a, result=_result(summary="CASE-A-SUMMARY"))
    job_b = _insert_job(db, case_b, "succeeded")
    run_b = _insert_run(db, case_b, job_id=job_b, result=_result(summary="CASE-B-SUMMARY"))

    resp = _get(client, case_a, run_id=str(run_b))

    assert resp.json()["run"]["summary"] == "CASE-A-SUMMARY"
    assert "CASE-B-SUMMARY" not in resp.text and str(run_b) not in resp.text


def test_without_any_job_the_latest_final_row_is_shown(client, db):
    """No `jobs` row left (a purged queue, an old run): the newest row that is not a transient
    attempt is the answer."""
    case_id = _make_case(db, client.user_id)
    _insert_run(db, case_id, result=_result(summary="OLD-RUN"), created_at=_PAST)
    _insert_run(
        db, case_id, result=_result(summary="NEW-RUN"), created_at=_PAST + timedelta(days=1)
    )
    _insert_run(db, case_id, stopped_by="transient", created_at=_PAST + timedelta(days=2))

    body = _get(client, case_id).json()

    assert body["state"] == "done"
    assert body["run"]["summary"] == "NEW-RUN"


def test_the_failed_state_keeps_the_previous_good_result_and_ignores_attempt_rows(client, db):
    case_id = _make_case(db, client.user_id)
    good = _insert_job(db, case_id, "succeeded")
    _insert_run(db, case_id, job_id=good, result=_result(summary="LAST-GOOD"), created_at=_PAST)
    bad = _insert_job(db, case_id, "failed", attempts=3)
    _insert_run(
        db,
        case_id,
        run_id=tier2_investigate.attempt_run_id(bad, 1),
        stopped_by="transient",
        created_at=_PAST + timedelta(days=1),
    )

    body = _get(client, case_id).json()

    assert body["state"] == "failed"
    assert body["run"]["summary"] == "LAST-GOOD"
    assert body["run"]["result"] is not None  # the attempt row is not an outcome


@pytest.mark.parametrize(
    "status", ["concluded_fp", "concluded_policy_violation", "confirmed_incident"]
)
def test_a_concluded_case_is_closed_and_still_shows_the_last_result(client, db, status):
    case_id = _make_case(db, client.user_id, status=status)
    job_id = _insert_job(db, case_id, "succeeded")
    _insert_run(db, case_id, job_id=job_id, result=_result(summary="BEFORE-CONCLUSION"))

    body = _get(client, case_id).json()

    assert body["case_open"] is False
    assert body["state"] == "done"
    assert body["run"]["summary"] == "BEFORE-CONCLUSION"


def test_a_failed_job_on_a_concluded_case_is_failed_and_closed(client, db):
    case_id = _make_case(db, client.user_id, status="concluded_fp")
    _insert_job(db, case_id, "failed", attempts=3)

    body = _get(client, case_id).json()

    assert body["state"] == "failed"
    assert body["case_open"] is False


def test_a_concluded_case_without_a_result_is_idle_and_closed(client, db):
    case_id = _make_case(db, client.user_id, status="concluded_fp")

    body = _get(client, case_id).json()

    assert body["state"] == "idle" and body["run"] is None
    assert body["case_open"] is False


# ---------------------------------------------------------------------------
# Rules the deleted page tests pinned that no JSON test did (P10-T13, fix round 1)
#
# Each was found by an in-memory mutant of `investigation_view.py` that every other test here
# survived; each test below is red against its mutant (see the card report).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("check", [None, {}], ids=["no-check-row", "empty-check"])
def test_without_an_evidence_check_nothing_is_presented_as_verified(client, db, check):
    """`evidence_check` is NULL (or an empty object): the writer vouched for nothing, so no item
    is `verified` and each says it was not cross-checked — a mark is never assumed."""
    case_id = _make_case(db, client.user_id)
    parsed = _result(
        evidence=[
            {"alert_id": "a-1", "quote": "SOME-QUOTE-HERE", "why": "w1"},
            {"alert_id": "a-2", "quote": "OTHER-QUOTE-HERE", "why": "w2"},
        ]
    )
    _insert_run(db, case_id, result=parsed, evidence_check=check)

    items = _get(client, case_id).json()["run"]["evidence"]

    assert [i["verified"] for i in items] == [False, False]
    assert [i["reason_text"] for i in items] == [view.REJECT_TEXT_UNKNOWN] * 2


@pytest.mark.parametrize(
    ("original", "shown"),
    [
        ("<script>alert(1)</script>", "<script>alert(1)</script>"),
        ("some_future_code", "some_future_code"),
        (42, "42"),
    ],
    ids=["markup", "future-code", "not-a-string"],
)
def test_an_unknown_overruled_code_stays_verbatim_in_the_overrule_sentence(
    client, db, original, shown
):
    """The label lookup has no entry for it, and the sentence still says what the model
    proposed — the raw value, as data (the React page renders it as text). The known
    conclusion it was lowered to keeps its label."""
    case_id = _make_case(db, client.user_id)
    check = {"verified": [], "rejected": [], "original_conclusion": original}
    _insert_run(
        db, case_id, result=_result(suggested_conclusion="need_more_data"), evidence_check=check
    )

    overruled = _get(client, case_id).json()["run"]["overruled"]

    assert f"Mô hình đề xuất {shown} nhưng" in overruled
    assert "Cần thêm dữ liệu (need_more_data)" in overruled
    assert view.OVERRULE_NO_EVIDENCE in overruled


@pytest.mark.parametrize(
    ("hypothesis", "against"),
    [
        ({"noi_dung": "H"}, []),  # key missing
        ({"noi_dung": "H", "evidence_against": "x"}, []),  # a string, not a list
        ({"noi_dung": "H", "evidence_against": None}, []),
        ({"noi_dung": "H", "evidence_against": []}, []),  # the model skipped it
        ({"noi_dung": "H", "evidence_against": ["A1", "A2"]}, ["A1", "A2"]),
    ],
    ids=["missing", "string", "null", "empty", "given"],
)
def test_a_missing_or_malformed_evidence_against_is_an_empty_list(client, db, hypothesis, against):
    """The React page flags an empty `evidence_against` ("không nêu bằng chứng phản bác") and
    maps over it: the JSON always carries a list, never the raw value the model wrote."""
    case_id = _make_case(db, client.user_id)
    _insert_run(db, case_id, result=_result(gia_thuyet=[hypothesis]))

    (hypothesis_out,) = _get(client, case_id).json()["run"]["hypotheses"]

    assert hypothesis_out["evidence_against"] == against
    assert isinstance(hypothesis_out["evidence_for"], list)


def test_only_the_hypothesis_that_skipped_its_counter_argument_has_an_empty_list(client, db):
    case_id = _make_case(db, client.user_id)
    _insert_run(
        db,
        case_id,
        result=_result(
            gia_thuyet=[
                {"noi_dung": "H-WITHOUT", "evidence_for": ["F1"], "evidence_against": []},
                {"noi_dung": "H-WITH", "evidence_for": ["F2"], "evidence_against": ["A2"]},
            ]
        ),
    )

    hypotheses = _get(client, case_id).json()["run"]["hypotheses"]

    assert [(h["text"], h["evidence_against"]) for h in hypotheses] == [
        ("H-WITHOUT", []),
        ("H-WITH", ["A2"]),
    ]
