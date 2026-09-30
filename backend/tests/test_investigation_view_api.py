"""tier2/investigation_view.py + `GET /api/tier2/cases/{id}/investigation` — the ② view as
JSON (P10-T03), the route the React case page (P10-T11) reads.

The view is the one `GET /cases/{id}/investigation` (the Jinja page, P5-T05) renders from:
the code moved out of `web/routers/case_analyze_pages.py` into `app.tier2.investigation_view`
unchanged, so this file pins what the JSON carries — the five states, the evidence marks and
their reasons, the overrule sentence, the snapshot against the current values — and that the
page and the JSON say the same thing (`test_json_and_html_agree`; the page retires with the
Jinja UI in P10-T13, which converts or deletes that one test).

Every run and job row is inserted directly — no test makes a model call. Two hazards, as in
`test_pages_investigation.py`:

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
import html
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.infra import config
from app.infra.auth import Claims
from app.tier2 import investigate as tier2_investigate
from app.web import deps, main
from app.web.routers import pages
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
    scheduled_ago: timedelta | None = None,
    locked_ago: timedelta | None = None,
) -> int:
    """`*_ago` place the timestamps relative to the database's `now()` (the view measures a
    job's age by the database clock too)."""
    row = conn.execute(
        "INSERT INTO jobs (job_type, subject_id, status, attempts, scheduled_at, locked_at) "
        "VALUES ('investigate', %s, %s, 1, now() - COALESCE(%s, interval '0'), "
        "CASE WHEN %s::interval IS NULL THEN NULL ELSE now() - %s::interval END) "
        "RETURNING job_id",
        (case_id, status, scheduled_ago, locked_ago, locked_ago),
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
    result: dict | None = None,
    evidence_check: dict | None = None,
    stopped_by: str | None = None,
    agent_trace: dict | None = None,
) -> uuid.UUID:
    run_id = tier2_investigate.run_id_for_job(job_id) if job_id is not None else uuid.uuid4()
    conn.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, role, "
        "system_prompt, user_message, agent_trace, result, evidence_check, stopped_by) "
        "VALUES (%s, 'investigate', 'case', %s, 'investigator', 's', 'u', %s, %s, %s, %s)",
        (
            run_id,
            case_id,
            Jsonb(agent_trace) if agent_trace is not None else None,
            Jsonb(result) if result is not None else None,
            Jsonb(evidence_check) if evidence_check is not None else None,
            stopped_by,
        ),
    )
    return run_id


class _Client:
    """`TestClient` plus the user/role the overridden auth dependencies answer as.
    `pages.page_user` is overridden too: the Jinja page `test_json_and_html_agree` reads
    calls it inside its own body rather than through `Depends(current_user)`."""

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
    main.app.dependency_overrides[pages.page_user] = c.claims
    try:
        yield c
    finally:
        for dep in (deps.get_conn, deps.get_config, deps.current_user, pages.page_user):
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
# One view, two renderings
# ---------------------------------------------------------------------------


def test_json_and_html_agree(client, db):
    """The JSON `run.evidence` and the Jinja page (`GET /cases/{id}/investigation`, retired
    by P10-T13, which converts or deletes this test) are built by the same function: every
    `reason_text` the JSON carries is on the page, the verified count is the same, and the
    conclusion label, summary and overrule sentence are too."""
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
    _insert_run(db, case_id, job_id=job_id, result=parsed, evidence_check=check)

    body = _get(client, case_id).json()
    page = client.http.get(f"/cases/{case_id}/investigation", headers={"HX-Request": "true"})

    assert page.status_code == 200
    items = body["run"]["evidence"]
    assert [i["verified"] for i in items] == [True, False, False, False]
    reasons = [i["reason_text"] for i in items if not i["verified"]]
    assert len(set(reasons)) == 3  # not_found, too_short and not_in_case each say their own
    for reason in reasons:
        assert html.escape(reason) in page.text
    assert page.text.count('data-verified="true"') == 1
    assert page.text.count('data-verified="false"') == 3
    assert html.escape(body["run"]["conclusion_label"]) in page.text
    assert html.escape(body["run"]["summary"]) in page.text
    assert html.escape(body["run"]["overruled"]) in page.text
