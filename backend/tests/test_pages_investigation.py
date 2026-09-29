"""web/routers/case_analyze_pages.py + templates/_investigation.html — the ② half of
the case screen (P5-T05, DEC-151 wave 4): `POST /cases/{id}/analyze` (the *Phân tích*
button), `GET /cases/{id}/investigation` (the "đang phân tích…" polling partial and the
result block, with verified / unverified evidence marks).

Every run row here is inserted directly, or built by `tier2.investigate._check_evidence`
(the writer's own function, so a shape change on the T04 side turns the contract test red
instead of leaving this file's hand-typed JSON green) — no test makes a model call.

Two hazards this file is built around, both from earlier cards:

* `require_role` commits its `authz.denied` row itself, before it raises. The 403 tests
  spy `db.commit` and read the row at the moment of the call, so nothing is ever really
  committed into the shared session database.
* A returned non-2xx response is a "success" to `get_conn`, which would commit whatever
  the handler read. `test_a_refused_post_ends_with_a_rollback_and_never_commits` records
  the order of `execute` / `commit` / `rollback` on the shared connection and asserts the
  LAST event of a refused POST is the rollback — `api_analyze` rolls back before it raises,
  so a bare "a rollback happened" check would pass even if this module forgot its own.

`db.commit` / `db.rollback` are spied (no-ops) wherever a route may call them: the real
`rollback` would discard the rows the test just inserted on the shared connection.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

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
_TEMPLATE = (
    Path(__file__).resolve().parents[1] / "app" / "web" / "templates" / "_investigation.html"
)
_ROUTER = Path(__file__).resolve().parents[1] / "app" / "web" / "routers" / "case_analyze_pages.py"

_HTMX = {"HX-Request": "true"}
_SCRIPT = "<script>alert('pwn')</script>"
_IMG = '"><img src=x onerror=alert(1)>'

# ---------------------------------------------------------------------------
# Fixture helpers — this file's own copies (project convention: no test file imports
# helpers from another).
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
    description: str = "SSH brute force",
    duplicate_of: str | None = None,
    case_id: str | None = None,
) -> str:
    alert_id = f"p5t05-{uuid.uuid4()}"
    closed = _PAST if status != "escalated_tier2" else None
    conn.execute(
        "INSERT INTO alerts (alert_id, rule_id, rule_level, severity, description, "
        "agent_name, alert_time, category, resolved_by, mapping_version, "
        "event_bucket_hash, raw_payload, raw_log, status, duplicate_of, case_id, closed_at, "
        "sealed_at) "
        "VALUES (%s, '40112', 10, 'high', %s, 'agent-1', now(), 'brute_force', "
        "'rule_groups', 'v1', %s, '{}'::jsonb, %s, %s, %s, %s, %s, %s)",
        (
            alert_id,
            description,
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


def _insert_job(conn, case_id: str, status: str, *, attempts: int = 1) -> int:
    row = conn.execute(
        "INSERT INTO jobs (job_type, subject_id, status, attempts) "
        "VALUES ('investigate', %s, %s, %s) RETURNING job_id",
        (case_id, status, attempts),
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
    """`TestClient` plus the role the overridden auth dependencies answer as.
    `page_user` calls `optional_user` inside its own body rather than going through
    `Depends(current_user)`, so both `deps.current_user` (for `require_role`) and
    `pages.page_user` (the page's redirect-or-continue) are overridden — the shape
    `test_pages_cases.py` uses."""

    def __init__(self, user_id: str) -> None:
        self.http = TestClient(main.app, follow_redirects=False)
        self.user_id = user_id
        self.role = "tier2"

    def claims(self) -> Claims:
        return Claims(user_id=self.user_id, username=self.user_id, role=self.role, iat=0.0, exp=0.0)


@pytest.fixture
def client(db):
    user_id = _make_user(db)
    c = _Client(user_id)

    def get_conn():
        # deps.get_conn's real shape: rollback on any exception, no implicit commit.
        try:
            yield db
        except BaseException:
            db.rollback()
            raise

    main.app.dependency_overrides[deps.get_conn] = get_conn
    main.app.dependency_overrides[deps.get_config] = lambda: config.Config(
        ANALYZE_QUOTA_PER_USER_DAY=2
    )
    main.app.dependency_overrides[deps.current_user] = c.claims
    main.app.dependency_overrides[pages.page_user] = c.claims
    try:
        yield c
    finally:
        for dep in (deps.get_conn, deps.get_config, deps.current_user, pages.page_user):
            main.app.dependency_overrides.pop(dep, None)


def _get(client: _Client, case_id: str, **params):
    return client.http.get(f"/cases/{case_id}/investigation", params=params, headers=_HTMX)


def _post(client: _Client, case_id: str):
    return client.http.post(f"/cases/{case_id}/analyze", headers=_HTMX)


def _fields(html: str, name: str) -> list[str]:
    """The text of every element carrying `data-field="<name>"` (first closing tag)."""
    return [m.strip() for m in re.findall(rf'data-field="{name}"[^>]*>(.*?)</', html, re.DOTALL)]


def _evidence_items(html: str) -> list[str]:
    """One chunk of HTML per evidence `<li>` (they never nest another `<li>`)."""
    return [c.split("</li>")[0] for c in html.split('<li data-field="evidence"')[1:]]


def _has_button(html: str) -> bool:
    return 'data-field="analyze_button"' in html


def _polls(html: str) -> bool:
    return "every 3s" in html


# ---------------------------------------------------------------------------
# The seam and the routes' existence
# ---------------------------------------------------------------------------


def test_openapi_lists_both_routes():
    paths = sorted(main.app.openapi()["paths"])  # never app.routes (FastAPI 0.141 routing)
    assert "/cases/{case_id}/analyze" in paths
    assert "/cases/{case_id}/investigation" in paths


def test_case_page_renders_the_partial_when_present(client, db):
    """The seam, from this side (the card's name for it): `case.html` includes
    `_investigation.html` with no run data (P5-T07 owns the page and passes no
    investigation), so the included partial is a shell that fetches the real state on
    load. P5-T07 owns the mirror test, that the page renders without the partial."""
    case_id = _make_case(db, client.user_id)

    resp = client.http.get(f"/cases/{case_id}")

    assert resp.status_code == 200
    assert resp.text.count('id="investigation"') == 1
    assert f'hx-get="/cases/{case_id}/investigation"' in resp.text
    assert 'hx-trigger="load"' in resp.text
    assert not _polls(resp.text)
    assert not _has_button(resp.text)  # the shell carries no button; the state does


def test_the_shell_is_replaced_by_the_state_it_loads(client, db):
    """The state fragment is the same `<section id="investigation">` (outerHTML swap),
    and it no longer asks to be loaded — no request loop."""
    case_id = _make_case(db, client.user_id)

    resp = _get(client, case_id)

    assert resp.status_code == 200
    assert resp.text.count('id="investigation"') == 1
    assert 'hx-trigger="load"' not in resp.text


def test_the_template_and_router_never_mark_model_text_safe():
    source = _TEMPLATE.read_text(encoding="utf-8")
    for needle in ("|safe", "| safe", "autoescape false", "Markup"):
        assert needle not in source
    assert "Markup" not in _ROUTER.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# GET /cases/{id}/investigation — the five states
# ---------------------------------------------------------------------------


def test_idle_shows_the_button_and_does_not_poll(client, db):
    case_id = _make_case(db, client.user_id)

    resp = _get(client, case_id)

    assert 'data-state="idle"' in resp.text
    assert "Chưa có phân tích nào" in resp.text
    assert _has_button(resp.text)
    assert f'hx-post="/cases/{case_id}/analyze"' in resp.text
    assert not _polls(resp.text)


def test_running_polls_with_the_run_id_and_hides_the_button(client, db):
    case_id = _make_case(db, client.user_id)
    job_id = _insert_job(db, case_id, "running")
    run_id = tier2_investigate.run_id_for_job(job_id)

    resp = _get(client, case_id)

    assert 'data-state="running"' in resp.text
    assert "đang phân tích" in resp.text.lower()
    assert 'hx-trigger="every 3s"' in resp.text
    assert f'data-run-id="{run_id}"' in resp.text
    assert f'hx-get="/cases/{case_id}/investigation?run_id={run_id}"' in resp.text
    assert not _has_button(resp.text)


def test_a_transient_attempt_row_between_attempts_is_not_a_result(client, db):
    """P5-T04 round 1 (B1): a non-final failed attempt writes `stopped_by='transient'`
    under an attempt-scoped id while the job is still live. That is not an outcome — the
    page keeps spinning and shows nothing of it."""
    case_id = _make_case(db, client.user_id)
    job_id = _insert_job(db, case_id, "pending", attempts=1)
    _insert_run(
        db,
        case_id,
        run_id=tier2_investigate.attempt_run_id(job_id, 1),
        stopped_by="transient",
    )

    resp = _get(client, case_id)

    assert 'data-state="running"' in resp.text
    assert _polls(resp.text)
    assert not _fields(resp.text, "analysis_stopped")


def test_done_renders_the_result_and_stops_polling(client, db):
    case_id = _make_case(db, client.user_id)
    job_id = _insert_job(db, case_id, "succeeded")
    _insert_run(
        db,
        case_id,
        job_id=job_id,
        result=_result(next_steps=["STEP-ONE", "STEP-TWO"], playbook_used="PLAYBOOK-NAME"),
        evidence_check={"verified": [], "rejected": []},
    )

    resp = _get(client, case_id)

    assert 'data-state="done"' in resp.text
    assert not _polls(resp.text)
    assert _fields(resp.text, "analysis_summary") == ["SUMMARY-TEXT"]
    assert "NARRATIVE-TEXT" in resp.text
    assert "HYPOTHESIS-TEXT" in resp.text and "FOR-TEXT" in resp.text
    assert "AGAINST-TEXT" in resp.text
    assert _fields(resp.text, "next_step") == ["STEP-ONE", "STEP-TWO"]
    assert "PLAYBOOK-NAME" in resp.text
    assert "confirmed_incident" in resp.text
    assert _fields(resp.text, "analysis_confidence") == ["high"]
    assert _has_button(resp.text)  # an open case can be analysed again


def test_the_newest_job_wins_and_older_runs_stay_out_of_the_way(client, db):
    case_id = _make_case(db, client.user_id)
    older = _insert_job(db, case_id, "succeeded")
    _insert_run(
        db, case_id, job_id=older, result=_result(summary="OLDER-SUMMARY"), created_at=_PAST
    )
    newer = _insert_job(db, case_id, "succeeded")
    _insert_run(db, case_id, job_id=newer, result=_result(summary="NEWER-SUMMARY"))

    resp = _get(client, case_id)

    assert _fields(resp.text, "analysis_summary") == ["NEWER-SUMMARY"]
    assert "OLDER-SUMMARY" not in resp.text


def test_a_run_of_another_case_is_never_shown(client, db):
    case_a = _make_case(db, client.user_id)
    case_b = _make_case(db, client.user_id)
    job_b = _insert_job(db, case_b, "succeeded")
    _insert_run(db, case_b, job_id=job_b, result=_result(summary="CASE-B-SUMMARY"))

    resp = _get(client, case_a)

    assert 'data-state="idle"' in resp.text
    assert "CASE-B-SUMMARY" not in resp.text


def test_without_any_job_the_latest_final_row_is_shown(client, db):
    """No `jobs` row left (a purged queue, an old run): the newest row that is not a
    transient attempt is the answer."""
    case_id = _make_case(db, client.user_id)
    _insert_run(db, case_id, result=_result(summary="OLD-RUN"), created_at=_PAST)
    _insert_run(
        db, case_id, result=_result(summary="NEW-RUN"), created_at=_PAST + timedelta(days=1)
    )
    _insert_run(db, case_id, stopped_by="transient", created_at=_PAST + timedelta(days=2))

    resp = _get(client, case_id)

    assert _fields(resp.text, "analysis_summary") == ["NEW-RUN"]


@pytest.mark.parametrize(
    ("stopped_by", "keyword"),
    [
        ("cap", "hạn mức"),
        ("permanent", "không thể thử lại"),
        ("linter", "kiểm tra"),
        ("schema", "sai định dạng"),
        ("transient", "không phản hồi"),
    ],
)
def test_a_run_without_a_result_says_why_and_offers_a_retry(client, db, stopped_by, keyword):
    case_id = _make_case(db, client.user_id)
    job_id = _insert_job(db, case_id, "failed" if stopped_by == "transient" else "succeeded")
    _insert_run(db, case_id, job_id=job_id, stopped_by=stopped_by)

    resp = _get(client, case_id)

    stopped = _fields(resp.text, "analysis_stopped")
    assert len(stopped) == 1 and keyword in stopped[0]
    assert not _fields(resp.text, "analysis_summary")
    assert _has_button(resp.text)
    assert not _polls(resp.text)


def test_an_unknown_stopped_by_is_shown_escaped_not_dropped(client, db):
    case_id = _make_case(db, client.user_id)
    _insert_run(db, case_id, stopped_by="<b>weird</b>")

    resp = _get(client, case_id)

    assert "&lt;b&gt;weird&lt;/b&gt;" in resp.text
    assert "<b>weird</b>" not in resp.text


# ---------------------------------------------------------------------------
# The addendum: a last attempt that fails without an LLM error leaves no row
# ---------------------------------------------------------------------------


def test_a_failed_job_without_a_final_row_is_a_failure_with_a_retry_never_a_spinner(client, db):
    """P5-T04 round 2: a 5 s statement timeout while the dossier is built for a huge case
    ends the job `failed` with no `llm_runs` row at all — `GET /api/tier2/runs/{run_id}`
    answers 404 after the 202. The page reads the database, sees the failed job and no
    row, and stops polling."""
    case_id = _make_case(db, client.user_id)
    _insert_job(db, case_id, "failed", attempts=3)

    resp = _get(client, case_id)

    assert 'data-state="failed"' in resp.text
    assert _fields(resp.text, "analysis_failed") == ["Phân tích thất bại — có thể thử lại"]
    assert _has_button(resp.text)
    assert not _polls(resp.text)


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

    resp = _get(client, case_id)

    assert 'data-state="failed"' in resp.text
    assert _fields(resp.text, "analysis_summary") == ["LAST-GOOD"]
    assert "lượt phân tích trước" in resp.text
    assert not _fields(resp.text, "analysis_stopped")  # the attempt row is not an outcome
    assert _has_button(resp.text)


def test_a_failed_job_on_a_concluded_case_offers_no_retry(client, db):
    case_id = _make_case(db, client.user_id, status="concluded_fp")
    _insert_job(db, case_id, "failed", attempts=3)

    resp = _get(client, case_id)

    assert _fields(resp.text, "analysis_failed") == ["Phân tích thất bại"]
    assert not _has_button(resp.text)


def test_a_run_id_the_server_has_never_heard_of_is_shown_as_a_failure(client, db):
    """The page-side twin of the API's 404: the poll carries the `run_id` of the 202, and
    a case with no job and no row at all behind it is a failure, not an idle screen the
    user would mistake for "nothing was started"."""
    case_id = _make_case(db, client.user_id)

    resp = _get(client, case_id, run_id=str(uuid.uuid4()))

    assert 'data-state="failed"' in resp.text
    assert _fields(resp.text, "analysis_failed") == ["Phân tích thất bại — có thể thử lại"]
    assert not _polls(resp.text)


def test_a_malformed_run_id_is_ignored(client, db):
    case_id = _make_case(db, client.user_id)

    resp = _get(client, case_id, run_id="not-a-uuid")

    assert resp.status_code == 200
    assert 'data-state="idle"' in resp.text


# ---------------------------------------------------------------------------
# A concluded case
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "status", ["concluded_fp", "concluded_policy_violation", "confirmed_incident"]
)
def test_a_concluded_case_hides_the_button_and_shows_the_last_result(client, db, status):
    case_id = _make_case(db, client.user_id, status=status)
    job_id = _insert_job(db, case_id, "succeeded")
    _insert_run(db, case_id, job_id=job_id, result=_result(summary="BEFORE-CONCLUSION"))

    resp = _get(client, case_id)

    assert _fields(resp.text, "analysis_summary") == ["BEFORE-CONCLUSION"]
    assert not _has_button(resp.text)
    assert "hx-post" not in resp.text


def test_a_concluded_case_without_a_result_says_so_and_has_no_button(client, db):
    case_id = _make_case(db, client.user_id, status="concluded_fp")

    resp = _get(client, case_id)

    assert "đã kết luận" in resp.text
    assert not _has_button(resp.text)


# ---------------------------------------------------------------------------
# Evidence marks — the reason this card exists
# ---------------------------------------------------------------------------


def _evidence_case(db, user_id: str):
    case_id = _make_case(db, user_id)
    head = _add_head(db, case_id, user_id, raw_log="Failed password for root from 10.0.0.9")
    other_case = _make_case(db, user_id)
    foreign = _add_head(db, other_case, user_id, raw_log="unrelated log line of another case")
    return case_id, head, foreign


def test_evidence_marks_come_from_the_writers_own_check(client, db):
    """The contract test: `evidence_check` is produced by `_check_evidence` itself — the
    function the job calls — over real alerts, covering all four outcomes: verified,
    `quote_not_found`, `quote_too_short`, `not_in_case`. A shape change on the T04 side
    (the index type, the reason names) turns this red."""
    case_id, head, foreign = _evidence_case(db, client.user_id)
    evidence = [
        {"alert_id": head, "quote": "Failed password for root", "why": "WHY-VERIFIED"},
        {"alert_id": head, "quote": "this quote is not in the log", "why": "WHY-NOT-FOUND"},
        {"alert_id": head, "quote": "abc", "why": "WHY-TOO-SHORT"},
        {"alert_id": foreign, "quote": "unrelated log line of another case", "why": "WHY-FOREIGN"},
    ]
    parsed = _result(evidence=evidence)
    check = tier2_investigate._check_evidence(db, case_id, parsed)
    job_id = _insert_job(db, case_id, "succeeded")
    _insert_run(db, case_id, job_id=job_id, result=parsed, evidence_check=check)

    resp = _get(client, case_id)

    items = _evidence_items(resp.text)
    assert len(items) == 4
    verified, not_found, too_short, not_in_case = items
    assert 'data-verified="true"' in verified and "Đã kiểm chứng" in verified
    assert "WHY-VERIFIED" in verified and "Failed password for root" in verified
    for chunk in (not_found, too_short, not_in_case):
        assert 'data-verified="false"' in chunk and "Chưa kiểm chứng" in chunk
        assert "Đã kiểm chứng" not in chunk
    assert "không có trong log" in not_found
    assert f"ngắn hơn {tier2_investigate.MIN_QUOTE_CHARS} ký tự" in too_short
    assert "không thuộc case" in not_in_case
    assert "WHY-NOT-FOUND" in not_found and "WHY-FOREIGN" in not_in_case


def test_an_unverified_item_is_marked_and_a_verified_one_is_not(client, db):
    """Red step (c): drop the marking and this goes red while
    `test_done_renders_the_result_and_stops_polling` stays green (it has no evidence)."""
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
    _insert_run(db, case_id, result=parsed, evidence_check=check)

    resp = _get(client, case_id)

    first, second = _evidence_items(resp.text)
    assert 'data-verified="true"' in first and "Đã kiểm chứng" in first
    assert 'data-verified="false"' in second and "Chưa kiểm chứng" in second
    assert "Đã kiểm chứng" not in second


def test_without_an_evidence_check_nothing_is_presented_as_verified(client, db):
    case_id = _make_case(db, client.user_id)
    parsed = _result(evidence=[{"alert_id": "a-1", "quote": "SOME-QUOTE-HERE", "why": "w"}])
    _insert_run(db, case_id, result=parsed, evidence_check=None)

    resp = _get(client, case_id)

    (item,) = _evidence_items(resp.text)
    assert 'data-verified="false"' in item and "Chưa kiểm chứng" in item


def test_a_rejected_index_pointing_nowhere_does_not_verify_an_item(client, db):
    """`verified` holds indexes; an index that is a string, or out of range, is ignored —
    never coerced into a mark."""
    case_id = _make_case(db, client.user_id)
    parsed = _result(evidence=[{"alert_id": "a-1", "quote": "SOME-QUOTE-HERE", "why": "w"}])
    _insert_run(db, case_id, result=parsed, evidence_check={"verified": ["0", 7], "rejected": []})

    (item,) = _evidence_items(_get(client, case_id).text)

    assert 'data-verified="false"' in item


# ---------------------------------------------------------------------------
# The model was overruled
# ---------------------------------------------------------------------------


def test_an_overruled_conclusion_shows_need_more_data_and_the_original(client, db):
    case_id = _make_case(db, client.user_id)
    parsed = _result(suggested_conclusion="need_more_data")
    check = {"verified": [], "rejected": [], "original_conclusion": "false_positive"}
    _insert_run(db, case_id, result=parsed, evidence_check=check)

    resp = _get(client, case_id)

    assert "need_more_data" in resp.text
    assert "false_positive" in resp.text
    (overruled,) = _fields(resp.text, "analysis_overruled")
    assert "false_positive" in overruled and "need_more_data" in overruled
    assert "không có bằng chứng nào" in overruled


def test_forced_by_is_said_in_words(client, db):
    case_id = _make_case(db, client.user_id)
    parsed = _result(suggested_conclusion="need_more_data")
    check = {
        "verified": [0],
        "rejected": [],
        "forced_by": "high_severity_injection_finding",
        "original_conclusion": "false_positive",
    }
    parsed["evidence"] = [{"alert_id": "a-1", "quote": "SOME-QUOTE-HERE", "why": "w"}]
    _insert_run(db, case_id, result=parsed, evidence_check=check)

    resp = _get(client, case_id)

    (overruled,) = _fields(resp.text, "analysis_overruled")
    assert "tiêm lệnh" in overruled
    assert "false_positive" in overruled and "need_more_data" in overruled
    assert (
        "không có bằng chứng nào" not in overruled
    )  # the evidence verified; the cause is the injection


def test_an_unremarkable_result_has_no_overrule_note(client, db):
    case_id = _make_case(db, client.user_id)
    _insert_run(db, case_id, result=_result(), evidence_check={"verified": [], "rejected": []})

    assert not _fields(_get(client, case_id).text, "analysis_overruled")


# ---------------------------------------------------------------------------
# Model output is untrusted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("payload", [_SCRIPT, _IMG], ids=["script", "img-onerror"])
def test_every_model_string_is_escaped(client, db, payload):
    """Red step (b): render `attack_narrative` with `|safe` and this goes red."""
    case_id = _make_case(db, client.user_id)
    parsed = _result(
        summary=f"S {payload}",
        attack_narrative=f"N {payload}",
        confidence=payload,
        gia_thuyet=[
            {
                "noi_dung": f"H {payload}",
                "evidence_for": [f"F {payload}"],
                "evidence_against": [f"A {payload}"],
            }
        ],
        evidence=[{"alert_id": f"id {payload}", "quote": f"Q {payload}", "why": f"W {payload}"}],
        next_steps=[f"X {payload}"],
        playbook_used=f"P {payload}",
    )
    check = {"verified": [0], "rejected": []}
    _insert_run(db, case_id, result=parsed, evidence_check=check)

    resp = _get(client, case_id)

    assert "<script>" not in resp.text and "<img" not in resp.text
    escaped = (
        payload.replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&#34;")
        .replace("'", "&#39;")
    )
    for field in (
        "analysis_summary",
        "hypothesis_text",
        "evidence_quote",
        "evidence_why",
        "next_step",
    ):
        text, *_ = _fields(resp.text, field)
        assert escaped in text, field
    assert escaped in resp.text.split('data-field="analysis_narrative"')[1].split("</pre>")[0]


def test_an_evidence_alert_id_and_an_unknown_reason_cannot_inject_either(client, db):
    case_id = _make_case(db, client.user_id)
    parsed = _result(evidence=[{"alert_id": _IMG, "quote": "SOME-QUOTE-HERE", "why": "w"}])
    check = {"verified": [], "rejected": [{"index": 0, "alert_id": _IMG, "reason": _SCRIPT}]}
    _insert_run(db, case_id, result=parsed, evidence_check=check)

    resp = _get(client, case_id)

    assert "<script>" not in resp.text and "<img" not in resp.text


# ---------------------------------------------------------------------------
# The snapshot beside the current values (P7-2; T07 owns the "ongoing" label)
# ---------------------------------------------------------------------------


def _snapshot_case(db, user_id: str):
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


def test_the_recorded_snapshot_is_shown_beside_the_current_values(client, db):
    case_id, seen = _snapshot_case(db, client.user_id)
    trace = {"alert_count": 3, "total_occurrences": 12, "last_seen_at": seen.isoformat()}
    _insert_run(db, case_id, result=_result(), agent_trace=trace)

    resp = _get(client, case_id)

    (then,) = _fields(resp.text, "analysis_snapshot")
    (now,) = _fields(resp.text, "analysis_current")
    assert "3 alert" in then and "12 lần xuất hiện" in then
    assert "3 alert" in now and "20 lần xuất hiện" in now
    assert _fields(resp.text, "analysis_changed")
    assert "tiếp diễn" not in resp.text  # T07's label owns "ongoing"; there is only one


def test_an_unchanged_case_gets_no_changed_sentence(client, db):
    case_id, seen = _snapshot_case(db, client.user_id)
    trace = {"alert_count": 3, "total_occurrences": 20, "last_seen_at": seen.isoformat()}
    _insert_run(db, case_id, result=_result(), agent_trace=trace)

    resp = _get(client, case_id)

    assert _fields(resp.text, "analysis_snapshot") and _fields(resp.text, "analysis_current")
    assert not _fields(resp.text, "analysis_changed")


def test_a_run_without_a_recorded_snapshot_shows_no_comparison(client, db):
    case_id, _ = _snapshot_case(db, client.user_id)
    _insert_run(db, case_id, result=_result(), agent_trace=None)

    resp = _get(client, case_id)

    assert resp.status_code == 200
    assert not _fields(resp.text, "analysis_snapshot")
    assert not _fields(resp.text, "analysis_changed")


# ---------------------------------------------------------------------------
# GET — access and unknown cases
# ---------------------------------------------------------------------------


def test_get_on_an_unknown_case_is_the_not_found_page(client):
    resp = _get(client, str(uuid.uuid4()))

    assert resp.status_code == 404
    assert "Không tìm thấy case" in resp.text


def test_an_anonymous_visitor_is_sent_to_login(client, db):
    main.app.dependency_overrides.pop(pages.page_user)
    case_id = _make_case(db, client.user_id)

    get = client.http.get(f"/cases/{case_id}/investigation")
    post = client.http.post(f"/cases/{case_id}/analyze")

    for resp in (get, post):
        assert resp.status_code == 303
        assert resp.headers["location"] == "/login"


@pytest.mark.parametrize("method", ["get", "post"])
def test_tier1_is_forbidden_and_the_denial_is_committed(client, db, monkeypatch, method):
    """`require_role` commits `authz.denied` before it raises. The commit is spied (and
    the row read at that moment) so nothing really lands in the shared database. One
    request per test: `get_conn`'s rollback on the exception is the real one here."""
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

    resp = _get(client, case_id) if method == "get" else _post(client, case_id)

    assert resp.status_code == 403
    assert seen == [["authz.denied"]]


# ---------------------------------------------------------------------------
# POST /cases/{id}/analyze
# ---------------------------------------------------------------------------


def test_post_starts_a_run_and_answers_with_the_polling_state(client, db, monkeypatch):
    case_id = _make_case(db, client.user_id)
    commits: list[str] = []
    monkeypatch.setattr(db, "commit", lambda: commits.append("commit"))

    resp = _post(client, case_id)

    assert resp.status_code == 200
    ((job_id, status),) = db.execute(
        "SELECT job_id, status FROM jobs WHERE subject_id = %s AND job_type = 'investigate'",
        (case_id,),
    ).fetchall()
    assert status == "pending"
    run_id = tier2_investigate.run_id_for_job(job_id)
    assert 'data-state="running"' in resp.text
    assert f'data-run-id="{run_id}"' in resp.text
    assert 'hx-trigger="every 3s"' in resp.text
    assert commits == ["commit"]  # api_analyze's own; this module adds none
    audit = db.execute(
        "SELECT payload FROM audit_events WHERE event_type = 'case.analyzed' AND subject_id = %s",
        (case_id,),
    ).fetchone()
    assert audit[0]["run_id"] == str(run_id)


def test_a_plain_form_post_redirects_back_to_the_case(client, db, monkeypatch):
    """`cases_pages.add_note_page`'s convention: only an htmx request gets a bare fragment."""
    case_id = _make_case(db, client.user_id)
    monkeypatch.setattr(db, "commit", lambda: None)

    resp = client.http.post(f"/cases/{case_id}/analyze")

    assert resp.status_code == 303
    assert resp.headers["location"] == f"/cases/{case_id}"
    assert (
        db.execute("SELECT count(*) FROM jobs WHERE subject_id = %s", (case_id,)).fetchone()[0] == 1
    )


def test_a_second_post_is_a_409_naming_the_running_analysis_inside_the_fragment(
    client, db, monkeypatch
):
    case_id = _make_case(db, client.user_id)
    monkeypatch.setattr(db, "commit", lambda: None)
    monkeypatch.setattr(db, "rollback", lambda: None)

    first = _post(client, case_id)
    second = _post(client, case_id)

    assert (first.status_code, second.status_code) == (200, 409)
    (message,) = _fields(second.text, "analyze_message")
    assert message == "Đang có một lượt phân tích chạy cho case này"
    assert 'data-state="running"' in second.text and _polls(second.text)
    assert 'id="flash"' not in second.text  # not an OOB flash: case.html has no #flash target
    assert "hx-swap-oob" not in second.text
    assert (
        db.execute("SELECT count(*) FROM jobs WHERE subject_id = %s", (case_id,)).fetchone()[0] == 1
    )


def test_the_quota_answers_200_with_the_message_inside_the_fragment(client, db, monkeypatch):
    """A 429 would never be swapped (`case.html`'s `beforeSwap` enables 409/422/503 only),
    so the quota — a message, not an error — is a 200. N comes from the config (2 here)."""
    cases = [_make_case(db, client.user_id) for _ in range(3)]
    commits: list[str] = []
    monkeypatch.setattr(db, "commit", lambda: commits.append("commit"))
    monkeypatch.setattr(db, "rollback", lambda: None)

    responses = [_post(client, c) for c in cases]

    assert [r.status_code for r in responses] == [200, 200, 200]
    assert not _fields(responses[0].text, "analyze_message")
    (message,) = _fields(responses[2].text, "analyze_message")
    assert message == "Đã dùng hết 2 lượt phân tích hôm nay"
    assert 'data-state="running"' not in responses[2].text
    assert _has_button(responses[2].text)
    assert commits == ["commit", "commit"]  # the refused third commits nothing
    assert (
        db.execute("SELECT count(*) FROM jobs WHERE subject_id = %s", (cases[2],)).fetchone()[0]
        == 0
    )


@pytest.mark.parametrize(
    "status", ["concluded_fp", "concluded_policy_violation", "confirmed_incident"]
)
def test_a_concluded_case_is_a_409_with_the_message_and_no_button(client, db, monkeypatch, status):
    case_id = _make_case(db, client.user_id, status=status)
    monkeypatch.setattr(db, "commit", lambda: None)
    monkeypatch.setattr(db, "rollback", lambda: None)

    resp = _post(client, case_id)

    assert resp.status_code == 409
    (message,) = _fields(resp.text, "analyze_message")
    assert "Case đã kết luận" in message
    assert not _has_button(resp.text)
    assert (
        db.execute("SELECT count(*) FROM jobs WHERE subject_id = %s", (case_id,)).fetchone()[0] == 0
    )
    assert (
        db.execute(
            "SELECT count(*) FROM audit_events WHERE event_type = 'case.analyzed' AND subject_id = %s",
            (case_id,),
        ).fetchone()[0]
        == 0
    )


@pytest.mark.parametrize("scenario", ["running", "concluded", "quota"])
def test_a_refused_post_ends_with_a_rollback_and_never_commits(client, db, monkeypatch, scenario):
    """`get_conn` commits whatever a returned response left in the transaction, so every
    refusal must end on its own rollback — after the reads it renders from. The event log
    is what makes this discriminating: `api_analyze` rolls back before it raises, so the
    reads this module does afterwards would otherwise be the last thing that happened."""
    case_id = _make_case(
        db, client.user_id, status="concluded_fp" if scenario == "concluded" else "investigating"
    )
    monkeypatch.setattr(db, "commit", lambda: None)
    monkeypatch.setattr(db, "rollback", lambda: None)
    if scenario == "running":
        _insert_job(db, case_id, "pending")
    if scenario == "quota":
        for _ in range(2):  # the fixture's quota is 2
            other = _make_case(db, client.user_id)
            assert _post(client, other).status_code == 200

    events: list[str] = []
    real_execute = db.execute

    def _spy_execute(*args, **kwargs):
        events.append("execute")
        return real_execute(*args, **kwargs)

    monkeypatch.setattr(db, "execute", _spy_execute)
    monkeypatch.setattr(db, "commit", lambda: events.append("commit"))
    monkeypatch.setattr(db, "rollback", lambda: events.append("rollback"))

    resp = _post(client, case_id)

    assert resp.status_code in (200, 409)
    assert "commit" not in events
    assert events[-1] == "rollback"


def test_post_on_an_unknown_case_is_the_not_found_page(client, db, monkeypatch):
    monkeypatch.setattr(db, "commit", lambda: None)
    monkeypatch.setattr(db, "rollback", lambda: None)

    resp = _post(client, str(uuid.uuid4()))

    assert resp.status_code == 404
    assert "Không tìm thấy case" in resp.text


def test_a_refusal_is_a_bare_swappable_section_never_an_oob_flash(client, db, monkeypatch):
    """Every message lives inside `<section id="investigation">` — the fragment the button
    targets — so it is swapped in with the rest, and `_flash.html`'s OOB `#flash` (which
    `case.html` has no placeholder for, htmx 2.0.4 drops it) is never involved."""
    case_id = _make_case(db, client.user_id, status="concluded_fp")
    monkeypatch.setattr(db, "commit", lambda: None)
    monkeypatch.setattr(db, "rollback", lambda: None)

    resp = _post(client, case_id)

    assert resp.text.lstrip().startswith("<section")
    assert 'id="investigation"' in resp.text
    assert "hx-swap-oob" not in resp.text


# ---------------------------------------------------------------------------
# End to end through the routes: button -> polling state -> job finishes -> result
# ---------------------------------------------------------------------------


def test_button_then_poll_then_result(client, db, monkeypatch):
    case_id = _make_case(db, client.user_id)
    head = _add_head(db, case_id, client.user_id, raw_log="Failed password for root from 10.0.0.9")
    monkeypatch.setattr(db, "commit", lambda: None)

    started = _post(client, case_id)
    poll_url = re.search(r'hx-get="([^"]+)"', started.text).group(1)
    still_running = client.http.get(poll_url, headers=_HTMX)

    # what the worker does at the end of the job: the final row and `succeeded`, together
    (job_id,) = db.execute(
        "SELECT job_id FROM jobs WHERE subject_id = %s AND job_type = 'investigate'", (case_id,)
    ).fetchone()
    parsed = _result(evidence=[{"alert_id": head, "quote": "Failed password for root", "why": "w"}])
    check = tier2_investigate._check_evidence(db, case_id, parsed)
    _insert_run(db, case_id, job_id=job_id, result=parsed, evidence_check=check)
    db.execute("UPDATE jobs SET status = 'succeeded' WHERE job_id = %s", (job_id,))
    finished = client.http.get(poll_url, headers=_HTMX)

    assert _polls(started.text) and _polls(still_running.text)
    assert 'data-state="done"' in finished.text
    assert not _polls(finished.text)
    (item,) = _evidence_items(finished.text)
    assert 'data-verified="true"' in item
