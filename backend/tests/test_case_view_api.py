"""P10-T04 — `GET /api/tier2/cases/{id}` (and the `POST .../conclude` response, which
returns the same body) gain the fields the React case page reads instead of recomputing
them: `concluded_by_name`, `author_name` on each note, the per-head supplement
(`raw_log`, `raw_log_truncated`, `risk_band`, `last_seen_at` — never `risk_score`) and
`ongoing` / `ongoing_last_seen`. The helpers under test live in `app.tier2.case_view`,
moved out of the Jinja case page's router (that page retired in P10-T13).

Every db test runs inside the `db` fixture's transaction and is rolled back: the
overridden `get_conn` yields that connection and never commits. Fixture helpers are
copied from `test_tier2_api.py` (its lines 34-144), extended with the alert columns this
card reads.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from app.infra import config
from app.infra.auth import Claims
from app.tier1.queue import risk_band as tier1_risk_band
from app.tier2 import case_view, conclude
from app.web import deps, main
from fastapi.testclient import TestClient

_T0 = datetime(2026, 3, 1, 8, 0, tzinfo=UTC)

# ---------------------------------------------------------------------------
# Fixture helpers — copied from test_tier2_api.py, plus the columns this card reads
# ---------------------------------------------------------------------------


def _make_user(conn: psycopg.Connection, *, role: str = "tier2") -> tuple[str, str]:
    """`(user_id, username)` — the username is generated, so a test can compare to it."""
    user_id = str(uuid.uuid4())
    username = f"user-{user_id[:8]}"
    conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash) "
        "VALUES (%s, %s, %s, %s, 'x')",
        (user_id, username, "Test Analyst", role),
    )
    return user_id, username


def _make_case(
    conn: psycopg.Connection,
    user_id: str,
    *,
    title: str = "case",
    status: str = "investigating",
    created_at=None,
    last_analyzed_at=None,
    concluded_at=None,
    concluded_by=None,
    conclusion_reason=None,
) -> str:
    case_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO cases (case_id, title, status, severity, created_by, concluded_at, "
        "concluded_by, conclusion_reason) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (case_id, title, status, "high", user_id, concluded_at, concluded_by, conclusion_reason),
    )
    if created_at is not None:
        conn.execute("UPDATE cases SET created_at = %s WHERE case_id = %s", (created_at, case_id))
    if last_analyzed_at is not None:
        conn.execute(
            "UPDATE cases SET last_analyzed_at = %s WHERE case_id = %s", (last_analyzed_at, case_id)
        )
    return case_id


def _insert_alert(
    conn: psycopg.Connection,
    *,
    status: str,
    case_id: str | None = None,
    duplicate_of: str | None = None,
    closed_at=None,
    sealed_at=None,
    raw_log: str = "",
    raw_log_truncated: bool = False,
    risk_score: int | None = None,
    last_seen_at=None,
) -> str:
    alert_id = f"p10t04-{uuid.uuid4()}"
    conn.execute(
        "INSERT INTO alerts (alert_id, rule_id, rule_level, severity, description, "
        "agent_name, alert_time, category, resolved_by, mapping_version, "
        "event_bucket_hash, raw_payload, raw_log, raw_log_truncated, status, duplicate_of, "
        "case_id, closed_at, sealed_at, risk_score) "
        "VALUES (%s, '40112', 10, 'high', 'SSH brute force', 'agent-1', now(), "
        "'brute_force', 'rule_groups', 'v1', %s, '{}'::jsonb, %s, %s, %s, %s, %s, %s, %s, %s)",
        (
            alert_id,
            hashlib.sha256(alert_id.encode()).hexdigest(),
            raw_log,
            raw_log_truncated,
            status,
            duplicate_of,
            case_id,
            closed_at,
            sealed_at,
            risk_score,
        ),
    )
    if last_seen_at is not None:
        # `ck_alerts_last_seen_khong_lui`: last_seen_at may not precede first_seen_at, which
        # defaults to now() — so the fixed `_T0`-relative instants below move both.
        conn.execute(
            "UPDATE alerts SET first_seen_at = %s, last_seen_at = %s WHERE alert_id = %s",
            (_T0, last_seen_at, alert_id),
        )
    return alert_id


def _add_head(
    conn: psycopg.Connection, case_id: str, alert_id: str, added_by: str, *, added_at=None
) -> None:
    """`added_at` fixes the head's place in `case_detail`'s order (`added_at, alert_id`); left
    out it is `now()`, the same instant for every head of a test's one transaction."""
    conn.execute(
        "INSERT INTO case_alerts (case_id, alert_id, added_by) VALUES (%s, %s, %s)",
        (case_id, alert_id, added_by),
    )
    if added_at is not None:
        conn.execute(
            "UPDATE case_alerts SET added_at = %s WHERE case_id = %s AND alert_id = %s",
            (added_at, case_id, alert_id),
        )


class _Client:
    """`TestClient` plus the user/role the overridden auth dependency answers as."""

    def __init__(self, user_id: str, username: str) -> None:
        self.http = TestClient(main.app, follow_redirects=False)
        self.user_id = user_id
        self.username = username
        self.role = "tier2"

    def claims(self) -> Claims:
        return Claims(
            user_id=self.user_id, username=self.username, role=self.role, iat=0.0, exp=0.0
        )


@pytest.fixture
def client(db):
    user_id, username = _make_user(db)
    c = _Client(user_id, username)

    def get_conn():
        # The real dependency's shape minus the commit: this connection is the shared `db`
        # fixture's, and its own teardown rolls everything back.
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


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value)


# ---------------------------------------------------------------------------
# concluded_by_name / author_name
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_detail_has_concluded_by_name(client, db):
    other_id, other_name = _make_user(db)
    case_id = _make_case(
        db,
        client.user_id,
        status="concluded_fp",
        concluded_at=_T0,
        concluded_by=other_id,
        conclusion_reason="scanner",
    )

    resp = client.http.get(f"/api/tier2/cases/{case_id}")

    assert resp.status_code == 200
    body = resp.json()
    assert body["concluded_by"] == other_id
    assert body["concluded_by_name"] == other_name
    assert body["concluded_by_name"] != client.username  # the concluder, not the viewer


@pytest.mark.db
def test_concluded_by_name_is_none_for_an_open_case(client, db):
    case_id = _make_case(db, client.user_id)

    body = client.http.get(f"/api/tier2/cases/{case_id}").json()

    assert body["concluded_by"] is None
    assert body["concluded_by_name"] is None


@pytest.mark.db
def test_notes_carry_author_name(client, db):
    other_id, other_name = _make_user(db)
    case_id = _make_case(db, client.user_id)
    conclude.add_note(db, case_id, client.user_id, "mine")
    conclude.add_note(db, case_id, other_id, "theirs")

    body = client.http.get(f"/api/tier2/cases/{case_id}").json()

    assert [(n["body"], n["author_name"]) for n in body["notes"]] == [
        ("mine", client.username),
        ("theirs", other_name),
    ]
    assert [n["author_id"] for n in body["notes"]] == [client.user_id, other_id]


# ---------------------------------------------------------------------------
# the per-head supplement
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_heads_carry_raw_log_band_last_seen_and_no_risk_score(client, db):
    u = client.user_id
    case_id = _make_case(db, u, created_at=_T0)
    scored = _insert_alert(
        db,
        status="escalated_tier2",
        case_id=case_id,
        raw_log="Failed password for root",
        raw_log_truncated=True,
        risk_score=83,
        last_seen_at=_T0 + timedelta(minutes=5),
    )
    unscored = _insert_alert(db, status="escalated_tier2", case_id=case_id, last_seen_at=_T0)
    _add_head(db, case_id, scored, u)
    _add_head(db, case_id, unscored, u)

    body = client.http.get(f"/api/tier2/cases/{case_id}").json()

    heads = {h["alert_id"]: h for h in body["heads"]}
    head = heads[scored]
    assert head["raw_log"] == "Failed password for root"
    assert head["raw_log_truncated"] is True
    assert head["risk_band"] == "Rất cao"  # risk_band(83): the label the row shows, 75-100
    assert _instant(head["last_seen_at"]) == _T0 + timedelta(minutes=5)
    assert "risk_score" not in head  # P4's rule: the band, never the bare number
    bare = heads[unscored]
    assert bare["raw_log"] == ""
    assert bare["raw_log_truncated"] is False
    assert bare["risk_band"] is None
    assert "risk_score" not in bare
    assert "risk_score" not in client.http.get(f"/api/tier2/cases/{case_id}").text


@pytest.mark.parametrize("score", range(-5, 106))
def test_head_band_label_is_the_tier1_queue_label(score):
    """`tier2` cannot import `tier1` (G1, `test_import_rules`), so `case_view` derives the
    label from `llm.builder.risk_band` and its own four-entry table. This pins that table to
    the queue's `risk_band` for every score, including the clamped ones outside 0-100."""
    assert case_view.head_band(score) == tier1_risk_band(score)


def test_head_band_of_no_score_is_none():
    assert case_view.head_band(None) is None


# ---------------------------------------------------------------------------
# ongoing / ongoing_last_seen
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_ongoing_true_when_an_escalated_head_grew_after_creation(client, db):
    u = client.user_id
    case_id = _make_case(db, u, created_at=_T0)
    # Three heads whose `added_at` order (first, middle, last) is fixed, and whose newest
    # `last_seen_at` is the MIDDLE one: a rule that keeps the first qualifying head answers
    # +1h, one that keeps the last answers +1.5h, and only the max answers +2h.
    first = _insert_alert(
        db,
        status="escalated_tier2",
        case_id=case_id,
        last_seen_at=_T0 + timedelta(hours=1),
    )
    middle = _insert_alert(
        db,
        status="escalated_tier2",
        case_id=case_id,
        last_seen_at=_T0 + timedelta(hours=2),
    )
    last = _insert_alert(
        db,
        status="escalated_tier2",
        case_id=case_id,
        last_seen_at=_T0 + timedelta(hours=1, minutes=30),
    )
    _add_head(db, case_id, first, u, added_at=_T0)
    _add_head(db, case_id, middle, u, added_at=_T0 + timedelta(minutes=1))
    _add_head(db, case_id, last, u, added_at=_T0 + timedelta(minutes=2))

    body = client.http.get(f"/api/tier2/cases/{case_id}").json()

    assert [h["alert_id"] for h in body["heads"]] == [first, middle, last]  # the fixed order
    assert body["ongoing"] is True
    assert _instant(body["ongoing_last_seen"]) == _T0 + timedelta(hours=2)  # the latest head


@pytest.mark.db
def test_ongoing_false_for_a_fresh_case(client, db):
    """`escalate` inserts the case and its heads in one transaction, so a head that never
    grew has `last_seen_at == created_at` exactly — not "newer than" it."""
    u = client.user_id
    case_id = _make_case(db, u, created_at=_T0)
    head = _insert_alert(db, status="escalated_tier2", case_id=case_id, last_seen_at=_T0)
    _add_head(db, case_id, head, u)

    body = client.http.get(f"/api/tier2/cases/{case_id}").json()

    assert body["ongoing"] is False
    assert body["ongoing_last_seen"] is None


@pytest.mark.db
def test_ongoing_false_when_analyzed_after_the_last_growth(client, db):
    """`since` is `last_analyzed_at` once ② has run: growth older than the analysis is not
    "ongoing" any more."""
    u = client.user_id
    case_id = _make_case(db, u, created_at=_T0, last_analyzed_at=_T0 + timedelta(hours=2))
    head = _insert_alert(
        db,
        status="escalated_tier2",
        case_id=case_id,
        last_seen_at=_T0 + timedelta(hours=1),
    )
    _add_head(db, case_id, head, u)

    body = client.http.get(f"/api/tier2/cases/{case_id}").json()

    assert body["ongoing"] is False
    assert body["ongoing_last_seen"] is None


@pytest.mark.db
def test_ongoing_true_again_when_a_duplicate_arrives_after_the_last_analysis(client, db):
    """The other side of the rule above (case 4 of the deleted page's `test_ongoing_label_matrix`):
    once ② has run, `since` is `last_analyzed_at`, and a head that grew *after* it is ongoing
    again — the label comes back with the newest growth, not the analysis time."""
    u = client.user_id
    case_id = _make_case(db, u, created_at=_T0, last_analyzed_at=_T0 + timedelta(hours=2))
    head = _insert_alert(
        db,
        status="escalated_tier2",
        case_id=case_id,
        last_seen_at=_T0 + timedelta(hours=3),
    )
    _add_head(db, case_id, head, u)

    body = client.http.get(f"/api/tier2/cases/{case_id}").json()

    assert body["ongoing"] is True
    assert _instant(body["ongoing_last_seen"]) == _T0 + timedelta(hours=3)


@pytest.mark.db
def test_ongoing_false_for_a_concluded_case_whose_head_grew(client, db):
    u = client.user_id
    case_id = _make_case(
        db,
        u,
        status="concluded_fp",
        created_at=_T0,
        concluded_at=_T0 + timedelta(hours=3),
        concluded_by=u,
        conclusion_reason="x",
    )
    head = _insert_alert(
        db,
        status="closed_fp",
        case_id=case_id,
        closed_at=_T0 + timedelta(hours=3),
        sealed_at=_T0 + timedelta(hours=3),
        last_seen_at=_T0 + timedelta(hours=1),
    )
    _add_head(db, case_id, head, u)

    body = client.http.get(f"/api/tier2/cases/{case_id}").json()

    assert body["ongoing"] is False
    assert body["ongoing_last_seen"] is None


def _archived_case(db, user_id: str, *, title: str = "archived") -> tuple[str, str]:
    """A case as `transitions.archive_before` leaves it (DEC-212): `archived`, a moment and a reason,
    nobody who concluded it; its one head `archived` too, sealed. Returns `(case_id, head_id)`."""
    case_id = _make_case(
        db,
        user_id,
        title=title,
        status="archived",
        created_at=_T0,
        concluded_at=_T0 + timedelta(hours=3),
        conclusion_reason="DEC-212",
    )
    head = _insert_alert(
        db,
        status="archived",
        case_id=case_id,
        closed_at=_T0 + timedelta(hours=3),
        sealed_at=_T0 + timedelta(hours=3),
        last_seen_at=_T0 + timedelta(hours=1),
    )
    _add_head(db, case_id, head, user_id)
    return case_id, head


@pytest.mark.db
def test_an_archived_case_is_shown_as_closed_with_nobody_who_concluded_it(client, db):
    """INT-T03 / DEC-212: the case page of an archived case says `archived`, has no `concluded_by` and
    no name for one, is not `ongoing` (its head is archived, and a head that grew after the archive is
    a new alert in a new cluster), and its heads are `archived` too."""
    case_id, head = _archived_case(db, client.user_id)

    resp = client.http.get(f"/api/tier2/cases/{case_id}")

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "archived"
    assert body["concluded_by"] is None and body["concluded_by_name"] is None
    assert body["concluded_at"] is not None and body["conclusion_reason"] == "DEC-212"
    assert body["ongoing"] is False and body["ongoing_last_seen"] is None
    assert [(h["alert_id"], h["status"]) for h in body["heads"]] == [(head, "archived")]


@pytest.mark.db
def test_the_case_list_puts_an_archived_case_with_the_closed_ones_never_with_the_active(client, db):
    u = client.user_id
    older_active = _make_case(db, u, title="older active", created_at=_T0)
    archived, _head = _archived_case(db, u)
    concluded = _make_case(
        db,
        u,
        title="concluded",
        status="concluded_fp",
        created_at=_T0 + timedelta(hours=2),
        concluded_at=_T0 + timedelta(hours=3),
        concluded_by=u,
        conclusion_reason="r",
    )
    newer_active = _make_case(db, u, title="newer active", created_at=_T0 + timedelta(hours=4))

    rows = client.http.get("/api/tier2/cases").json()

    ids = [row["case_id"] for row in rows]
    # `investigating` first, newest first; then everything else, newest first
    assert ids.index(newer_active) < ids.index(older_active) < ids.index(concluded)
    assert ids.index(older_active) < ids.index(archived)
    by_id = {row["case_id"]: row for row in rows}
    assert by_id[archived]["status"] == "archived"
    assert by_id[archived]["cluster_count"] == 1


# ---------------------------------------------------------------------------
# existing keys are untouched; the conclude response carries the new ones too
# ---------------------------------------------------------------------------

_CASE_KEYS_BEFORE = {
    "case_id",
    "title",
    "status",
    "severity",
    "created_by",
    "created_at",
    "last_analyzed_at",
    "concluded_by",
    "concluded_at",
    "conclusion_reason",
    "heads",
    "notes",
}
_HEAD_KEYS_BEFORE = {
    "alert_id",
    "rule_id",
    "severity",
    "description",
    "agent_name",
    "alert_time",
    "srcip",
    "category",
    "occurrence_count",
    "status",
}
_NOTE_KEYS_BEFORE = {"note_id", "case_id", "author_id", "body", "created_at"}


# ---------------------------------------------------------------------------
# INT-T02 item 5a — `last_run`: the newest ② run, so "Phân tích gần nhất" is not "chưa phân tích"
# after a run that stopped (`cases.last_analyzed_at` is written only by a run with a result)
# ---------------------------------------------------------------------------


def _last_run(body: dict) -> tuple[datetime, bool]:
    """`(created_at, has_result)` of `body["last_run"]`, which has exactly these two keys."""
    run = body["last_run"]
    assert set(run) == {"created_at", "has_result"}
    return _instant(run["created_at"]), run["has_result"]


def _insert_investigate_run(
    conn: psycopg.Connection,
    case_id: str,
    *,
    created_at: datetime,
    result: dict | None = None,
    stopped_by: str | None = None,
) -> None:
    conn.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, role, system_prompt, "
        "user_message, result, stopped_by, created_at) VALUES (gen_random_uuid(), 'investigate', "
        "'case', %s, 'investigator', 's', 'u', %s::jsonb, %s, %s)",
        (case_id, json.dumps(result) if result is not None else None, stopped_by, created_at),
    )


@pytest.mark.db
def test_a_case_never_analysed_has_no_last_run(client, db):
    case_id = _make_case(db, client.user_id)

    body = client.http.get(f"/api/tier2/cases/{case_id}").json()

    assert body["last_run"] is None
    assert body["last_analyzed_at"] is None


@pytest.mark.db
def test_a_run_that_stopped_is_the_last_run_though_last_analyzed_at_is_still_empty(client, db):
    """The 402 of the owner's trial: ② ran, wrote a row with `stopped_by='permanent'` and no result,
    and `cases.last_analyzed_at` stayed NULL. The field must not say the case was never analysed."""
    case_id = _make_case(db, client.user_id)
    _insert_investigate_run(
        db, case_id, created_at=_T0 + timedelta(hours=1), stopped_by="permanent"
    )

    body = client.http.get(f"/api/tier2/cases/{case_id}").json()

    assert body["last_analyzed_at"] is None  # unchanged: it still means "a run with a result"
    assert _last_run(body) == (_T0 + timedelta(hours=1), False)


@pytest.mark.db
def test_a_run_with_a_result_is_the_last_run_with_a_result(client, db):
    case_id = _make_case(db, client.user_id, last_analyzed_at=_T0 + timedelta(hours=1))
    _insert_investigate_run(
        db, case_id, created_at=_T0 + timedelta(hours=1), result={"summary": "s"}
    )

    body = client.http.get(f"/api/tier2/cases/{case_id}").json()

    assert _last_run(body) == (_T0 + timedelta(hours=1), True)


@pytest.mark.db
def test_the_newest_run_wins_over_an_older_good_one_and_over_an_older_stopped_one(client, db):
    case_id = _make_case(db, client.user_id, last_analyzed_at=_T0 + timedelta(hours=1))
    _insert_investigate_run(db, case_id, created_at=_T0 + timedelta(hours=1), result={"s": 1})
    _insert_investigate_run(db, case_id, created_at=_T0 + timedelta(hours=3), stopped_by="cap")
    body = client.http.get(f"/api/tier2/cases/{case_id}").json()
    assert _last_run(body) == (_T0 + timedelta(hours=3), False)

    _insert_investigate_run(db, case_id, created_at=_T0 + timedelta(hours=5), result={"s": 2})
    body = client.http.get(f"/api/tier2/cases/{case_id}").json()
    assert _last_run(body) == (_T0 + timedelta(hours=5), True)


@pytest.mark.db
def test_only_this_cases_investigate_runs_count(client, db):
    case_id = _make_case(db, client.user_id)
    other = _make_case(db, client.user_id)
    _insert_investigate_run(db, other, created_at=_T0 + timedelta(hours=9), stopped_by="permanent")
    db.execute(  # a ① triage run whose subject_id happens to be this id is not ②
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, role, system_prompt, "
        "user_message, stopped_by, created_at) VALUES (gen_random_uuid(), 'triage', 'alert', %s, "
        "'proposer', 's', 'u', 'cap', %s)",
        (case_id, _T0 + timedelta(hours=9)),
    )

    body = client.http.get(f"/api/tier2/cases/{case_id}").json()

    assert body["last_run"] is None


@pytest.mark.db
def test_list_rows_carry_the_same_last_run_as_the_case_detail(client, db):
    """INT-T02 fix round 1, N4: the case list's "Phân tích gần nhất" follows the same rule as the
    case page, so one column title does not mean two things. One extra read for the page's ids; the
    list's SQL, its order and its paging are not touched."""
    u = client.user_id
    never = _make_case(db, u, title="never")
    stopped = _make_case(db, u, title="stopped")
    good = _make_case(db, u, title="good", last_analyzed_at=_T0 + timedelta(hours=1))
    newest_stopped = _make_case(db, u, title="newest-stopped", last_analyzed_at=_T0)
    _insert_investigate_run(
        db, stopped, created_at=_T0 + timedelta(hours=1), stopped_by="permanent"
    )
    _insert_investigate_run(db, good, created_at=_T0 + timedelta(hours=1), result={"s": 1})
    _insert_investigate_run(
        db, newest_stopped, created_at=_T0 + timedelta(hours=1), result={"s": 1}
    )
    _insert_investigate_run(
        db, newest_stopped, created_at=_T0 + timedelta(hours=2), stopped_by="cap"
    )
    db.execute(  # a ① triage run whose subject_id is a case id is not ②
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, role, system_prompt, "
        "user_message, stopped_by, created_at) VALUES (gen_random_uuid(), 'triage', 'alert', %s, "
        "'proposer', 's', 'u', 'cap', %s)",
        (never, _T0 + timedelta(hours=9)),
    )

    rows = {row["case_id"]: row for row in client.http.get("/api/tier2/cases").json()}

    assert rows[never]["last_run"] is None
    assert _last_run(rows[stopped]) == (_T0 + timedelta(hours=1), False)
    assert _last_run(rows[good]) == (_T0 + timedelta(hours=1), True)
    assert _last_run(rows[newest_stopped]) == (_T0 + timedelta(hours=2), False)
    for case_id, row in rows.items():  # the list and the detail answer the same
        if case_id in {never, stopped, good, newest_stopped}:
            detail = client.http.get(f"/api/tier2/cases/{case_id}").json()
            assert row["last_run"] == detail["last_run"]
            assert row["last_analyzed_at"] == detail["last_analyzed_at"]  # unchanged


@pytest.mark.db
def test_list_rows_keep_their_keys_their_order_and_their_paging_with_last_run(client, db):
    u = client.user_id
    ids = [_make_case(db, u, title=f"case-{i}") for i in range(3)]
    _insert_investigate_run(db, ids[1], created_at=_T0, stopped_by="permanent")

    every = client.http.get("/api/tier2/cases").json()
    page = client.http.get("/api/tier2/cases", params={"offset": 1, "limit": 1}).json()
    past_end = client.http.get("/api/tier2/cases", params={"offset": 10_000}).json()

    assert set(every[0]) == {
        "case_id",
        "title",
        "status",
        "severity",
        "created_at",
        "last_analyzed_at",
        "last_run",
        "cluster_count",
        "occurrence_count",
    }
    assert len(page) == 1 and page[0] == every[1]  # the same order, the same row
    assert past_end == []  # an empty page asks for no runs


@pytest.mark.db
def test_ongoing_still_follows_last_analyzed_at_not_a_run_that_stopped(client, db):
    """The new key changes what the field shows and nothing that is computed from the case: a
    stopped run is no analysis, so growth after the case was created is still `ongoing`."""
    u = client.user_id
    case_id = _make_case(db, u, created_at=_T0)
    head = _insert_alert(
        db, status="escalated_tier2", case_id=case_id, last_seen_at=_T0 + timedelta(hours=1)
    )
    _add_head(db, case_id, head, u)
    _insert_investigate_run(
        db, case_id, created_at=_T0 + timedelta(hours=2), stopped_by="permanent"
    )

    body = client.http.get(f"/api/tier2/cases/{case_id}").json()

    assert body["ongoing"] is True
    assert body["last_run"]["has_result"] is False


@pytest.mark.db
def test_existing_keys_unchanged(client, db):
    u = client.user_id
    case_id = _make_case(db, u, created_at=_T0)
    head = _insert_alert(db, status="escalated_tier2", case_id=case_id, last_seen_at=_T0)
    _add_head(db, case_id, head, u)
    conclude.add_note(db, case_id, u, "n")

    body = client.http.get(f"/api/tier2/cases/{case_id}").json()

    assert _CASE_KEYS_BEFORE <= set(body)
    assert _HEAD_KEYS_BEFORE <= set(body["heads"][0])
    assert _NOTE_KEYS_BEFORE <= set(body["notes"][0])
    assert {"concluded_by_name", "ongoing", "ongoing_last_seen"} <= set(body)
    assert {"raw_log", "raw_log_truncated", "risk_band", "last_seen_at"} <= set(body["heads"][0])
    assert "author_name" in body["notes"][0]


@pytest.mark.db
def test_a_head_carries_its_stored_duplicate_inclusive_occurrence_count(client, db):
    """`ingest/dedup.py`'s `bump_parent` is what increments a head's `occurrence_count` as
    duplicates arrive; the JSON carries that stored, already duplicate-inclusive column (the
    value the deleted page test pinned as 7), not a per-cluster 1 and not a count of the
    duplicate rows beside the head."""
    u = client.user_id
    case_id = _make_case(db, u, created_at=_T0)
    head = _insert_alert(db, status="escalated_tier2", case_id=case_id, last_seen_at=_T0)
    _add_head(db, case_id, head, u)
    for _ in range(2):
        _insert_alert(
            db,
            status="duplicate",
            duplicate_of=head,
            case_id=case_id,
            closed_at=_T0,
            sealed_at=_T0,
        )
    db.execute("UPDATE alerts SET occurrence_count = 7 WHERE alert_id = %s", (head,))

    body = client.http.get(f"/api/tier2/cases/{case_id}").json()

    (head_out,) = body["heads"]  # the duplicates are not heads
    assert head_out["alert_id"] == head
    assert head_out["occurrence_count"] == 7


@pytest.mark.db
def test_conclude_response_carries_the_new_fields(client, db):
    u = client.user_id
    case_id = _make_case(db, u, created_at=_T0)
    head = _insert_alert(
        db, status="escalated_tier2", case_id=case_id, raw_log="x", risk_score=10, last_seen_at=_T0
    )
    _add_head(db, case_id, head, u)
    conclude.add_note(db, case_id, u, "n")

    resp = client.http.post(
        f"/api/tier2/cases/{case_id}/conclude",
        json={"conclusion": "concluded_fp", "reason": "scanner"},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "concluded_fp"
    assert body["concluded_by_name"] == client.username
    assert body["ongoing"] is False  # heads are closed now
    assert body["ongoing_last_seen"] is None
    assert body["heads"][0]["raw_log"] == "x"
    assert body["heads"][0]["risk_band"] == "Thấp"
    assert "risk_score" not in body["heads"][0]
    assert body["notes"][0]["author_name"] == client.username


# ---------------------------------------------------------------------------
# usernames()
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_usernames_maps_known_ids_and_omits_unknown_and_none(db):
    a_id, a_name = _make_user(db)
    b_id, b_name = _make_user(db)

    got = case_view.usernames(db, {a_id, uuid.UUID(b_id), str(uuid.uuid4()), None})

    assert got == {a_id: a_name, b_id: b_name}
    assert case_view.usernames(db, set()) == {}
    assert case_view.usernames(db, {None}) == {}
