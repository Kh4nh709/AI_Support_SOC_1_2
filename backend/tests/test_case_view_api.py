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
