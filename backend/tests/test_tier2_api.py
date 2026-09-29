"""web/routers/tier2.py over the FastAPI app — the four §6.4 case operations,
`require_role("tier2", "admin")` refusing a `tier1` session with 403 and an
`authz.denied` row that survives the raise, the list's ordering and its
duplicate-inclusive count, and a 404 for a case that does not exist. P5-T06.

Every test runs inside the `db` fixture's transaction and is rolled back: the
overridden `get_conn` yields that connection and never commits (the pattern
`test_labels.py` uses).
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime

import psycopg
import pytest
from app.domain import transitions
from app.infra import config
from app.infra.auth import Claims
from app.tier2 import conclude
from app.web import deps, main
from fastapi.testclient import TestClient

pytestmark = pytest.mark.db

_PAST = datetime(2026, 1, 1, tzinfo=UTC)

# ---------------------------------------------------------------------------
# Fixture helpers — this file's own, mirroring test_conclude.py's
# ---------------------------------------------------------------------------


def _make_user(conn: psycopg.Connection, *, role: str = "tier2") -> str:
    user_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash) "
        "VALUES (%s, %s, %s, %s, 'x')",
        (user_id, f"user-{user_id[:8]}", "Test Analyst", role),
    )
    return user_id


def _make_case(
    conn: psycopg.Connection,
    user_id: str,
    *,
    title: str = "case",
    status: str = "investigating",
    created_at=None,
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
    return case_id


def _insert_alert(
    conn: psycopg.Connection,
    *,
    status: str,
    case_id: str | None = None,
    duplicate_of: str | None = None,
    closed_at=None,
    sealed_at=None,
) -> str:
    alert_id = f"p5t06-api-{uuid.uuid4()}"
    conn.execute(
        "INSERT INTO alerts (alert_id, rule_id, rule_level, severity, description, "
        "agent_name, alert_time, category, resolved_by, mapping_version, "
        "event_bucket_hash, raw_payload, status, duplicate_of, case_id, closed_at, sealed_at) "
        "VALUES (%s, '40112', 10, 'high', 'SSH brute force', 'agent-1', now(), "
        "'brute_force', 'rule_groups', 'v1', %s, '{}'::jsonb, %s, %s, %s, %s, %s)",
        (
            alert_id,
            hashlib.sha256(alert_id.encode()).hexdigest(),
            status,
            duplicate_of,
            case_id,
            closed_at,
            sealed_at,
        ),
    )
    return alert_id


def _add_head(conn: psycopg.Connection, case_id: str, alert_id: str, added_by: str) -> None:
    conn.execute(
        "INSERT INTO case_alerts (case_id, alert_id, added_by) VALUES (%s, %s, %s)",
        (case_id, alert_id, added_by),
    )


class _Client:
    """`TestClient` plus the user/role the overridden auth dependency answers
    as — the pattern `test_labels.py`'s `_Client` uses."""

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
        yield db  # never committed: the `db` fixture rolls everything back

    main.app.dependency_overrides[deps.get_conn] = get_conn
    main.app.dependency_overrides[deps.get_config] = lambda: config.Config()
    main.app.dependency_overrides[deps.current_user] = c.claims
    try:
        yield c
    finally:
        for dep in (deps.get_conn, deps.get_config, deps.current_user):
            main.app.dependency_overrides.pop(dep, None)


# ---------------------------------------------------------------------------
# require_role("tier2", "admin")
# ---------------------------------------------------------------------------


def test_tier1_role_gets_403_and_writes_authz_denied(client, db):
    client.role = "tier1"

    resp = client.http.get("/api/tier2/cases")

    assert resp.status_code == 403
    row = db.execute(
        "SELECT event_type FROM audit_events WHERE actor_id = %s ORDER BY audit_id DESC LIMIT 1",
        (client.user_id,),
    ).fetchone()
    assert row is not None
    assert row[0] == "authz.denied"


def test_admin_role_is_also_allowed(client, db):
    client.role = "admin"
    resp = client.http.get("/api/tier2/cases")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# GET /api/tier2/cases
# ---------------------------------------------------------------------------


def test_list_cases_orders_investigating_first_then_recent(client, db):
    u = client.user_id
    old_active = _make_case(db, u, title="old-active", created_at=_PAST)
    concluded = _make_case(
        db,
        u,
        title="done",
        status="concluded_fp",
        concluded_at=_PAST,
        concluded_by=u,
        conclusion_reason="x",
    )
    recent_active = _make_case(db, u, title="recent-active")

    resp = client.http.get("/api/tier2/cases")

    assert resp.status_code == 200
    ids = [row["case_id"] for row in resp.json()]
    assert ids.index(recent_active) < ids.index(old_active) < ids.index(concluded)


def test_list_cases_occurrence_count_includes_duplicates(client, db):
    u = client.user_id
    case_id = _make_case(db, u)
    head = _insert_alert(db, status="escalated_tier2", case_id=case_id)
    _add_head(db, case_id, head, u)
    for _ in range(4):
        _insert_alert(
            db,
            status="duplicate",
            duplicate_of=head,
            case_id=case_id,
            closed_at=_PAST,
            sealed_at=_PAST,
        )

    resp = client.http.get("/api/tier2/cases")

    row = next(r for r in resp.json() if r["case_id"] == case_id)
    assert row["cluster_count"] == 1
    assert row["occurrence_count"] == 5


def test_list_cases_is_offset_paged(client, db):
    u = client.user_id
    ids = [_make_case(db, u, title=f"case-{i}") for i in range(3)]

    page = client.http.get("/api/tier2/cases", params={"offset": 1, "limit": 1}).json()

    assert len(page) == 1
    assert page[0]["case_id"] in ids


# ---------------------------------------------------------------------------
# GET /api/tier2/cases/{case_id}
# ---------------------------------------------------------------------------


def test_case_detail_returns_heads_and_notes(client, db):
    u = client.user_id
    case_id = _make_case(db, u)
    head = _insert_alert(db, status="escalated_tier2", case_id=case_id)
    _add_head(db, case_id, head, u)
    conclude.add_note(db, case_id, u, "an analyst note")

    resp = client.http.get(f"/api/tier2/cases/{case_id}")

    assert resp.status_code == 200
    body = resp.json()
    assert body["case_id"] == case_id
    assert [h["alert_id"] for h in body["heads"]] == [head]
    assert "raw_log" not in body["heads"][0]
    assert len(body["notes"]) == 1
    assert body["notes"][0]["body"] == "an analyst note"


def test_case_detail_404_when_absent(client):
    resp = client.http.get(f"/api/tier2/cases/{uuid.uuid4()}")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/tier2/cases/{case_id}/notes
# ---------------------------------------------------------------------------


def test_notes_route_201_and_persists(client, db):
    case_id = _make_case(db, client.user_id)

    resp = client.http.post(f"/api/tier2/cases/{case_id}/notes", json={"body": "watch this"})

    assert resp.status_code == 201
    body = resp.json()
    assert body["body"] == "watch this"
    row = db.execute(
        "SELECT body FROM case_notes WHERE note_id = %s", (body["note_id"],)
    ).fetchone()
    assert row[0] == "watch this"


def test_notes_route_422_on_empty_body(client, db):
    case_id = _make_case(db, client.user_id)
    resp = client.http.post(f"/api/tier2/cases/{case_id}/notes", json={"body": "   "})
    assert resp.status_code == 422


def test_notes_route_404_on_unknown_case(client):
    resp = client.http.post(f"/api/tier2/cases/{uuid.uuid4()}/notes", json={"body": "orphan note"})
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/tier2/cases/{case_id}/conclude
# ---------------------------------------------------------------------------


def test_conclude_route_200_and_updates_status(client, db):
    u = client.user_id
    case_id = _make_case(db, u)
    head = _insert_alert(db, status="escalated_tier2", case_id=case_id)
    _add_head(db, case_id, head, u)

    resp = client.http.post(
        f"/api/tier2/cases/{case_id}/conclude",
        json={"conclusion": "concluded_fp", "reason": "scanner"},
    )

    assert resp.status_code == 200
    assert resp.json()["status"] == "concluded_fp"
    alert_status = db.execute("SELECT status FROM alerts WHERE alert_id = %s", (head,)).fetchone()[
        0
    ]
    assert alert_status == "closed_fp"


def test_conclude_route_409_when_already_concluded(client, db):
    u = client.user_id
    case_id = _make_case(
        db,
        u,
        status="concluded_fp",
        concluded_at=_PAST,
        concluded_by=u,
        conclusion_reason="prior",
    )

    resp = client.http.post(
        f"/api/tier2/cases/{case_id}/conclude",
        json={"conclusion": "confirmed_incident", "reason": "x"},
    )

    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["status"] == "concluded_fp"
    assert detail["concluded_by"] == u


def test_conclude_route_422_on_empty_reason(client, db):
    case_id = _make_case(db, client.user_id)
    resp = client.http.post(
        f"/api/tier2/cases/{case_id}/conclude",
        json={"conclusion": "concluded_fp", "reason": "  "},
    )
    assert resp.status_code == 422


def test_conclude_route_422_on_unknown_conclusion(client, db):
    case_id = _make_case(db, client.user_id)
    resp = client.http.post(
        f"/api/tier2/cases/{case_id}/conclude",
        json={"conclusion": "bogus", "reason": "x"},
    )
    assert resp.status_code == 422


def test_conclude_route_500_on_illegal_transition(client, db, monkeypatch):
    case_id = _make_case(db, client.user_id)

    def _boom(conn, cid, uid, *, conclusion, reason):
        raise transitions.IllegalTransition("no edge for this test")

    monkeypatch.setattr(conclude.transitions, "conclude_case", _boom)

    resp = client.http.post(
        f"/api/tier2/cases/{case_id}/conclude",
        json={"conclusion": "concluded_fp", "reason": "x"},
    )
    assert resp.status_code == 500


def test_conclude_route_503_on_statement_timeout(client, db, monkeypatch):
    case_id = _make_case(db, client.user_id)

    def _boom(conn, cid, uid, *, conclusion, reason):
        raise psycopg.errors.QueryCanceled("canceling statement due to statement timeout")

    monkeypatch.setattr(conclude.transitions, "conclude_case", _boom)

    resp = client.http.post(
        f"/api/tier2/cases/{case_id}/conclude",
        json={"conclusion": "concluded_fp", "reason": "x"},
    )
    assert resp.status_code == 503


def test_conclude_route_404_style_conflict_for_unknown_case(client):
    """`conclude_case`'s `StaleState` does not distinguish "never existed"
    from "already concluded" (design note 1) — both translate to 409, not
    404. Recorded here as the behaviour this card inherits, not adds."""
    resp = client.http.post(
        f"/api/tier2/cases/{uuid.uuid4()}/conclude",
        json={"conclusion": "concluded_fp", "reason": "x"},
    )
    assert resp.status_code == 409
    assert resp.json()["detail"]["status"] is None
