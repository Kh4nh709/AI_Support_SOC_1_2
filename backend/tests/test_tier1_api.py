"""API tests for `web/routers/tier1.py` over `TestClient` — the blind-branch proof at the
API for `tier1`, `tier2` and `admin`, and the six operations' error mapping (P4-T03).

**Stop-condition note (`prompts/P4.md:20,56`):** `llm_runs` holds 0 rows on `soc_dev` and
P3-T10 (the writer) is not merged — every suggestion-visible test below therefore inserts its
own proposer row in **P3-T10's shape** (P4-T02's fixture INSERT, copied verbatim) and depends
on P3 only for that shape, not for its merge.

`get_conn` is overridden with a generator that yields the `db` fixture's connection and never
commits — every test runs inside `db`'s transaction and is rolled back (conftest.py); `current_user`
is overridden per role (the `_Client.as_role` pattern from `test_labels.py`).
"""

from __future__ import annotations

import dataclasses
import hashlib
import itertools
import json
import uuid
from pathlib import Path
from typing import Any

import psycopg
import pytest
from app.domain import transitions
from app.domain.alert import Alert, AlertContext
from app.domain.transitions import AutocloseMatch, finish_enrichment, open_alert, start_enrichment
from app.infra import config
from app.infra.auth import Claims
from app.ingest.wazuh_parser import parse_wazuh_alert
from app.tier1 import decide as decide_module
from app.web import deps, main
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

pytestmark = pytest.mark.db

FIXTURES = Path(__file__).resolve().parent / "fixtures"
_CANONICAL: Alert = parse_wazuh_alert(
    json.loads((FIXTURES / "alert_40112.json").read_text(encoding="utf-8"))
).alert
assert _CANONICAL is not None

TIER1_ID = "00000000-0000-0000-0000-0000000404a1"
TIER2_ID = "00000000-0000-0000-0000-0000000404a2"
ADMIN_ID = "00000000-0000-0000-0000-0000000404a3"
TIER1_NAME = "P4-T03 tier1"

_EMPTY_CONTEXT = AlertContext(
    asset_present=False,
    asset_criticality="unknown",
    asset_owner=None,
    asset_role=None,
    identity_privileged=None,
    ioc_reputation="skipped",
    lookup_status={},
)

RESULT: dict[str, Any] = {
    "suggested_action": "false_positive",
    "confidence": "high",
    "structured_basis": {"severity": "critical", "occurrence_count": 1},
    "reasons": [{"claim": "c", "quote": "q", "source": "wazuh_raw_log"}],
    "playbook_used": None,
}
GATE: dict[str, Any] = {
    "proposed_verdict": "false_positive",
    "final_verdict": "false_positive",
    "forced": False,
    "forced_by": [],
    "warnings": [],
    "facts": {"correlated_clusters": 1},
    "verifier_verdict": "false_positive",
}

_counter = itertools.count()


# ---------------------------------------------------------------------------
# Fixture helpers (test_decide.py's pattern, copied)
# ---------------------------------------------------------------------------


def _hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _alert(**overrides: Any) -> Alert:
    n = next(_counter)
    alert_id = overrides.pop("alert_id", f"p4t03api-{n}")
    fields: dict[str, Any] = {"alert_id": alert_id, "event_bucket_hash": _hash(alert_id)}
    fields.update(overrides)
    return dataclasses.replace(_CANONICAL, **fields)


def _seed_users(conn: psycopg.Connection) -> None:
    for user_id, name, role in (
        (TIER1_ID, TIER1_NAME, "tier1"),
        (TIER2_ID, "P4-T03 tier2", "tier2"),
        (ADMIN_ID, "P4-T03 admin", "admin"),
    ):
        conn.execute(
            "INSERT INTO users (user_id, username, display_name, role, password_hash) "
            "VALUES (%s, %s, %s, %s, 'x') ON CONFLICT (user_id) DO NOTHING",
            (user_id, f"u{user_id[-6:]}", name, role),
        )


def _queued(
    conn: psycopg.Connection,
    *,
    suggestion_visible: bool = False,
    source: str = "wazuh",
    **overrides: Any,
) -> str:
    alert = _alert(**overrides)
    open_alert(conn, alert, kind="received", source=source, suggestion_visible=suggestion_visible)
    start_enrichment(conn, alert.alert_id)
    finish_enrichment(
        conn, alert.alert_id, context=_EMPTY_CONTEXT, risk_score=10, risk_components={}
    )
    return alert.alert_id


def _active(conn: psycopg.Connection, *, actor_id: str = TIER1_ID, **overrides: Any) -> str:
    alert_id = _queued(conn, **overrides)
    transitions.acknowledge(conn, alert_id, actor_id)
    return alert_id


def _autoclose_rule(conn: psycopg.Connection, created_by: str) -> str:
    """`autoclose_rules` FKs `created_by` to `users` — `rule_id` must be a real row."""
    rule_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO autoclose_rules (autoclose_rule_id, name, match, reason, created_by) "
        "VALUES (%s, %s, %s, %s, %s)",
        (rule_id, "p4t03api-idle", Jsonb({}), "idle_gap", created_by),
    )
    return rule_id


def _auto_closed(conn: psycopg.Connection, *, created_by: str = TIER1_ID, **overrides: Any) -> str:
    alert = _alert(**overrides)
    rule_id = _autoclose_rule(conn, created_by)
    open_alert(
        conn,
        alert,
        kind="auto_closed",
        source="wazuh",
        suggestion_visible=False,
        rule=AutocloseMatch(rule_id=rule_id, name="idle", reason="idle_gap"),
    )
    return alert.alert_id


def _insert_run(conn: psycopg.Connection, alert_id: str) -> str:
    """One `llm_runs` proposer row in P3-T10's shape (P4-T02's fixture INSERT)."""
    row = conn.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt, "
        "user_message, result, role, gate_result) "
        "VALUES (gen_random_uuid(), 'triage', 'alert', %s, 's', 'u', %s::jsonb, 'proposer', "
        "%s::jsonb) RETURNING run_id",
        (alert_id, json.dumps(RESULT), json.dumps(GATE)),
    ).fetchone()
    return str(row[0])


class _Client:
    """`TestClient` plus the role/user the overridden `current_user` answers as."""

    def __init__(self) -> None:
        self.http = TestClient(main.app)
        self.role = "tier1"
        self.user_id = TIER1_ID

    def as_role(self, role: str, user_id: str) -> _Client:
        self.role = role
        self.user_id = user_id
        return self

    def claims(self) -> Claims:
        return Claims(user_id=self.user_id, username=self.user_id, role=self.role, iat=0.0, exp=0.0)


@pytest.fixture
def client(db):
    _seed_users(db)
    c = _Client()

    def get_conn():
        # The real dependency's shape minus the success commit (review round 1,
        # item 9): a route's own exception still rolls back mid-request, exactly
        # like production, but a normal return never commits — every test stays
        # inside the `db` fixture's one transaction, rolled back at teardown.
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


_SUGGESTION_KEYS = (
    "suggestion",
    "suggested_action",
    "confidence",
    "gate_forced",
    "triage_status",
    "run_id",  # ANALYST_HIDE also drops the queue row's top-level run_id (DEC-101)
)


# ---------------------------------------------------------------------------
# The blind-branch proof
# ---------------------------------------------------------------------------


def test_api_blind_alert_has_no_suggestion_for_tier1_tier2_admin(db, client) -> None:
    alert_id = _queued(db, suggestion_visible=False)
    _insert_run(db, alert_id)

    for role, user_id in (("tier1", TIER1_ID), ("tier2", TIER2_ID), ("admin", ADMIN_ID)):
        client.as_role(role, user_id)
        resp = client.http.get(f"/api/tier1/alerts/{alert_id}")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        for key in _SUGGESTION_KEYS:
            assert key not in body, (role, key)
        assert "false_positive" not in resp.text


def test_api_blind_queue_row_has_no_suggestion_keys(db, client) -> None:
    alert_id = _queued(db, suggestion_visible=False)
    _insert_run(db, alert_id)

    client.as_role("tier1", TIER1_ID)
    resp = client.http.get("/api/tier1/queue", params={"page_size": 200})
    assert resp.status_code == 200, resp.text
    rows = [r for r in resp.json()["rows"] if r["alert_id"] == alert_id]
    assert len(rows) == 1
    row = rows[0]
    for key in _SUGGESTION_KEYS:
        assert key not in row, key
    assert "false_positive" not in resp.text


def test_api_after_decision_suggestion_appears_and_payload_joins(db, client) -> None:
    alert_id = _queued(db, suggestion_visible=False)
    run_id = _insert_run(db, alert_id)

    client.as_role("tier1", TIER1_ID)
    ack = client.http.post(f"/api/tier1/alerts/{alert_id}/acknowledge")
    assert ack.status_code == 200, ack.text

    dec = client.http.post(
        f"/api/tier1/alerts/{alert_id}/decide",
        json={"decision": "benign", "reason": "matches the KB", "seen_occurrence_count": 1},
    )
    assert dec.status_code == 200, dec.text

    view = client.http.get(f"/api/tier1/alerts/{alert_id}").json()
    assert view["suggestion"]["suggested_action"] == "false_positive"

    payload = db.execute(
        "SELECT payload FROM audit_events WHERE event_type = 'tier1.decided' AND subject_id = %s",
        (alert_id,),
    ).fetchone()[0]
    assert payload["llm_suggestion"] == "false_positive"
    assert payload["llm_confidence"] == "high"
    assert payload["gate_forced"] is False
    assert payload["suggestion_visible"] is False
    assert payload["llm_run_id"] == run_id


def test_api_visible_alert_shows_suggestion_before_decision(db, client) -> None:
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id)

    client.as_role("tier2", TIER2_ID)
    resp = client.http.get(f"/api/tier1/alerts/{alert_id}")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["suggestion"]["suggested_action"] == "false_positive"
    assert body["status"] == "queued_tier1"  # not yet decided


# ---------------------------------------------------------------------------
# Roles and error mapping
# ---------------------------------------------------------------------------


def test_api_tier2_post_decide_is_403_and_audited(db, client, monkeypatch, _test_database) -> None:
    """Review round 1, BLOCKER 1. `require_role`'s 403 path calls `conn.commit()`
    directly (planning decision 3) — on the shared `db` fixture connection that
    would make everything this test set up (the seeded users, the alert, the
    `authz.denied` row and, critically, the pending `triage` job `finish_
    enrichment` enqueues) permanent: `db`'s own `rollback()` at teardown only
    undoes what came *after* that commit, which is nothing. A leaked pending
    job is exactly what `test_triage_job.py::test_idle_timeout_survives_an_
    eleven_second_call` claimed instead of its own in review round 1's finding
    — not a timing flake.

    `db.commit` is monkeypatched to a spy: it records the `authz.denied` row
    for `TIER2_ID` at the moment of the real commit (still visible to `db`
    itself — read-your-own-writes, uncommitted or not) and does **not** call
    through, so nothing survives this test's own rollback. A second, entirely
    separate connection then proves it: no row of this test's making is
    visible to anyone else."""
    alert_id = _active(db)

    commits: list[list[tuple]] = []

    def _spy_commit() -> None:
        commits.append(
            db.execute(
                "SELECT payload FROM audit_events WHERE event_type = 'authz.denied' "
                "AND actor_id = %s",
                (TIER2_ID,),
            ).fetchall()
        )

    monkeypatch.setattr(db, "commit", _spy_commit)

    client.as_role("tier2", TIER2_ID)
    resp = client.http.post(
        f"/api/tier1/alerts/{alert_id}/decide",
        json={"decision": "benign", "reason": "x", "seen_occurrence_count": 1},
    )
    assert resp.status_code == 403, resp.text

    assert len(commits) == 1  # exactly one commit attempt
    assert len(commits[0]) == 1  # exactly one authz.denied row, at that moment
    assert commits[0][0][0]["required"] == ["tier1"]

    # Proof: a fresh, independent connection sees none of it — jobs, alerts, users.
    fresh = psycopg.connect(_test_database)
    try:
        counts = fresh.execute(
            "SELECT (SELECT count(*) FROM jobs WHERE subject_id = %s), "
            "(SELECT count(*) FROM alerts WHERE alert_id = %s), "
            "(SELECT count(*) FROM users WHERE user_id = %s)",
            (alert_id, alert_id, TIER2_ID),
        ).fetchone()
    finally:
        fresh.close()
    assert counts == (0, 0, 0), counts


def test_api_decide_409_body_has_n_and_m(db, client) -> None:
    alert_id = _active(db)
    db.execute("UPDATE alerts SET occurrence_count = 25 WHERE alert_id = %s", (alert_id,))

    client.as_role("tier1", TIER1_ID)
    resp = client.http.post(
        f"/api/tier1/alerts/{alert_id}/decide",
        json={"decision": "benign", "reason": "x", "seen_occurrence_count": 4},
    )
    assert resp.status_code == 409, resp.text
    body = resp.json()
    assert body["kind"] == "cluster_grew"
    assert body["occurrence_count"] == 25
    assert body["seen_occurrence_count"] == 4


@pytest.fixture
def real_shape_client(db, monkeypatch):
    """`get_conn` with the *real* dependency's shape (commit on success,
    rollback on exception) — needed only to prove a 409 rolls back before that
    commit would run (review round 1, item 4). `commit`/`rollback` are
    replaced by call recorders so nothing really persists; the genuine
    `rollback` is called explicitly at teardown, before handing back to the
    `db` fixture's own, so its teardown is never silently skipped."""
    calls: list[str] = []
    real_rollback = db.rollback
    monkeypatch.setattr(db, "commit", lambda: calls.append("commit"))
    monkeypatch.setattr(db, "rollback", lambda: calls.append("rollback"))

    def get_conn():
        try:
            yield db
        except BaseException:
            db.rollback()
            raise
        else:
            db.commit()

    main.app.dependency_overrides[deps.get_conn] = get_conn
    main.app.dependency_overrides[deps.get_config] = lambda: config.Config()
    main.app.dependency_overrides[deps.current_user] = lambda: Claims(
        user_id=TIER1_ID, username=TIER1_ID, role="tier1", iat=0.0, exp=0.0
    )
    try:
        yield TestClient(main.app), calls
    finally:
        for dep in (deps.get_conn, deps.get_config, deps.current_user):
            main.app.dependency_overrides.pop(dep, None)
        monkeypatch.undo()
        real_rollback()


def test_api_409_rolls_back_before_the_wrappers_commit(db, real_shape_client) -> None:
    """Review round 1, item 4. Without `_conflict_response`'s explicit
    `conn.rollback()`, a 409 `JSONResponse` is a normal *return*, not an
    exception — the real `get_conn` would take its `else: conn.commit()`
    branch and persist the guard's own reads (planning decision 3 is about
    the opposite direction: a *4xx that must persist a write* commits before
    raising; a 409 must persist nothing, so it must roll back before
    returning)."""
    _seed_users(db)
    http, calls = real_shape_client
    alert_id = _active(db)
    db.execute("UPDATE alerts SET occurrence_count = 25 WHERE alert_id = %s", (alert_id,))

    resp = http.post(
        f"/api/tier1/alerts/{alert_id}/decide",
        json={"decision": "benign", "reason": "x", "seen_occurrence_count": 4},
    )
    assert resp.status_code == 409, resp.text
    assert calls[:1] == ["rollback"], calls


def test_api_bad_body_is_422(db, client) -> None:
    alert_id = _active(db)
    client.as_role("tier1", TIER1_ID)
    resp = client.http.post(
        f"/api/tier1/alerts/{alert_id}/decide",
        json={"decision": "not_a_real_decision", "reason": "x", "seen_occurrence_count": 1},
    )
    assert resp.status_code == 422, resp.text


def test_api_unknown_alert_is_404(client) -> None:
    client.as_role("tier1", TIER1_ID)
    resp = client.http.get("/api/tier1/alerts/does-not-exist")
    assert resp.status_code == 404, resp.text


@pytest.mark.parametrize(
    "verb,body",
    [
        ("acknowledge", None),
        ("decide", {"decision": "benign", "reason": "x", "seen_occurrence_count": 1}),
        ("escalate", {"title": "t"}),
        ("reopen", {"reason": "x"}),
    ],
)
def test_api_unknown_alert_post_is_404_for_every_verb(client, verb, body) -> None:
    """Review round 1, item 5 — `decide` and `reopen` fell through to a 409
    (`transitions.*`'s own `StaleState` on a nonexistent id) before `tier1/
    decide.py` re-read `None` and raised `NotFound`; `acknowledge` and
    `escalate` already had their own `FOR UPDATE` guard and were always 404."""
    client.as_role("tier1", TIER1_ID)
    resp = client.http.post(f"/api/tier1/alerts/does-not-exist/{verb}", json=body)
    assert resp.status_code == 404, resp.text


def test_api_query_canceled_is_503(db, client, monkeypatch) -> None:
    alert_id = _active(db)

    def _raise(*args, **kwargs):
        raise psycopg.errors.QueryCanceled("simulated")

    monkeypatch.setattr(decide_module, "decide", _raise)
    client.as_role("tier1", TIER1_ID)
    resp = client.http.post(
        f"/api/tier1/alerts/{alert_id}/decide",
        json={"decision": "benign", "reason": "x", "seen_occurrence_count": 1},
    )
    assert resp.status_code == 503, resp.text
    assert resp.json() == {"detail": "fan-out timed out; nothing was written"}


def test_api_escalate_201_with_case(db, client) -> None:
    alert_id = _active(db)
    client.as_role("tier1", TIER1_ID)
    resp = client.http.post(
        f"/api/tier1/alerts/{alert_id}/escalate", json={"title": "brute force", "severity": "high"}
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["status"] == "escalated_tier2"
    assert body["case_id"]


def test_api_reopen_200(db, client) -> None:
    alert_id = _auto_closed(db)
    client.as_role("tier1", TIER1_ID)
    resp = client.http.post(
        f"/api/tier1/alerts/{alert_id}/reopen", json={"reason": "reviewed, was noise"}
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"alert_id": alert_id, "status": "queued_tier1"}


@pytest.mark.parametrize("verb", ["decide", "escalate", "reopen"])
def test_api_nul_byte_in_reason_or_title_is_422(db, client, verb) -> None:
    """Review round 1, item 10 — a NUL byte can never reach a query: rejected
    by the body's own Pydantic validation, before any DB call."""
    client.as_role("tier1", TIER1_ID)
    alert_id = _auto_closed(db) if verb == "reopen" else _active(db)
    body = {
        "decide": {"decision": "benign", "reason": "a\x00b", "seen_occurrence_count": 1},
        "escalate": {"title": "a\x00b"},
        "reopen": {"reason": "a\x00b"},
    }[verb]
    resp = client.http.post(f"/api/tier1/alerts/{alert_id}/{verb}", json=body)
    assert resp.status_code == 422, resp.text
