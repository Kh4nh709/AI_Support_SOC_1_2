"""P4-T06 — the composed-tree end-to-end proof: three Tier-1 flows plus the auth
gate, walked through the **HTML** routes with real session cookies from
`POST /login` (`app.web.main.app` as it stands after every P4 card merged).

**A scratch database, not the shared `db` fixture.** `require_role`'s 403 path and
the login lockout path both `conn.commit()` before raising, so a `lambda: db`
override would land those commits in the session-scoped test database
(`conftest._test_database`) that every other db-marked file reads from zero. This
module builds, migrates and drops its **own** database (`test_auth.py`'s
`scratch_dsn`/`sdb` shape, `PG*` passed explicitly to `createdb`/`dropdb` as
`test_health.py` does) and overrides `get_conn` with the real dependency's shape:
commit on a normal return, rollback on any exception.

Every session is real — a seeded user's password through `POST /login`, the cookie
jar carrying it; `current_user`/`page_user` are never overridden.
`follow_redirects=False` throughout; every SQL read uses an explicit column list
(G10).
"""

from __future__ import annotations

import dataclasses
import hashlib
import itertools
import json
import os
import re
import shutil
import subprocess
import urllib.parse
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

import psycopg
import pytest
from app.domain.alert import AlertContext
from app.domain.transitions import AutocloseMatch, finish_enrichment, open_alert, start_enrichment
from app.infra import auth, config
from app.ingest.wazuh_parser import parse_wazuh_alert
from app.web import deps, main
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from tests import conftest

pytestmark = pytest.mark.db

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
PASSWORD = "correct horse battery staple"

_CANONICAL = parse_wazuh_alert(
    json.loads((FIXTURES / "alert_40112.json").read_text(encoding="utf-8"))
).alert
assert _CANONICAL is not None
_BASE_TIME = _CANONICAL.alert_time

_counter = itertools.count()

_EMPTY_CONTEXT = AlertContext(
    asset_present=False,
    asset_criticality="unknown",
    asset_owner=None,
    asset_role=None,
    identity_privileged=None,
    ioc_reputation="skipped",
    lookup_status={"asset": "not_found", "identity": "skipped", "ioc": "skipped"},
)

#: P3-T10's proposer shape (`test_pages_alerts.py`'s `RESULT`/`GATE`, copied):
#: `suggested_action`/`confidence` are what the pages print verbatim, and
#: `p4t06_quote_marker` is the string this file greps for around the decision.
RESULT: dict[str, Any] = {
    "suggested_action": "false_positive",
    "confidence": "high",
    "reasons": [
        {"claim": "matches known pattern", "quote": "p4t06_quote_marker", "source": "wazuh_raw_log"}
    ],
}
GATE: dict[str, Any] = {
    "forced": False,
    "forced_by": [],
    "proposed_verdict": "false_positive",
    "final_verdict": "false_positive",
    "verifier_verdict": "false_positive",
    "warnings": [],
    "facts": {"correlated_clusters": 1},
}


# ---------------------------------------------------------------------------
# Scratch database — built once per module, dropped at the end.
# ---------------------------------------------------------------------------


def _scratch_target() -> tuple[str, str, dict[str, str]]:
    """`(dbname, dsn, env)` for the scratch database. The DSN is a full one —
    scheme/host/port/user/password copied from `TEST_DATABASE_URL`, only the database
    name replaced, never a bare `postgresql:///<name>` that would resolve through
    this process's ambient `PG*` — and `env` carries the same server as `PG*` for the
    bare `createdb`/`dropdb` calls (`test_health.py`'s pattern)."""
    parts = urllib.parse.urlsplit(
        os.environ.get("TEST_DATABASE_URL", conftest.DEFAULT_TEST_DATABASE_URL)
    )
    dbname = f"{parts.path.lstrip('/')}_e2e_test"
    env = dict(os.environ)
    if parts.hostname:
        env["PGHOST"] = parts.hostname
    if parts.port:
        env["PGPORT"] = str(parts.port)
    if parts.username:
        env["PGUSER"] = urllib.parse.unquote(parts.username)
    if parts.password:
        env["PGPASSWORD"] = urllib.parse.unquote(parts.password)
    return dbname, urllib.parse.urlunsplit(parts._replace(path=f"/{dbname}")), env


@pytest.fixture(scope="module")
def scratch_dsn():
    if shutil.which("psql") is None or shutil.which("createdb") is None:
        pytest.skip("psql/createdb not on PATH — cannot build the e2e scratch database")
    dbname, dsn, env = _scratch_target()
    subprocess.run(["dropdb", "--if-exists", dbname], check=True, capture_output=True, env=env)
    try:
        subprocess.run(["createdb", dbname], check=True, capture_output=True, env=env)
        result = subprocess.run(
            ["bash", "scripts/migrate.sh", dsn],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        # Not `assert result.returncode == 0`: pytest would print `result` whole,
        # argument list and DSN included (conftest.py's `_test_database`).
        if result.returncode != 0:
            pytest.fail(f"migrate failed (exit {result.returncode}):\n{result.stderr}")
        yield dsn
    finally:
        subprocess.run(["dropdb", "--if-exists", dbname], check=False, capture_output=True, env=env)


@pytest.fixture
def sdb(scratch_dsn):
    conn = psycopg.connect(scratch_dsn)
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


def _cfg(**overrides: Any) -> config.Config:
    """DEC-047: the secret is a literal on a `Config`, never read from `.env`."""
    return dataclasses.replace(config.Config(), JWT_SECRET="e2e-secret", **overrides)


@pytest.fixture
def app_conn(sdb):
    """Installs a real-shape `get_conn` on the scratch connection and yields the
    connection for the test's own fixture-building SQL."""

    def get_conn():
        try:
            yield sdb
        except BaseException:
            sdb.rollback()
            raise
        else:
            sdb.commit()

    main.app.dependency_overrides[deps.get_conn] = get_conn
    main.app.dependency_overrides[deps.get_config] = lambda: _cfg()
    try:
        yield sdb
    finally:
        main.app.dependency_overrides.pop(deps.get_conn, None)
        main.app.dependency_overrides.pop(deps.get_config, None)


# ---------------------------------------------------------------------------
# Fixture helpers (`test_pages_alerts.py`'s pattern, copied — each file stays
# self-contained rather than importing fixtures across cards).
# ---------------------------------------------------------------------------


def _hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _offset(**delta: float) -> Any:
    """`_BASE_TIME` plus a delta. Each flow places its heads at its own multi-hour
    offset so the ±2h correlation window (`domain/correlation.py`) never reaches
    across flows: the commit-per-request `get_conn` does not roll a test's writes
    back, so all four tests' data coexists in this module's one database."""
    return _BASE_TIME + timedelta(**delta)


def _alert(**overrides: Any):
    n = next(_counter)
    alert_id = overrides.pop("alert_id", f"p4t06-{n}-{uuid.uuid4().hex[:6]}")
    fields: dict[str, Any] = {"alert_id": alert_id, "event_bucket_hash": _hash(alert_id)}
    fields.update(overrides)
    return dataclasses.replace(_CANONICAL, **fields)


def _queued(
    conn: psycopg.Connection, *, suggestion_visible: bool, risk_score: int, **overrides: Any
) -> str:
    alert = _alert(**overrides)
    open_alert(conn, alert, kind="received", source="wazuh", suggestion_visible=suggestion_visible)
    start_enrichment(conn, alert.alert_id)
    finish_enrichment(
        conn, alert.alert_id, context=_EMPTY_CONTEXT, risk_score=risk_score, risk_components={}
    )
    return alert.alert_id


def _auto_closed(conn: psycopg.Connection, *, created_by: str, **overrides: Any) -> str:
    alert = _alert(**overrides)
    rule_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO autoclose_rules (autoclose_rule_id, name, match, reason, created_by) "
        "VALUES (%s, %s, %s, %s, %s)",
        (rule_id, f"p4t06-idle-{uuid.uuid4().hex[:6]}", Jsonb({}), "idle_gap", created_by),
    )
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
    """One `llm_runs` proposer row in P3-T10's shape."""
    row = conn.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt, "
        "user_message, result, role, gate_result) "
        "VALUES (gen_random_uuid(), 'triage', 'alert', %s, 's', 'u', %s::jsonb, 'proposer', "
        "%s::jsonb) RETURNING run_id",
        (alert_id, json.dumps(RESULT), json.dumps(GATE)),
    ).fetchone()
    return str(row[0])


def _seed_user(
    conn: psycopg.Connection, *, role: str, prefix: str, password: str = PASSWORD
) -> tuple[str, str]:
    username = f"p4t06-{prefix}-{uuid.uuid4().hex[:8]}"
    user_id = auth.create_user(
        conn, username=username, display_name=f"P4-T06 {prefix}", role=role, password=password
    )
    return username, user_id


def login(client: TestClient, username: str, password: str) -> None:
    resp = client.post("/login", data={"username": username, "password": password})
    assert resp.status_code == 303, resp.text
    assert deps.COOKIE_NAME in client.cookies


def _hidden_seen_count(value: int) -> re.Pattern[str]:
    """The decision form's hidden `seen_occurrence_count` input carrying `value`
    (a bare `value="22"` would also match any other attribute or text)."""
    return re.compile(rf'name="seen_occurrence_count"[^>]*value="{value}"')


# ---------------------------------------------------------------------------
# Flow 1 — decide with fan-out, and the blind branch for all three roles.
# ---------------------------------------------------------------------------


def test_flow_decide_fanout_and_blind_branch(app_conn) -> None:
    conn = app_conn
    t1_user, _t1_id = _seed_user(conn, role="tier1", prefix="t1")
    t2_user, _t2_id = _seed_user(conn, role="tier2", prefix="t2")
    adm_user, _adm_id = _seed_user(conn, role="admin", prefix="adm")

    # C first, committed on its own: `first_seen_at` defaults to `now()` (the
    # transaction start), so C is strictly older than A and the queue's
    # `first_seen_at ASC` tie-break would put C first — only `risk_score DESC`
    # can put A ahead of it.
    c_id = _queued(conn, suggestion_visible=False, risk_score=20, alert_time=_offset(minutes=30))
    conn.commit()
    # A: blind, highest risk, with 3 duplicates -> occurrence_count 4 (the fan-out).
    a_id = _queued(conn, suggestion_visible=False, risk_score=95, alert_time=_offset(hours=0))
    for _ in range(3):
        open_alert(
            conn,
            _alert(),
            kind="duplicate",
            source="wazuh",
            suggestion_visible=False,
            duplicate_of=a_id,
        )
    conn.execute("UPDATE alerts SET occurrence_count = 4 WHERE alert_id = %s", (a_id,))
    run_id = _insert_run(conn, a_id)
    conn.commit()

    t1 = TestClient(main.app, follow_redirects=False)
    t2 = TestClient(main.app, follow_redirects=False)
    adm = TestClient(main.app, follow_redirects=False)
    login(t1, t1_user, PASSWORD)
    login(t2, t2_user, PASSWORD)
    login(adm, adm_user, PASSWORD)

    resp = t1.get("/queue")
    assert resp.status_code == 200
    assert resp.text.index(a_id) < resp.text.index(c_id)  # risk 95 before 20, though C is older

    # Blind branch, before the decision, for all three roles: neither the queue's
    # ① column nor the detail page shows the suggestion or its quote, and the
    # decision controls render for tier1 only.
    for client, role in ((t1, "tier1"), (t2, "tier2"), (adm, "admin")):
        resp = client.get("/queue")
        assert resp.status_code == 200
        assert "false_positive" not in resp.text
        resp = client.get(f"/alerts/{a_id}")
        assert resp.status_code == 200
        assert "false_positive" not in resp.text
        assert "p4t06_quote_marker" not in resp.text
        assert "Gợi ý ① ẩn — nhánh mù." in resp.text
        if role == "tier1":
            assert "Tiếp nhận" in resp.text
        else:
            assert "Chỉ Tier 1 thao tác được" in resp.text
            assert "Tiếp nhận" not in resp.text

    resp = t1.post(f"/alerts/{a_id}/acknowledge")
    assert resp.status_code == 200
    assert _hidden_seen_count(4).search(resp.text)

    # tier2 is refused the tier1-only verb.
    resp = t2.post(f"/alerts/{a_id}/acknowledge")
    assert resp.status_code == 403

    resp = t1.post(
        f"/alerts/{a_id}/decide",
        data={"decision": "benign", "reason": "e2e", "seen_occurrence_count": "4"},
    )
    assert resp.status_code == 200
    assert resp.text == ""
    redirect = resp.headers["HX-Redirect"]
    # The success flash travels on the redirect target, never a bare "/queue".
    assert redirect.startswith("/queue?flash=closed&n=")

    # DB: A is closed_benign, sealed, triaged_count == 4; its 3 duplicates follow it.
    head = conn.execute(
        "SELECT status, closed_at IS NOT NULL, sealed_at IS NOT NULL, triaged_count "
        "FROM alerts WHERE alert_id = %s",
        (a_id,),
    ).fetchone()
    assert head == ("closed_benign", True, True, 4)
    dups = conn.execute("SELECT status FROM alerts WHERE duplicate_of = %s", (a_id,)).fetchall()
    assert dups == [("closed_benign",)] * 3

    # Exactly one tier1.decided row, payload carrying the join fields.
    decided_rows = conn.execute(
        "SELECT payload FROM audit_events WHERE event_type = 'tier1.decided' AND subject_id = %s",
        (a_id,),
    ).fetchall()
    assert len(decided_rows) == 1
    payload = decided_rows[0][0]
    assert payload["decision"] == "closed_benign"
    assert payload["llm_suggestion"] == "false_positive"
    assert payload["llm_confidence"] == "high"
    assert payload["gate_forced"] is False
    assert payload["suggestion_visible"] is False
    assert payload["llm_run_id"] == run_id

    n = urllib.parse.parse_qs(urllib.parse.urlsplit(redirect).query)["n"][0]
    assert n == "4"
    resp = t1.get(redirect)
    assert resp.status_code == 200
    assert a_id not in resp.text
    assert c_id in resp.text
    assert f"Đã đóng cụm ({n} alert)" in resp.text

    # Decided -> the suggestion shows, for every role (blind branch lifted).
    for client in (t1, t2, adm):
        resp = client.get(f"/alerts/{a_id}")
        assert resp.status_code == 200
        assert "false_positive" in resp.text
        assert "p4t06_quote_marker" in resp.text


# ---------------------------------------------------------------------------
# Flow 2 — escalate pulls the correlated head out of the queue.
# ---------------------------------------------------------------------------


def test_flow_escalate_pulls_correlated_head(app_conn) -> None:
    conn = app_conn
    t1_user, t1_id = _seed_user(conn, role="tier1", prefix="t1")

    agent = f"p4t06-escalate-{uuid.uuid4().hex[:6]}"
    e_id = _queued(
        conn, suggestion_visible=True, risk_score=50, agent_name=agent, alert_time=_offset(hours=8)
    )
    f_id = _queued(
        conn,
        suggestion_visible=True,
        risk_score=50,
        agent_name=agent,
        alert_time=_offset(hours=8, minutes=20),
    )
    conn.commit()

    t1 = TestClient(main.app, follow_redirects=False)
    login(t1, t1_user, PASSWORD)

    # Both heads are in the queue before the escalate.
    resp = t1.get("/queue")
    assert resp.status_code == 200
    assert e_id in resp.text
    assert f_id in resp.text

    resp = t1.post(f"/alerts/{e_id}/acknowledge")
    assert resp.status_code == 200

    resp = t1.post(f"/alerts/{e_id}/escalate", data={"title": "e2e case"})
    assert resp.status_code == 201  # as merged; the 19/09 card expected 200
    assert resp.text == ""
    redirect = resp.headers["HX-Redirect"]
    assert redirect.startswith("/queue?flash=escalated&case=")
    case8 = redirect.split("case=")[1].split("&")[0]

    case_row = conn.execute(
        "SELECT case_id, status FROM cases WHERE title = %s AND created_by = %s",
        ("e2e case", t1_id),
    ).fetchone()
    assert case_row is not None
    case_id, case_status = str(case_row[0]), case_row[1]
    assert case_status == "investigating"
    assert case_id[:8] == case8

    case_alerts = conn.execute(
        "SELECT alert_id FROM case_alerts WHERE case_id = %s", (case_row[0],)
    ).fetchall()
    assert {row[0] for row in case_alerts} == {e_id, f_id}

    heads = conn.execute(
        "SELECT alert_id, status, sealed_at IS NULL FROM alerts WHERE alert_id IN (%s, %s)",
        (e_id, f_id),
    ).fetchall()
    assert set(heads) == {(e_id, "escalated_tier2", True), (f_id, "escalated_tier2", True)}  # H3

    events = conn.execute(
        "SELECT subject_id, event_type FROM audit_events WHERE subject_id IN (%s, %s)",
        (e_id, case_id),
    ).fetchall()
    assert {(e_id, "tier1.escalated"), (case_id, "case.opened")} <= set(events)

    resp = t1.get(redirect)
    assert resp.status_code == 200
    assert e_id not in resp.text
    assert f_id not in resp.text
    assert f"Đã mở case {case8}" in resp.text

    resp = t1.post(f"/alerts/{e_id}/escalate", data={"title": "again"})
    assert resp.status_code == 409


# ---------------------------------------------------------------------------
# Flow 3 — reopen only from auto_closed, and the 409 with N and M.
# ---------------------------------------------------------------------------


def test_flow_reopen_and_optimistic_lock(app_conn) -> None:
    conn = app_conn
    t1_user, t1_id = _seed_user(conn, role="tier1", prefix="t1")

    b_id = _queued(conn, suggestion_visible=True, risk_score=50, alert_time=_offset(hours=16))
    c_id = _queued(
        conn, suggestion_visible=True, risk_score=50, alert_time=_offset(hours=16, minutes=5)
    )
    d_id = _auto_closed(conn, created_by=t1_id, alert_time=_offset(hours=16, minutes=10))
    conn.commit()

    t1 = TestClient(main.app, follow_redirects=False)
    login(t1, t1_user, PASSWORD)

    resp = t1.post(f"/alerts/{d_id}/reopen", data={"reason": "e2e"})
    assert resp.status_code == 200
    assert resp.text == ""
    assert resp.headers["HX-Redirect"] == f"/alerts/{d_id}"
    status = conn.execute("SELECT status FROM alerts WHERE alert_id = %s", (d_id,)).fetchone()[0]
    assert status == "queued_tier1"

    # C is queued_tier1, not auto_closed -> not reopenable.
    resp = t1.post(f"/alerts/{c_id}/reopen", data={"reason": "e2e"})
    assert resp.status_code == 409

    # The optimistic lock on B: acknowledge (seen == 1), then the cluster grows
    # behind the analyst's back (a count, not a status).
    resp = t1.post(f"/alerts/{b_id}/acknowledge")
    assert resp.status_code == 200
    conn.execute(
        "UPDATE alerts SET occurrence_count = occurrence_count + 21 WHERE alert_id = %s", (b_id,)
    )
    conn.commit()

    resp = t1.post(
        f"/alerts/{b_id}/decide",
        data={"decision": "benign", "reason": "e2e", "seen_occurrence_count": "1"},
    )
    assert resp.status_code == 409
    assert resp.headers["content-type"].startswith("text/html")
    # The #flash placeholder sits outside #decision, so htmx cannot drop it.
    assert 'id="flash"' in resp.text
    assert resp.text.index('id="flash"') < resp.text.index('<div id="decision">')
    # Both numbers (N the analyst saw, M the current count) in the flash text.
    assert "Cụm đã tăng từ 1 lên 22" in resp.text
    # The re-rendered form's hidden seen_occurrence_count equals the new M.
    assert _hidden_seen_count(22).search(resp.text)

    resp = t1.post(
        f"/alerts/{b_id}/decide",
        data={"decision": "benign", "reason": "e2e", "seen_occurrence_count": "22"},
    )
    assert resp.status_code == 200
    assert resp.headers["HX-Redirect"].startswith("/queue?flash=closed&n=")


# ---------------------------------------------------------------------------
# Auth on the way: the unauthenticated redirect, the lockout, and logout.
# ---------------------------------------------------------------------------


def test_auth_gates_pages_and_logout_kills_session(app_conn) -> None:
    conn = app_conn

    anon = TestClient(main.app, follow_redirects=False)
    resp = anon.get("/queue")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"

    username, user_id = _seed_user(conn, role="tier1", prefix="lock")
    conn.commit()

    t1 = TestClient(main.app, follow_redirects=False)
    for _ in range(4):
        resp = t1.post("/login", data={"username": username, "password": "wrong"})
        assert resp.status_code == 401
    resp = t1.post("/login", data={"username": username, "password": "wrong"})
    assert resp.status_code == 423

    conn.execute(
        "UPDATE users SET locked_until = NULL, failed_logins = 0 WHERE user_id = %s", (user_id,)
    )
    conn.commit()
    login(t1, username, PASSWORD)
    old_cookie = t1.cookies.get(deps.COOKIE_NAME)
    assert old_cookie

    resp = t1.get("/queue")
    assert resp.status_code == 200

    resp = t1.post("/logout")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"

    # The client jar dropped the cookie, so this only proves the cookie was cleared.
    resp = t1.get("/queue")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"

    # The session itself is dead: a stale copy of the SAME token, sent by a fresh
    # client, is refused server-side.
    replay = TestClient(main.app, follow_redirects=False)
    resp = replay.get("/queue", headers={"cookie": f"{deps.COOKIE_NAME}={old_cookie}"})
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"
