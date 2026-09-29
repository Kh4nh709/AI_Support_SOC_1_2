"""P4-T06 — the composed-tree end-to-end proof: three Tier-1 flows plus the auth
gate, walked through the **HTML** routes with real session cookies from
`POST /login` (`app.web.main.app` as it stands after every P4 card merged).

**Why a scratch database, not the shared `db` fixture (the Director's design
change on this card).** The card as written 19/09 called for
`app.dependency_overrides[deps.get_conn] = lambda: db` — the never-commits,
rolled-back-at-teardown wrapper other page-test files use. That shape is wrong
here: `require_role`'s 403 path and the login lockout path both call
`conn.commit()` *before* raising (P4-tasks.md planning decision 3), and a
`lambda: db` override still points at the one shared, module-scoped
`soc_p4t06_test` session database that `test_schema_v3_017.py` and every other
db-marked file in the same run reads from zero — so those commits would land
there and outlive this file. This already hit P4-T03, P5-T06 and P5-T09 (and,
before them, P5-T11 — see `test_health.py`'s own docstring at its `GET
/health` section). So this file builds, migrates and drops its **own**
scratch database, following `test_auth.py`'s `scratch_dsn`/`sdb` pattern for
the create/migrate/drop shape and `test_health.py`'s pattern for passing
`PGHOST`/`PGPORT`/`PGUSER`/`PGPASSWORD` to the bare `createdb`/`dropdb`
subprocess calls explicitly (never relied on from the ambient environment —
`order_proof.sh` does export them, but a bare `pytest -m db` invocation might
not). `get_conn` is overridden with the *real* dependency's shape — commit on
a normal return, rollback on any exception — so every request behaves exactly
as it does in production.

**Read first, for the assertions below.** The card was written 19/09;
`P4-T05.review.md`'s two review rounds changed the pages since, so this file
asserts them **as merged** at `969ce96`, not as the 19/09 card describes:
decide's success redirect is `/queue?flash=closed&n=<N>` (not bare `/queue`,
review S2); escalate answers `201` (not `200`) with
`/queue?flash=escalated&case=<8 hex>`; the decision controls
(Tiếp nhận/decide/escalate/reopen) render for `tier1` only — tier2/admin see
"Chỉ Tier 1 thao tác được" instead (review S3); a 409/422/503 renders as a
`#flash` fragment sitting outside `#decision`, never dropped by htmx (review
B1); an unknown alert is an HTML 404 page, never a bare JSON body (review
nit 7).

Every session is real: a seeded user's real password through `POST /login`,
the cookie jar carrying it — `current_user`/`page_user` are never overridden.
`follow_redirects=False` throughout; every SQL read below uses an explicit
column list (G10).
"""

from __future__ import annotations

import dataclasses
import hashlib
import itertools
import json
import os
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

#: P3-T10's shape (P4-T02's fixture, copied — `test_pages_alerts.py`'s `RESULT`/`GATE`):
#: `suggested_action`/`confidence` are what `_suggestion.html` prints verbatim, and
#: `p4t06_quote_marker` is the distinctive string this file greps for after a decision.
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
# Scratch database — build once per module, drop at the end (test_auth.py's
# scratch_dsn/sdb pattern; PG* passed explicitly, test_health.py's pattern).
# ---------------------------------------------------------------------------


def _scratch_source_parts() -> urllib.parse.SplitResult:
    session = os.environ.get("TEST_DATABASE_URL", conftest.DEFAULT_TEST_DATABASE_URL)
    return urllib.parse.urlsplit(session)


def _scratch_dbname() -> str:
    return f"{_scratch_source_parts().path.lstrip('/')}_e2e_test"


def _scratch_dsn(dbname: str) -> str:
    """A full DSN — scheme/host/port/user/password copied from `TEST_DATABASE_URL`,
    only the path (database name) replaced — never a bare `postgresql:///<name>`
    (test_health.py's `_scratch_dsn`: a host-less DSN resolves through this
    *process's* ambient `PGHOST`/`PGPORT`/`PGUSER`, which a bare `pytest -m db`
    invocation may not have populated)."""
    return urllib.parse.urlunsplit(_scratch_source_parts()._replace(path=f"/{dbname}"))


def _scratch_env(dsn: str) -> dict[str, str]:
    """`PGHOST`/`PGPORT`/`PGUSER`/`PGPASSWORD` for the bare `dropdb`/`createdb`
    calls below, derived from `dsn` itself — never relied on from the ambient
    environment (test_health.py's `_scratch_subprocess_env`)."""
    parts = urllib.parse.urlsplit(dsn)
    env = dict(os.environ)
    if parts.hostname:
        env["PGHOST"] = parts.hostname
    if parts.port:
        env["PGPORT"] = str(parts.port)
    if parts.username:
        env["PGUSER"] = urllib.parse.unquote(parts.username)
    if parts.password:
        env["PGPASSWORD"] = urllib.parse.unquote(parts.password)
    return env


@pytest.fixture(scope="module")
def scratch_dsn():
    if shutil.which("psql") is None or shutil.which("createdb") is None:
        pytest.skip("psql/createdb not on PATH — cannot build the e2e scratch database")
    dbname = _scratch_dbname()
    dsn = _scratch_dsn(dbname)
    env = _scratch_env(dsn)
    subprocess.run(["dropdb", "--if-exists", dbname], check=True, capture_output=True, env=env)
    subprocess.run(["createdb", dbname], check=True, capture_output=True, env=env)
    result = subprocess.run(
        ["bash", "scripts/migrate.sh", dsn],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"scratch migrate failed:\n{result.stderr}"
    try:
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
    """Installs a real-shape `get_conn` on the scratch connection — `try: yield
    conn; conn.commit()` / `except BaseException: conn.rollback(); raise`, the
    same shape `deps.get_conn` itself has (module docstring) — and yields the
    connection for the test's own fixture-building SQL. `current_user`/
    `page_user` are never overridden (hard rule): every session below is real."""

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
# Fixture helpers (test_pages_alerts.py's pattern, copied — its own docstring
# calls it "test_tier1_api.py's pattern, copied": each file stays
# self-contained rather than importing fixtures across cards).
# ---------------------------------------------------------------------------


def _hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _offset(**delta: float) -> Any:
    """`_BASE_TIME` plus a delta — every test below places its own heads at a
    distinct multi-hour offset so the ±2h correlation window
    (`domain/correlation.py`'s `_WINDOW_PREDICATE`) can never reach across
    test functions inside this file's one persistent scratch database (a
    commit-per-request `get_conn`, unlike the shared `db` fixture, does not
    roll a test's writes back at teardown)."""
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


def _duplicate(
    conn: psycopg.Connection, *, duplicate_of: str, suggestion_visible: bool, **overrides: Any
) -> str:
    alert = _alert(**overrides)
    open_alert(
        conn,
        alert,
        kind="duplicate",
        source="wazuh",
        suggestion_visible=suggestion_visible,
        duplicate_of=duplicate_of,
    )
    return alert.alert_id


def _autoclose_rule(conn: psycopg.Connection, created_by: str) -> str:
    rule_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO autoclose_rules (autoclose_rule_id, name, match, reason, created_by) "
        "VALUES (%s, %s, %s, %s, %s)",
        (rule_id, f"p4t06-idle-{uuid.uuid4().hex[:6]}", Jsonb({}), "idle_gap", created_by),
    )
    return rule_id


def _auto_closed(conn: psycopg.Connection, *, created_by: str, **overrides: Any) -> str:
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


# ---------------------------------------------------------------------------
# Flow 1 — decide with fan-out, and the blind branch for all three roles.
# ---------------------------------------------------------------------------


def test_flow_decide_fanout_and_blind_branch(app_conn) -> None:
    conn = app_conn
    t1_user, _t1_id = _seed_user(conn, role="tier1", prefix="t1")
    t2_user, _t2_id = _seed_user(conn, role="tier2", prefix="t2")
    adm_user, _adm_id = _seed_user(conn, role="admin", prefix="adm")

    # A: blind, highest risk, with 3 duplicates -> occurrence_count 4 (the fan-out).
    a_id = _queued(conn, suggestion_visible=False, risk_score=95, alert_time=_offset(hours=0))
    for _ in range(3):
        _duplicate(conn, duplicate_of=a_id, suggestion_visible=False)
    conn.execute("UPDATE alerts SET occurrence_count = 4 WHERE alert_id = %s", (a_id,))
    run_id = _insert_run(conn, a_id)
    # C: on A's agent 30 minutes later (correlated), lower risk -> sorts after A.
    c_id = _queued(
        conn,
        suggestion_visible=False,
        risk_score=20,
        alert_time=_offset(minutes=30),
    )
    conn.commit()

    t1 = TestClient(main.app, follow_redirects=False)
    t2 = TestClient(main.app, follow_redirects=False)
    adm = TestClient(main.app, follow_redirects=False)
    login(t1, t1_user, PASSWORD)
    login(t2, t2_user, PASSWORD)
    login(adm, adm_user, PASSWORD)

    # An unknown alert is an HTML 404 page (review nit 7), never a bare JSON body.
    resp = t1.get("/alerts/does-not-exist")
    assert resp.status_code == 404
    assert resp.headers["content-type"].startswith("text/html")
    assert "Không tìm thấy alert" in resp.text

    resp = t1.get("/queue")
    assert resp.status_code == 200
    assert resp.text.index(a_id) < resp.text.index(c_id)  # risk order: A (95) before C (20)

    # Blind branch, before the decision, for all three roles; the decision
    # controls render for tier1 only (review S3).
    for client, role in ((t1, "tier1"), (t2, "tier2"), (adm, "admin")):
        resp = client.get(f"/alerts/{a_id}")
        assert resp.status_code == 200
        assert "false_positive" not in resp.text
        assert "Gợi ý ① ẩn — nhánh mù." in resp.text
        if role == "tier1":
            assert "Tiếp nhận" in resp.text
        else:
            assert "Chỉ Tier 1 thao tác được" in resp.text
            assert "Tiếp nhận" not in resp.text

    resp = t1.post(f"/alerts/{a_id}/acknowledge")
    assert resp.status_code == 200
    assert 'name="seen_occurrence_count"' in resp.text
    assert 'value="4"' in resp.text

    resp = t2.post(f"/alerts/{a_id}/acknowledge")
    assert resp.status_code == 403

    resp = t1.post(
        f"/alerts/{a_id}/decide",
        data={"decision": "benign", "reason": "e2e", "seen_occurrence_count": "4"},
    )
    assert resp.status_code == 200
    assert resp.text == ""
    redirect = resp.headers["HX-Redirect"]
    # Review S2 — the success flash travels on the redirect target now, never
    # the 19/09 card's bare "/queue".
    assert redirect.startswith("/queue?flash=closed&n=")

    # DB: A and its 3 duplicates are closed_benign, sealed, A's triaged_count == 4.
    head = conn.execute(
        "SELECT status, closed_at, sealed_at, triaged_count FROM alerts WHERE alert_id = %s",
        (a_id,),
    ).fetchone()
    assert head[0] == "closed_benign"
    assert head[1] is not None
    assert head[2] is not None
    assert head[3] == 4
    dup_rows = conn.execute(
        "SELECT status, closed_at, sealed_at FROM alerts WHERE duplicate_of = %s", (a_id,)
    ).fetchall()
    assert len(dup_rows) == 3
    for status, closed_at, sealed_at in dup_rows:
        assert status == "closed_benign"
        assert closed_at is not None
        assert sealed_at is not None

    # Exactly one tier1.decided row, payload carrying the four join fields.
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
    t2_user, _t2_id = _seed_user(conn, role="tier2", prefix="t2")
    adm_user, _adm_id = _seed_user(conn, role="admin", prefix="adm")

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
    t2 = TestClient(main.app, follow_redirects=False)
    adm = TestClient(main.app, follow_redirects=False)
    login(t1, t1_user, PASSWORD)
    login(t2, t2_user, PASSWORD)
    login(adm, adm_user, PASSWORD)

    resp = t1.post(f"/alerts/{e_id}/acknowledge")
    assert resp.status_code == 200

    resp = t1.post(f"/alerts/{e_id}/escalate", data={"title": "e2e case"})
    # The card (19/09) expected 200; as merged the route is `status_code=201`.
    assert resp.status_code == 201
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

    case_alert_ids = {
        row[0]
        for row in conn.execute(
            "SELECT alert_id FROM case_alerts WHERE case_id = %s", (case_row[0],)
        ).fetchall()
    }
    assert case_alert_ids == {e_id, f_id}

    for alert_id in (e_id, f_id):
        status, sealed_at = conn.execute(
            "SELECT status, sealed_at FROM alerts WHERE alert_id = %s", (alert_id,)
        ).fetchone()
        assert status == "escalated_tier2"
        assert sealed_at is None  # H3

    event_types = {
        row[0]
        for row in conn.execute(
            "SELECT event_type FROM audit_events WHERE subject_id = %s", (e_id,)
        ).fetchall()
    }
    assert "tier1.escalated" in event_types
    case_event_types = {
        row[0]
        for row in conn.execute(
            "SELECT event_type FROM audit_events WHERE subject_id = %s", (str(case_row[0]),)
        ).fetchall()
    }
    assert "case.opened" in case_event_types

    resp = t1.get(redirect)
    assert resp.status_code == 200
    assert e_id not in resp.text
    assert f_id not in resp.text
    assert f"Đã mở case {case8}" in resp.text

    resp = t1.post(f"/alerts/{e_id}/escalate", data={"title": "again"})
    assert resp.status_code == 409

    # The case link: tier2/admin only (review S3's mirror image).
    for client in (t2, adm):
        resp = client.get(f"/alerts/{e_id}")
        assert resp.status_code == 200
        assert f'href="/cases/{case_row[0]}"' in resp.text
    resp = t1.get(f"/alerts/{e_id}")
    assert resp.status_code == 200
    assert f'href="/cases/{case_row[0]}"' not in resp.text
    assert f"Case: {case8}" in resp.text


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

    # The optimistic lock on B: acknowledge (seen == 1), then the cluster
    # grows behind the analyst's back (a count, not a status).
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
    # The #flash placeholder sits outside #decision (review B1's fix).
    assert 'id="flash"' in resp.text
    assert resp.text.index('id="flash"') < resp.text.index('<div id="decision">')
    # Both numbers (N the analyst saw, M the current count) in the flash text.
    assert "Cụm đã tăng từ 1 lên 22" in resp.text
    # The re-rendered form's hidden seen_occurrence_count equals the new M.
    assert 'name="seen_occurrence_count"' in resp.text
    assert 'value="22"' in resp.text

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

    resp = t1.get("/queue")
    assert resp.status_code == 200

    resp = t1.post("/logout")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"

    resp = t1.get("/queue")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"
