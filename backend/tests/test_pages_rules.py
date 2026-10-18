"""P5-T10 — the admin rules screen: `web/routers/admin_rules.py`,
`web/templates/rules.html`. A screen over three functions `app.ingest.autoclose`
already has and already tests (`simulate`, `rule_width_report`, `reload_rules`)
— this file inserts alerts and rules directly with plain SQL and never imports
from `test_autoclose.py` (a different card's test file, out of this card's
scope), so it stays self-contained.

Every db-marked test uses the shared `db` fixture, overridden into the app as
`deps.get_conn` directly (no commit/rollback shape — `test_reload_inventory.py`'s
pattern): every write in a test is visible to that same test's own assertions
because they share one uncommitted transaction, and the fixture's teardown
rolls the whole thing back. `pages.page_user` and `deps.current_user` are both
overridden (P5-T10's routes mix `page_user`-gated HTML routes and
`require_role("admin")`-gated API routes, and `page_user` does not go through
`deps.current_user` — it reads the cookie/token directly via `optional_user`).

One exception: `deps.require_role`'s dependency commits *before* raising its
403 (P4 planning decision 3 — the `authz.denied` row must survive), and that
commit is real and permanent regardless of the `db` fixture's later rollback.
Run on the shared session database, it would leak an `audit_events` row past
this file into whichever test runs next in the same `make test-db` session —
measured: `test_schema_v3_017.py` sorts after `test_pages_rules.py` and
assumes `audit_events` starts empty, so it broke on exactly this leak the
first time this test used the shared `db` fixture. `test_non_admin_is_refused`
below therefore gets its own scratch database (`test_pages_login.py`'s
pattern), so its one real commit never reaches a shared table.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import shutil
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg
import pytest
from app.domain.alert import Alert, AlertContext
from app.infra import auth, config
from app.infra.auth import Claims
from app.ingest import autoclose
from app.web import deps, main
from app.web.routers import admin_rules, pages
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from tests import conftest

REPO_ROOT = Path(__file__).resolve().parents[2]
REASON_MATCH_EVERYTHING = "[]"
_ALERT_TIME = datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _reset_rule_cache():
    autoclose._rule_cache = None
    yield
    autoclose._rule_cache = None


def _alert(**overrides: Any) -> Alert:
    """A `severity=medium`, non-privileged, present-asset alert — the only
    G8'-closable shape (test_autoclose.py's `_alert`/`_ctx` factories'
    intent, reproduced here so this file imports nothing from another card's
    test module)."""
    fields: dict[str, Any] = {
        "alert_id": "p5t10-cache-alert",
        "manager_id": "IA1803",
        "rule_id": "40112",
        "description": "d",
        "agent_name": "some-agent",
        "agent_id": "001",
        "agent_ip": None,
        "origin_host": "some-agent",
        "alert_time": _ALERT_TIME,
        "event_time": None,
        "srcip": "127.0.0.1",
        "dstip": "",
        "src_port": 1,
        "dst_port": 0,
        "alert_user": "user1",
        "decoder": "sshd",
        "mitre_ids": (),
        "rule_groups": (),
        "rule_level": 5,
        "severity": "medium",
        "category": "generic",
        "categories": (),
        "resolved_by": "none",
        "mapping_version": "v1",
        "srcip_is_private": True,
        "dstip_is_private": None,
        "raw_log": "log",
        "raw_log_truncated": False,
        "event_bucket_hash": "0" * 64,
        "raw_payload": {},
    }
    fields.update(overrides)
    return Alert(**fields)


def _ctx(**overrides: Any) -> AlertContext:
    fields: dict[str, Any] = {
        "asset_present": True,
        "asset_criticality": "medium",
        "asset_owner": None,
        "asset_role": None,
        "identity_privileged": False,
        "ioc_reputation": "not_found",
        "lookup_status": {"asset": "found", "identity": "found", "ioc": "not_found"},
    }
    fields.update(overrides)
    return AlertContext(**fields)


def _scoped(html: str, marker: str, *, until: str = "</ul>") -> str:
    """The substring of `html` from `marker` up to the next `until` — scopes
    an assertion to one `data-field=`/`id=` block instead of the whole page
    (review round 1: two adjacent breakdowns made a loose substring check
    pass for reasons that had nothing to do with the thing under test)."""
    start = html.index(marker)
    end = html.index(until, start)
    return html[start:end]


# ---------------------------------------------------------------------------
# Factories — plain SQL, minimal columns, the two CHECKs that bite here
# satisfied explicitly: ck_alerts_hash_sha256_hex (64 hex chars) and
# ck_alerts_g3_terminal_phai_co_closed_at (a terminal status needs closed_at).
# ---------------------------------------------------------------------------


def _insert_alert(
    conn: Any,
    *,
    alert_id: str,
    severity: str = "medium",
    agent_name: str = "some-agent",
    occurrence_count: int = 1,
    status: str = "received",
    autoclose_rule_id: str | None = None,
    asset_context: dict | None = None,
    identity_context: dict | None = None,
    ioc_context: dict | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO alerts (
            alert_id, rule_id, rule_level, severity, description, agent_name, alert_time,
            category, resolved_by, mapping_version, event_bucket_hash, raw_payload,
            status, occurrence_count, autoclose_rule_id, closed_at,
            asset_context, identity_context, ioc_context
        ) VALUES (
            %(alert_id)s, '1', 5, %(severity)s, 'd', %(agent_name)s, now(),
            'generic', 'none', 'v1', %(event_bucket_hash)s, %(raw_payload)s,
            %(status)s, %(occurrence_count)s, %(autoclose_rule_id)s,
            CASE WHEN %(status)s = 'received' THEN NULL ELSE now() END,
            %(asset_context)s, %(identity_context)s, %(ioc_context)s
        )
        """,
        {
            "alert_id": alert_id,
            "severity": severity,
            "agent_name": agent_name,
            "event_bucket_hash": hashlib.sha256(alert_id.encode()).hexdigest(),
            "raw_payload": Jsonb({}),
            "status": status,
            "occurrence_count": occurrence_count,
            "autoclose_rule_id": autoclose_rule_id,
            "asset_context": Jsonb(asset_context) if asset_context is not None else None,
            "identity_context": Jsonb(identity_context) if identity_context is not None else None,
            "ioc_context": Jsonb(ioc_context) if ioc_context is not None else None,
        },
    )


def _insert_rule(
    conn: Any,
    *,
    rule_id: str,
    created_by: str,
    match: list | None = None,
    name: str = "r",
    reason: str = "t",
    enabled: bool = True,
) -> None:
    conn.execute(
        "INSERT INTO autoclose_rules (autoclose_rule_id, name, enabled, match, reason, created_by) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (rule_id, name, enabled, Jsonb(match if match is not None else []), reason, created_by),
    )


def _seed_admin(conn: Any, *, prefix: str = "admin") -> tuple[str, Claims]:
    user_id = auth.create_user(
        conn,
        username=f"p5t10-{prefix}-{uuid.uuid4().hex[:8]}",
        display_name="P5-T10 Admin",
        role="admin",
        password="unused",
    )
    claims = Claims(user_id=user_id, username="p5t10-admin", role="admin", iat=0.0, exp=0.0)
    return user_id, claims


# ---------------------------------------------------------------------------
# The client — get_conn -> db; page_user and current_user -> a fixed Claims
# ---------------------------------------------------------------------------


@pytest.fixture
def client(db):
    admin_id, claims = _seed_admin(db)
    main.app.dependency_overrides[deps.get_conn] = lambda: db
    main.app.dependency_overrides[deps.current_user] = lambda: claims
    main.app.dependency_overrides[pages.page_user] = lambda: claims
    try:
        yield TestClient(main.app, follow_redirects=False), db, admin_id
    finally:
        main.app.dependency_overrides.pop(deps.get_conn, None)
        main.app.dependency_overrides.pop(deps.current_user, None)
        main.app.dependency_overrides.pop(pages.page_user, None)


# ---------------------------------------------------------------------------
# The preview: renders every SimulateStats field, writes nothing
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_preview_writes_nothing(client) -> None:
    """Also the card's own acceptance-1 name: renders every `SimulateStats`
    field and writes nothing (design note 6)."""
    tc, db, _ = client
    # severity "low" (distinct from asset_criticality "medium") so each
    # breakdown's own value is pinned inside its own data-field list, not
    # found only because the other breakdown's text happens to match too.
    _insert_alert(
        db,
        alert_id="prev-1",
        severity="low",
        asset_context={"present": True, "criticality": "medium"},
        identity_context={"privileged": False},
        ioc_context={"reputation": "not_found"},
    )
    resp = tc.post(
        "/admin/rules/preview",
        data={"name": "n", "reason": "r", "match_json": REASON_MATCH_EVERYTHING},
    )
    assert resp.status_code == 200
    assert 'data-field="clusters">1<' in resp.text
    assert 'data-field="alerts">1<' in resp.text
    assert "low: 1" in _scoped(resp.text, 'data-field="by_severity"')
    assert "medium: 1" in _scoped(resp.text, 'data-field="by_asset_criticality"')
    # samples, as a link to the alert page of the new UI (P10-T13: the Jinja alert page is
    # gone; the link keeps the host the admin came in on and changes only the port)
    assert "prev-1" in resp.text
    assert 'href="http://testserver:8080/alerts/prev-1"' in resp.text
    assert 'href="/alerts/' not in resp.text

    count = db.execute("SELECT count(*) FROM autoclose_rules").fetchone()[0]
    assert count == 0


@pytest.mark.db
def test_preview_samples_are_plain_ids_when_the_host_header_is_not_a_plain_host(client) -> None:
    """P10-T13: the sample links are built from the request's own host; a `Host` header with a
    path in it gets no link at all (`pages.new_ui_url` refuses it), and the id is still shown."""
    tc, db, _ = client
    _insert_alert(
        db,
        alert_id="prev-2",
        severity="low",
        asset_context={"present": True, "criticality": "medium"},
        identity_context={"privileged": False},
        ioc_context={"reputation": "not_found"},
    )
    resp = tc.post(
        "/admin/rules/preview",
        data={"name": "n", "reason": "r", "match_json": REASON_MATCH_EVERYTHING},
        headers={"host": "127.0.0.1:8000/evil"},
    )
    assert resp.status_code == 200
    assert "prev-2" in resp.text
    assert "<a href=" not in _scoped(resp.text, 'data-field="samples"')
    assert "evil" not in resp.text


@pytest.mark.db
def test_whitelist_violation_renders_422_flash_naming_the_field(client) -> None:
    tc, db, _ = client
    resp = tc.post(
        "/admin/rules/preview",
        data={
            "name": "n",
            "reason": "r",
            "match_json": '[{"field": "risk_score", "op": "lte", "value": 10}]',
        },
    )
    assert resp.status_code == 422
    assert "risk_score" in resp.text
    count = db.execute("SELECT count(*) FROM autoclose_rules").fetchone()[0]
    assert count == 0


# ---------------------------------------------------------------------------
# The empty-preview tally — review round 1: counts only rows the candidate
# rule's own conditions match, never the whole 30-day window
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_empty_preview_tally_counts_only_rows_the_rule_matches(client) -> None:
    tc, _db, _ = client
    # Matches the rule (agent_name = some-agent) and is hard-blocked
    # (asset absent) — counted.
    _insert_alert(
        _db,
        alert_id="tally-blocked",
        agent_name="some-agent",
        severity="medium",
        asset_context={"present": False, "criticality": "unknown"},
        identity_context={"privileged": False},
        ioc_context={"reputation": "not_found"},
    )
    # Also hard-blocked the same way, but the rule's own condition
    # (agent_name) does not match it — must NOT be counted.
    _insert_alert(
        _db,
        alert_id="tally-not-matched",
        agent_name="other-agent",
        severity="medium",
        asset_context={"present": False, "criticality": "unknown"},
        identity_context={"privileged": False},
        ioc_context={"reputation": "not_found"},
    )
    match = '[{"field": "agent_name", "op": "eq", "value": "some-agent"}]'
    resp = tc.post("/admin/rules/preview", data={"name": "n", "reason": "r", "match_json": match})
    assert resp.status_code == 200
    assert 'data-field="clusters">0<' in resp.text
    assert 'data-field="tally_matched">1<' in resp.text
    tally = _scoped(resp.text, 'id="empty-preview-tally"', until="</div>")
    asset_row = _scoped(tally, 'data-block="asset_not_in_inventory"', until="</li>")
    assert ": 1" in asset_row
    assert "tally-not-matched" not in resp.text  # not a sample either — 0 clusters


@pytest.mark.db
def test_empty_preview_tally_says_no_match_when_the_rule_matches_nothing(client) -> None:
    tc, _db, _ = client
    # Closable by every predicate, but the rule below names a different agent.
    _insert_alert(
        _db,
        alert_id="tally-none",
        agent_name="some-agent",
        severity="medium",
        asset_context={"present": True, "criticality": "medium"},
        identity_context={"privileged": False},
        ioc_context={"reputation": "not_found"},
    )
    match = '[{"field": "agent_name", "op": "eq", "value": "nobody-matches-this"}]'
    resp = tc.post("/admin/rules/preview", data={"name": "n", "reason": "r", "match_json": match})
    assert resp.status_code == 200
    assert 'data-field="clusters">0<' in resp.text
    assert 'data-field="tally_none"' in resp.text


# ---------------------------------------------------------------------------
# Create: writes the row, the audit event, and is live without the cache TTL
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_create_writes_row_audit_and_makes_load_rules_return_it_immediately(client) -> None:
    tc, db, admin_id = client
    alert, ctx = _alert(), _ctx()
    # Warm the 60 s rule cache first, as "no rules" — evaluate()'s normal,
    # cached path (`_cached_rules`). `load_rules()` alone never touches this
    # cache (it always re-queries), so it cannot discriminate reload_rules()
    # being called or not — evaluate() is what design note 6 actually needs.
    assert autoclose.evaluate(db, alert, ctx).match is None

    resp = tc.post(
        "/admin/rules",
        data={"name": "everything", "reason": "test rule", "match_json": REASON_MATCH_EVERYTHING},
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin/rules"

    row = db.execute(
        "SELECT autoclose_rule_id, name, enabled, created_by FROM autoclose_rules"
    ).fetchone()
    assert row is not None
    rule_id, name, enabled, created_by = row
    assert name == "everything"
    assert enabled is True
    assert str(created_by) == admin_id

    audit_row = db.execute(
        "SELECT actor_id, payload FROM audit_events "
        "WHERE event_type = 'admin.autoclose_rule_toggled' AND subject_id = %s",
        (str(rule_id),),
    ).fetchone()
    assert audit_row is not None
    actor_id, payload = audit_row
    assert str(actor_id) == admin_id
    assert payload == {"name": "everything", "before": False, "after": True}

    # Live immediately, from the SAME still-warm cache window — no waiting
    # for RULE_CACHE_TTL_S (design note 6; DEC-025 red case (a)).
    after = autoclose.evaluate(db, alert, ctx)
    assert after.match is not None
    assert after.match.rule_id == str(rule_id)


@pytest.mark.db
def test_create_whitelist_violation_renders_422_and_writes_nothing(client) -> None:
    tc, db, _ = client
    resp = tc.post(
        "/admin/rules",
        data={
            "name": "n",
            "reason": "r",
            "match_json": '[{"field": "risk_score", "op": "lte", "value": 10}]',
        },
    )
    assert resp.status_code == 422
    assert "risk_score" in resp.text
    count = db.execute("SELECT count(*) FROM autoclose_rules").fetchone()[0]
    assert count == 0


# ---------------------------------------------------------------------------
# Toggle: writes before/after, flips the rule's effect, live immediately
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_toggle_is_live_without_waiting_for_the_cache(client) -> None:
    """The card's own acceptance-1 name: writes before/after and flips the
    rule's effect without waiting for `RULE_CACHE_TTL_S` (design note 6)."""
    tc, db, admin_id = client
    rule_id = str(uuid.uuid4())
    _insert_rule(db, rule_id=rule_id, created_by=admin_id, match=[], enabled=True)

    alert, ctx = _alert(), _ctx()
    # Warm the cache with the rule enabled first (the cached `evaluate()`
    # path — `load_rules()` alone always re-queries and cannot discriminate
    # reload_rules() being called or not, see the create test above).
    before = autoclose.evaluate(db, alert, ctx)
    assert before.match is not None
    assert before.match.rule_id == rule_id

    resp = tc.post(f"/admin/rules/{rule_id}/toggle", data={"enabled": "false"})
    assert resp.status_code == 303

    enabled = db.execute(
        "SELECT enabled FROM autoclose_rules WHERE autoclose_rule_id = %s", (rule_id,)
    ).fetchone()[0]
    assert enabled is False

    payload = db.execute(
        "SELECT payload FROM audit_events "
        "WHERE event_type = 'admin.autoclose_rule_toggled' AND subject_id = %s",
        (rule_id,),
    ).fetchone()[0]
    assert payload == {"name": "r", "before": True, "after": False}

    # Live immediately, from the SAME still-warm cache window — no waiting
    # for RULE_CACHE_TTL_S (design note 6; DEC-025 red case (a)).
    after = autoclose.evaluate(db, alert, ctx)
    assert after.match is None


# ---------------------------------------------------------------------------
# A malformed rule id is a 422, not a 500 (review round 1) — both the HTML
# path parameter and the JSON API body are `uuid.UUID`, not `str`.
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_toggle_bad_rule_id_is_422(client) -> None:
    tc, _db, _ = client

    html_resp = tc.post("/admin/rules/not-a-uuid/toggle", data={"enabled": "false"})
    assert html_resp.status_code == 422

    api_resp = tc.patch("/api/admin/rules", json={"rule_id": "not-a-uuid", "enabled": False})
    assert api_resp.status_code == 422


# ---------------------------------------------------------------------------
# The width warning — belongs here, and only for a rule above the threshold
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_width_warning_appears_above_threshold_and_not_below(client) -> None:
    tc, db, admin_id = client
    wide_id = str(uuid.uuid4())
    narrow_id = str(uuid.uuid4())
    _insert_rule(db, rule_id=wide_id, created_by=admin_id, name="wide-rule")
    _insert_rule(db, rule_id=narrow_id, created_by=admin_id, name="narrow-rule")

    _insert_alert(
        db,
        alert_id="width-big",
        status="auto_closed",
        occurrence_count=5000,
        autoclose_rule_id=wide_id,
    )
    _insert_alert(
        db,
        alert_id="width-small",
        status="auto_closed",
        occurrence_count=1,
        autoclose_rule_id=narrow_id,
    )
    # A third rule that closed 1500 occurrences: 1500 of the 6601 in the window, 22.7 %, under
    # the 30 % threshold. Divided by the 103 ROWS it was over 1400 % and carried a warning
    # (P11-T20 row 27), so this row is what tells the two formulas apart on the page.
    middle_id = str(uuid.uuid4())
    _insert_rule(db, rule_id=middle_id, created_by=admin_id, name="middle-rule")
    _insert_alert(
        db,
        alert_id="width-middle",
        status="auto_closed",
        occurrence_count=1500,
        autoclose_rule_id=middle_id,
    )
    for i in range(100):
        _insert_alert(db, alert_id=f"width-other-{i}", status="received", occurrence_count=1)

    resp = tc.get("/admin/rules")
    assert resp.status_code == 200
    assert "wide-rule" in resp.text
    assert "narrow-rule" in resp.text

    # The wide rule's row carries a width warning; the narrow and the middle rule's do not.
    def _row_of(name: str) -> str:
        start = resp.text.index(name)
        return resp.text[start : resp.text.index("</tr>", start)]

    assert "⚠" in _row_of("wide-rule")
    assert "⚠" not in _row_of("narrow-rule")
    assert "⚠" not in _row_of("middle-rule")


# ---------------------------------------------------------------------------
# Role and refusal — its own scratch database (module docstring): this is
# the one test whose commit is real (`require_role`'s commit-before-raise),
# and it must never land in the shared session database.
# ---------------------------------------------------------------------------


def _scratch_dbname() -> str:
    session = os.environ.get("TEST_DATABASE_URL", conftest.DEFAULT_TEST_DATABASE_URL)
    return f"{conftest._dbname(session)}_rules_scratch_test"


@pytest.fixture(scope="module")
def scratch_dsn():
    if shutil.which("psql") is None or shutil.which("createdb") is None:
        pytest.skip("psql/createdb not on PATH — cannot build the rules scratch database")
    dbname = _scratch_dbname()
    subprocess.run(["dropdb", "--if-exists", dbname], check=True, capture_output=True)
    subprocess.run(["createdb", dbname], check=True, capture_output=True)
    dsn = f"postgresql:///{dbname}"
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
        subprocess.run(["dropdb", "--if-exists", dbname], check=False, capture_output=True)


@pytest.fixture
def sdb(scratch_dsn):
    conn = psycopg.connect(scratch_dsn)
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


@pytest.fixture(autouse=True)
def _require_db_marker_for_scratch(request):
    uses = {"sdb", "scratch_dsn"} & set(request.fixturenames)
    if uses and request.node.get_closest_marker("db") is None:
        pytest.fail(f"{request.node.nodeid} uses {sorted(uses)} without @pytest.mark.db")


#: All 8 routes this router mounts — every one of them behind `Admin`
#: (review round 1: parametrised, not just the one page GET). Each body is
#: syntactically valid for its route so the 403 is never shadowed by an
#: earlier 422 on the body/path, whichever FastAPI resolves first. The
#: `toggle` path and the `PATCH` body use a well-formed, nonexistent rule id
#: — the 404-vs-403 question never arises because `require_role` fires
#: before the route body runs.
_PLACEHOLDER_RULE_ID = "00000000-0000-0000-0000-0000000000aa"
_ADMIN_ROUTES: tuple[tuple[str, str, dict[str, Any]], ...] = (
    ("get", "/api/admin/rules", {}),
    ("post", "/api/admin/rules", {"json": {"name": "n", "reason": "r", "match": []}}),
    (
        "patch",
        "/api/admin/rules",
        {"json": {"rule_id": _PLACEHOLDER_RULE_ID, "enabled": True}},
    ),
    ("post", "/api/admin/rules/simulate", {"json": {"match": []}}),
    ("get", "/admin/rules", {}),
    ("post", "/admin/rules/preview", {"data": {"name": "n", "reason": "r", "match_json": "[]"}}),
    ("post", "/admin/rules", {"data": {"name": "n", "reason": "r", "match_json": "[]"}}),
    (
        "post",
        f"/admin/rules/{_PLACEHOLDER_RULE_ID}/toggle",
        {"data": {"enabled": "false"}},
    ),
)


@pytest.mark.parametrize("method, path, kwargs", _ADMIN_ROUTES)
@pytest.mark.db
def test_non_admin_is_refused_and_authz_denied_row_present(sdb, method, path, kwargs) -> None:
    tier1_claims = Claims(user_id=str(uuid.uuid4()), username="t1", role="tier1", iat=0.0, exp=0.0)
    main.app.dependency_overrides[deps.get_conn] = lambda: sdb
    main.app.dependency_overrides[deps.current_user] = lambda: tier1_claims
    main.app.dependency_overrides[pages.page_user] = lambda: tier1_claims
    try:
        tc = TestClient(main.app, follow_redirects=False)
        resp = getattr(tc, method)(path, **kwargs)
    finally:
        main.app.dependency_overrides.pop(deps.get_conn, None)
        main.app.dependency_overrides.pop(deps.current_user, None)
        main.app.dependency_overrides.pop(pages.page_user, None)

    assert resp.status_code == 403, f"{method.upper()} {path} -> {resp.status_code}: {resp.text}"
    # subject_id is `request.url.path` (deps.require_role) — each route in
    # the table is a distinct path, so this pins the row to THIS route even
    # though the scratch database accumulates one real, committed row per
    # parametrised case (require_role commits before it raises).
    row = sdb.execute(
        "SELECT payload->'required' AS required, payload->>'role' AS role "
        "FROM audit_events WHERE event_type = 'authz.denied' AND subject_id = %s "
        "ORDER BY created_at DESC LIMIT 1",
        (path,),
    ).fetchone()
    assert row is not None, f"no authz.denied row for {path}"
    required, role = row
    assert required == ["admin"]
    assert role == "tier1"


# ---------------------------------------------------------------------------
# The routes exist, and only these — sorted(app.openapi()["paths"]) (DEC-101 b)
# ---------------------------------------------------------------------------


def test_rules_routes_are_listed() -> None:
    paths = set(main.app.openapi()["paths"])
    assert "/admin/rules" in paths
    assert "/admin/rules/preview" in paths
    assert "/admin/rules/{rule_id}/toggle" in paths
    assert "/api/admin/rules" in paths
    assert "/api/admin/rules/simulate" in paths


# ---------------------------------------------------------------------------
# The JSON API (§6.4) — a thin sanity check; the page tests above are the
# card's real acceptance surface (design note 6)
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_api_simulate_create_and_toggle(client) -> None:
    tc, _db, _admin_id = client

    sim = tc.post("/api/admin/rules/simulate", json={"match": []})
    assert sim.status_code == 200
    assert sim.json()["clusters"] == 0

    created = tc.post("/api/admin/rules", json={"name": "api-rule", "reason": "t", "match": []})
    assert created.status_code == 201
    rule_id = created.json()["rule_id"]

    toggled = tc.patch("/api/admin/rules", json={"rule_id": rule_id, "enabled": False})
    assert toggled.status_code == 200
    assert toggled.json()["enabled"] is False

    listed = tc.get("/api/admin/rules")
    assert listed.status_code == 200
    row = next(r for r in listed.json() if r["rule_id"] == rule_id)
    assert row["enabled"] is False


# ---------------------------------------------------------------------------
# P11-T06 — the two additions of the admin console v1.1 spec §5.5:
# `hard_block_tally` on `POST /api/admin/rules/simulate` and
# `width_threshold_pct` on every row of `GET /api/admin/rules`. Both additive.
# ---------------------------------------------------------------------------

#: The six codes the UI will key its Vietnamese labels on (P11-T14), in
#: `_HARD_BLOCK_ORDER` order. Spelled out here on purpose: the codes are an
#: API contract, so renaming one must fail a test, not silently reach the UI.
_SIX_CODES = [
    "critical",
    "never_autoclose_agent",
    "asset_high",
    "asset_not_in_inventory",
    "identity_privileged",
    "ioc_bad",
]
_WATCHED_AGENT = "blk-watched"
_BLK_RULE = [{"field": "agent_name", "op": "prefix", "value": "blk-"}]
_CLEAN_CONTEXTS: dict[str, dict] = {
    "asset_context": {"present": True, "criticality": "medium"},
    "identity_context": {"privileged": False},
    "ioc_context": {"reputation": "not_found"},
}


def _blocked_alert_kwargs(code: str) -> dict[str, Any]:
    """The `_insert_alert` arguments under which `autoclose._first_hard_block`
    answers exactly `code` — one fault on an otherwise clean alert, so no
    earlier block in the fixed order can claim it first."""
    kwargs: dict[str, Any] = {"agent_name": f"blk-{code}", **_CLEAN_CONTEXTS}
    if code == "critical":
        kwargs["severity"] = "critical"
    elif code == "never_autoclose_agent":
        kwargs["agent_name"] = _WATCHED_AGENT
    elif code == "asset_high":
        kwargs["asset_context"] = {"present": True, "criticality": "high"}
    elif code == "asset_not_in_inventory":
        kwargs["asset_context"] = {"present": False, "criticality": "unknown"}
    elif code == "identity_privileged":
        kwargs["identity_context"] = {"privileged": True}
    elif code == "ioc_bad":
        kwargs["ioc_context"] = {"reputation": "malicious"}
    else:  # pragma: no cover — a typo in this file, not a product path
        raise AssertionError(code)
    return kwargs


def _seed_blocked(db: Any, counts: dict[str, int]) -> None:
    for code, n in counts.items():
        for i in range(n):
            _insert_alert(db, alert_id=f"blk-{code}-{i}", **_blocked_alert_kwargs(code))


def _post_simulate(tc: TestClient, match: Any) -> Any:
    return tc.post("/api/admin/rules/simulate", json={"match": match})


@pytest.fixture
def tally_spy(monkeypatch):
    """Wraps `_hard_block_tally`, recording each call, and runs the real one."""
    calls: list[list[dict[str, Any]]] = []
    real = admin_rules._hard_block_tally

    def spy(conn, cfg, match):
        calls.append(match)
        return real(conn, cfg, match)

    monkeypatch.setattr(admin_rules, "_hard_block_tally", spy)
    return calls


@pytest.mark.db
def test_api_simulate_tally_counts_per_code_when_the_rule_matches_only_hard_blocked_rows(
    client, monkeypatch, tally_spy
) -> None:
    tc, db, _ = client
    monkeypatch.setenv("NEVER_AUTOCLOSE_AGENTS", f'["{_WATCHED_AGENT}"]')
    counts = {
        "ioc_bad": 5,
        "never_autoclose_agent": 4,
        "asset_not_in_inventory": 4,
        "critical": 3,
        "asset_high": 2,
        "identity_privileged": 1,
    }
    _seed_blocked(db, counts)
    # Hard-blocked too, but not this rule's business: its agent_name has no "blk-" prefix.
    for i in range(2):
        _insert_alert(db, alert_id=f"other-{i}", **{**_CLEAN_CONTEXTS, "severity": "critical"})

    resp = _post_simulate(tc, _BLK_RULE)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["clusters"] == 0
    tally = body["hard_block_tally"]
    # `matched` is what the rule's own conditions match, hard-blocked or not.
    own_matches = db.execute("SELECT count(*) FROM alerts WHERE agent_name LIKE 'blk-%'").fetchone()
    assert own_matches[0] == sum(counts.values()) == 19
    assert tally["matched"] == 19
    assert set(tally) == {"matched", "blocks"}
    assert {b["code"]: b["count"] for b in tally["blocks"]} == counts
    assert len(tally["blocks"]) == 6
    # The labels stay in the UI: a block is exactly `{code, count}`.
    assert all(set(b) == {"code", "count"} for b in tally["blocks"])
    assert all(isinstance(b["count"], int) for b in tally["blocks"])
    assert len(tally_spy) == 1


@pytest.mark.db
def test_api_simulate_tally_order_is_the_order_hard_block_tally_returns(
    client, monkeypatch
) -> None:
    tc, db, _ = client
    monkeypatch.setenv("NEVER_AUTOCLOSE_AGENTS", f'["{_WATCHED_AGENT}"]')
    # Largest first; the three empty codes keep their fixed relative order (ties).
    _seed_blocked(db, {"ioc_bad": 3, "identity_privileged": 2, "asset_high": 1})

    body = _post_simulate(tc, _BLK_RULE).json()
    got = [(b["code"], b["count"]) for b in body["hard_block_tally"]["blocks"]]

    _matched, tally = admin_rules._hard_block_tally(db, config.load(), _BLK_RULE)
    assert got == [(code, count) for code, _label, count in tally]
    # ...which is not just `_HARD_BLOCK_ORDER` again: the route must not renormalise.
    assert [code for code, _ in got] != _SIX_CODES
    assert [code for code, _ in got] == [
        "ioc_bad",
        "identity_privileged",
        "asset_high",
        "critical",
        "never_autoclose_agent",
        "asset_not_in_inventory",
    ]


@pytest.mark.db
def test_api_simulate_tally_for_a_rule_matching_nothing_is_zero_across_all_six_codes(
    client, tally_spy
) -> None:
    tc, db, _ = client
    _insert_alert(db, alert_id="quiet-clean", agent_name="some-agent", **_CLEAN_CONTEXTS)
    _insert_alert(
        db,
        alert_id="quiet-blocked",
        agent_name="some-agent",
        **{**_CLEAN_CONTEXTS, "severity": "critical"},
    )
    match = [{"field": "agent_name", "op": "eq", "value": "nobody-matches-this"}]

    resp = _post_simulate(tc, match)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["clusters"] == 0
    assert body["hard_block_tally"] == {
        "matched": 0,
        "blocks": [{"code": code, "count": 0} for code in _SIX_CODES],
    }
    assert len(tally_spy) == 1


@pytest.mark.db
def test_api_simulate_tally_is_null_when_the_rule_closes_rows(client, tally_spy) -> None:
    tc, db, _ = client
    _insert_alert(db, alert_id="closes-1", agent_name="ok-agent", **_CLEAN_CONTEXTS)
    _insert_alert(
        db, alert_id="closes-2", agent_name="ok-agent", occurrence_count=3, **_CLEAN_CONTEXTS
    )
    # A matched row that is hard-blocked changes nothing: the rule still closes the other two.
    _insert_alert(
        db,
        alert_id="closes-blocked",
        agent_name="ok-agent",
        **{**_CLEAN_CONTEXTS, "severity": "critical"},
    )
    match = [{"field": "agent_name", "op": "eq", "value": "ok-agent"}]

    resp = _post_simulate(tc, match)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["clusters"] == 2
    assert body["alerts"] == 4
    assert "hard_block_tally" in body  # present and null, not omitted
    assert body["hard_block_tally"] is None
    assert tally_spy == []  # not even computed: no second 30-day scan


@pytest.mark.db
def test_api_simulate_tally_counts_a_row_hit_by_two_blocks_once_under_the_first(client) -> None:
    """P11-T20 row 24 (P11-T06 review F1; mutant m1: every block that applies is counted). The
    other tests seed one fault per row, so no row ever had two. Here each row has several, and
    each is counted ONCE, under the first of `_HARD_BLOCK_ORDER`; the blocks therefore add up to
    `matched`, the rule's own matches, none of which closes."""
    tc, db, _ = client
    clean = _CLEAN_CONTEXTS
    # critical + high asset + malicious IoC  -> critical
    _insert_alert(
        db,
        alert_id="blk-two-critical",
        agent_name="blk-two-critical",
        severity="critical",
        **{
            **clean,
            "asset_context": {"present": True, "criticality": "high"},
            "ioc_context": {"reputation": "malicious"},
        },
    )
    # privileged identity + suspicious IoC    -> identity_privileged
    _insert_alert(
        db,
        alert_id="blk-two-identity",
        agent_name="blk-two-identity",
        **{
            **clean,
            "identity_context": {"privileged": True},
            "ioc_context": {"reputation": "suspicious"},
        },
    )
    # not in the inventory + malicious IoC    -> asset_not_in_inventory
    _insert_alert(
        db,
        alert_id="blk-two-inventory",
        agent_name="blk-two-inventory",
        **{
            **clean,
            "asset_context": {"present": False, "criticality": "unknown"},
            "ioc_context": {"reputation": "malicious"},
        },
    )

    body = _post_simulate(tc, _BLK_RULE).json()

    assert body["clusters"] == 0
    tally = body["hard_block_tally"]
    counts = {b["code"]: b["count"] for b in tally["blocks"]}
    assert counts == {
        "critical": 1,
        "never_autoclose_agent": 0,
        "asset_high": 0,  # the first row has it too, but `critical` claimed that row
        "asset_not_in_inventory": 1,
        "identity_privileged": 1,
        "ioc_bad": 0,  # two rows have it, claimed by `critical` and `asset_not_in_inventory`
    }
    assert tally["matched"] == 3
    assert sum(counts.values()) == tally["matched"]


@pytest.mark.db
def test_api_simulate_tally_is_null_when_the_rule_closes_exactly_one_row(client, tally_spy) -> None:
    """P11-T20 row 25 (P11-T06 review F2; mutant m4: `clusters <= 1`). The tally says why a rule
    closes NOTHING; one closed row is a rule that closes something, even when every other row it
    matches is hard-blocked. The boundary is 1 cluster, not 2."""
    tc, db, _ = client
    _insert_alert(db, alert_id="one-closes", agent_name="blk-one", **_CLEAN_CONTEXTS)
    _insert_alert(
        db,
        alert_id="one-blocked-1",
        agent_name="blk-one-b",
        **{**_CLEAN_CONTEXTS, "severity": "critical"},
    )
    _insert_alert(
        db,
        alert_id="one-blocked-2",
        agent_name="blk-one-c",
        **{**_CLEAN_CONTEXTS, "ioc_context": {"reputation": "malicious"}},
    )

    body = _post_simulate(tc, _BLK_RULE).json()

    assert body["clusters"] == 1
    assert body["hard_block_tally"] is None
    assert tally_spy == []


@pytest.mark.db
def test_api_simulate_keeps_every_simulate_stats_field_unchanged(client) -> None:
    tc, db, _ = client
    _insert_alert(db, alert_id="keep-1", agent_name="ok-agent", **_CLEAN_CONTEXTS)
    _insert_alert(db, alert_id="keep-2", agent_name="ok-agent", **_CLEAN_CONTEXTS)
    fields = {f.name for f in dataclasses.fields(autoclose.SimulateStats)}
    assert fields == {"clusters", "alerts", "by_severity", "by_asset_criticality", "samples"}

    for match in (
        [{"field": "agent_name", "op": "eq", "value": "ok-agent"}],  # closes rows
        [{"field": "agent_name", "op": "eq", "value": "nobody"}],  # closes none
    ):
        body = _post_simulate(tc, match).json()
        expected = dataclasses.asdict(autoclose.simulate(db, match))
        assert set(body) == fields | {"hard_block_tally"}
        assert {k: body[k] for k in fields} == expected


_BAD_MATCHES: tuple[Any, ...] = (
    [{"field": "risk_score", "op": "eq", "value": "1"}],  # field outside the whitelist
    [{"field": "identity_privileged", "op": "in", "value": [True]}],  # op the field disallows
    [{"field": "dst_port", "op": "eq", "value": "443"}],  # value of the wrong type
    [{"field": "agent_name", "op": "eq"}],  # a condition without its value
    "not-a-list",  # not even a body Pydantic accepts
)


@pytest.mark.parametrize("match", _BAD_MATCHES)
@pytest.mark.db
def test_api_simulate_bad_rule_is_422_and_the_tally_is_never_computed(
    client, monkeypatch, match
) -> None:
    tc, db, _ = client
    _insert_alert(db, alert_id="bad-1", agent_name="ok-agent", **_CLEAN_CONTEXTS)
    calls: list[object] = []

    def must_not_run(*args: Any, **kwargs: Any) -> None:
        calls.append(args)
        raise AssertionError("_hard_block_tally ran for a rule that failed validation")

    monkeypatch.setattr(admin_rules, "_hard_block_tally", must_not_run)

    resp = _post_simulate(tc, match)
    assert resp.status_code == 422, resp.text
    assert calls == []
    assert "hard_block_tally" not in resp.json()


@pytest.mark.db
def test_api_list_rules_rows_carry_width_threshold_pct_from_the_config(client, monkeypatch) -> None:
    tc, db, admin_id = client
    ids = [str(uuid.uuid4()), str(uuid.uuid4())]
    _insert_rule(db, rule_id=ids[0], created_by=admin_id, name="first")
    _insert_rule(db, rule_id=ids[1], created_by=admin_id, name="second", enabled=False)

    # The configured default, whatever the environment says.
    default = config.load().AUTOCLOSE_RULE_WIDTH_PCT
    rows = tc.get("/api/admin/rules").json()
    assert {r["rule_id"] for r in rows} == set(ids)  # one transaction: created_at ties
    assert [r["width_threshold_pct"] for r in rows] == [default, default]

    # Overridden to a non-default value: the response follows the config, not a constant.
    cfg = dataclasses.replace(config.load(), AUTOCLOSE_RULE_WIDTH_PCT=17)
    monkeypatch.setitem(main.app.dependency_overrides, deps.get_config, lambda: cfg)
    rows = tc.get("/api/admin/rules").json()
    assert [r["width_threshold_pct"] for r in rows] == [17, 17]
    assert all(type(r["width_threshold_pct"]) is int for r in rows)
    # Additive: every field the row had before is still there.
    assert set(rows[0]) == {
        "rule_id",
        "name",
        "enabled",
        "match",
        "match_json",
        "reason",
        "created_by",
        "created_at",
        "width_pct",
        "width_threshold_pct",
    }


@pytest.mark.db
def test_api_list_rules_width_pct_and_its_threshold_come_from_the_same_setting(
    client, monkeypatch
) -> None:
    tc, db, admin_id = client
    rule_id = str(uuid.uuid4())
    _insert_rule(db, rule_id=rule_id, created_by=admin_id, name="quarter")
    # 20 of the window's 99 occurrences (the head's 20 and 79 single alerts): 20.2 %, over a
    # threshold of 17 and under the default 30. Dividing by the 80 ROWS gave 25.0 (P11-T20
    # row 27; the figure differs, so this pins the share of occurrences).
    _insert_alert(
        db,
        alert_id="quarter-closed",
        status="auto_closed",
        occurrence_count=20,
        autoclose_rule_id=rule_id,
    )
    for i in range(79):
        _insert_alert(db, alert_id=f"quarter-other-{i}")
    monkeypatch.setenv("AUTOCLOSE_RULE_WIDTH_PCT", "17")

    (row,) = tc.get("/api/admin/rules").json()
    assert row["width_threshold_pct"] == 17
    assert row["width_pct"] == 20.2
