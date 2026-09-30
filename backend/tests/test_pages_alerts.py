"""P4-T05 — the Tier-1 queue page and the alert detail page, with HTMX partials:
`web/routers/alerts_pages.py`, `templates/{queue,alert,_decision_form,_suggestion}.html`.

Fixture helpers are `test_tier1_api.py`'s pattern, copied (that file's own docstring
calls it "test_decide.py's pattern, copied" — each API/page test file stays
self-contained rather than importing fixtures across cards).

`get_conn` is overridden with a generator that yields the `db` fixture's connection and
never commits on a normal return — every test runs inside `db`'s one transaction, rolled
back at teardown (conftest.py). `page_user` (this card's pages) and `current_user`
(`require_role("tier1")`'s own sub-dependency, reached from `page_user` failing over into
the POST routes) are both overridden per role, mirroring `test_pages_rules.py`'s pattern
for a `page_user`-gated router.
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
from app.tier1.queue import QueuePage
from app.web import deps, main, templating
from app.web.routers import pages
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

pytestmark = pytest.mark.db

FIXTURES = Path(__file__).resolve().parent / "fixtures"
_CANONICAL: Alert = parse_wazuh_alert(
    json.loads((FIXTURES / "alert_40112.json").read_text(encoding="utf-8"))
).alert
assert _CANONICAL is not None

TIER1_ID = "00000000-0000-0000-0000-0000000405a1"
TIER2_ID = "00000000-0000-0000-0000-0000000405a2"
TIER1_NAME = "P4-T05 tier1"

_EMPTY_CONTEXT = AlertContext(
    asset_present=False,
    asset_criticality="unknown",
    asset_owner=None,
    asset_role=None,
    identity_privileged=None,
    ioc_reputation="skipped",
    lookup_status={"asset": "not_found", "identity": "skipped", "ioc": "skipped"},
)

RESULT: dict[str, Any] = {
    "suggested_action": "false_positive",
    "confidence": "high",
    "structured_basis": {"severity": "critical", "occurrence_count": 1},
    "reasons": [
        {"claim": "matches known pattern", "quote": "sshd_quote_marker", "source": "wazuh_raw_log"}
    ],
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
# Fixture helpers (test_tier1_api.py's pattern, copied)
# ---------------------------------------------------------------------------


def _hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _alert(**overrides: Any) -> Alert:
    n = next(_counter)
    alert_id = overrides.pop("alert_id", f"p4t05-{n}")
    fields: dict[str, Any] = {"alert_id": alert_id, "event_bucket_hash": _hash(alert_id)}
    fields.update(overrides)
    return dataclasses.replace(_CANONICAL, **fields)


def _seed_users(conn: psycopg.Connection) -> None:
    for user_id, name, role in (
        (TIER1_ID, TIER1_NAME, "tier1"),
        (TIER2_ID, "P4-T05 tier2", "tier2"),
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
    risk_score: int = 10,
    **overrides: Any,
) -> str:
    alert = _alert(**overrides)
    open_alert(conn, alert, kind="received", source=source, suggestion_visible=suggestion_visible)
    start_enrichment(conn, alert.alert_id)
    finish_enrichment(
        conn, alert.alert_id, context=_EMPTY_CONTEXT, risk_score=risk_score, risk_components={}
    )
    return alert.alert_id


def _active(conn: psycopg.Connection, *, actor_id: str = TIER1_ID, **overrides: Any) -> str:
    alert_id = _queued(conn, **overrides)
    transitions.acknowledge(conn, alert_id, actor_id)
    return alert_id


def _autoclose_rule(conn: psycopg.Connection, created_by: str) -> str:
    rule_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO autoclose_rules (autoclose_rule_id, name, match, reason, created_by) "
        "VALUES (%s, %s, %s, %s, %s)",
        (rule_id, "p4t05-idle", Jsonb({}), "idle_gap", created_by),
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
    """One `llm_runs` proposer row in P3-T10's shape (P4-T02's fixture INSERT, copied)."""
    row = conn.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt, "
        "user_message, result, role, gate_result) "
        "VALUES (gen_random_uuid(), 'triage', 'alert', %s, 's', 'u', %s::jsonb, 'proposer', "
        "%s::jsonb) RETURNING run_id",
        (alert_id, json.dumps(RESULT), json.dumps(GATE)),
    ).fetchone()
    return str(row[0])


class _Client:
    """`TestClient` plus the role/user `page_user`/`current_user` answer as."""

    def __init__(self) -> None:
        self.http = TestClient(main.app, follow_redirects=False)
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
        # The real dependency's shape minus the success commit (test_tier1_api.py's
        # pattern, review round 1 item 9): a route's own exception still rolls back
        # mid-request, exactly like production, but a normal return never commits —
        # every test stays inside the `db` fixture's one transaction.
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


@pytest.fixture
def real_shape_client(db, monkeypatch):
    """`get_conn` with the *real* dependency's shape (commit on success, rollback on
    exception) — needed to prove a 409/422/503 rolls back before that commit would run
    (pitfall 1) and that `require_role`'s 403 path commits exactly one `authz.denied`
    row and nothing else (pitfall 2) — `test_tier1_api.py`'s `real_shape_client`
    pattern, copied. `commit`/`rollback` are replaced by call recorders so nothing
    really persists; the genuine `rollback` runs at teardown regardless."""
    _seed_users(db)
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

    c = _Client()
    main.app.dependency_overrides[deps.get_conn] = get_conn
    main.app.dependency_overrides[deps.get_config] = lambda: config.Config()
    main.app.dependency_overrides[deps.current_user] = c.claims
    main.app.dependency_overrides[pages.page_user] = c.claims
    try:
        yield c, calls
    finally:
        for dep in (deps.get_conn, deps.get_config, deps.current_user, pages.page_user):
            main.app.dependency_overrides.pop(dep, None)
        monkeypatch.undo()
        real_rollback()


# ---------------------------------------------------------------------------
# The queue page
# ---------------------------------------------------------------------------


def test_queue_page_lists_band_not_score(db, client) -> None:
    _queued(db, risk_score=63)  # 50-74 -> "Cao" (phase-4 band)

    resp = client.http.get("/queue")
    assert resp.status_code == 200, resp.text
    assert "Cao" in resp.text
    assert "63" not in resp.text


def test_queue_needs_retriage_first_with_marker(db, client) -> None:
    # Visible arm: on a blind head the marker and the order would say "① ran" (R17 / DEC-101).
    normal_id = _queued(db, risk_score=90, suggestion_visible=True)
    retriage_id = _queued(db, risk_score=5, suggestion_visible=True)
    # needs_retriage requires triaged_count > 0 AND a big enough occurrence_count
    # delta (RETRIAGE_FACTOR=10, RETRIAGE_ABS_DELTA=200) — a direct UPDATE of a
    # non-status column, in a test only (card's working rules).
    db.execute(
        "UPDATE alerts SET triaged_count = 1, occurrence_count = 250 WHERE alert_id = %s",
        (retriage_id,),
    )

    resp = client.http.get("/queue")
    assert resp.status_code == 200, resp.text
    retriage_pos = resp.text.index(retriage_id)
    normal_pos = resp.text.index(normal_id)
    assert retriage_pos < normal_pos, "the needs_retriage row must sort first"
    # the marker appears on the retriage row's line, not before it
    row_start = resp.text.rfind("<tr", 0, retriage_pos)
    row_end = resp.text.index("</tr>", retriage_pos)
    assert "⟳" in resp.text[row_start:row_end]


def test_queue_blind_retriage_head_has_no_marker_and_does_not_jump_the_queue(db, client) -> None:
    """R17 / DEC-101 on the Jinja page: a blind head that ① has triaged and that then grew
    shows no ⟳, no `data-needs-retriage`, and sorts by risk like any other head."""
    normal_id = _queued(db, risk_score=90, suggestion_visible=False)
    retriage_id = _queued(db, risk_score=5, suggestion_visible=False)
    db.execute(
        "UPDATE alerts SET triaged_count = 1, occurrence_count = 250 WHERE alert_id = %s",
        (retriage_id,),
    )

    resp = client.http.get("/queue")
    assert resp.status_code == 200, resp.text
    assert resp.text.index(normal_id) < resp.text.index(retriage_id), "risk decides, not ①"
    row_start = resp.text.rfind("<tr", 0, resp.text.index(retriage_id))
    row_end = resp.text.index("</tr>", resp.text.index(retriage_id))
    assert "⟳" not in resp.text[row_start:row_end]
    assert "data-needs-retriage" not in resp.text[row_start:row_end]


def test_queue_blind_row_shows_dash_and_no_verdict_text(db, client) -> None:
    alert_id = _queued(db, suggestion_visible=False)
    _insert_run(db, alert_id)

    resp = client.http.get("/queue")
    assert resp.status_code == 200, resp.text
    assert "false_positive" not in resp.text
    row_start = resp.text.index(f'href="/alerts/{alert_id}"')
    row_end = resp.text.index("</tr>", row_start)
    assert "—" in resp.text[row_start:row_end]


def test_queue_visible_row_shows_verdict(db, client) -> None:
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id)

    resp = client.http.get("/queue")
    assert resp.status_code == 200, resp.text
    row_start = resp.text.index(f'href="/alerts/{alert_id}"')
    row_end = resp.text.index("</tr>", row_start)
    assert "false_positive" in resp.text[row_start:row_end]


def test_queue_column_branches_on_key_presence_not_flag(db) -> None:
    """The template branches on `"suggested_action" in row`, never on
    `row.suggestion_visible` — a row with the flag `True` but the keys absent (a
    shape `visibility.strip` never actually produces, since it only ever removes
    those keys together with a *false* flag) must still render `—` (card §2)."""
    row = {
        "alert_id": "synthetic-1",
        "rule_id": "40112",
        "description": "d",
        "category": "ssh_brute_force",
        "severity": "high",
        "agent_name": "agent-1",
        "occurrence_count": 3,
        "first_seen_at": None,
        "risk_band": "Cao",
        "needs_retriage": False,
        "suggestion_visible": True,  # flipped True on purpose; keys stay absent
    }
    page = QueuePage(rows=[row], total=1, page=1, page_size=50)
    claims = Claims(user_id=TIER1_ID, username=TIER1_ID, role="tier1", iat=0.0, exp=0.0)
    html = templating.templates.get_template("queue.html").render(
        page=page,
        user=claims,
        request=None,
        flash=None,
        htmx_src=templating.HTMX_SRC,
        htmx_integrity=templating.HTMX_INTEGRITY,
        tz="Asia/Ho_Chi_Minh",
        total_pages=1,
    )
    row_start = html.index("synthetic-1")
    row_end = html.index("</tr>", row_start)
    assert "—" in html[row_start:row_end]
    assert "false_positive" not in html


# ---------------------------------------------------------------------------
# The detail page
# ---------------------------------------------------------------------------


def test_detail_blind_undecided_has_no_suggestion_text(db, client) -> None:
    alert_id = _queued(db, suggestion_visible=False)
    _insert_run(db, alert_id)

    resp = client.http.get(f"/alerts/{alert_id}")
    assert resp.status_code == 200, resp.text
    assert "false_positive" not in resp.text
    assert "nhánh mù" in resp.text
    start = resp.text.index('data-section="suggestion"')
    end = resp.text.index("</section>", start)
    section = resp.text[start:end]
    assert "cổng đã ép" not in section
    assert "sshd_quote_marker" not in section


def test_detail_after_decision_shows_suggestion_with_quote(db, client) -> None:
    alert_id = _active(db, suggestion_visible=False)
    _insert_run(db, alert_id)
    decide_module.decide(
        db,
        alert_id,
        decide_module.Actor(TIER1_ID, "tier1"),
        decision="benign",
        reason="matches the KB",
        seen_occurrence_count=1,
    )

    resp = client.http.get(f"/alerts/{alert_id}")
    assert resp.status_code == 200, resp.text
    assert "sshd_quote_marker" in resp.text
    assert "false_positive" in resp.text


def test_detail_raw_log_is_escaped(db, client) -> None:
    alert_id = _queued(db, raw_log="<script>alert(1)</script>")

    resp = client.http.get(f"/alerts/{alert_id}")
    assert resp.status_code == 200, resp.text
    assert "<script>alert(1)</script>" not in resp.text
    assert "&lt;script&gt;" in resp.text


def test_detail_shows_accounts_correlation_playbook_enrichment(db, client) -> None:
    alert_id = _queued(db)  # canonical fixture: category=ssh_brute_force, alert_user=user1

    resp = client.http.get(f"/alerts/{alert_id}")
    assert resp.status_code == 200, resp.text
    assert "user1" in resp.text  # targeted_accounts
    assert "cụm liên quan trong" in resp.text  # correlation count sentence
    assert "Playbook" in resp.text or "playbook" in resp.text
    assert "ssh_brute_force" in resp.text or "Brute" in resp.text or "brute" in resp.text
    assert "unknown" in resp.text  # asset_context.criticality (_EMPTY_CONTEXT)
    assert "skipped" in resp.text  # ioc_context.reputation


# ---------------------------------------------------------------------------
# The four HTMX partials
# ---------------------------------------------------------------------------


def test_acknowledge_partial_enables_form_with_seen_count(db, client) -> None:
    alert_id = _queued(db)

    resp = client.http.post(f"/alerts/{alert_id}/acknowledge")
    assert resp.status_code == 200, resp.text
    assert 'name="seen_occurrence_count" value="1"' in resp.text
    assert 'name="decision"' in resp.text


def test_decide_partial_redirects_and_closes_cluster(db, client) -> None:
    alert_id = _active(db)

    resp = client.http.post(
        f"/alerts/{alert_id}/decide",
        data={"decision": "benign", "reason": "matches the KB", "seen_occurrence_count": "1"},
    )
    assert resp.status_code == 200, resp.text
    # Review round 1, S2: the confirmation now travels as a query string on the
    # redirect target (HX-Redirect's body is dead code — htmx navigates before it
    # ever processes a swap), so the exact target carries `?flash=closed&n=...`.
    assert resp.headers["HX-Redirect"].startswith("/queue")
    status = db.execute("SELECT status FROM alerts WHERE alert_id = %s", (alert_id,)).fetchone()[0]
    assert status == "closed_benign"


def test_decide_stale_seen_count_is_409_flash_with_n_and_m_and_refreshed_field(
    db, real_shape_client
) -> None:
    """`real_shape_client`, not the plain `client` fixture: this router's 409 path
    calls a *real* `conn.rollback()` (pitfall 1), and the plain `client` fixture's
    `db` connection is the SAME uncommitted transaction this test's own `_active` +
    `UPDATE` setup ran on — a real rollback there would undo the setup too, not just
    the request. `real_shape_client` replaces `commit`/`rollback` with recorders, so
    the router's rollback call is real *as a call* (provable) but not as a database
    effect, leaving the setup visible for the fragment's re-read — exactly as
    production behaves (the setup would already be a separately committed request)."""
    client, _calls = real_shape_client
    alert_id = _active(db)
    db.execute(
        "UPDATE alerts SET occurrence_count = occurrence_count + 21 WHERE alert_id = %s",
        (alert_id,),
    )

    resp = client.http.post(
        f"/alerts/{alert_id}/decide",
        data={
            "decision": "benign",
            "reason": "the typed reason survives",
            "seen_occurrence_count": "1",
        },
    )
    assert resp.status_code == 409, resp.text
    assert "lên 22" in resp.text
    assert "chênh 21" in resp.text
    assert 'name="seen_occurrence_count" value="22"' in resp.text
    # Review round 1, N9: the analyst's own unsaved text survives the re-render —
    # escaped by Jinja's autoescape like every other value here, never reset to empty.
    assert "the typed reason survives" in resp.text


def test_decide_409_rolls_back_before_the_wrappers_commit(db, real_shape_client) -> None:
    """Pitfall 1: without an explicit `conn.rollback()` before rendering the 409
    fragment, the real `get_conn` would take its `else: conn.commit()` branch on a
    normal *return* (a 409 is not an exception) and persist the guard's own reads."""
    client, calls = real_shape_client
    alert_id = _active(db)
    db.execute(
        "UPDATE alerts SET occurrence_count = occurrence_count + 21 WHERE alert_id = %s",
        (alert_id,),
    )

    resp = client.http.post(
        f"/alerts/{alert_id}/decide",
        data={"decision": "benign", "reason": "x", "seen_occurrence_count": "1"},
    )
    assert resp.status_code == 409, resp.text
    assert calls[:1] == ["rollback"], calls


def test_tier2_post_is_403(db, real_shape_client) -> None:
    """`real_shape_client`, not the plain `client` fixture: `require_role`'s 403 path
    calls the connection's real `.commit()` directly (planning decision 3), regardless
    of which `get_conn` wrapper is in front of it — on the plain `client` fixture's
    unmonkeypatched `db` that write is real and permanent in the private
    `soc_p4t05_test` database, undone by no later `rollback()` (a commit is not
    reversible). `real_shape_client` replaces `commit` with a recorder so this test's
    own 403 leaves nothing behind for a later test in this file, or a later file in
    the same `make test-db` session, to trip over (pitfall 2)."""
    client, _calls = real_shape_client
    alert_id = _active(db)
    client.as_role("tier2", TIER2_ID)

    resp = client.http.post(
        f"/alerts/{alert_id}/decide",
        data={"decision": "benign", "reason": "x", "seen_occurrence_count": "1"},
    )
    assert resp.status_code == 403, resp.text


def test_forbidden_post_is_audited_and_not_committed(db, real_shape_client) -> None:
    """Pitfall 2: `require_role`'s 403 path calls `conn.commit()` directly — on the
    shared `db` fixture connection that would make everything this test set up
    permanent unless the request's own rollback-on-exception is real. `db.commit` is
    spied instead of monkeypatched to a plain recorder here so the spy can also read
    back the just-written row (still visible to `db` itself, uncommitted or not)."""
    client, calls = real_shape_client
    alert_id = _active(db)
    client.as_role("tier2", TIER2_ID)

    seen: list[list[tuple]] = []

    def _spy_commit() -> None:
        calls.append("commit")
        seen.append(
            db.execute(
                "SELECT payload FROM audit_events WHERE event_type = 'authz.denied' "
                "AND actor_id = %s",
                (TIER2_ID,),
            ).fetchall()
        )

    db.commit = _spy_commit  # override the recorder installed by real_shape_client

    resp = client.http.post(
        f"/alerts/{alert_id}/decide",
        data={"decision": "benign", "reason": "x", "seen_occurrence_count": "1"},
    )
    assert resp.status_code == 403, resp.text
    assert len(seen) == 1
    assert len(seen[0]) == 1
    assert seen[0][0][0]["required"] == ["tier1"]


def test_escalate_partial_redirects_with_case(db, client) -> None:
    alert_id = _active(db)

    resp = client.http.post(f"/alerts/{alert_id}/escalate", data={"title": "brute force"})
    # Review round 1, S2: same as decide — the confirmation travels on the redirect
    # target's query string now, not a dead-code response body.
    assert resp.headers["HX-Redirect"].startswith("/queue")
    case_id = db.execute("SELECT case_id FROM alerts WHERE alert_id = %s", (alert_id,)).fetchone()[
        0
    ]
    assert case_id is not None
    row = db.execute("SELECT status FROM cases WHERE case_id = %s", (case_id,)).fetchone()
    assert row is not None


def test_reopen_partial_on_auto_closed(db, client) -> None:
    alert_id = _auto_closed(db)

    resp = client.http.post(f"/alerts/{alert_id}/reopen", data={"reason": "reviewed, was noise"})
    assert resp.status_code == 200, resp.text
    assert resp.headers["HX-Redirect"] == f"/alerts/{alert_id}"
    status = db.execute("SELECT status FROM alerts WHERE alert_id = %s", (alert_id,)).fetchone()[0]
    assert status == "queued_tier1"


# ---------------------------------------------------------------------------
# Session and unknown-id handling
# ---------------------------------------------------------------------------


def test_page_without_session_redirects_to_login(db) -> None:
    main.app.dependency_overrides[deps.get_conn] = lambda: db
    main.app.dependency_overrides[deps.get_config] = lambda: config.Config()
    try:
        tc = TestClient(main.app, follow_redirects=False)
        resp = tc.get("/alerts/does-not-exist")
    finally:
        main.app.dependency_overrides.pop(deps.get_conn, None)
        main.app.dependency_overrides.pop(deps.get_config, None)
    assert resp.status_code == 303, resp.text
    assert resp.headers["location"] == "/login"


def test_unknown_alert_is_404(client) -> None:
    resp = client.http.get("/alerts/does-not-exist")
    assert resp.status_code == 404, resp.text
    # Review round 1, nit N7: an HTML page (through `templating.render`, same as
    # every other page), never a bare `HTTPException`'s JSON body.
    assert resp.headers["content-type"].startswith("text/html")
    assert "Không tìm thấy alert" in resp.text


def test_before_swap_listener_present(db, client) -> None:
    alert_id = _queued(db)

    resp = client.http.get(f"/alerts/{alert_id}")
    assert resp.status_code == 200, resp.text
    assert "shouldSwap" in resp.text
    assert "409" in resp.text and "422" in resp.text and "503" in resp.text


# ---------------------------------------------------------------------------
# Review round 1 — blocker B1, shoulds S2-S5, nits N6-N9
# ---------------------------------------------------------------------------


def test_flash_placeholder_precedes_decision(db, client) -> None:
    """Blocker B1: an empty `<div id="flash"></div>` outside `#decision` is the only
    landing zone `_flash.html`'s OOB fragment has on first load (`flash` is always
    `None` on a GET, so `_flash.html`'s own conditional div never renders). Exactly
    one `id="flash"` on the page, and it comes before `id="decision"`."""
    alert_id = _queued(db)

    resp = client.http.get(f"/alerts/{alert_id}")
    assert resp.status_code == 200, resp.text
    assert resp.text.count('id="flash"') == 1
    assert resp.text.index('id="flash"') < resp.text.index('id="decision"')


def test_queue_flash_closed_shows_message(db, client) -> None:
    """Should S2: the decide-success confirmation now arrives as
    `?flash=closed&n=<closed_count>` on the redirect target, not a dead HX-Redirect
    body — `/queue` builds the fixed message from it."""
    resp = client.http.get("/queue", params={"flash": "closed", "n": "3"})
    assert resp.status_code == 200, resp.text
    assert "Đã đóng cụm (3 alert)" in resp.text


def test_queue_flash_unknown_kind_shows_nothing(db, client) -> None:
    """Should S2: an unrecognised `flash` kind is dropped whole, never echoed —
    `?flash=<script>` never reaches the page at all, not even escaped."""
    resp = client.http.get("/queue", params={"flash": "<script>alert(1)</script>"})
    assert resp.status_code == 200, resp.text
    assert "<script>alert(1)</script>" not in resp.text
    assert "&lt;script&gt;" not in resp.text


def test_queue_flash_bad_n_shows_nothing(db, client) -> None:
    """Should S2: `n=abc` (not digits-only) suppresses the whole flash rather than
    interpolating something broken or unbounded."""
    resp = client.http.get("/queue", params={"flash": "closed", "n": "abc"})
    assert resp.status_code == 200, resp.text
    assert "Đã đóng cụm" not in resp.text


@pytest.mark.parametrize(
    "params",
    [
        {"flash": "closed", "n": "12\n"},
        {"flash": "closed", "n": "1234567"},
        {"flash": "escalated", "case": "abc12345\n"},
    ],
)
def test_queue_flash_rejects_a_trailing_newline_and_an_unbounded_n(db, client, params) -> None:
    """Added by the Director at merge (review round 2 nit): the values are matched whole,
    so a trailing newline no longer passes and `n` is at most six digits."""
    resp = client.http.get("/queue", params=params)
    assert resp.status_code == 200, resp.text
    assert "Đã đóng cụm" not in resp.text
    assert "Đã mở case" not in resp.text


def test_queue_flash_escalated_with_cut_shows_case_and_truncation(db, client) -> None:
    """Should S2: the escalate-success confirmation, `case` an 8-hex id, `cut=1`
    appending the truncation note (`cfg.MAX_ALERTS_PER_CASE`, default 200)."""
    resp = client.http.get("/queue", params={"flash": "escalated", "case": "abc12345", "cut": "1"})
    assert resp.status_code == 200, resp.text
    assert "Đã mở case abc12345" in resp.text
    assert "cắt ở 200 cụm" in resp.text


def test_queue_flash_bad_case_shows_nothing(db, client) -> None:
    """Should S2: `case` must be exactly 8 hex characters — anything else (here,
    a short, non-hex string) suppresses the flash."""
    resp = client.http.get("/queue", params={"flash": "escalated", "case": "not-hex!"})
    assert resp.status_code == 200, resp.text
    assert "Đã mở case" not in resp.text


def test_decision_controls_hidden_for_non_tier1(db, client) -> None:
    """Should S3: only `tier1` sees the decide/escalate controls — a tier2 or admin
    viewer sees a plain sentence instead, so a click never silently does nothing
    (the frozen `require_role("tier1")` 403 is JSON and htmx drops it unseen)."""
    alert_id = _active(db)
    client.as_role("tier2", TIER2_ID)

    resp = client.http.get(f"/alerts/{alert_id}")
    assert resp.status_code == 200, resp.text
    assert "Chỉ Tier 1 thao tác được" in resp.text
    assert f'hx-post="/alerts/{alert_id}/decide"' not in resp.text
    assert f'hx-post="/alerts/{alert_id}/escalate"' not in resp.text


def test_decision_controls_shown_for_tier1(db, client) -> None:
    """The mirror of the above: a tier1 viewer still sees the real controls."""
    alert_id = _active(db)

    resp = client.http.get(f"/alerts/{alert_id}")
    assert resp.status_code == 200, resp.text
    assert "Chỉ Tier 1 thao tác được" not in resp.text
    assert f'hx-post="/alerts/{alert_id}/decide"' in resp.text


def test_case_link_gated_by_role(db, client) -> None:
    """Should S3: `/cases/{id}` is tier2/admin's page — a tier1 viewer sees the
    short case id as plain text, never a link to a page they cannot open."""
    alert_id = _active(db)
    result = decide_module.escalate(
        db, alert_id, decide_module.Actor(TIER1_ID, "tier1"), title="brute force"
    )
    case_id = result["case_id"]

    resp_tier1 = client.http.get(f"/alerts/{alert_id}")
    assert resp_tier1.status_code == 200, resp_tier1.text
    assert f'href="/cases/{case_id}"' not in resp_tier1.text
    assert case_id[:8] in resp_tier1.text

    client.as_role("tier2", TIER2_ID)
    resp_tier2 = client.http.get(f"/alerts/{alert_id}")
    assert resp_tier2.status_code == 200, resp_tier2.text
    assert f'href="/cases/{case_id}"' in resp_tier2.text


def test_queue_visible_row_with_no_verdict_shows_chua_co(db, client) -> None:
    """Should S4: a visible head whose latest proposer run has no verdict yet
    (`result->>'suggested_action'` is NULL, the row's key is present but `None`)
    must render "chưa có", never the literal string "None (None)"."""
    alert_id = _queued(db, suggestion_visible=True)
    # No `_insert_run`: `suggested_action` is a present-but-NULL SQL column, not an
    # absent dict key (that only happens via `visibility.strip`'s removal).

    resp = client.http.get("/queue")
    assert resp.status_code == 200, resp.text
    assert "None (None)" not in resp.text
    row_start = resp.text.index(f'href="/alerts/{alert_id}"')
    row_end = resp.text.index("</tr>", row_start)
    assert "chưa có" in resp.text[row_start:row_end]


@pytest.mark.parametrize(
    "method,path_suffix,kwargs",
    [
        ("get", "", {}),
        ("post", "/acknowledge", {}),
        (
            "post",
            "/decide",
            {"data": {"decision": "benign", "reason": "x", "seen_occurrence_count": "1"}},
        ),
        ("post", "/escalate", {"data": {"title": "t"}}),
        ("post", "/reopen", {"data": {"reason": "x"}}),
    ],
)
def test_nul_byte_in_path_is_404_not_500(client, method, path_suffix, kwargs) -> None:
    """Nit N8: a NUL byte in the `{alert_id}` path segment (`/alerts/a%00b...`) is
    rejected before any query — psycopg would otherwise raise a driver-level error,
    a 500, not a clean 404. `%00`, not a raw `\\x00`: httpx itself refuses to send a
    literal control character in a URL, so the percent-encoded form is what actually
    reaches the ASGI layer as a NUL byte once the router decodes the path segment."""
    resp = getattr(client.http, method)(f"/alerts/a%00b{path_suffix}", **kwargs)
    assert resp.status_code == 404, resp.text


def test_decide_bad_decision_on_unknown_alert_is_404_not_500(client) -> None:
    """Nit N9: the `_decision_fragment`/`view is None` branch is reachable, not
    unreachable — `decide.decide` raises `ValueError` for a bad `decision` *before*
    it ever checks whether `alert_id` exists, so the re-read this router does on the
    `422` path can find a genuinely nonexistent alert."""
    resp = client.http.post(
        "/alerts/does-not-exist/decide",
        data={"decision": "not_a_real_choice", "reason": "x", "seen_occurrence_count": "1"},
    )
    assert resp.status_code == 404, resp.text


def test_decide_invalid_severity_on_escalate_is_422_with_fixed_vietnamese_text(
    db, real_shape_client
) -> None:
    """Nit N6: a fixed Vietnamese sentence, never `str(exc)` — an invalid `severity`
    is this router's own check (`decide.escalate` does not validate it itself).
    `real_shape_client`, not the plain `client` fixture: this router's 422 path calls
    a real `conn.rollback()` (pitfall 1's pattern extends to every non-2xx fragment),
    which on the plain fixture's shared, uncommitted `db` connection would also undo
    this test's own `_active` setup."""
    client, _calls = real_shape_client
    alert_id = _active(db)

    resp = client.http.post(
        f"/alerts/{alert_id}/escalate", data={"title": "t", "severity": "not-a-real-severity"}
    )
    assert resp.status_code == 422, resp.text
    assert "Mức độ nghiêm trọng không hợp lệ." in resp.text
    assert "not-a-real-severity" not in resp.text


def test_reopen_nul_byte_reason_is_422_with_fixed_vietnamese_text(db, real_shape_client) -> None:
    """Nit N6: the NUL-byte branch of `_error_text`, not the generic reason text —
    proven on `reopen` (the other two routes' NUL case is `test_api_nul_byte_in_
    reason_or_title_is_422`'s pattern at the API layer, already covered there).
    `real_shape_client` for the same reason as the severity test above."""
    client, _calls = real_shape_client
    alert_id = _auto_closed(db)

    resp = client.http.post(f"/alerts/{alert_id}/reopen", data={"reason": "a\x00b"})
    assert resp.status_code == 422, resp.text
    assert "Dữ liệu chứa ký tự không hợp lệ." in resp.text
