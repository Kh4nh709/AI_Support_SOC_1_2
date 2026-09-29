"""P5-T09 — the admin digest page: `web/routers/admin_digest.py`,
`web/templates/{digest,_digest_row}.html`. A screen over two functions
`app.tier1.digest` (P5-T08) already has and already tests (`build`, `review`)
— this file inserts alerts, rules and llm_runs directly with plain SQL and
never imports from `test_digest.py` (a different card's test file, out of
this card's scope), so it stays self-contained — the same convention
`test_pages_rules.py` documents for itself.

Every db-marked test uses the shared `db` fixture, overridden into the app as
`deps.get_conn` directly (no commit/rollback shape — `test_reload_inventory.py`'s
pattern): every write in a test is visible to that same test's own assertions
because they share one uncommitted transaction, and the fixture's teardown
rolls the whole thing back. `pages.page_user` and `deps.current_user` are both
overridden with a fixed `Claims`, matching `test_pages_rules.py`'s own
`client` fixture rather than the card's older "a real admin cookie" wording —
current code wins (Director's dispatch), and it is what every merged P5/P6
page test file actually does.

Two exceptions get their own scratch database, never the shared `db`
fixture's connection, because their one write is real and committed
regardless of `db`'s later rollback:

- `deps.require_role`'s dependency commits *before* raising its 403 (P4
  planning decision 3 — the `authz.denied` row must survive). Run on the
  shared session database this would leak a row past this file into whatever
  test runs next in the same `make test-db` session (`test_pages_rules.py`'s
  own docstring names the exact prior incident: `test_schema_v3_017.py`
  assumes `audit_events` starts empty). `test_non_admin_is_refused_...`
  therefore runs on its own scratch database (`sdb`/`scratch_dsn`).
- `test_409_rolls_back_before_a_later_commit_would_run` needs `get_conn`'s
  *real* shape (commit on success, rollback on exception) to prove the
  ordering (known pitfall 1) — `commit`/`rollback` are replaced with call
  recorders so nothing really persists, and the genuine `rollback` runs at
  teardown, before the `db` fixture's own (`test_tier1_api.py`'s
  `real_shape_client` pattern for P4-T03's `_conflict_response`).

Review round 1 (DEC-151): a third test needs the same treatment for a
different reason —
`test_non_admin_is_refused_and_authz_denied_row_persists_on_another_connection`
must prove `authz.denied` is durable, not merely visible to the same
session that wrote it, so its `get_conn` wraps the scratch connection in
the real commit/rollback shape (`test_auth.py`'s own `client` fixture
pattern) and the row is read back on a *second*, independent connection
(`test_auth.py:623-646`).
"""

from __future__ import annotations

import hashlib
import itertools
import os
import shutil
import subprocess
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import psycopg
import pytest
from app.infra import auth
from app.infra.auth import Claims
from app.web import deps, main
from app.web.routers import admin_digest, pages
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from tests import conftest

REPO_ROOT = Path(__file__).resolve().parents[2]
_TZ = "Asia/Ho_Chi_Minh"  # UTC+7, no DST — cfg.DISPLAY_TZ's default
_DAY = "2026-09-29"
# Local day 2026-09-29 (ICT) spans [2026-09-28 17:00 UTC, 2026-09-29 17:00 UTC).
_IN_DAY = datetime(2026, 9, 29, 10, 0, tzinfo=UTC)  # 17:00 ICT on the 29th

_counter = itertools.count()


# ---------------------------------------------------------------------------
# Fixture helpers — plain SQL, self-contained (test_pages_rules.py's own
# convention: not imported from test_digest.py, a different card's file)
# ---------------------------------------------------------------------------


def _hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _seed_claims(conn: Any, *, role: str, prefix: str) -> tuple[str, Claims]:
    user_id = auth.create_user(
        conn,
        username=f"p5t09-{prefix}-{uuid.uuid4().hex[:8]}",
        display_name="P5-T09 Test",
        role=role,
        password="unused",
    )
    claims = Claims(user_id=user_id, username=f"p5t09-{prefix}", role=role, iat=0.0, exp=0.0)
    return user_id, claims


def _seed_admin(conn: Any) -> tuple[str, Claims]:
    return _seed_claims(conn, role="admin", prefix="admin")


def _make_autoclose_rule(
    conn: Any, user_id: str, *, name: str = "known-scanner", match: list | None = None
) -> str:
    """`match=[]` (the default) is the whitelist's "matches everything" shape
    (`ingest.autoclose._parse_match`/`_rule_matches`'s own contract) — an
    empty **dict** parses to `None` and the rule is silently skipped whole by
    `load_rules`, which is exactly the "chưa có rule" empty state this file
    also has to tell apart from "no cluster today"."""
    rule_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO autoclose_rules (autoclose_rule_id, name, match, reason, created_by) "
        "VALUES (%s, %s, %s, %s, %s)",
        (rule_id, name, Jsonb(match if match is not None else []), "matched scanner", user_id),
    )
    return rule_id


def _insert_alert(
    conn: Any,
    *,
    alert_id: str | None = None,
    status: str = "auto_closed",
    closed_at: datetime | None = _IN_DAY,
    sealed_at: datetime | None = None,
    autoclose_rule_id: str | None = None,
    occurrence_count: int = 1,
    agent_name: str = "host-1",
    severity: str = "high",
    category: str = "brute_force",
    description: str = "SSH brute force",
    is_synthetic: bool = False,
) -> str:
    """A direct INSERT bypassing `domain.transitions.open_alert`, matching
    `test_digest.py`/`test_transitions.py`/`test_queue.py`'s own convention
    for setting up an arbitrary starting status."""
    alert_id = alert_id or f"digest-page-{next(_counter)}"
    conn.execute(
        """
        INSERT INTO alerts (
            alert_id, rule_id, rule_level, severity, description, agent_name,
            alert_time, category, resolved_by, mapping_version,
            event_bucket_hash, raw_payload, status, occurrence_count,
            closed_at, sealed_at, autoclose_rule_id, close_reason, is_synthetic
        ) VALUES (
            %s, '40112', 10, %s, %s, %s,
            now(), %s, 'rule_groups', 'v1',
            %s, %s, %s, %s,
            %s, %s, %s, %s, %s
        )
        """,
        (
            alert_id,
            severity,
            description,
            agent_name,
            category,
            _hash(alert_id),
            Jsonb({}),
            status,
            occurrence_count,
            closed_at,
            sealed_at,
            autoclose_rule_id,
            "matched scanner" if closed_at is not None else None,
            is_synthetic,
        ),
    )
    return alert_id


def _insert_run(
    conn: Any, alert_id: str, *, suggested_action: str | None, role: str = "proposer"
) -> str:
    """One `llm_runs` row in P3-T10's shape (`test_digest.py`'s own convention)."""
    import json

    result = {"suggested_action": suggested_action, "confidence": "high", "reasons": []}
    row = conn.execute(
        """
        INSERT INTO llm_runs (
            run_id, pipeline, subject_type, subject_id, system_prompt,
            user_message, result, role, gate_result
        ) VALUES (
            gen_random_uuid(), 'triage', 'alert', %s, 's', 'u', %s::jsonb, %s, %s::jsonb
        ) RETURNING run_id
        """,
        (alert_id, json.dumps(result), role, json.dumps({})),
    ).fetchone()
    return str(row[0])


def _scoped(html: str, marker: str, *, until: str = "</tr>") -> str:
    """The substring of `html` from `marker` up to the next `until` — scopes
    an assertion to one row instead of the whole page/fragment
    (`test_pages_rules.py`'s own helper, same rationale)."""
    start = html.index(marker)
    end = html.index(until, start)
    return html[start:end]


# ---------------------------------------------------------------------------
# The client — get_conn -> db; page_user and current_user -> a fixed admin Claims
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
# The day: default is yesterday in DISPLAY_TZ; ?day= picks any day; a link
# to today is always present.
# ---------------------------------------------------------------------------


def test_display_tz_is_utc_plus_7() -> None:
    """Sanity check on the environment's tzdata (review round 1, nit 6): the
    day-boundary tests below assume Asia/Ho_Chi_Minh is a fixed UTC+7 with
    no DST — if this ever went red, every "default day"/"00:30 local"
    assertion below would be testing the wrong boundary."""
    assert admin_digest._now_local(_TZ).utcoffset() == timedelta(hours=7)


@pytest.mark.db
def test_default_day_is_yesterday_in_display_tz(client, monkeypatch) -> None:
    tc, _db, _admin_id = client
    monkeypatch.setattr(
        admin_digest, "_now_local", lambda tz: datetime(2026, 9, 30, 9, 0, tzinfo=ZoneInfo(tz))
    )
    resp = tc.get("/admin/digest")
    assert resp.status_code == 200
    assert 'data-field="day">2026-09-29<' in resp.text


@pytest.mark.db
def test_default_day_at_0030_local_is_still_yesterday(client, monkeypatch) -> None:
    """Review round 1, nit 6: 00:30 local on the 30th is 17:30 UTC on the
    29th — if the default-day seam ever confused the two clocks (used UTC's
    date instead of the local one), "yesterday" would come out as the 28th,
    not the 29th."""
    tc, _db, _admin_id = client
    monkeypatch.setattr(
        admin_digest, "_now_local", lambda tz: datetime(2026, 9, 30, 0, 30, tzinfo=ZoneInfo(tz))
    )
    resp = tc.get("/admin/digest")
    assert resp.status_code == 200
    assert 'data-field="day">2026-09-29<' in resp.text


@pytest.mark.db
def test_day_query_param_overrides_the_default(client) -> None:
    tc, db, admin_id = client
    rule_id = _make_autoclose_rule(db, admin_id)
    aid = _insert_alert(db, alert_id="d-picked", autoclose_rule_id=rule_id)
    resp = tc.get(f"/admin/digest?day={_DAY}")
    assert resp.status_code == 200
    assert 'data-field="day">' + _DAY in resp.text
    assert aid in resp.text


@pytest.mark.db
def test_malformed_day_falls_back_to_default_with_an_error_flash(client, monkeypatch) -> None:
    """Review round 1, nit 8: this is a page — it answers with HTML, never a
    bare JSON error body. A malformed `?day=` degrades gracefully to the
    usual default (yesterday, local) instead of refusing the whole page."""
    tc, _db, _admin_id = client
    monkeypatch.setattr(
        admin_digest, "_now_local", lambda tz: datetime(2026, 9, 30, 9, 0, tzinfo=ZoneInfo(tz))
    )
    resp = tc.get("/admin/digest?day=not-a-date")
    assert resp.status_code == 200
    assert 'data-field="day">2026-09-29<' in resp.text
    assert "Ngày không hợp lệ" in resp.text
    assert resp.text.count('id="flash"') == 1  # base.html's own, guarded digest.html placeholder


@pytest.mark.db
def test_today_link_present_and_correct(client, monkeypatch) -> None:
    tc, _db, _admin_id = client
    monkeypatch.setattr(
        admin_digest, "_now_local", lambda tz: datetime(2026, 9, 30, 9, 0, tzinfo=ZoneInfo(tz))
    )
    resp = tc.get("/admin/digest")
    assert 'href="/admin/digest?day=2026-09-30"' in resp.text
    assert "hôm nay (đến giờ)" in resp.text


# ---------------------------------------------------------------------------
# The two empty states (design note 1) — which of the two things is missing
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_empty_state_no_rules_at_all(client) -> None:
    tc, _db, _admin_id = client
    resp = tc.get(f"/admin/digest?day={_DAY}")
    assert resp.status_code == 200
    assert "Chưa có rule tự đóng nào đang bật." in resp.text
    assert "Không có cụm nào bị tự đóng trong ngày." not in resp.text


@pytest.mark.db
def test_empty_state_no_clusters_today(client) -> None:
    tc, db, admin_id = client
    _make_autoclose_rule(db, admin_id)
    resp = tc.get(f"/admin/digest?day={_DAY}")
    assert resp.status_code == 200
    assert "Không có cụm nào bị tự đóng trong ngày." in resp.text
    assert "Chưa có rule tự đóng nào đang bật." not in resp.text


@pytest.mark.db
def test_a_disabled_only_rule_with_no_rows_still_reads_as_no_rule(client) -> None:
    """`load_rules` (this page's read) only ever returns *enabled* rules — a
    rule that exists but is off cannot have closed anything today either, so
    the "why is this page empty" message stays the rule one — deviation 4,
    kept, with the review round 1 wording refinement ("...đang bật")."""
    tc, db, admin_id = client
    rule_id = _make_autoclose_rule(db, admin_id)
    db.execute(
        "UPDATE autoclose_rules SET enabled = false WHERE autoclose_rule_id = %s", (rule_id,)
    )
    resp = tc.get(f"/admin/digest?day={_DAY}")
    assert "Chưa có rule tự đóng nào đang bật." in resp.text


@pytest.mark.db
def test_rows_show_even_when_no_rule_is_currently_enabled(client) -> None:
    """Review round 1's blocker: a rule that closed clusters earlier and was
    then disabled must never hide those rows behind the "no rule" empty
    state — `rows` is checked first, `rules_exist` only when `rows` is
    itself empty. Red step: the card's original `{% if not rules_exist %}
    ... {% elif not rows %} ... {% else %}` ordering — this test goes red
    against it (the empty-no-rules sentence shows instead of the table)."""
    tc, db, admin_id = client
    rule_id = _make_autoclose_rule(db, admin_id)
    aid = _insert_alert(db, alert_id="row-survives-disable", autoclose_rule_id=rule_id)
    db.execute(
        "UPDATE autoclose_rules SET enabled = false WHERE autoclose_rule_id = %s", (rule_id,)
    )
    resp = tc.get(f"/admin/digest?day={_DAY}")
    assert resp.status_code == 200
    assert "Chưa có rule tự đóng nào đang bật." not in resp.text
    assert "Không có cụm nào bị tự đóng trong ngày." not in resp.text
    assert f'data-alert-id="{aid}"' in resp.text


# ---------------------------------------------------------------------------
# Disagreements sort first, and carry a visible marker; escaping
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_disagreement_sorts_first_and_carries_a_marker(client) -> None:
    tc, db, admin_id = client
    rule_id = _make_autoclose_rule(db, admin_id)
    agree_id = _insert_alert(db, alert_id="agree-1", autoclose_rule_id=rule_id, occurrence_count=5)
    disagree_id = _insert_alert(
        db, alert_id="disagree-1", autoclose_rule_id=rule_id, occurrence_count=1
    )
    _insert_run(db, agree_id, suggested_action="false_positive")
    _insert_run(db, disagree_id, suggested_action="escalate")

    resp = tc.get(f"/admin/digest?day={_DAY}")
    assert resp.status_code == 200
    # Higher occurrence_count would sort first among equals, but a disagreement
    # outranks it — proves the page renders build()'s order, not its own.
    assert resp.text.index(disagree_id) < resp.text.index(agree_id)

    disagree_row = _scoped(resp.text, f'data-alert-id="{disagree_id}"')
    assert 'data-field="disagreement-marker"' in disagree_row
    agree_row = _scoped(resp.text, f'data-alert-id="{agree_id}"')
    assert 'data-field="disagreement-marker"' not in agree_row


@pytest.mark.db
def test_no_suggestion_is_not_a_disagreement(client) -> None:
    tc, db, admin_id = client
    rule_id = _make_autoclose_rule(db, admin_id)
    aid = _insert_alert(db, alert_id="no-run", autoclose_rule_id=rule_id)
    resp = tc.get(f"/admin/digest?day={_DAY}")
    row = _scoped(resp.text, f'data-alert-id="{aid}"')
    assert 'data-field="disagreement-marker"' not in row
    assert "(chưa có kết quả ①)" in row


@pytest.mark.db
def test_description_is_escaped(client) -> None:
    tc, db, admin_id = client
    rule_id = _make_autoclose_rule(db, admin_id)
    _insert_alert(
        db,
        alert_id="xss-1",
        autoclose_rule_id=rule_id,
        description="<script>bad()</script>",
    )
    resp = tc.get(f"/admin/digest?day={_DAY}")
    assert "<script>bad()</script>" not in resp.text
    assert "&lt;script&gt;bad()&lt;/script&gt;" in resp.text


def test_no_safe_filter_in_digest_templates() -> None:
    templates_dir = REPO_ROOT / "backend" / "app" / "web" / "templates"
    for name in ("digest.html", "_digest_row.html"):
        text = (templates_dir / name).read_text(encoding="utf-8")
        assert "|safe" not in text, name


# ---------------------------------------------------------------------------
# Each button, through the page — one click, one row, no page reload
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_get_page_buttons_target_their_own_alert_id(client) -> None:
    """Red step (a): a hardcoded/shared alert_id in even one of a row's three
    buttons would drop this row's occurrence count below 3 while a generic
    "page renders" check stayed green. Counting (not just `in`) matters: a
    constant hardcoded into only one of the three buttons still leaves the
    other two correct, so a bare membership check would not catch it."""
    tc, db, admin_id = client
    rule_id = _make_autoclose_rule(db, admin_id)
    first = _insert_alert(db, alert_id="btn-a", autoclose_rule_id=rule_id)
    second = _insert_alert(db, alert_id="btn-b", autoclose_rule_id=rule_id)
    resp = tc.get(f"/admin/digest?day={_DAY}")
    assert resp.status_code == 200
    assert resp.text.count(f'hx-post="/admin/digest/{first}/review"') == 3
    assert resp.text.count(f'hx-post="/admin/digest/{second}/review"') == 3


@pytest.mark.db
def test_review_posts_to_the_clicked_rows_own_alert_id(client) -> None:
    """Red step (a), the POST side: reviewing one row must never touch a
    sibling row's alert."""
    tc, db, admin_id = client
    rule_id = _make_autoclose_rule(db, admin_id)
    first = _insert_alert(db, alert_id="row-a", autoclose_rule_id=rule_id)
    second = _insert_alert(db, alert_id="row-b", autoclose_rule_id=rule_id)

    resp = tc.post(f"/admin/digest/{second}/review", data={"day": _DAY, "verdict": "correct"})
    assert resp.status_code == 200
    assert f'data-alert-id="{second}"' in resp.text

    reviewed = [r[0] for r in db.execute("SELECT alert_id FROM autoclose_reviews").fetchall()]
    assert reviewed == [second]
    status_first = db.execute("SELECT status FROM alerts WHERE alert_id = %s", (first,)).fetchone()[
        0
    ]
    assert status_first == "auto_closed"


@pytest.mark.db
def test_correct_writes_the_label_and_shows_the_reviewed_row(client) -> None:
    tc, db, admin_id = client
    rule_id = _make_autoclose_rule(db, admin_id)
    aid = _insert_alert(db, alert_id="v-correct", autoclose_rule_id=rule_id)

    resp = tc.post(f"/admin/digest/{aid}/review", data={"day": _DAY, "verdict": "correct"})
    assert resp.status_code == 200
    assert 'data-field="reviewed-verdict">Đúng<' in resp.text
    row_html = _scoped(resp.text, f'data-alert-id="{aid}"')
    assert "hx-post=" not in row_html  # the buttons are gone

    label = db.execute(
        "SELECT label, source FROM triage_labels WHERE alert_id = %s", (aid,)
    ).fetchone()
    assert label == ("false_positive", "digest")
    status = db.execute("SELECT status FROM alerts WHERE alert_id = %s", (aid,)).fetchone()[0]
    assert status == "auto_closed"


@pytest.mark.db
def test_wrong_reopens_the_alert_and_the_row_says_so(client) -> None:
    """Review round 1, should-2: both assertions are scoped to the returned
    *row*, not the whole response (which also contains the flash — a
    page-wide `in resp.text` check would pass even if the row itself said
    nothing), and the description is distinctive enough that `in` cannot be
    vacuously true."""
    tc, db, admin_id = client
    rule_id = _make_autoclose_rule(db, admin_id)
    aid = _insert_alert(
        db,
        alert_id="v-wrong",
        autoclose_rule_id=rule_id,
        description="distinctive-brute-force-marker-9f3c",
    )

    resp = tc.post(f"/admin/digest/{aid}/review", data={"day": _DAY, "verdict": "wrong"})
    assert resp.status_code == 200
    row_html = _scoped(resp.text, f'data-alert-id="{aid}"')
    assert 'data-field="reopened-note"' in row_html
    assert "đã mở lại về hàng đợi Tier 1" in row_html
    # The reopened row is still built from the pre-call snapshot: its
    # cosmetic data survives even though build() would no longer return it.
    assert 'data-field="description">distinctive-brute-force-marker-9f3c<' in row_html
    # The flash also carries the note, in the sentence-case combined form
    # (review round 1, nit 11).
    assert "Đã ghi nhận: Sai — đã mở lại về hàng đợi Tier 1" in resp.text

    status = db.execute("SELECT status FROM alerts WHERE alert_id = %s", (aid,)).fetchone()[0]
    assert status == "queued_tier1"
    labels = db.execute(
        "SELECT count(*) FROM triage_labels WHERE alert_id = %s", (aid,)
    ).fetchone()[0]
    assert labels == 0


@pytest.mark.db
def test_a_reopened_alert_is_gone_from_the_next_page_render(client) -> None:
    """`build()` only lists `auto_closed` rows — confirms the digest.py
    contract this router relies on for the wrong-verdict deviation."""
    tc, db, admin_id = client
    rule_id = _make_autoclose_rule(db, admin_id)
    aid = _insert_alert(db, alert_id="v-wrong-gone", autoclose_rule_id=rule_id)
    tc.post(f"/admin/digest/{aid}/review", data={"day": _DAY, "verdict": "wrong"})

    resp = tc.get(f"/admin/digest?day={_DAY}")
    assert aid not in resp.text


@pytest.mark.db
def test_unsure_writes_only_the_review(client) -> None:
    tc, db, admin_id = client
    rule_id = _make_autoclose_rule(db, admin_id)
    aid = _insert_alert(db, alert_id="v-unsure", autoclose_rule_id=rule_id)

    resp = tc.post(f"/admin/digest/{aid}/review", data={"day": _DAY, "verdict": "unsure"})
    assert resp.status_code == 200
    assert 'data-field="reviewed-verdict">Không chắc<' in resp.text

    labels = db.execute(
        "SELECT count(*) FROM triage_labels WHERE alert_id = %s", (aid,)
    ).fetchone()[0]
    assert labels == 0
    status = db.execute("SELECT status FROM alerts WHERE alert_id = %s", (aid,)).fetchone()[0]
    assert status == "auto_closed"


# ---------------------------------------------------------------------------
# A 409 is a normal outcome, not an error (design note 4) — and it re-reads
# the database rather than replaying the pre-call snapshot (design note 2 /
# red step (b))
# ---------------------------------------------------------------------------


@pytest.fixture
def scratch_client(scratch_dsn):
    """Like `client`, but `get_conn` opens a *fresh* connection per request
    with the real commit-on-success / rollback-on-error shape — needed only
    when an EARLIER request's write must durably survive a LATER request's
    rollback, the way it does in production (`get_conn`'s `scope="function"`
    exit code). The naive `client` fixture shares one never-committed
    transaction across every request in a test, so a later request's
    `conn.rollback()` would wipe out an earlier request's write too — a test
    artefact, not the real behaviour. Backed by the scratch database
    (module-scoped, dropped and rebuilt at the start of this module's run,
    `scratch_dsn` below), so these real commits never touch the shared
    per-coder `soc_p5t09_test`."""

    def get_conn():
        conn = psycopg.connect(scratch_dsn)
        try:
            yield conn
        except BaseException:
            conn.rollback()
            raise
        else:
            conn.commit()
        finally:
            conn.close()

    setup_conn = psycopg.connect(scratch_dsn)
    try:
        admin_id, claims = _seed_admin(setup_conn)
        setup_conn.commit()
    finally:
        setup_conn.close()

    main.app.dependency_overrides[deps.get_conn] = get_conn
    main.app.dependency_overrides[deps.current_user] = lambda: claims
    main.app.dependency_overrides[pages.page_user] = lambda: claims
    try:
        yield TestClient(main.app, follow_redirects=False), scratch_dsn, admin_id
    finally:
        main.app.dependency_overrides.pop(deps.get_conn, None)
        main.app.dependency_overrides.pop(deps.current_user, None)
        main.app.dependency_overrides.pop(pages.page_user, None)


@pytest.mark.db
def test_second_review_is_409_and_shows_the_first_reviewers_verdict(scratch_client) -> None:
    tc, scratch_dsn, admin_id = scratch_client
    setup_conn = psycopg.connect(scratch_dsn)
    try:
        rule_id = _make_autoclose_rule(setup_conn, admin_id)
        aid = _insert_alert(setup_conn, alert_id="v-race", autoclose_rule_id=rule_id)
        setup_conn.commit()
    finally:
        setup_conn.close()

    first = tc.post(f"/admin/digest/{aid}/review", data={"day": _DAY, "verdict": "correct"})
    assert first.status_code == 200

    second = tc.post(f"/admin/digest/{aid}/review", data={"day": _DAY, "verdict": "unsure"})
    assert second.status_code == 409
    assert "Cụm này đã được duyệt trước đó" in second.text
    # request 1 committed for real (this fixture's whole point), so its
    # verdict is durably visible to request 2's own read, whether that read
    # happens before or after request 2's `review()` call — end to end, the
    # conflict correctly shows the first reviewer's "Đúng", never a stack
    # trace and never a silent no-op (design note 4).
    assert 'data-field="reviewed-verdict">Đúng<' in second.text

    check_conn = psycopg.connect(scratch_dsn)
    try:
        reviews = check_conn.execute(
            "SELECT verdict FROM autoclose_reviews WHERE alert_id = %s", (aid,)
        ).fetchall()
        assert [r[0] for r in reviews] == ["correct"]  # the second attempt wrote nothing
    finally:
        check_conn.rollback()
        check_conn.close()


@pytest.mark.db
def test_conflict_fragment_uses_the_post_rollback_reread_not_the_pre_call_snapshot(
    scratch_client, monkeypatch
) -> None:
    """Red step (b), isolated from timing coincidence: `digest.build` is
    wrapped so its *first* call within the request (the pre-`review()`
    snapshot) reports no reviewed_verdict for this alert — standing in for
    genuine interleaving — while later calls see the real, already-conflicting
    state. The competing review is committed for real (`scratch_client`), so
    it survives this request's own `conn.rollback()` and a second, undoctored
    `build()` call can find it. If the handler rendered the first call's
    (doctored) result instead of calling `build()` again after the rollback,
    this would see no verdict at all, never "Đúng"."""
    tc, scratch_dsn, admin_id = scratch_client
    setup_conn = psycopg.connect(scratch_dsn)
    try:
        rule_id = _make_autoclose_rule(setup_conn, admin_id)
        aid = _insert_alert(setup_conn, alert_id="v-reread", autoclose_rule_id=rule_id)
        other_id, _other_claims = _seed_claims(setup_conn, role="admin", prefix="other")
        setup_conn.commit()
    finally:
        setup_conn.close()

    from app.tier1 import digest as digest_module

    real_review_conn = psycopg.connect(scratch_dsn)
    try:
        digest_module.review(real_review_conn, aid, "correct", other_id)
        real_review_conn.commit()
    finally:
        real_review_conn.close()

    real_build = digest_module.build
    calls = {"n": 0}

    def stale_first_call(conn, day, *, tz=None):
        calls["n"] += 1
        rows = real_build(conn, day, tz=tz)
        if calls["n"] == 1:
            import dataclasses as dc

            rows = [dc.replace(r, reviewed_verdict=None) if r.alert_id == aid else r for r in rows]
        return rows

    monkeypatch.setattr(admin_digest.digest, "build", stale_first_call)

    resp = tc.post(f"/admin/digest/{aid}/review", data={"day": _DAY, "verdict": "unsure"})
    assert resp.status_code == 409
    assert calls["n"] >= 2, "build() must be called again after the rollback, not just once"
    assert 'data-field="reviewed-verdict">Đúng<' in resp.text


@pytest.mark.db
def test_review_on_a_never_auto_closed_alert_is_409_stale_state(client) -> None:
    tc, _db, _admin_id = client
    aid = _insert_alert(
        _db, alert_id="v-notclosed", status="queued_tier1", closed_at=None, sealed_at=None
    )
    resp = tc.post(f"/admin/digest/{aid}/review", data={"day": _DAY, "verdict": "correct"})
    assert resp.status_code == 409
    assert "Cụm không còn ở trạng thái tự đóng" in resp.text


@pytest.mark.db
def test_review_on_an_already_reopened_alert_is_409_with_a_named_blank_row(client) -> None:
    """The alert left `auto_closed` entirely (a `wrong` review, from an
    earlier request in this same test). `build()` only lists `auto_closed`
    rows, so neither a fresh re-read nor this *second* request's own
    pre-call snapshot (captured after the alert was already reopened) has
    anything left to show for it — correctly so: there is nothing honest
    left to display. Review round 1, should-4: the row renders as one wide
    cell naming the alert id and the conflict, never nine empty-looking
    cells and a "Số lần 0" that reads as real (if odd) data."""
    tc, db, admin_id = client
    rule_id = _make_autoclose_rule(db, admin_id)
    aid = _insert_alert(
        db, alert_id="v-already-reopened", autoclose_rule_id=rule_id, description="zzz"
    )
    tc.post(f"/admin/digest/{aid}/review", data={"day": _DAY, "verdict": "wrong"})

    resp = tc.post(f"/admin/digest/{aid}/review", data={"day": _DAY, "verdict": "correct"})
    assert resp.status_code == 409
    assert "Cụm không còn ở trạng thái tự đóng" in resp.text
    row_html = _scoped(resp.text, f'data-alert-id="{aid}"')
    assert f'data-field="blank-conflict">Cụm {aid}:' in row_html
    assert "trạng thái đã thay đổi — tải lại trang" in row_html
    assert 'colspan="10"' in row_html
    assert "hx-post=" not in row_html  # no buttons are offered on a conflict row
    assert 'data-field="occurrence_count"' not in row_html  # no fake "Số lần 0"
    assert "zzz" not in row_html  # the stale cosmetic snapshot is not shown either


@pytest.mark.db
def test_409_rolls_back_before_a_later_commit_would_run(db, monkeypatch) -> None:
    """Known pitfall 1 (P4-T03's `_conflict_response` shape): a *returned*
    409 is a success as far as `get_conn` is concerned and would otherwise
    commit. `commit`/`rollback` are call recorders so nothing really
    persists; the genuine rollback runs at teardown."""
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

    admin_id, claims = _seed_admin(db)
    main.app.dependency_overrides[deps.get_conn] = get_conn
    main.app.dependency_overrides[deps.current_user] = lambda: claims
    main.app.dependency_overrides[pages.page_user] = lambda: claims
    try:
        tc = TestClient(main.app, follow_redirects=False)
        rule_id = _make_autoclose_rule(db, admin_id)
        aid = _insert_alert(db, alert_id="rb-race", autoclose_rule_id=rule_id)

        first = tc.post(f"/admin/digest/{aid}/review", data={"day": _DAY, "verdict": "correct"})
        assert first.status_code == 200
        calls.clear()  # only the second call's ordering is under test

        second = tc.post(f"/admin/digest/{aid}/review", data={"day": _DAY, "verdict": "unsure"})
        assert second.status_code == 409, second.text
        assert calls[:1] == ["rollback"], calls
    finally:
        for dep in (deps.get_conn, deps.current_user, pages.page_user):
            main.app.dependency_overrides.pop(dep, None)
        monkeypatch.undo()
        real_rollback()


# ---------------------------------------------------------------------------
# htmx 2.0.4 does not swap 4xx/5xx responses by default (known pitfall 3)
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_htmx_before_swap_listener_is_present(client) -> None:
    tc, _db, _admin_id = client
    resp = tc.get(f"/admin/digest?day={_DAY}")
    assert resp.status_code == 200
    assert "htmx:beforeSwap" in resp.text
    assert "shouldSwap = true" in resp.text
    assert "409" in resp.text
    assert "422" in resp.text
    assert "503" in resp.text


# ---------------------------------------------------------------------------
# Director heads-up (verified against htmx 2.0.4 in jsdom by the P4-T05
# review): an out-of-band swap with no matching id already in the DOM is
# silently dropped. This page never passes `flash` on GET, so base.html's
# own `{% include "_flash.html" %}` never renders `id="flash"` here — the
# page carries its own empty placeholder instead (fix (a)), and it must be
# the *only* one, in every branch, so htmx has exactly one place to land a
# row response's out-of-band flash div.
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_page_carries_exactly_one_flash_placeholder_with_rows(client) -> None:
    tc, db, admin_id = client
    rule_id = _make_autoclose_rule(db, admin_id)
    _insert_alert(db, alert_id="flash-target", autoclose_rule_id=rule_id)
    resp = tc.get(f"/admin/digest?day={_DAY}")
    assert resp.status_code == 200
    assert resp.text.count('id="flash"') == 1


@pytest.mark.db
def test_page_carries_exactly_one_flash_placeholder_empty_state(client) -> None:
    tc, _db, _admin_id = client
    resp = tc.get(f"/admin/digest?day={_DAY}")
    assert resp.status_code == 200
    assert "Chưa có rule tự đóng nào đang bật." in resp.text
    assert resp.text.count('id="flash"') == 1


@pytest.mark.db
def test_a_review_response_targets_the_pages_flash_placeholder_out_of_band(client) -> None:
    """The row fragment's own `_flash.html` include renders
    `hx-swap-oob="true"` on `id="flash"` — the same id the page's
    placeholder carries, so htmx has a real target to land it on."""
    tc, db, admin_id = client
    rule_id = _make_autoclose_rule(db, admin_id)
    aid = _insert_alert(db, alert_id="flash-oob", autoclose_rule_id=rule_id)
    resp = tc.post(f"/admin/digest/{aid}/review", data={"day": _DAY, "verdict": "correct"})
    assert resp.status_code == 200
    assert 'id="flash" hx-swap-oob="true"' in resp.text


# ---------------------------------------------------------------------------
# Role and refusal — its own scratch database (known pitfall 2): this is the
# one commit that is real (`require_role`'s commit-before-raise), and it must
# never land in the shared session database.
# ---------------------------------------------------------------------------


def _scratch_dbname() -> str:
    session = os.environ.get("TEST_DATABASE_URL", conftest.DEFAULT_TEST_DATABASE_URL)
    return f"{conftest._dbname(session)}_digest_scratch_test"


@pytest.fixture(scope="module")
def scratch_dsn():
    if shutil.which("psql") is None or shutil.which("createdb") is None:
        pytest.skip("psql/createdb not on PATH — cannot build the digest scratch database")
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


_PLACEHOLDER_ALERT_ID = "digest-403-placeholder"
_ADMIN_DIGEST_ROUTES: tuple[tuple[str, str, dict[str, Any]], ...] = (
    ("get", "/admin/digest", {}),
    (
        "post",
        f"/admin/digest/{_PLACEHOLDER_ALERT_ID}/review",
        {"data": {"day": _DAY, "verdict": "correct"}},
    ),
)


@pytest.mark.parametrize("method, path, kwargs", _ADMIN_DIGEST_ROUTES)
@pytest.mark.db
def test_non_admin_is_refused_and_authz_denied_row_persists_on_another_connection(
    sdb, scratch_dsn, method, path, kwargs
) -> None:
    """Review round 1, should-3: `sdb.execute(...)` reading back on the
    *same* connection that wrote the row would pass even if `require_role`
    never called `conn.commit()` at all — same-session reads see their own
    uncommitted writes regardless. `get_conn` here has the real dependency's
    commit/rollback shape (`test_auth.py`'s `client` fixture pattern), and
    the row is read back on a *second*, independent connection
    (`test_auth.py:623-646`'s own pattern), so only a row that is genuinely,
    durably committed can make this test pass."""
    tier1_claims = Claims(user_id=str(uuid.uuid4()), username="t1", role="tier1", iat=0.0, exp=0.0)

    def get_conn():
        try:
            yield sdb
        except BaseException:
            sdb.rollback()
            raise
        else:
            sdb.commit()

    main.app.dependency_overrides[deps.get_conn] = get_conn
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
    with psycopg.connect(scratch_dsn) as other:
        row = other.execute(
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
# Review round 1, nit 7: a NUL byte in the path is 404, never 500
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_nul_byte_in_alert_id_is_404_not_500(client) -> None:
    tc, _db, _admin_id = client
    resp = tc.post("/admin/digest/%00/review", data={"day": _DAY, "verdict": "correct"})
    assert resp.status_code == 404, resp.text


# ---------------------------------------------------------------------------
# Review round 1, nit 8: a bad POST is still HTML — the row plus a flash,
# never a bare JSON error body
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_post_malformed_day_is_422_with_a_named_blank_row_and_flash(client) -> None:
    tc, db, admin_id = client
    rule_id = _make_autoclose_rule(db, admin_id)
    aid = _insert_alert(db, alert_id="bad-day-post", autoclose_rule_id=rule_id)
    resp = tc.post(f"/admin/digest/{aid}/review", data={"day": "not-a-date", "verdict": "correct"})
    assert resp.status_code == 422
    assert "Ngày không hợp lệ" in resp.text
    row_html = _scoped(resp.text, f'data-alert-id="{aid}"')
    assert f'data-field="blank-conflict">Cụm {aid}:' in row_html
    assert 'colspan="10"' in row_html
    # Nothing was written — the malformed day is rejected before any review.
    reviewed = db.execute(
        "SELECT count(*) FROM autoclose_reviews WHERE alert_id = %s", (aid,)
    ).fetchone()[0]
    assert reviewed == 0


@pytest.mark.db
def test_post_invalid_verdict_is_422_with_the_real_row_and_flash(client) -> None:
    tc, db, admin_id = client
    rule_id = _make_autoclose_rule(db, admin_id)
    aid = _insert_alert(
        db, alert_id="bad-verdict-post", autoclose_rule_id=rule_id, description="keep-me"
    )
    resp = tc.post(f"/admin/digest/{aid}/review", data={"day": _DAY, "verdict": "maybe"})
    assert resp.status_code == 422
    assert "Đánh giá không hợp lệ" in resp.text
    row_html = _scoped(resp.text, f'data-alert-id="{aid}"')
    # The alert's own row is still known (unlike the blank-row case above),
    # so it renders normally — cosmetic data and all three buttons intact —
    # rather than as a named blank conflict row.
    assert 'data-field="description">keep-me<' in row_html
    assert resp.text.count(f'hx-post="/admin/digest/{aid}/review"') == 3
    reviewed = db.execute(
        "SELECT count(*) FROM autoclose_reviews WHERE alert_id = %s", (aid,)
    ).fetchone()[0]
    assert reviewed == 0


# ---------------------------------------------------------------------------
# Review round 1, nit 9: the rule cell is two columns
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_rule_cell_is_split_into_two_columns(client) -> None:
    tc, db, admin_id = client
    rule_id = _make_autoclose_rule(db, admin_id, name="named-scanner-rule")
    aid = _insert_alert(db, alert_id="split-cols", autoclose_rule_id=rule_id)
    resp = tc.get(f"/admin/digest?day={_DAY}")
    assert resp.status_code == 200
    assert "<th>Rule tự đóng</th><th>Rule</th>" in resp.text
    row_html = _scoped(resp.text, f'data-alert-id="{aid}"')
    assert 'data-field="autoclose_rule_name">named-scanner-rule<' in row_html
    assert 'data-field="rule_id">40112<' in row_html


# ---------------------------------------------------------------------------
# Review round 1, nit 10: the reopened note is a per-response flag, never
# derived from a (possibly stale) reviewed_verdict == "wrong"
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_a_stale_wrong_verdict_on_page_render_carries_no_reopened_note(client) -> None:
    """P5-T08's own recorded limit: `autoclose_reviews` is keyed on
    `alert_id` alone, so an alert that was auto-closed, reviewed `wrong`
    (reopening it), and later auto-closed *again* still carries its old
    `wrong` review row when `build()` joins it back in. The page must show
    "Sai" (the historical verdict is real) without implying *this* render
    just reopened it — the note is this request's own flag, not derived
    from `reviewed_verdict`."""
    tc, db, admin_id = client
    rule_id = _make_autoclose_rule(db, admin_id)
    aid = _insert_alert(db, alert_id="stale-wrong", autoclose_rule_id=rule_id)
    db.execute(
        "INSERT INTO autoclose_reviews (alert_id, reviewer_id, verdict) VALUES (%s, %s, 'wrong')",
        (aid, admin_id),
    )
    # Simulate the second auto-close the limit describes: still auto_closed
    # by the time this page renders, with the old review row still joined.
    resp = tc.get(f"/admin/digest?day={_DAY}")
    assert resp.status_code == 200
    row_html = _scoped(resp.text, f'data-alert-id="{aid}"')
    assert 'data-field="reviewed-verdict">Sai<' in row_html
    assert 'data-field="reopened-note"' not in row_html


# ---------------------------------------------------------------------------
# Review round 1, nit 5: a reviewed row is greyed, a disagreement is styled
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_reviewed_row_carries_the_reviewed_class(client) -> None:
    tc, db, admin_id = client
    rule_id = _make_autoclose_rule(db, admin_id)
    aid = _insert_alert(db, alert_id="greyed", autoclose_rule_id=rule_id)
    resp = tc.post(f"/admin/digest/{aid}/review", data={"day": _DAY, "verdict": "correct"})
    assert resp.status_code == 200
    assert f'data-alert-id="{aid}" class="reviewed' in resp.text


def test_style_block_covers_reviewed_and_disagreement_and_lives_in_digest_html() -> None:
    templates_dir = REPO_ROOT / "backend" / "app" / "web" / "templates"
    digest_text = (templates_dir / "digest.html").read_text(encoding="utf-8")
    assert "tr.reviewed" in digest_text
    assert "tr.disagreement" in digest_text
    base_text = (templates_dir / "base.html").read_text(encoding="utf-8")
    assert "reviewed" not in base_text
    assert "disagreement" not in base_text


# ---------------------------------------------------------------------------
# The page writes no SQL of its own — a Python-level sanity check alongside
# the Director's own grep acceptance
# ---------------------------------------------------------------------------


def test_router_has_no_raw_sql() -> None:
    import re

    text = (REPO_ROOT / "backend" / "app" / "web" / "routers" / "admin_digest.py").read_text(
        encoding="utf-8"
    )
    assert re.search(r"SELECT |INSERT |UPDATE ", text) is None
