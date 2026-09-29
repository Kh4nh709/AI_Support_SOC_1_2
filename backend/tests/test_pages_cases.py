"""web/routers/cases_pages.py — the case list and case detail pages (P5-T07):
`GET /cases`, `GET /cases/{case_id}`, `POST .../notes`, `POST .../conclude`.

`test_case_page_renders_without_the_investigation_partial` is this card's
most important test (design note 1): it forces `_investigation.html` to be
absent from the Jinja loader's search path — not merely relying on the fact
that P5-T05 has not merged into this worktree, which would make the test
vacuous the day it does — and asserts the page still renders. Removing
`ignore missing` from `case.html`'s include line turns this test red with
`TemplateNotFound` (DEC-025's red step (a), demonstrated by hand and
reverted — see the report).

`get_conn`'s override has the real dependency's shape (rollback on any
exception, no implicit commit) so the 403 test — `require_role` commits its
`authz.denied` row itself, before raising — never leaves a permanent row in
the shared `db` fixture's database (the pitfall that hit P5-T06's first
round; `test_tier2_api.py`'s pattern, reused here unchanged).
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import UTC, datetime

import jinja2
import psycopg
import pytest
from app.domain import transitions
from app.infra import config
from app.infra.auth import Claims
from app.tier2 import conclude
from app.web import deps, main, templating
from app.web.routers import pages
from fastapi.testclient import TestClient

pytestmark = pytest.mark.db

_PAST = datetime(2026, 1, 1, tzinfo=UTC)

# ---------------------------------------------------------------------------
# Fixture helpers — mirroring test_tier2_api.py's (P5-T06), this file's own
# copy: no test file imports helpers from another (project convention).
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
    severity: str = "high",
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
        (case_id, title, status, severity, user_id, concluded_at, concluded_by, conclusion_reason),
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
    raw_log: str = "",
    risk_score: int | None = None,
    last_seen_at=None,
) -> str:
    alert_id = f"p5t07-{uuid.uuid4()}"
    conn.execute(
        "INSERT INTO alerts (alert_id, rule_id, rule_level, severity, description, "
        "agent_name, alert_time, category, resolved_by, mapping_version, "
        "event_bucket_hash, raw_payload, raw_log, status, duplicate_of, case_id, closed_at, "
        "sealed_at, risk_score) "
        "VALUES (%s, '40112', 10, 'high', 'SSH brute force', 'agent-1', now(), "
        "'brute_force', 'rule_groups', 'v1', %s, '{}'::jsonb, %s, %s, %s, %s, %s, %s, %s)",
        (
            alert_id,
            hashlib.sha256(alert_id.encode()).hexdigest(),
            raw_log,
            status,
            duplicate_of,
            case_id,
            closed_at,
            sealed_at,
            risk_score,
        ),
    )
    if last_seen_at is not None:
        conn.execute(
            "UPDATE alerts SET last_seen_at = %s WHERE alert_id = %s", (last_seen_at, alert_id)
        )
    return alert_id


def _add_head(conn: psycopg.Connection, case_id: str, alert_id: str, added_by: str) -> None:
    conn.execute(
        "INSERT INTO case_alerts (case_id, alert_id, added_by) VALUES (%s, %s, %s)",
        (case_id, alert_id, added_by),
    )


class _Client:
    """`TestClient` plus the user/role the overridden auth dependencies answer
    as — the pattern `test_tier2_api.py`'s `_Client` uses. `page_user` does
    **not** go through `Depends(current_user)` — it calls `optional_user`
    directly inside its own body (`web/routers/pages.py`) — so both
    `deps.current_user` (for `require_role`'s internal check) and
    `pages.page_user` (for the page's own redirect-or-continue) must be
    overridden, the shape `test_labels.py`'s fixture uses."""

    def __init__(self, user_id: str) -> None:
        self.http = TestClient(main.app, follow_redirects=False)
        self.user_id = user_id
        self.role = "tier2"

    def claims(self) -> Claims:
        return Claims(user_id=self.user_id, username=self.user_id, role=self.role, iat=0.0, exp=0.0)


def _get_conn(db):
    # deps.get_conn's real shape: rollback on any exception, re-raise, no
    # implicit commit — this is the shared `db` fixture's own connection,
    # whose teardown rolls everything back. require_role's own inline
    # `conn.commit()` on the 403 path is handled per-test with a spy on
    # `db.commit` (see the 403 test below), never here.
    def get_conn():
        try:
            yield db
        except BaseException:
            db.rollback()
            raise

    return get_conn


@pytest.fixture
def client(db):
    user_id = _make_user(db)
    c = _Client(user_id)

    main.app.dependency_overrides[deps.get_conn] = _get_conn(db)
    main.app.dependency_overrides[deps.get_config] = lambda: config.Config()
    main.app.dependency_overrides[deps.current_user] = c.claims
    main.app.dependency_overrides[pages.page_user] = c.claims
    try:
        yield c
    finally:
        for dep in (deps.get_conn, deps.get_config, deps.current_user, pages.page_user):
            main.app.dependency_overrides.pop(dep, None)


# ---------------------------------------------------------------------------
# The seam — this card's most important test
# ---------------------------------------------------------------------------


class _NoInvestigationLoader(jinja2.BaseLoader):
    """Wraps the real loader and makes `_investigation.html` unconditionally
    `TemplateNotFound`, regardless of whether the file exists on disk — so
    this test still exercises the "partial absent" branch the day P5-T05
    merges `_investigation.html` into this same templates directory."""

    def __init__(self, real: jinja2.BaseLoader) -> None:
        self._real = real

    def get_source(self, environment, template):
        if template == "_investigation.html":
            raise jinja2.TemplateNotFound(template)
        return self._real.get_source(environment, template)


def test_case_page_renders_without_the_investigation_partial(client, db, monkeypatch):
    monkeypatch.setattr(
        templating.templates.env, "loader", _NoInvestigationLoader(templating.templates.env.loader)
    )
    case_id = _make_case(db, client.user_id)

    resp = client.http.get(f"/cases/{case_id}")

    assert resp.status_code == 200
    assert "TemplateNotFound" not in resp.text


# ---------------------------------------------------------------------------
# GET /cases — list, order, pager
# ---------------------------------------------------------------------------


def test_cases_list_orders_investigating_first_then_recent(client, db):
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

    resp = client.http.get("/cases")

    assert resp.status_code == 200
    text = resp.text
    assert text.index(recent_active) < text.index(old_active) < text.index(concluded)


def test_cases_list_shows_vietnamese_status_and_duplicate_inclusive_count(client, db):
    u = client.user_id
    case_id = _make_case(db, u, title="dup-case")
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

    resp = client.http.get("/cases")

    assert resp.status_code == 200
    assert "Đang điều tra" in resp.text
    # review round 1, nit N9: the old `or` made this assertion vacuous
    # ("cluster_count" is always in the row's own `data-field` attribute).
    row = resp.text[resp.text.index("dup-case") :].split("</tr>")[0]
    assert 'data-field="cluster_count">1<' in row
    assert 'data-field="occurrence_count">5<' in row


def test_cases_list_is_offset_paged(client, db):
    u = client.user_id
    [_make_case(db, u, title=f"case-{i}") for i in range(3)]

    resp = client.http.get("/cases", params={"offset": 1, "limit": 1})

    assert resp.status_code == 200
    assert resp.text.count('data-field="case_title"') == 1
    assert 'data-field="prev_page"' in resp.text
    assert 'data-field="next_page"' in resp.text


def test_cases_list_pager_hides_next_on_a_short_last_page(client, db):
    """Review round 1, alignment item: `next` never lands on an empty page —
    fewer rows than `limit` came back, so there is nothing after this page."""
    u = client.user_id
    [_make_case(db, u, title=f"short-page-{i}") for i in range(2)]

    resp = client.http.get("/cases", params={"offset": 0, "limit": 50})

    assert resp.status_code == 200
    assert 'data-field="next_page"' not in resp.text
    assert 'data-field="prev_page"' not in resp.text  # offset == 0 too


def test_cases_list_shows_never_analyzed_placeholder(client, db):
    _make_case(db, client.user_id, title="fresh-case")
    resp = client.http.get("/cases")
    assert "chưa phân tích" in resp.text


# ---------------------------------------------------------------------------
# GET /cases/{case_id} — detail
# ---------------------------------------------------------------------------


def test_case_detail_shows_per_head_duplicate_inclusive_occurrence_count(client, db):
    """`ingest/dedup.py`'s `bump_parent` is what actually increments a head's
    `occurrence_count` as duplicates arrive (already tested elsewhere); this
    test only proves the page renders that stored, already duplicate-inclusive
    column (`_HEAD_COLUMNS`'s `occurrence_count`, P5-T06) rather than a bare
    per-cluster count of 1."""
    u = client.user_id
    case_id = _make_case(db, u)
    head = _insert_alert(db, status="escalated_tier2", case_id=case_id)
    _add_head(db, case_id, head, u)
    db.execute("UPDATE alerts SET occurrence_count = 7 WHERE alert_id = %s", (head,))

    resp = client.http.get(f"/cases/{case_id}")

    assert resp.status_code == 200
    assert 'data-field="occurrence_count">7<' in resp.text


def test_case_detail_renders_risk_band_never_the_raw_score(client, db):
    u = client.user_id
    case_id = _make_case(db, u)
    head = _insert_alert(db, status="escalated_tier2", case_id=case_id, risk_score=83)
    _add_head(db, case_id, head, u)

    resp = client.http.get(f"/cases/{case_id}")

    assert resp.status_code == 200
    cell = re.search(r'data-field="risk_band">([^<]*)<', resp.text)
    assert cell is not None
    assert cell.group(1) == "Rất cao"  # risk_band(83) == "Rất cao" (75-100)
    assert "83" not in cell.group(1)
    # the bare number is not exposed as page data anywhere (P4's rule)
    assert "risk_score" not in resp.text


def test_case_detail_escapes_raw_log_script_tag(client, db):
    u = client.user_id
    case_id = _make_case(db, u)
    head = _insert_alert(
        db, status="escalated_tier2", case_id=case_id, raw_log="<script>alert(1)</script>"
    )
    _add_head(db, case_id, head, u)

    resp = client.http.get(f"/cases/{case_id}")

    assert resp.status_code == 200
    assert "<script>alert(1)</script>" not in resp.text
    assert "&lt;script&gt;" in resp.text


def test_case_detail_shows_raw_log_truncated_note(client, db):
    """Review round 1, alignment item: `raw_log_truncated` shows the cut
    line under the head's raw_log."""
    u = client.user_id
    case_id = _make_case(db, u)
    head = _insert_alert(db, status="escalated_tier2", case_id=case_id)
    _add_head(db, case_id, head, u)
    db.execute("UPDATE alerts SET raw_log_truncated = true WHERE alert_id = %s", (head,))

    resp = client.http.get(f"/cases/{case_id}")

    assert resp.status_code == 200
    assert 'data-field="raw_log_truncated"' in resp.text
    assert "[đã cắt ở 1000 KB]" in resp.text


def test_case_detail_shows_per_head_last_seen_at(client, db):
    """Review round 1, should S3: design note 3 lists `last_seen_at` as a
    per-head column. `ck_alerts_last_seen_khong_lui` forbids `last_seen_at <
    first_seen_at`, so it is moved forward from `now()`, not to a fixed past
    date."""
    u = client.user_id
    case_id = _make_case(db, u)
    head = _insert_alert(db, status="escalated_tier2", case_id=case_id)
    _add_head(db, case_id, head, u)
    db.execute(
        "UPDATE alerts SET last_seen_at = now() + interval '5 minutes' WHERE alert_id = %s",
        (head,),
    )

    resp = client.http.get(f"/cases/{case_id}")

    assert resp.status_code == 200
    assert 'data-field="last_seen_at"' in resp.text


def test_case_detail_404_when_absent_renders_html_not_json(client):
    """Review round 1, alignment item: an unknown case is an HTML page
    through `templating.render`, never a bare `HTTPException` JSON body."""
    resp = client.http.get(f"/cases/{uuid.uuid4()}")
    assert resp.status_code == 404
    assert resp.headers["content-type"].startswith("text/html")
    assert 'data-field="not_found"' in resp.text
    with pytest.raises(json.JSONDecodeError):
        json.loads(resp.text)


# ---------------------------------------------------------------------------
# Ongoing-cluster label — P7-2
# ---------------------------------------------------------------------------


def _ongoing_shown(resp) -> bool:
    return 'data-field="ongoing_label"' in resp.text


def test_ongoing_label_matrix(client, db):
    """Review round 1, blocker B1 — the five cases, in order, re-run from the
    Reviewer's probe (`test_zz_review_probe.py::test_ongoing_label_matrix`,
    read but not copied). `alerts.last_seen_at` is `NOT NULL DEFAULT now()`,
    so the old `last_seen is not None` rule showed the label on every open
    case — cases 1 and 3 below are exactly the two that caught it. Every
    statement in this test shares the `db` fixture's one open transaction, so
    every un-adjusted `now()` below is the *same* instant (`escalate`'s own
    shape — case and head inserted together); only an explicit `interval`
    offset moves a timestamp relative to it."""
    u = client.user_id

    # 1 · open, head never grew after escalation — hidden
    c1 = _make_case(db, u, title="never-grew")
    h1 = _insert_alert(db, status="escalated_tier2", case_id=c1)
    _add_head(db, c1, h1, u)

    # 2 · open, head bumped after the case was created — shown
    c2 = _make_case(db, u, title="grew")
    h2 = _insert_alert(db, status="escalated_tier2", case_id=c2)
    _add_head(db, c2, h2, u)
    db.execute(
        "UPDATE alerts SET last_seen_at = now() + interval '1 minute' WHERE alert_id = %s", (h2,)
    )

    # 3 · open, grew, then analysed after the last duplicate — hidden
    c3 = _make_case(db, u, title="analysed-after")
    h3 = _insert_alert(db, status="escalated_tier2", case_id=c3)
    _add_head(db, c3, h3, u)
    db.execute(
        "UPDATE alerts SET last_seen_at = now() + interval '1 minute' WHERE alert_id = %s", (h3,)
    )
    db.execute(
        "UPDATE cases SET last_analyzed_at = now() + interval '2 minutes' WHERE case_id = %s", (c3,)
    )

    # 4 · open, a duplicate arrived after the analysis — shown
    c4 = _make_case(db, u, title="grew-after-analysis")
    h4 = _insert_alert(db, status="escalated_tier2", case_id=c4)
    _add_head(db, c4, h4, u)
    db.execute(
        "UPDATE cases SET last_analyzed_at = now() + interval '2 minutes' WHERE case_id = %s", (c4,)
    )
    db.execute(
        "UPDATE alerts SET last_seen_at = now() + interval '3 minutes' WHERE alert_id = %s", (h4,)
    )

    # 5 · concluded (heads closed + sealed), last_seen_at after creation — hidden
    c5 = _make_case(
        db,
        u,
        title="concluded",
        status="concluded_fp",
        concluded_at=_PAST,
        concluded_by=u,
        conclusion_reason="x",
    )
    h5 = _insert_alert(db, status="closed_fp", case_id=c5, closed_at=_PAST, sealed_at=_PAST)
    _add_head(db, c5, h5, u)
    db.execute(
        "UPDATE alerts SET last_seen_at = now() + interval '1 minute' WHERE alert_id = %s", (h5,)
    )

    result = {
        "1 open, never grew": _ongoing_shown(client.http.get(f"/cases/{c1}")),
        "2 open, grew after creation": _ongoing_shown(client.http.get(f"/cases/{c2}")),
        "3 open, analysed after last dup": _ongoing_shown(client.http.get(f"/cases/{c3}")),
        "4 open, grew after analysis": _ongoing_shown(client.http.get(f"/cases/{c4}")),
        "5 concluded": _ongoing_shown(client.http.get(f"/cases/{c5}")),
    }
    assert result == {
        "1 open, never grew": False,
        "2 open, grew after creation": True,
        "3 open, analysed after last dup": False,
        "4 open, grew after analysis": True,
        "5 concluded": False,
    }


# ---------------------------------------------------------------------------
# POST /cases/{case_id}/notes — the _case_notes.html HTMX swap target
# ---------------------------------------------------------------------------


_HX = {"HX-Request": "true"}


def test_add_note_htmx_returns_the_notes_fragment_with_the_new_note(client, db):
    case_id = _make_case(db, client.user_id)

    resp = client.http.post(
        f"/cases/{case_id}/notes", data={"body": "watch this cluster"}, headers=_HX
    )

    assert resp.status_code == 200
    assert "watch this cluster" in resp.text
    assert 'id="case-notes"' in resp.text
    assert "<nav>" not in resp.text  # a fragment, not the whole page
    row = db.execute("SELECT body FROM case_notes WHERE case_id = %s", (case_id,)).fetchone()
    assert row[0] == "watch this cluster"


def test_add_note_htmx_empty_body_is_422_with_inline_vietnamese_error(client, db):
    case_id = _make_case(db, client.user_id)
    resp = client.http.post(f"/cases/{case_id}/notes", data={"body": "   "}, headers=_HX)
    assert resp.status_code == 422
    assert 'data-field="note_error"' in resp.text
    # review round 1, nit N7: a Vietnamese sentence, never str(ValueError)
    assert "must not be empty" not in resp.text
    assert "để trống" in resp.text
    assert (
        db.execute("SELECT count(*) FROM case_notes WHERE case_id = %s", (case_id,)).fetchone()[0]
        == 0
    )


def test_add_note_no_htmx_success_redirects(client, db):
    """Review round 1, nit N10: without an `HX-Request` header (a plain
    browser form submission, or a JS-disabled fallback) the route redirects
    like every other page mutation, instead of handing back a bare fragment
    no full-page load would ever render meaningfully."""
    case_id = _make_case(db, client.user_id)

    resp = client.http.post(f"/cases/{case_id}/notes", data={"body": "no js here"})

    assert resp.status_code == 303
    assert resp.headers["location"] == f"/cases/{case_id}"
    row = db.execute("SELECT body FROM case_notes WHERE case_id = %s", (case_id,)).fetchone()
    assert row[0] == "no js here"


def test_add_note_no_htmx_empty_body_422_redraws_case_page_with_flash(client, db):
    case_id = _make_case(db, client.user_id)
    resp = client.http.post(f"/cases/{case_id}/notes", data={"body": "   "})
    assert resp.status_code == 422
    assert 'id="flash"' in resp.text
    assert "để trống" in resp.text
    assert "<nav>" in resp.text  # the full case page, not the bare fragment


def test_add_note_unknown_case_is_404_html(client):
    resp = client.http.post(f"/cases/{uuid.uuid4()}/notes", data={"body": "orphan"})
    assert resp.status_code == 404
    assert 'data-field="not_found"' in resp.text


# ---------------------------------------------------------------------------
# POST /cases/{case_id}/conclude — posts to this page, not the JSON API
# ---------------------------------------------------------------------------


def test_conclude_form_has_client_side_required_on_reason(client, db):
    case_id = _make_case(db, client.user_id)
    resp = client.http.get(f"/cases/{case_id}")
    form = resp.text[resp.text.index("Kết luận case") - 400 : resp.text.index("Kết luận case") + 20]
    assert '<textarea id="reason" name="reason" required>' in form


def test_conclude_success_redirects_and_updates_status(client, db):
    u = client.user_id
    case_id = _make_case(db, u)
    head = _insert_alert(db, status="escalated_tier2", case_id=case_id)
    _add_head(db, case_id, head, u)

    resp = client.http.post(
        f"/cases/{case_id}/conclude", data={"conclusion": "concluded_fp", "reason": "scanner noise"}
    )

    assert resp.status_code == 303
    assert resp.headers["location"] == f"/cases/{case_id}"
    status = db.execute("SELECT status FROM cases WHERE case_id = %s", (case_id,)).fetchone()[0]
    assert status == "concluded_fp"


def test_conclude_empty_reason_is_422_server_side(client, db):
    case_id = _make_case(db, client.user_id)
    resp = client.http.post(
        f"/cases/{case_id}/conclude", data={"conclusion": "concluded_fp", "reason": "   "}
    )
    assert resp.status_code == 422
    assert 'id="flash"' in resp.text
    # review round 1, nit N7: a Vietnamese sentence, never str(ValueError)
    assert "must not be empty" not in resp.text
    assert "để trống" in resp.text
    status = db.execute("SELECT status FROM cases WHERE case_id = %s", (case_id,)).fetchone()[0]
    assert status == "investigating"


def test_conclude_missing_fields_are_422_not_a_bare_fastapi_error(client, db):
    """Review round 1, nit N7: `conclusion`/`reason` default to `""`, so a
    field missing from the POST body entirely still reaches
    `conclude.submit`'s own validation (a Vietnamese flash), rather than
    FastAPI's own JSON 422 for a required field."""
    case_id = _make_case(db, client.user_id)
    no_conclusion = client.http.post(f"/cases/{case_id}/conclude", data={"reason": "r"})
    no_reason = client.http.post(f"/cases/{case_id}/conclude", data={"conclusion": "concluded_fp"})
    for resp in (no_conclusion, no_reason):
        assert resp.status_code == 422
        assert 'id="flash"' in resp.text
        assert resp.headers["content-type"].startswith("text/html")


def test_conclude_409_renders_flash_naming_who_what_and_when(client, db):
    u = client.user_id
    other = _make_user(db)
    case_id = _make_case(
        db,
        u,
        status="concluded_fp",
        concluded_at=_PAST,
        concluded_by=other,
        conclusion_reason="prior",
    )
    concluder_name = db.execute(
        "SELECT username FROM users WHERE user_id = %s", (other,)
    ).fetchone()[0]

    resp = client.http.post(
        f"/cases/{case_id}/conclude", data={"conclusion": "confirmed_incident", "reason": "x"}
    )

    assert resp.status_code == 409
    assert 'id="flash"' in resp.text
    # review round 1, nit N6: docs/phase-7-tier2.md:349 — who, what and when
    assert concluder_name in resp.text  # who
    assert "Không phải sự cố" in resp.text  # what — STATUS_LABELS["concluded_fp"]
    assert "không ghi đè" in resp.text


def test_conclude_unknown_case_is_404_html(client):
    resp = client.http.post(
        f"/cases/{uuid.uuid4()}/conclude", data={"conclusion": "concluded_fp", "reason": "x"}
    )
    assert resp.status_code == 404
    assert 'data-field="not_found"' in resp.text


def test_conclude_500_on_illegal_transition_shows_flash_not_a_traceback(client, db, monkeypatch):
    case_id = _make_case(db, client.user_id)

    def _boom(conn, cid, uid, *, conclusion, reason):
        raise transitions.IllegalTransition("no edge for this test")

    monkeypatch.setattr(conclude.transitions, "conclude_case", _boom)

    resp = client.http.post(
        f"/cases/{case_id}/conclude", data={"conclusion": "concluded_fp", "reason": "x"}
    )
    assert resp.status_code == 500
    assert 'id="flash"' in resp.text


def test_confirmed_incident_scope_note_is_on_the_screen(client, db):
    case_id = _make_case(db, client.user_id)
    resp = client.http.get(f"/cases/{case_id}")
    assert 'data-field="scope_note"' in resp.text
    assert "không có" in resp.text and "ứng cứu" in resp.text


def test_confirmed_incident_scope_note_also_shows_on_the_concluded_screen(client, db):
    """Review round 1, nit N8: the scope sentence repeats on an already
    concluded `confirmed_incident` case, not only on the still-open form."""
    u = client.user_id
    case_id = _make_case(
        db,
        u,
        status="confirmed_incident",
        concluded_at=_PAST,
        concluded_by=u,
        conclusion_reason="real incident",
    )
    resp = client.http.get(f"/cases/{case_id}")
    assert resp.status_code == 200
    assert 'data-field="scope_note"' in resp.text
    # the open-form radios are gone (case.status != "investigating")
    assert 'name="conclusion"' not in resp.text


def test_confirmed_incident_scope_note_absent_from_other_concluded_screens(client, db):
    u = client.user_id
    case_id = _make_case(
        db, u, status="concluded_fp", concluded_at=_PAST, concluded_by=u, conclusion_reason="fp"
    )
    resp = client.http.get(f"/cases/{case_id}")
    assert 'data-field="scope_note"' not in resp.text


def test_conclude_statement_timeout_renders_503_flash_and_case_stays_investigating(
    client, db, monkeypatch
):
    """Review round 1, should S2 — the Reviewer's probe, read (not copied):
    a real statement timeout aborts the transaction exactly as a slow A16
    fan-out would; without the savepoint the re-read in `_case_page` raises
    `InFailedSqlTransaction` instead of rendering the 503 flash."""
    case_id = _make_case(db, client.user_id)
    head = _insert_alert(db, status="escalated_tier2", case_id=case_id)
    _add_head(db, case_id, head, client.user_id)

    def _slow_conclude(conn, cid, uid, *, conclusion, reason):
        conn.execute("SET LOCAL statement_timeout = '10ms'")
        conn.execute("SELECT pg_sleep(1)")

    monkeypatch.setattr(conclude.transitions, "conclude_case", _slow_conclude)

    resp = client.http.post(
        f"/cases/{case_id}/conclude", data={"conclusion": "concluded_fp", "reason": "slow"}
    )

    assert resp.status_code == 503
    assert 'id="flash"' in resp.text
    status = db.execute("SELECT status FROM cases WHERE case_id = %s", (case_id,)).fetchone()[0]
    assert status == "investigating"


def test_case_html_has_the_htmx_before_swap_listener(client, db):
    """Review round 1, should S4: htmx 2.0.4 does not swap 4xx/5xx responses
    by default, so without this listener the notes form's 422 would never
    show. This is the only script the page carries."""
    case_id = _make_case(db, client.user_id)
    resp = client.http.get(f"/cases/{case_id}")
    assert "htmx:beforeSwap" in resp.text
    assert "shouldSwap" in resp.text
    for code in ("409", "422", "503"):
        assert code in resp.text


# ---------------------------------------------------------------------------
# require_role("tier2", "admin") and page_user — the known pitfall
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method,route,form_data",
    [
        ("get", "/cases", None),
        ("get", "/cases/{case_id}", None),
        ("post", "/cases/{case_id}/notes", {"body": "x"}),
        ("post", "/cases/{case_id}/conclude", {"conclusion": "concluded_fp", "reason": "x"}),
    ],
    ids=["list", "detail", "notes", "conclude"],
)
def test_tier1_role_gets_403_and_writes_authz_denied_without_polluting_the_db(
    client, db, monkeypatch, method, route, form_data
):
    """The known pitfall: `require_role` (`web/deps.py`) commits the
    `authz.denied` row itself, before raising — on the shared `db` fixture's
    real connection, which nothing later can undo (`test_auth.py`,
    `P5-T06.review.md` round 1's blocker). `db.commit` is monkeypatched to a
    spy that reads the row back instead of committing it for real."""
    client.role = "tier1"
    path = route.format(case_id=str(uuid.uuid4()))
    seen_at_commit: list[list[str]] = []

    def _spy_commit() -> None:
        rows = db.execute(
            "SELECT event_type FROM audit_events WHERE actor_id = %s ORDER BY audit_id",
            (client.user_id,),
        ).fetchall()
        seen_at_commit.append([r[0] for r in rows])

    monkeypatch.setattr(db, "commit", _spy_commit)

    call = getattr(client.http, method)
    resp = call(path, data=form_data) if form_data is not None else call(path)

    assert resp.status_code == 403
    assert seen_at_commit == [["authz.denied"]]


def test_admin_role_is_also_allowed(client, db):
    client.role = "admin"
    resp = client.http.get("/cases")
    assert resp.status_code == 200


def test_no_session_redirects_to_login(db):
    """No override on `deps.current_user`/`pages.page_user` here — the real
    `page_user` runs, sees no token (`read_token` returns `None` before conn
    or cfg is ever touched) and redirects, exactly as `web/routers/pages.py`
    is written to for every page. Only `get_conn`/`get_config` are overridden
    (FastAPI resolves `Conn`/`Cfg` eagerly regardless of whether the function
    body reaches them)."""
    main.app.dependency_overrides[deps.get_conn] = _get_conn(db)
    main.app.dependency_overrides[deps.get_config] = lambda: config.Config()
    try:
        http = TestClient(main.app, follow_redirects=False)
        resp = http.get("/cases")
        assert resp.status_code == 303
        assert resp.headers["location"] == "/login"
        detail = http.get(f"/cases/{uuid.uuid4()}")
        assert detail.status_code == 303
        assert detail.headers["location"] == "/login"
    finally:
        for dep in (deps.get_conn, deps.get_config):
            main.app.dependency_overrides.pop(dep, None)
