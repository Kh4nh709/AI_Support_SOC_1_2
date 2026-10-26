"""P13-T05 / DEC-210, spec §7.5 — `web/routers/admin_knowledge.py`: the admin review API of the learned
knowledge (the page that reads it is P13-T06).

Every test runs the real app through `TestClient(main.app)` with `deps.get_conn` overridden to this
module's own connection and `deps.current_user` to a fixed `Claims` (`test_admin_overview.py`'s shape),
on a scratch database this module builds and drops. The connection is wrapped in `Session`: `commit`
is counted and does nothing (the routes of this card commit by hand, and a real commit would leave
the seeded rows in the scratch database for the next test), and so is `rollback` (Tier 2's own
investigation route ends on one, which the seeded rows must outlive); the connection is rolled back
when the test ends. The tree the files live in is a temporary directory
(`admin_knowledge.KB_LEARNED_ROOT`).

    guard      every route: 403 as tier1 and tier2, 401 without a session
    drafts     the list (empty on the first day, shape, status, the pending order: conflicts first then
               the oldest, paging) and the detail: `source` is the same JSON as the Tier-1 alert route,
               or the Tier-2 case and investigation routes, plus the decision, the notes, the SOAR
               block and the conflicting entry
    approve    200 {entry_id}; 404; 409 and 422 bodies; a failed commit removes the file; a file that
               cannot be written is 503 and stores nothing
    reject     the reason's 1-500 characters; 404; 409
    entries    the list, the detail with its evidence and integrity, retire
    tags       the closed vocabulary
"""

from __future__ import annotations

import dataclasses
import os
import uuid
from pathlib import Path

import psycopg
import pytest
from app.audit.events import write_event
from app.infra import config
from app.infra.auth import Claims
from app.rag import publish
from app.rag.tags import load_tags
from app.web import deps, main
from app.web.routers import admin_knowledge
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from tests.rag_data import add_entry
from tests.scratch_db import insert_user, scratch_database
from tests.test_rag_publish import (
    GOOD,
    concluded_case,
    decided_alert,
    events,
    new_id,
    pending_draft,
)

URL = "/api/admin/knowledge"
FAKE_ID = "11111111-2222-4333-8444-555555555555"

DRAFT_ROW_KEYS = {
    "draft_id",
    "source_kind",
    "source_id",
    "conclusion",
    "status",
    "title",
    "has_text",
    "warnings",
    "conflict_with_entry",
    "duplicate_of_entry",
    "created_at",
    "reviewed_by",
    "reviewed_by_name",
    "reviewed_at",
    "review_note",
}
ENTRY_ROW_KEYS = {
    "entry_id",
    "version",
    "status",
    "title",
    "conclusion",
    "category",
    "mitre_ids",
    "tags",
    "soar_scenario",
    "rule_ids",
    "log_source",
    "file_path",
    "content_sha256",
    "evidence_count",
    "approved_by",
    "approved_by_name",
    "approved_at",
}


# ── the scratch database, the session, the client ─────────────────────────────────────────────


@pytest.fixture(scope="module")
def scratch_dsn():
    with scratch_database("p13t05api") as dsn:
        yield dsn


@pytest.fixture(autouse=True)
def _require_db_marker_for_scratch(request):
    uses = {"sdb", "scratch_dsn", "api"} & set(request.fixturenames)
    if uses and request.node.get_closest_marker("db") is None:
        pytest.fail(f"{request.node.nodeid} uses {sorted(uses)} without @pytest.mark.db")


@pytest.fixture
def sdb(scratch_dsn):
    conn = psycopg.connect(scratch_dsn)
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


class Session:
    """The test's connection as the app sees it. `commit` is counted and does nothing (or fails, when
    `fail_commit`), `rollback` is a counted no-op too (`GET .../investigation` of Tier 2 ends on one,
    and the seeded rows must outlive it), everything else is the connection's own."""

    def __init__(self, conn: psycopg.Connection) -> None:
        self._conn = conn
        self.commits = 0
        self.rollbacks = 0
        self.fail_commit = False

    def commit(self) -> None:
        self.commits += 1
        if self.fail_commit:
            raise psycopg.OperationalError("the commit failed")

    def rollback(self) -> None:
        self.rollbacks += 1

    def __getattr__(self, name):
        return getattr(self._conn, name)


@dataclasses.dataclass
class Api:
    client: TestClient
    conn: psycopg.Connection
    session: Session
    root: Path
    admin_id: str
    claims: Claims

    def get(self, path: str, **kw):
        return self.client.get(URL + path, **kw)

    def post(self, path: str, body=None):
        return self.client.post(URL + path, json={} if body is None else body)


def _claims(conn, role: str) -> Claims:
    return Claims(
        user_id=insert_user(conn, role), username=f"p13t05-{role}", role=role, iat=0.0, exp=0.0
    )


@pytest.fixture
def api(sdb, tmp_path, monkeypatch):
    root = tmp_path / "kb_learned"
    root.mkdir()
    monkeypatch.setattr(admin_knowledge, "KB_LEARNED_ROOT", root)
    session = Session(sdb)
    claims = _claims(sdb, "admin")
    cfg = dataclasses.replace(config.load(), DISPLAY_TZ="Asia/Ho_Chi_Minh")
    main.app.dependency_overrides[deps.get_conn] = lambda: session
    main.app.dependency_overrides[deps.current_user] = lambda: claims
    main.app.dependency_overrides[deps.get_config] = lambda: cfg
    try:
        yield Api(TestClient(main.app), sdb, session, root, claims.user_id, claims)
    finally:
        for dependency in (deps.get_conn, deps.current_user, deps.get_config):
            main.app.dependency_overrides.pop(dependency, None)


def as_role(api: Api, role: str) -> None:
    claims = _claims(api.conn, role)
    main.app.dependency_overrides[deps.current_user] = lambda: claims


# ── data ──────────────────────────────────────────────────────────────────────────────────────


def alert_draft(conn, **kw) -> tuple[str, uuid.UUID]:
    alert = decided_alert(conn)
    return alert, pending_draft(conn, f"alert:{alert}", **kw)


def case_draft(conn, **kw) -> tuple[str, uuid.UUID]:
    case_id = concluded_case(conn)
    return case_id, pending_draft(conn, f"case:{case_id}", **kw)


def an_entry(api: Api) -> str:
    """An approved entry with its file, through the module under test's own function."""
    _, draft_id = alert_draft(api.conn)
    return str(publish.approve(api.conn, draft_id, api.admin_id, root=api.root))


ROUTES = [
    ("get", f"{URL}/drafts", None),
    ("get", f"{URL}/drafts/{FAKE_ID}", None),
    ("post", f"{URL}/drafts/{FAKE_ID}/approve", {}),
    ("post", f"{URL}/drafts/{FAKE_ID}/reject", {"reason": "x"}),
    ("post", f"{URL}/drafts/{FAKE_ID}/redraft", {}),
    ("get", f"{URL}/entries", None),
    ("get", f"{URL}/entries/{FAKE_ID}", None),
    ("post", f"{URL}/entries/{FAKE_ID}/retire", {"reason": "x"}),
    ("get", f"{URL}/tags", None),
]
ROUTE_IDS = [f"{method}-{path.removeprefix(URL)}" for method, path, _ in ROUTES]


def call(api: Api, method: str, path: str, body):
    if method == "get":
        return api.client.get(path)
    return api.client.post(path, json=body)


# ═══ the guard ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.db
@pytest.mark.parametrize(("method", "path", "body"), ROUTES, ids=ROUTE_IDS)
@pytest.mark.parametrize("role", ["tier1", "tier2"])
def test_every_route_is_forbidden_to_an_analyst(api, role, method, path, body) -> None:
    as_role(api, role)
    _, draft_id = alert_draft(api.conn)

    response = call(api, method, path.replace(FAKE_ID, str(draft_id)), body)

    assert response.status_code == 403
    assert api.conn.execute("SELECT count(*) FROM knowledge_entries").fetchone()[0] == 0
    assert api.conn.execute(
        "SELECT status FROM knowledge_drafts WHERE draft_id = %s", (draft_id,)
    ).fetchone() == ("pending",)


@pytest.mark.db
@pytest.mark.parametrize(("method", "path", "body"), ROUTES, ids=ROUTE_IDS)
def test_every_route_needs_a_session(api, method, path, body) -> None:
    main.app.dependency_overrides.pop(deps.current_user)

    assert call(api, method, path, body).status_code == 401


@pytest.mark.db
@pytest.mark.parametrize(
    ("path", "body"),
    [
        (f"{URL}/drafts/{FAKE_ID}/approve", {}),
        (f"{URL}/drafts/{FAKE_ID}/reject", {"reason": "x"}),
        (f"{URL}/drafts/{FAKE_ID}/redraft", {}),
        (f"{URL}/entries/{FAKE_ID}/retire", {"reason": "x"}),
    ],
)
def test_a_post_that_is_not_json_is_refused_after_the_role_check(api, path, body) -> None:
    response = api.client.post(
        path, content='{"reason": "x"}', headers={"content-type": "text/plain"}
    )
    assert response.status_code == 422
    assert response.json() == {"detail": {"field": "body", "reason": "invalid"}}

    as_role(api, "tier1")
    assert (
        api.client.post(path, content="x", headers={"content-type": "text/plain"}).status_code
        == 403
    )


# ═══ the redraft ═════════════════════════════════════════════════════════════════════════════


def textless(conn, warnings, *, status: str = "pending", draft=None) -> tuple[str, uuid.UUID]:
    alert = decided_alert(conn)
    (draft_id,) = conn.execute(
        "INSERT INTO knowledge_drafts (source_kind, source_id, conclusion, status, draft, warnings)"
        " VALUES ('alert', %s, 'closed_fp', %s, %s, %s) RETURNING draft_id",
        (alert, status, Jsonb({} if draft is None else draft), Jsonb(list(warnings))),
    ).fetchone()
    return alert, draft_id


def drafts_on(api: Api, enabled: bool = True) -> None:
    cfg = dataclasses.replace(
        config.load(), DISPLAY_TZ="Asia/Ho_Chi_Minh", KNOWLEDGE_DRAFT_ENABLED=enabled
    )
    main.app.dependency_overrides[deps.get_config] = lambda: cfg


@pytest.mark.db
def test_redraft_answers_200_removes_the_draft_and_queues_the_job(api) -> None:
    drafts_on(api)
    alert, draft_id = textless(api.conn, ["budget", "llm_permanent"])

    response = api.post(f"/drafts/{draft_id}/redraft")

    assert (response.status_code, response.json()) == (
        200,
        {"draft_id": str(draft_id), "queued": True},
    )
    assert api.conn.execute("SELECT count(*) FROM knowledge_drafts").fetchone()[0] == 0
    assert api.conn.execute(
        "SELECT status FROM jobs WHERE job_type = 'knowledge_draft' AND subject_id = %s",
        (f"alert:{alert}",),
    ).fetchall() == [("pending",)]
    ((subject, actor_id, payload),) = events(api.conn, "knowledge.redraft_requested")
    assert (subject, actor_id, payload) == (alert, api.admin_id, {"draft_id": str(draft_id)})


@pytest.mark.db
@pytest.mark.parametrize(
    ("status", "draft", "warnings", "reason"),
    [
        ("approved", {}, ["budget"], "not_pending"),
        ("pending", GOOD, ["budget"], "not_redraftable"),
        ("pending", {}, ["v3_ipv4:summary"], "not_redraftable"),
        ("pending", {}, [], "not_redraftable"),
    ],
)
def test_redraft_of_a_draft_that_is_not_redraftable_is_409_and_changes_nothing(
    api, status, draft, warnings, reason
) -> None:
    drafts_on(api)
    _alert, draft_id = textless(api.conn, warnings, status=status, draft=draft)

    response = api.post(f"/drafts/{draft_id}/redraft")

    assert (response.status_code, response.json()) == (409, {"detail": {"reason": reason}})
    assert api.conn.execute("SELECT count(*) FROM knowledge_drafts").fetchone()[0] == 1
    assert events(api.conn, "knowledge.redraft_requested") == []
    assert (
        api.conn.execute("SELECT count(*) FROM jobs WHERE job_type = 'knowledge_draft'").fetchone()[
            0
        ]
        == 0
    )


@pytest.mark.db
def test_redraft_with_the_drafts_switch_off_is_409_and_spends_nothing(api) -> None:
    """A re-draft is a model call: with `KNOWLEDGE_DRAFT_ENABLED` false (the Owner switched drafts off) the
    page cannot start one."""
    drafts_on(api, enabled=False)
    _alert, draft_id = textless(api.conn, ["budget"])

    response = api.post(f"/drafts/{draft_id}/redraft")

    assert (response.status_code, response.json()) == (
        409,
        {"detail": {"reason": "drafts_disabled"}},
    )
    assert api.conn.execute("SELECT count(*) FROM knowledge_drafts").fetchone()[0] == 1
    assert (
        api.conn.execute("SELECT count(*) FROM jobs WHERE job_type = 'knowledge_draft'").fetchone()[
            0
        ]
        == 0
    )


@pytest.mark.db
def test_redraft_of_an_unknown_draft_is_404(api) -> None:
    drafts_on(api)
    assert api.post(f"/drafts/{uuid.uuid4()}/redraft").status_code == 404
    assert api.post("/drafts/not-a-uuid/redraft").status_code == 422


@pytest.mark.db
def test_redraft_takes_no_body(api) -> None:
    drafts_on(api)
    _alert, draft_id = textless(api.conn, ["budget"])
    response = api.post(f"/drafts/{draft_id}/redraft", {"reason": "x"})
    assert (response.status_code, response.json()) == (
        422,
        {"detail": {"field": "body", "reason": "invalid"}},
    )
    assert api.conn.execute("SELECT count(*) FROM knowledge_drafts").fetchone()[0] == 1


@pytest.mark.db
def test_the_redraft_event_is_on_the_audit_page_under_configuration(api) -> None:
    from app.web.routers import admin_audit

    assert "knowledge.redraft_requested" in admin_audit.GROUPS["configuration"]


# ═══ the drafts ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.db
@pytest.mark.parametrize("status", ["pending", "approved", "merged", "rejected"])
def test_an_empty_store_answers_every_list_with_an_empty_list(api, status) -> None:
    """Review Focus 1: the first day, nothing to show, no error."""
    response = api.get(f"/drafts?status={status}")
    assert (response.status_code, response.json()) == (200, [])
    for path in ("/entries?status=active", "/entries?status=retired"):
        assert (api.get(path).status_code, api.get(path).json()) == (200, [])


@pytest.mark.db
def test_the_draft_list_is_pending_by_default_and_each_row_has_this_shape(api) -> None:
    alert, draft_id = alert_draft(api.conn)

    rows = api.get("/drafts").json()

    (row,) = rows
    assert set(row) == DRAFT_ROW_KEYS
    assert row["draft_id"] == str(draft_id)
    assert (row["source_kind"], row["source_id"], row["conclusion"]) == (
        "alert",
        alert,
        "closed_fp",
    )
    assert (row["status"], row["title"], row["has_text"]) == ("pending", GOOD["title"], True)
    assert row["warnings"] == [] and row["conflict_with_entry"] is None
    assert row["reviewed_by"] is None and row["reviewed_at"] is None


@pytest.mark.db
def test_a_draft_with_no_text_has_no_title(api) -> None:
    alert = decided_alert(api.conn)
    draft_id = pending_draft(api.conn, f"alert:{alert}", draft={})
    api.conn.execute(
        "UPDATE knowledge_drafts SET warnings = '[\"budget\"]'::jsonb WHERE draft_id = %s",
        (draft_id,),
    )

    (row,) = api.get("/drafts").json()

    assert (row["title"], row["has_text"], row["warnings"]) == (None, False, ["budget"])


@pytest.mark.db
def test_pending_lists_the_conflicts_first_then_the_oldest_first(api) -> None:
    entry = add_entry(api.conn)
    _, old = alert_draft(api.conn, minutes_ago=60)
    _, new = alert_draft(api.conn, minutes_ago=10)
    _, conflict_new = alert_draft(api.conn, minutes_ago=1, conflict_with=entry)
    _, conflict_old = alert_draft(api.conn, minutes_ago=30, conflict_with=entry)

    ids = [row["draft_id"] for row in api.get("/drafts?status=pending").json()]

    assert ids == [str(conflict_old), str(conflict_new), str(old), str(new)]
    conflicts = [row["conflict_with_entry"] for row in api.get("/drafts").json()]
    assert conflicts == [entry, entry, None, None]


@pytest.mark.db
def test_each_status_lists_only_its_own_the_newest_review_first(api) -> None:
    entry = add_entry(api.conn)
    _, pending = alert_draft(api.conn)
    _, first = alert_draft(api.conn, status="rejected")
    _, second = alert_draft(api.conn, status="rejected")
    _, approved = alert_draft(api.conn, status="approved")
    _, merged = alert_draft(api.conn, status="merged")
    api.conn.execute(
        "UPDATE knowledge_drafts SET reviewed_at = now() - interval '2 hours', review_note = 'cũ'"
        " WHERE draft_id = %s",
        (first,),
    )
    api.conn.execute(
        "UPDATE knowledge_drafts SET reviewed_at = now() - interval '1 hour', review_note = 'mới'"
        " WHERE draft_id = %s",
        (second,),
    )
    api.conn.execute(
        "UPDATE knowledge_drafts SET duplicate_of_entry = %s WHERE draft_id = %s", (entry, merged)
    )

    def listed(status):
        return [row["draft_id"] for row in api.get(f"/drafts?status={status}").json()]

    assert listed("pending") == [str(pending)]
    assert listed("rejected") == [str(second), str(first)]
    assert listed("approved") == [str(approved)]
    assert listed("merged") == [str(merged)]
    (merged_row,) = api.get("/drafts?status=merged").json()
    assert merged_row["duplicate_of_entry"] == entry
    assert api.get("/drafts?status=rejected").json()[0]["review_note"] == "mới"


@pytest.mark.db
def test_the_draft_list_pages(api) -> None:
    ids = [str(alert_draft(api.conn, minutes_ago=m)[1]) for m in (50, 40, 30)]

    assert [r["draft_id"] for r in api.get("/drafts?limit=2").json()] == ids[:2]
    assert [r["draft_id"] for r in api.get("/drafts?limit=2&offset=2").json()] == ids[2:]


@pytest.mark.db
@pytest.mark.parametrize("path", ["/drafts", "/entries"])
@pytest.mark.parametrize("query", ["status=other", "limit=0", "limit=501", "offset=-1", "limit=x"])
def test_a_bad_list_query_is_a_422(api, path, query) -> None:
    assert api.get(f"{path}?{query}").status_code == 422


# ── the detail ────────────────────────────────────────────────────────────────────────────────


@pytest.mark.db
def test_an_alert_drafts_source_is_the_tier_1_alert_view(api) -> None:
    alert, draft_id = alert_draft(api.conn)
    analyst = insert_user(api.conn, "tier1")
    write_event(
        api.conn,
        "tier1.decided",
        alert,
        "analyst",
        actor_id=analyst,
        payload={
            "decision": "closed_fp",
            "reason": "đã xác minh MARK-REASON",
            "llm_suggestion": "false_positive",
            "api_key": "super-secret-value",
        },
    )

    body = api.get(f"/drafts/{draft_id}").json()

    assert set(body) == {"draft", "source"}
    source = body["source"]
    assert (source["kind"], source["id"]) == ("alert", alert)
    assert source["alert"] == api.client.get(f"/api/tier1/alerts/{alert}").json()
    assert source["alert"]["alert_id"] == alert and source["alert"]["close_reason"] == "đã xác minh"
    assert source["case"] is None and source["investigation"] is None
    assert source["notes"] == [] and source["conflict_entry"] is None
    decision = source["decision"]
    assert (decision["event_type"], decision["actor_id"]) == ("tier1.decided", analyst)
    assert decision["actor_name"].startswith("p10t05-") and decision["at"]
    assert decision["payload"]["reason"] == "đã xác minh MARK-REASON"
    assert decision["payload"]["llm_suggestion"] == "false_positive"
    assert decision["payload"]["api_key"] == "[đã ẩn]"  # the audit page's redaction
    assert "super-secret-value" not in api.get(f"/drafts/{draft_id}").text


@pytest.mark.db
def test_the_draft_row_in_the_detail(api) -> None:
    alert, draft_id = alert_draft(api.conn)

    draft = api.get(f"/drafts/{draft_id}").json()["draft"]

    assert set(draft) == {
        "draft_id",
        "source_kind",
        "source_id",
        "conclusion",
        "status",
        "draft",
        "warnings",
        "llm_run_id",
        "duplicate_of_entry",
        "conflict_with_entry",
        "created_at",
        "reviewed_by",
        "reviewed_by_name",
        "reviewed_at",
        "review_note",
    }
    assert draft["draft_id"] == str(draft_id) and draft["source_id"] == alert
    assert set(draft["draft"]) == {
        "title",
        "conclusion",
        "category",
        "mitre_ids",
        "soar_scenario",
        "rule_ids",
        "log_source",
        "tags",
        "summary",
        "distinguishing_signals",
        "check_next_time",
        "confidence_note",
    }
    assert draft["draft"]["title"] == GOOD["title"]


@pytest.mark.db
def test_the_soar_enrichment_block_of_an_alert(api) -> None:
    block = {"scenario": {"id": "SC03", "name": "x"}, "case": {"dedup_key": "k"}, "note": "văn bản"}
    secret = {"api_key": "hunter2-secret", "link": "postgresql://app:hunter2@db:5432/soc"}
    alert = decided_alert(api.conn, raw_payload={"enrichment": {**block, **secret}, "other": "no"})
    draft_id = pending_draft(api.conn, f"alert:{alert}")

    response = api.get(f"/drafts/{draft_id}")

    # the block, as the audit page would show it: a secret key and a URL with a password are hidden
    assert response.json()["source"]["enrichment"] == {
        **block,
        "api_key": "[đã ẩn]",
        "link": "[đã ẩn]",
    }
    assert "hunter2" not in response.text


@pytest.mark.db
def test_an_alert_with_no_enrichment_has_none(api) -> None:
    alert = decided_alert(api.conn, raw_payload={})
    draft_id = pending_draft(api.conn, f"alert:{alert}")

    assert api.get(f"/drafts/{draft_id}").json()["source"]["enrichment"] is None


@pytest.mark.db
def test_a_case_drafts_source_is_the_tier_2_case_and_investigation(api) -> None:
    heads = (new_id("sh1"), new_id("sh2"))
    case_id = concluded_case(api.conn, heads=heads)
    draft_id = pending_draft(api.conn, f"case:{case_id}")
    author = insert_user(api.conn, "tier2")
    api.conn.execute(
        "INSERT INTO case_notes (case_id, author_id, body) VALUES (%s, %s, 'ghi chú MARK-NOTE')",
        (case_id, author),
    )
    for head, payload in (
        (heads[0], '{"enrichment": {"scenario": {"id": "SC03"}}}'),
        (heads[1], "{}"),
    ):
        api.conn.execute("UPDATE alerts SET raw_payload = %s WHERE alert_id = %s", (payload, head))
    write_event(
        api.conn,
        "tier2.concluded",
        case_id,
        "analyst",
        actor_id=author,
        payload={"conclusion": "concluded_fp", "reason": "xác minh xong"},
    )

    source = api.get(f"/drafts/{draft_id}").json()["source"]

    assert (source["kind"], source["id"]) == ("case", case_id)
    assert source["alert"] is None
    assert source["case"] == api.client.get(f"/api/tier2/cases/{case_id}").json()
    assert sorted(h["alert_id"] for h in source["case"]["heads"]) == sorted(heads)
    assert source["notes"] == source["case"]["notes"]
    assert [n["body"] for n in source["notes"]] == ["ghi chú MARK-NOTE"]
    assert source["decision"]["event_type"] == "tier2.concluded"
    assert source["decision"]["payload"] == {
        "conclusion": "concluded_fp",
        "reason": "xác minh xong",
    }
    assert source["enrichment"] == {heads[0]: {"scenario": {"id": "SC03"}}}
    assert source["conflict_entry"] is None
    # the investigation view, last: its own route ends on a rollback
    assert (
        source["investigation"]
        == api.client.get(f"/api/tier2/cases/{case_id}/investigation").json()
    )
    assert (
        source["investigation"]["state"] == "idle" and source["investigation"]["case_open"] is False
    )


@pytest.mark.db
def test_a_conflict_shows_the_entry_it_conflicts_with_rendered(api) -> None:
    entry_id = an_entry(api)
    other = decided_alert(api.conn, status="closed_benign")
    draft_id = pending_draft(api.conn, f"alert:{other}", conflict_with=entry_id)

    source = api.get(f"/drafts/{draft_id}").json()["source"]
    conflict = source["conflict_entry"]

    entry = api.get(f"/entries/{entry_id}").json()
    assert conflict == entry
    assert conflict["entry_id"] == entry_id and conflict["conclusion"] == "closed_fp"
    assert conflict["title"] == GOOD["title"]
    assert conflict["content"].startswith("---\nentry_id: ") and "## Tóm tắt" in conflict["content"]
    assert api.get(f"/drafts/{draft_id}").json()["draft"]["conflict_with_entry"] == entry_id


@pytest.mark.db
def test_a_draft_with_no_text_has_an_empty_draft_in_the_detail(api) -> None:
    alert = decided_alert(api.conn)
    draft_id = pending_draft(api.conn, f"alert:{alert}", draft={})

    body = api.get(f"/drafts/{draft_id}").json()

    assert body["draft"]["draft"] == {} and body["source"]["alert"]["alert_id"] == alert


@pytest.mark.db
def test_a_draft_whose_source_is_gone_still_answers(api) -> None:
    """No row of `alerts` or `cases` behind the draft (nothing forbids it): no 500."""
    # a case id that is not a UUID is one too (P13 fix wave, item 7: it was a 500 from `WHERE case_id = ...`)
    for kind, source_id in (
        ("alert", "no-such-alert"),
        ("case", str(uuid.uuid4())),
        ("case", "not-a-uuid"),
        ("case", "123"),
    ):
        (draft_id,) = api.conn.execute(
            "INSERT INTO knowledge_drafts (source_kind, source_id, conclusion, status)"
            " VALUES (%s, %s, 'closed_fp', 'pending') RETURNING draft_id",
            (kind, source_id),
        ).fetchone()

        response = api.get(f"/drafts/{draft_id}")

        assert response.status_code == 200
        source = response.json()["source"]
        assert source["alert"] is None and source["case"] is None
        assert source["decision"] is None and source["investigation"] is None


@pytest.mark.db
def test_the_detail_changes_nothing(api) -> None:
    _, draft_id = case_draft(api.conn)

    def counts():
        return [
            api.conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in ("audit_events", "knowledge_entries", "llm_runs", "jobs")
        ]

    before = counts()
    api.get(f"/drafts/{draft_id}")

    assert counts() == before


@pytest.mark.db
def test_an_unknown_draft_is_404_and_a_bad_id_is_422(api) -> None:
    response = api.get(f"/drafts/{FAKE_ID}")
    assert (response.status_code, response.json()) == (404, {"detail": {"reason": "not_found"}})
    assert api.get("/drafts/not-a-uuid").status_code == 422


# ═══ approve ═════════════════════════════════════════════════════════════════════════════════


@pytest.mark.db
def test_approve_answers_the_entry_id_and_publishes(api) -> None:
    alert, draft_id = alert_draft(api.conn)

    response = api.post(f"/drafts/{draft_id}/approve")

    assert response.status_code == 200
    assert set(response.json()) == {"entry_id"}
    entry_id = response.json()["entry_id"]
    assert api.session.commits == 1
    ((_, actor_id, payload),) = events(api.conn, "knowledge.approved")
    assert payload == {"draft_id": str(draft_id), "entry_id": entry_id} and actor_id == api.admin_id
    entry = api.get(f"/entries/{entry_id}").json()
    assert entry["status"] == "active" and entry["source_alert_ids"] == [alert]
    assert entry["integrity"] == {"content_ok": True, "file_ok": True}
    assert (api.root / entry["file_path"]).read_bytes() == entry["content"].encode("utf-8")
    assert api.get("/drafts").json() == []
    assert [r["draft_id"] for r in api.get("/drafts?status=approved").json()] == [str(draft_id)]


@pytest.mark.db
def test_approve_with_no_body_at_all_is_the_plain_approval(api) -> None:
    _, draft_id = alert_draft(api.conn)

    response = api.client.post(
        f"{URL}/drafts/{draft_id}/approve",
        content=b"",
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 200


@pytest.mark.db
def test_approve_with_an_edit_publishes_the_edit(api) -> None:
    _, draft_id = alert_draft(api.conn)
    edited = {"title": "Tiêu đề đã sửa", "tags": ["port_scan"], "summary": "Tóm tắt mới."}

    response = api.post(f"/drafts/{draft_id}/approve", {"edited": edited})

    assert response.status_code == 200
    entry = api.get(f"/entries/{response.json()['entry_id']}").json()
    assert entry["title"] == "Tiêu đề đã sửa" and entry["tags"] == ["port_scan"]
    assert "Tóm tắt mới." in entry["content"]


@pytest.mark.db
def test_a_fault_is_a_422_with_the_faults_and_nothing_is_stored(api) -> None:
    _, draft_id = alert_draft(api.conn)

    response = api.post(
        f"/drafts/{draft_id}/approve", {"edited": {"summary": "Máy 203.0.113.7 quét cổng."}}
    )

    assert response.status_code == 422
    assert response.json() == {"faults": ["v3_ipv4:summary"]}
    assert api.conn.execute("SELECT count(*) FROM knowledge_entries").fetchone()[0] == 0
    assert list(api.root.rglob("*")) == []
    assert events(api.conn, "knowledge.approved") == []
    assert api.session.commits == 0


@pytest.mark.db
def test_several_faults_come_back_by_rule_and_field(api) -> None:
    _, draft_id = alert_draft(api.conn)

    response = api.post(
        f"/drafts/{draft_id}/approve",
        {
            "edited": {
                "title": ("ab " * 50).strip(),
                "tags": ["nope"],
                "confidence_note": ("ab " * 100).strip(),
            }
        },
    )

    assert response.status_code == 422
    assert set(response.json()["faults"]) == {
        "v5_length:title",
        "v1_tags:unknown_tag",
        "v5_length:confidence_note",
    }


@pytest.mark.db
def test_a_closed_field_in_the_request_is_a_422_and_never_stored(api) -> None:
    _, draft_id = alert_draft(api.conn)

    response = api.post(
        f"/drafts/{draft_id}/approve", {"edited": {"conclusion": "confirmed_incident"}}
    )

    assert (response.status_code, response.json()) == (
        422,
        {"faults": ["v1_schema:unexpected_key"]},
    )
    assert api.conn.execute("SELECT count(*) FROM knowledge_entries").fetchone()[0] == 0


@pytest.mark.db
@pytest.mark.parametrize(
    ("body", "field"),
    [
        ({"edited": ["title"]}, "edited"),
        ({"edited": "title"}, "edited"),
        ({"edited": 5}, "edited"),
        ({"unknown": 1}, "body"),
        ({"edited": {}, "unknown": 1}, "body"),
    ],
)
def test_a_malformed_approve_request_is_a_422_that_repeats_nothing(api, body, field) -> None:
    _, draft_id = alert_draft(api.conn)

    response = api.post(f"/drafts/{draft_id}/approve", body)

    assert (response.status_code, response.json()) == (
        422,
        {"detail": {"field": field, "reason": "invalid"}},
    )


@pytest.mark.db
@pytest.mark.parametrize("raw", ["[1]", "5", '"x"', "{not json"])
def test_a_body_that_is_not_an_object_is_a_422(api, raw) -> None:
    _, draft_id = alert_draft(api.conn)

    response = api.client.post(
        f"{URL}/drafts/{draft_id}/approve",
        content=raw,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 422
    assert response.json() == {"detail": {"field": "body", "reason": "invalid"}}


@pytest.mark.db
def test_the_second_approve_is_409_and_there_is_one_entry_one_file_one_event(api) -> None:
    _, draft_id = alert_draft(api.conn)
    assert api.post(f"/drafts/{draft_id}/approve").status_code == 200

    response = api.post(f"/drafts/{draft_id}/approve")

    assert (response.status_code, response.json()) == (409, {"detail": {"reason": "not_pending"}})
    assert api.conn.execute("SELECT count(*) FROM knowledge_entries").fetchone()[0] == 1
    assert len(list(api.root.rglob("*.md"))) == 1
    assert len(events(api.conn, "knowledge.approved")) == 1


@pytest.mark.db
@pytest.mark.parametrize("status", ["merged", "rejected"])
def test_a_draft_that_is_not_pending_cannot_be_approved(api, status) -> None:
    _, draft_id = alert_draft(api.conn, status=status)

    response = api.post(f"/drafts/{draft_id}/approve")

    assert (response.status_code, response.json()) == (409, {"detail": {"reason": "not_pending"}})


@pytest.mark.db
def test_a_source_that_is_no_longer_decided_is_409(api) -> None:
    alert, draft_id = alert_draft(api.conn)
    api.conn.execute(
        "UPDATE alerts SET status = 'queued_tier1', closed_at = NULL, sealed_at = NULL"
        " WHERE alert_id = %s",
        (alert,),
    )

    response = api.post(f"/drafts/{draft_id}/approve")

    assert (response.status_code, response.json()) == (
        409,
        {"detail": {"reason": "source_changed"}},
    )


@pytest.mark.db
def test_a_category_that_could_leave_the_tree_is_409_and_publishes_nothing(api) -> None:
    alert = decided_alert(api.conn)
    api.conn.execute("UPDATE alerts SET category = 'x/../../../out' WHERE alert_id = %s", (alert,))
    draft_id = pending_draft(api.conn, f"alert:{alert}")

    response = api.post(f"/drafts/{draft_id}/approve")

    assert (response.status_code, response.json()) == (409, {"detail": {"reason": "unpublishable"}})
    assert list(api.root.rglob("*")) == []


@pytest.mark.db
def test_approve_of_an_unknown_draft_is_404(api) -> None:
    response = api.post(f"/drafts/{FAKE_ID}/approve")

    assert (response.status_code, response.json()) == (404, {"detail": {"reason": "not_found"}})


@pytest.mark.db
def test_a_commit_that_fails_removes_the_file(api) -> None:
    _, draft_id = alert_draft(api.conn)
    api.session.fail_commit = True

    with pytest.raises(psycopg.OperationalError):
        api.post(f"/drafts/{draft_id}/approve")

    assert list(api.root.rglob("*.md")) == []


@pytest.mark.db
@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_a_file_that_cannot_be_written_is_503_and_stores_nothing(api) -> None:
    _, draft_id = alert_draft(api.conn)
    api.root.chmod(0o555)
    try:
        response = api.post(f"/drafts/{draft_id}/approve")
    finally:
        api.root.chmod(0o755)

    assert (response.status_code, response.json()) == (
        503,
        {"detail": {"reason": "publish_failed"}},
    )
    assert str(api.root) not in response.text
    assert api.conn.execute("SELECT count(*) FROM knowledge_entries").fetchone()[0] == 0
    assert api.session.commits == 0
    # nothing was lost: the draft can be approved once the tree can be written
    assert api.post(f"/drafts/{draft_id}/approve").status_code == 200


# ═══ reject ══════════════════════════════════════════════════════════════════════════════════


@pytest.mark.db
def test_reject_marks_the_draft_and_answers(api) -> None:
    alert, draft_id = alert_draft(api.conn)

    response = api.post(f"/drafts/{draft_id}/reject", {"reason": "  Không đủ tổng quát  "})

    assert response.status_code == 200
    assert response.json() == {"draft_id": str(draft_id), "status": "rejected"}
    ((subject, actor_id, payload),) = events(api.conn, "knowledge.rejected")
    assert payload == {"draft_id": str(draft_id), "reason": "Không đủ tổng quát"}
    assert (subject, actor_id) == (alert, api.admin_id)
    (row,) = api.get("/drafts?status=rejected").json()
    assert (row["review_note"], row["reviewed_by"]) == ("Không đủ tổng quát", api.admin_id)
    assert row["reviewed_by_name"].startswith("p10t05-")
    assert api.get("/drafts").json() == []


@pytest.mark.db
@pytest.mark.parametrize(
    ("body", "reason"),
    [
        ({}, "required"),
        ({"reason": None}, "required"),
        ({"reason": ""}, "required"),
        ({"reason": "   "}, "required"),
        ({"reason": 5}, "invalid"),
        ({"reason": ["x"]}, "invalid"),
        ({"reason": "x" * 501}, "invalid"),
        ({"reason": "a\u0000b"}, "invalid"),
        ({"reason": "ok", "extra": 1}, "invalid"),
    ],
)
def test_reject_needs_a_reason_of_one_to_five_hundred_characters(api, body, reason) -> None:
    _, draft_id = alert_draft(api.conn)

    response = api.post(f"/drafts/{draft_id}/reject", body)

    assert response.status_code == 422
    expected = {"field": "body" if "extra" in body else "reason", "reason": reason}
    assert response.json() == {"detail": expected}
    assert events(api.conn, "knowledge.rejected") == []


@pytest.mark.db
def test_reject_accepts_five_hundred_characters(api) -> None:
    _, draft_id = alert_draft(api.conn)

    assert api.post(f"/drafts/{draft_id}/reject", {"reason": "ê" * 500}).status_code == 200


@pytest.mark.db
def test_reject_of_a_draft_that_is_not_pending_is_409_and_of_an_unknown_one_404(api) -> None:
    _, draft_id = alert_draft(api.conn, status="approved")

    assert api.post(f"/drafts/{draft_id}/reject", {"reason": "x"}).json() == {
        "detail": {"reason": "not_pending"}
    }
    assert api.post(f"/drafts/{draft_id}/reject", {"reason": "x"}).status_code == 409
    response = api.post(f"/drafts/{FAKE_ID}/reject", {"reason": "x"})
    assert (response.status_code, response.json()) == (404, {"detail": {"reason": "not_found"}})


@pytest.mark.db
def test_a_rejected_draft_cannot_be_approved(api) -> None:
    _, draft_id = alert_draft(api.conn)
    api.post(f"/drafts/{draft_id}/reject", {"reason": "x"})

    assert api.post(f"/drafts/{draft_id}/approve").status_code == 409


# ═══ the entries ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.db
def test_the_entry_list_rows_have_no_markdown(api) -> None:
    entry_id = an_entry(api)

    (row,) = api.get("/entries").json()

    assert set(row) == ENTRY_ROW_KEYS
    assert row["entry_id"] == entry_id and row["title"] == GOOD["title"]
    assert (row["status"], row["version"], row["conclusion"], row["category"]) == (
        "active",
        1,
        "closed_fp",
        "recon",
    )
    assert row["tags"] == ["port_scan", "firewall"] and row["evidence_count"] == 1
    assert row["file_path"] == f"entries/recon/{entry_id}.md"
    assert row["approved_by"] == api.admin_id and row["approved_at"]
    assert api.get("/entries?status=retired").json() == []


@pytest.mark.db
def test_the_entry_list_is_active_by_default_newest_approval_first(api) -> None:
    old, new = an_entry(api), an_entry(api)
    api.conn.execute(
        "UPDATE knowledge_entries SET approved_at = now() - interval '3 days' WHERE entry_id = %s",
        (old,),
    )
    api.conn.execute(
        "UPDATE knowledge_entries SET approved_at = now() - interval '1 days' WHERE entry_id = %s",
        (new,),
    )
    retired = add_entry(api.conn, status="retired", content="# x\n")

    assert [r["entry_id"] for r in api.get("/entries").json()] == [new, old]
    assert [r["entry_id"] for r in api.get("/entries?status=active&limit=1&offset=1").json()] == [
        old
    ]
    assert [r["entry_id"] for r in api.get("/entries?status=retired").json()] == [retired]


@pytest.mark.db
def test_the_entry_detail_is_the_entry_with_its_evidence(api) -> None:
    entry_id = an_entry(api)

    entry = api.get(f"/entries/{entry_id}").json()

    assert set(entry) == (ENTRY_ROW_KEYS - {"evidence_count"}) | {
        "fingerprint",
        "content",
        "source_alert_ids",
        "source_case_ids",
        "evidence",
        "supersedes_entry",
        "integrity",
    }
    assert [e["subject"].split(":")[0] for e in entry["evidence"]] == ["alert"]
    assert entry["fingerprint"].startswith("category: recon")
    assert entry["supersedes_entry"] is None and entry["approved_by_name"]
    assert entry["integrity"] == {"content_ok": True, "file_ok": True}


@pytest.mark.db
def test_the_entry_detail_says_when_the_file_was_changed_or_is_gone(api) -> None:
    entry_id = an_entry(api)
    path = api.root / api.get(f"/entries/{entry_id}").json()["file_path"]

    path.write_text("injected", encoding="utf-8")
    assert api.get(f"/entries/{entry_id}").json()["integrity"] == {
        "content_ok": True,
        "file_ok": False,
    }
    path.unlink()
    assert api.get(f"/entries/{entry_id}").json()["integrity"]["file_ok"] is False
    api.conn.execute(
        "UPDATE knowledge_entries SET content = content || 'x' WHERE entry_id = %s", (entry_id,)
    )
    assert api.get(f"/entries/{entry_id}").json()["integrity"]["content_ok"] is False


@pytest.mark.db
def test_an_unknown_entry_is_404_and_a_bad_id_is_422(api) -> None:
    response = api.get(f"/entries/{FAKE_ID}")
    assert (response.status_code, response.json()) == (404, {"detail": {"reason": "not_found"}})
    assert api.get("/entries/not-a-uuid").status_code == 422


@pytest.mark.db
def test_retire_moves_the_file_and_answers(api) -> None:
    entry_id = an_entry(api)
    before = api.get(f"/entries/{entry_id}").json()

    response = api.post(f"/entries/{entry_id}/retire", {"reason": "Không còn đúng"})

    assert response.status_code == 200
    assert response.json() == {"entry_id": entry_id, "status": "retired"}
    after = api.get(f"/entries/{entry_id}").json()
    assert after["status"] == "retired" and after["file_path"] == f"retired/recon/{entry_id}.md"
    assert after["integrity"] == {"content_ok": True, "file_ok": True}
    assert not (api.root / before["file_path"]).exists()
    ((subject, actor_id, payload),) = events(api.conn, "knowledge.retired")
    assert payload == {"entry_id": entry_id, "reason": "Không còn đúng"}
    assert (subject, actor_id) == (entry_id, api.admin_id)
    assert api.get("/entries").json() == []
    assert [r["entry_id"] for r in api.get("/entries?status=retired").json()] == [entry_id]


@pytest.mark.db
@pytest.mark.parametrize(
    ("body", "reason"),
    [({}, "required"), ({"reason": "  "}, "required"), ({"reason": "x" * 501}, "invalid")],
)
def test_retire_needs_a_reason(api, body, reason) -> None:
    entry_id = an_entry(api)

    response = api.post(f"/entries/{entry_id}/retire", body)

    assert (response.status_code, response.json()) == (
        422,
        {"detail": {"field": "reason", "reason": reason}},
    )
    assert api.get(f"/entries/{entry_id}").json()["status"] == "active"


@pytest.mark.db
def test_retire_twice_is_409_and_of_an_unknown_entry_404(api) -> None:
    entry_id = an_entry(api)
    assert api.post(f"/entries/{entry_id}/retire", {"reason": "x"}).status_code == 200

    again = api.post(f"/entries/{entry_id}/retire", {"reason": "x"})
    assert (again.status_code, again.json()) == (409, {"detail": {"reason": "not_active"}})
    missing = api.post(f"/entries/{FAKE_ID}/retire", {"reason": "x"})
    assert (missing.status_code, missing.json()) == (404, {"detail": {"reason": "not_found"}})
    assert len(events(api.conn, "knowledge.retired")) == 1


@pytest.mark.db
def test_a_retire_whose_commit_fails_moves_the_file_back(api) -> None:
    entry_id = an_entry(api)
    path = api.root / api.get(f"/entries/{entry_id}").json()["file_path"]
    api.session.fail_commit = True

    with pytest.raises(psycopg.OperationalError):
        api.post(f"/entries/{entry_id}/retire", {"reason": "x"})

    assert path.is_file()
    assert list((api.root / "retired").rglob("*.md")) == []


# ═══ the tags ════════════════════════════════════════════════════════════════════════════════


@pytest.mark.db
def test_the_tags_are_the_closed_vocabulary_with_a_description_each(api) -> None:
    body = api.get("/tags").json()

    assert set(body) == {"tags", "descriptions"}
    assert body["tags"] == sorted(load_tags())
    assert set(body["descriptions"]) == set(body["tags"])
    assert all(isinstance(text, str) and text for text in body["descriptions"].values())


# ═══ a whole round, as the page does it ══════════════════════════════════════════════════════


@pytest.mark.db
def test_the_round_a_page_makes(api) -> None:
    """list -> open -> edit and approve -> it is listed as approved and as an entry -> retire."""
    _, draft_id = case_draft(api.conn)

    (row,) = api.get("/drafts").json()
    detail = api.get(f"/drafts/{row['draft_id']}").json()
    entry_id = api.post(
        f"/drafts/{draft_id}/approve", {"edited": {"title": "Tiêu đề của admin"}}
    ).json()["entry_id"]
    (listed,) = api.get("/entries").json()
    api.post(f"/entries/{entry_id}/retire", {"reason": "hết hạn"})

    assert detail["source"]["case"]["case_id"] == detail["draft"]["source_id"]
    assert listed["entry_id"] == entry_id and listed["title"] == "Tiêu đề của admin"
    assert api.get("/entries").json() == []
    assert api.get("/entries?status=retired").json()[0]["entry_id"] == entry_id
