"""M1: a NUL byte, or any other control character, in an `alert_id` or `case_id` path parameter of
`/api/tier1/*` and `/api/tier2/*` (and of `POST /admin/digest/{alert_id}/review`, the one HTML route
with an alert id, P10-T17 fix round 1) answers 404 (the id names nothing), never a psycopg `DataError` 500.

The Reviewer found it on P10-T13: `GET /api/tier1/alerts/a%00b` reached `WHERE alert_id = %s` with a NUL
in the parameter, and the driver refused it (a `text` column cannot hold 0x00). It was parked with the
API frozen; P10-T17 item 8e fixes it with one shared validator, `deps.clean_path_id`, behind two
annotated types, `deps.AlertId` (tier1, a text id) and `deps.CaseId` (tier2, a uuid). The validator runs
as the path value is parsed, so it answers after the role check (a wrong role is still a 403) and before
the type check and any SQL; a malformed uuid with no control character is still the 422 that
`test_tier2_api.py` pins.

Three groups:
  - the validator itself (no database);
  - the HTTP answer of every route that takes such an id, GET and each POST, on a connection that
    fails the test if it is touched (so "before any SQL" is checked, not assumed);
  - the same routes on a real connection with a NUL byte, the case that was a 500 (db suite).
"""

from __future__ import annotations

import typing
import unicodedata
import uuid
from urllib.parse import quote

import pytest
from app.infra import config
from app.infra.auth import Claims
from app.web import deps, main
from app.web.routers import admin_digest, pages, tier1, tier2, tier2_runs
from fastapi import HTTPException
from fastapi.testclient import TestClient

# Every route with an id in its path: (method, path, role that may call it, JSON body).
ID_ROUTES = [
    ("get", "/api/tier1/alerts/{alert_id}", "tier1", None),
    ("post", "/api/tier1/alerts/{alert_id}/acknowledge", "tier1", None),
    (
        "post",
        "/api/tier1/alerts/{alert_id}/decide",
        "tier1",
        {"decision": "false_positive", "reason": "r", "seen_occurrence_count": 1},
    ),
    ("post", "/api/tier1/alerts/{alert_id}/escalate", "tier1", {"title": "t"}),
    ("post", "/api/tier1/alerts/{alert_id}/reopen", "tier1", {"reason": "r"}),
    ("get", "/api/tier2/cases/{case_id}", "tier2", None),
    ("post", "/api/tier2/cases/{case_id}/notes", "tier2", {"body": "b"}),
    (
        "post",
        "/api/tier2/cases/{case_id}/conclude",
        "tier2",
        {"conclusion": "concluded_fp", "reason": "r"},
    ),
    ("post", "/api/tier2/cases/{case_id}/analyze", "tier2", None),
    ("get", "/api/tier2/cases/{case_id}/investigation", "tier2", None),
]
ROUTE_IDS = [f"{m}-{p.split('/api/')[1]}" for m, p, _, _ in ID_ROUTES]

# The C0 set, DEL and the C1 set are all `Cc`; NUL is the one the driver refuses.
CONTROL_CHARS = ["\x00", "\x01", "\t", "\n", "\r", "\x1b", "\x1f", "\x7f", "\x85", "\x9f"]


def _url(template: str, raw_id: str) -> str:
    return template.replace("{alert_id}", quote(raw_id, safe="")).replace(
        "{case_id}", quote(raw_id, safe="")
    )


def _id_paths_of(*modules) -> set[tuple[str, str]]:
    found = set()
    for module in modules:
        for route in module.router.routes:
            if "{alert_id}" in route.path or "{case_id}" in route.path:
                found |= {(method.lower(), route.path) for method in route.methods}
    return found


# ---------------------------------------------------------------------------
# the validator
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("char", CONTROL_CHARS)
@pytest.mark.parametrize("where", ["a{}b", "{}ab", "ab{}"])
def test_the_validator_refuses_a_control_character_anywhere_in_the_id(char, where):
    with pytest.raises(HTTPException) as excinfo:
        deps.clean_path_id(where.format(char))
    assert excinfo.value.status_code == 404


@pytest.mark.parametrize(
    "value",
    [
        "1700000000.123456",  # a Wazuh alert id
        "p4t03api-7",
        str(uuid.uuid4()),
        "a b",  # a space is not a control character
        "é\u200b",  # nor is a letter, nor a zero-width space (category Cf)
        "x" * 300,
    ],
)
def test_the_validator_passes_an_id_without_one_and_returns_it_unchanged(value):
    assert deps.clean_path_id(value) == value


def test_the_control_set_is_the_unicode_Cc_category():
    refused = [chr(c) for c in range(0x110) if unicodedata.category(chr(c)) == "Cc"]
    assert len(refused) == 65  # 0x00-0x1f, 0x7f, 0x80-0x9f
    for char in refused:
        with pytest.raises(HTTPException):
            deps.clean_path_id(f"a{char}b")
    for code in range(0x20, 0x110):
        if unicodedata.category(chr(code)) != "Cc":
            assert deps.clean_path_id(f"a{chr(code)}b") == f"a{chr(code)}b"


def test_the_validator_leaves_a_value_that_is_not_text_to_the_type_check():
    # `CaseId` is a uuid: an already-parsed value (or None) is not this validator's to judge.
    value = uuid.uuid4()
    assert deps.clean_path_id(value) is value


# ---------------------------------------------------------------------------
# every route that takes an id uses the shared types (a new route cannot slip past)
# ---------------------------------------------------------------------------


def test_the_table_above_is_every_route_with_an_alert_or_case_id():
    assert _id_paths_of(tier1, tier2, tier2_runs) == {(m, p) for m, p, _, _ in ID_ROUTES}


def test_every_id_parameter_carries_the_shared_validator():
    checked = 0
    for module in (tier1, tier2, tier2_runs):
        for route in module.router.routes:
            hints = typing.get_type_hints(route.endpoint, include_extras=True)
            for name, shared in (("alert_id", deps.AlertId), ("case_id", deps.CaseId)):
                if f"{{{name}}}" in route.path:
                    assert hints[name] == shared, f"{route.path}: {name} is not deps."
                    checked += 1
    assert checked == len(ID_ROUTES)


# ---------------------------------------------------------------------------
# the HTTP answer
# ---------------------------------------------------------------------------


class _NoSql:
    """A connection that fails the test if a route touches it: the guard answers before any SQL."""

    def __getattr__(self, name):
        raise AssertionError(f"the route reached the connection ({name}) with a control character")


class _Http:
    def __init__(self, conn) -> None:
        self.role = "tier1"
        self.conn = conn
        self.client = TestClient(main.app, raise_server_exceptions=False)

    def claims(self) -> Claims:
        return Claims(user_id=str(uuid.uuid4()), username="u", role=self.role, iat=0.0, exp=0.0)

    def call(self, method: str, url: str, body, role: str):
        self.role = role
        send = getattr(self.client, method)
        return send(url, json=body) if body is not None else send(url)


def _http(conn):
    def get_conn():
        try:
            yield conn
        except BaseException:
            if not isinstance(conn, _NoSql):
                conn.rollback()
            raise

    http = _Http(conn)
    main.app.dependency_overrides[deps.get_conn] = get_conn
    main.app.dependency_overrides[deps.get_config] = lambda: config.Config()
    main.app.dependency_overrides[deps.current_user] = http.claims
    return http


@pytest.fixture
def no_sql_http():
    http = _http(_NoSql())
    try:
        yield http
    finally:
        for dep in (deps.get_conn, deps.get_config, deps.current_user):
            main.app.dependency_overrides.pop(dep, None)


@pytest.mark.parametrize("char", CONTROL_CHARS)
@pytest.mark.parametrize("method,template,role,body", ID_ROUTES, ids=ROUTE_IDS)
def test_a_control_character_in_the_id_is_a_404_on_every_route(
    no_sql_http, method, template, role, body, char
):
    resp = no_sql_http.call(method, _url(template, f"a{char}b"), body, role)
    assert resp.status_code == 404, (resp.status_code, resp.text[:200])


@pytest.mark.parametrize("method,template,role,body", ID_ROUTES, ids=ROUTE_IDS)
def test_a_control_character_wins_over_a_bad_body(no_sql_http, method, template, role, body):
    # The id is judged as it is parsed, before the body: an id that names nothing is a 404 either way.
    bad = {"unexpected": "x"} if body is not None else None
    resp = no_sql_http.call(method, _url(template, "a\x00b"), bad, role)
    assert resp.status_code == 404, (resp.status_code, resp.text[:200])


@pytest.mark.parametrize("method,template,role,body", ID_ROUTES, ids=ROUTE_IDS)
def test_a_wrong_role_is_still_a_403_with_a_control_character_in_the_id(
    monkeypatch, method, template, role, body
):
    """Auth first: the role check runs before the id is parsed, so the answer for a caller who may not
    use the route does not depend on the id (and the `authz.denied` row is still written)."""

    class Conn:
        def __init__(self) -> None:
            self.committed = 0
            self.events: list = []

        def execute(self, *args, **kwargs):
            self.events.append(args)
            return self

        def fetchone(self):
            return (1,)

        def commit(self):
            self.committed += 1

        def rollback(self):
            pass

    conn = Conn()
    http = _http(conn)
    try:
        wrong = "viewer"  # no route here admits it (the alert GET admits all three real roles)
        written = []
        monkeypatch.setattr(
            "app.web.deps.write_event", lambda *a, **k: written.append((a, k)), raising=True
        )
        resp = http.call(method, _url(template, "a\x00b"), body, wrong)
    finally:
        for dep in (deps.get_conn, deps.get_config, deps.current_user):
            main.app.dependency_overrides.pop(dep, None)
    assert resp.status_code == 403, (resp.status_code, resp.text[:200])
    assert len(written) == 1 and written[0][0][1] == "authz.denied"


@pytest.mark.parametrize(
    "method,template,role,body",
    [
        ("get", "/api/tier2/cases/{case_id}", "tier2", None),
        ("post", "/api/tier2/cases/{case_id}/notes", "tier2", {"body": "b"}),
    ],
    ids=["detail", "notes"],
)
def test_a_malformed_uuid_without_a_control_character_is_still_a_422(
    no_sql_http, method, template, role, body
):
    """The existing contract (`test_tier2_api.py`): the control-character rule does not touch it."""
    resp = no_sql_http.call(method, _url(template, "not-a-uuid"), body, role)
    assert resp.status_code == 422, (resp.status_code, resp.text[:200])


# ---------------------------------------------------------------------------
# the one HTML route with an alert id: POST /admin/digest/{alert_id}/review
# ---------------------------------------------------------------------------

ADMIN_REVIEW = "/admin/digest/{alert_id}/review"
REVIEW_FORM = {"day": "2026-09-30", "verdict": "correct"}


def test_the_admin_digest_review_is_the_only_html_route_with_an_alert_id_and_takes_the_shared_type():
    assert _id_paths_of(admin_digest) == {("post", ADMIN_REVIEW)}
    hints = typing.get_type_hints(admin_digest.review_submit, include_extras=True)
    assert hints["alert_id"] == deps.AlertId


def _admin_http(conn):
    """`_http`, plus the page-level login (`pages.page_user`) answering with the same claims."""
    http = _http(conn)
    main.app.dependency_overrides[pages.page_user] = http.claims
    return http


def _clear_overrides() -> None:
    for dep in (deps.get_conn, deps.get_config, deps.current_user, pages.page_user):
        main.app.dependency_overrides.pop(dep, None)


def _post_review(http, raw_id: str, data, role: str):
    http.role = role
    url = ADMIN_REVIEW.replace("{alert_id}", quote(raw_id, safe=""))
    return http.client.post(url, data=data)


@pytest.mark.parametrize("char", CONTROL_CHARS)
def test_a_control_character_in_the_id_is_a_404_on_the_admin_digest_review(char):
    http = _admin_http(_NoSql())
    try:
        resp = _post_review(http, f"a{char}b", REVIEW_FORM, "admin")
    finally:
        _clear_overrides()
    assert resp.status_code == 404, (resp.status_code, resp.text[:200])


def test_a_control_character_wins_over_a_bad_form_on_the_admin_digest_review():
    # The id is judged as it is parsed, before the form: an id that names nothing is a 404 either way.
    http = _admin_http(_NoSql())
    try:
        resp = _post_review(http, "a\x00b", {}, "admin")
    finally:
        _clear_overrides()
    assert resp.status_code == 404, (resp.status_code, resp.text[:200])


def test_a_wrong_role_is_still_a_403_on_the_admin_digest_review_with_a_control_character(
    monkeypatch,
):
    class Conn:
        def execute(self, *args, **kwargs):
            return self

        def fetchone(self):
            return (1,)

        def commit(self):
            pass

        def rollback(self):
            pass

    http = _admin_http(Conn())
    written = []
    monkeypatch.setattr(
        "app.web.deps.write_event", lambda *a, **k: written.append((a, k)), raising=True
    )
    try:
        resp = _post_review(http, "a\x00b", REVIEW_FORM, "tier1")
    finally:
        _clear_overrides()
    assert resp.status_code == 403, (resp.status_code, resp.text[:200])
    assert len(written) == 1 and written[0][0][1] == "authz.denied"


# ---------------------------------------------------------------------------
# the case that was a 500: a real connection and a NUL byte
# ---------------------------------------------------------------------------


@pytest.mark.db
@pytest.mark.parametrize("method,template,role,body", ID_ROUTES, ids=ROUTE_IDS)
def test_a_nul_byte_in_the_id_is_a_404_on_a_real_connection(db, method, template, role, body):
    http = _http(db)
    try:
        resp = http.call(method, _url(template, "a\x00b"), body, role)
        assert resp.status_code == 404, (resp.status_code, resp.text[:200])
        # Nothing reached the driver: the one connection is still clean and usable.
        assert db.execute("SELECT 1").fetchone() == (1,)
    finally:
        for dep in (deps.get_conn, deps.get_config, deps.current_user):
            main.app.dependency_overrides.pop(dep, None)


@pytest.mark.db
@pytest.mark.parametrize("char", ["\x00", "\x1b"])
def test_a_control_character_in_the_id_is_a_404_on_the_admin_digest_review_on_a_real_connection(
    db, char
):
    http = _admin_http(db)
    try:
        resp = _post_review(http, f"a{char}b", REVIEW_FORM, "admin")
        assert resp.status_code == 404, (resp.status_code, resp.text[:200])
        assert db.execute("SELECT 1").fetchone() == (1,)
    finally:
        _clear_overrides()
