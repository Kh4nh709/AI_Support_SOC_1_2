"""P4-T04 — `web/templating.py`, `web/templates/{base,login,_flash}.html`,
`web/routers/pages.py` (`GET`/`POST /login`, `POST /logout`, `GET /`).

P10-T13 retired the Jinja Tier-1/Tier-2 pages: `GET /` is now the home a role lands on
(tier1/tier2 → the page that points to the React UI on port 8080, admin → `/admin/rules`,
no session → `/login`), the queue/alert/case routes answer 404 for everyone, and the
navigation carries admin links only.

A scratch database, not the shared `db` fixture (`test_auth.py`'s pattern,
P4-T01): login and logout are separate, committed transactions, and
`sessions_invalid_before` (set at logout) must be measured against the real
clock, not `db`'s one held-open transaction's frozen `now()` — and a
committing test must never write into the shared `soc_test` that
`test_schema_v3_017.py` counts from zero.
"""

from __future__ import annotations

import dataclasses
import os
import shutil
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import psycopg
import pytest
from app.infra import auth, config
from app.web import deps, main, templating
from app.web.routers import pages
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from tests import conftest

REPO_ROOT = Path(__file__).resolve().parents[2]
SECRET = "test-secret"
PASSWORD = "correct horse battery staple"
LOGIN_FAILED_TEXT = "Sai tên đăng nhập hoặc mật khẩu"
NEW_UI_HEADING = "Dùng giao diện mới tại cổng 8080"

#: Every route the Jinja Tier-1/Tier-2 pages had (the alert, case and case-analyze page
#: routers), with a placeholder id: none may answer any more.
RETIRED_ROUTES = [
    ("GET", "/queue"),
    ("GET", "/alerts/x"),
    ("POST", "/alerts/x/acknowledge"),
    ("POST", "/alerts/x/decide"),
    ("POST", "/alerts/x/escalate"),
    ("POST", "/alerts/x/reopen"),
    ("GET", "/cases"),
    ("GET", "/cases/x"),
    ("POST", "/cases/x/notes"),
    ("POST", "/cases/x/conclude"),
    ("GET", "/cases/x/investigation"),
    ("POST", "/cases/x/analyze"),
]


def _cfg(secret: str = SECRET, **overrides) -> config.Config:
    return dataclasses.replace(config.Config(), JWT_SECRET=secret, **overrides)


def _seed(conn, *, role: str = "tier1", password: str = PASSWORD, prefix: str = "u"):
    username = f"p4t04-{prefix}-{uuid.uuid4().hex[:8]}"
    user_id = auth.create_user(
        conn, username=username, display_name=f"P4-T04 {prefix}", role=role, password=password
    )
    return username, user_id


def _scratch_dbname() -> str:
    session = os.environ.get("TEST_DATABASE_URL", conftest.DEFAULT_TEST_DATABASE_URL)
    return f"{conftest._dbname(session)}_pages_test"


@pytest.fixture(scope="module")
def scratch_dsn():
    if shutil.which("psql") is None or shutil.which("createdb") is None:
        pytest.skip("psql/createdb not on PATH — cannot build the pages scratch database")
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


@pytest.fixture
def client(sdb):
    """`get_conn` → `sdb`, in the real dependency's commit/rollback shape;
    `get_config` → a literal `JWT_SECRET` (DEC-047)."""

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
        yield TestClient(main.app, follow_redirects=False)
    finally:
        main.app.dependency_overrides.pop(deps.get_conn, None)
        main.app.dependency_overrides.pop(deps.get_config, None)


# --------------------------------------------------------------------------
# GET /login, GET /, POST /login, POST /logout
# --------------------------------------------------------------------------


@pytest.mark.db
def test_login_page_renders_with_pinned_htmx(client) -> None:
    resp = client.get("/login")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert 'name="password"' in resp.text
    assert "/htmx/2.0.4/" in resp.text
    assert "latest" not in resp.text


@pytest.mark.db
def test_login_sets_httponly_lax_cookie_and_redirects_home(client, sdb) -> None:
    username, _ = _seed(sdb)
    resp = client.post("/login", data={"username": username, "password": PASSWORD})
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"
    set_cookie = resp.headers["set-cookie"]
    assert "soc_session=" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "samesite=lax" in set_cookie.lower()
    assert "secure" not in set_cookie.lower()


@pytest.mark.db
def test_login_wrong_password_is_401_html_with_flash(client, sdb) -> None:
    username, _ = _seed(sdb)
    resp = client.post("/login", data={"username": username, "password": "wrong"})
    assert resp.status_code == 401
    assert resp.headers["content-type"].startswith("text/html")
    assert LOGIN_FAILED_TEXT in resp.text


@pytest.mark.db
def test_login_five_wrong_is_423(client, sdb) -> None:
    username, _ = _seed(sdb)
    for _ in range(4):
        resp = client.post("/login", data={"username": username, "password": "wrong"})
        assert resp.status_code == 401
    resp = client.post("/login", data={"username": username, "password": "wrong"})
    assert resp.status_code == 423
    assert "bị khoá" in resp.text
    # the sixth attempt, even with the RIGHT password, is still refused
    resp = client.post("/login", data={"username": username, "password": PASSWORD})
    assert resp.status_code == 423


@pytest.mark.db
def test_login_with_empty_secret_is_503(sdb) -> None:
    username, _ = _seed(sdb)

    def get_conn():
        try:
            yield sdb
        except BaseException:
            sdb.rollback()
            raise
        else:
            sdb.commit()

    main.app.dependency_overrides[deps.get_conn] = get_conn
    main.app.dependency_overrides[deps.get_config] = lambda: _cfg(secret="")
    try:
        client = TestClient(main.app, follow_redirects=False)
        resp = client.post("/login", data={"username": username, "password": PASSWORD})
    finally:
        main.app.dependency_overrides.pop(deps.get_conn, None)
        main.app.dependency_overrides.pop(deps.get_config, None)
    assert resp.status_code == 503
    assert resp.headers["content-type"].startswith("text/html")


@pytest.mark.db
def test_logout_clears_cookie_and_kills_session(client, sdb) -> None:
    username, _ = _seed(sdb)
    client.post("/login", data={"username": username, "password": PASSWORD})
    old_cookie = client.cookies.get("soc_session")
    assert old_cookie

    resp = client.post("/logout")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"
    assert "max-age=0" in resp.headers["set-cookie"].lower()

    # the client jar dropped the expired cookie already; a stale copy of the
    # SAME token must still be refused server-side (the session, not the
    # cookie, is what died). A manual header, not `cookies=`, keeps this a
    # one-request override instead of mutating the client's own jar.
    resp = client.get("/login", headers={"cookie": f"soc_session={old_cookie}"})
    assert resp.status_code == 200


def _sign_in(client, sdb, role: str) -> None:
    username, _ = _seed(sdb, role=role, prefix=role)
    resp = client.post("/login", data={"username": username, "password": PASSWORD})
    assert resp.status_code == 303, resp.text


def _assert_points_to_the_new_ui(resp, *, href: str) -> None:
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert NEW_UI_HEADING in resp.text
    assert f'href="{href}"' in resp.text
    # Nothing on it leads to a retired page, and the header keeps the sign-out form.
    for retired in ("/queue", "/cases", "/alerts/"):
        assert f'href="{retired}' not in resp.text
    assert 'action="/logout"' in resp.text


@pytest.mark.db
def test_tier1_home_points_to_the_new_ui(client, sdb) -> None:
    _sign_in(client, sdb, "tier1")
    resp = client.get("/")
    # `testserver` is the TestClient's own Host: only the port changes.
    _assert_points_to_the_new_ui(resp, href="http://testserver:8080/")


@pytest.mark.db
def test_tier2_home_points_to_the_new_ui(client, sdb) -> None:
    _sign_in(client, sdb, "tier2")
    resp = client.get("/")
    _assert_points_to_the_new_ui(resp, href="http://testserver:8080/")


@pytest.mark.db
def test_admin_home_is_admin_rules(client, sdb) -> None:
    _sign_in(client, sdb, "admin")
    resp = client.get("/")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin/rules"
    # ... and the target is a real page for that session, not another redirect.
    assert client.get("/admin/rules").status_code == 200


@pytest.mark.db
def test_home_without_a_session_goes_to_login(client) -> None:
    resp = client.get("/")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


@pytest.mark.db
def test_login_lands_on_the_home_of_each_role(client, sdb) -> None:
    """`POST /login` always answers 303 `/`; `/` then sends each role where it belongs
    (the redirect chain, not just its first hop)."""
    landing = {}
    for role in ("tier1", "tier2", "admin"):
        chain = TestClient(main.app, follow_redirects=True)
        username, _ = _seed(sdb, role=role, prefix=f"land-{role}")
        sdb.commit()
        resp = chain.post("/login", data={"username": username, "password": PASSWORD})
        landing[role] = (resp.status_code, resp.url.path, NEW_UI_HEADING in resp.text)
    assert landing == {
        "tier1": (200, "/", True),
        "tier2": (200, "/", True),
        "admin": (200, "/admin/rules", False),
    }


@pytest.mark.db
@pytest.mark.parametrize("role", ["tier1", "tier2", "admin", None])
def test_retired_routes_are_gone(client, sdb, role) -> None:
    """P10-T13: the Jinja queue, alert, case and investigation/analyze pages (and their
    decision/notes/conclude fragments) are not routes any more — 404 for every role and
    for no session at all (a redirect to /login would mean a route still exists)."""
    if role is not None:
        _sign_in(client, sdb, role)
    seen = {route: client.request(*route).status_code for route in RETIRED_ROUTES}
    assert seen == {route: 404 for route in RETIRED_ROUTES}


@pytest.mark.db
def test_the_json_api_beside_the_retired_pages_still_answers(client, sdb) -> None:
    _sign_in(client, sdb, "tier1")
    assert client.get("/api/tier1/queue").status_code == 200


# --- the link to the new UI: the Host the user came in on, the port swapped -------------


@pytest.mark.db
@pytest.mark.parametrize(
    ("host_header", "href"),
    [
        ("127.0.0.1:8000", "http://127.0.0.1:8080/"),
        ("192.168.10.7:8000", "http://192.168.10.7:8080/"),
        ("soc-box.lan", "http://soc-box.lan:8080/"),
        ("[::1]:8000", "http://[::1]:8080/"),
    ],
)
def test_the_new_ui_link_keeps_the_host_and_changes_only_the_port(
    client, sdb, host_header, href
) -> None:
    _sign_in(client, sdb, "tier1")
    resp = client.get("/", headers={"host": host_header})
    _assert_points_to_the_new_ui(resp, href=href)
    assert ":8000" not in resp.text.split("<main>", 1)[1]


@pytest.mark.db
@pytest.mark.parametrize(
    "host_header",
    [
        "127.0.0.1:8000/evil",
        "evil.example:80@127.0.0.1",
        '"><script>alert(1)</script>',
    ],
)
def test_a_hostile_host_header_gets_no_link_and_is_not_echoed(client, sdb, host_header) -> None:
    _sign_in(client, sdb, "tier1")
    resp = client.get("/", headers={"host": host_header})
    assert resp.status_code == 200
    assert NEW_UI_HEADING in resp.text
    body = resp.text.split("<main>", 1)[1]
    assert "http://" not in body  # no link at all
    assert "evil" not in resp.text
    assert "<script>alert" not in resp.text


@pytest.mark.parametrize(
    ("host_header", "expected"),
    [
        ("127.0.0.1:8000", "http://127.0.0.1:8080/"),
        ("127.0.0.1", "http://127.0.0.1:8080/"),
        ("192.168.10.7:8000", "http://192.168.10.7:8080/"),
        ("SOC-Box.Example.com:443", "http://SOC-Box.Example.com:8080/"),
        ("[::1]:8000", "http://[::1]:8080/"),
        ("[fe80::1]", "http://[fe80::1]:8080/"),
    ],
)
def test_new_ui_url_swaps_only_the_port(host_header, expected) -> None:
    assert pages.new_ui_url(host_header) == expected


@pytest.mark.parametrize(
    "host_header",
    [
        None,
        "",
        "   ",
        "127.0.0.1:8000/evil",  # a path
        "127.0.0.1:8000?x=1",  # a query
        "127.0.0.1:8000#frag",  # a fragment
        "evil.example:80@127.0.0.1",  # userinfo
        "user@127.0.0.1",
        "127.0.0.1:8000:9090",  # two ports
        "127.0.0.1:",  # an empty port
        ":8000",  # no host
        "127.0.0.1:99999",  # not a port
        "127.0.0.1:80 80",
        "a b.example",
        "-evil.example",
        "evil-.example",
        "evil..example",
        ".example",
        "example.",
        '"><script>alert(1)</script>',
        "evil.example\\@127.0.0.1",
        "[::1",  # unclosed
        "[evil]:8000",  # not an address
        "[::1]x",
        "127.0.0.1\r\nX-Injected: 1",
        "é.example",  # not ASCII
        "a" * 64 + ".example",  # a label over 63 characters
    ],
)
def test_new_ui_url_rejects_a_port_or_path_trick(host_header) -> None:
    assert pages.new_ui_url(host_header) is None


def test_the_new_ui_port_is_the_one_compose_publishes() -> None:
    """The link's port is a constant in `pages.py`; `docker-compose.yml`'s `ui` service is
    where the port really lives (`127.0.0.1:8080:80`, P10-T01): the two cannot drift apart."""
    compose = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert f":{pages.NEW_UI_PORT}:80" in compose


@pytest.mark.db
def test_login_page_when_signed_in_redirects(client, sdb) -> None:
    username, _ = _seed(sdb)
    client.post("/login", data={"username": username, "password": PASSWORD})
    resp = client.get("/login")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"


# --------------------------------------------------------------------------
# templating.py — pure, no database
# --------------------------------------------------------------------------


def test_autoescape_is_on() -> None:
    html = templating.templates.get_template("_flash.html").render(
        flash={"level": "info", "text": "<b>x</b>"}
    )
    assert "&lt;b&gt;" in html
    assert "<b>x</b>" not in html


def test_local_time_filter_uses_display_tz() -> None:
    value = datetime(2026, 9, 16, 17, 56, 56, tzinfo=UTC)
    assert templating.local_time(value, "Asia/Ho_Chi_Minh") == "17/09 00:56:56"
    assert templating.local_time(None, "Asia/Ho_Chi_Minh") == ""


def test_admin_nav_link_only_for_admin() -> None:
    admin = auth.Claims(user_id="1", username="chi", role="admin", iat=0.0, exp=0.0)
    tier1 = auth.Claims(user_id="2", username="an", role="tier1", iat=0.0, exp=0.0)
    template = templating.templates.get_template("base.html")
    html_admin = template.render(user=admin, htmx_src=templating.HTMX_SRC, htmx_integrity=None)
    html_tier1 = template.render(user=tier1, htmx_src=templating.HTMX_SRC, htmx_integrity=None)
    assert "/admin/labels" in html_admin
    assert "/admin/labels" not in html_tier1


def test_nav_carries_admin_links_only() -> None:
    # P10-T13: the queue and case links went with the pages. What is left is the admin
    # console (labels P4, rules P5-T10, digest P5-T09), for admin only.
    template = templating.templates.get_template("base.html")
    html = {
        role: template.render(
            user=auth.Claims(user_id="1", username="u", role=role, iat=0.0, exp=0.0),
            htmx_src=templating.HTMX_SRC,
            htmx_integrity=None,
        )
        for role in ("tier1", "tier2", "admin")
    }
    for role, page in html.items():
        for retired in ('href="/queue"', 'href="/cases"'):
            assert retired not in page, f"{role}: {retired}"
        assert 'href="/"' in page  # the brand link goes home, and home knows the role
    for link in ('href="/admin/labels"', 'href="/admin/rules"', 'href="/admin/digest"'):
        assert link in html["admin"]
        assert link not in html["tier1"]
        assert link not in html["tier2"]
    # No admin link, no empty navigation bar either.
    assert "<nav>" not in html["tier1"]
    assert "<nav>" not in html["tier2"]


# --------------------------------------------------------------------------
# pages.page_user — not wired to any route in this card, so tested on an
# ad-hoc app (P4-T05 and P6-T02 wire it to real pages). Nothing here ever
# writes, so the shared `db` fixture (rolled back at teardown) is fine.
# --------------------------------------------------------------------------


@pytest.mark.db
def test_page_user_redirects_instead_of_401(db) -> None:
    app = FastAPI()

    @app.get("/protected")
    def protected(user: Annotated[auth.Claims, Depends(pages.page_user)]):
        return {"user_id": user.user_id}

    def get_conn():
        try:
            yield db
        except BaseException:
            db.rollback()
            raise
        else:
            db.commit()

    app.dependency_overrides[deps.get_conn] = get_conn
    app.dependency_overrides[deps.get_config] = lambda: _cfg()
    tc = TestClient(app, follow_redirects=False)
    resp = tc.get("/protected")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"
