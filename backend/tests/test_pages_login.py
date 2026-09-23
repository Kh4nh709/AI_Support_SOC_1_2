"""P4-T04 — `web/templating.py`, `web/templates/{base,login,_flash}.html`,
`web/routers/pages.py` (`GET`/`POST /login`, `POST /logout`, `GET /`).

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
def test_login_sets_httponly_lax_cookie_and_redirects_to_queue(client, sdb) -> None:
    username, _ = _seed(sdb)
    resp = client.post("/login", data={"username": username, "password": PASSWORD})
    assert resp.status_code == 303
    assert resp.headers["location"] == "/queue"
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


@pytest.mark.db
def test_root_redirects_to_queue(client) -> None:
    resp = client.get("/")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/queue"


@pytest.mark.db
def test_login_page_when_signed_in_redirects(client, sdb) -> None:
    username, _ = _seed(sdb)
    client.post("/login", data={"username": username, "password": PASSWORD})
    resp = client.get("/login")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/queue"


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
