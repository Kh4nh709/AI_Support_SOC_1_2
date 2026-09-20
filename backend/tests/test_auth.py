"""P4-T01 — `infra/auth.py`, `web/deps.py`, `web/routers/auth.py`, the discovering `main.py`
and the seed CLI.

Transaction discipline, because it decides what these tests can see. `now()` in
PostgreSQL is the *transaction start* time, and the `db` fixture holds one open
transaction until teardown. `logout`/`deactivate` write `sessions_invalid_before
= now()`, so a test that logs in and then logs out inside one transaction would
stamp the logout *before* the token's `iat` and prove nothing. Tests that need
time to move therefore commit between steps through the `committed` helper,
which deletes the users it created at teardown (`audit_events` is append-only —
those rows stay, keyed by usernames no other test uses).

The API tests override `deps.get_conn` with a generator that has the real
dependency's shape (commit on success, rollback on any exception) rather than
`lambda: db` — that is what makes the two commit-before-raise red steps
(DEC-025 (a) and (b)) go red: without the explicit `conn.commit()`, the
`HTTPException` rolls the counter / the `authz.denied` row back.
"""

from __future__ import annotations

import dataclasses
import importlib
import json
import os
import pkgutil
import shutil
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
import psycopg
import pytest
from app.infra import auth, config
from app.web import deps, main
from fastapi import APIRouter
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[2]
SECRET = "test-secret"
PASSWORD = "correct horse battery staple"


def _cfg(secret: str = SECRET, **overrides) -> config.Config:
    """DEC-047: the secret is a literal on a `Config`, never read from `.env`."""
    return dataclasses.replace(config.Config(), JWT_SECRET=secret, **overrides)


def _name(prefix: str) -> str:
    return f"p4t01-{prefix}-{uuid.uuid4().hex[:8]}"


def _seed(
    db, *, role: str = "tier1", password: str = PASSWORD, prefix: str = "u"
) -> tuple[str, str]:
    username = _name(prefix)
    user_id = auth.create_user(
        db, username=username, display_name=f"P4-T01 {prefix}", role=role, password=password
    )
    return username, user_id


def _row(db, user_id: str) -> tuple:
    return db.execute(
        "SELECT failed_logins, locked_until, sessions_invalid_before, is_active, role "
        "FROM users WHERE user_id = %s",
        (user_id,),
    ).fetchone()


@pytest.fixture
def committed(db):
    """Create users that are committed at once (so every later step is its own
    transaction and `now()` moves) and deleted at teardown."""
    created: list[str] = []

    def make(
        *, role: str = "tier1", password: str = PASSWORD, prefix: str = "u"
    ) -> tuple[str, str]:
        username, user_id = _seed(db, role=role, password=password, prefix=prefix)
        db.commit()
        created.append(user_id)
        return username, user_id

    yield make
    db.rollback()
    for user_id in created:
        db.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
    db.commit()


@pytest.fixture
def client(db):
    """`TestClient` on the real app with `get_conn` → the `db` fixture wrapped in the
    real dependency's commit/rollback shape, and `get_config` → a literal secret."""

    def get_conn():
        try:
            yield db
        except BaseException:
            db.rollback()
            raise
        else:
            db.commit()

    main.app.dependency_overrides[deps.get_conn] = get_conn
    main.app.dependency_overrides[deps.get_config] = lambda: _cfg()
    try:
        yield TestClient(main.app)
    finally:
        main.app.dependency_overrides.pop(deps.get_conn, None)
        main.app.dependency_overrides.pop(deps.get_config, None)


def _api_login(client: TestClient, username: str, password: str = PASSWORD):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --------------------------------------------------------------------------
# pure — hashing and tokens, no database
# --------------------------------------------------------------------------


def test_password_roundtrip_and_mismatch() -> None:
    hashed = auth.hash_password("s3cret")
    assert hashed.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert auth.verify_password(hashed, "s3cret") is True
    assert auth.verify_password(hashed, "s3cret ") is False
    assert auth.verify_password(hashed, "") is False


def test_malformed_hash_is_false_not_error() -> None:
    # argon2-cffi 25.1.0 raises `InvalidHashError(ValueError)` — *not* an
    # `Argon2Error` — on garbage; the migration 011 backfill hash raises
    # `VerificationError`. Both must be "no", never a 500.
    assert auth.verify_password("garbage", "pw") is False
    assert auth.verify_password("", "pw") is False
    assert auth.verify_password("$argon2id$v=19$m=65536,t=3,p=4$CHUA_DAT$CHUA_DAT", "pw") is False


def test_token_payload_keys() -> None:
    cfg = _cfg()
    claims = auth.Claims(user_id="u-1", username="alice", role="tier1", iat=1_000.25, exp=2_000.75)
    token = auth.issue_token(claims, cfg)
    payload = jwt.decode(
        token, SECRET, algorithms=["HS256"], options={"verify_exp": False, "verify_iat": False}
    )
    assert sorted(payload) == ["exp", "iat", "role", "sub"]
    assert payload == {"sub": "u-1", "role": "tier1", "iat": 1_000.25, "exp": 2_000.75}
    assert isinstance(payload["iat"], float) and isinstance(payload["exp"], float)


def test_expired_token_is_unauthorized_expired() -> None:
    cfg = _cfg()
    now = time.time()
    claims = auth.Claims(user_id="u-1", username="alice", role="tier1", iat=now - 20, exp=now - 10)
    token = auth.issue_token(claims, cfg)
    with pytest.raises(auth.Unauthorized) as excinfo:
        auth.verify(None, token, cfg)  # conn=None: the decode fails before any SQL
    assert excinfo.value.reason == "expired"


def test_wrong_secret_is_malformed() -> None:
    now = time.time()
    claims = auth.Claims(user_id="u-1", username="alice", role="tier1", iat=now, exp=now + 60)
    token = auth.issue_token(claims, _cfg(secret="another-secret"))
    with pytest.raises(auth.Unauthorized) as excinfo:
        auth.verify(None, token, _cfg())
    assert excinfo.value.reason == "malformed"


def test_garbage_and_missing_claims_are_malformed() -> None:
    cfg = _cfg()
    with pytest.raises(auth.Unauthorized) as excinfo:
        auth.verify(None, "not.a.token", cfg)
    assert excinfo.value.reason == "malformed"
    bare = jwt.encode({"sub": "u-1"}, SECRET, algorithm="HS256")
    with pytest.raises(auth.Unauthorized) as excinfo:
        auth.verify(None, bare, cfg)
    assert excinfo.value.reason == "malformed"


def test_empty_secret_is_auth_disabled_before_sql() -> None:
    cfg = _cfg(secret="")
    # conn=None: reaching any SQL would be an AttributeError, not AuthDisabled.
    with pytest.raises(auth.AuthDisabled):
        auth.login(None, "alice", "pw", cfg)
    with pytest.raises(auth.AuthDisabled):
        auth.verify(None, "whatever", cfg)


def test_create_user_rejects_a_bad_role_before_any_sql() -> None:
    with pytest.raises(ValueError, match="boss"):
        auth.create_user(None, username="x", display_name="X", role="boss", password="pw")


# --------------------------------------------------------------------------
# db — login, lockout, logout, deactivate, verify
# --------------------------------------------------------------------------


@pytest.mark.db
def test_create_user_writes_row_and_system_event(db) -> None:
    username, user_id = _seed(db, role="tier2", prefix="create")
    uuid.UUID(user_id)  # a real uuid, returned as str
    row = db.execute(
        "SELECT username, display_name, role, is_active, failed_logins, locked_until, "
        "sessions_invalid_before FROM users WHERE user_id = %s",
        (user_id,),
    ).fetchone()
    assert row == (username, "P4-T01 create", "tier2", True, 0, None, None)
    events = db.execute(
        "SELECT event_type, subject_id, actor_role, actor_id, payload FROM audit_events "
        "WHERE subject_id = %s",
        (user_id,),
    ).fetchall()
    assert events == [
        ("admin.user_created", user_id, "system", None, {"username": username, "role": "tier2"})
    ]


@pytest.mark.db
def test_create_user_never_stores_the_password(db) -> None:
    _username, user_id = _seed(db, prefix="hash")
    (stored,) = db.execute(
        "SELECT password_hash FROM users WHERE user_id = %s", (user_id,)
    ).fetchone()
    assert PASSWORD not in stored
    assert auth.verify_password(stored, PASSWORD)


@pytest.mark.db
def test_login_resets_failed_logins(db) -> None:
    cfg = _cfg()
    username, user_id = _seed(db, prefix="reset")
    db.execute("UPDATE users SET failed_logins = 3 WHERE user_id = %s", (user_id,))
    before = time.time()
    claims = auth.login(db, username, PASSWORD, cfg)
    assert claims.user_id == user_id
    assert claims.username == username
    assert claims.role == "tier1"
    assert before <= claims.iat <= time.time()
    assert claims.exp == pytest.approx(claims.iat + 8 * 3600)
    assert _row(db, user_id)[:2] == (0, None)


@pytest.mark.db
def test_unknown_user_and_inactive_user_are_login_failed(db) -> None:
    cfg = _cfg()
    with pytest.raises(auth.LoginFailed) as excinfo:
        auth.login(db, _name("nobody"), PASSWORD, cfg)
    assert excinfo.value.reason == "unknown_user"
    username, user_id = _seed(db, prefix="inactive")
    assert auth.deactivate(db, username) is True
    with pytest.raises(auth.LoginFailed) as excinfo:
        auth.login(db, username, PASSWORD, cfg)
    assert excinfo.value.reason == "inactive"
    # an inactive user's right password neither counts as a failure nor locks
    assert _row(db, user_id)[:2] == (0, None)


@pytest.mark.db
def test_fifth_wrong_password_locks_and_sixth_right_one_is_still_locked(db) -> None:
    cfg = _cfg()
    username, user_id = _seed(db, prefix="lock")
    for attempt in range(1, 5):
        with pytest.raises(auth.LoginFailed) as excinfo:
            auth.login(db, username, "wrong", cfg)
        assert excinfo.value.reason == "bad_password"
        assert _row(db, user_id)[:2] == (attempt, None)
    with pytest.raises(auth.AccountLocked) as locked:
        auth.login(db, username, "wrong", cfg)
    failed, locked_until, *_ = _row(db, user_id)
    assert failed == 5 == cfg.LOGIN_MAX_FAILS
    assert locked.value.locked_until == locked_until
    (window,) = db.execute(
        "SELECT locked_until - now() FROM users WHERE user_id = %s", (user_id,)
    ).fetchone()
    assert window == timedelta(minutes=cfg.LOCKOUT_MINUTES)
    # the sixth attempt with the RIGHT password is refused without touching the counter
    with pytest.raises(auth.AccountLocked) as still:
        auth.login(db, username, PASSWORD, cfg)
    assert still.value.locked_until == locked_until
    assert _row(db, user_id)[:2] == (5, locked_until)


@pytest.mark.db
def test_expired_lock_lets_the_right_password_in_and_resets(db) -> None:
    cfg = _cfg()
    username, user_id = _seed(db, prefix="unlock")
    db.execute(
        "UPDATE users SET failed_logins = 5, locked_until = now() - interval '1 second' "
        "WHERE user_id = %s",
        (user_id,),
    )
    claims = auth.login(db, username, PASSWORD, cfg)
    assert claims.username == username
    assert _row(db, user_id)[:2] == (0, None)


@pytest.mark.db
def test_logout_kills_earlier_token_and_later_login_works_without_sleep(committed, db) -> None:
    cfg = _cfg()
    username, user_id = committed(prefix="logout")
    first = auth.issue_token(auth.login(db, username, PASSWORD, cfg), cfg)
    db.commit()
    assert auth.verify(db, first, cfg).user_id == user_id

    # Force the logout and the next login into the SAME second (planning decision
    # 8's case): with an integer `iat`, or `<` instead of `<=`, the later token
    # would die with the earlier one. Retrying is cheap; the loop almost always
    # exits on the first pass.
    for _ in range(50):
        auth.logout(db, user_id)
        db.commit()
        with pytest.raises(auth.Unauthorized) as excinfo:
            auth.verify(db, first, cfg)
        assert excinfo.value.reason == "logged_out"
        later = auth.login(db, username, PASSWORD, cfg)
        db.commit()
        (invalid_epoch,) = db.execute(
            "SELECT EXTRACT(EPOCH FROM sessions_invalid_before) FROM users WHERE user_id = %s",
            (user_id,),
        ).fetchone()
        if int(later.iat) == int(invalid_epoch):
            break
    else:  # pragma: no cover — 50 misses in a row would be a clock problem, not a code one
        pytest.fail("could not place a logout and a login inside the same second")

    assert later.iat > float(invalid_epoch)
    assert auth.verify(db, auth.issue_token(later, cfg), cfg).user_id == user_id


@pytest.mark.db
def test_deactivate_kills_tokens(committed, db) -> None:
    cfg = _cfg()
    username, user_id = committed(prefix="deact")
    token = auth.issue_token(auth.login(db, username, PASSWORD, cfg), cfg)
    db.commit()
    assert auth.deactivate(db, username) is True
    db.commit()
    with pytest.raises(auth.Unauthorized) as excinfo:
        auth.verify(db, token, cfg)
    assert excinfo.value.reason == "inactive"
    assert _row(db, user_id)[2] is not None  # sessions_invalid_before set at the same moment
    assert auth.deactivate(db, _name("nobody")) is False


@pytest.mark.db
def test_verify_returns_row_role_not_token_role(db) -> None:
    cfg = _cfg()
    username, user_id = _seed(db, role="tier1", prefix="role")
    token = auth.issue_token(auth.login(db, username, PASSWORD, cfg), cfg)
    assert jwt.decode(token, SECRET, algorithms=["HS256"])["role"] == "tier1"
    db.execute("UPDATE users SET role = 'admin' WHERE user_id = %s", (user_id,))
    claims = auth.verify(db, token, cfg)
    assert claims.role == "admin"
    assert (claims.user_id, claims.username) == (user_id, username)


@pytest.mark.db
def test_verify_unknown_user_is_unauthorized(db) -> None:
    cfg = _cfg()
    ghost = auth.Claims(
        user_id=str(uuid.uuid4()),
        username="ghost",
        role="admin",
        iat=time.time(),
        exp=time.time() + 60,
    )
    with pytest.raises(auth.Unauthorized) as excinfo:
        auth.verify(db, auth.issue_token(ghost, cfg), cfg)
    assert excinfo.value.reason == "unknown_user"
    not_a_uuid = dataclasses.replace(ghost, user_id="not-a-uuid")
    with pytest.raises(auth.Unauthorized) as excinfo:
        auth.verify(db, auth.issue_token(not_a_uuid, cfg), cfg)
    assert excinfo.value.reason == "malformed"


@pytest.mark.db
def test_set_password(db) -> None:
    cfg = _cfg()
    username, _ = _seed(db, prefix="setpw")
    assert auth.set_password(db, username, "new one") is True
    with pytest.raises(auth.LoginFailed):
        auth.login(db, username, PASSWORD, cfg)
    assert auth.login(db, username, "new one", cfg).username == username
    assert auth.set_password(db, _name("nobody"), "x") is False


# --------------------------------------------------------------------------
# api — through TestClient
# --------------------------------------------------------------------------


@pytest.mark.db
def test_api_login_sets_cookie_and_returns_token(committed, client, db) -> None:
    username, user_id = committed(prefix="api")
    before = datetime.now(UTC)
    response = _api_login(client, username)
    assert response.status_code == 200, response.text
    body = response.json()
    assert sorted(body) == ["expires_at", "role", "token", "user_id"]
    assert body["role"] == "tier1" and body["user_id"] == user_id
    expires_at = datetime.fromisoformat(body["expires_at"])
    assert timedelta(hours=8) <= expires_at - before < timedelta(hours=8, seconds=30)
    assert auth.verify(db, body["token"], _cfg()).user_id == user_id

    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{deps.COOKIE_NAME}={body['token']};")
    lowered = cookie.lower()
    assert "httponly" in lowered and "samesite=lax" in lowered and "path=/" in lowered
    assert "max-age=28800" in lowered
    assert "secure" not in lowered
    assert client.cookies[deps.COOKIE_NAME] == body["token"]


@pytest.mark.db
def test_api_cookie_alone_authenticates_and_bearer_wins_over_it(committed, client, db) -> None:
    username, _ = committed(prefix="cookie")
    token = _api_login(client, username).json()["token"]
    assert client.cookies[deps.COOKIE_NAME] == token
    # a bad bearer is refused even though the cookie in the jar is good
    refused = client.post("/api/auth/logout", headers=_bearer("garbage"))
    assert refused.status_code == 401 and refused.json() == {"detail": "malformed"}
    # the cookie alone authenticates
    response = client.post("/api/auth/logout")
    assert response.status_code == 204
    assert deps.COOKIE_NAME not in client.cookies


@pytest.mark.db
def test_api_invalid_credentials_body_never_says_which(committed, client, db) -> None:
    username, _ = committed(prefix="which")
    inactive, _ = committed(prefix="inact")
    auth.deactivate(db, inactive)
    db.commit()
    bodies = {
        _api_login(client, _name("nobody")).json()["detail"],
        _api_login(client, username, "wrong").json()["detail"],
        _api_login(client, inactive).json()["detail"],
    }
    assert bodies == {"invalid credentials"}


@pytest.mark.db
def test_api_five_wrong_passwords_is_423(committed, client, db) -> None:
    username, user_id = committed(prefix="five")
    for _ in range(4):
        response = _api_login(client, username, "wrong")
        assert response.status_code == 401
        assert response.json() == {"detail": "invalid credentials"}
    fifth = _api_login(client, username, "wrong")
    assert fifth.status_code == 423, fifth.text
    body = fifth.json()
    assert body["detail"] == "locked"
    locked_until = datetime.fromisoformat(body["locked_until"])
    assert locked_until.tzinfo is not None
    assert sorted(body) == ["detail", "locked_until"]
    # the lock survived the 4xx: the right password is refused too
    sixth = _api_login(client, username)
    assert sixth.status_code == 423
    assert sixth.json()["locked_until"] == body["locked_until"]
    assert _row(db, user_id)[0] == 5


@pytest.mark.db
def test_api_logout_then_bearer_is_401(committed, client) -> None:
    username, _ = committed(prefix="bye")
    token = _api_login(client, username).json()["token"]
    response = client.post("/api/auth/logout", headers=_bearer(token))
    assert response.status_code == 204
    assert response.content == b""
    cleared = response.headers["set-cookie"].lower()
    assert cleared.startswith(f"{deps.COOKIE_NAME}=") and "max-age=0" in cleared
    again = client.post("/api/auth/logout", headers=_bearer(token))
    assert again.status_code == 401
    assert again.json() == {"detail": "logged_out"}


@pytest.mark.db
def test_api_logout_without_a_session_is_401(client) -> None:
    response = client.post("/api/auth/logout")
    assert response.status_code == 401
    assert response.json() == {"detail": "not authenticated"}


@pytest.mark.db
def test_reload_inventory_as_tier1_is_403_and_authz_denied_persists(
    committed, client, _test_database, monkeypatch
) -> None:
    monkeypatch.setenv("INVENTORY_PATHS", json.dumps(["/nonexistent/p4t01/inventory.yaml"]))
    username, user_id = committed(prefix="t1")
    token = _api_login(client, username).json()["token"]
    response = client.post("/api/admin/reload-inventory", headers=_bearer(token))
    assert response.status_code == 403
    assert response.json() == {"detail": "forbidden"}
    # A second connection sees only what was committed: the row survived the 403.
    with psycopg.connect(_test_database) as other:
        rows = other.execute(
            "SELECT subject_id, actor_role, actor_id, payload FROM audit_events "
            "WHERE event_type = 'authz.denied' AND actor_id = %s",
            (user_id,),
        ).fetchall()
    assert rows == [
        (
            "/api/admin/reload-inventory",
            "analyst",
            uuid.UUID(user_id),
            {"required": ["admin"], "role": "tier1", "method": "POST"},
        )
    ]


@pytest.mark.db
def test_reload_inventory_as_admin_is_not_403(committed, client, db, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("INVENTORY_PATHS", json.dumps([str(tmp_path / "missing.yaml")]))
    username, user_id = committed(role="admin", prefix="adm")
    token = _api_login(client, username).json()["token"]
    response = client.post("/api/admin/reload-inventory", headers=_bearer(token))
    # past both dependencies: P2-T08's own 422 for a file that is not there
    assert response.status_code == 422, response.text
    assert any("file not found" in problem for problem in response.json()["detail"])
    (denied,) = db.execute(
        "SELECT count(*) FROM audit_events WHERE event_type = 'authz.denied' AND actor_id = %s",
        (user_id,),
    ).fetchone()
    assert denied == 0


@pytest.mark.db
def test_api_login_with_empty_secret_is_503(client) -> None:
    main.app.dependency_overrides[deps.get_config] = lambda: _cfg(secret="")
    response = _api_login(client, "anyone")
    assert response.status_code == 503
    assert response.json() == {"detail": "auth disabled: JWT_SECRET unset"}


@pytest.mark.db
def test_api_verify_with_empty_secret_is_503(client) -> None:
    main.app.dependency_overrides[deps.get_config] = lambda: _cfg(secret="")
    response = client.post("/api/auth/logout", headers=_bearer("anything"))
    assert response.status_code == 503
    assert response.json() == {"detail": "auth disabled: JWT_SECRET unset"}


# --------------------------------------------------------------------------
# the routers package and main.py
# --------------------------------------------------------------------------


def test_routers_are_discovered_sorted_and_auth_routes_exist() -> None:
    from app.web import routers

    names = [info.name for info in pkgutil.iter_modules(routers.__path__)]
    assert "auth" in names
    found = routers.iter_routers()
    assert len(found) == len(names)
    assert all(isinstance(router, APIRouter) for router in found)
    by_name = [importlib.import_module(f"app.web.routers.{n}").router for n in sorted(names)]
    assert found == by_name  # sorted by module name, every module's `router`
    auth_paths = {route.path for route in found[sorted(names).index("auth")].routes}
    assert auth_paths == {"/api/auth/login", "/api/auth/logout"}

    # FastAPI 0.141.1 keeps an included router as one lazy `_IncludedRouter`
    # node in `app.routes` (measured) — the mounted paths are read from the
    # OpenAPI table, which resolves them.
    app_paths = set(main.app.openapi()["paths"])
    assert {"/api/auth/login", "/api/auth/logout", "/api/admin/reload-inventory"} <= app_paths
    assert main.app.openapi()["paths"]["/api/auth/logout"].keys() == {"post"}
    assert main.get_conn is deps.get_conn


def test_router_module_without_router_fails_at_startup(tmp_path, monkeypatch) -> None:
    """DEC-039's shape, refused: a module under routers/ that forgets `router`
    is an `AttributeError` when the app starts, never a silently missing route.
    The real `__init__.py` is copied verbatim into a scratch package to prove it."""
    package = tmp_path / "scratch_routers"
    package.mkdir()
    shutil.copy(REPO_ROOT / "backend" / "app" / "web" / "routers" / "__init__.py", package)
    (package / "broken.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    scratch = importlib.import_module("scratch_routers")
    with pytest.raises(AttributeError, match="router"):
        scratch.iter_routers()


# --------------------------------------------------------------------------
# the seed CLI
# --------------------------------------------------------------------------


def _env_key(username: str) -> str:
    return f"SEED_PASSWORD_{username.upper().replace('-', '_')}"


def _run_cli(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "app.infra.auth", *args],
        cwd=REPO_ROOT,
        env={**os.environ, "PYTHONPATH": "backend", **env},
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


@pytest.mark.db
def test_cli_seed_users_creates_then_skips(db, _test_database) -> None:
    dsn = _test_database
    one, two = _name("cli-a"), _name("cli-b")
    env = {_env_key(one): "one-pw", _env_key(two): "two-pw"}
    args = [
        "seed-users",
        "--dsn",
        dsn,
        "--user",
        one,
        "tier1",
        "Alpha One",
        "--user",
        two,
        "admin",
        "Bravo Two",
    ]
    try:
        first = _run_cli(args, env)
        assert first.returncode == 0, first.stdout + first.stderr
        assert f"created: {one} (tier1)" in first.stdout
        assert f"created: {two} (admin)" in first.stdout
        hashes = dict(
            db.execute(
                "SELECT username, password_hash FROM users WHERE username IN (%s, %s)", (one, two)
            ).fetchall()
        )
        assert set(hashes) == {one, two}
        assert auth.login(db, one, "one-pw", _cfg()).role == "tier1"
        db.commit()

        second = _run_cli(args, {_env_key(one): "changed", _env_key(two): "changed"})
        assert second.returncode == 0, second.stdout + second.stderr
        assert f"exists, skipped: {one}" in second.stdout
        assert f"exists, skipped: {two}" in second.stdout
        assert "created:" not in second.stdout
        again = dict(
            db.execute(
                "SELECT username, password_hash FROM users WHERE username IN (%s, %s)", (one, two)
            ).fetchall()
        )
        assert again == hashes  # never overwritten

        for output in (first, second):
            text = output.stdout + output.stderr
            for secret in ("one-pw", "two-pw", "changed", dsn, *hashes.values()):
                assert secret not in text
        (events,) = db.execute(
            "SELECT count(*) FROM audit_events WHERE event_type = 'admin.user_created' "
            "AND actor_role = 'system' AND actor_id IS NULL "
            "AND payload->>'username' IN (%s, %s)",
            (one, two),
        ).fetchone()
        assert events == 2
    finally:
        db.rollback()
        db.execute("DELETE FROM users WHERE username IN (%s, %s)", (one, two))
        db.commit()


def test_cli_has_no_password_argument() -> None:
    parser = auth.build_parser()
    assert "--password" not in parser.format_help()
    for command in ("seed-users", "set-password", "deactivate"):
        assert command in parser.format_help()
    subparsers = next(a for a in parser._actions if isinstance(a, auth.argparse._SubParsersAction))
    assert "password" not in subparsers.choices["seed-users"].format_help()


def test_cli_bad_role_exits_1(capsys, monkeypatch) -> None:
    monkeypatch.setenv("SEED_PASSWORD_X", "pw")
    # no reachable DSN is needed: the role is validated before connecting
    rc = auth.main(
        ["seed-users", "--dsn", "postgresql:///p4t01_unreachable", "--user", "x", "boss", "X"]
    )
    assert rc == 1
    assert "boss" in capsys.readouterr().err


@pytest.mark.db
def test_cli_set_password_deactivate_and_exit_codes(
    db, _test_database, capsys, monkeypatch
) -> None:
    dsn = _test_database
    username = _name("cli-c")
    key = _env_key(username)
    try:
        monkeypatch.setenv(key, "first")
        assert auth.main(["seed-users", "--dsn", dsn, "--user", username, "tier2", "Charlie"]) == 0
        assert auth.login(db, username, "first", _cfg()).role == "tier2"
        db.commit()

        monkeypatch.setenv(key, "second")
        assert auth.main(["set-password", "--dsn", dsn, username]) == 0
        assert auth.login(db, username, "second", _cfg()).role == "tier2"
        db.commit()

        monkeypatch.delenv(key)
        monkeypatch.setattr(auth.getpass, "getpass", lambda prompt: "")
        assert auth.main(["set-password", "--dsn", dsn, username]) == 1
        assert auth.main(["seed-users", "--dsn", dsn, "--user", _name("cli-d"), "tier1", "D"]) == 1

        assert auth.main(["set-password", "--dsn", dsn, _name("nobody")]) == 1
        assert auth.main(["deactivate", "--dsn", dsn, _name("nobody")]) == 1
        assert auth.main(["deactivate", "--dsn", dsn, username]) == 0
        with pytest.raises(auth.LoginFailed) as excinfo:
            auth.login(db, username, "second", _cfg())
        assert excinfo.value.reason == "inactive"
        db.commit()

        monkeypatch.setenv(key, "x")
        assert (
            auth.main(
                [
                    "seed-users",
                    "--dsn",
                    "postgresql:///p4t01_no_such_db",
                    "--user",
                    username,
                    "tier1",
                    "C",
                ]
            )
            == 2
        )
        captured = capsys.readouterr()
        assert "p4t01_no_such_db" not in captured.out
        assert "postgresql:///" not in captured.out + captured.err
        for secret in ("first", "second"):
            assert secret not in captured.out + captured.err
    finally:
        db.rollback()
        db.execute("DELETE FROM users WHERE username = %s", (username,))
        db.commit()
