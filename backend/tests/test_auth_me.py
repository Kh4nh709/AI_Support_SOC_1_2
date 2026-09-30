"""GET /api/auth/me — P10-T01."""

from __future__ import annotations

import dataclasses
import time
import uuid

import pytest
from app.infra import auth, config
from app.infra.auth import Claims
from app.web import deps, main
from fastapi.testclient import TestClient

pytestmark = pytest.mark.db


SENTINEL_HASH = "$argon2id$v=19$m=65536,t=3,p=4$SENTINELSALT$SENTINELHASH"


def _make_user(conn, role="tier1", display="Người Thử", password_hash="x"):
    uid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash) "
        "VALUES (%s, %s, %s, %s, %s)",
        (uid, f"u-{uid[:8]}", display, role, password_hash),
    )
    return uid


@pytest.fixture
def client(db):
    def get_conn():
        try:
            yield db
        except BaseException:
            db.rollback()
            raise

    # A non-empty JWT_SECRET (Director ruling R4): with the default empty one, the real
    # `current_user` answers 503 (AuthDisabled), not 401, for any request that carries a token.
    main.app.dependency_overrides[deps.get_conn] = get_conn
    main.app.dependency_overrides[deps.get_config] = lambda: dataclasses.replace(
        config.Config(), JWT_SECRET="test-secret"
    )
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()


def test_me_returns_the_signed_in_user(db, client):
    uid = _make_user(db, role="tier2", display="Mai Nam")
    main.app.dependency_overrides[deps.current_user] = lambda: Claims(
        user_id=uid, username="nguyen", role="tier2", iat=0.0, exp=1_900_000_000.0
    )
    body = client.get("/api/auth/me").json()
    assert body == {
        "user_id": uid,
        "username": "nguyen",
        "display_name": "Mai Nam",
        "role": "tier2",
        "expires_at": "2030-03-17T17:46:40+00:00",
    }


def test_me_without_a_session_is_401(client):
    assert client.get("/api/auth/me").status_code == 401


def test_me_with_a_bad_token_is_401(client):
    # Unlike the no-token case (`current_user` answers 401 before it reads the config), a token
    # reaches `auth.verify`, which needs the fixture's JWT_SECRET: with it empty this is 503.
    response = client.get("/api/auth/me", headers={"Authorization": "Bearer not-a-jwt"})
    assert response.status_code == 401


def test_me_never_returns_a_hash(db, client):
    uid = _make_user(db, password_hash=SENTINEL_HASH)
    main.app.dependency_overrides[deps.current_user] = lambda: Claims(
        user_id=uid, username="k", role="tier1", iat=0.0, exp=1.0
    )
    response = client.get("/api/auth/me")
    assert response.status_code == 200
    text = response.text
    assert "password" not in text and "hash" not in text
    # The stored value itself must not appear under any key, neutral ones included.
    assert "SENTINEL" not in text and "argon2" not in text


def test_me_takes_the_role_from_the_row_not_the_token(db, client):
    # No `current_user` override: the real dependency verifies a real token and re-reads the row.
    uid = _make_user(db, role="tier1", display="Trần Hạ")
    username = db.execute("SELECT username FROM users WHERE user_id = %s", (uid,)).fetchone()[0]
    now = time.time()
    token = auth.issue_token(
        Claims(user_id=uid, username="ignored", role="admin", iat=now, exp=now + 3600),
        dataclasses.replace(config.Config(), JWT_SECRET="test-secret"),
    )
    response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    body = response.json()
    assert body["role"] == "tier1"  # the row's role, not the token's "admin"
    assert body["username"] == username
    assert body["display_name"] == "Trần Hạ"
    assert body["user_id"] == uid
