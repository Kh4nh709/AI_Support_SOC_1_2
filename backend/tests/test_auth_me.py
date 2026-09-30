"""GET /api/auth/me — P10-T01."""

from __future__ import annotations

import dataclasses
import uuid

import pytest
from app.infra import config
from app.infra.auth import Claims
from app.web import deps, main
from fastapi.testclient import TestClient

pytestmark = pytest.mark.db


def _make_user(conn, role="tier1", display="Người Thử"):
    uid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash) "
        "VALUES (%s, %s, %s, %s, 'x')",
        (uid, f"u-{uid[:8]}", display, role),
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

    # A non-empty JWT_SECRET, so the real `current_user` answers 401 (not 503, AuthDisabled)
    # when no token is sent (Director ruling R4).
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
    uid = _make_user(db)
    main.app.dependency_overrides[deps.current_user] = lambda: Claims(
        user_id=uid, username="k", role="tier1", iat=0.0, exp=1.0
    )
    text = client.get("/api/auth/me").text
    assert "password" not in text and "hash" not in text
