"""P2-T08 — `POST /api/admin/reload-inventory` and the `get_conn` dependency.

Design note 4: `DATABASE_URL` (the `app_rw` DSN) exists only in the Owner's
`.env`, absent from every worktree, so the route is tested through
`fastapi.testclient.TestClient` with `app.dependency_overrides[get_conn]`
pointed at the `db` fixture's connection rather than the real dependency.
`get_conn`'s commit/rollback/close behaviour is proven separately against a
fake connection, with no database needed.
"""

from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent

import pytest
from app.infra import auth
from app.web import deps, main
from fastapi.testclient import TestClient


def _write(tmp_path: Path, name: str, text: str) -> str:
    path = tmp_path / name
    path.write_text(dedent(text).lstrip("\n"), encoding="utf-8")
    return str(path)


def _valid_files(tmp_path: Path) -> list[str]:
    assets = _write(
        tmp_path,
        "inventory.yaml",
        """
        version: 1
        assets:
          - hostname: host-a
            criticality: high
        """,
    )
    identities = _write(
        tmp_path,
        "identities.yaml",
        """
        version: 1
        identities:
          - username: alice
        """,
    )
    iocs = _write(
        tmp_path,
        "iocs.csv",
        """
        value,reputation,expires_at,source
        203.0.113.10,malicious,2030-01-01T00:00:00Z,manual
        """,
    )
    return [assets, identities, iocs]


@pytest.fixture
def client(db):
    # P4-T01: the route is behind `require_role("admin")`. `current_user` is
    # overridden with a seeded admin — never the role check itself, so a
    # `tier1` claim would still be refused — and the seed is rolled back with
    # the rest of the `db` fixture's transaction.
    admin_id = auth.create_user(
        db, username="p2t08-admin", display_name="Admin", role="admin", password="unused"
    )
    main.app.dependency_overrides[main.get_conn] = lambda: db
    main.app.dependency_overrides[deps.current_user] = lambda: auth.Claims(
        user_id=admin_id, username="p2t08-admin", role="admin", iat=0.0, exp=0.0
    )
    try:
        yield TestClient(main.app)
    finally:
        main.app.dependency_overrides.pop(main.get_conn, None)
        main.app.dependency_overrides.pop(deps.current_user, None)


# --------------------------------------------------------------------------
# the route, through TestClient with the dependency override
# --------------------------------------------------------------------------


@pytest.mark.db
def test_reload_inventory_returns_200_with_the_load_report(
    tmp_path: Path, monkeypatch, client: TestClient
) -> None:
    monkeypatch.setenv("INVENTORY_PATHS", json.dumps(_valid_files(tmp_path)))
    response = client.post("/api/admin/reload-inventory")
    assert response.status_code == 200
    assert response.json() == {
        "assets": 1,
        "identities": 1,
        "iocs": 1,
        "deactivated": 0,
        "warnings": [],
    }


@pytest.mark.db
def test_reload_inventory_returns_422_with_the_problem_list_on_a_broken_file(
    tmp_path: Path, monkeypatch, client: TestClient
) -> None:
    files = _valid_files(tmp_path)
    _write(
        tmp_path,
        "inventory.yaml",
        """
        version: 1
        assets:
          - hostname: host-a
            criticality: severe
        """,
    )
    monkeypatch.setenv("INVENTORY_PATHS", json.dumps(files))
    response = client.post("/api/admin/reload-inventory")
    assert response.status_code == 422
    problems = response.json()["detail"]
    assert isinstance(problems, list) and problems
    assert any("severe" in p and "inventory.yaml" in p for p in problems)


@pytest.mark.db
def test_reload_inventory_writes_nothing_on_a_broken_file(
    db, tmp_path: Path, monkeypatch, client: TestClient
) -> None:
    files = _valid_files(tmp_path)
    _write(
        tmp_path,
        "inventory.yaml",
        """
        version: 1
        assets:
          - hostname: host-a
            criticality: severe
        """,
    )
    monkeypatch.setenv("INVENTORY_PATHS", json.dumps(files))
    client.post("/api/admin/reload-inventory")
    count = db.execute("SELECT count(*) FROM assets").fetchone()[0]
    assert count == 0


@pytest.mark.db
def test_reload_inventory_succeeds_as_app_rw(
    db, tmp_path: Path, monkeypatch, client: TestClient
) -> None:
    # 017 grants app_rw INSERT/UPDATE on the three tables via ALTER DEFAULT
    # PRIVILEGES — this is the proof the real application role can reload.
    db.execute("SET ROLE app_rw")
    monkeypatch.setenv("INVENTORY_PATHS", json.dumps(_valid_files(tmp_path)))
    response = client.post("/api/admin/reload-inventory")
    assert response.status_code == 200
    assert response.json()["assets"] == 1


@pytest.mark.db
def test_reload_inventory_without_session_is_401(
    tmp_path: Path, monkeypatch, client: TestClient
) -> None:
    main.app.dependency_overrides.pop(deps.current_user)
    monkeypatch.setenv("INVENTORY_PATHS", json.dumps(_valid_files(tmp_path)))
    response = client.post("/api/admin/reload-inventory")
    assert response.status_code == 401
    assert response.json() == {"detail": "not authenticated"}


def test_reload_inventory_route_exists_under_api() -> None:
    # P4-T01: this used to assert the route was the *only* `/api/` path. Routers
    # are now discovered from `app.web.routers/` and every later card adds one,
    # so an exact snapshot here would make this file the shared file planning
    # decision 1 exists to avoid; each card asserts its own routes instead.
    api_paths = sorted(
        route.path for route in main.app.routes if getattr(route, "path", "").startswith("/api/")
    )
    assert "/api/admin/reload-inventory" in api_paths


def test_reload_inventory_route_accepts_post_only() -> None:
    (route,) = [
        r for r in main.app.routes if getattr(r, "path", None) == "/api/admin/reload-inventory"
    ]
    assert route.methods == {"POST"}


# --------------------------------------------------------------------------
# get_conn — commit on success, rollback on error, always closed
# --------------------------------------------------------------------------


class _FakeConn:
    def __init__(self) -> None:
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True

    def close(self) -> None:
        self.closed = True


def test_get_conn_commits_and_closes_on_success(monkeypatch) -> None:
    fake = _FakeConn()
    monkeypatch.setattr(deps.db, "connect", lambda: fake)
    gen = main.get_conn()
    conn = next(gen)
    assert conn is fake
    with pytest.raises(StopIteration):
        next(gen)
    assert fake.committed is True
    assert fake.rolled_back is False
    assert fake.closed is True


def test_get_conn_rolls_back_and_closes_on_exception(monkeypatch) -> None:
    fake = _FakeConn()
    monkeypatch.setattr(deps.db, "connect", lambda: fake)
    gen = main.get_conn()
    next(gen)
    with pytest.raises(ValueError, match="boom"):
        gen.throw(ValueError("boom"))
    assert fake.committed is False
    assert fake.rolled_back is True
    assert fake.closed is True
