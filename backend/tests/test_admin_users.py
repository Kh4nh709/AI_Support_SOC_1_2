"""Users and roles (P11-T02, DEC-200, spec §5.1).

Everything runs through the real app on a scratch database the module builds: real logins,
real Bearer tokens, committed rows. A session ending is shown the only way that counts — a
token issued before the change stops working on `GET /api/auth/me` — and the last-admin guard
is shown on real connections racing each other, because a single admin acting alone can never
reach it: the actor is an active admin, so another active admin always remains unless two of
them act at once.

The route tests read the database through their own connection (`sdb`) after the app has
committed on its own; the race tests call `update_user` directly on two or three connections
with committed seed data, because "A has demoted B but not committed" cannot be said through
HTTP.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import threading
import time
import uuid

import psycopg
import pytest
from app.infra import auth, config
from app.web import deps, main
from app.web.routers import admin_users
from fastapi.testclient import TestClient

from tests.scratch_db import scratch_database

pytestmark = pytest.mark.db

SECRET = "p11t02-secret"
PASSWORD = "correct horse battery staple"
NEW_PASSWORD = "another horse, twelve+"
MISSING = object()  # a body field left out, as opposed to a field set to something


def _cfg() -> config.Config:
    return dataclasses.replace(config.Config(), JWT_SECRET=SECRET)


@pytest.fixture(scope="module")
def dsn():
    with scratch_database("users") as scratch:
        yield scratch


@pytest.fixture
def sdb(dsn):
    conn = psycopg.connect(dsn)
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


@pytest.fixture
def client(dsn):
    """The real app; every request gets its own connection to the scratch database, committed
    on success and rolled back on error — the shape of the real `get_conn`."""

    def get_conn():
        conn = psycopg.connect(dsn)
        try:
            yield conn
        except BaseException:
            conn.rollback()
            raise
        else:
            conn.commit()
        finally:
            conn.close()

    main.app.dependency_overrides[deps.get_conn] = get_conn
    main.app.dependency_overrides[deps.get_config] = _cfg
    try:
        yield TestClient(main.app)
    finally:
        main.app.dependency_overrides.pop(deps.get_conn, None)
        main.app.dependency_overrides.pop(deps.get_config, None)


def _seed(sdb, role: str, *, prefix: str = "u", password: str = PASSWORD) -> tuple[str, str]:
    username = f"p11t02-{prefix}-{uuid.uuid4().hex[:8]}"
    user_id = auth.create_user(
        sdb, username=username, display_name=f"P11-T02 {prefix}", role=role, password=password
    )
    sdb.commit()
    return username, user_id


def _login(client: TestClient, username: str, password: str = PASSWORD) -> dict[str, str]:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


def _admin(client, sdb, prefix: str = "admin") -> tuple[str, str, dict[str, str]]:
    username, user_id = _seed(sdb, "admin", prefix=prefix)
    return username, user_id, _login(client, username)


def _events(sdb, event_type: str, subject_id: str) -> list[tuple]:
    sdb.rollback()  # a fresh snapshot: the app committed on its own connection
    return sdb.execute(
        "SELECT actor_id::text, actor_role, payload FROM audit_events "
        "WHERE event_type = %s AND subject_id = %s ORDER BY audit_id",
        (event_type, subject_id),
    ).fetchall()


def _count_events(sdb, event_type: str) -> int:
    sdb.rollback()
    (count,) = sdb.execute(
        "SELECT count(*) FROM audit_events WHERE event_type = %s", (event_type,)
    ).fetchone()
    return count


def _alive(client, headers) -> bool:
    return client.get("/api/auth/me", headers=headers).status_code == 200


def _row(sdb, user_id: str) -> dict:
    """The columns this card writes, read straight from the table."""
    sdb.rollback()
    cols = ("role", "display_name", "is_active", "failed_logins", "locked_until")
    values = sdb.execute(
        f"SELECT {', '.join(cols)}, sessions_invalid_before IS NOT NULL FROM users "
        "WHERE user_id = %s",
        (user_id,),
    ).fetchone()
    return dict(zip((*cols, "sessions_ended"), values, strict=True))


def _keys(value):
    """Every dict key at any depth."""
    if isinstance(value, dict):
        for key, inner in value.items():
            yield key
            yield from _keys(inner)
    elif isinstance(value, list):
        for item in value:
            yield from _keys(item)


USER_ROW_KEYS = {
    "user_id",
    "username",
    "display_name",
    "role",
    "is_active",
    "locked_until",
    "failed_logins",
    "last_login_at",
    "created_at",
}


def _assert_no_credential(response) -> None:
    """No key that names a credential, at any depth, and no hash value either."""
    assert not [k for k in _keys(response.json()) if "password" in k.lower() or "hash" in k.lower()]
    assert "$argon2" not in response.text


def _only_these_admins_active(sdb, keep: set[str]) -> None:
    sdb.execute(
        "UPDATE users SET is_active = false WHERE role = 'admin' AND NOT (user_id::text = ANY(%s))",
        (list(keep),),
    )
    sdb.commit()


def _unlock(client, headers, user_id):
    """`unlock` has no payload, but like every write of this module it needs the JSON type."""
    return client.post(f"/api/admin/users/{user_id}/unlock", headers=headers, json={})


def _active_admins(sdb) -> int:
    sdb.rollback()
    (count,) = sdb.execute(
        "SELECT count(*) FROM users WHERE role = 'admin' AND is_active"
    ).fetchone()
    return count


def _in_thread(fn):
    """Run `fn` on a thread; the outcome is read from the box, never raised in the test thread."""
    box: dict[str, object] = {}

    def run() -> None:
        try:
            box["result"] = fn()
        except BaseException as exc:  # noqa: BLE001 - handed to the asserting thread
            box["error"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, box


def _connect(dsn) -> psycopg.Connection:
    # A bounded lock wait: a guard that goes wrong fails the test instead of hanging it.
    return psycopg.connect(dsn, options="-c lock_timeout=20000")


# --------------------------------------------------------------------------
# login stamps last_login_at
# --------------------------------------------------------------------------


def test_login_stamps_last_login_at_and_a_failed_login_does_not(client, sdb):
    username, user_id = _seed(sdb, "tier1")

    def stamp():
        sdb.rollback()
        return sdb.execute(
            "SELECT last_login_at, last_login_at > now() - interval '1 minute' "
            "FROM users WHERE user_id = %s",
            (user_id,),
        ).fetchone()

    wrong = {"username": username, "password": "wrong"}
    assert client.post("/api/auth/login", json=wrong).status_code == 401
    assert stamp() == (None, None)
    _login(client, username)
    first, recent = stamp()
    assert first is not None and recent
    assert client.post("/api/auth/login", json=wrong).status_code == 401
    assert stamp()[0] == first  # a failed login leaves the stamp alone
    time.sleep(0.01)
    _login(client, username)
    assert stamp()[0] > first  # and the next success moves it


def test_a_locked_account_is_not_stamped(client, sdb):
    username, user_id = _seed(sdb, "tier1")
    sdb.execute(
        "UPDATE users SET failed_logins = 5, locked_until = now() + interval '15 minutes' "
        "WHERE user_id = %s",
        (user_id,),
    )
    sdb.commit()
    good = {"username": username, "password": PASSWORD}
    assert client.post("/api/auth/login", json=good).status_code == 423
    sdb.rollback()
    (stamp,) = sdb.execute(
        "SELECT last_login_at FROM users WHERE user_id = %s", (user_id,)
    ).fetchone()
    assert stamp is None


# --------------------------------------------------------------------------
# list
# --------------------------------------------------------------------------


def test_list_has_every_user_and_no_credential(client, sdb):
    _, _, headers = _admin(client, sdb)
    tier1_name, tier1_id = _seed(sdb, "tier1")
    response = client.get("/api/admin/users", headers=headers)
    assert response.status_code == 200
    _assert_no_credential(response)
    body = response.json()
    assert set(body) == {"users"}
    row = next(u for u in body["users"] if u["user_id"] == tier1_id)
    assert set(row) == USER_ROW_KEYS
    assert row["username"] == tier1_name and row["last_login_at"] is None
    assert row["is_active"] is True and row["failed_logins"] == 0 and row["locked_until"] is None


def test_the_list_carries_the_lock_and_the_last_login(client, sdb):
    _, _, headers = _admin(client, sdb)
    username, user_id = _seed(sdb, "tier2")
    _login(client, username)
    sdb.execute(
        "UPDATE users SET failed_logins = 3, locked_until = now() + interval '10 minutes' "
        "WHERE user_id = %s",
        (user_id,),
    )
    sdb.commit()
    row = next(
        u
        for u in client.get("/api/admin/users", headers=headers).json()["users"]
        if u["user_id"] == user_id
    )
    assert row["failed_logins"] == 3
    assert row["locked_until"] is not None and row["last_login_at"] is not None


def test_the_list_is_ordered_by_username_in_byte_order(client, sdb):
    _, _, headers = _admin(client, sdb)
    token = uuid.uuid4().hex[:8]
    names = [f"p11t02-ord-{token}-{tail}" for tail in ("b", "a1", "a-1", "a.1", "a_1", "a")]
    for name in names:
        auth.create_user(sdb, username=name, display_name="o", role="tier1", password=PASSWORD)
    sdb.commit()
    listed = [
        u["username"] for u in client.get("/api/admin/users", headers=headers).json()["users"]
    ]
    assert listed == sorted(listed)  # the whole list, as the database's locale might not sort it
    assert [n for n in listed if token in n] == sorted(names)


# --------------------------------------------------------------------------
# create
# --------------------------------------------------------------------------


def _new_body(**override) -> dict:
    body = {
        "username": f"p11t02-new-{uuid.uuid4().hex[:8]}",
        "display_name": "Ngô Bình",
        "role": "tier1",
        "password": PASSWORD,
        **override,
    }
    return {k: v for k, v in body.items() if v is not MISSING}


def test_create_writes_the_user_and_an_event_the_admin_signs(client, sdb):
    _, admin_id, headers = _admin(client, sdb)
    body = _new_body(display_name="  Ngô Bình  ", role="tier2")
    response = client.post("/api/admin/users", headers=headers, json=body)
    assert response.status_code == 201, response.text
    assert set(response.json()) == {"user_id"}
    user_id = response.json()["user_id"]
    [(actor_id, actor_role, payload)] = _events(sdb, "admin.user_created", user_id)
    assert (actor_id, actor_role) == (admin_id, "admin")
    assert payload == {"username": body["username"], "role": "tier2"}
    assert _row(sdb, user_id)["display_name"] == "Ngô Bình"  # stripped
    assert _alive(client, _login(client, body["username"]))


AT_THE_BOUND = {
    "username-3-chars": lambda: {"username": uuid.uuid4().hex[:3]},
    "username-32-chars": lambda: {"username": "u" + uuid.uuid4().hex[:31]},
    "username-dot-underscore-dash": lambda: {"username": f"a.b_c-{uuid.uuid4().hex[:6]}"},
    "display-name-1-char": lambda: {"display_name": "x"},
    "display-name-100-chars": lambda: {"display_name": "\u01a0" * 100},
    "role-admin": lambda: {"role": "admin"},
    "password-12-chars": lambda: {"password": "twelve chars"},
    "password-256-chars": lambda: {"password": "p" * 256},
}


@pytest.mark.parametrize("make", AT_THE_BOUND.values(), ids=AT_THE_BOUND.keys())
def test_create_accepts_each_value_at_its_bound(client, sdb, make):
    _, _, headers = _admin(client, sdb)
    body = _new_body(**make())
    response = client.post("/api/admin/users", headers=headers, json=body)
    assert response.status_code == 201, response.text
    assert _alive(client, _login(client, body["username"], body["password"]))  # the whole password


def test_create_refuses_a_taken_username_and_writes_nothing(client, sdb):
    _, _, headers = _admin(client, sdb)
    taken, taken_id = _seed(sdb, "tier2")
    created = _count_events(sdb, "admin.user_created")
    response = client.post(
        "/api/admin/users", headers=headers, json=_new_body(username=taken, role="admin")
    )
    assert response.status_code == 409
    assert response.json()["detail"] == {"reason": "username_taken"}
    assert _count_events(sdb, "admin.user_created") == created
    assert _row(sdb, taken_id)["role"] == "tier2"  # the existing account is untouched
    (rows,) = sdb.execute("SELECT count(*) FROM users WHERE username = %s", (taken,)).fetchone()
    assert rows == 1


CREATE_BAD = [
    ({"password": "elevenchars"}, "password", "too_short"),
    ({"password": ""}, "password", "too_short"),
    ({"password": "x" * 257}, "password", "too_long"),
    ({"password": 123456789012}, "password", "invalid"),
    ({"password": MISSING}, "password", "empty"),
    ({"role": "root"}, "role", "invalid"),
    ({"role": "ADMIN"}, "role", "invalid"),
    ({"role": ["admin"]}, "role", "invalid"),
    ({"role": MISSING}, "role", "empty"),
    ({"username": "ab"}, "username", "invalid"),
    ({"username": "Abc"}, "username", "invalid"),
    ({"username": "has space"}, "username", "invalid"),
    ({"username": "x" * 33}, "username", "invalid"),
    ({"username": "trailing\n"}, "username", "invalid"),  # `$` alone would let this through
    ({"username": "ngô-bình"}, "username", "invalid"),
    ({"username": 12345}, "username", "invalid"),
    ({"username": MISSING}, "username", "empty"),
    ({"display_name": "   "}, "display_name", "empty"),
    ({"display_name": "x" * 101}, "display_name", "too_long"),
    ({"display_name": "two\nlines"}, "display_name", "invalid"),
    ({"display_name": MISSING}, "display_name", "empty"),
]


@pytest.mark.parametrize(
    ("override", "field", "reason"),
    CREATE_BAD,
    ids=[f"{field}-{reason}-{i}" for i, (_, field, reason) in enumerate(CREATE_BAD)],
)
def test_create_validates_each_field(client, sdb, override, field, reason):
    _, _, headers = _admin(client, sdb)
    created = _count_events(sdb, "admin.user_created")
    body = _new_body(**override)
    response = client.post("/api/admin/users", headers=headers, json=body)
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert isinstance(detail, dict)
    assert (detail["field"], detail["reason"]) == (field, reason)
    if (field, reason) == ("password", "too_short"):
        assert detail["min"] == 12
    # the answer never carries a password, the sent one or another field's
    assert PASSWORD not in response.text
    sent = body.get("password")
    if isinstance(sent, str) and len(sent) > 3:
        assert sent not in response.text
    assert _count_events(sdb, "admin.user_created") == created


def test_the_first_bad_field_is_the_one_reported_in_the_form_order(client, sdb):
    _, _, headers = _admin(client, sdb)
    body = _new_body(username="x", display_name="", role="root", password="short")
    response = client.post("/api/admin/users", headers=headers, json=body)
    assert response.json()["detail"]["field"] == "username"


def test_a_password_that_cannot_be_encoded_and_a_nul_in_the_name_are_422_not_500(client, sdb):
    _, _, headers = _admin(client, sdb)
    json_headers = {**headers, "Content-Type": "application/json"}
    name = f"p11t02-raw-{uuid.uuid4().hex[:8]}"
    # a lone surrogate is legal JSON and illegal UTF-8: argon2 would raise on it
    lone = f'{{"username": "{name}", "display_name": "V", "role": "tier1", "password": "\\ud800{"a" * 20}"}}'
    nul = f'{{"username": "{name}", "display_name": "a\\u0000b", "role": "tier1", "password": "{PASSWORD}"}}'
    first = client.post("/api/admin/users", headers=json_headers, content=lone)
    second = client.post("/api/admin/users", headers=json_headers, content=nul)
    assert first.status_code == 422
    assert first.json()["detail"] == {"field": "password", "reason": "invalid"}
    assert second.status_code == 422
    assert second.json()["detail"] == {"field": "display_name", "reason": "invalid"}


def _create_text(**override) -> str:
    return json.dumps(_new_body(**override))


@pytest.mark.parametrize(
    ("content", "content_type"),
    [
        ("{not json", "application/json"),
        ('["leak-leak-leak-leak"]', "application/json"),
        ("null", "application/json"),
        ('"leak-leak-leak-leak"', "application/json"),
        ("", "application/json"),
        # a cross-site form post cannot say application/json: the cookie must not carry it
        (_create_text(password="leak-leak-leak-leak"), "text/plain"),
        (_create_text(password="leak-leak-leak-leak"), "application/x-www-form-urlencoded"),
        # and a no-cors fetch with a Blob body sends no Content-Type at all
        (_create_text(password="leak-leak-leak-leak"), None),
    ],
    ids=["bad-json", "array", "null", "string", "empty", "text-plain", "form", "no-content-type"],
)
def test_a_body_that_is_not_a_json_object_is_refused_and_never_echoed(
    client, sdb, content, content_type
):
    _, _, headers = _admin(client, sdb)
    created = _count_events(sdb, "admin.user_created")
    sent = dict(headers) if content_type is None else {**headers, "Content-Type": content_type}
    response = client.post("/api/admin/users", headers=sent, content=content)
    assert response.status_code == 422
    assert response.json()["detail"] == {"field": "body", "reason": "invalid"}
    assert "leak" not in response.text
    assert _count_events(sdb, "admin.user_created") == created


def test_a_field_the_route_does_not_take_is_refused_not_ignored(client, sdb):
    _, _, headers = _admin(client, sdb)
    created = _count_events(sdb, "admin.user_created")
    response = client.post(
        "/api/admin/users", headers=headers, json=_new_body(is_active=False, hunter2hunter2=1)
    )
    assert response.status_code == 422
    assert response.json()["detail"] == {"field": "body", "reason": "invalid"}
    assert "hunter2" not in response.text
    assert _count_events(sdb, "admin.user_created") == created


BODY_INVALID = {"field": "body", "reason": "invalid"}


def _cookie_session(client, sdb) -> str:
    """Log an admin in so the client's jar holds `soc_session`, and return the admin's id. The
    requests below carry that cookie and no `Authorization` header: the shape a browser sends."""
    username, admin_id = _seed(sdb, "admin", prefix="cookie")
    login = client.post("/api/auth/login", json={"username": username, "password": PASSWORD})
    assert login.status_code == 200 and "soc_session" in client.cookies
    return admin_id


def _raw(client, method: str, path: str, content: str, content_type: str | None):
    headers = {} if content_type is None else {"Content-Type": content_type}
    request = client.build_request(method, path, content=content, headers=headers)
    assert "authorization" not in request.headers  # the cookie alone signs this request in
    assert "soc_session" in request.headers["cookie"]
    assert ("content-type" in request.headers) is (content_type is not None)
    return client.send(request)


def _victim_calls(victim: str) -> dict[str, tuple[str, str, str]]:
    return {
        "create": ("POST", "/api/admin/users", _create_text()),
        "update": ("PATCH", f"/api/admin/users/{victim}", '{"role": "admin"}'),
        "reset": (
            "POST",
            f"/api/admin/users/{victim}/password",
            json.dumps({"password": NEW_PASSWORD}),
        ),
        "unlock": ("POST", f"/api/admin/users/{victim}/unlock", "{}"),
    }


@pytest.mark.parametrize("call", ["create", "update", "reset", "unlock"])
def test_a_request_with_no_content_type_is_refused_even_when_the_cookie_signs_it_in(
    client, sdb, call
):
    """The `soc_session` cookie authenticates a request from any page on the same host, and a
    no-cors `fetch` with a Blob body sends no Content-Type. FastAPI's own parsing refuses that
    shape; this module reads bodies itself, so it must refuse it too — on every route that
    changes something, `unlock` (which has no body to speak of) included."""
    _cookie_session(client, sdb)
    _, victim = _seed(sdb, "tier1")
    sdb.execute("UPDATE users SET failed_logins = 4 WHERE user_id = %s", (victim,))
    sdb.commit()
    (hash_before,) = sdb.execute(
        "SELECT password_hash FROM users WHERE user_id = %s", (victim,)
    ).fetchone()
    sdb.rollback()
    created = _count_events(sdb, "admin.user_created")
    updated = _count_events(sdb, "admin.user_updated")
    method, path, content = _victim_calls(victim)[call]

    refused = _raw(client, method, path, content, None)

    assert refused.status_code == 422, refused.text
    assert refused.json()["detail"] == BODY_INVALID
    assert _count_events(sdb, "admin.user_created") == created
    assert _count_events(sdb, "admin.user_updated") == updated
    row = _row(sdb, victim)
    assert (row["role"], row["failed_logins"], row["sessions_ended"]) == ("tier1", 4, False)
    (hash_after,) = sdb.execute(
        "SELECT password_hash FROM users WHERE user_id = %s", (victim,)
    ).fetchone()
    assert hash_after == hash_before
    # the same request with the type is the one that goes through: the cookie did sign it in
    accepted = _raw(client, method, path, content, "application/json")
    assert accepted.status_code == {"create": 201, "update": 200}.get(call, 204), accepted.text


@pytest.mark.parametrize("content_type", ["application/x-www-form-urlencoded", "text/plain", None])
def test_unlock_refuses_a_form_post_and_a_post_with_no_type(client, sdb, content_type):
    _cookie_session(client, sdb)
    _, victim = _seed(sdb, "tier1")
    sdb.execute("UPDATE users SET failed_logins = 4 WHERE user_id = %s", (victim,))
    sdb.commit()
    path = f"/api/admin/users/{victim}/unlock"
    refused = _raw(client, "POST", path, "", content_type)
    assert refused.status_code == 422 and refused.json()["detail"] == BODY_INVALID
    assert _row(sdb, victim)["failed_logins"] == 4
    assert _events(sdb, "admin.user_updated", victim) == []


@pytest.mark.parametrize(
    ("content", "status"),
    [("", 204), ("{}", 204), ("  \n", 204), ('{"role": "admin"}', 422), ("[]", 422), ("null", 422)],
    ids=["empty", "empty-object", "blank", "unknown-key", "array", "null"],
)
def test_unlock_takes_an_empty_body_or_an_empty_object_with_the_json_type(
    client, sdb, content, status
):
    _, _, headers = _admin(client, sdb)
    _, victim = _seed(sdb, "tier1")
    response = client.post(
        f"/api/admin/users/{victim}/unlock",
        headers={**headers, "Content-Type": "application/json"},
        content=content,
    )
    assert response.status_code == status, response.text
    if status == 422:
        assert response.json()["detail"] == BODY_INVALID


@pytest.mark.parametrize(
    ("content_type", "accepted"),
    [
        ("application/json", True),
        ("application/json; charset=utf-8", True),
        ("Application/JSON", True),
        ("application/merge-patch+json", True),
        ("application/vnd.api+json", True),
        ("text/json", False),
        ("application/jsonp", False),
        ("application/x-json", False),
        ("multipart/form-data; boundary=x", False),
    ],
)
def test_only_application_json_and_application_plus_json_are_a_json_body(
    client, sdb, content_type, accepted
):
    _, _, headers = _admin(client, sdb)
    _, victim = _seed(sdb, "tier1")
    response = client.patch(
        f"/api/admin/users/{victim}",
        headers={**headers, "Content-Type": content_type},
        content='{"display_name": "P11-T02 u"}',  # the current name: nothing is written
    )
    assert response.status_code == (200 if accepted else 422), response.text


# --------------------------------------------------------------------------
# update
# --------------------------------------------------------------------------


def test_a_role_change_writes_before_and_after_and_ends_the_users_sessions(client, sdb):
    _, admin_id, headers = _admin(client, sdb)
    username, user_id = _seed(sdb, "tier1")
    user_headers = _login(client, username)
    response = client.patch(f"/api/admin/users/{user_id}", headers=headers, json={"role": "tier2"})
    assert response.status_code == 200, response.text
    assert response.json()["role"] == "tier2"
    [(actor_id, actor_role, payload)] = _events(sdb, "admin.user_updated", user_id)
    assert (actor_id, actor_role) == (admin_id, "admin")
    assert payload == {
        "username": username,
        "before": {"role": "tier1"},
        "after": {"role": "tier2"},
    }
    assert not _alive(client, user_headers)
    assert _alive(client, _login(client, username))


def test_a_promotion_to_admin_ends_the_sessions_too(client, sdb):
    _, _, headers = _admin(client, sdb)
    username, user_id = _seed(sdb, "tier2")
    user_headers = _login(client, username)
    response = client.patch(f"/api/admin/users/{user_id}", headers=headers, json={"role": "admin"})
    assert response.status_code == 200 and response.json()["role"] == "admin"
    assert not _alive(client, user_headers)
    assert client.get("/api/admin/users", headers=_login(client, username)).status_code == 200


def test_the_answer_is_the_whole_user_row_and_no_credential(client, sdb):
    _, _, headers = _admin(client, sdb)
    username, user_id = _seed(sdb, "tier1")
    response = client.patch(
        f"/api/admin/users/{user_id}", headers=headers, json={"display_name": "Row Shape"}
    )
    unchanged = client.patch(
        f"/api/admin/users/{user_id}", headers=headers, json={"display_name": "Row Shape"}
    )  # the same value again: the row is read, not written
    for answer in (response, unchanged):
        _assert_no_credential(answer)
        row = answer.json()
        assert set(row) == USER_ROW_KEYS
        assert row["user_id"] == user_id and row["username"] == username
        assert row["display_name"] == "Row Shape"


def test_deactivating_ends_the_sessions_and_reactivating_lets_the_user_back(client, sdb):
    _, _, headers = _admin(client, sdb)
    username, user_id = _seed(sdb, "tier2")
    user_headers = _login(client, username)
    off = client.patch(f"/api/admin/users/{user_id}", headers=headers, json={"is_active": False})
    assert off.status_code == 200 and off.json()["is_active"] is False
    assert not _alive(client, user_headers)
    login = {"username": username, "password": PASSWORD}
    assert client.post("/api/auth/login", json=login).status_code == 401
    [(_, _, payload)] = _events(sdb, "admin.user_updated", user_id)
    assert payload["before"] == {"is_active": True} and payload["after"] == {"is_active": False}
    on = client.patch(f"/api/admin/users/{user_id}", headers=headers, json={"is_active": True})
    assert on.status_code == 200 and on.json()["is_active"] is True
    assert _alive(client, _login(client, username))


def test_a_combined_change_records_each_changed_field_and_only_those(client, sdb):
    _, _, headers = _admin(client, sdb)
    username, user_id = _seed(sdb, "tier1")
    same_name = "P11-T02 u"  # the seeded display name: sent again, it is not a change
    response = client.patch(
        f"/api/admin/users/{user_id}",
        headers=headers,
        json={"role": "tier2", "display_name": same_name, "is_active": True},
    )
    assert response.status_code == 200
    [(_, _, payload)] = _events(sdb, "admin.user_updated", user_id)
    assert payload == {
        "username": username,
        "before": {"role": "tier1"},
        "after": {"role": "tier2"},
    }


def test_a_display_name_change_keeps_the_sessions_and_records_only_that_field(client, sdb):
    _, _, headers = _admin(client, sdb)
    username, user_id = _seed(sdb, "tier1")
    user_headers = _login(client, username)
    response = client.patch(
        f"/api/admin/users/{user_id}", headers=headers, json={"display_name": "  Lê Tuấn  "}
    )
    assert response.status_code == 200 and response.json()["display_name"] == "Lê Tuấn"
    assert _alive(client, user_headers)
    assert _row(sdb, user_id)["sessions_ended"] is False
    [(_, _, payload)] = _events(sdb, "admin.user_updated", user_id)
    assert payload["before"].keys() == {"display_name"} == payload["after"].keys()
    assert payload["after"] == {"display_name": "Lê Tuấn"}


@pytest.mark.parametrize(
    "body", [{"role": "tier1"}, {"is_active": True}, {"display_name": "P11-T02 u"}]
)
def test_a_value_equal_to_the_current_one_changes_nothing_and_writes_nothing(client, sdb, body):
    _, _, headers = _admin(client, sdb)
    username, user_id = _seed(sdb, "tier1")
    user_headers = _login(client, username)
    response = client.patch(f"/api/admin/users/{user_id}", headers=headers, json=body)
    assert response.status_code == 200
    assert _events(sdb, "admin.user_updated", user_id) == []
    assert _row(sdb, user_id)["sessions_ended"] is False
    assert _alive(client, user_headers)


@pytest.mark.parametrize("body", [{"role": "tier2"}, {"is_active": False}])
def test_an_admin_cannot_change_their_own_role_or_active_flag(client, sdb, body):
    _, admin_id, headers = _admin(client, sdb)
    response = client.patch(f"/api/admin/users/{admin_id}", headers=headers, json=body)
    assert response.status_code == 409
    assert response.json()["detail"] == {"reason": "self_change"}
    assert _alive(client, headers)
    assert _events(sdb, "admin.user_updated", admin_id) == []
    assert _row(sdb, admin_id)["role"] == "admin" and _row(sdb, admin_id)["is_active"]


def test_the_self_guard_answers_even_when_the_actor_is_the_only_admin(client, sdb):
    _, admin_id, headers = _admin(client, sdb)
    _only_these_admins_active(sdb, {admin_id})
    response = client.patch(f"/api/admin/users/{admin_id}", headers=headers, json={"role": "tier1"})
    assert response.status_code == 409
    assert response.json()["detail"] == {"reason": "self_change"}


def test_a_self_change_refuses_the_whole_request_including_a_harmless_field(client, sdb):
    _, admin_id, headers = _admin(client, sdb)
    response = client.patch(
        f"/api/admin/users/{admin_id}",
        headers=headers,
        json={"display_name": "Should Not Land", "role": "tier2"},
    )
    assert response.status_code == 409
    assert _row(sdb, admin_id)["display_name"] != "Should Not Land"


def test_an_admin_naming_their_own_current_values_is_not_a_self_change(client, sdb):
    _, admin_id, headers = _admin(client, sdb)
    response = client.patch(
        f"/api/admin/users/{admin_id}",
        headers=headers,
        json={"role": "admin", "is_active": True},
    )
    assert response.status_code == 200
    assert _events(sdb, "admin.user_updated", admin_id) == []
    assert _alive(client, headers)  # and the sessions stand


def test_an_admin_may_change_their_own_display_name(client, sdb):
    _, admin_id, headers = _admin(client, sdb)
    response = client.patch(
        f"/api/admin/users/{admin_id}", headers=headers, json={"display_name": "Tôi"}
    )
    assert response.status_code == 200 and _alive(client, headers)
    assert _row(sdb, admin_id)["display_name"] == "Tôi"


@pytest.mark.parametrize(
    ("body", "detail"),
    [
        ({}, {"reason": "empty"}),
        ({"role": "root"}, {"field": "role", "reason": "invalid"}),
        ({"role": None}, {"field": "role", "reason": "empty"}),
        ({"display_name": ""}, {"field": "display_name", "reason": "empty"}),
        ({"display_name": "x" * 101}, {"field": "display_name", "reason": "too_long", "max": 100}),
        ({"display_name": 5}, {"field": "display_name", "reason": "invalid"}),
        ({"is_active": "false"}, {"field": "is_active", "reason": "invalid"}),
        ({"is_active": 0}, {"field": "is_active", "reason": "invalid"}),
        ({"username": "someone-else"}, {"field": "body", "reason": "invalid"}),
        ({"role": "tier2", "password": "hunter2hunter2"}, {"field": "body", "reason": "invalid"}),
    ],
    ids=lambda v: json.dumps(v)[:30],
)
def test_update_validates_its_body(client, sdb, body, detail):
    _, _, headers = _admin(client, sdb)
    _, user_id = _seed(sdb, "tier1")
    response = client.patch(f"/api/admin/users/{user_id}", headers=headers, json=body)
    assert response.status_code == 422
    assert response.json()["detail"] == detail
    assert "hunter2" not in response.text
    assert _events(sdb, "admin.user_updated", user_id) == []


def test_unknown_and_malformed_ids(client, sdb):
    _, _, headers = _admin(client, sdb)
    unknown = str(uuid.uuid4())
    patch = client.patch(f"/api/admin/users/{unknown}", headers=headers, json={"role": "tier1"})
    assert patch.status_code == 404 and patch.json()["detail"] == {"reason": "not_found"}
    assert _unlock(client, headers, unknown).status_code == 404
    reset = client.post(
        f"/api/admin/users/{unknown}/password", headers=headers, json={"password": NEW_PASSWORD}
    )
    assert reset.status_code == 404
    for path in ("not-a-uuid", "123", "00000000-0000-0000-0000-00000000000g"):
        call = client.patch(f"/api/admin/users/{path}", headers=headers, json={"role": "tier1"})
        assert call.status_code == 422, path
        assert _unlock(client, headers, path).status_code == 422
    assert _events(sdb, "admin.user_updated", unknown) == []


# --------------------------------------------------------------------------
# the last-admin guard
# --------------------------------------------------------------------------


@pytest.mark.parametrize("changes", [{"role": "tier2"}, {"is_active": False}])
def test_the_only_active_admin_cannot_be_demoted_or_deactivated(dsn, sdb, changes):
    """The count, apart from the lock: one active admin, and an actor who is not that admin (the
    route can never send this — an actor is an active admin — so the call is direct)."""
    _, a_id = _seed(sdb, "admin", prefix="sole")
    _only_these_admins_active(sdb, {a_id})
    with _connect(dsn) as conn, pytest.raises(admin_users.UserConflict) as exc:
        admin_users.update_user(conn, actor_id=str(uuid.uuid4()), target_id=a_id, changes=changes)
    assert exc.value.reason == "last_active_admin"
    assert _row(sdb, a_id)["role"] == "admin" and _row(sdb, a_id)["is_active"]
    assert _events(sdb, "admin.user_updated", a_id) == []


def test_demoting_an_inactive_admin_is_not_removing_an_active_one(client, sdb):
    _, a_id, headers = _admin(client, sdb)
    _, b_id = _seed(sdb, "admin", prefix="idle")
    _only_these_admins_active(sdb, {a_id})  # B is inactive; A is the only active admin
    response = client.patch(f"/api/admin/users/{b_id}", headers=headers, json={"role": "tier1"})
    assert response.status_code == 200 and response.json()["role"] == "tier1"
    assert _active_admins(sdb) == 1


def test_two_admins_demoting_each_other_at_once_leave_one_admin(dsn, sdb):
    """A demotes B while B demotes A. Each request alone is fine (the other admin remains);
    together they would leave no admin. The guard locks the active admins first, so B waits
    for A's commit, then sees that A is the last one."""
    _, a_id = _seed(sdb, "admin", prefix="race-a")
    _, b_id = _seed(sdb, "admin", prefix="race-b")
    _only_these_admins_active(sdb, {a_id, b_id})

    conn_a, conn_b = _connect(dsn), _connect(dsn)
    try:
        # A's call has run and holds its locks; its transaction is open.
        admin_users.update_user(conn_a, actor_id=a_id, target_id=b_id, changes={"role": "tier1"})

        def b_demotes_a():
            try:
                admin_users.update_user(
                    conn_b, actor_id=b_id, target_id=a_id, changes={"role": "tier1"}
                )
                conn_b.commit()
            except BaseException:
                conn_b.rollback()
                raise

        thread, box = _in_thread(b_demotes_a)
        thread.join(timeout=1.0)
        assert thread.is_alive(), "B did not wait for A's lock: the admin rows were not locked"
        conn_a.commit()
        thread.join(timeout=15.0)
        assert not thread.is_alive()
    finally:
        conn_a.close()
        conn_b.close()
    assert isinstance(box.get("error"), admin_users.UserConflict), box
    assert box["error"].reason == "last_active_admin"
    assert _active_admins(sdb) == 1
    assert _row(sdb, b_id)["role"] == "tier1" and _row(sdb, a_id)["role"] == "admin"
    # the refused call wrote nothing: one event, A's
    assert len(_events(sdb, "admin.user_updated", b_id)) == 1
    assert _events(sdb, "admin.user_updated", a_id) == []


def test_three_admins_demoting_in_a_ring_always_leave_one(dsn, sdb):
    """A demotes B, B demotes C, C demotes A — all at once. Whichever of the last two goes first
    succeeds; the other finds one admin left. Either order, one admin remains."""
    _, a_id = _seed(sdb, "admin", prefix="ring-a")
    _, b_id = _seed(sdb, "admin", prefix="ring-b")
    _, c_id = _seed(sdb, "admin", prefix="ring-c")
    _only_these_admins_active(sdb, {a_id, b_id, c_id})

    conns = {name: _connect(dsn) for name in "abc"}

    def demote(actor: str, target: str, by: str):
        def call():
            try:
                admin_users.update_user(
                    conns[by], actor_id=actor, target_id=target, changes={"role": "tier1"}
                )
                conns[by].commit()
            except BaseException:
                conns[by].rollback()
                raise

        return call

    try:
        admin_users.update_user(
            conns["a"], actor_id=a_id, target_id=b_id, changes={"role": "tier1"}
        )
        t_bc, box_bc = _in_thread(demote(b_id, c_id, "b"))
        t_ca, box_ca = _in_thread(demote(c_id, a_id, "c"))
        t_bc.join(timeout=1.0)
        t_ca.join(timeout=1.0)
        assert t_bc.is_alive() and t_ca.is_alive(), "the ring did not wait on A's locks"
        conns["a"].commit()
        t_bc.join(timeout=15.0)
        t_ca.join(timeout=15.0)
        assert not t_bc.is_alive() and not t_ca.is_alive()
    finally:
        for conn in conns.values():
            conn.close()
    outcomes = [box.get("error") for box in (box_bc, box_ca)]
    refused = [e for e in outcomes if isinstance(e, admin_users.UserConflict)]
    assert len(refused) == 1 and refused[0].reason == "last_active_admin", outcomes
    assert outcomes.count(None) == 1  # the other one went through
    assert _active_admins(sdb) == 1


def test_deactivating_the_last_active_admin_is_refused_once_the_other_one_is_gone(dsn, sdb):
    """The `is_active` half of the guard, in sequence (the races above are on `role`): A has
    deactivated B and committed; B's own call on A must then find A the last one."""
    _, a_id = _seed(sdb, "admin", prefix="race-c")
    _, b_id = _seed(sdb, "admin", prefix="race-d")
    _only_these_admins_active(sdb, {a_id, b_id})
    with _connect(dsn) as conn_a, _connect(dsn) as conn_b:
        admin_users.update_user(conn_a, actor_id=a_id, target_id=b_id, changes={"is_active": False})
        conn_a.commit()
        with pytest.raises(admin_users.UserConflict) as exc:
            admin_users.update_user(
                conn_b, actor_id=b_id, target_id=a_id, changes={"is_active": False}
            )
        assert exc.value.reason == "last_active_admin"
    assert _active_admins(sdb) == 1


@pytest.mark.parametrize("change", ["role", "password"])
def test_the_sessions_end_at_the_moment_of_the_change_not_at_the_start_of_its_transaction(
    dsn, client, sdb, change
):
    """`now()` is frozen when the transaction begins; a change that waits on the admin locks
    would then stamp a moment before a login that happened during the wait, and that token would
    outlive the demotion (or the reset). The stamp is `clock_timestamp()`."""
    _, admin_id = _seed(sdb, "admin", prefix="clock")
    username, user_id = _seed(sdb, "tier1")
    conn = _connect(dsn)
    try:
        conn.execute("SELECT 1")  # the transaction begins here
        time.sleep(0.05)
        token = _login(client, username)  # issued after it began
        if change == "role":
            admin_users.update_user(
                conn, actor_id=admin_id, target_id=user_id, changes={"role": "tier2"}
            )
        else:
            assert auth.admin_set_password(conn, user_id, NEW_PASSWORD) == username
        conn.commit()
    finally:
        conn.close()
    assert not _alive(client, token)


# --------------------------------------------------------------------------
# password reset, unlock
# --------------------------------------------------------------------------


def test_a_password_reset_sets_the_new_one_ends_the_sessions_and_leaks_nowhere(client, sdb, caplog):
    _, admin_id, headers = _admin(client, sdb)
    username, user_id = _seed(sdb, "tier1")
    user_headers = _login(client, username)
    caplog.set_level(logging.DEBUG)
    response = client.post(
        f"/api/admin/users/{user_id}/password", headers=headers, json={"password": NEW_PASSWORD}
    )
    assert response.status_code == 204 and response.content == b""
    assert not _alive(client, user_headers)
    login = {"username": username, "password": PASSWORD}
    assert client.post("/api/auth/login", json=login).status_code == 401
    assert _alive(client, _login(client, username, NEW_PASSWORD))
    [(actor_id, actor_role, payload)] = _events(sdb, "admin.user_updated", user_id)
    assert (actor_id, actor_role) == (admin_id, "admin")
    assert payload == {"username": username, "action": "password_reset"}
    assert NEW_PASSWORD not in caplog.text and PASSWORD not in caplog.text
    # no audit row anywhere holds either password
    for secret in (NEW_PASSWORD, PASSWORD):
        (found,) = sdb.execute(
            "SELECT count(*) FROM audit_events WHERE strpos(payload::text, %s) > 0", (secret,)
        ).fetchone()
        assert found == 0
    # the stored value is a hash, and it is the new password's
    (stored,) = sdb.execute(
        "SELECT password_hash FROM users WHERE user_id = %s", (user_id,)
    ).fetchone()
    assert stored.startswith("$argon2") and NEW_PASSWORD not in stored


def test_no_request_of_this_module_logs_a_password(client, sdb, caplog):
    _, _, headers = _admin(client, sdb)
    caplog.set_level(logging.DEBUG)
    body = _new_body(password="log-me-not-12345")
    created = client.post("/api/admin/users", headers=headers, json=body)
    assert created.status_code == 201
    user_id = created.json()["user_id"]
    short = client.post(
        f"/api/admin/users/{user_id}/password", headers=headers, json={"password": "log-me-no"}
    )
    assert short.status_code == 422
    reset = client.post(
        f"/api/admin/users/{user_id}/password",
        headers=headers,
        json={"password": "log-me-not-67890"},
    )
    assert reset.status_code == 204
    assert "log-me-no" not in caplog.text


def test_a_password_reset_refuses_a_bad_password(client, sdb):
    _, _, headers = _admin(client, sdb)
    username, user_id = _seed(sdb, "tier1")
    cases = [
        ({"password": "short"}, {"field": "password", "reason": "too_short", "min": 12}),
        ({"password": "x" * 257}, {"field": "password", "reason": "too_long", "max": 256}),
        ({"password": 7}, {"field": "password", "reason": "invalid"}),
        ({}, {"field": "password", "reason": "empty"}),
        ({"password": NEW_PASSWORD, "role": "admin"}, {"field": "body", "reason": "invalid"}),
    ]
    for body, detail in cases:
        response = client.post(f"/api/admin/users/{user_id}/password", headers=headers, json=body)
        assert response.status_code == 422, body
        assert response.json()["detail"] == detail
        assert "short" not in response.text.replace("too_short", "")
    assert _alive(client, _login(client, username))  # the old password still works
    assert _events(sdb, "admin.user_updated", user_id) == []


def test_an_admin_may_reset_their_own_password_which_ends_their_own_session(client, sdb):
    username, admin_id, headers = _admin(client, sdb)
    response = client.post(
        f"/api/admin/users/{admin_id}/password", headers=headers, json={"password": NEW_PASSWORD}
    )
    assert response.status_code == 204
    assert not _alive(client, headers)
    assert _alive(client, _login(client, username, NEW_PASSWORD))


def test_a_password_can_be_reset_for_an_inactive_account(client, sdb):
    _, _, headers = _admin(client, sdb)
    username, user_id = _seed(sdb, "tier2")
    off = client.patch(f"/api/admin/users/{user_id}", headers=headers, json={"is_active": False})
    assert off.status_code == 200
    response = client.post(
        f"/api/admin/users/{user_id}/password", headers=headers, json={"password": NEW_PASSWORD}
    )
    assert response.status_code == 204
    client.patch(f"/api/admin/users/{user_id}", headers=headers, json={"is_active": True})
    assert _alive(client, _login(client, username, NEW_PASSWORD))


def test_unlock_clears_the_counter_and_the_lock(client, sdb):
    _, admin_id, headers = _admin(client, sdb)
    username, user_id = _seed(sdb, "tier1")
    sdb.execute(
        "UPDATE users SET failed_logins = 5, locked_until = now() + interval '15 minutes' "
        "WHERE user_id = %s",
        (user_id,),
    )
    sdb.commit()
    login = {"username": username, "password": PASSWORD}
    assert client.post("/api/auth/login", json=login).status_code == 423
    response = _unlock(client, headers, user_id)
    assert response.status_code == 204 and response.content == b""
    sdb.rollback()
    assert sdb.execute(
        "SELECT failed_logins, locked_until FROM users WHERE user_id = %s", (user_id,)
    ).fetchone() == (0, None)
    [(actor_id, actor_role, payload)] = _events(sdb, "admin.user_updated", user_id)
    assert (actor_id, actor_role) == (admin_id, "admin")
    assert payload == {"username": username, "action": "unlock"}
    assert _alive(client, _login(client, username))


def test_unlock_touches_only_the_lock_columns(client, sdb):
    _, _, headers = _admin(client, sdb)
    username, user_id = _seed(sdb, "tier2")
    user_headers = _login(client, username)
    response = _unlock(client, headers, user_id)
    assert response.status_code == 204
    assert _alive(client, user_headers)  # no session ended
    assert _row(sdb, user_id)["sessions_ended"] is False


# --------------------------------------------------------------------------
# admin only
# --------------------------------------------------------------------------


def _every_call(target: str) -> list[tuple[str, str, dict | None]]:
    return [
        ("get", "/api/admin/users", None),
        ("post", "/api/admin/users", _new_body()),
        ("patch", f"/api/admin/users/{target}", {"role": "admin"}),
        ("post", f"/api/admin/users/{target}/password", {"password": NEW_PASSWORD}),
        ("post", f"/api/admin/users/{target}/unlock", {}),
    ]


@pytest.mark.parametrize("role", ["tier1", "tier2"])
def test_every_users_route_refuses_a_non_admin_and_records_it(client, sdb, role):
    _, _, admin_headers = _admin(client, sdb)
    username, user_id = _seed(sdb, role)
    headers = _login(client, username)
    _, victim = _seed(sdb, "tier1")
    before = client.get("/api/admin/users", headers=admin_headers).json()["users"]
    for method, path, body in _every_call(victim):
        kwargs = {"headers": headers}
        if body is not None:
            kwargs["json"] = body
        response = getattr(client, method)(path, **kwargs)
        assert response.status_code == 403, (method, path)
        assert response.json() == {"detail": "forbidden"}
        assert _events(sdb, "authz.denied", path)[-1][:2] == (user_id, "analyst")
    # a refused call changed nothing: the victim is as seeded and no user was added
    assert _row(sdb, victim)["role"] == "tier1" and _row(sdb, victim)["sessions_ended"] is False
    assert client.get("/api/admin/users", headers=admin_headers).json()["users"] == before


def test_every_users_route_answers_401_without_a_token(client):
    for method, path, body in _every_call(str(uuid.uuid4())):
        kwargs = {} if body is None else {"json": body}
        assert getattr(client, method)(path, **kwargs).status_code == 401, (method, path)


# --------------------------------------------------------------------------
# infra/auth.create_user: the actor
# --------------------------------------------------------------------------


def test_create_user_signs_its_audit_row_with_an_actor_only_when_given_one(sdb):
    _, admin_id = _seed(sdb, "admin", prefix="signer")
    web = auth.create_user(
        sdb,
        username=f"p11t02-web-{uuid.uuid4().hex[:8]}",
        display_name="w",
        role="tier1",
        password=PASSWORD,
        actor_id=admin_id,
    )
    cli = auth.create_user(
        sdb,
        username=f"p11t02-cli-{uuid.uuid4().hex[:8]}",
        display_name="c",
        role="tier1",
        password=PASSWORD,
    )
    found = sdb.execute(
        "SELECT subject_id, actor_id::text, actor_role FROM audit_events "
        "WHERE event_type = 'admin.user_created' AND subject_id = ANY(%s)",
        ([web, cli],),
    ).fetchall()
    assert {subject: (actor, role) for subject, actor, role in found} == {
        web: (admin_id, "admin"),
        cli: (None, "system"),
    }
