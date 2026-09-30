"""P10-T05 — `GET /api/ws`, the real-time channel's socket, and the listener behind it.

The protocol under test (DEC-162):

1. the server accepts, then waits up to 5 s for `{"type":"auth","token":str}` — the token is
   the FIRST MESSAGE and nowhere else: never a URL, so it never reaches an access log;
2. close code 4401 when the token is missing, invalid, expired, or its user is inactive or
   logged out;
3. otherwise `{"type":"ready"}` and then hub messages;
4. the token is re-verified every 60 s and at `exp`; a failure closes 4401;
5. tier1, tier2 and admin may connect.

Two halves. The first needs no database: everything that must be refused BEFORE a lookup
(no message, a malformed message, a token in the URL) runs against a DSN nothing listens on,
so a socket that reached for the database anywhere on those paths would answer 1011, not
4401, and the test would go red. The second half commits real users and real alerts to a
scratch database of this module's own (`tests/scratch_db.py`) and marks every test `db`.

`TestClient.websocket_connect` blocks on `receive` with no timeout, so every wait goes
through `_within`: a missing close is a failed test, not a hung run.
"""

from __future__ import annotations

import asyncio
import dataclasses
import re
import threading
import time
import uuid

import psycopg
import pytest
import yaml
from app.infra import auth, config
from app.web import deps, live, main
from app.web.routers import live_ws
from fastapi.testclient import TestClient
from starlette.websockets import WebSocket, WebSocketDisconnect

from tests import conftest
from tests.scratch_db import insert_alert, scratch_database

SECRET = "test-secret-p10t05"
NOWHERE = "postgresql://nobody@127.0.0.1:9/nothing"  # port 9 (discard): nothing listens


def _cfg(dsn: str = NOWHERE, secret: str = SECRET) -> config.Config:
    return dataclasses.replace(config.Config(), JWT_SECRET=secret, DATABASE_URL=str(dsn))


def _within(seconds: float, fn):
    """`fn()` on a helper thread; a test failure, not a hang, if it does not return."""
    box: dict = {}

    def run():
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 — re-raised on the caller's thread
            box["error"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(seconds)
    if thread.is_alive():
        pytest.fail(f"nothing arrived within {seconds} s")
    if "error" in box:
        raise box["error"]
    return box["value"]


def _receive(ws, seconds: float = 5.0) -> dict:
    return _within(seconds, ws.receive_json)


def _close_code(ws, seconds: float = 5.0) -> int:
    with pytest.raises(WebSocketDisconnect) as info:
        _within(seconds, ws.receive_json)
    return info.value.code


def _claims(user_id: str, role: str = "tier1", *, ttl: float = 3600.0) -> auth.Claims:
    now = time.time()
    return auth.Claims(user_id=user_id, username="x", role=role, iat=now, exp=now + ttl)


def _token(user_id: str, role: str = "tier1", *, ttl: float = 3600.0, secret: str = SECRET) -> str:
    return auth.issue_token(_claims(user_id, role, ttl=ttl), _cfg(secret=secret))


@pytest.fixture
def fast(monkeypatch):
    """Short protocol clocks, and a hub that flushes in 20 ms instead of 500."""
    monkeypatch.setattr(live_ws, "AUTH_TIMEOUT_S", 0.1)
    monkeypatch.setattr(live, "HUB", live.Hub(coalesce_ms=20))
    return live.HUB


@pytest.fixture
def offline_client(monkeypatch):
    """The real app, `get_config` → a literal secret and a DSN nothing listens on."""
    main.app.dependency_overrides[deps.get_config] = lambda: _cfg()
    try:
        yield TestClient(main.app)
    finally:
        main.app.dependency_overrides.pop(deps.get_config, None)


# --------------------------------------------------------------------------------------
# Refused before any lookup — no database on this half
# --------------------------------------------------------------------------------------


def test_no_auth_message_closes_4401_after_timeout(offline_client, fast):
    with offline_client.websocket_connect("/api/ws") as ws:
        started = time.monotonic()
        assert _close_code(ws) == 4401
        assert time.monotonic() - started < 3  # the patched 0.1 s, not the default 5 s


def test_the_default_wait_for_the_auth_message_is_five_seconds():
    assert live_ws.AUTH_TIMEOUT_S == 5
    assert live_ws.REVERIFY_INTERVAL_S == 60


def test_every_uvicorn_launch_of_the_app_caps_the_websocket_frame_size():
    """`MAX_AUTH_MESSAGE_CHARS` is checked after uvicorn has read the whole frame, and
    uvicorn's own default cap is 16 MiB: an unauthenticated peer could make the server buffer
    that much per connection. Both launch sites — the compose `app` command and
    `make run-app-native` (`make run-app` is the compose one) — pass a small `--ws-max-size`,
    and it still fits the largest legal first frame (4 UTF-8 bytes per character)."""
    root = conftest.REPO_ROOT
    compose = yaml.safe_load((root / "docker-compose.yml").read_text())["services"]["app"]
    make_launches = [
        line
        for line in (root / "Makefile").read_text().splitlines()
        if "uvicorn app.web.main:app" in line
    ]
    assert len(make_launches) == 1, "Makefile: expected one uvicorn launch of the app"
    for site, command in {
        "docker-compose.yml": compose["command"],
        "Makefile": make_launches[0],
    }.items():
        found = re.findall(r"--ws-max-size[ =](\d+)", command)
        assert len(found) == 1, f"{site}: the uvicorn command has no --ws-max-size"
        assert 4 * live_ws.MAX_AUTH_MESSAGE_CHARS <= int(found[0]) <= 1024 * 1024, site


def test_token_in_query_string_is_ignored(offline_client, fast):
    """`?token=` alone gives 4401: the URL is never read. A URL ends up in access logs,
    proxies and browser history; the first message does not."""
    token = _token(str(uuid.uuid4()))
    headers = {"Authorization": f"Bearer {token}", "Cookie": f"soc_session={token}"}
    with offline_client.websocket_connect(f"/api/ws?token={token}", headers=headers) as ws:
        assert _close_code(ws) == 4401


@pytest.mark.parametrize(
    "first",
    [
        "not json at all",
        "[]",
        "null",
        '"a string"',
        "{}",
        '{"type":"hello"}',
        '{"type":"auth"}',
        '{"type":"auth","token":""}',
        '{"type":"auth","token":7}',
        '{"type":"auth","token":null}',
        '{"type":"auth","token":["a"]}',
        '{"token":"abc"}',
    ],
)
def test_a_malformed_first_message_closes_4401_without_a_lookup(offline_client, fast, first):
    with offline_client.websocket_connect("/api/ws") as ws:
        ws.send_text(first)
        assert _close_code(ws) == 4401  # 1011 here would mean a database was reached for


def test_a_binary_first_frame_closes_4401(offline_client, fast):
    with offline_client.websocket_connect("/api/ws") as ws:
        ws.send_bytes(b'{"type":"auth","token":"abc"}')
        assert _close_code(ws) == 4401


def test_an_oversized_first_message_closes_4401(offline_client, fast):
    with offline_client.websocket_connect("/api/ws") as ws:
        ws.send_text('{"type":"auth","token":"' + "a" * 100_000 + '"}')
        assert _close_code(ws) == 4401


def test_a_database_that_cannot_be_reached_closes_1011_not_4401(offline_client, fast):
    """An outage is not a logout: 4401 sends the browser to the login page, 1011 makes it
    retry. (The DSN is a port nothing listens on; the fixture never touches a live database.)"""
    with offline_client.websocket_connect("/api/ws") as ws:
        ws.send_json({"type": "auth", "token": _token(str(uuid.uuid4()))})
        assert _close_code(ws) == 1011


def test_no_secret_configured_closes_1011_never_lets_anyone_in(monkeypatch, fast):
    main.app.dependency_overrides[deps.get_config] = lambda: _cfg(secret="")
    try:
        with TestClient(main.app).websocket_connect("/api/ws") as ws:
            ws.send_json({"type": "auth", "token": "anything"})
            assert _close_code(ws) == 1011
    finally:
        main.app.dependency_overrides.pop(deps.get_config, None)


def test_lifespan_without_a_dsn_starts_no_listener_and_does_not_fail(monkeypatch, caplog):
    monkeypatch.setattr(config, "load", lambda **kwargs: _cfg(dsn=""))
    started: list = []

    async def never(hub, dsn):  # pragma: no cover — must not be called
        started.append(dsn)

    monkeypatch.setattr(live, "run_listener", never)
    with TestClient(main.app):
        pass
    assert started == []
    assert "DATABASE_URL" in caplog.text


# --------------------------------------------------------------------------------------
# The half that needs committed data — a scratch database of this module's own
# --------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def scratch_dsn():
    with scratch_database("ws") as dsn:
        yield dsn


@pytest.fixture
def sdb(scratch_dsn):
    conn = psycopg.connect(scratch_dsn)
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


@pytest.fixture
def committed_user(sdb):
    def make(role: str = "tier1") -> str:
        user_id = auth.create_user(
            sdb,
            username=f"p10t05-{uuid.uuid4().hex[:8]}",
            display_name="P10-T05",
            role=role,
            password="correct horse battery staple",
        )
        sdb.commit()
        return user_id

    return make


@pytest.fixture
def client(scratch_dsn, fast):
    main.app.dependency_overrides[deps.get_config] = lambda: _cfg(scratch_dsn)
    try:
        yield TestClient(main.app)
    finally:
        main.app.dependency_overrides.pop(deps.get_config, None)


@pytest.mark.db
@pytest.mark.parametrize("role", ["tier1", "tier2", "admin"])
def test_valid_token_gets_ready_then_hub_message(client, committed_user, fast, role):
    token = _token(committed_user(role), role)
    with client.websocket_connect("/api/ws") as ws:
        ws.send_json({"type": "auth", "token": token})
        assert _receive(ws) == {"type": "ready"}

        fast.publish("x")

        assert _receive(ws) == {"type": "alerts.changed", "ids": ["x"]}


@pytest.mark.db
def test_ready_means_subscribed_a_publish_right_after_it_is_never_lost(
    client, committed_user, fast
):
    """The browser refetches the queue on `ready`; anything after that must reach it."""
    token = _token(committed_user())
    for round_ in range(5):
        with client.websocket_connect("/api/ws") as ws:
            ws.send_json({"type": "auth", "token": token})
            assert _receive(ws) == {"type": "ready"}
            fast.publish(f"r{round_}")
            assert _receive(ws) == {"type": "alerts.changed", "ids": [f"r{round_}"]}


@pytest.mark.db
def test_the_subscription_exists_before_ready_is_sent(client, committed_user, fast, monkeypatch):
    """A publish made at the very moment `ready` goes out reaches the socket.

    The test above races the client against the server, so it would pass by luck if the
    subscription were taken just AFTER `ready`. Here the publish is made from inside the
    server's send of `ready`: only a subscription that already exists can receive it.
    """
    send_json = WebSocket.send_json

    async def send_json_publishing_on_ready(self, data, mode="text"):
        if data == {"type": "ready"}:
            fast.publish("at-ready")
        await send_json(self, data, mode)

    monkeypatch.setattr(WebSocket, "send_json", send_json_publishing_on_ready)
    token = _token(committed_user())
    with client.websocket_connect("/api/ws") as ws:
        ws.send_json({"type": "auth", "token": token})
        assert _receive(ws) == {"type": "ready"}
        assert _receive(ws) == {"type": "alerts.changed", "ids": ["at-ready"]}


@pytest.mark.db
def test_a_burst_of_publishes_reaches_the_socket_as_one_message(client, committed_user, fast):
    token = _token(committed_user())
    with client.websocket_connect("/api/ws") as ws:
        ws.send_json({"type": "auth", "token": token})
        assert _receive(ws) == {"type": "ready"}
        for i in range(50):
            fast.publish(f"b{i:02d}")
        message = _receive(ws)
        assert message["type"] == "alerts.changed" and len(message["ids"]) == 50


@pytest.mark.db
def test_a_valid_token_in_the_url_does_not_authenticate(client, committed_user):
    """A real user, a token that would verify, in the URL only: no first message, so 4401.

    The offline test proves the URL is not read while nothing can be looked up; this one
    proves it against a database where the lookup would succeed.
    """
    token = _token(committed_user())
    with client.websocket_connect(f"/api/ws?token={token}") as ws:
        assert _close_code(ws) == 4401


@pytest.mark.db
@pytest.mark.parametrize(
    "make_token",
    [
        pytest.param(lambda uid: "not-a-jwt", id="garbage"),
        pytest.param(lambda uid: _token(uid, secret="another-secret"), id="wrong-secret"),
        pytest.param(lambda uid: _token(uid, ttl=-10), id="expired"),
        pytest.param(lambda uid: _token(str(uuid.uuid4())), id="unknown-user"),
    ],
)
def test_bad_token_closes_4401(client, committed_user, make_token):
    token = make_token(committed_user())
    with client.websocket_connect("/api/ws") as ws:
        ws.send_json({"type": "auth", "token": token})
        assert _close_code(ws) == 4401


@pytest.mark.db
def test_a_deactivated_user_closes_4401(client, sdb, committed_user):
    user_id = committed_user()
    token = _token(user_id)
    sdb.execute("UPDATE users SET is_active = false WHERE user_id = %s", (user_id,))
    sdb.commit()
    with client.websocket_connect("/api/ws") as ws:
        ws.send_json({"type": "auth", "token": token})
        assert _close_code(ws) == 4401


@pytest.mark.db
def test_a_token_from_before_a_logout_closes_4401(client, sdb, committed_user):
    user_id = committed_user()
    token = _token(user_id)
    time.sleep(0.05)
    auth.logout(sdb, user_id)
    sdb.commit()
    with client.websocket_connect("/api/ws") as ws:
        ws.send_json({"type": "auth", "token": token})
        assert _close_code(ws) == 4401


@pytest.mark.db
def test_logout_closes_on_next_reverify(client, sdb, committed_user, monkeypatch):
    monkeypatch.setattr(live_ws, "REVERIFY_INTERVAL_S", 0.1)
    user_id = committed_user()
    token = _token(user_id)
    with client.websocket_connect("/api/ws") as ws:
        ws.send_json({"type": "auth", "token": token})
        assert _receive(ws) == {"type": "ready"}

        sdb.execute(
            "UPDATE users SET sessions_invalid_before = now() WHERE user_id = %s", (user_id,)
        )
        sdb.commit()

        assert _close_code(ws, seconds=5) == 4401


@pytest.mark.db
def test_deactivation_closes_on_next_reverify(client, sdb, committed_user, monkeypatch):
    monkeypatch.setattr(live_ws, "REVERIFY_INTERVAL_S", 0.1)
    user_id = committed_user()
    with client.websocket_connect("/api/ws") as ws:
        ws.send_json({"type": "auth", "token": _token(user_id)})
        assert _receive(ws) == {"type": "ready"}

        sdb.execute("UPDATE users SET is_active = false WHERE user_id = %s", (user_id,))
        sdb.commit()

        assert _close_code(ws) == 4401


@pytest.mark.db
def test_the_socket_closes_at_exp_without_waiting_for_the_next_interval(client, committed_user):
    """Re-verify is every 60 s AND at `exp`: a token that expires in 1.5 s must not live
    until the minute is up."""
    assert live_ws.REVERIFY_INTERVAL_S == 60
    token = _token(committed_user(), ttl=1.5)
    with client.websocket_connect("/api/ws") as ws:
        ws.send_json({"type": "auth", "token": token})
        assert _receive(ws) == {"type": "ready"}
        started = time.monotonic()

        assert _close_code(ws, seconds=8) == 4401
        assert time.monotonic() - started < 6


@pytest.mark.db
def test_a_valid_session_survives_many_reverifications(client, committed_user, fast, monkeypatch):
    monkeypatch.setattr(live_ws, "REVERIFY_INTERVAL_S", 0.05)
    token = _token(committed_user())
    with client.websocket_connect("/api/ws") as ws:
        ws.send_json({"type": "auth", "token": token})
        assert _receive(ws) == {"type": "ready"}
        time.sleep(0.6)  # a dozen re-verifications

        fast.publish("still-here")

        assert _receive(ws) == {"type": "alerts.changed", "ids": ["still-here"]}


@pytest.mark.db
def test_a_role_outside_the_allowed_set_closes_4403(client, committed_user, monkeypatch):
    monkeypatch.setattr(live_ws, "ALLOWED_ROLES", frozenset({"admin"}))
    token = _token(committed_user("tier1"))
    with client.websocket_connect("/api/ws") as ws:
        ws.send_json({"type": "auth", "token": token})
        assert _close_code(ws) == 4403


@pytest.mark.db
@pytest.mark.parametrize(
    ("row_role", "claim_role", "close_code"),
    [
        pytest.param("tier1", "admin", 4403, id="row-tier1-claim-admin"),
        pytest.param("admin", "tier1", None, id="row-admin-claim-tier1"),
    ],
)
def test_the_role_is_the_rows_not_the_tokens(
    client, committed_user, monkeypatch, row_role, claim_role, close_code
):
    """Only admin is allowed here, so the two roles differ in outcome: a token that claims
    admin over a tier1 row is refused, and a token that claims tier1 over an admin row is
    let in. (With all three roles allowed the test could not tell the row from the claim.)"""
    monkeypatch.setattr(live_ws, "ALLOWED_ROLES", frozenset({"admin"}))
    token = _token(committed_user(row_role), role=claim_role)
    with client.websocket_connect("/api/ws") as ws:
        ws.send_json({"type": "auth", "token": token})
        if close_code is None:
            assert _receive(ws) == {"type": "ready"}
        else:
            assert _close_code(ws) == close_code


@pytest.mark.db
def test_a_closed_socket_releases_its_subscription(client, committed_user, fast):
    token = _token(committed_user())
    for _ in range(3):
        with client.websocket_connect("/api/ws") as ws:
            ws.send_json({"type": "auth", "token": token})
            assert _receive(ws) == {"type": "ready"}
            assert fast.subscribers == 1
    deadline = time.monotonic() + 3
    while fast.subscribers and time.monotonic() < deadline:
        time.sleep(0.02)
    assert fast.subscribers == 0


@pytest.mark.db
def test_a_failed_login_never_subscribes(client, fast):
    with client.websocket_connect("/api/ws") as ws:
        ws.send_json({"type": "auth", "token": "not-a-jwt"})
        assert _close_code(ws) == 4401
    assert fast.subscribers == 0


# --------------------------------------------------------------------------------------
# run_listener against a real server: NOTIFY -> hub -> socket
# --------------------------------------------------------------------------------------

LISTENING = (
    "SELECT pid FROM pg_stat_activity WHERE datname = current_database() "
    "AND query = 'LISTEN alerts_changed' AND pid <> pg_backend_pid()"
)


async def _listener_pids(dsn) -> list[int]:
    async with await psycopg.AsyncConnection.connect(dsn, autocommit=True) as conn:
        cur = await conn.execute(LISTENING)
        return [row[0] for row in await cur.fetchall()]


async def _wait_for_listener(dsn, *, other_than: frozenset = frozenset(), seconds: float = 10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        pids = [p for p in await _listener_pids(dsn) if p not in other_than]
        if pids:
            return pids[0]
        await asyncio.sleep(0.05)
    raise AssertionError("the listener never issued LISTEN alerts_changed")


@pytest.mark.db
def test_listener_relays_a_committed_insert_to_the_hub(scratch_dsn, sdb):
    async def scenario():
        hub = live.Hub(coalesce_ms=20)
        sub = hub.subscribe()
        task = asyncio.create_task(live.run_listener(hub, scratch_dsn))
        try:
            await _wait_for_listener(scratch_dsn)
            insert_alert(sdb, "p10t05-listen-1")
            sdb.commit()
            message = await asyncio.wait_for(sub.next_message(), 5)
            assert message == {"type": "alerts.changed", "ids": ["p10t05-listen-1"]}
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(scenario())


@pytest.mark.db
def test_listener_coalesces_a_bulk_insert_into_one_message(scratch_dsn, sdb):
    async def scenario():
        hub = live.Hub(coalesce_ms=200)
        sub = hub.subscribe()
        task = asyncio.create_task(live.run_listener(hub, scratch_dsn))
        try:
            await _wait_for_listener(scratch_dsn)
            for i in range(30):
                insert_alert(sdb, f"p10t05-bulk-{i:02d}")
            sdb.commit()
            message = await asyncio.wait_for(sub.next_message(), 5)
            assert message["ids"] == [f"p10t05-bulk-{i:02d}" for i in range(30)]
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(sub.next_message(), 0.5)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(scenario())


@pytest.mark.db
def test_listener_ignores_a_notification_it_cannot_read_and_keeps_listening(scratch_dsn, sdb):
    async def scenario():
        hub = live.Hub(coalesce_ms=20)
        sub = hub.subscribe()
        task = asyncio.create_task(live.run_listener(hub, scratch_dsn))
        try:
            await _wait_for_listener(scratch_dsn)
            for payload in ("not json", "[]", '{"no_id": 1}', '{"alert_id": 5}'):
                sdb.execute("SELECT pg_notify('alerts_changed', %s)", (payload,))
            sdb.commit()
            insert_alert(sdb, "p10t05-after-junk")
            sdb.commit()
            message = await asyncio.wait_for(sub.next_message(), 5)
            assert message == {"type": "alerts.changed", "ids": ["p10t05-after-junk"]}
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(scenario())


@pytest.mark.db
def test_listener_reconnects_after_the_server_drops_it_and_says_many(scratch_dsn, sdb):
    """A LISTEN connection that dies loses whatever was sent meanwhile. After the reconnect
    the hub tells every socket to refetch (`many`), and new writes flow again."""

    async def scenario():
        hub = live.Hub(coalesce_ms=20)
        sub = hub.subscribe()
        task = asyncio.create_task(live.run_listener(hub, scratch_dsn))
        try:
            first = await _wait_for_listener(scratch_dsn)
            async with await psycopg.AsyncConnection.connect(scratch_dsn, autocommit=True) as admin:
                await admin.execute("SELECT pg_terminate_backend(%s)", (first,))

            message = await asyncio.wait_for(sub.next_message(), 10)
            assert message == {"type": "alerts.changed", "many": True}

            await _wait_for_listener(scratch_dsn, other_than=frozenset({first}))
            insert_alert(sdb, "p10t05-after-drop")
            sdb.commit()
            message = await asyncio.wait_for(sub.next_message(), 5)
            assert message == {"type": "alerts.changed", "ids": ["p10t05-after-drop"]}
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(scenario())


@pytest.mark.db
def test_the_first_connection_does_not_claim_it_missed_anything(scratch_dsn):
    async def scenario():
        hub = live.Hub(coalesce_ms=20)
        sub = hub.subscribe()
        task = asyncio.create_task(live.run_listener(hub, scratch_dsn))
        try:
            await _wait_for_listener(scratch_dsn)
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(sub.next_message(), 0.5)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(scenario())


@pytest.mark.db
def test_the_lifespan_starts_the_listener_and_a_commit_reaches_a_connected_socket(
    scratch_dsn, sdb, committed_user, fast, monkeypatch
):
    """The whole chain: an alert committed by the writer -> the trigger -> LISTEN -> the hub
    -> the browser's socket. The listener's DSN is this module's scratch database."""
    cfg = _cfg(scratch_dsn)
    monkeypatch.setattr(config, "load", lambda **kwargs: cfg)
    token = _token(committed_user())

    # Entering the TestClient context runs the app's lifespan, which starts the listener.
    with TestClient(main.app) as client, client.websocket_connect("/api/ws") as ws:
        ws.send_json({"type": "auth", "token": token})
        assert _receive(ws) == {"type": "ready"}
        asyncio.run(_wait_for_listener(scratch_dsn))

        insert_alert(sdb, "p10t05-e2e-1")
        sdb.commit()

        assert _receive(ws) == {"type": "alerts.changed", "ids": ["p10t05-e2e-1"]}

    # The lifespan's exit cancels the listener: its backend leaves the server.
    deadline = time.monotonic() + 5
    while asyncio.run(_listener_pids(scratch_dsn)) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert asyncio.run(_listener_pids(scratch_dsn)) == []
