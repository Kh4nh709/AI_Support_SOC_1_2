"""SR-T1 fix round 1 (I1) — the call to n8n is bounded as a WHOLE, whatever the server does.

`N8N_APPROVAL_TIMEOUT_SECONDS` (at most 100) is what a call may take, and the lock a press takes is released by the next press after
120 seconds: a call that outlived that would let a second person take over a live lock and n8n be asked twice for one decision. httpx
bounds each WAIT (connect; the response; each piece of the body) but not their sum, so a server that drips a byte at a time keeps a
call alive for ever. The reviewer measured, with a timeout of 3 s against a dripping server, 5.0 s (headers, then body) and 8.1 s (a
header drip with no upper bound).

These tests run the REAL client (`n8n_approval.call` with no `client_factory`) against a REAL local server (the standard library, on
127.0.0.1) that drips: at the connect, in the headers and in the body. Each must give `unavailable` / `timeout` within the timeout
plus a small margin (the Director's bound is the timeout plus 5 s), and the connection must be closed. Pure: no database, loopback only.
"""

from __future__ import annotations

import select
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import replace

import pytest
from app.infra import config, n8n_approval
from app.infra.config import Config
from app.soar import reviews

TIMEOUT_S = 2
#: What the Director allows over the timeout; the client is held to a tighter margin than that.
BOUND_S = TIMEOUT_S + 5
TIGHT_S = TIMEOUT_S + 1.0
#: How long the dripping servers go on: longer than the bound, so a client that is not bounded is plainly caught.
SERVER_LIFE_S = 12.0


class DrippingServer:
    """A server on 127.0.0.1 that reads the request and then drips for `SERVER_LIFE_S`: `body` sends the headers and drips the body
    (a `Content-Length` of 1 MB), `header` never ends the headers, `silent` never answers. `closed` is set when the client's
    connection is seen closed."""

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.closed = threading.Event()
        self.received = threading.Event()
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(5)
        self.port = self._listener.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/webhook/soar-approval"

    def _serve(self) -> None:
        self._listener.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except (TimeoutError, OSError):
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5)
            buffer = b""
            while b"\r\n\r\n" not in buffer:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buffer += chunk
            head, _, rest = buffer.partition(b"\r\n\r\n")
            length = 0
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    length = int(line.split(b":", 1)[1])
            while len(rest) < length:
                rest += conn.recv(4096)
            self.received.set()
            if self.mode == "body":
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000000\r\n\r\n"
                )
            elif self.mode == "header":
                conn.sendall(b"HTTP/1.1 200 OK\r\nX-Drip: ")
            deadline = time.monotonic() + SERVER_LIFE_S
            while time.monotonic() < deadline and not self._stop.is_set():
                readable, _, _ = select.select([conn], [], [], 0.25)
                if readable and conn.recv(4096) == b"":  # the client hung up
                    self.closed.set()
                    return
                if self.mode in ("body", "header"):
                    conn.sendall(b" " if self.mode == "body" else b"a")
        except OSError:
            self.closed.set()  # a send or a read failed: the peer is gone
        finally:
            conn.close()

    def close(self) -> None:
        self._stop.set()
        self._listener.close()


def _cfg(url: str, timeout: int = TIMEOUT_S) -> Config:
    return replace(
        Config(),
        N8N_APPROVAL_URL=url,
        N8N_APPROVAL_SECRET="s",
        N8N_APPROVAL_TIMEOUT_SECONDS=timeout,
    )


def _call(cfg: Config) -> tuple[n8n_approval.Answer, float]:
    started = time.monotonic()
    answer = n8n_approval.call(
        cfg, review_id="K7QM2XHP", decision="keep", user="a", user_role="admin"
    )
    return answer, time.monotonic() - started


@pytest.mark.parametrize("mode", ["body", "header", "silent"])
def test_a_dripping_or_silent_server_cannot_keep_the_call_past_the_timeout(mode):
    server = DrippingServer(mode)
    try:
        answer, elapsed = _call(_cfg(server.url))
        print(f"wall time, {mode} drip, timeout {TIMEOUT_S} s: {elapsed:.2f} s")
        assert server.received.is_set(), "the request never reached the server"
        assert (answer.outcome, answer.kind) == ("unavailable", "timeout"), (mode, answer)
        assert elapsed < BOUND_S, f"{mode}: the call took {elapsed:.2f} s (bound {BOUND_S} s)"
        assert (
            elapsed < TIGHT_S
        ), f"{mode}: the call took {elapsed:.2f} s over a timeout of {TIMEOUT_S} s"
        assert server.closed.wait(2.0), f"{mode}: the connection was not closed"
    finally:
        server.close()


def _blocked_connect() -> tuple[socket.socket, list[socket.socket], int] | None:
    """A listener whose accept queue is full, so a further connect hangs: the nearest a loopback test gets to a slow connect.
    `None` when this kernel does not behave so."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(0)
    port = listener.getsockname()[1]
    fillers: list[socket.socket] = []
    for _ in range(3):
        filler = socket.socket()
        filler.settimeout(0.3)
        try:
            filler.connect(("127.0.0.1", port))
        except OSError:
            pass
        fillers.append(filler)
    probe = socket.socket()
    probe.settimeout(0.5)
    try:
        probe.connect(("127.0.0.1", port))
    except OSError:
        probe.close()
        return listener, fillers, port
    probe.close()
    for filler in fillers:
        filler.close()
    listener.close()
    return None


def test_a_connect_that_never_completes_cannot_keep_the_call_past_the_timeout():
    blocked = _blocked_connect()
    if blocked is None:
        pytest.skip("this kernel completes a loopback connect even with a full accept queue")
    listener, fillers, port = blocked
    try:
        answer, elapsed = _call(_cfg(f"http://127.0.0.1:{port}/webhook/soar-approval"))
        print(f"wall time, connect that never completes, timeout {TIMEOUT_S} s: {elapsed:.2f} s")
        assert (answer.outcome, answer.kind) == ("unavailable", "timeout"), answer
        assert elapsed < BOUND_S and elapsed < TIGHT_S, f"the call took {elapsed:.2f} s"
    finally:
        for filler in fillers:
            filler.close()
        listener.close()


def test_a_name_that_never_resolves_cannot_keep_the_call_past_the_timeout(monkeypatch):
    """Name resolution is the operating system's and has no timeout of its own: it is bounded here, so the bound is of the whole call
    and not only of what comes after the address is known."""

    def never(*args, **kwargs):
        time.sleep(30)
        return []

    monkeypatch.setattr(socket, "getaddrinfo", never)
    answer, elapsed = _call(_cfg("http://n8n.never-resolves.test:5678/webhook/soar-approval"))
    assert (answer.outcome, answer.kind) == ("unavailable", "timeout"), answer
    assert elapsed < BOUND_S and elapsed < TIGHT_S, f"the call took {elapsed:.2f} s"


def test_a_name_that_does_not_exist_is_a_network_failure_not_a_timeout(monkeypatch):
    def refuse(*args, **kwargs):
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    answer, elapsed = _call(_cfg("http://no-such-host.test:5678/x"))
    assert (answer.outcome, answer.kind) == ("unavailable", "network")
    assert elapsed < 1.0


def test_a_server_that_answers_in_time_is_still_served_through_the_bounded_client():
    """The bound must not get in the way of a good answer: the real client, a real server, one piece."""

    class Good(DrippingServer):
        def _handle(self, conn: socket.socket) -> None:
            try:
                conn.settimeout(5)
                buffer = b""
                while b"\r\n\r\n" not in buffer:
                    buffer += conn.recv(4096)
                head, _, rest = buffer.partition(b"\r\n\r\n")
                length = int(
                    next(
                        line
                        for line in head.split(b"\r\n")
                        if line.lower().startswith(b"content-length")
                    ).split(b":")[1]
                )
                while len(rest) < length:
                    rest += conn.recv(4096)
                body = b'{"ok": true, "status": "kept", "message": "xong"}'
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s"
                    % (len(body), body)
                )
            finally:
                conn.close()

    server = Good("good")
    try:
        answer, elapsed = _call(_cfg(server.url))
    finally:
        server.close()
    assert (answer.outcome, answer.status, answer.message) == ("ok", "kept", "xong")
    assert elapsed < 1.0


def test_the_ceiling_plus_the_bound_plus_the_databases_share_is_under_the_stale_lock_threshold():
    """100 + 5 + 10 < 120: a live call, the lock before it and the finish after it always end before a lock may be taken over."""
    ceiling = config._N8N_TIMEOUT_MAX_S
    margin = n8n_approval.DEADLINE_MARGIN_S
    assert margin <= 5
    assert ceiling + margin + 10 < reviews.LOCK_STALE_SECONDS


@pytest.mark.parametrize(
    "build",
    [lambda: n8n_approval._build_client(time.monotonic() + 5, time.monotonic)],
    ids=["default"],
)
def test_the_default_client_is_closed_by_its_context_and_ignores_the_proxy_environment(
    build: Callable, monkeypatch
):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    server = DrippingServer("silent")
    try:
        with build() as client:
            with pytest.raises(
                Exception
            ):  # the deadline of 5 s is longer than the 0.5 s of the read below
                client.post(server.url, content=b"{}", timeout=0.5)
        assert (
            server.received.is_set()
        ), "the request went through a proxy instead of straight to the server"
    finally:
        server.close()
