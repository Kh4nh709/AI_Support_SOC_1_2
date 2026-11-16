"""Fake n8n approval webhook — a test double for the real n8n behind `N8N_APPROVAL_URL` (spec 2026-11-16 §3).

Do not import backend/app/** here: this is a test double, not an implementation.

It is an `httpx.MockTransport` handler, so the real client (`app/infra/n8n_approval.py`) runs end to end against it —
the request it builds, the answer it reads — with no socket. `FakeN8n.client_factory` is what the client takes
(`call(..., client_factory=fake.client_factory)`) and what the decision route's provider hands out in a route test.

    fake = FakeN8n()                      # answers 200 {"ok": true, "status": <what the decision means>}
    fake = FakeN8n(Reply.failed("GỠ THẤT BẠI: pfSense không trả lời"))    # a script: one reply per call, in order
    fake.calls                            # every request seen: Call(url, secret, content_type, body)

A script that runs out repeats its last reply. `Reply` builds the answers of the contract (`ok`, `failed`, `conflict`) and
the ones that are not (`http`, `text`, `timeout`, `network_error`).

`hold`: make the fake wait before it answers, to keep a decision "in flight" while a test does something else (a second
request, a webhook update). `fake.entered` is set when a request has arrived; the answer is sent when `fake.release()` is
called (or at once, if `hold` was never turned on). `fake.hold = True` turns the wait on.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

#: What a successful decision comes back as (spec §3).
STATUS_OF_DECISION = {"keep": "kept", "undo": "undone", "fp": "false_positive"}


@dataclass(frozen=True)
class Call:
    """One request the fake received."""

    url: str
    secret: str | None
    content_type: str | None
    body: dict[str, Any]
    timeout: dict[str, float | None] = field(default_factory=dict)


@dataclass(frozen=True)
class Reply:
    """One scripted answer. `status_code` and `content` are what goes on the wire; `raises` is raised instead."""

    status_code: int = 200
    content: bytes = b""
    raises: Exception | None = None

    @staticmethod
    def ok(status: str, result: str | None = "done", message: str | None = "Đã xử lý") -> Reply:
        body = {"ok": True, "status": status, "result": result, "message": message}
        return Reply(200, json.dumps(body).encode())

    @staticmethod
    def failed(
        message: str | None = "GỠ THẤT BẠI", result: str | None = None, status: str = "open"
    ) -> Reply:
        body = {"ok": False, "status": status, "result": result, "message": message}
        return Reply(200, json.dumps(body).encode())

    @staticmethod
    def conflict(status: str = "undone", message: str | None = "Đã xử lý ở nơi khác") -> Reply:
        body = {"ok": False, "status": status, "message": message}
        return Reply(409, json.dumps(body).encode())

    @staticmethod
    def http(status_code: int, content: bytes = b"") -> Reply:
        return Reply(status_code, content)

    @staticmethod
    def text(content: str, status_code: int = 200) -> Reply:
        return Reply(status_code, content.encode())

    @staticmethod
    def json_body(body: Any, status_code: int = 200) -> Reply:
        return Reply(status_code, json.dumps(body).encode())

    @staticmethod
    def timeout() -> Reply:
        return Reply(raises=httpx.ReadTimeout("read timed out"))

    @staticmethod
    def network_error(message: str = "connection refused") -> Reply:
        return Reply(raises=httpx.ConnectError(message))


class FakeN8n:
    """Records every call in `calls`; never touches the network. Thread-safe: a test may send two requests at once."""

    def __init__(self, *script: Reply, hold: bool = False) -> None:
        self._script = list(script)
        self._lock = threading.Lock()
        self.calls: list[Call] = []
        self.hold = hold
        self.entered = threading.Event()  # set when a request has arrived
        self._released = threading.Event()
        self.on_request: Callable[[Call], None] | None = (
            None  # a hook run before the answer (a test's side effect)
        )

    # ── the transport ───────────────────────────────────────────────────────────────────────

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        call = Call(
            url=str(request.url),
            secret=request.headers.get("x-soar-secret"),
            content_type=request.headers.get("content-type"),
            body=body,
            timeout=dict(request.extensions.get("timeout", {})),
        )
        with self._lock:
            index = len(self.calls)
            self.calls.append(call)
        self.entered.set()
        if self.on_request is not None:
            self.on_request(call)
        if self.hold:
            self._released.wait(timeout=30)
        reply = self._reply(index, body)
        if reply.raises is not None:
            raise reply.raises
        return httpx.Response(reply.status_code, content=reply.content)

    def _reply(self, index: int, body: dict[str, Any]) -> Reply:
        if not self._script:
            status = STATUS_OF_DECISION.get(body.get("decision", ""), "kept")
            return Reply.ok(status)
        return self._script[min(index, len(self._script) - 1)]

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def client_factory(self) -> httpx.Client:
        """What `n8n_approval.call(client_factory=...)` takes: a client whose transport is this fake."""
        return httpx.Client(transport=self.transport)

    # ── what a test does with it ────────────────────────────────────────────────────────────

    def release(self) -> None:
        """Let the answers that wait go out (and every later one go out at once)."""
        self._released.set()

    @property
    def secrets_seen(self) -> list[str | None]:
        return [call.secret for call in self.calls]
