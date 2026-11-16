"""`infra.n8n_approval` — the one call the web makes to n8n when a person presses a button (spec 2026-11-16 §3,
"Contract B"): `call(cfg, ...) -> Answer`.

    POST {N8N_APPROVAL_URL}
    X-SOAR-Secret: <N8N_APPROVAL_SECRET>      Content-Type: application/json
    {"source": "web", "review_id", "decision", "callback": "<decision>:<review_id>",
     "user", "user_role", "note", "requested_at"}

n8n answers one of four things, and the caller (`soar/reviews.py`) needs to tell them apart and nothing finer:

| n8n answers                                                           | `Answer.outcome` |
| --------------------------------------------------------------------- | ---------------- |
| `200 {"ok": true, "status": kept|undone|false_positive, ...}`          | `ok`             |
| `200 {"ok": false, ...}`: the action failed, the ticket keeps its state | `failed`         |
| `409 {"ok": false, "status", "message"}`: already handled elsewhere   | `conflict`       |
| `401`, `404`, `5xx`, any other code, a timeout, a network error, a body that is not this JSON, a `200 ok:true` whose `status` is not one of the three | `unavailable` |

`unavailable` is temporary by design: the ticket goes back to the state it had and the person may press again. Its
`message` is one of a few fixed sentences naming the kind (`timeout`, `network`, `http`, `bad_answer`), never text taken
from the exception or the answer.

**It never raises** (the contract of `infra/notify.py`, whose pattern this follows: a client built at the call site by an
injectable `client_factory`, so a test hands it an `httpx.Client` over a fake transport and no test touches the network).
Every exception is caught in one place and becomes `unavailable`.

**No secret in a log line, an exception text or an answer.** The secret is put in the request header and nowhere else; the
URL (whose query may carry a token) is never logged; the `except` logs only the exception's class name, never `str(exc)`,
because an `httpx` exception's message can contain the request URL. `httpx` itself logs every request's URL at INFO
(`httpx/_client.py`), which would put that URL in the root logger regardless of anything here, so its logger is raised to
WARNING at import, as `infra/notify.py` does. What is logged is the outcome, the status code and the duration.

**A deadline for the whole call.** `N8N_APPROVAL_TIMEOUT_SECONDS` (1..100, enforced by the configuration) is the time a call may
take, and a lock older than two minutes is released by the next press, so a live call that outlived it would make n8n be asked twice for
one decision. `httpx` bounds each WAIT (the connect, the response, each piece of the body) but not their sum: a server that drips a
byte at a time kept a call alive for ever (the reviewer measured 5 s, and 8 s with no upper bound, on a timeout of 3 s). The real client
therefore runs on a network backend (`_DeadlineBackend`) whose every wait, in the connect, the TLS handshake, the headers and the body,
is cut to the time remaining of the whole call, and whose name resolution is not waited for past it; the body is also read against the
deadline. The call returns `unavailable` / `timeout` within `DEADLINE_MARGIN_S` of the timeout and closes the connection. 100 + 5 is under
120. A test's `client_factory` replaces the client and, with it, this bound.

The answer's texts (`message`, `result`) are n8n's: stored and shown as text, cut at `MAX_TEXT`, never used to build
anything.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

import httpcore
import httpx

from app.infra.config import Config
from app.infra.storable import make_storable

logger = logging.getLogger(__name__)

# `httpx` logs the full URL of every request at INFO: see the module docstring.
logging.getLogger("httpx").setLevel(logging.WARNING)

#: The decisions of the page's buttons, and the statuses n8n may answer a successful one with.
DECISIONS = ("keep", "undo", "fp")
OK_STATUSES = ("kept", "undone", "false_positive")

#: The call returns no later than `N8N_APPROVAL_TIMEOUT_SECONDS` plus this many seconds, whatever the server does (a drip at the
#: connect, in the headers or in the body, a name that does not resolve). With the configuration's ceiling of 100 seconds that is 105,
#: under the 120 seconds after which a lock is released: a live call never looks like a stale lock.
DEADLINE_MARGIN_S = 5

#: A text of n8n's answer is cut to this many characters (the cap `soar/review_notice.py` puts on the texts n8n pushes).
MAX_TEXT = 2000
#: The answer is a few hundred bytes; one far larger is not this JSON.
MAX_BODY_BYTES = 64 * 1024
#: How long a connection may take to be made, so an address that does not answer is not waited for the whole timeout.
CONNECT_TIMEOUT_S = 10.0

Outcome = Literal["ok", "failed", "conflict", "unavailable"]
Kind = Literal["timeout", "network", "http", "bad_answer"]

#: What the person is told when n8n could not be asked or did not answer properly. Fixed text: nothing of the exception, the
#: URL, the secret or the body is in it. `http` carries only the status code, a number.
_UNAVAILABLE_TEXT: dict[str, str] = {
    "timeout": "Không nhận được phản hồi từ n8n trong thời gian chờ. Phiếu giữ nguyên trạng thái; thử lại sau.",
    "network": "Không kết nối được tới n8n. Phiếu giữ nguyên trạng thái; thử lại sau.",
    "http": "n8n trả về lỗi HTTP {code}. Phiếu giữ nguyên trạng thái; thử lại sau.",
    "bad_answer": "n8n trả về phản hồi không hợp lệ. Phiếu giữ nguyên trạng thái; thử lại sau.",
}


@dataclass(frozen=True)
class Answer:
    """What n8n said, reduced to what the web acts on.

    `status`, `result` and `message` are n8n's own (a text or `None`; `status` is only trusted by the caller for `ok`, where
    it is one of `OK_STATUSES`, and for `conflict`, where the caller checks it against the states a ticket can have).
    `kind` and `http_status` say what went wrong for `unavailable`; `message` is then the fixed sentence for the kind.
    """

    outcome: Outcome
    status: str | None = None
    result: str | None = None
    message: str | None = None
    kind: Kind | None = None
    http_status: int | None = None
    duration_ms: int = 0


class _TooSlow(Exception):
    """The deadline of the whole call passed while the body was being read."""


class _TooLarge(Exception):
    """The body is larger than any answer of this contract."""


def is_configured(cfg: Config) -> bool:
    """Both the address and the secret are set: otherwise the decision route answers 503 before it locks anything."""
    return bool(cfg.N8N_APPROVAL_URL) and bool(cfg.N8N_APPROVAL_SECRET)


class _DeadlineStream(httpcore.NetworkStream):
    """A connection whose every wait is cut to what is left of the call's deadline: a read, a write and a TLS handshake each wait at
    most the smaller of their own timeout and the time remaining, and none starts once the deadline has passed.
    """

    def __init__(
        self,
        inner: httpcore.NetworkStream,
        left: Callable[[float | None, type[Exception]], float | None],
    ) -> None:
        self._inner = inner
        self._left = left

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return self._inner.read(max_bytes, timeout=self._left(timeout, httpcore.ReadTimeout))

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self._inner.write(buffer, timeout=self._left(timeout, httpcore.WriteTimeout))

    def close(self) -> None:
        self._inner.close()

    def start_tls(
        self, ssl_context, server_hostname: str | None = None, timeout: float | None = None
    ):
        tls = self._inner.start_tls(
            ssl_context, server_hostname, timeout=self._left(timeout, httpcore.ConnectTimeout)
        )
        return _DeadlineStream(tls, self._left)

    def get_extra_info(self, info: str) -> Any:
        return self._inner.get_extra_info(info)


class _DeadlineBackend(httpcore.NetworkBackend):
    """The network backend of the client: `httpx` bounds each wait but not their sum, so a server that drips a byte at a time, in
    the connect, the headers or the body, would keep a call alive for ever. Every wait goes through `left` (the time remaining of the
    whole call), and the name is resolved in a thread that is not waited for past the deadline: resolution is the operating system's
    and has no timeout of its own."""

    def __init__(self, deadline: float, clock: Callable[[], float]) -> None:
        self._deadline = deadline
        self._clock = clock
        self._inner = httpcore.SyncBackend()

    def _left(self, timeout: float | None, error: type[Exception]) -> float | None:
        remaining = self._deadline - self._clock()
        if remaining <= 0:
            raise error("the deadline of the whole call passed")
        return remaining if timeout is None else min(timeout, remaining)

    def _resolve(self, host: str, port: int) -> str:
        try:
            ipaddress.ip_address(host)
            return host  # an address: nothing to look up
        except ValueError:
            pass
        found: list[Any] = []

        def lookup() -> None:
            try:
                found.append(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0][4][0])
            except (OSError, IndexError) as exc:
                found.append(exc)

        worker = threading.Thread(target=lookup, daemon=True)
        worker.start()
        worker.join(self._left(None, httpcore.ConnectTimeout))
        if not found:
            raise httpcore.ConnectTimeout("the name did not resolve before the deadline")
        if isinstance(found[0], Exception):
            raise httpcore.ConnectError("the name did not resolve")
        return found[0]

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        address = self._resolve(host, port)
        stream = self._inner.connect_tcp(
            address,
            port,
            timeout=self._left(timeout, httpcore.ConnectTimeout),
            local_address=local_address,
            socket_options=socket_options,
        )
        return _DeadlineStream(stream, self._left)

    def connect_unix_socket(self, path, timeout=None, socket_options=None):
        stream = self._inner.connect_unix_socket(
            path,
            timeout=self._left(timeout, httpcore.ConnectTimeout),
            socket_options=socket_options,
        )
        return _DeadlineStream(stream, self._left)

    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


def _build_client(deadline: float, clock: Callable[[], float] = time.monotonic) -> httpx.Client:
    """The real client: every wait of the call ends by `deadline`, and the connection is closed when the client is. No redirect is
    followed (n8n's webhook answers directly, and a redirect would carry the secret header elsewhere), and the proxy variables of the
    environment are not read (the call goes straight to the address that was configured)."""
    transport = httpx.HTTPTransport()
    transport._pool.close()  # the transport's own pool is replaced by one on the bounded backend
    transport._pool = httpcore.ConnectionPool(
        ssl_context=httpx.create_ssl_context(),
        max_connections=1,
        max_keepalive_connections=0,
        http1=True,
        http2=False,
        network_backend=_DeadlineBackend(deadline, clock),
    )
    return httpx.Client(transport=transport, follow_redirects=False, trust_env=False)


def request_body(
    review_id: str,
    decision: str,
    user: str,
    user_role: str,
    note: str | None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """The JSON body of the call (spec §3). `note` is always a text, empty when the person wrote none; `requested_at` is
    the moment of the call in UTC."""
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    return {
        "source": "web",
        "review_id": review_id,
        "decision": decision,
        "callback": f"{decision}:{review_id}",
        "user": user,
        "user_role": user_role,
        "note": note or "",
        "requested_at": moment.isoformat(),
    }


def _text(value: Any) -> str | None:
    """n8n's text field: a string, made storable (a NUL removed, a lone surrogate replaced: `infra.storable`) and then cut; anything
    else is no text. n8n has already acted when this is read: a text the database refuses must not cost the record of it.
    """
    return make_storable(value)[:MAX_TEXT] if isinstance(value, str) else None


def _read_capped(response: httpx.Response, deadline: float, clock: Callable[[], float]) -> bytes:
    """The body, at most `MAX_BODY_BYTES`, read piece by piece against the deadline of the whole call."""
    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_bytes():
        if clock() > deadline:
            raise _TooSlow
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            raise _TooLarge
        chunks.append(chunk)
    if clock() > deadline:
        raise _TooSlow
    return b"".join(chunks)


def _unavailable(
    kind: Kind, started: float, clock: Callable[[], float], code: int | None = None
) -> Answer:
    text = _UNAVAILABLE_TEXT[kind].format(code=code)
    return Answer(
        outcome="unavailable",
        message=text,
        kind=kind,
        http_status=code,
        duration_ms=int((clock() - started) * 1000),
    )


def _interpret(code: int, raw: bytes) -> tuple[Outcome, dict[str, Any]] | None:
    """`(outcome, data)` for an answer this contract defines, or `None` when it is not one (the caller says
    `unavailable`)."""
    if code not in (200, 409):
        return None
    try:
        data = json.loads(raw)
    except ValueError:  # JSONDecodeError and UnicodeDecodeError both
        return None
    if not isinstance(data, dict):
        return None
    if code == 409:
        return "conflict", data
    ok = data.get("ok")
    if ok is False:
        return "failed", data
    if ok is True and data.get("status") in OK_STATUSES:
        return "ok", data
    return None


def call(
    cfg: Config,
    *,
    review_id: str,
    decision: str,
    user: str,
    user_role: str,
    note: str | None = None,
    client_factory: Callable[[], httpx.Client] | None = None,
    clock: Callable[[], float] = time.monotonic,
    now: datetime | None = None,
) -> Answer:
    """Ask n8n to carry out `decision` on `review_id` for `user`; see the module docstring for the answers.

    `client_factory` and `clock` are the injection points of a test (a fake transport, a fake clock); `now` fixes
    `requested_at`. Never raises."""
    started = clock()
    timeout_s = float(cfg.N8N_APPROVAL_TIMEOUT_SECONDS)
    deadline = started + timeout_s
    code: int | None = None
    failure: str | None = None  # the class name of what was raised, for the log line
    try:
        headers = {"X-SOAR-Secret": cfg.N8N_APPROVAL_SECRET, "Content-Type": "application/json"}
        body = request_body(review_id, decision, user, user_role, note, now)
        timeout = httpx.Timeout(timeout_s, connect=min(timeout_s, CONNECT_TIMEOUT_S))
        with (
            client_factory() if client_factory else _build_client(deadline, clock) as client,
            client.stream(
                "POST", cfg.N8N_APPROVAL_URL, json=body, headers=headers, timeout=timeout
            ) as response,
        ):
            code = response.status_code
            raw = _read_capped(response, deadline, clock)
        interpreted = _interpret(code, raw)
        if interpreted is None:
            answer = _unavailable(
                "http" if code not in (200, 409) else "bad_answer", started, clock, code
            )
        else:
            outcome, data = interpreted
            answer = Answer(
                outcome=outcome,
                status=_text(data.get("status")),
                result=_text(data.get("result")),
                message=_text(data.get("message")),
                http_status=code,
                duration_ms=int((clock() - started) * 1000),
            )
    except (_TooSlow, httpx.TimeoutException) as exc:
        failure = type(exc).__name__
        answer = _unavailable("timeout", started, clock, code)
    except _TooLarge as exc:
        failure = type(exc).__name__
        answer = _unavailable("bad_answer", started, clock, code)
    except Exception as exc:  # noqa: BLE001 - the contract: never raises
        # Any other failure (a transport error, a bad URL, a bug) is a network failure to the caller.
        # Never `str(exc)`: an httpx exception's own message can carry the request URL, token included.
        failure = type(exc).__name__
        answer = _unavailable("network", started, clock, code)
    logger.info(
        "n8n approval: outcome=%s http_status=%s duration_ms=%d exception=%s",
        answer.outcome,
        answer.http_status,
        answer.duration_ms,
        failure,
    )
    return answer
