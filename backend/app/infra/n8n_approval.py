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

**A deadline, not only a socket timeout.** `N8N_APPROVAL_TIMEOUT_SECONDS` (1..100, enforced by the configuration) is the
time a call may take. `httpx` bounds each wait (connect, then the response, then each piece of the body) but not their sum,
so the body is read piece by piece against a deadline of the whole call: a lock older than two minutes is released by the
next press, and a live call that outlived it would make n8n be asked twice for one decision.

The answer's texts (`message`, `result`) are n8n's: stored and shown as text, cut at `MAX_TEXT`, never used to build
anything.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

import httpx

from app.infra.config import Config

logger = logging.getLogger(__name__)

# `httpx` logs the full URL of every request at INFO: see the module docstring.
logging.getLogger("httpx").setLevel(logging.WARNING)

#: The decisions of the page's buttons, and the statuses n8n may answer a successful one with.
DECISIONS = ("keep", "undo", "fp")
OK_STATUSES = ("kept", "undone", "false_positive")

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


def _build_client() -> httpx.Client:
    # No redirect is followed: n8n's webhook answers directly, and a redirect would carry the secret header elsewhere.
    return httpx.Client(follow_redirects=False)


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
    """n8n's text field: a string, cut; anything else is no text."""
    return value[:MAX_TEXT] if isinstance(value, str) else None


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
            (client_factory or _build_client)() as client,
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
