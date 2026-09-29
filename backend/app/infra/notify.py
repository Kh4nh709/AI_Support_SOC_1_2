"""`infra.notify` — `send(level, text) -> bool`, one env-selected sink, and it
never raises into its caller (P5-tasks.md planning decision 6 / §8's INBOX
answer A: Telegram plus a log sink, no e-mail arm — a second, mail-based sink
would be six new §6.3 keys, a frozen-contract change out of this card's
scope; acceptance 6 keeps that arm's env-var prefix out of this file too).

Telegram is used when `NOTIFY_TELEGRAM_BOT_TOKEN` **and**
`NOTIFY_TELEGRAM_CHAT_ID` are both non-empty: one `httpx.post` to the bot API
with a short timeout (`infra/puller.py`'s `httpx` usage is the precedent this
mirrors — a client built at the call site, never a module-level global).
Otherwise the **log sink**, which is not a stub: on this host, today, `.env`
carries neither Telegram key, so the log sink is the only sink there is and
the health job must be demonstrable without a bot token.

`send()` never raises: every exception — a timeout, a DNS failure, a 4xx, a
bad `Config` — is caught in one place, logged and counted, and `send()`
returns `False`. A notifier that raises would take the health job down with
it (the job's exception handling would retry/fail the whole `health` job over
a notification, not a health problem) — this is the reason the try/except
below wraps the whole dispatch, not just the Telegram branch.

The bot token is never logged: the URL that carries it is built only inside
`_send_telegram`, used once, and never printed or included in any log line —
only `level` and `text` are. Review round 1, S4: `httpx` itself logs every
request's URL at INFO (`httpx/_client.py`), which would carry the token
straight into the root logger regardless of anything this module does —
raised to WARNING at import time, below, so nothing from `httpx`'s own
logger reaches a handler by default.

Review round 1, N7: the `except` in `send()` never logs `str(exc)` — an
`httpx` exception's message can itself contain the request URL (and so the
token) — only the exception's type name and, for an `HTTPStatusError`, the
response status code.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable

import httpx

from app.infra import config
from app.infra.config import Config

logger = logging.getLogger(__name__)

# S4: httpx's own per-request INFO log line includes the full URL — silence it
# here so a bot token in that URL can never reach a handler through httpx's
# logger, independent of whatever level this module's own `logger` is set to.
logging.getLogger("httpx").setLevel(logging.WARNING)

_TELEGRAM_API = "https://api.telegram.org"
_TELEGRAM_TIMEOUT = httpx.Timeout(10.0, connect=5.0)  # B1: a tight connect bound too

_counters: dict[str, int] = {}


def counters() -> dict[str, int]:
    """A copy of this module's send counters (`infra/errors.py:counters()`'s
    precedent) — callers must not be able to mutate the live state."""
    return dict(_counters)


def _count(key: str) -> None:
    _counters[key] = _counters.get(key, 0) + 1


def _build_client() -> httpx.Client:
    return httpx.Client(timeout=_TELEGRAM_TIMEOUT)


def _send_telegram(
    cfg: Config, level: str, text: str, client_factory: Callable[[], httpx.Client]
) -> bool:
    """One `httpx.post`, injectable `client_factory` for tests (a fake
    transport — no real network send). Raises straight through to `send`'s
    one catch-all; this function has no try/except of its own on purpose, so
    that catch-all is the only place the "never raises" contract is kept."""
    url = f"{_TELEGRAM_API}/bot{cfg.NOTIFY_TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": cfg.NOTIFY_TELEGRAM_CHAT_ID, "text": f"[{level}] {text}"}
    with client_factory() as client:
        response = client.post(url, json=payload)
        response.raise_for_status()
    _count("telegram_sent")
    return True


def _send_log(level: str, text: str) -> bool:
    _count(f"log_{level}")
    print(json.dumps({"notify_sink": "log", "level": level, "text": text}))
    return True


def send(
    level: str,
    text: str,
    *,
    cfg: Config | None = None,
    client_factory: Callable[[], httpx.Client] | None = None,
) -> bool:
    """One adapter, env-selected. `cfg`/`client_factory` are keyword-only
    injection points for callers/tests that already hold a `Config` or want a
    fake transport (`infra.health.check` passes its own `cfg` through, so a
    test's `Config` — never the real `.env`, DEC-047 — decides the sink);
    `notify.send(level, text)` with neither is the acceptance-4 call form and
    behaves identically, reading `config.load()` itself.
    """
    try:
        cfg = cfg or config.load()
        if cfg.NOTIFY_TELEGRAM_BOT_TOKEN and cfg.NOTIFY_TELEGRAM_CHAT_ID:
            return _send_telegram(cfg, level, text, client_factory or _build_client)
        return _send_log(level, text)
    except Exception as exc:  # noqa: BLE001 — deliberately broad: this is the
        # whole "never raises into the caller" contract in one place (module
        # docstring) — a timeout, a DNS failure, a 4xx, a bad Config, anything.
        _count("failed")
        # N7: never `str(exc)` — an httpx exception's own message can carry
        # the request URL, token included. Only the exception's type name,
        # plus the response status for an HTTPStatusError.
        status = getattr(getattr(exc, "response", None), "status_code", None)
        logger.warning(
            "notify: send failed (level=%s exc_type=%s status=%s)",
            level,
            type(exc).__name__,
            status,
        )
        return False
