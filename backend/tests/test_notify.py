"""`backend/tests/test_notify.py` — P5-T11, `app.infra.notify` (pure: no test
here uses the `db` fixture, so none carries `@pytest.mark.db` and `make test`
picks up the whole file unmarked — acceptance 1's
`-m "not db"` run).

Design note 5/7: `send(level, text) -> bool`, Telegram when both keys are set
(a fake `httpx.MockTransport` stands in for the bot API — no real network
send), otherwise the log sink; every exception is caught, `send` never
raises, and the bot token never appears in captured output.
"""

from __future__ import annotations

import json
import logging
from dataclasses import replace

import httpx
import pytest
from app.infra import notify
from app.infra.config import Config

_TOKEN = "123456:AA-super-secret-telegram-token"
_CHAT_ID = "-100999"


def _cfg(**overrides) -> Config:
    return replace(Config(), **overrides)


def _telegram_cfg(**overrides) -> Config:
    return _cfg(NOTIFY_TELEGRAM_BOT_TOKEN=_TOKEN, NOTIFY_TELEGRAM_CHAT_ID=_CHAT_ID, **overrides)


def _mock_client_factory(handler):
    return lambda: httpx.Client(transport=httpx.MockTransport(handler))


# ---------------------------------------------------------------------------
# the Telegram arm
# ---------------------------------------------------------------------------


def test_telegram_arm_builds_the_right_url_and_posts_once():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"ok": True})

    result = notify.send(
        "alarm", "disk free 12%", cfg=_telegram_cfg(), client_factory=_mock_client_factory(handler)
    )

    assert result is True
    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == f"https://api.telegram.org/bot{_TOKEN}/sendMessage"
    body = json.loads(request.content)
    assert body == {"chat_id": _CHAT_ID, "text": "[alarm] disk free 12%"}


def test_build_client_never_disables_tls_verification(monkeypatch):
    """N8, mutant M10: `_build_client` must never pass `verify=False` — the
    `MockTransport`-based tests above never exercise real TLS, so this spies
    on the actual keyword arguments `httpx.Client(...)` is constructed with."""
    captured: dict[str, object] = {}
    real_init = httpx.Client.__init__

    def spy_init(self, *args, **kwargs):
        captured.update(kwargs)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "__init__", spy_init)

    client = notify._build_client()
    client.close()

    assert captured.get("verify", True) is not False


def test_an_httpx_exception_returns_false_and_does_not_propagate():
    """Design note 7's most important test: a notifier that raises would take
    the health job down with it. Red step (a) — DEC-025: temporarily narrow
    `send`'s `except Exception` to `except ValueError`, watch this go red,
    then restore it."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("connection timed out", request=request)

    result = notify.send(
        "alarm", "x", cfg=_telegram_cfg(), client_factory=_mock_client_factory(handler)
    )

    assert result is False


def test_a_4xx_response_returns_false_and_does_not_propagate():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"ok": False, "description": "Unauthorized"})

    result = notify.send(
        "alarm", "x", cfg=_telegram_cfg(), client_factory=_mock_client_factory(handler)
    )

    assert result is False


def test_token_never_appears_in_captured_records(capsys, caplog):
    """Review round 1, S4: `httpx` itself logs each request's URL at INFO
    (`httpx/_client.py`) — a bot token embedded in that URL would reach any
    handler attached to the `httpx` logger regardless of what this module
    does, unless that logger is silenced (the fix: `notify.py`'s module-level
    `logging.getLogger("httpx").setLevel(logging.WARNING)`). `caplog` is set
    to DEBUG so nothing is filtered out *before* it reaches this assertion —
    the point is to prove the token never reaches a captured record at all,
    not merely that it is absent from this module's own log line. Two
    scenarios, both through the real `httpx` request path (`MockTransport`,
    no real network): a 200 (the send succeeds) and a 401 (the send fails)."""
    caplog.set_level(logging.DEBUG)

    def ok_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    def unauthorized_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"ok": False, "description": "Unauthorized"})

    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("boom", request=request)

    for handler in (ok_handler, unauthorized_handler, timeout_handler):
        notify.send("alarm", "x", cfg=_telegram_cfg(), client_factory=_mock_client_factory(handler))

    out = capsys.readouterr().out
    assert _TOKEN not in out
    assert _TOKEN not in caplog.text
    for record in caplog.records:
        assert _TOKEN not in record.getMessage()


# ---------------------------------------------------------------------------
# the log sink — not a stub (module docstring): the only sink on this host
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "token,chat_id",
    [("", ""), ("", _CHAT_ID), (_TOKEN, "")],
    ids=["both-empty", "token-empty", "chat-id-empty"],
)
def test_log_sink_fires_when_either_telegram_key_is_empty(token, chat_id, capsys):
    cfg = _cfg(NOTIFY_TELEGRAM_BOT_TOKEN=token, NOTIFY_TELEGRAM_CHAT_ID=chat_id)

    result = notify.send("alarm", "disk free 12%", cfg=cfg)

    assert result is True
    out = capsys.readouterr().out.strip()
    line = json.loads(out)
    assert line == {"notify_sink": "log", "level": "alarm", "text": "disk free 12%"}


def test_log_sink_output_never_contains_a_telegram_token(capsys):
    # The log sink never sees a token (no Telegram keys are set) — this pins
    # that down rather than assuming it from the log line's shape above.
    cfg = _cfg(NOTIFY_TELEGRAM_BOT_TOKEN="", NOTIFY_TELEGRAM_CHAT_ID="")
    notify.send("alarm", f"unrelated to {_TOKEN}", cfg=cfg)
    out = capsys.readouterr().out
    # the token substring itself was never configured, so this is a sanity
    # check on the *shape* (one JSON line, `text` verbatim) rather than a
    # secrecy claim — the real secrecy claim is the Telegram-branch test above.
    assert json.loads(out.strip())["text"] == f"unrelated to {_TOKEN}"


# ---------------------------------------------------------------------------
# never raises, even when config.load() itself would raise
# ---------------------------------------------------------------------------


def test_send_never_raises_when_cfg_is_omitted_and_config_load_fails(monkeypatch):
    from app.infra import config
    from app.infra.errors import ConfigError

    def _broken_load(*, env_file=".env"):
        raise ConfigError("boom")

    monkeypatch.setattr(config, "load", _broken_load)

    result = notify.send("alarm", "x")

    assert result is False


# ---------------------------------------------------------------------------
# counters — "a module counter" (design note 5)
# ---------------------------------------------------------------------------


def test_counters_count_telegram_sent_and_failed():
    before = notify.counters()

    def ok_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    def fail_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("boom", request=request)

    notify.send("alarm", "x", cfg=_telegram_cfg(), client_factory=_mock_client_factory(ok_handler))
    notify.send(
        "alarm", "x", cfg=_telegram_cfg(), client_factory=_mock_client_factory(fail_handler)
    )

    after = notify.counters()
    assert after.get("telegram_sent", 0) == before.get("telegram_sent", 0) + 1
    assert after.get("failed", 0) == before.get("failed", 0) + 1


def test_counters_returns_a_copy_not_the_live_dict():
    snapshot = notify.counters()
    snapshot["telegram_sent"] = 999999
    assert notify.counters().get("telegram_sent", 0) != 999999
