"""SR-T1 — `app.infra.n8n_approval`: the call the web makes to n8n when a person presses a button (spec §3).

Pure: a fake `httpx.MockTransport` (`tests/fakes/n8n.py`) stands in for n8n, so the real client runs end to end and no
test touches the network. Four things are on trial: the request it builds (URL, secret header, body), the four outcomes
and what each table row of the spec maps to, that it never raises, and that no secret, URL or exception text reaches a
log line or an answer.
"""

from __future__ import annotations

import json
import logging
from dataclasses import replace
from datetime import UTC, datetime

import httpx
import pytest
from app.infra import n8n_approval
from app.infra.config import Config

from tests.fakes.n8n import FakeN8n, Reply

SECRET = "approval-SECRET-aaa111"
URL_TOKEN = "urltoken-QQQ999"
URL = f"http://n8n.test:5678/webhook/soar-approval?token={URL_TOKEN}"
NOW = datetime(2026, 11, 16, 9, 30, 15, 123456, tzinfo=UTC)


def _cfg(**over) -> Config:
    fields = {"N8N_APPROVAL_URL": URL, "N8N_APPROVAL_SECRET": SECRET, **over}
    return replace(Config(), **fields)


def _call(
    fake: FakeN8n, *, decision="undo", note="gỡ vì là máy in", cfg=None
) -> n8n_approval.Answer:
    return n8n_approval.call(
        cfg or _cfg(),
        review_id="K7QM2XHP",
        decision=decision,
        user="alice",
        user_role="tier2",
        note=note,
        client_factory=fake.client_factory,
        now=NOW,
    )


def _call_with(cfg: Config, **kwargs) -> n8n_approval.Answer:
    return n8n_approval.call(
        cfg, review_id="K7QM2XHP", decision="keep", user="a", user_role="admin", **kwargs
    )


# ── the request ─────────────────────────────────────────────────────────────────────────────


def test_it_posts_once_to_the_url_with_the_secret_header_and_a_json_body():
    fake = FakeN8n()
    _call(fake)
    assert len(fake.calls) == 1
    call = fake.calls[0]
    assert call.url == URL
    assert call.secret == SECRET
    assert call.content_type == "application/json"


def test_the_body_is_exactly_the_contract_b_object():
    fake = FakeN8n()
    _call(fake)
    assert fake.calls[0].body == {
        "source": "web",
        "review_id": "K7QM2XHP",
        "decision": "undo",
        "callback": "undo:K7QM2XHP",
        "user": "alice",
        "user_role": "tier2",
        "note": "gỡ vì là máy in",
        "requested_at": "2026-11-16T09:30:15.123456+00:00",
    }


@pytest.mark.parametrize("decision", ["keep", "undo", "fp"])
def test_the_callback_is_decision_colon_review_id(decision):
    fake = FakeN8n()
    _call(fake, decision=decision)
    assert fake.calls[0].body["callback"] == f"{decision}:K7QM2XHP"


@pytest.mark.parametrize("note", [None, ""])
def test_a_missing_note_is_sent_as_an_empty_text(note):
    fake = FakeN8n()
    _call(fake, note=note)
    assert fake.calls[0].body["note"] == ""


def test_requested_at_is_the_moment_of_the_call_in_utc():
    fake = FakeN8n()
    before = datetime.now(UTC)
    _call_with(_cfg(), client_factory=fake.client_factory)
    after = datetime.now(UTC)
    moment = datetime.fromisoformat(fake.calls[0].body["requested_at"])
    assert moment.utcoffset().total_seconds() == 0
    assert before <= moment <= after


def test_the_timeout_of_the_request_is_the_configured_one():
    fake = FakeN8n()
    _call(fake, cfg=_cfg(N8N_APPROVAL_TIMEOUT_SECONDS=30))
    timeout = fake.calls[0].timeout
    assert timeout["read"] == 30.0 and timeout["write"] == 30.0 and timeout["pool"] == 30.0
    assert timeout["connect"] == min(30.0, n8n_approval.CONNECT_TIMEOUT_S)


def test_a_short_timeout_shortens_the_connect_wait_too():
    fake = FakeN8n()
    _call(fake, cfg=_cfg(N8N_APPROVAL_TIMEOUT_SECONDS=3))
    assert fake.calls[0].timeout["connect"] == 3.0


@pytest.mark.parametrize(
    "cfg,expected",
    [
        (Config(), False),
        (Config(N8N_APPROVAL_SECRET="s"), True),
        (Config(N8N_APPROVAL_URL="", N8N_APPROVAL_SECRET="s"), False),
        (Config(N8N_APPROVAL_SECRET=""), False),
    ],
    ids=["default", "secret-set", "url-empty", "secret-empty"],
)
def test_is_configured_needs_both_the_address_and_the_secret(cfg, expected):
    assert n8n_approval.is_configured(cfg) is expected


# ── the four outcomes ───────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "decision,status",
    [("keep", "kept"), ("undo", "undone"), ("fp", "false_positive")],
)
def test_200_ok_true_with_one_of_the_three_statuses_is_ok(decision, status):
    reply = Reply.ok(status, result="đã gỡ", message="Đã gỡ chặn")
    answer = _call(FakeN8n(reply), decision=decision)
    assert answer.outcome == "ok"
    assert answer.status == status
    assert answer.result == "đã gỡ"
    assert answer.message == "Đã gỡ chặn"
    assert answer.http_status == 200
    assert answer.kind is None


def test_ok_carries_null_texts_as_none():
    answer = _call(FakeN8n(Reply.json_body({"ok": True, "status": "kept"})))
    assert (answer.outcome, answer.status, answer.result, answer.message) == (
        "ok",
        "kept",
        None,
        None,
    )


def test_200_ok_false_is_failed_and_carries_n8ns_message_and_result():
    reply = Reply.failed("GỠ THẤT BẠI: pfSense không trả lời", result="timeout", status="open")
    answer = _call(FakeN8n(reply))
    assert answer.outcome == "failed"
    assert answer.message == "GỠ THẤT BẠI: pfSense không trả lời"
    assert answer.result == "timeout"
    assert answer.status == "open"
    assert answer.http_status == 200


def test_failed_without_a_message_has_none():
    answer = _call(FakeN8n(Reply.json_body({"ok": False})))
    assert (answer.outcome, answer.message, answer.result, answer.status) == (
        "failed",
        None,
        None,
        None,
    )


def test_409_is_conflict_with_the_status_and_message_n8n_gave():
    answer = _call(FakeN8n(Reply.conflict("undone", "Đã được gỡ bởi người khác")))
    assert answer.outcome == "conflict"
    assert answer.status == "undone"
    assert answer.message == "Đã được gỡ bởi người khác"
    assert answer.http_status == 409


def test_409_with_a_json_object_and_no_status_is_still_a_conflict():
    answer = _call(FakeN8n(Reply.json_body({"ok": False}, 409)))
    assert (answer.outcome, answer.status) == ("conflict", None)


@pytest.mark.parametrize("code", [400, 401, 403, 404, 408, 429, 500, 502, 503, 504, 302, 204, 201])
def test_any_other_status_code_is_unavailable_naming_the_code(code):
    answer = _call(FakeN8n(Reply.http(code, b'{"ok": true, "status": "kept"}')))
    assert answer.outcome == "unavailable"
    assert answer.kind == "http"
    assert answer.http_status == code
    assert str(code) in answer.message


@pytest.mark.parametrize(
    "reply",
    [
        Reply.text("<html>proxy error</html>"),
        Reply.text(""),
        Reply.text("not json {"),
        Reply.json_body(["ok", True]),
        Reply.json_body("ok"),
        Reply.json_body(None),
        Reply.json_body({}),
        Reply.json_body({"status": "kept"}),
        Reply.json_body({"ok": "true", "status": "kept"}),
        Reply.json_body({"ok": 1, "status": "kept"}),
        Reply.json_body({"ok": None, "status": "kept"}),
        Reply.json_body({"ok": True}),
        Reply.json_body({"ok": True, "status": "open"}),
        Reply.json_body({"ok": True, "status": "expired"}),
        Reply.json_body({"ok": True, "status": "processing"}),
        Reply.json_body({"ok": True, "status": "KEPT"}),
        Reply.json_body({"ok": True, "status": ["kept"]}),
        Reply.text("<html>conflict page</html>", 409),
        Reply.text("[1]", 409),
        Reply.http(200, b"\xff\xfe not utf-8"),
    ],
    ids=lambda r: f"{r.status_code}-{r.content[:24]!r}",
)
def test_a_body_that_is_not_the_contract_is_unavailable_as_a_bad_answer(reply):
    answer = _call(FakeN8n(reply))
    assert answer.outcome == "unavailable"
    assert answer.kind == "bad_answer"
    assert answer.status is None and answer.result is None


def test_a_timeout_is_unavailable():
    answer = _call(FakeN8n(Reply.timeout()))
    assert (answer.outcome, answer.kind, answer.http_status) == ("unavailable", "timeout", None)


@pytest.mark.parametrize(
    "error",
    [
        httpx.ConnectError("refused"),
        httpx.ConnectTimeout("connect timed out"),
        httpx.ReadError("reset"),
        httpx.RemoteProtocolError("bad"),
        httpx.UnsupportedProtocol("no"),
    ],
    ids=lambda e: type(e).__name__,
)
def test_a_network_error_is_unavailable_and_a_connect_timeout_is_a_timeout(error):
    answer = _call(FakeN8n(Reply(raises=error)))
    assert answer.outcome == "unavailable"
    assert answer.kind == ("timeout" if isinstance(error, httpx.TimeoutException) else "network")


def test_an_unexpected_exception_is_unavailable_too_and_never_raised():
    answer = _call(FakeN8n(Reply(raises=RuntimeError("anything at all"))))
    assert (answer.outcome, answer.kind) == ("unavailable", "network")


def test_a_client_factory_that_raises_is_unavailable_too():
    def broken():
        raise OSError("cannot build a client")

    answer = _call_with(_cfg(), client_factory=broken)
    assert (answer.outcome, answer.kind) == ("unavailable", "network")


def test_a_bad_url_is_unavailable_not_an_exception():
    answer = _call_with(_cfg(N8N_APPROVAL_URL="not a url"))
    assert answer.outcome == "unavailable"


def test_the_redirect_is_not_followed_so_the_secret_goes_nowhere_else():
    answer = _call(FakeN8n(Reply.http(307, b"")))
    assert (answer.outcome, answer.kind, answer.http_status) == ("unavailable", "http", 307)


# ── texts: n8n's are cut, ours are fixed ────────────────────────────────────────────────────


def test_n8ns_texts_are_cut_at_2000_characters():
    long = "x" * 5000
    body = {"ok": True, "status": "kept", "message": long, "result": long}
    answer = _call(FakeN8n(Reply.json_body(body)))
    assert len(answer.message) == len(answer.result) == n8n_approval.MAX_TEXT == 2000


def test_a_text_that_is_not_a_string_is_no_text():
    body = {"ok": False, "message": {"a": 1}, "result": 42, "status": ["x"]}
    answer = _call(FakeN8n(Reply.json_body(body)))
    assert (answer.message, answer.result, answer.status) == (None, None, None)


@pytest.mark.parametrize("kind", ["timeout", "network", "http", "bad_answer"])
def test_each_unavailable_kind_has_its_own_fixed_sentence(kind):
    replies = {
        "timeout": Reply.timeout(),
        "network": Reply.network_error(),
        "http": Reply.http(503),
        "bad_answer": Reply.text("???"),
    }
    answer = _call(FakeN8n(replies[kind]))
    assert answer.kind == kind
    assert answer.message
    others = {_call(FakeN8n(r)).message for k, r in replies.items() if k != kind}
    assert answer.message not in others


def test_an_unavailable_message_carries_nothing_of_the_exception_the_url_the_secret_or_the_answer():
    hostile = f"{URL} {SECRET} <script>alert(1)</script>"
    for reply in (
        Reply(raises=httpx.ConnectError(hostile)),
        Reply(raises=httpx.ReadTimeout(hostile)),
        Reply(raises=RuntimeError(hostile)),
        Reply.text(hostile),
        Reply.http(500, hostile.encode()),
    ):
        answer = _call(FakeN8n(reply))
        text = f"{answer.message}{answer.result}{answer.status}"
        for forbidden in (SECRET, URL_TOKEN, "n8n.test", "script", "RuntimeError"):
            assert forbidden not in text


# ── the size and the deadline ───────────────────────────────────────────────────────────────


def test_a_body_over_64_kib_is_a_bad_answer_and_nothing_of_it_is_read():
    big = json.dumps({"ok": True, "status": "kept", "message": "m" * 200_000})
    answer = _call(FakeN8n(Reply.text(big)))
    assert (answer.outcome, answer.kind) == ("unavailable", "bad_answer")


class _SlowStream(httpx.SyncByteStream):
    """A body that arrives piece by piece while a fake clock moves on: no real waiting."""

    def __init__(self, clock: list[float], step: float, pieces: int) -> None:
        self._clock, self._step, self._pieces = clock, step, pieces

    def __iter__(self):
        for _ in range(self._pieces):
            self._clock[0] += self._step
            yield b" "
        yield b'{"ok": true, "status": "kept"}'


def _slow_factory(clock: list[float], step: float, pieces: int):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=_SlowStream(clock, step, pieces))

    return lambda: httpx.Client(transport=httpx.MockTransport(handler))


def test_a_body_that_dribbles_in_past_the_deadline_is_a_timeout_even_if_each_wait_was_short():
    """httpx bounds each wait, not their sum; the call is bounded as a whole."""
    clock = [1000.0]
    answer = _call_with(
        _cfg(N8N_APPROVAL_TIMEOUT_SECONDS=45),  # 5 pieces x 20 s = 100 s
        client_factory=_slow_factory(clock, step=20.0, pieces=5),
        clock=lambda: clock[0],
    )
    assert (answer.outcome, answer.kind) == ("unavailable", "timeout")


def test_the_same_body_inside_the_deadline_is_read():
    clock = [1000.0]
    answer = _call_with(
        _cfg(N8N_APPROVAL_TIMEOUT_SECONDS=45),
        client_factory=_slow_factory(clock, step=2.0, pieces=5),
        clock=lambda: clock[0],
    )
    assert answer.outcome == "ok"
    assert answer.duration_ms == 10_000


def test_the_duration_is_measured_by_the_injected_clock():
    ticks = iter([100.0, 100.0, 100.25, 100.25, 100.25])
    answer = _call_with(
        _cfg(),
        client_factory=FakeN8n().client_factory,
        clock=lambda: next(ticks, 100.25),
    )
    assert answer.duration_ms == 250


# ── nothing secret in a log line ────────────────────────────────────────────────────────────


def _all_log_text(caplog) -> str:
    return "\n".join(f"{r.name} {r.getMessage()}" for r in caplog.records)


@pytest.mark.parametrize(
    "reply",
    [
        Reply.ok("kept"),
        Reply.failed("x"),
        Reply.conflict(),
        Reply.http(503),
        Reply.text("junk"),
        Reply.timeout(),
        Reply.network_error(f"cannot reach {URL} with {SECRET}"),
        Reply(raises=RuntimeError(f"boom {URL} {SECRET}")),
    ],
    ids=lambda r: f"{r.status_code}-{type(r.raises).__name__}",
)
def test_no_log_line_carries_the_secret_the_url_or_an_exception_text(caplog, reply):
    caplog.set_level(logging.DEBUG)
    _call(FakeN8n(reply))
    text = _all_log_text(caplog)
    assert "n8n approval:" in text, "the call logged nothing"
    for forbidden in (SECRET, URL_TOKEN, "n8n.test", "5678", "cannot reach", "boom", "K7QM2XHP"):
        assert forbidden not in text, forbidden


def test_the_log_line_says_the_outcome_the_status_code_and_the_duration(caplog):
    caplog.set_level(logging.INFO, logger="app.infra.n8n_approval")
    _call(FakeN8n(Reply.http(503)))
    lines = [r.getMessage() for r in caplog.records if r.name == "app.infra.n8n_approval"]
    assert len(lines) == 1
    assert "outcome=unavailable" in lines[0]
    assert "http_status=503" in lines[0]
    assert "duration_ms=" in lines[0]


def test_an_exception_is_named_by_its_class_only(caplog):
    caplog.set_level(logging.INFO, logger="app.infra.n8n_approval")
    _call(FakeN8n(Reply(raises=httpx.ConnectError(f"refused {SECRET}"))))
    line = next(r.getMessage() for r in caplog.records if r.name == "app.infra.n8n_approval")
    assert "exception=ConnectError" in line
    assert SECRET not in line


def test_httpxs_own_per_request_info_line_is_silenced():
    """httpx logs `HTTP Request: POST <full url>` at INFO; that line would carry the URL's query."""
    assert logging.getLogger("httpx").getEffectiveLevel() >= logging.WARNING


def test_a_real_httpx_client_logs_no_url_through_the_root_logger(caplog):
    caplog.set_level(logging.DEBUG)
    transport = httpx.MockTransport(lambda r: httpx.Response(200, json={}))
    with httpx.Client(transport=transport) as client:
        client.post(URL, json={})
    assert URL_TOKEN not in _all_log_text(caplog)
