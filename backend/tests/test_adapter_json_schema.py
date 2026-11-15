"""`DeepSeekAdapter` and a `json_schema` request: the fallback to `json_object` (DEC-218, spec section 5).

A fake OpenAI client throughout, no network, no sleep. The rule under test is narrow: when a request that
asked for `response_format: json_schema` is refused with HTTP 400 or 422, the same request is sent once more
with `json_object` and the result says which format produced it (`LLMResult.response_format`). Every other
failure is classified as it is today: a 400 on a `json_object` request is still permanent; a 402, a 429, a 5xx,
a timeout and a connection error on a `json_schema` request are not a fallback and are not changed. The
fallback is not one of the `LLM_RETRY` attempts (`usage["attempts"]` does not count it) and is per call: the
adapter remembers nothing.
"""

from __future__ import annotations

import httpx
import openai
import pytest
from app.infra.errors import TransientError, classify
from app.llm.adapter import (
    DeepSeekAdapter,
    LLMBudgetExceeded,
    LLMPermanent,
    LLMTimeout,
    LLMUnavailable,
)

from tests.test_adapter import (
    VALID_SYSTEM,
    FakeClient,
    SlowClient,
    _cfg,
    _connection_error,
    _response,
    _status_error,
)

_REQUEST = httpx.Request("POST", "https://api.z.ai/v1/chat/completions")

SCHEMA_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "triage_v3",
        "strict": True,
        "schema": {
            "type": "object",
            "additionalProperties": False,
            "required": [],
            "properties": {},
        },
    },
}
JSON_OBJECT = {"type": "json_object"}


def _sdk_error(cls, status_code: int) -> Exception:
    """The SDK's own exception for a status, as the real client raises it (carries `.status_code`)."""
    return cls("refused", response=httpx.Response(status_code, request=_REQUEST), body=None)


def _refusals():
    return [
        pytest.param(lambda: _status_error(400), id="400-bare"),
        pytest.param(lambda: _status_error(422), id="422-bare"),
        pytest.param(lambda: _sdk_error(openai.BadRequestError, 400), id="400-sdk"),
        pytest.param(lambda: _sdk_error(openai.UnprocessableEntityError, 422), id="422-sdk"),
    ]


class _Adapter(DeepSeekAdapter):
    """The adapter with its log lines and its pauses kept where a test can read them."""

    def __init__(self, client, **cfg):
        self.events: list[dict] = []
        self.pauses: list[float] = []
        super().__init__(_cfg(**cfg), client=client, sleep=self.pauses.append, log=self.events.append)


class TestTheRequestAndTheResult:
    def test_a_json_schema_request_that_is_accepted_is_sent_once_and_says_json_schema(self):
        client = FakeClient([_response(content="{}")])
        adapter = _Adapter(client)

        result = adapter.complete(system=VALID_SYSTEM, user="x", response_format=SCHEMA_FORMAT)

        assert client.call_count == 1
        assert client.calls[0]["response_format"] == SCHEMA_FORMAT
        assert result.response_format == "json_schema"

    def test_the_default_request_is_unchanged_and_says_json_object(self):
        client = FakeClient([_response(content="{}")])
        adapter = _Adapter(client)

        result = adapter.complete(system=VALID_SYSTEM, user="alert 1")

        assert client.call_count == 1
        kwargs = client.calls[0]
        assert kwargs["response_format"] == JSON_OBJECT
        assert kwargs["extra_body"] == {"thinking": {"type": "disabled"}}
        assert result.response_format == "json_object"

    def test_a_caller_supplied_other_format_is_reported_as_its_own_type(self):
        client = FakeClient([_response(content="{}")])
        adapter = _Adapter(client)

        result = adapter.complete(system=VALID_SYSTEM, user="x", response_format={"type": "text"})

        assert result.response_format == "text"


class TestTheFallback:
    @pytest.mark.parametrize("make_error", _refusals())
    def test_a_400_or_422_on_a_json_schema_request_is_sent_again_as_json_object(self, make_error):
        client = FakeClient([make_error(), _response(content='{"ok": 1}')])
        adapter = _Adapter(client)

        result = adapter.complete(system=VALID_SYSTEM, user="u", response_format=SCHEMA_FORMAT)

        assert client.call_count == 2
        assert client.calls[0]["response_format"] == SCHEMA_FORMAT
        assert client.calls[1]["response_format"] == JSON_OBJECT
        assert result.content == '{"ok": 1}'
        assert result.response_format == "json_object"

    @pytest.mark.parametrize("make_error", _refusals())
    def test_the_second_request_differs_from_the_first_in_the_format_alone(self, make_error):
        client = FakeClient([make_error(), _response(content="{}")])
        adapter = _Adapter(client)

        adapter.complete(
            system=VALID_SYSTEM, user="u", response_format=SCHEMA_FORMAT, model="m", timeout_s=7
        )

        first, second = client.calls
        assert {k: v for k, v in first.items() if k != "response_format"} == {
            k: v for k, v in second.items() if k != "response_format"
        }
        assert first["model"] == "m" and first["timeout"] == 7

    def test_the_fallback_is_not_one_of_the_llm_retry_attempts(self):
        client = FakeClient([_status_error(400), _response(content="{}")])
        adapter = _Adapter(client, LLM_RETRY=0)  # no retry at all: the fallback still happens

        result = adapter.complete(system=VALID_SYSTEM, user="x", response_format=SCHEMA_FORMAT)

        assert client.call_count == 2
        assert result.usage["attempts"] == 1
        assert adapter.pauses == []

    def test_a_second_refusal_on_the_json_object_request_is_permanent_and_no_third_call(self):
        client = FakeClient([_status_error(400), _status_error(400)])
        adapter = _Adapter(client)

        with pytest.raises(LLMPermanent):
            adapter.complete(system=VALID_SYSTEM, user="x", response_format=SCHEMA_FORMAT)

        assert client.call_count == 2

    def test_a_402_on_the_fallback_request_is_unavailable_as_ever(self):
        client = FakeClient([_status_error(422), _status_error(402)])
        adapter = _Adapter(client)

        with pytest.raises(LLMUnavailable):
            adapter.complete(system=VALID_SYSTEM, user="x", response_format=SCHEMA_FORMAT)

        assert client.call_count == 2

    def test_a_5xx_on_the_fallback_request_is_the_ordinary_retry_and_asks_for_the_schema_again(self):
        """The fallback is per request, nothing is remembered: the next attempt of the same call is the
        request the caller made, and the provider that refused it refuses it again, then the fallback again."""
        client = FakeClient(
            [_status_error(400), _status_error(503), _status_error(400), _response(content="{}")]
        )
        adapter = _Adapter(client, LLM_RETRY=2)

        result = adapter.complete(system=VALID_SYSTEM, user="x", response_format=SCHEMA_FORMAT)

        assert [c["response_format"]["type"] for c in client.calls] == [
            "json_schema",
            "json_object",
            "json_schema",
            "json_object",
        ]
        assert result.usage["attempts"] == 2  # the 503 used the one retry; the 400s used none
        assert adapter.pauses == [2.0]

    def test_nothing_is_remembered_the_next_call_asks_for_the_schema_again(self):
        client = FakeClient([_status_error(400), _response(content="{}"), _response(content="{}")])
        adapter = _Adapter(client)

        first = adapter.complete(system=VALID_SYSTEM, user="x", response_format=SCHEMA_FORMAT)
        second = adapter.complete(system=VALID_SYSTEM, user="x", response_format=SCHEMA_FORMAT)

        assert [c["response_format"]["type"] for c in client.calls] == [
            "json_schema",
            "json_object",
            "json_schema",
        ]
        assert first.response_format == "json_object"
        assert second.response_format == "json_schema"

    def test_the_log_names_the_refused_request_and_the_one_that_answered(self):
        client = FakeClient([_status_error(400), _response(content="{}")])
        adapter = _Adapter(client)

        adapter.complete(
            system=VALID_SYSTEM, user="super secret alert body", response_format=SCHEMA_FORMAT
        )

        assert [e["outcome"] for e in adapter.events] == ["format_fallback", "ok"]
        for event in adapter.events:
            assert set(event) == {"llm", "n", "outcome", "ms"}
            assert event["n"] == 1
            assert "super secret alert body" not in str(event)


class TestEverythingElseIsClassifiedAsToday:
    def test_a_400_on_a_json_object_request_is_still_permanent_without_a_second_call(self):
        client = FakeClient([_status_error(400)])
        adapter = _Adapter(client)

        with pytest.raises(LLMPermanent):
            adapter.complete(system=VALID_SYSTEM, user="x")  # the default is json_object

        assert client.call_count == 1

    def test_a_400_on_an_explicit_json_object_request_is_still_permanent(self):
        client = FakeClient([_status_error(400)])
        adapter = _Adapter(client)

        with pytest.raises(LLMPermanent):
            adapter.complete(system=VALID_SYSTEM, user="x", response_format=JSON_OBJECT)

        assert client.call_count == 1

    def test_a_422_on_a_text_request_is_not_a_fallback_either(self):
        client = FakeClient([_status_error(422)])
        adapter = _Adapter(client)

        with pytest.raises(LLMPermanent):
            adapter.complete(system=VALID_SYSTEM, user="x", response_format={"type": "text"})

        assert client.call_count == 1

    def test_a_429_on_a_json_schema_request_is_permanent_one_call_no_fallback(self):
        client = FakeClient([_status_error(429)])
        adapter = _Adapter(client)

        with pytest.raises(LLMPermanent) as excinfo:
            adapter.complete(system=VALID_SYSTEM, user="x", response_format=SCHEMA_FORMAT)

        assert not isinstance(excinfo.value, LLMUnavailable)
        assert client.call_count == 1
        assert [e["outcome"] for e in adapter.events] == ["permanent"]

    def test_a_402_on_a_json_schema_request_is_unavailable_one_call_no_fallback(self):
        client = FakeClient([_status_error(402)])
        adapter = _Adapter(client)

        with pytest.raises(LLMUnavailable):
            adapter.complete(system=VALID_SYSTEM, user="x", response_format=SCHEMA_FORMAT)

        assert client.call_count == 1

    @pytest.mark.parametrize("status", [500, 502, 503])
    def test_a_5xx_on_a_json_schema_request_is_retried_as_json_schema_then_transient(self, status):
        client = FakeClient([_status_error(status)] * 3)
        adapter = _Adapter(client, LLM_RETRY=2)

        with pytest.raises(Exception) as excinfo:
            adapter.complete(system=VALID_SYSTEM, user="x", response_format=SCHEMA_FORMAT)

        assert client.call_count == 3
        assert all(c["response_format"] == SCHEMA_FORMAT for c in client.calls)
        assert adapter.pauses == [2.0, 4.0]
        assert excinfo.value.status_code == status
        assert classify(excinfo.value) == "transient"
        assert [e["outcome"] for e in adapter.events] == ["transient"] * 3

    def test_a_connection_error_on_a_json_schema_request_is_retried_then_wrapped_as_transient(self):
        client = FakeClient([_connection_error()] * 3)
        adapter = _Adapter(client, LLM_RETRY=2)

        with pytest.raises(TransientError) as excinfo:
            adapter.complete(system=VALID_SYSTEM, user="x", response_format=SCHEMA_FORMAT)

        assert client.call_count == 3
        assert all(c["response_format"] == SCHEMA_FORMAT for c in client.calls)
        assert classify(excinfo.value) == "transient"

    def test_a_timeout_on_a_json_schema_request_is_not_retried_and_not_a_fallback(self):
        client = SlowClient(delay_s=3)
        adapter = _Adapter(client, LLM_TIMEOUT_S=1, LLM_RETRY=2)

        with pytest.raises(LLMTimeout):
            adapter.complete(system=VALID_SYSTEM, user="x", response_format=SCHEMA_FORMAT)

        assert client.call_count == 1
        assert [e["outcome"] for e in adapter.events] == ["timeout"]

    def test_the_monthly_cap_still_stops_a_json_schema_request_before_any_socket(self):
        client = FakeClient([_response(content="{}")])
        adapter = DeepSeekAdapter(_cfg(LLM_MONTHLY_USD_CAP=30), client=client, spent_usd=lambda: 30.0)

        with pytest.raises(LLMBudgetExceeded):
            adapter.complete(system=VALID_SYSTEM, user="x", response_format=SCHEMA_FORMAT)

        assert client.call_count == 0
