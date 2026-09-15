"""Unit tests for app.llm.adapter — a fake OpenAI client throughout; no network, no sleep.

Every retry/backoff test injects `sleep` to record pauses instead of waiting; only the
wall-clock deadline tests (design note 3) use a real clock, because that is the thing
under test.
"""

from __future__ import annotations

import dataclasses
import math
import time
from types import SimpleNamespace

import httpx
import openai
import pytest
from app.infra.config import Config
from app.infra.errors import TransientError, classify
from app.llm.adapter import (
    DeepSeekAdapter,
    LLMBudgetExceeded,
    LLMPermanent,
    LLMTimeout,
    cost_usd,
    estimate_tokens,
)

VALID_SYSTEM = "Respond with a single JSON object and nothing else."
_REQUEST = httpx.Request("POST", "https://api.deepseek.com/v1/chat/completions")


def _cfg(**overrides) -> Config:
    base = Config(
        LLM_MODEL_PROPOSER="deepseek-v4-flash",
        LLM_MODEL_VERIFIER="deepseek-v4-flash",
        LLM_TIMEOUT_S=5,
        LLM_RETRY=2,
        LLM_THINKING="disabled",
        LLM_MONTHLY_USD_CAP=30,
        LLM_PRICE_IN_PER_M=0.014,
        LLM_PRICE_OUT_PER_M=0.66,
    )
    return dataclasses.replace(base, **overrides)


def _response(*, content, model="fake-deepseek-1", usage=None, model_extra=None):
    message = SimpleNamespace(content=content, model_extra=model_extra or {})
    return SimpleNamespace(
        choices=[SimpleNamespace(message=message)], model=model, usage=usage or {}
    )


def _status_error(status_code: int) -> Exception:
    """Mimics an SDK error carrying `.status_code` directly, the same shape
    `infra.errors._status_code` reads (see `test_errors.py::FakeStatusAttr`)."""
    exc = Exception(f"HTTP {status_code}")
    exc.status_code = status_code
    return exc


def _connection_error() -> openai.APIConnectionError:
    return openai.APIConnectionError(request=_REQUEST)


class FakeClient:
    """`client.chat.completions.create(**kwargs)` — queues responses/errors in order."""

    def __init__(self, sequence):
        self.calls: list[dict] = []
        self._sequence = list(sequence)
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        if not self._sequence:
            raise AssertionError("FakeClient: no response/error queued for this call")
        item = self._sequence.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    @property
    def call_count(self) -> int:
        return len(self.calls)


class SlowClient:
    """A client whose create() blocks `delay_s` via a real `time.sleep` — the fixture
    design note 3 asks for: something that outlives the deadline it is tested against."""

    def __init__(self, delay_s: float):
        self.calls: list[dict] = []
        self._delay_s = delay_s
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        time.sleep(self._delay_s)
        return _response(content="{}")

    @property
    def call_count(self) -> int:
        return len(self.calls)


class TestTheCallExactly:
    def test_sends_json_object_and_thinking_extra_body(self):
        client = FakeClient([_response(content="{}")])
        adapter = DeepSeekAdapter(_cfg(), client=client, sleep=lambda s: None)

        result = adapter.complete(system=VALID_SYSTEM, user="alert 1")

        assert client.call_count == 1
        kwargs = client.calls[0]
        assert kwargs["response_format"] == {"type": "json_object"}
        assert kwargs["extra_body"] == {"thinking": {"type": "disabled"}}
        assert kwargs["messages"] == [
            {"role": "system", "content": VALID_SYSTEM},
            {"role": "user", "content": "alert 1"},
        ]
        assert kwargs["model"] == "deepseek-v4-flash"
        assert kwargs["timeout"] == 5
        assert result.content == "{}"

    def test_caller_supplied_response_format_and_model_and_timeout_are_honoured(self):
        client = FakeClient([_response(content="{}")])
        adapter = DeepSeekAdapter(_cfg(), client=client, sleep=lambda s: None)

        adapter.complete(
            system=VALID_SYSTEM,
            user="x",
            response_format={"type": "text"},
            model="deepseek-v4-pro",
            timeout_s=9,
        )

        kwargs = client.calls[0]
        assert kwargs["response_format"] == {"type": "text"}
        assert kwargs["model"] == "deepseek-v4-pro"
        assert kwargs["timeout"] == 9

    @pytest.mark.parametrize("thinking", ["enabled", "disabled"])
    def test_thinking_value_follows_config(self, thinking):
        client = FakeClient([_response(content="{}")])
        adapter = DeepSeekAdapter(_cfg(LLM_THINKING=thinking), client=client, sleep=lambda s: None)

        adapter.complete(system=VALID_SYSTEM, user="x")

        assert client.calls[0]["extra_body"] == {"thinking": {"type": thinking}}


class TestReadingTheResponse:
    def test_reads_content_and_ignores_reasoning_content(self):
        client = FakeClient(
            [_response(content='{"a":1}', model_extra={"reasoning_content": "IGNORE ME"})]
        )
        adapter = DeepSeekAdapter(_cfg(), client=client, sleep=lambda s: None)

        result = adapter.complete(system=VALID_SYSTEM, user="x")

        assert result.content == '{"a":1}'

    def test_content_defaults_to_empty_string_when_absent(self):
        client = FakeClient([_response(content=None)])
        adapter = DeepSeekAdapter(_cfg(), client=client, sleep=lambda s: None)

        result = adapter.complete(system=VALID_SYSTEM, user="x")

        assert result.content == ""

    def test_usage_flattened_with_reasoning_tokens(self):
        usage = {
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "total_tokens": 150,
            "completion_tokens_details": {"reasoning_tokens": 20},
            "prompt_cache_hit_tokens": 10,
            "prompt_cache_miss_tokens": 90,
        }
        client = FakeClient([_response(content="{}", usage=usage)])
        adapter = DeepSeekAdapter(_cfg(), client=client, sleep=lambda s: None)

        result = adapter.complete(system=VALID_SYSTEM, user="x")

        assert result.usage["prompt_tokens"] == 100
        assert result.usage["completion_tokens"] == 50
        assert result.usage["total_tokens"] == 150
        assert result.usage["reasoning_tokens"] == 20
        assert result.usage["prompt_cache_hit_tokens"] == 10
        assert result.usage["prompt_cache_miss_tokens"] == 90
        assert result.usage["attempts"] == 1

    def test_model_falls_back_to_the_requested_model_when_response_omits_it(self):
        response = _response(content="{}")
        response.model = None
        client = FakeClient([response])
        adapter = DeepSeekAdapter(_cfg(), client=client, sleep=lambda s: None)

        result = adapter.complete(system=VALID_SYSTEM, user="x")

        assert result.model == "deepseek-v4-flash"


class TestCostFormula:
    def test_cost_formula_matches_p1_t08(self):
        cfg = _cfg(LLM_PRICE_IN_PER_M=0.014, LLM_PRICE_OUT_PER_M=0.66)

        assert cost_usd({"prompt_tokens": 1_000_000, "completion_tokens": 100_000}, cfg) == 0.08
        assert cost_usd({"prompt_tokens": 1652, "completion_tokens": 285}, cfg) == 0.00021

    def test_cost_rounds_to_five_decimals(self):
        cfg = _cfg(LLM_PRICE_IN_PER_M=123_456, LLM_PRICE_OUT_PER_M=0.0)

        assert cost_usd({"prompt_tokens": 1, "completion_tokens": 0}, cfg) == 0.12346

    def test_completion_tokens_priced_at_output_rate_not_input_rate(self):
        cfg = _cfg(LLM_PRICE_IN_PER_M=0.66, LLM_PRICE_OUT_PER_M=0.014)

        assert cost_usd({"prompt_tokens": 1_000_000, "completion_tokens": 100_000}, cfg) != 0.08


class TestWallClockDeadline:
    def test_wall_clock_deadline_raises_llm_timeout(self):
        client = SlowClient(delay_s=3)
        adapter = DeepSeekAdapter(
            _cfg(LLM_TIMEOUT_S=1, LLM_RETRY=0), client=client, sleep=lambda s: None
        )

        started = time.monotonic()
        with pytest.raises(LLMTimeout):
            adapter.complete(system=VALID_SYSTEM, user="x")
        elapsed = time.monotonic() - started

        assert elapsed < 1.5

    def test_timeout_is_not_retried(self):
        client = SlowClient(delay_s=3)
        adapter = DeepSeekAdapter(
            _cfg(LLM_TIMEOUT_S=1, LLM_RETRY=2), client=client, sleep=lambda s: None
        )

        with pytest.raises(LLMTimeout):
            adapter.complete(system=VALID_SYSTEM, user="x")

        assert client.call_count == 1


class TestRetriesAndClassification:
    def test_retries_twice_on_5xx_then_raises_transient(self):
        client = FakeClient([_status_error(500), _status_error(502), _status_error(503)])
        pauses: list[float] = []
        adapter = DeepSeekAdapter(_cfg(LLM_RETRY=2), client=client, sleep=pauses.append)

        with pytest.raises(Exception) as excinfo:
            adapter.complete(system=VALID_SYSTEM, user="x")

        assert client.call_count == 3
        assert pauses == [2.0, 4.0]
        assert excinfo.value.status_code == 503
        assert classify(excinfo.value) == "transient"

    def test_retries_on_connection_error(self):
        client = FakeClient([_connection_error(), _connection_error(), _response(content="{}")])
        pauses: list[float] = []
        adapter = DeepSeekAdapter(_cfg(LLM_RETRY=2), client=client, sleep=pauses.append)

        result = adapter.complete(system=VALID_SYSTEM, user="x")

        assert client.call_count == 3
        assert pauses == [2.0, 4.0]
        assert result.content == "{}"
        assert result.usage["attempts"] == 3

    def test_connection_error_exhausted_wraps_as_transient_error(self):
        """DEC-025 note for design note 4's wrapping rule: without it, an exhausted
        `APIConnectionError` would classify transient only via `infra.errors.classify`'s
        UNCLASSIFIED fallback (it carries no `.status_code`) — not deterministically."""
        client = FakeClient([_connection_error(), _connection_error(), _connection_error()])
        adapter = DeepSeekAdapter(_cfg(LLM_RETRY=2), client=client, sleep=lambda s: None)

        with pytest.raises(TransientError) as excinfo:
            adapter.complete(system=VALID_SYSTEM, user="x")

        assert not isinstance(excinfo.value, openai.APIConnectionError)
        assert classify(excinfo.value) == "transient"

    def test_4xx_is_permanent_without_retry(self):
        client = FakeClient([_status_error(400)])
        adapter = DeepSeekAdapter(_cfg(LLM_RETRY=2), client=client, sleep=lambda s: None)

        with pytest.raises(LLMPermanent):
            adapter.complete(system=VALID_SYSTEM, user="x")

        assert client.call_count == 1


class TestMonthlySpendCap:
    def test_cap_refuses_before_any_call(self):
        client = FakeClient([_response(content="{}")])
        adapter = DeepSeekAdapter(
            _cfg(LLM_MONTHLY_USD_CAP=30),
            client=client,
            spent_usd=lambda: 30.0,
            sleep=lambda s: None,
        )

        with pytest.raises(LLMBudgetExceeded):
            adapter.complete(system=VALID_SYSTEM, user="x")

        assert client.call_count == 0

    def test_cap_boundary_is_gte(self):
        over = FakeClient([_response(content="{}")])
        adapter_over = DeepSeekAdapter(
            _cfg(LLM_MONTHLY_USD_CAP=30), client=over, spent_usd=lambda: 30.0, sleep=lambda s: None
        )
        with pytest.raises(LLMBudgetExceeded):
            adapter_over.complete(system=VALID_SYSTEM, user="x")

        under = FakeClient([_response(content="{}")])
        adapter_under = DeepSeekAdapter(
            _cfg(LLM_MONTHLY_USD_CAP=30),
            client=under,
            spent_usd=lambda: 29.999,
            sleep=lambda s: None,
        )
        result = adapter_under.complete(system=VALID_SYSTEM, user="x")

        assert result.content == "{}"
        assert under.call_count == 1

    def test_cap_checked_before_every_attempt_not_only_the_first(self):
        spent = {"value": 0.0}
        client = FakeClient([_connection_error(), _response(content="{}")])
        adapter = DeepSeekAdapter(
            _cfg(LLM_RETRY=2, LLM_MONTHLY_USD_CAP=30),
            client=client,
            spent_usd=lambda: spent["value"],
            sleep=lambda s: spent.__setitem__("value", 30.0),
        )

        with pytest.raises(LLMBudgetExceeded):
            adapter.complete(system=VALID_SYSTEM, user="x")

        assert client.call_count == 1


class TestSystemMustContainJson:
    def test_system_without_json_word_is_refused(self):
        client = FakeClient([_response(content="{}")])
        adapter = DeepSeekAdapter(_cfg(), client=client, sleep=lambda s: None)

        with pytest.raises(LLMPermanent):
            adapter.complete(system="Be a helpful analyst.", user="x")

        assert client.call_count == 0


class TestEstimateTokens:
    def test_estimate_tokens_is_conservative(self):
        text = "x" * 33_564  # docs/smoke-test-D1-nothink.md §2: measured 12,576 prompt tokens

        assert estimate_tokens(text) == math.ceil(33_564 / 2.5)
        assert estimate_tokens(text) >= 12_576

    def test_estimate_tokens_formula_on_a_small_string(self):
        assert estimate_tokens("x" * 10) == 4  # ceil(10 / 2.5)


class TestStructuredLogging:
    def test_log_receives_one_line_per_attempt_and_never_the_prompt(self):
        events: list[dict] = []
        client = FakeClient([_status_error(500), _response(content="{}")])
        adapter = DeepSeekAdapter(
            _cfg(LLM_RETRY=2), client=client, sleep=lambda s: None, log=events.append
        )

        adapter.complete(system=VALID_SYSTEM, user="super secret alert body")

        assert [event["outcome"] for event in events] == ["transient", "ok"]
        for event in events:
            assert set(event) == {"llm", "n", "outcome", "ms"}
            assert "super secret alert body" not in str(event)

    def test_no_log_by_default_does_not_raise(self):
        client = FakeClient([_response(content="{}")])
        adapter = DeepSeekAdapter(_cfg(), client=client, sleep=lambda s: None)

        adapter.complete(system=VALID_SYSTEM, user="x")
