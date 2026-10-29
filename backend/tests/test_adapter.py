"""Unit tests for app.llm.adapter — a fake OpenAI client throughout; no network, no sleep.

Every retry/backoff test injects `sleep` to record pauses instead of waiting; only the
wall-clock deadline tests (design note 3) use a real clock, because that is the thing
under test.
"""

from __future__ import annotations

import dataclasses
import json
import math
import time
import uuid
from contextlib import contextmanager
from functools import partial
from types import SimpleNamespace

import httpx
import openai
import psycopg
import pytest
from app.infra.config import Config
from app.infra.errors import TransientError, classify
from app.infra.settings import (
    KEYS,
    Limits,
    LimitSource,
    SettingsUnavailable,
    effective_limits,
)
from app.llm import investigate as llm_investigate
from app.llm.adapter import (
    DeepSeekAdapter,
    LLMBudgetExceeded,
    LLMPermanent,
    LLMTimeout,
    LLMUnavailable,
    cost_usd,
    estimate_tokens,
)

from tests.test_investigate import _fake_dossier, _investigate_v2

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

    def test_402_is_unavailable_a_kind_of_permanent(self):
        """A 402 (Payment Required: no balance / exhausted quota) raises LLMUnavailable, so ① can
        catch it first and record the alert `unavailable` with the provider's message instead of a
        hard failure (S8, DEC-211). It is also an LLMPermanent (R4, INT-T01): every other caller that
        catches LLMPermanent - ②, the RAG lookup, the knowledge draft - then sees a 402 as the
        permanent model refusal it is, not as a linter fault. One call, no retry."""
        client = FakeClient([_status_error(402)])
        adapter = DeepSeekAdapter(_cfg(LLM_RETRY=2), client=client, sleep=lambda s: None)

        with pytest.raises(LLMUnavailable) as excinfo:
            adapter.complete(system=VALID_SYSTEM, user="x")

        assert issubclass(LLMUnavailable, LLMPermanent)
        assert isinstance(excinfo.value, LLMPermanent)
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


# ── P11-T03 · the editable, fail-closed limits (DEC-200 item 3) ─────────────────────────────


def _limits(*, cap_usd=30, quota_per_24h=30, timeout_s=5) -> Limits:
    sources = {key: LimitSource("env", None, None) for key in KEYS}
    return Limits(cap_usd, quota_per_24h, timeout_s, sources)


class _CountingLimits:
    """A `limits` callable that counts its calls and answers the current `value` — or raises
    `SettingsUnavailable` while `unreadable` is set."""

    def __init__(self, value: Limits | None = None) -> None:
        self.value = value or _limits()
        self.unreadable = False
        self.calls = 0

    def __call__(self) -> Limits:
        self.calls += 1
        if self.unreadable:
            raise SettingsUnavailable("settings table unreadable")
        return self.value


class _UnreadableConn:
    """A connection whose read of `settings` fails like a dropped one: the real
    `effective_limits` over it must raise `SettingsUnavailable`."""

    info = SimpleNamespace(transaction_status=psycopg.pq.TransactionStatus.INTRANS)

    @contextmanager
    def transaction(self):
        yield self

    def execute(self, *args, **kwargs):
        raise psycopg.OperationalError("server closed the connection unexpectedly")


def _complete_expecting_a_refusal_without_a_call(adapter, client) -> LLMBudgetExceeded:
    """One `complete()` over limits that cannot be read: it must be refused as
    `LLMBudgetExceeded` and the client must not have been touched. The client count is checked
    first, so a silent fallback to `.env` shows up as the call it made."""
    refusal = None
    try:
        adapter.complete(system=VALID_SYSTEM, user="x")
    except LLMBudgetExceeded as exc:
        refusal = exc
    assert (
        client.call_count == 0
    ), f"{client.call_count} model call(s) went out although the limits could not be read"
    assert refusal is not None, "complete() answered although the limits could not be read"
    return refusal


class TestEditableLimitsFailClosed:
    def test_unreadable_limits_stop_the_call_before_any_socket(self):
        client = FakeClient([_response(content="{}")])
        limits = _CountingLimits()
        limits.unreadable = True
        adapter = DeepSeekAdapter(_cfg(), client=client, limits=limits, sleep=lambda s: None)

        with pytest.raises(LLMBudgetExceeded, match="limits unreadable — fail closed"):
            adapter.complete(system=VALID_SYSTEM, user="x")

        assert client.call_count == 0

    def test_the_real_accessor_on_a_failing_read_never_reaches_the_client(self):
        """The fail-closed chain end to end, minus the SQL: a failing read inside the real
        `effective_limits` — and `.env` carries a perfectly good cap and timeout. A silent
        fallback to `.env` would send the request."""
        client = FakeClient([_response(content="{}")])
        cfg = _cfg()
        adapter = DeepSeekAdapter(
            cfg,
            client=client,
            limits=partial(effective_limits, _UnreadableConn(), cfg),
            sleep=lambda s: None,
        )

        _complete_expecting_a_refusal_without_a_call(adapter, client)

    def test_limits_are_read_once_per_attempt_and_before_any_socket(self):
        order: list[str] = []

        class _Client(FakeClient):
            def _create(self, **kwargs):
                order.append("socket")
                return super()._create(**kwargs)

        client = _Client([_connection_error(), _response(content="{}")])
        limits = _CountingLimits()

        def spying() -> Limits:
            order.append("limits")
            return limits()

        adapter = DeepSeekAdapter(
            _cfg(LLM_RETRY=2), client=client, limits=spying, sleep=lambda s: None
        )

        adapter.complete(system=VALID_SYSTEM, user="x")

        assert order == ["limits", "socket", "limits", "socket"]
        assert limits.calls == 2

    def test_a_limits_read_that_fails_on_the_retry_stops_the_second_attempt(self):
        client = FakeClient([_connection_error(), _response(content="{}")])
        limits = _CountingLimits()
        adapter = DeepSeekAdapter(
            _cfg(LLM_RETRY=2),
            client=client,
            limits=limits,
            sleep=lambda s: setattr(limits, "unreadable", True),
        )

        with pytest.raises(LLMBudgetExceeded, match="fail closed"):
            adapter.complete(system=VALID_SYSTEM, user="x")

        assert client.call_count == 1  # the first attempt only; the retry opened no socket

    def test_the_cap_comes_from_limits_not_from_cfg(self):
        refused = FakeClient([_response(content="{}")])
        adapter_refused = DeepSeekAdapter(
            _cfg(LLM_MONTHLY_USD_CAP=30),  # `.env` would let 12 USD through
            client=refused,
            limits=_CountingLimits(_limits(cap_usd=10)),
            spent_usd=lambda: 12.0,
            sleep=lambda s: None,
        )
        with pytest.raises(LLMBudgetExceeded, match="LLM_MONTHLY_USD_CAP=10"):
            adapter_refused.complete(system=VALID_SYSTEM, user="x")
        assert refused.call_count == 0

        allowed = FakeClient([_response(content="{}")])
        adapter_allowed = DeepSeekAdapter(
            _cfg(LLM_MONTHLY_USD_CAP=5),  # `.env` would refuse 12 USD
            client=allowed,
            limits=_CountingLimits(_limits(cap_usd=100)),
            spent_usd=lambda: 12.0,
            sleep=lambda s: None,
        )
        adapter_allowed.complete(system=VALID_SYSTEM, user="x")
        assert allowed.call_count == 1

    def test_the_deadline_comes_from_limits_when_the_caller_passes_none(self):
        client = FakeClient([_response(content="{}")])
        adapter = DeepSeekAdapter(
            _cfg(LLM_TIMEOUT_S=5),
            client=client,
            limits=_CountingLimits(_limits(timeout_s=77)),
            sleep=lambda s: None,
        )

        adapter.complete(system=VALID_SYSTEM, user="x")

        assert client.calls[0]["timeout"] == 77

    def test_a_caller_supplied_deadline_still_wins_over_limits(self):
        client = FakeClient([_response(content="{}")])
        adapter = DeepSeekAdapter(
            _cfg(),
            client=client,
            limits=_CountingLimits(_limits(timeout_s=77)),
            sleep=lambda s: None,
        )

        adapter.complete(system=VALID_SYSTEM, user="x", timeout_s=9)

        assert client.calls[0]["timeout"] == 9

    def test_a_change_of_limits_is_seen_by_the_next_call(self):
        client = FakeClient([_response(content="{}"), _response(content="{}")])
        limits = _CountingLimits(_limits(cap_usd=30, timeout_s=20))
        adapter = DeepSeekAdapter(
            _cfg(), client=client, limits=limits, spent_usd=lambda: 15.0, sleep=lambda s: None
        )

        adapter.complete(system=VALID_SYSTEM, user="x")
        limits.value = _limits(cap_usd=10, timeout_s=40)
        with pytest.raises(LLMBudgetExceeded):
            adapter.complete(system=VALID_SYSTEM, user="x")

        assert client.call_count == 1
        assert client.calls[0]["timeout"] == 20

    def test_without_limits_the_adapter_behaves_exactly_as_on_cfg(self):
        client = FakeClient([_response(content="{}")])
        adapter = DeepSeekAdapter(
            _cfg(LLM_TIMEOUT_S=13, LLM_MONTHLY_USD_CAP=30),
            client=client,
            spent_usd=lambda: 29.0,
            sleep=lambda s: None,
        )

        adapter.complete(system=VALID_SYSTEM, user="x")

        assert client.calls[0]["timeout"] == 13
        capped = DeepSeekAdapter(
            _cfg(LLM_MONTHLY_USD_CAP=30),
            client=FakeClient([_response(content="{}")]),
            spent_usd=lambda: 30.0,
            sleep=lambda s: None,
        )
        with pytest.raises(LLMBudgetExceeded):
            capped.complete(system=VALID_SYSTEM, user="x")


class TestInvestigateTakesItsDeadlineFromTheLimits:
    def test_the_call_and_its_repair_run_under_the_limits_deadline(self):
        """`llm/investigate.py` no longer reads `LLM_TIMEOUT_S` off the config: both sends (the
        call and its one repair) run under the deadline the limits say, as the real adapter
        resolves it. Red step: put `timeout_s=cfg.LLM_TIMEOUT_S` back and the client sees 5."""
        dossier = _fake_dossier()
        bad = _investigate_v2()
        del bad["confidence"]
        client = FakeClient(
            [
                _response(content=json.dumps(bad)),
                _response(content=json.dumps(_investigate_v2())),
            ]
        )
        cfg = _cfg(LLM_TIMEOUT_S=5)
        adapter = DeepSeekAdapter(
            cfg, client=client, limits=_CountingLimits(_limits(timeout_s=77)), sleep=lambda s: None
        )

        result = llm_investigate.investigate(adapter, dossier, nonce=dossier.nonce, cfg=cfg)

        assert result.calls == 2
        assert [call["timeout"] for call in client.calls] == [77, 77]

    def test_unreadable_limits_stop_the_investigation_before_any_socket(self):
        dossier = _fake_dossier()
        client = FakeClient([_response(content=json.dumps(_investigate_v2()))])
        limits = _CountingLimits()
        limits.unreadable = True
        cfg = _cfg()
        adapter = DeepSeekAdapter(cfg, client=client, limits=limits, sleep=lambda s: None)

        with pytest.raises(LLMBudgetExceeded):
            llm_investigate.investigate(adapter, dossier, nonce=dossier.nonce, cfg=cfg)

        assert client.call_count == 0


@pytest.mark.db
class TestTheAdapterOverTheRealAccessor:
    def test_a_missing_settings_table_stops_the_call_and_the_transaction_survives(self, db):
        db.execute("DROP TABLE settings")  # rolled back with the test's transaction
        client = FakeClient([_response(content="{}")])
        cfg = _cfg()
        adapter = DeepSeekAdapter(
            cfg,
            client=client,
            limits=partial(effective_limits, db, cfg),
            sleep=lambda s: None,
        )

        refusal = _complete_expecting_a_refusal_without_a_call(adapter, client)

        assert "fail closed" in str(refusal)
        assert db.execute("SELECT 1").fetchone() == (1,)  # the caller's transaction is usable

    def test_a_saved_row_changes_the_cap_and_the_timeout_on_the_next_call(self, db):
        user_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO users (user_id, username, display_name, role, password_hash) "
            "VALUES (%s, %s, 'Admin', 'admin', 'x')",
            (user_id, f"user-{user_id[:8]}"),
        )
        client = FakeClient([_response(content="{}"), _response(content="{}")])
        cfg = _cfg(LLM_MONTHLY_USD_CAP=30, LLM_TIMEOUT_S=5)
        adapter = DeepSeekAdapter(
            cfg,
            client=client,
            limits=partial(effective_limits, db, cfg),
            spent_usd=lambda: 20.0,
            sleep=lambda s: None,
        )

        adapter.complete(system=VALID_SYSTEM, user="x")  # 20 < 30, no row yet
        db.execute(
            "INSERT INTO settings (key, value, updated_by) VALUES "
            "('LLM_MONTHLY_USD_CAP', 15, %s), ('LLM_TIMEOUT_S', 90, %s)",
            (user_id, user_id),
        )
        with pytest.raises(LLMBudgetExceeded):  # 20 >= 15 now
            adapter.complete(system=VALID_SYSTEM, user="x")

        assert client.call_count == 1
        assert client.calls[0]["timeout"] == 5
