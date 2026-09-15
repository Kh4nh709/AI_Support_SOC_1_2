"""The DeepSeek chat completion call, §7.5 exactly: `json_object`, `LLM_THINKING` as
`extra_body`, a wall-clock deadline the adapter enforces (DEC-033), two retries on
network/5xx, the monthly spend cap checked before any socket opens, cost from `usage`.

Scope out (P3-T04 card): JSON parsing and schema validation (`llm/schemas.py`, P3-T05),
the repair round (`llm/triage.py`, P3-T09), reading `llm_runs` for `spent_usd` (P3-T10),
and all prompt content. This module never imports any of that — `llm` may import
`security`, `infra`, `kb` and nothing else (context pack §4).
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import openai

from app.infra.config import Config
from app.infra.errors import PermanentError, TransientError


@dataclass(frozen=True)
class LLMResult:
    """The same four fields `backend/tests/fakes/llm.py`'s `LLMResult` carries, so every
    caller is written once against either. Re-declared rather than imported: the fake must
    not import the product and the product must not import the fake."""

    content: str  # choices[0].message.content, or "" when absent — never reasoning_content
    model: str  # response.model, falling back to the requested model
    usage: dict  # prompt/completion/total/reasoning tokens, the two cache counters, attempts
    latency_ms: int


class LLMTimeout(TransientError):
    """The `LLM_TIMEOUT_S` wall-clock deadline (DEC-033) expired before the call returned."""


class LLMBudgetExceeded(PermanentError):
    """`spent_usd() >= LLM_MONTHLY_USD_CAP`, checked before this attempt opened a socket."""


class LLMPermanent(PermanentError):
    """A 4xx response, retries exhausted on a permanent error, or a system prompt that
    would make DeepSeek reject `json_object` (no "JSON" in it)."""


def estimate_tokens(text: str) -> int:
    """A conservative pre-send budget check (P3-T09, against `PROMPT_TOTAL_BUDGET_TOKENS`):
    character-based, 2.5 bytes/token against the measured 2.67
    (`docs/smoke-test-D1-nothink.md` §2: 33,564 bytes -> 12,576 prompt tokens). The
    authoritative count is always `usage`, never this estimate."""
    return math.ceil(len(text.encode("utf-8")) / 2.5)


def cost_usd(usage: Mapping[str, Any], cfg: Config) -> float:
    """`usage["prompt_tokens"]` and `usage["completion_tokens"]` (which already includes
    reasoning tokens, billed at the output price) against §6.3's prices, rounded to 5
    decimals — `llm_runs.cost_usd` is `numeric(10,5)`."""
    cost = (
        usage["prompt_tokens"] / 1_000_000 * cfg.LLM_PRICE_IN_PER_M
        + usage["completion_tokens"] / 1_000_000 * cfg.LLM_PRICE_OUT_PER_M
    )
    return round(cost, 5)


def _as_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _usage_dict(usage: Any) -> dict[str, Any]:
    """Flattened per `eval/smoke_test.py`'s `usage_dict`, verbatim rules: `completion_tokens`
    already includes `reasoning_tokens`; the two cache counters are carried, not priced."""
    raw = _as_dict(usage)
    details = _as_dict(raw.get("completion_tokens_details"))
    return {
        "prompt_tokens": int(raw.get("prompt_tokens") or 0),
        "completion_tokens": int(raw.get("completion_tokens") or 0),
        "total_tokens": int(raw.get("total_tokens") or 0),
        "reasoning_tokens": int(details.get("reasoning_tokens") or 0),
        "prompt_cache_hit_tokens": raw.get("prompt_cache_hit_tokens"),
        "prompt_cache_miss_tokens": raw.get("prompt_cache_miss_tokens"),
    }


def _message_content(message: Any) -> str:
    # reasoning_content sits alongside content as a model_extra key in thinking mode
    # (eval/smoke_test.py:836-853) and is never read here: the gate re-derives every
    # verdict from structured_basis, so the reasoning trace is never an input to it.
    if isinstance(message, Mapping):
        return message.get("content") or ""
    return getattr(message, "content", None) or ""


def _classify_attempt(exc: Exception) -> str:
    """ "transient" (retry) or "permanent" (stop now) — §7.5's rule, not `infra.errors.classify`:
    only a connection/timeout error or a 5xx retries; a 4xx, or anything else this adapter does
    not recognise, is treated as permanent so nothing is silently retried past this boundary."""
    if isinstance(exc, (openai.APIConnectionError, openai.APITimeoutError)):
        return "transient"
    status = getattr(exc, "status_code", None)
    if isinstance(status, int) and status >= 500:
        return "transient"
    return "permanent"


class DeepSeekAdapter:
    """One chat completion the §7.5 way: `json_object`, `LLM_THINKING` as `extra_body`,
    a wall-clock deadline around the SDK call, two retries on network/5xx, the monthly
    cap checked before any socket opens."""

    def __init__(
        self,
        cfg: Config,
        *,
        client: Any | None = None,
        spent_usd: Callable[[], float] = lambda: 0.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        log: Callable[[dict], None] | None = None,
    ) -> None:
        self._cfg = cfg
        self._client = (
            client
            if client is not None
            else openai.OpenAI(
                api_key=cfg.LLM_API_KEY,
                base_url=cfg.LLM_BASE_URL,
                timeout=cfg.LLM_TIMEOUT_S,
                max_retries=0,
            )
        )
        self._spent_usd = spent_usd
        self._sleep = sleep
        self._clock = clock
        self._log = log

    def complete(
        self,
        *,
        system: str,
        user: str,
        response_format: dict | None = None,
        timeout_s: float | None = None,
        model: str | None = None,
    ) -> LLMResult:
        if "JSON" not in system:
            raise LLMPermanent(
                'system prompt must contain "JSON" — DeepSeek rejects json_object otherwise'
            )

        resolved_model = model or self._cfg.LLM_MODEL_PROPOSER
        deadline_s = timeout_s or self._cfg.LLM_TIMEOUT_S
        attempts_allowed = 1 + self._cfg.LLM_RETRY

        for attempt in range(1, attempts_allowed + 1):
            if self._spent_usd() >= self._cfg.LLM_MONTHLY_USD_CAP:
                raise LLMBudgetExceeded(
                    f"spent_usd() >= LLM_MONTHLY_USD_CAP={self._cfg.LLM_MONTHLY_USD_CAP}"
                )
            started = self._clock()
            try:
                response = self._call_once(
                    model=resolved_model,
                    system=system,
                    user=user,
                    response_format=response_format,
                    timeout_s=deadline_s,
                )
            except LLMTimeout:
                self._emit(attempt, "timeout", started)
                raise  # design note 3: a timeout is not retried inside the adapter
            except Exception as exc:
                outcome = _classify_attempt(exc)
                self._emit(attempt, outcome, started)
                if outcome == "permanent":
                    raise LLMPermanent(f"DeepSeek call failed: {exc}") from exc
                if attempt == attempts_allowed:
                    if isinstance(exc, (openai.APIConnectionError, openai.APITimeoutError)):
                        # no .status_code: infra.errors.classify would only reach
                        # "transient" via its UNCLASSIFIED default — wrap so the
                        # worker's classification is deterministic (design note 4).
                        raise TransientError(str(exc)) from exc
                    raise  # already carries .status_code >= 500 — classify() is deterministic
                self._sleep(2.0 * attempt)
                continue
            else:
                self._emit(attempt, "ok", started)
                message = response.choices[0].message
                usage = _usage_dict(getattr(response, "usage", None))
                usage["attempts"] = attempt
                return LLMResult(
                    content=_message_content(message),
                    model=getattr(response, "model", None) or resolved_model,
                    usage=usage,
                    latency_ms=int((self._clock() - started) * 1000),
                )
        raise AssertionError("unreachable: attempts_allowed is always >= 1")

    def _call_once(
        self,
        *,
        model: str,
        system: str,
        user: str,
        response_format: dict | None,
        timeout_s: float,
    ) -> Any:
        """The SDK call on a daemon thread; the caller joins with the deadline as the
        timeout. A thread still alive when the join returns is abandoned — it is a
        daemon, and its eventual result lands in `holder`, a fresh dict per call, never
        shared state, so a late result can never reach a later `complete()` call."""
        holder: dict[str, Any] = {}

        def _run() -> None:
            try:
                holder["response"] = self._client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    response_format=response_format or {"type": "json_object"},
                    extra_body={"thinking": {"type": self._cfg.LLM_THINKING}},
                    timeout=timeout_s,
                )
            except Exception as exc:  # noqa: BLE001 — any failure must cross the thread
                # boundary to be classified and re-raised on the caller's side below.
                holder["error"] = exc

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        thread.join(timeout=timeout_s)
        if thread.is_alive():
            raise LLMTimeout(f"model call exceeded {timeout_s} s wall-clock")
        if "error" in holder:
            raise holder["error"]
        return holder["response"]

    def _emit(self, attempt: int, outcome: str, started: float) -> None:
        if self._log is None:
            return
        self._log(
            {
                "llm": "attempt",
                "n": attempt,
                "outcome": outcome,
                "ms": int((self._clock() - started) * 1000),
            }
        )
