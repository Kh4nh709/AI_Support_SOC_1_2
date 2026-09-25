"""P7's evaluation cache, its spend guard and its bounded concurrency (card P7-T02).

`CachingAdapter` wraps anything with `DeepSeekAdapter.complete()`'s keyword-only signature, so
every caller of `adapter.complete(...)` — `llm.triage.propose` and `verify` included — can be
handed one, and a repeated measurement is answered from disk:

* **One formula, not two** (DEC-032, DEC-042). The key is `smoke_test.cache_key(model, system,
  user, thinking)`; the nonce is folded out of `user` by `smoke_test.stable_user`; an entry is read
  back by `smoke_test.load_cached`, from the same `<key>.json` layout. Only the write is new here,
  and it is atomic (a temporary file, then a rename).
* **The thinking mode is part of the key and has no default** anywhere on the key path: without it
  the paired ablation replays one mode's answers for both and reports a null difference.
* **The nonce is folded** because context pack §7.1 makes every build's nonce fresh, so an unfolded
  key would miss on every re-run. A message carrying two distinct boundary nonces is a builder
  defect: it raises `NonceAmbiguous` and is neither sent nor cached.
* **An entry is a measurement**: content, response model, usage, latency and the time of the live
  call, plus digests of the key inputs — never the prompt text (context pack §9). A hit reports the
  recorded usage and latency and is marked `cached=True`, so "cost of the measurement" and "billed
  in this run" stay separable.

`SpendGuard` refuses a live call once this month's spend plus this run's live spend reaches the
cap; hits cost nothing and never trip it. `estimate_cost` / `refuse_if_over` are the brief's "cost
estimate before running". `run_bounded` runs work items at most four at a time (the brief's
ceiling), returns their outcomes in input order, and captures an item's exception on that item.

The cache directory is the harness's argument (`eval/results/cache/`, git-ignored), never a
constant here. Stdlib only; no network — the inner adapter does the calling.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import re
import sys
import tempfile
import threading
from collections.abc import Callable, Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Sibling import by path (build_gold.py's pattern): eval/ is a composition root, not a package on
# sys.path, so this makes `import smoke_test` work from a script and under the tests, which load
# this file with importlib.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import smoke_test
from app.infra.config import Config
from app.llm.adapter import LLMBudgetExceeded, LLMResult, cost_usd

#: §6.3's closed set for `LLM_THINKING` (DEC-032), the smoke test's own tuple.
THINKING_MODES: tuple[str, ...] = smoke_test.THINKING_MODES
#: The brief's ceiling: "concurrency ≤ 4".
MAX_WORKERS = 4
#: Written into every entry; an entry in another format is a miss, never a hit.
ENTRY_FORMAT = "p7-llm-cache/1"

# A boundary is `<untrusted_data nonce="…" …>` or `</untrusted_data nonce="…">` — the form
# `security/wrap.py` emits and `security/linter.py` recognises; `secrets.token_hex(8)` is 16
# lowercase hex. Only the tag is read: block content is HTML-escaped, so it never holds a literal
# `<`, but it is escaped with quote=False, so an attacker's own `nonce="…"` text survives inside a
# block — matching the bare attribute would call that a second nonce and refuse the message.
_BOUNDARY_NONCE = re.compile(r'</?untrusted_data nonce="([0-9a-f]{16})"')

# One lock per key, shared by every CachingAdapter in the process: concurrent misses on one key
# make one live call and the others are served the entry it wrote, so a run and its re-run give
# every item the same answer. Re-entrant, so a nested wrapper cannot deadlock itself. An
# evaluation process sees a few thousand keys at most, so the registry is never pruned.
_KEY_LOCKS: dict[str, Any] = {}
_KEY_LOCKS_GUARD = threading.Lock()


def _key_lock(key: str) -> Any:
    with _KEY_LOCKS_GUARD:
        lock = _KEY_LOCKS.get(key)
        if lock is None:
            lock = _KEY_LOCKS[key] = threading.RLock()
        return lock


class NonceAmbiguous(ValueError):
    """Two or more distinct boundary nonces in one message: a build carries exactly one (§7.1),
    so this is a builder defect. Such a message is never sent through the cache, never cached."""


class CostRefused(RuntimeError):
    """The run's cost estimate is more than the monthly cap has left."""


def fold_nonce(text: str) -> str:
    """`text` with its build's nonce replaced by ``NONCE`` everywhere (`smoke_test.stable_user`).

    The nonce is the value in the `nonce="<16 hex>"` attribute of the message's `untrusted_data`
    boundary tags. No boundary: `text` unchanged. Two or more distinct values: `NonceAmbiguous`
    (the message names how many, never which, and never the text).
    """
    found = set(_BOUNDARY_NONCE.findall(text))
    if not found:
        return text
    if len(found) > 1:
        raise NonceAmbiguous(
            f"{len(found)} distinct boundary nonces in one message; one build carries exactly one "
            "(context pack §7.1) — refused: not sent, not cached"
        )
    return smoke_test.stable_user(text, found.pop())


@dataclass(frozen=True)
class CachedResult(LLMResult):
    """`LLMResult`'s four fields, plus where this one came from. `cached=True`: read from the
    entry, no call made, nothing billed in this run, and `usage`/`latency_ms` are the recorded
    measurement's. `cached=False`: the inner adapter was called live. `key` names the entry."""

    cached: bool
    key: str


class SpendGuard:
    """Refuses a live call when `month_spend_usd() + this run's live spend >= cap_usd`.

    `month_spend_usd` is what the month has already spent elsewhere (the pilot's `llm_runs`, say).
    The evaluation writes no `llm_runs` (P7-tasks §3 item 2), so this run's own live spend is
    tracked here, priced with `adapter.cost_usd`. A cached hit is never checked and never recorded.
    Thread-safe. As with `DeepSeekAdapter`'s own cap, the check precedes the call and a call's cost
    is known only after it returns, so a run can end past the cap by what the calls in flight at
    the last passing check cost: at most one call on one worker, at most `MAX_WORKERS` calls under
    `run_bounded`. A non-finite month spend is refused, never read as "under the cap".
    """

    def __init__(self, month_spend_usd: Callable[[], float], cap_usd: float, cfg: Config) -> None:
        if not math.isfinite(cap_usd):
            raise ValueError(f"cap_usd must be finite, got {cap_usd!r}")
        self._month_spend_usd = month_spend_usd
        self._cap_usd = float(cap_usd)
        self._cfg = cfg
        self._live_usd = 0.0
        self._lock = threading.Lock()

    @property
    def live_spent_usd(self) -> float:
        """What this run has spent on live calls so far."""
        with self._lock:
            return self._live_usd

    def total_usd(self) -> float:
        """Month spend plus this run's live spend — the value to hand `DeepSeekAdapter` as
        `spent_usd` so the adapter's own cap check sees the evaluation's spend too."""
        return float(self._month_spend_usd()) + self.live_spent_usd

    def check(self) -> None:
        """Raise `LLMBudgetExceeded` if a live call may not start now."""
        month = float(self._month_spend_usd())
        live = self.live_spent_usd
        if not math.isfinite(month):
            raise LLMBudgetExceeded(f"month_spend_usd() returned {month!r}: refusing to spend")
        if month + live >= self._cap_usd:
            raise LLMBudgetExceeded(
                f"month spend ${month:.5f} + this run's live spend ${live:.5f} "
                f">= LLM_MONTHLY_USD_CAP ${self._cap_usd:.5f}"
            )

    def record(self, usage: Mapping[str, Any]) -> float:
        """Add one live call's cost (`adapter.cost_usd`) to this run's spend; return that cost."""
        cost = cost_usd(usage, self._cfg)
        with self._lock:
            self._live_usd += cost
        return cost


def _check_amounts(**amounts: float) -> None:
    for name, value in amounts.items():
        if not math.isfinite(value) or value < 0:
            raise ValueError(f"{name} must be a finite number >= 0, got {value!r}")


def estimate_cost(n_alerts: int, calls_per_alert: float, usd_per_call: float) -> float:
    """The brief's "cost estimate before running": alerts × calls per alert × $ per call.
    `calls_per_alert` may be fractional, to carry a repair margin (P7-tasks §4: +10 %)."""
    _check_amounts(n_alerts=n_alerts, calls_per_alert=calls_per_alert, usd_per_call=usd_per_call)
    return n_alerts * calls_per_alert * usd_per_call


def refuse_if_over(estimate: float, month_spend: float, cap: float) -> None:
    """Raise `CostRefused`, naming the three numbers, when `estimate` is more than `cap -
    month_spend`. An estimate of exactly what is left is allowed: every call would start under
    the cap."""
    _check_amounts(estimate=estimate, month_spend=month_spend, cap=cap)
    remaining = cap - month_spend
    if estimate > remaining:
        raise CostRefused(
            f"estimated cost ${estimate:.5f} is more than the ${remaining:.5f} left this month: "
            f"${month_spend:.5f} already spent of the ${cap:.5f} LLM_MONTHLY_USD_CAP — not running"
        )


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _write_atomic(path: Path, entry: Mapping[str, Any]) -> None:
    """A temporary file in the entry's own directory, flushed and fsynced, then `os.replace`d
    onto the entry: a reader sees the whole entry or none. On any failure the temporary file is
    removed and the error re-raised."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.stem}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(entry, handle, indent=2, ensure_ascii=False, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_name)
        raise


class CachingAdapter:
    """`DeepSeekAdapter.complete()`'s keyword-only signature over an on-disk cache.

    `thinking` is required and has no default; it must be one of `THINKING_MODES` and, when the
    inner adapter carries a `Config` (`DeepSeekAdapter` keeps it as `_cfg`), equal to the
    `LLM_THINKING` that adapter sends — otherwise every entry would be filed under the wrong mode.
    The request model is resolved the way `DeepSeekAdapter` resolves it (`model or
    cfg.LLM_MODEL_PROPOSER`); an inner adapter with no `Config` needs an explicit `model=`, and
    `llm.triage.propose`/`verify` always pass one. The key never carries a guessed model.

    Every result is also appended to `results` (the side record): `propose`/`verify` wrap a result
    in a `Proposal` that drops the `cached` attribute, so a harness reads `results` instead — one
    CachingAdapter per work item gives per-item records (they share the directory, the key locks
    and the `SpendGuard`).
    """

    def __init__(
        self,
        inner: Any,
        *,
        cache_dir: Path,
        thinking: str,
        spend: SpendGuard | None = None,
    ) -> None:
        if thinking not in THINKING_MODES:
            raise ValueError(
                f"thinking must be one of {'|'.join(THINKING_MODES)}, got {thinking!r} — it is "
                "part of every cache key (DEC-042) and has no default"
            )
        inner_cfg = getattr(inner, "_cfg", None)
        if not isinstance(inner_cfg, Config):  # a fake, a mock, a wrapper: nothing to read
            inner_cfg = None
        if inner_cfg is not None and inner_cfg.LLM_THINKING != thinking:
            raise ValueError(
                f"thinking={thinking!r} but the inner adapter sends LLM_THINKING="
                f"{inner_cfg.LLM_THINKING!r}: its answers would be filed under the other mode "
                "(DEC-042)"
            )
        self._inner = inner
        self._cache_dir = Path(cache_dir)
        self._thinking = thinking
        self._spend = spend
        self._default_model = inner_cfg.LLM_MODEL_PROPOSER if inner_cfg is not None else None
        self._results: list[CachedResult] = []
        self._results_lock = threading.Lock()

    @property
    def thinking(self) -> str:
        return self._thinking

    @property
    def results(self) -> list[CachedResult]:
        """Every result returned so far, in call order (a copy)."""
        with self._results_lock:
            return list(self._results)

    def key_for(self, *, system: str, user: str, model: str | None = None) -> str:
        """The key of this request's entry: `smoke_test.cache_key` over the resolved request
        model, the system prompt (the template), the nonce-folded user message and the mode."""
        return self._key_inputs(system, user, model)[0]

    def complete(
        self,
        *,
        system: str,
        user: str,
        response_format: dict | None = None,
        timeout_s: float | None = None,
        model: str | None = None,
    ) -> CachedResult:
        key, request_model, folded = self._key_inputs(system, user, model)
        request = {
            "model": request_model,
            "thinking": self._thinking,
            "system_sha256": _sha256(system),
            "user_sha256": _sha256(folded),
        }
        entry = self._load(key, request)
        cached = entry is not None
        if entry is None:
            with _key_lock(key):
                entry = self._load(key, request)  # measured by another thread meanwhile?
                cached = entry is not None
                if entry is None:
                    entry = self._measure(
                        key,
                        request,
                        system=system,
                        user=user,
                        response_format=response_format,
                        timeout_s=timeout_s,
                        model=request_model,
                    )
        result = CachedResult(
            content=entry["content"],
            model=entry["model"],
            usage=dict(entry["usage"]),
            latency_ms=entry["latency_ms"],
            cached=cached,
            key=key,
        )
        with self._results_lock:
            self._results.append(result)
        return result

    def _key_inputs(self, system: str, user: str, model: str | None) -> tuple[str, str, str]:
        request_model = model or self._default_model
        if not request_model:
            raise ValueError(
                "model=None and the inner adapter carries no Config to resolve it from: pass "
                "model= (llm.triage.propose/verify always do) — the key never guesses a model"
            )
        folded = fold_nonce(user)
        key = smoke_test.cache_key(request_model, system, folded, self._thinking)
        return key, request_model, folded

    def _load(self, key: str, request: Mapping[str, str]) -> dict[str, Any] | None:
        """The entry recorded for exactly this request, or None. A missing, unparsable or
        foreign entry (another format, other key inputs, a field of the wrong type) is a miss:
        the call is measured again and the entry replaced whole."""
        try:
            entry = smoke_test.load_cached(self._cache_dir, key)
        except ValueError:  # undecodable bytes; load_cached already maps OSError and bad JSON
            return None
        if (
            isinstance(entry, dict)
            and entry.get("format") == ENTRY_FORMAT
            and entry.get("key") == key
            and entry.get("request") == request
            and isinstance(entry.get("content"), str)
            and isinstance(entry.get("model"), str)
            and isinstance(entry.get("usage"), dict)
            and type(entry.get("latency_ms")) is int
        ):
            return entry
        return None

    def _measure(
        self,
        key: str,
        request: Mapping[str, str],
        *,
        system: str,
        user: str,
        response_format: dict | None,
        timeout_s: float | None,
        model: str,
    ) -> dict[str, Any]:
        """One live call through the inner adapter, recorded. The spend is checked before the
        call and recorded as soon as it returns — before the write, which may still fail."""
        if self._spend is not None:
            self._spend.check()
        called_at = datetime.now(UTC).isoformat(timespec="milliseconds")
        live = self._inner.complete(
            system=system,
            user=user,
            response_format=response_format,
            timeout_s=timeout_s,
            model=model,
        )
        if self._spend is not None:
            self._spend.record(live.usage)
        entry = {
            "format": ENTRY_FORMAT,
            "key": key,
            "request": dict(request),
            "called_at": called_at,
            "content": live.content,
            "model": live.model,
            "usage": dict(live.usage),
            "latency_ms": int(live.latency_ms),
        }
        _write_atomic(self._cache_dir / f"{key}.json", entry)
        return entry


@dataclass(frozen=True)
class Outcome:
    """One work item's outcome: `value` when `fn(item)` returned, `error` when it raised."""

    index: int
    item: Any
    value: Any = None
    error: Exception | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


def run_bounded(
    items: Iterable[Any], fn: Callable[[Any], Any], *, max_workers: int = MAX_WORKERS
) -> list[Outcome]:
    """`fn(item)` for every item, at most `max_workers` at a time, outcomes in input order. An
    exception in one item is captured on that item's `Outcome`, never aborts the others."""
    if isinstance(max_workers, bool) or not isinstance(max_workers, int):
        raise TypeError(f"max_workers must be an int, got {max_workers!r}")
    if not 1 <= max_workers <= MAX_WORKERS:
        raise ValueError(
            f"max_workers must be 1..{MAX_WORKERS} (the brief's concurrency ceiling), "
            f"got {max_workers}"
        )
    work = list(enumerate(items))

    def one(pair: tuple[int, Any]) -> Outcome:
        index, item = pair
        try:
            return Outcome(index, item, value=fn(item))
        except Exception as exc:  # noqa: BLE001 — captured on its item, the others go on
            return Outcome(index, item, error=exc)

    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="llm-cache") as pool:
        return list(pool.map(one, work))
