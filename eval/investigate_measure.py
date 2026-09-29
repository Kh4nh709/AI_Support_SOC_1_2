#!/usr/bin/env python3
"""P5-T02 — the DEC-032 amendment (b) measurement: what pipeline ② (``investigate_v2``)
actually costs at its own prompt size, ``CASE_PROMPT_BUDGET_TOKENS = 60_000``, against
the ≈ 12,828-token ceiling the real corpus can ever reach (``P5-tasks.md`` §1).

Design (docs/plan/tasks/P5/P5-T02.prompt.md):

* The content comes **only** from six committed fixtures under
  ``backend/tests/fixtures/`` — never the database (``soc_dev`` is the live pilot's)
  and never the 30-day archive (not on this host). This script opens no database
  connection and sends no alert anywhere except the live LLM call it exists to make.
* The prompt follows §7.6's nine-block shape (case header as facts, every cluster
  with ``raw_log``, timeline, entities, ±2h correlation, Tier-1 decisions, playbooks,
  notes + previous ② result, the out-of-block "not available" sentence), every
  free-text block wrapped through ``app.security.wrap.untrusted_block`` with one
  session nonce, and grown to the requested budget by **repeating whole clusters**
  from the fixture set, each with a distinct synthetic ``alert_id``, until
  ``tokens(user) + tokens(system)`` is within ± 2 % of the target. The token
  estimate is the crude ``len(text) / 4``, rounded — the exact byte count is always
  printed alongside it so a reader can redo the arithmetic with a real tokeniser.
* Sending goes through ``app.llm.adapter.DeepSeekAdapter`` — never a hand-rolled
  client — so the measurement inherits DEC-033's wall-clock deadline, the retry
  policy and the monthly-cap check shape production will have. This script has no
  access to the real month-to-date spend (that lives in ``llm_runs`` on ``soc_dev``,
  which this card may not query), so the adapter's ``spent_usd`` callback reflects
  only this run's own running total; the guard that actually protects a live run is
  ``--max-spend-usd`` (default 0.50), checked before every call.

Run it from the repository root::

    PYTHONPATH=backend python3 eval/investigate_measure.py --dry-run --budget-tokens 60000
    PYTHONPATH=backend python3 eval/investigate_measure.py --calls 30 --arms 60000,12800 \\
        --report docs/investigate-size-class.md --env-file ../AI_Support_SOC_1_2/.env

Exit codes: 0 ok · 2 configuration or budget-floor problem · 5 the spend guard tripped.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.domain.alert import severity_from_level
from app.infra.config import Config
from app.infra.config import load as load_config
from app.llm import adapter as llm_adapter
from app.llm import schemas
from app.llm.builder import ENUM_VALUES
from app.security import wrap

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENV_FILE = REPO_ROOT / ".env"
DEFAULT_CACHE_DIR = REPO_ROOT / "eval" / "results" / "investigate"
FIXTURES_DIR = REPO_ROOT / "backend" / "tests" / "fixtures"
SYSTEM_TEMPLATE = REPO_ROOT / "backend" / "app" / "llm" / "templates" / "investigate_system.txt"

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_BUDGET = 5

DEFAULT_ARMS = "60000,12800"
DEFAULT_CALLS = 30
DEFAULT_MAX_SPEND_USD = 0.50
TOLERANCE = 0.02  # design note 2: ± 2 %

# The six fixtures design note 1 names, and from nothing else. Order fixed: it is
# also the cycling order the padding loop repeats.
FIXTURE_FILES: tuple[str, ...] = (
    "indexer_sample_rule92601.json",
    "indexer_sample_rule5503.json",
    "indexer_sample_rule5760.json",
    "indexer_sample_rule521.json",
    "indexer_sample_rule591.json",
    "alert_40112.json",
)

# A category per fixture — cosmetic content for this byte-budget measurement, not a
# claim about the real category resolver (`app.ingest.category`, untouched here).
FIXTURE_CATEGORY: dict[str, str] = {
    "indexer_sample_rule92601.json": "policy_violation",
    "indexer_sample_rule5503.json": "suspicious_login",
    "indexer_sample_rule5760.json": "suspicious_login",
    "indexer_sample_rule521.json": "malware",
    "indexer_sample_rule591.json": "unknown",
    "alert_40112.json": "ssh_brute_force",
}

# A fixed 16-hex-char nonce used only for *sizing* — planning how many clusters are
# needed. Length, not value, is what affects prompt size, so this keeps the padding
# loop deterministic; every live call still gets its own `wrap.new_nonce()` (§6.5:
# "nonce regenerated per attempt").
SIZING_NONCE = "0" * 16

# ---------------------------------------------------------------------------
# the nine-block template vocabulary (§7.6) — shared with the linter (design note 8)
# ---------------------------------------------------------------------------

HEADING_CASE = "## Case"
HEADING_CLUSTERS = "## Cụm cảnh báo"
HEADING_TIMELINE = "## Dòng thời gian"
HEADING_ENTITIES = "## Thực thể"
HEADING_CORRELATION = "## Tương quan ±2h"
HEADING_TIER1 = "## Quyết định Tier-1"
HEADING_PLAYBOOK = "## Playbook"
HEADING_NOTES = "## Ghi chú và ② trước đó"
NOT_AVAILABLE_SENTENCE = (
    "Không có sẵn trong phép đo này: tra cứu inventory thời gian thực, lịch sử 7 ngày "
    "theo thực thể từ cơ sở dữ liệu, và kho lưu trữ 30 ngày — nội dung trên chỉ dựng từ "
    "các fixture đã commit trong backend/tests/fixtures/."
)
CASE_ID = "1"
CASE_CATEGORY = FIXTURE_CATEGORY[FIXTURE_FILES[0]]
OPENED_AT = "2026-09-29T12:00:00+07:00"

FACT_LABELS: tuple[str, ...] = (
    "case_id",
    "opened_at",
    "cluster_count",
    "alert_count",
    "category",
    "cluster_id",
    "alert_id",
    "rule_id",
    "rule_level",
    "severity",
)

TEMPLATE_CONSTANTS: frozenset[str] = frozenset(
    {
        HEADING_CASE,
        HEADING_CLUSTERS,
        HEADING_TIMELINE,
        HEADING_ENTITIES,
        HEADING_CORRELATION,
        HEADING_TIER1,
        HEADING_PLAYBOOK,
        HEADING_NOTES,
        NOT_AVAILABLE_SENTENCE,
        *(f"{label}:" for label in FACT_LABELS),
    }
)

# Reused wholesale from the typed ① builder (app.llm.builder): the DB CHECK-set
# vocabulary, so "severity: critical" / "category: policy_violation" pass the
# linter without this module inventing a second copy of §6.1's enums.
LINT_ENUM_VALUES: frozenset[str] = frozenset(ENUM_VALUES)


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FixtureAlert:
    fixture_name: str
    alert_id: str
    rule_id: str
    rule_level: int
    rule_description: str
    full_log: str
    agent_name: str
    manager_name: str
    category: str


def _load_one_fixture(path: Path) -> FixtureAlert:
    doc = json.loads(path.read_text(encoding="utf-8"))
    src = doc.get("_source") or {}
    rule = src.get("rule") or {}
    agent = src.get("agent") or {}
    manager = src.get("manager") or {}
    return FixtureAlert(
        fixture_name=path.name,
        alert_id=str(src.get("id") or doc.get("_id") or "0.0"),
        rule_id=str(rule.get("id") or "0"),
        rule_level=int(rule.get("level") or 0),
        rule_description=str(rule.get("description") or ""),
        full_log=str(src.get("full_log") or ""),
        agent_name=str(agent.get("name") or ""),
        manager_name=str(manager.get("name") or ""),
        category=FIXTURE_CATEGORY[path.name],
    )


def load_fixtures(fixtures_dir: Path = FIXTURES_DIR) -> list[FixtureAlert]:
    """The six committed fixtures design note 1 names, in ``FIXTURE_FILES`` order.

    Raises ``FileNotFoundError`` naming the missing file — never silently skips one,
    which would quietly shrink the fixture pool the padding loop cycles through.
    """
    fixtures = []
    for name in FIXTURE_FILES:
        path = fixtures_dir / name
        if not path.is_file():
            raise FileNotFoundError(f"investigate_measure: missing fixture {path}")
        fixtures.append(_load_one_fixture(path))
    return fixtures


def build_system_text(template_path: Path = SYSTEM_TEMPLATE) -> str:
    """``investigate_system.txt`` as it is on ``main`` today, plus the rendered
    ``investigate_v2`` schema — the same planning-decision-14 shape
    ``app.llm.triage._system_prompt`` uses for ①, so the model is actually told the
    schema it is asked to answer in (the template's own line says "theo đúng schema
    được cho"). P5-T04 owns rewriting the template; this only reads it."""
    text = template_path.read_text(encoding="utf-8")
    return f"{text}\n\n## Schema investigate_v2\n{schemas.render('investigate_v2')}"


# ---------------------------------------------------------------------------
# the token estimate — design note 2: len(text) / 4, rounded, the crude estimator
# the card cites eval/smoke_test.py for. It is not actually there (recorded as a
# deviation in the report); this module implements exactly the formula the card
# specifies regardless.
# ---------------------------------------------------------------------------


def estimate_tokens(text: str) -> int:
    return round(len(text) / 4)


def _total_tokens(system_text: str, user_text: str) -> int:
    return estimate_tokens(system_text) + estimate_tokens(user_text)


# ---------------------------------------------------------------------------
# building the nine-block dossier
# ---------------------------------------------------------------------------


def _fact(label: str, value: str) -> str:
    return f"{label}: {value}"


def _synthetic_alert_id(base_id: str, copy_index: int) -> str:
    """A distinct id per repetition (design note 2), keeping the ``\\d+\\.\\d+``
    shape the linter's ``alert_id`` pattern expects: the copy index is appended to
    the fractional part, never adding a second dot."""
    if copy_index == 0:
        return base_id
    int_part, _, frac_part = base_id.partition(".")
    frac_part = frac_part or "0"
    return f"{int_part}.{frac_part}{copy_index:04d}"


def _cluster_section(
    fixtures: Sequence[FixtureAlert], plan: Sequence[tuple[int, int]], nonce: str
) -> str:
    parts = [HEADING_CLUSTERS]
    for position, (fixture_index, copy_index) in enumerate(plan, start=1):
        fx = fixtures[fixture_index]
        synthetic_id = _synthetic_alert_id(fx.alert_id, copy_index)
        severity = severity_from_level(fx.rule_level)
        parts.append(
            "\n".join(
                [
                    _fact("cluster_id", str(position)),
                    _fact("alert_id", synthetic_id),
                    _fact("rule_id", fx.rule_id),
                    _fact("rule_level", str(fx.rule_level)),
                    _fact("severity", severity),
                    _fact("category", fx.category),
                ]
            )
        )
        raw_block = wrap.untrusted_block(
            fx.full_log,
            "wazuh_raw_log",
            nonce=nonce,
            limit_bytes=8192,  # §7.6: every cluster's raw_log ≤ 8 KB
            alert_id=synthetic_id,
        )
        parts.append(raw_block.rendered)
        desc_block = wrap.untrusted_block(
            fx.rule_description,
            "rule_description",
            nonce=nonce,
            alert_id=synthetic_id,
        )
        parts.append(desc_block.rendered)
    return "\n\n".join(parts)


def _timeline_block(fixtures: Sequence[FixtureAlert], nonce: str) -> str:
    lines = [
        f"{fx.alert_id} · rule {fx.rule_id} · {fx.category} · {fx.rule_description}"
        for fx in fixtures
    ]
    blk = wrap.untrusted_block("\n".join(lines[:300]), "context", nonce=nonce)
    return f"{HEADING_TIMELINE}\n\n{blk.rendered}"


def _entities_block(fixtures: Sequence[FixtureAlert], nonce: str) -> str:
    lines = [
        f"agent={fx.agent_name} manager={fx.manager_name} rule={fx.rule_id} "
        "inventory_lookup=not_found history_7d=none (no database in this measurement, "
        "design note 1)"
        for fx in fixtures
    ]
    blk = wrap.untrusted_block("\n".join(lines), "context", nonce=nonce)
    return f"{HEADING_ENTITIES}\n\n{blk.rendered}"


def _correlation_block(fixtures: Sequence[FixtureAlert], nonce: str) -> str:
    text = (
        "±2h correlation window (synthetic, for this measurement only): clusters "
        "treated as co-occurring within ±2 hours — " + ", ".join(fx.alert_id for fx in fixtures)
    )
    blk = wrap.untrusted_block(text, "correlation_samples", nonce=nonce)
    return f"{HEADING_CORRELATION}\n\n{blk.rendered}"


def _tier1_block(fixtures: Sequence[FixtureAlert], nonce: str) -> str:
    lines = [
        f"{fx.alert_id}: needs_review — rule {fx.rule_id} ({fx.category}) escalated to Tier-2"
        for fx in fixtures
    ]
    blk = wrap.untrusted_block("\n".join(lines), "proposer", nonce=nonce)
    return f"{HEADING_TIER1}\n\n{blk.rendered}"


def _playbook_block(fixtures: Sequence[FixtureAlert], nonce: str) -> str:
    categories = sorted({fx.category for fx in fixtures})
    text = (
        "Playbooks referenced for this case's categories: "
        + ", ".join(categories)
        + " — kb/playbooks/*.md (measurement placeholder text, not the real playbook content)."
    )
    blk = wrap.untrusted_block(text, "kb_playbook", nonce=nonce)
    return f"{HEADING_PLAYBOOK}\n\n{blk.rendered}"


def _notes_block(nonce: str) -> str:
    text = (
        "Analyst notes: none recorded for this measurement case. Previous ② result: "
        "none — first investigation attempt for this synthetic case."
    )
    blk = wrap.untrusted_block(text, "context", nonce=nonce)
    return f"{HEADING_NOTES}\n\n{blk.rendered}"


def _case_header(cluster_count: int) -> str:
    return "\n".join(
        [
            HEADING_CASE,
            _fact("case_id", CASE_ID),
            _fact("category", CASE_CATEGORY),
            _fact("opened_at", OPENED_AT),
            _fact("cluster_count", str(cluster_count)),
            _fact("alert_count", str(cluster_count)),
        ]
    )


def build_user_text(
    fixtures: Sequence[FixtureAlert], plan: Sequence[tuple[int, int]], nonce: str
) -> str:
    """The nine-block user message, §7.6 order exactly: case header as facts · every
    cluster with raw_log · timeline · entities · ±2h correlation · Tier-1 decisions ·
    playbooks · notes and previous ② result · the out-of-block "not available"
    sentence. Only the cluster section (block 2) grows with ``plan``; the other
    blocks are built once from all six base fixtures regardless of padding — a
    deliberate simplification for a byte-budget measurement script, not the real
    dossier (P5-T03's ``tier2/dossier.py``, untouched here)."""
    sections = [
        _case_header(len(plan)),
        _cluster_section(fixtures, plan, nonce),
        _timeline_block(fixtures, nonce),
        _entities_block(fixtures, nonce),
        _correlation_block(fixtures, nonce),
        _tier1_block(fixtures, nonce),
        _playbook_block(fixtures, nonce),
        _notes_block(nonce),
        NOT_AVAILABLE_SENTENCE,
    ]
    return "\n\n".join(sections)


# ---------------------------------------------------------------------------
# reaching the budget — design note 2/3: repeat whole clusters until tokens(user)
# + tokens(system) is within ± 2 % of the target
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DossierPlan:
    plan: list[tuple[int, int]]
    user_text: str
    total_tokens: int
    within_tolerance: bool


def base_plan(fixtures: Sequence[FixtureAlert]) -> list[tuple[int, int]]:
    return [(i, 0) for i in range(len(fixtures))]


def floor_tokens(fixtures: Sequence[FixtureAlert], system_text: str) -> int:
    """The smallest prompt this builder can ever produce: the six base clusters and
    nothing repeated. Below this, no ``--budget-tokens`` request is reachable."""
    user_text = build_user_text(fixtures, base_plan(fixtures), SIZING_NONCE)
    return _total_tokens(system_text, user_text)


def resolve_plan(
    fixtures: Sequence[FixtureAlert],
    system_text: str,
    budget_tokens: int,
    *,
    sizing_nonce: str = SIZING_NONCE,
) -> DossierPlan | None:
    """Grow the base plan by repeating whole clusters until the total estimate is
    within ± 2 % of ``budget_tokens``. Returns ``None`` when even the six-cluster
    floor already exceeds the tolerance band (the request is below the smallest
    reachable size)."""
    lower = budget_tokens * (1 - TOLERANCE)
    upper = budget_tokens * (1 + TOLERANCE)

    plan = base_plan(fixtures)
    user_text = build_user_text(fixtures, plan, sizing_nonce)
    total = _total_tokens(system_text, user_text)
    if total > upper:
        return None  # the floor itself is already too big for this budget

    # Calibrate one marginal delta per fixture (7 real builds total), then do a
    # cheap best-fit greedy fill purely on the numbers before confirming for real.
    deltas: list[int] = []
    for i in range(len(fixtures)):
        candidate_plan = [*plan, (i, 1)]
        candidate_user = build_user_text(fixtures, candidate_plan, sizing_nonce)
        deltas.append(_total_tokens(system_text, candidate_user) - total)

    extra_counts = [0] * len(fixtures)
    running_total = total
    guard = 0
    while running_total < lower:
        fits = [(i, d) for i, d in enumerate(deltas) if running_total + d <= upper]
        i, d = max(fits, key=lambda c: c[1]) if fits else min(enumerate(deltas), key=lambda c: c[1])
        extra_counts[i] += 1
        running_total += d
        guard += 1
        if guard > 20_000:
            raise RuntimeError("resolve_plan: safety guard tripped building the estimate")
        if not fits:
            break  # smallest available step still overshoots upper; best effort, refine below

    for i, count in enumerate(extra_counts):
        for copy_index in range(1, count + 1):
            plan.append((i, copy_index))

    # Refine against the real (not estimated) byte count — calibration drift from
    # growing "cluster_id: N" digit widths is small but this confirms it either way.
    for _ in range(200):
        user_text = build_user_text(fixtures, plan, sizing_nonce)
        total = _total_tokens(system_text, user_text)
        if lower <= total <= upper:
            return DossierPlan(
                plan=plan, user_text=user_text, total_tokens=total, within_tolerance=True
            )
        if total < lower:
            i = min(range(len(fixtures)), key=lambda i: deltas[i])
            copy_index = extra_counts[i] + 1
            extra_counts[i] += 1
            plan.append((i, copy_index))
        else:
            if len(plan) <= len(fixtures):
                return None
            plan.pop()

    return DossierPlan(plan=plan, user_text=user_text, total_tokens=total, within_tolerance=False)


# ---------------------------------------------------------------------------
# the cache — design note 5: sha256(model + system + user + LLM_THINKING + budget).
# `LLM_THINKING` and `budget` are not optional: DEC-032/DEC-042 record that leaving
# the mode out of a cache key silently replays one mode's answers for both arms.
# ---------------------------------------------------------------------------


def cache_key(model: str, system: str, user: str, thinking: str, budget_tokens: int) -> str:
    digest = hashlib.sha256()
    digest.update(
        f"{model}\n{system}\n{user}\nthinking={thinking}\nbudget={budget_tokens}".encode()
    )
    return digest.hexdigest()


def load_cached(cache_dir: Path, key: str) -> dict[str, Any] | None:
    path = Path(cache_dir) / f"{key}.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def store_cached(cache_dir: Path, key: str, payload: dict[str, Any]) -> Path:
    directory = Path(cache_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{key}.json"
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# sending — §7.5 via app.llm.adapter, one repair round (design note 6/8)
# ---------------------------------------------------------------------------


def _decode_json(content: str) -> tuple[Any | None, str | None]:
    try:
        return json.loads(content), None
    except (json.JSONDecodeError, TypeError) as exc:
        return None, f"response is not JSON: {exc}"


def _empty_record(*, stopped_by: str, error: str, timed_out: bool) -> dict[str, Any]:
    return {
        "latency_ms": None,
        "input_tokens": None,
        "output_tokens": None,
        "cost_usd": 0.0,
        "json_ok": False,
        "schema_ok_first": False,
        "schema_ok_repaired": False,
        "repaired": False,
        "stopped_by": stopped_by,
        "timed_out": timed_out,
        "error": error,
    }


def send_and_validate(
    adapter: Any, system_text: str, user_text: str, cfg: Config, budget: dict[str, float]
) -> dict[str, Any]:
    """One measurement: send, validate, and — matching §7.5's gate step 1 — one
    repair round when the first attempt is not schema-valid."""
    try:
        result = adapter.complete(
            system=system_text,
            user=user_text,
            response_format={"type": "json_object"},
            timeout_s=cfg.LLM_TIMEOUT_S,
        )
    except llm_adapter.LLMTimeout as exc:
        return _empty_record(stopped_by="timeout", error=str(exc), timed_out=True)
    except llm_adapter.LLMBudgetExceeded:
        raise
    except llm_adapter.LLMPermanent as exc:
        return _empty_record(stopped_by="permanent_error", error=str(exc), timed_out=False)
    except Exception as exc:  # noqa: BLE001 — one bad call must not lose the measurement
        return _empty_record(
            stopped_by="error", error=f"{type(exc).__name__}: {exc}", timed_out=False
        )

    usage = result.usage
    cost = llm_adapter.cost_usd(usage, cfg)
    budget["spent"] = budget.get("spent", 0.0) + cost

    parsed, decode_error = _decode_json(result.content)
    problems_first = [decode_error] if decode_error else schemas.validate("investigate_v2", parsed)
    record: dict[str, Any] = {
        "latency_ms": result.latency_ms,
        "input_tokens": usage.get("prompt_tokens"),
        "output_tokens": usage.get("completion_tokens"),
        "cost_usd": cost,
        "json_ok": decode_error is None,
        "schema_ok_first": not problems_first,
        "schema_ok_repaired": not problems_first,
        "repaired": False,
        "stopped_by": None,
        "timed_out": False,
        "error": None,
    }
    if not problems_first:
        return record

    repair_user = (
        f"{user_text}\n\n== VALIDATION ERROR ON YOUR PREVIOUS ANSWER ==\n"
        "Câu trả lời trước không đúng schema investigate_v2. Sửa và trả lại DUY NHẤT "
        "một đối tượng JSON đúng schema. Các lỗi:\n- " + "\n- ".join(problems_first)
    )
    try:
        repair_result = adapter.complete(
            system=system_text,
            user=repair_user,
            response_format={"type": "json_object"},
            timeout_s=cfg.LLM_TIMEOUT_S,
        )
    except Exception as exc:  # noqa: BLE001 — record the repair failure, keep the first attempt
        record["repaired"] = True
        record["error"] = f"repair failed: {type(exc).__name__}: {exc}"
        return record

    repair_usage = repair_result.usage
    repair_cost = llm_adapter.cost_usd(repair_usage, cfg)
    budget["spent"] = budget.get("spent", 0.0) + repair_cost
    record["cost_usd"] += repair_cost
    record["input_tokens"] = (record["input_tokens"] or 0) + int(
        repair_usage.get("prompt_tokens") or 0
    )
    record["output_tokens"] = (record["output_tokens"] or 0) + int(
        repair_usage.get("completion_tokens") or 0
    )
    repaired_obj, repair_decode_error = _decode_json(repair_result.content)
    problems_repair = (
        [repair_decode_error]
        if repair_decode_error
        else schemas.validate("investigate_v2", repaired_obj)
    )
    record["repaired"] = True
    record["schema_ok_repaired"] = not problems_repair
    return record


def deterministic_nonce(call_index: int) -> str:
    """A reproducible per-call nonce, the same 16-hex-char shape ``wrap.new_nonce()``
    produces. §6.5 requires a fresh nonce "regenerated per attempt" — satisfied here
    by every call index getting its own distinct value — but a *random* nonce would
    make every one of the N calls in an arm as unrepeatable as the others, which
    would break acceptance 3 (a rerun without ``--refresh`` must replay every call
    from the cache, byte-identical). Determinism does not weaken the property the
    nonce boundary exists for (design note 8): the linter and the wrapper only need
    a value the built prompt does not otherwise contain, not an unpredictable one."""
    return f"{call_index:016x}"


def run_arm(
    adapter: Any,
    cfg: Config,
    fixtures: Sequence[FixtureAlert],
    system_text: str,
    budget_tokens: int,
    calls: int,
    cache_dir: Path,
    refresh: bool,
    budget: dict[str, float],
    new_nonce: Callable[[int], str] = deterministic_nonce,
) -> tuple[list[dict[str, Any]], DossierPlan]:
    dossier = resolve_plan(fixtures, system_text, budget_tokens, sizing_nonce=SIZING_NONCE)
    if dossier is None:
        raise ValueError(
            f"run_arm: --budget-tokens {budget_tokens} is below the smallest reachable size "
            f"({floor_tokens(fixtures, system_text)} estimated tokens)"
        )

    records: list[dict[str, Any]] = []
    for call_index in range(calls):
        nonce = new_nonce(call_index)  # a fresh nonce per attempt (§6.5), reproducible across runs
        user_text = build_user_text(fixtures, dossier.plan, nonce)
        key = cache_key(
            cfg.LLM_MODEL_PROPOSER, system_text, user_text, cfg.LLM_THINKING, budget_tokens
        )

        if not refresh:
            cached = load_cached(cache_dir, key)
            if cached is not None:
                # "origin" is this invocation's own truth (live vs replayed), used for
                # the STDOUT summary; "provenance" is the persisted "how was this
                # measurement ever obtained" the report file renders, so a rerun
                # without --refresh writes a byte-identical file (acceptance 3).
                records.append({**cached, "origin": "cache"})
                continue

        if budget.get("spent", 0.0) >= budget.get("cap", DEFAULT_MAX_SPEND_USD):
            budget["tripped"] = True
            records.append(
                {
                    **_empty_record(stopped_by="budget_guard", error="", timed_out=False),
                    "origin": "skipped",
                    "provenance": "skipped",
                }
            )
            continue

        record = send_and_validate(adapter, system_text, user_text, cfg, budget)
        record["provenance"] = "live"
        store_cached(cache_dir, key, record)
        records.append({**record, "origin": "live"})

    return records, dossier


# ---------------------------------------------------------------------------
# metrics
# ---------------------------------------------------------------------------


def percentile(values: Sequence[float], q: float) -> float | None:
    clean = sorted(v for v in values if v is not None)
    if not clean:
        return None
    rank = max(1, min(len(clean), int(-(-q / 100 * len(clean) // 1))))
    return float(clean[rank - 1])


def _rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _mean(values: Iterable[float]) -> float | None:
    items = [v for v in values if v is not None]
    return sum(items) / len(items) if items else None


def arm_metrics(records: Sequence[dict[str, Any]]) -> dict[str, Any]:
    measured = [r for r in records if r.get("origin") in ("live", "cache")]
    latencies_s = [r["latency_ms"] / 1000 for r in measured if r.get("latency_ms") is not None]
    return {
        "n": len(records),
        "measured_n": len(measured),
        "json_rate": _rate(sum(1 for r in measured if r.get("json_ok")), len(measured)),
        "schema_rate_first": _rate(
            sum(1 for r in measured if r.get("schema_ok_first")), len(measured)
        ),
        "schema_rate_repaired": _rate(
            sum(1 for r in measured if r.get("schema_ok_repaired")), len(measured)
        ),
        "p50_latency_s": percentile(latencies_s, 50),
        "p95_latency_s": percentile(latencies_s, 95),
        "max_latency_s": max(latencies_s) if latencies_s else None,
        "mean_input_tokens": _mean(r.get("input_tokens") for r in measured),
        "mean_output_tokens": _mean(r.get("output_tokens") for r in measured),
        "total_cost_usd": sum(r.get("cost_usd") or 0.0 for r in records),
        "over_timeout": sum(1 for r in records if r.get("stopped_by") == "timeout"),
        "live": sum(1 for r in records if r.get("origin") == "live"),
        "cached": sum(1 for r in records if r.get("origin") == "cache"),
        "skipped": sum(1 for r in records if r.get("origin") == "skipped"),
        "errors": sum(1 for r in records if r.get("stopped_by") in ("error", "permanent_error")),
    }


# The §4.5 thresholds (DEC-032's reading: p95 ≤ 60 s while JSON ≥ 90 % and
# schema-valid-after-one-repair ≥ 98 % hold), applied per arm here — the current
# context pack carries no literal "§4.5" heading (a deviation from the card,
# recorded in the report); DEC-032 is the surviving source for these four numbers.
THRESHOLDS: tuple[tuple[str, str, float, str, str], ...] = (
    ("JSON parses", "json_rate", 0.90, "≥ 90 %", "ge"),
    ("Schema-valid `investigate_v2`, first attempt", "schema_rate_first", 0.90, "≥ 90 %", "ge"),
    (
        "Schema-valid `investigate_v2`, after one repair",
        "schema_rate_repaired",
        0.98,
        "≥ 98 %",
        "ge",
    ),
    ("p95 latency", "p95_latency_s", 60.0, "≤ 60 s", "le"),
)


def threshold_rows(metrics: dict[str, Any]) -> list[tuple[str, str, str, bool | None]]:
    rows = []
    for name, key, required, shown_required, direction in THRESHOLDS:
        value = metrics.get(key)
        if value is None:
            rows.append((name, shown_required, "n/a", None))
            continue
        ok = value >= required if direction == "ge" else value <= required
        shown = f"{value * 100:.1f} %" if key.startswith(("json", "schema")) else f"{value:.2f} s"
        rows.append((name, shown_required, shown, ok))
    return rows


# ---------------------------------------------------------------------------
# the ceiling (design note 4) — cited, not re-derived: this card opens no database
# connection (design note 14), so the 12,828-token figure is quoted from
# docs/plan/tasks/P5/P5-tasks.md §1, measured 23/09 on soc_dev, not re-run here.
# ---------------------------------------------------------------------------

CEILING_HEADS_BYTES = 51_312
CEILING_HEADS_TOKENS = 12_828  # 51,312 / 4, rounded


def ceiling_section(cfg: Config) -> str:
    pct = CEILING_HEADS_TOKENS / cfg.CASE_PROMPT_BUDGET_TOKENS * 100
    return (
        "## 3 · The ceiling this corpus can actually reach\n\n"
        f"The 200 largest alert heads in the whole corpus total **{CEILING_HEADS_BYTES:,} bytes "
        f"≈ {CEILING_HEADS_TOKENS:,} tokens** (measured 23/09 on `soc_dev`, "
        "`docs/plan/tasks/P5/P5-tasks.md` §1 — cited here, not re-derived: design note 14 "
        "forbids this card opening a database connection), and "
        f"`MAX_ALERTS_PER_CASE = {cfg.MAX_ALERTS_PER_CASE}`. So the largest dossier a real case on "
        f"this deployment can ever produce is ≈ {CEILING_HEADS_TOKENS:,} tokens — "
        f"{pct:.0f} % of `CASE_PROMPT_BUDGET_TOKENS = {cfg.CASE_PROMPT_BUDGET_TOKENS:,}`. "
        "The 60 k arm below measures a class this deployment never reaches; the 12.8 k arm "
        "measures the class it actually will. Both numbers are in the table above — reporting "
        "only the 60 k arm would be a different way of measuring the wrong thing (the mistake "
        "DEC-025 exists to name)."
    )


# ---------------------------------------------------------------------------
# the report
# ---------------------------------------------------------------------------


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f} %"


def _num(value: float | None, digits: int = 2) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"


def _git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=REPO_ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:  # noqa: BLE001 — the report still renders without a sha
        return "unknown"


def _provenance(record: dict[str, Any]) -> str:
    """How this measurement was ever obtained — persisted on the cached payload,
    unlike ``record["origin"]`` (this invocation's own live-vs-replayed truth). The
    report renders this, so a rerun without ``--refresh`` writes a byte-identical
    file (acceptance 3): "N live" always counts responses fetched live at some
    point, never fewer just because a later run replayed them from the cache."""
    return record.get("provenance") or record.get("origin") or "unknown"


def render_report(
    arms_data: dict[int, dict[str, Any]],
    *,
    cfg: Config,
    calls_per_arm: int,
    generated_at: str,
    git_sha: str,
) -> str:
    all_records = [r for d in arms_data.values() for r in d["records"]]
    total_live = sum(1 for r in all_records if _provenance(r) == "live")
    total_cached = sum(1 for r in all_records if _provenance(r) == "cache")
    total_calls = sum(arm_metrics(d["records"])["n"] for d in arms_data.values())
    total_cost = sum(arm_metrics(d["records"])["total_cost_usd"] for d in arms_data.values())

    lines: list[str] = []
    lines.append("# ② size-class measurement — `investigate_v2` at 60 k against the 12.8 k ceiling")
    lines.append("")
    lines.append(
        "DEC-032 amendment (b) / DEC-097: the measurement the 28/09 ② agent-day rests on. "
        "This report only measures format, latency and cost — the decision is DEC-097's "
        "and the Owner's (§8)."
    )
    lines.append("")
    lines.append(f"- **Date:** {generated_at}")
    lines.append(f"- **Model:** `{cfg.LLM_MODEL_PROPOSER}` (`LLM_MODEL_PROPOSER`)")
    lines.append(f"- **Mode:** `LLM_THINKING={cfg.LLM_THINKING}`")
    lines.append(f"- **`LLM_TIMEOUT_S`:** {cfg.LLM_TIMEOUT_S} s (wall-clock, DEC-033)")
    lines.append(f"- **`CASE_PROMPT_BUDGET_TOKENS`:** {cfg.CASE_PROMPT_BUDGET_TOKENS:,}")
    lines.append(f"- **Git sha:** `{git_sha}`")
    lines.append(f"- **Calls per arm:** {calls_per_arm}")
    lines.append(f"- **Total calls:** {total_calls}")
    lines.append(f"- **Total spend:** ${total_cost:.5f}")
    lines.append(f"- **Provenance:** {total_live} live · {total_cached} cached")
    lines.append(
        "- **Token estimate:** `len(text) / 4`, rounded — the crude estimator the card cites "
        "`eval/smoke_test.py` for; that script does not actually carry a pre-send estimator "
        "(a card inaccuracy, recorded in the task report). The exact byte count is printed "
        "alongside every estimate below so a reader can redo the arithmetic with a real "
        "tokeniser."
    )
    lines.append("")
    lines.append("## 1 · Two-arm table")
    lines.append("")
    lines.append(
        "| Arm (tokens) | clusters | n | JSON parses | schema valid (1st) | schema valid "
        "(after repair) | p50 (s) | p95 (s) | max (s) | mean input tok | mean output tok | "
        "cost (USD) | over `LLM_TIMEOUT_S` |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for budget_tokens in sorted(arms_data, reverse=True):
        data = arms_data[budget_tokens]
        m = arm_metrics(data["records"])
        lines.append(
            f"| {budget_tokens:,} | {data['cluster_count']} | {m['n']} | {_pct(m['json_rate'])} | "
            f"{_pct(m['schema_rate_first'])} | {_pct(m['schema_rate_repaired'])} | "
            f"{_num(m['p50_latency_s'])} | {_num(m['p95_latency_s'])} | {_num(m['max_latency_s'])} | "
            f"{_num(m['mean_input_tokens'], 0)} | {_num(m['mean_output_tokens'], 0)} | "
            f"{m['total_cost_usd']:.5f} | {m['over_timeout']} |"
        )
    lines.append("")
    lines.append("## 2 · Verdict against the §4.5 thresholds (DEC-032's reading)")
    lines.append("")
    lines.append("| Arm (tokens) | Threshold | Required | Measured | Verdict |")
    lines.append("|---|---|---|---|---|")
    for budget_tokens in sorted(arms_data, reverse=True):
        data = arms_data[budget_tokens]
        m = arm_metrics(data["records"])
        for name, required, shown, ok in threshold_rows(m):
            verdict = "n/a" if ok is None else ("**PASS**" if ok else "**FAIL**")
            lines.append(f"| {budget_tokens:,} | {name} | {required} | {shown} | {verdict} |")
    lines.append("")
    lines.append(ceiling_section(cfg))
    lines.append("")
    lines.append("## 4 · What this does not settle")
    lines.append("")
    lines.append(
        "This run measures **format, latency and cost** — never verdict quality, the same "
        "caveat DEC-042 insisted on for the smoke test and for the same reason: the "
        "synthesized dossiers built from six repeated committed fixtures are not the content "
        "of any real case, so `suggested_conclusion` and the hypotheses returned here are not "
        "evidence about accuracy in either direction. Nothing in this report is a proposal to "
        "accept or reject a verdict; only a `structured_basis`-shaped hallucination or evidence "
        "gate (P5-T03/T04's, not built yet) could answer that question, and it would still need "
        "a labelled gold set, not a synthetic dossier."
    )
    lines.append("")
    lines.append("## 5 · Per call")
    lines.append("")
    lines.append(
        "| arm | # | origin | latency (s) | input tok | output tok | JSON | schema (1st) | schema (final) | cost (USD) | stopped_by |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for budget_tokens in sorted(arms_data, reverse=True):
        for i, r in enumerate(arms_data[budget_tokens]["records"], start=1):
            latency_s = "n/a" if r.get("latency_ms") is None else f"{r['latency_ms'] / 1000:.2f}"
            lines.append(
                f"| {budget_tokens:,} | {i} | {_provenance(r)} | {latency_s} | "
                f"{r.get('input_tokens', 'n/a')} | {r.get('output_tokens', 'n/a')} | "
                f"{'ok' if r.get('json_ok') else 'no'} | {'ok' if r.get('schema_ok_first') else 'no'} | "
                f"{'ok' if r.get('schema_ok_repaired') else 'no'} | {r.get('cost_usd', 0.0):.5f} | "
                f"{r.get('stopped_by') or '—'} |"
            )
    lines.append("")
    lines.append("## 6 · DEC-097")
    lines.append("")
    lines.append(
        'This is the measurement DEC-097 arms ② on: *"a surviving ② gets exactly one '
        "agent-day, 28/09, after DEC-032's measurement at its own prompt size.\"* The numbers "
        "above are that measurement. **This card reports numbers; it does not recommend a "
        "cut** (scope out) — the decision is DEC-097's and the Owner's."
    )
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--env-file",
        metavar="PATH",
        default=str(DEFAULT_ENV_FILE),
        help="file to read LLM_* from (default: %(default)s)",
    )
    parser.add_argument(
        "--budget-tokens",
        type=int,
        default=None,
        help="single budget for --dry-run (default: Config.CASE_PROMPT_BUDGET_TOKENS)",
    )
    parser.add_argument(
        "--arms",
        default=DEFAULT_ARMS,
        help="comma-separated token budgets for the live run (default: %(default)s)",
    )
    parser.add_argument(
        "--calls", type=int, default=DEFAULT_CALLS, help="calls per arm (default: %(default)s)"
    )
    parser.add_argument("--report", metavar="PATH", help="write the Markdown report here")
    parser.add_argument(
        "--cache-dir",
        metavar="DIR",
        default=str(DEFAULT_CACHE_DIR),
        help="where raw responses are cached (default: %(default)s, git-ignored)",
    )
    parser.add_argument(
        "--max-spend-usd",
        metavar="USD",
        type=float,
        default=DEFAULT_MAX_SPEND_USD,
        help="stop calling and exit 5 once this much has been spent (default: %(default)s)",
    )
    parser.add_argument(
        "--refresh", action="store_true", help="ignore the cache and re-send every call"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="build and measure the prompt; send nothing"
    )
    return parser


def dry_run(fixtures: Sequence[FixtureAlert], system_text: str, budget_tokens: int) -> int:
    floor = floor_tokens(fixtures, system_text)
    upper = budget_tokens * (1 + TOLERANCE)
    if upper < floor:
        print(
            f"investigate_measure: --budget-tokens {budget_tokens} is below the smallest "
            f"reachable size — the six base clusters alone already estimate {floor:,} tokens. "
            "Refusing rather than emit a truncated one-block prompt.",
            file=sys.stderr,
        )
        return EXIT_CONFIG

    dossier = resolve_plan(fixtures, system_text, budget_tokens, sizing_nonce=SIZING_NONCE)
    if dossier is None:
        print(
            f"investigate_measure: --budget-tokens {budget_tokens} is below the smallest "
            f"reachable size ({floor:,} estimated tokens).",
            file=sys.stderr,
        )
        return EXIT_CONFIG

    system_bytes = len(system_text.encode("utf-8"))
    user_bytes = len(dossier.user_text.encode("utf-8"))
    print(f"investigate_measure --dry-run --budget-tokens {budget_tokens}")
    print(
        f"  clusters: {len(dossier.plan)} ({len(fixtures)} base + {len(dossier.plan) - len(fixtures)} padding)"
    )
    print(f"  bytes: system {system_bytes:,} + user {user_bytes:,} = {system_bytes + user_bytes:,}")
    print(
        f"  estimated tokens (len/4): system {estimate_tokens(system_text):,} + "
        f"user {estimate_tokens(dossier.user_text):,} = {dossier.total_tokens:,}"
    )
    verdict = "within ±2%" if dossier.within_tolerance else "OUTSIDE ±2% (best effort)"
    print(f"  {verdict} of {budget_tokens}")
    return EXIT_OK if dossier.within_tolerance else EXIT_CONFIG


def main(
    argv: Sequence[str] | None = None, adapter_factory: Callable[[Config, dict], Any] | None = None
) -> int:
    args = build_parser().parse_args(argv)
    cfg = load_config(env_file=args.env_file)
    fixtures = load_fixtures()
    system_text = build_system_text()

    if args.dry_run:
        budget_tokens = (
            args.budget_tokens if args.budget_tokens is not None else cfg.CASE_PROMPT_BUDGET_TOKENS
        )
        return dry_run(fixtures, system_text, budget_tokens)

    try:
        arms = [int(x.strip()) for x in args.arms.split(",") if x.strip()]
    except ValueError:
        print(
            f"investigate_measure: --arms {args.arms!r} is not a comma-separated list of integers",
            file=sys.stderr,
        )
        return EXIT_CONFIG
    if not arms:
        print("investigate_measure: --arms named no budget", file=sys.stderr)
        return EXIT_CONFIG

    cache_dir = Path(args.cache_dir)
    budget = {"spent": 0.0, "cap": float(args.max_spend_usd), "tripped": False}

    if adapter_factory is None:

        def adapter_factory(cfg_: Config, budget_: dict) -> Any:
            return llm_adapter.DeepSeekAdapter(cfg_, spent_usd=lambda: budget_.get("spent", 0.0))

    adapter = adapter_factory(cfg, budget)

    arms_data: dict[int, dict[str, Any]] = {}
    for budget_tokens in arms:
        try:
            records, dossier = run_arm(
                adapter,
                cfg,
                fixtures,
                system_text,
                budget_tokens,
                args.calls,
                cache_dir,
                args.refresh,
                budget,
            )
        except ValueError as exc:
            print(f"investigate_measure: {exc}", file=sys.stderr)
            return EXIT_CONFIG
        arms_data[budget_tokens] = {"records": records, "cluster_count": len(dossier.plan)}
        if budget.get("tripped"):
            break

    generated_at = datetime.now(UTC).isoformat(timespec="seconds")
    report_text = render_report(
        arms_data, cfg=cfg, calls_per_arm=args.calls, generated_at=generated_at, git_sha=_git_sha()
    )

    if args.report:
        report_path = Path(args.report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report_text, encoding="utf-8")

    total_live = sum(arm_metrics(d["records"])["live"] for d in arms_data.values())
    total_cached = sum(arm_metrics(d["records"])["cached"] for d in arms_data.values())
    total_calls = sum(arm_metrics(d["records"])["n"] for d in arms_data.values())
    print(
        f"investigate_measure · {cfg.LLM_MODEL_PROPOSER} · thinking: {cfg.LLM_THINKING} · "
        f"{total_calls} calls ({args.calls} per arm) · spend ${budget['spent']:.5f} of "
        f"${float(args.max_spend_usd):.2f} --max-spend-usd guard"
    )
    print(f"  provenance: {total_live} live · {total_cached} cached")
    for budget_tokens in sorted(arms_data, reverse=True):
        m = arm_metrics(arms_data[budget_tokens]["records"])
        print(
            f"  arm {budget_tokens:,}: n={m['n']} p50={_num(m['p50_latency_s'])} s "
            f"p95={_num(m['p95_latency_s'])} s cost=${m['total_cost_usd']:.5f} "
            f"over_timeout={m['over_timeout']}"
        )
        if m["over_timeout"]:
            for i, r in enumerate(arms_data[budget_tokens]["records"], start=1):
                if r.get("stopped_by") == "timeout":
                    print(f"    call {i}: timed out ({cfg.LLM_TIMEOUT_S} s deadline)")
    if args.report:
        print(f"  wrote {args.report}")
    if budget.get("tripped"):
        print(
            f"investigate_measure: the spend guard tripped at ${budget['cap']:.2f}; the report "
            "holds what was collected before that.",
            file=sys.stderr,
        )
        return EXIT_BUDGET
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
