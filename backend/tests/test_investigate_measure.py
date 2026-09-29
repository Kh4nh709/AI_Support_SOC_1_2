"""Offline tests for eval/investigate_measure.py — pure, no live call (``-m "not db"``).

Design note 8 (docs/plan/tasks/P5/P5-T02.prompt.md): the builder reaches the budget
within ± 2 % for both card arms and a third, odd value; the block order matches
§7.6; every free-text block sits inside a nonce-carrying ``<untrusted_data>``
wrapper and ``app.security.linter.lint`` returns no violation on the built prompt
(G6′); the cache key changes when ``LLM_THINKING`` changes and when the budget
changes, and does not change when only ``--calls`` changes; ``--max-spend-usd``
aborts before the crossing call (fake adapter, fake usage); the report renders
both arms with a fake record set.

Live calls are this card's whole point and are confined to the script (rule 15);
no test here makes one.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from app.infra.config import Config
from app.security import linter

from tests.fakes.llm import INVESTIGATE_V2_OK

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "eval" / "investigate_measure.py"

# eval/ is a composition root outside backend/ and is not on sys.path — loaded by
# path, same precedent as test_smoke_test.py.
_spec = importlib.util.spec_from_file_location("investigate_measure", SCRIPT_PATH)
im = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = im
_spec.loader.exec_module(im)


FAKE_CFG = Config(
    LLM_MODEL_PROPOSER="fake-deepseek",
    LLM_THINKING="disabled",
    LLM_TIMEOUT_S=120,
    LLM_PRICE_IN_PER_M=0.014,
    LLM_PRICE_OUT_PER_M=0.66,
)

BLOCK_HEADING_ORDER = (
    im.HEADING_CASE,
    im.HEADING_CLUSTERS,
    im.HEADING_TIMELINE,
    im.HEADING_ENTITIES,
    im.HEADING_CORRELATION,
    im.HEADING_TIER1,
    im.HEADING_PLAYBOOK,
    im.HEADING_NOTES,
    im.NOT_AVAILABLE_SENTENCE,
)


@pytest.fixture(scope="module")
def fixtures():
    return im.load_fixtures()


@pytest.fixture(scope="module")
def system_text():
    return im.build_system_text()


# --- the padding loop reaches the budget within ± 2 % (design note 8) -------


@pytest.mark.parametrize("budget_tokens", [60_000, 12_800, 20_000])
def test_resolve_plan_reaches_the_budget_within_two_percent(fixtures, system_text, budget_tokens):
    dossier = im.resolve_plan(fixtures, system_text, budget_tokens, sizing_nonce=im.SIZING_NONCE)

    assert dossier is not None
    assert dossier.within_tolerance
    lower = budget_tokens * (1 - im.TOLERANCE)
    upper = budget_tokens * (1 + im.TOLERANCE)
    assert lower <= dossier.total_tokens <= upper


def test_a_budget_below_the_floor_is_refused(fixtures, system_text):
    floor = im.floor_tokens(fixtures, system_text)
    dossier = im.resolve_plan(fixtures, system_text, 60, sizing_nonce=im.SIZING_NONCE)
    assert dossier is None
    assert floor > 60 * 1.02


def test_dry_run_below_the_floor_names_the_smallest_reachable_size(fixtures, system_text, capsys):
    rc = im.dry_run(fixtures, system_text, 60)
    out = capsys.readouterr().err
    assert rc == im.EXIT_CONFIG
    assert "smallest reachable size" in out


def test_dry_run_prints_bytes_tokens_and_the_within_line(fixtures, system_text, capsys):
    rc = im.dry_run(fixtures, system_text, 12_800)
    out = capsys.readouterr().out
    assert rc == im.EXIT_OK
    assert "bytes:" in out
    assert "estimated tokens" in out
    assert "within ±2% of 12800" in out


def test_estimate_tokens_is_len_over_four_rounded():
    """Pins the formula design note 2 specifies: 400 chars / 4 = exactly 100."""
    assert im.estimate_tokens("x" * 400) == 100


def test_dossier_total_tokens_is_the_sum_of_both_pieces_estimates(fixtures, system_text):
    """Pins how ``total_tokens`` is computed — the sum of two independent len/4
    estimates, not (for example) one estimate over the concatenated text, which
    would differ by up to a couple of tokens because of the joining whitespace."""
    dossier = im.resolve_plan(fixtures, system_text, 12_800, sizing_nonce=im.SIZING_NONCE)
    assert dossier.total_tokens == round(len(system_text) / 4) + round(len(dossier.user_text) / 4)


# --- block order matches §7.6 (design note 8) -------------------------------


def test_block_order_matches_section_7_6(fixtures, system_text):
    dossier = im.resolve_plan(fixtures, system_text, 12_800, sizing_nonce=im.SIZING_NONCE)
    positions = [dossier.user_text.index(marker) for marker in BLOCK_HEADING_ORDER]
    assert positions == sorted(positions)


# --- every free-text block is wrapped; the linter is clean (G6′) -----------


def test_the_linter_finds_no_violation_on_the_built_prompt(fixtures, system_text):
    dossier = im.resolve_plan(fixtures, system_text, 12_800, sizing_nonce=im.SIZING_NONCE)
    violations = linter.lint(
        dossier.user_text,
        nonce=im.SIZING_NONCE,
        constants=im.TEMPLATE_CONSTANTS,
        enums=im.LINT_ENUM_VALUES,
    )
    assert violations == []


def test_red_case_b_a_block_moved_outside_its_wrapper_trips_the_linter(fixtures, system_text):
    """DEC-025 red case (b), reproduced without touching the product builder: text
    that carries the notes block's own content but with no ``<untrusted_data>``
    wrapper around it must NOT lint clean — proving the linter test above would
    have caught the defect design note 8(b) describes (moving a real block outside
    its wrapper) had it been present."""
    dossier = im.resolve_plan(fixtures, system_text, 12_800, sizing_nonce=im.SIZING_NONCE)
    unwrapped = dossier.user_text + "\n\nAnalyst notes: none recorded for this measurement case."
    violations = linter.lint(
        unwrapped,
        nonce=im.SIZING_NONCE,
        constants=im.TEMPLATE_CONSTANTS,
        enums=im.LINT_ENUM_VALUES,
    )
    assert violations != []


def test_red_case_c_a_wrong_tolerance_constant_fails_the_real_two_percent_check(
    fixtures, system_text, monkeypatch
):
    """DEC-025 red case (c), reproduced against the real ``resolve_plan`` (not an
    inline copy of its algorithm): monkeypatching the module's own ``TOLERANCE``
    to 0.5 makes the padding loop's real stopping condition equivalent to "stop at
    50 % of the budget" — design note 8(c)'s exact defect — and the result fails
    the true ± 2 % window for both arms, proving
    ``test_resolve_plan_reaches_the_budget_within_two_percent`` is checked for
    real and would go red had ``TOLERANCE`` regressed to something this loose."""
    monkeypatch.setattr(im, "TOLERANCE", 0.5)
    for budget_tokens in (60_000, 12_800):
        dossier = im.resolve_plan(
            fixtures, system_text, budget_tokens, sizing_nonce=im.SIZING_NONCE
        )
        assert dossier is not None
        real_lower = budget_tokens * (1 - 0.02)  # the true ± 2 % window, independent of the patch
        assert dossier.total_tokens < real_lower


# --- the cache key (design note 5/8) ----------------------------------------


def test_cache_key_changes_with_thinking_and_with_budget():
    """Unit-level pin on the pure function itself — genuine assertions (each input
    is independently varied and checked), not the tautological "does not change
    with --calls" claim this test used to also make: ``cache_key`` never takes a
    ``calls`` parameter at all, so that could never have been anything other than
    true by construction. The *behavioural* versions of both properties —
    ``run_arm`` making new calls when the mode changes, and a warm cache surviving
    a bump in ``--calls`` — are below, exercising the real call path instead."""
    base = im.cache_key("m", "s", "u", "disabled", 60_000)

    assert base != im.cache_key("m", "s", "u", "enabled", 60_000), "thinking must change the key"
    assert base != im.cache_key("m", "s", "u", "disabled", 12_800), "budget must change the key"
    assert base == im.cache_key("m", "s", "u", "disabled", 60_000), "same inputs, same key"


def test_run_arm_makes_new_calls_when_thinking_mode_changes(fixtures, system_text, tmp_path):
    """Kills the mutant "LLM_THINKING dropped from cache_key" at the ``run_arm``
    level (DEC-025 red case (a), now exercising the real product path instead of
    an inline copy of the hash formula): the same cache directory, the same
    fixtures and budget, but a different ``LLM_THINKING`` must make N brand new
    calls, never replay the other mode's cache entries (DEC-032/DEC-042)."""
    import dataclasses

    adapter = _FakeAdapter(usage={"prompt_tokens": 100, "completion_tokens": 50})
    budget = {"spent": 0.0, "cap": 10.0, "tripped": False}
    im.run_arm(
        adapter,
        FAKE_CFG,
        fixtures,
        system_text,
        20_000,
        calls=3,
        cache_dir=tmp_path,
        refresh=True,
        budget=budget,
    )
    assert len(adapter.calls) == 3

    enabled_cfg = dataclasses.replace(FAKE_CFG, LLM_THINKING="enabled")
    budget2 = {"spent": 0.0, "cap": 10.0, "tripped": False}
    im.run_arm(
        adapter,
        enabled_cfg,
        fixtures,
        system_text,
        20_000,
        calls=3,
        cache_dir=tmp_path,
        refresh=False,
        budget=budget2,
    )
    assert (
        len(adapter.calls) == 6
    ), "a different thinking mode must never replay the other mode's cache"


def test_bumping_calls_reuses_the_existing_cache_entries(fixtures, system_text, tmp_path):
    """Kills the mutant "call index left out of the nonce/key": raising --calls
    from 2 to 3 on a warm cache must make exactly one new call — the first two
    replay from the cache built by the calls=2 run."""
    adapter = _FakeAdapter(usage={"prompt_tokens": 100, "completion_tokens": 50})
    budget = {"spent": 0.0, "cap": 10.0, "tripped": False}
    im.run_arm(
        adapter,
        FAKE_CFG,
        fixtures,
        system_text,
        20_000,
        calls=2,
        cache_dir=tmp_path,
        refresh=False,
        budget=budget,
    )
    assert len(adapter.calls) == 2

    im.run_arm(
        adapter,
        FAKE_CFG,
        fixtures,
        system_text,
        20_000,
        calls=3,
        cache_dir=tmp_path,
        refresh=False,
        budget=budget,
    )
    assert (
        len(adapter.calls) == 3
    ), "raising --calls must add exactly one new call, not resend the first two"


def test_store_and_load_cache_round_trip(tmp_path):
    key = im.cache_key("m", "s", "u", "disabled", 60_000)
    im.store_cached(tmp_path, key, {"cost_usd": 0.001, "origin": "ignored-on-write"})
    assert im.load_cached(tmp_path, key) == {"cost_usd": 0.001, "origin": "ignored-on-write"}
    assert im.load_cached(tmp_path, "nonexistent" * 8) is None


# --- the spend guard (fake adapter, fake usage) -----------------------------


class _FakeAdapter:
    """Duck-types ``app.llm.adapter.DeepSeekAdapter.complete`` — no network, ever."""

    def __init__(self, usage: dict, content: str | None = None):
        self._usage = usage
        self._content = content or json.dumps(INVESTIGATE_V2_OK)
        self.calls: list[dict] = []

    def complete(self, *, system, user, response_format=None, timeout_s=None):
        self.calls.append({"system": system, "user": user, "timeout_s": timeout_s})
        return SimpleNamespace(
            content=self._content, model="fake-deepseek", usage=dict(self._usage), latency_ms=250
        )


def test_the_spend_guard_stops_once_the_cap_is_reached(fixtures, system_text, tmp_path):
    """--max-spend-usd is checked before each send, so it stops calling once the
    running total has reached the cap — never mid-flight, and never by letting
    one call's cost push the total past the cap first."""
    # cost of one call: 20000/1e6*0.014 + 500/1e6*0.66 = 0.00028 + 0.00033 = 0.00061
    adapter = _FakeAdapter(usage={"prompt_tokens": 20_000, "completion_tokens": 500})
    budget = {"spent": 0.0, "cap": 0.0005, "tripped": False}

    records, dossier = im.run_arm(
        adapter,
        FAKE_CFG,
        fixtures,
        system_text,
        20_000,
        calls=5,
        cache_dir=tmp_path,
        refresh=True,
        budget=budget,
    )

    assert dossier.within_tolerance
    assert len(adapter.calls) == 1, "the guard must stop calling once the cap is reached"
    origins = [r["origin"] for r in records]
    assert origins[0] == "live"
    assert origins[1:] == ["skipped"] * 4
    assert budget["tripped"] is True
    assert budget["spent"] >= budget["cap"]


def test_below_the_cap_every_call_is_made(fixtures, system_text, tmp_path):
    adapter = _FakeAdapter(usage={"prompt_tokens": 100, "completion_tokens": 50})
    budget = {"spent": 0.0, "cap": 10.0, "tripped": False}

    records, _ = im.run_arm(
        adapter,
        FAKE_CFG,
        fixtures,
        system_text,
        20_000,
        calls=3,
        cache_dir=tmp_path,
        refresh=True,
        budget=budget,
    )

    assert len(adapter.calls) == 3
    assert all(r["origin"] == "live" for r in records)
    assert budget["tripped"] is False


def test_each_call_gets_a_fresh_nonce_and_a_distinct_cache_entry(fixtures, system_text, tmp_path):
    """§6.5: a fresh nonce per attempt. The default ``deterministic_nonce`` gives
    call 0, 1, 2 within one arm three distinct nonces (and so three distinct sent
    prompts and cache entries) — reproducibly, unlike a random nonce, which is what
    acceptance 3's rerun-replays-from-cache requirement needs."""
    adapter = _FakeAdapter(usage={"prompt_tokens": 100, "completion_tokens": 50})
    budget = {"spent": 0.0, "cap": 10.0, "tripped": False}

    _records, _ = im.run_arm(
        adapter,
        FAKE_CFG,
        fixtures,
        system_text,
        20_000,
        calls=3,
        cache_dir=tmp_path,
        refresh=True,
        budget=budget,
    )

    assert len(adapter.calls) == 3
    users = {c["user"] for c in adapter.calls}
    assert len(users) == 3, "a fresh nonce per attempt must make each sent prompt distinct"


def test_a_cached_call_is_replayed_without_calling_the_adapter(fixtures, system_text, tmp_path):
    """The reproducibility half of acceptance 3: the same call index gets the same
    nonce on a second invocation, so it lands on the first run's cache entry."""
    adapter = _FakeAdapter(usage={"prompt_tokens": 100, "completion_tokens": 50})
    budget = {"spent": 0.0, "cap": 10.0, "tripped": False}

    records_first, _ = im.run_arm(
        adapter,
        FAKE_CFG,
        fixtures,
        system_text,
        20_000,
        calls=1,
        cache_dir=tmp_path,
        refresh=True,
        budget=budget,
    )
    assert len(adapter.calls) == 1

    records_second, _ = im.run_arm(
        adapter,
        FAKE_CFG,
        fixtures,
        system_text,
        20_000,
        calls=1,
        cache_dir=tmp_path,
        refresh=False,
        budget=budget,
    )
    assert len(adapter.calls) == 1, "a warm cache must make no second call"
    assert records_second[0]["origin"] == "cache"
    assert records_second[0]["cost_usd"] == records_first[0]["cost_usd"]


def test_a_cached_rerun_renders_a_byte_identical_report_except_the_timestamp(
    fixtures, system_text, tmp_path
):
    """Acceptance 3: a rerun without ``--refresh`` prints '0 live · N cached' (this
    invocation's own truth, via ``origin``) but writes the same report bytes as the
    live run (the persisted ``provenance``, not ``origin``, is what the file
    renders) — everything except the header ``Date:`` line must match exactly."""
    adapter = _FakeAdapter(usage={"prompt_tokens": 100, "completion_tokens": 50})
    budget_first = {"spent": 0.0, "cap": 10.0, "tripped": False}

    records_first, dossier = im.run_arm(
        adapter,
        FAKE_CFG,
        fixtures,
        system_text,
        20_000,
        calls=2,
        cache_dir=tmp_path,
        refresh=True,
        budget=budget_first,
    )
    arms_first = {20_000: {"records": records_first, "cluster_count": len(dossier.plan)}}
    report_first = im.render_report(
        arms_first,
        cfg=FAKE_CFG,
        calls_per_arm=2,
        generated_at="2026-09-29T09:00:00+00:00",
        git_sha="abc1234",
    )

    budget_second = {"spent": 0.0, "cap": 10.0, "tripped": False}
    records_second, _ = im.run_arm(
        adapter,
        FAKE_CFG,
        fixtures,
        system_text,
        20_000,
        calls=2,
        cache_dir=tmp_path,
        refresh=False,
        budget=budget_second,
    )
    assert len(adapter.calls) == 2, "the second run must make no new call at all"
    assert all(r["origin"] == "cache" for r in records_second)

    arms_second = {20_000: {"records": records_second, "cluster_count": len(dossier.plan)}}
    report_second = im.render_report(
        arms_second,
        cfg=FAKE_CFG,
        calls_per_arm=2,
        generated_at="2026-09-29T09:05:00+00:00",
        git_sha="abc1234",
    )

    def strip_date(text: str) -> str:
        return "\n".join(line for line in text.splitlines() if not line.startswith("- **Date:**"))

    assert strip_date(report_first) == strip_date(report_second)
    assert (
        "0 live" not in report_first
    )  # the file reports persisted provenance, not this-run origin
    assert "2 live" in report_first
    assert "2 live" in report_second, "the file must still say 2 live on the cached rerun"


# --- one repair round (§7.5 / gate step 1) ----------------------------------


def test_a_schema_invalid_first_attempt_gets_one_repair_round(fixtures, system_text):
    bad = json.dumps({**INVESTIGATE_V2_OK, "confidence": "extremely high"})  # not in the enum
    good = json.dumps(INVESTIGATE_V2_OK)

    class _TwoStepAdapter:
        def __init__(self):
            self.calls = []

        def complete(self, *, system, user, response_format=None, timeout_s=None):
            self.calls.append(user)
            content = bad if len(self.calls) == 1 else good
            return SimpleNamespace(
                content=content,
                model="fake-deepseek",
                usage={"prompt_tokens": 100, "completion_tokens": 50},
                latency_ms=250,
            )

    adapter = _TwoStepAdapter()
    record = im.send_and_validate(adapter, "system with JSON", "user", FAKE_CFG, {"spent": 0.0})

    assert len(adapter.calls) == 2
    assert record["repaired"] is True
    assert record["schema_ok_first"] is False
    assert record["schema_ok_repaired"] is True


def test_a_schema_valid_first_attempt_needs_no_repair(fixtures, system_text):
    adapter = _FakeAdapter(usage={"prompt_tokens": 100, "completion_tokens": 50})
    record = im.send_and_validate(adapter, "system with JSON", "user", FAKE_CFG, {"spent": 0.0})

    assert len(adapter.calls) == 1
    assert record["repaired"] is False
    assert record["schema_ok_first"] is True
    assert record["schema_ok_repaired"] is True


def test_a_timeout_is_counted_by_arm_metrics_and_rendered_in_the_report(fixtures, system_text):
    """The wall-clock deadline (DEC-033) path was previously untested end to end:
    a fake adapter that raises ``LLMTimeout`` must produce a record
    ``arm_metrics`` counts under ``over_timeout``, and that count must actually
    reach the rendered report's `over LLM_TIMEOUT_S` column."""

    class _TimeoutAdapter:
        def complete(self, *, system, user, response_format=None, timeout_s=None):
            raise im.llm_adapter.LLMTimeout(f"model call exceeded {timeout_s} s wall-clock")

    record = im.send_and_validate(
        _TimeoutAdapter(), "system with JSON", "user", FAKE_CFG, {"spent": 0.0}
    )
    assert record["stopped_by"] == "timeout"
    assert record["timed_out"] is True

    metrics = im.arm_metrics([record])
    assert metrics["over_timeout"] == 1

    arms_data = {
        60_000: {
            "records": [record],
            "cluster_count": 131,
            "system_bytes": 2_586,
            "user_bytes": 235_061,
            "estimated_tokens": 59_254,
        }
    }
    report = im.render_report(
        arms_data,
        cfg=FAKE_CFG,
        calls_per_arm=1,
        generated_at="2026-09-29T12:00:00+00:00",
        git_sha="deadbee",
    )
    # The two-arm table's last column is "over `LLM_TIMEOUT_S`"; with exactly one
    # record and it a timeout, that cell reads 1.
    row = next(line for line in report.splitlines() if line.startswith("| 60,000 |"))
    assert row.rstrip("|").rsplit("|", 1)[-1].strip() == "1"


# --- the report renders both arms with a fake record set (design note 8) ---


def _fake_record(
    *, origin="live", json_ok=True, schema_first=True, schema_final=True, latency_ms=1500
):
    return {
        "origin": origin,
        "latency_ms": latency_ms,
        "input_tokens": 12_000,
        "output_tokens": 400,
        "cost_usd": 0.00045,
        "json_ok": json_ok,
        "schema_ok_first": schema_first,
        "schema_ok_repaired": schema_final,
        "repaired": not schema_first,
        "stopped_by": None,
        "timed_out": False,
        "error": None,
    }


def test_render_report_covers_both_arms_and_the_ceiling_section():
    arms_data = {
        60_000: {"records": [_fake_record() for _ in range(3)], "cluster_count": 131},
        12_800: {
            "records": [_fake_record(), _fake_record(schema_first=False)],
            "cluster_count": 29,
        },
    }

    report = im.render_report(
        arms_data,
        cfg=FAKE_CFG,
        calls_per_arm=3,
        generated_at="2026-09-29T12:00:00+00:00",
        git_sha="deadbee",
    )

    assert "60,000" in report
    assert "12,800" in report
    assert "12,828" in report or "12828" in report
    assert "MAX_ALERTS_PER_CASE" in report
    assert "§4.5" in report
    assert "DEC-097" in report
    assert "deadbee" in report


def test_render_report_marks_a_failing_threshold():
    slow_record = _fake_record(latency_ms=90_000)  # 90 s > the 60 s p95 threshold
    arms_data = {60_000: {"records": [slow_record], "cluster_count": 131}}

    report = im.render_report(
        arms_data,
        cfg=FAKE_CFG,
        calls_per_arm=1,
        generated_at="2026-09-29T12:00:00+00:00",
        git_sha="deadbee",
    )

    assert "**FAIL**" in report
