"""The 7-step gate that turns a proposer/verifier LLM response into a triage_status.

Implements context pack §7.3 literally (`docs/plan/tasks/P3/P3-T08.prompt.md` pastes the same
seven steps). `security` may import only `infra` (G1), so three things the gate needs — schema
validation (P3-T05), the decision-table check (P3-T10, wrapping `kb.rule_holds`), and the
detector (P3-T07) — arrive as injected callables rather than imports; the verifier's parsed JSON
arrives as a plain argument for the same reason.

Verdict transitions are monotone: only `start()` may set `verdict` to `false_positive` or
`escalate` (from the proposer's own claim); every step after that may only force it to
`needs_review`, appending its own name to `forced_by`. `forced = proposed_verdict != verdict`.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from app.security import output_guard
from app.security.wrap import Block

Validator = Callable[[str, Any], list[str]]
RuleCheck = Callable[[str | None], tuple[bool, str | None]]
Scanner = Callable[[Iterable[Block]], list[Any]]

_STEP2_STRING_FIELDS = ("severity", "ioc_reputation", "asset_criticality", "identity_privileged")
_FP_IOC_BLOCKS = frozenset({"malicious", "suspicious"})
_FP_ASSET_BLOCKS = frozenset({"high", "unknown"})


@dataclass
class GateState:
    proposer_raw: dict  # the parsed model JSON, never mutated
    facts: Mapping[str, Any]  # planning decision 7
    blocks: Mapping[str, Block]  # BuiltPrompt.block_index
    proposed_verdict: str
    verdict: str  # evolves through the steps
    reasons: list[dict]  # surviving reasons
    steps: dict[str, str]
    forced_by: list[str]
    missing: list[str]
    mismatched_fields: list[str]
    dropped_reasons: list[dict]
    hallucination_flag: bool
    warnings: list[str]
    injection_findings: list[Any]
    verifier_verdict: str | None


def step1_schema(
    parsed: dict | None, validate: Validator, *, repaired: bool
) -> tuple[str, list[str]]:
    """`parsed=None` (JSON did not parse) counts as invalid without calling `validate`."""
    if parsed is None:
        errors = ["<root>: invalid JSON"]
    else:
        errors = validate("triage_v2", parsed)
    if not errors:
        return "ok", []
    return ("failed" if repaired else "repair"), errors


def start(
    parsed: dict, facts: Mapping[str, Any], blocks: Mapping[str, Block], *, repaired: bool
) -> GateState:
    """Build the initial state after step 1 has passed."""
    return GateState(
        proposer_raw=parsed,
        facts=facts,
        blocks=blocks,
        proposed_verdict=parsed["suggested_action"],
        verdict=parsed["suggested_action"],
        reasons=list(parsed["reasons"]),
        steps={"1": "repaired" if repaired else "ok"},
        forced_by=[],
        missing=[],
        mismatched_fields=[],
        dropped_reasons=[],
        hallucination_flag=False,
        warnings=[],
        injection_findings=[],
        verifier_verdict=None,
    )


def _force_needs_review(state: GateState, step_name: str) -> None:
    state.verdict = "needs_review"
    state.forced_by.append(step_name)


def step2_basis(state: GateState) -> None:
    """structured_basis vs DB facts, field by field, lower-cased strings, integer count."""
    basis = state.proposer_raw["structured_basis"]
    mismatched = []
    for field in _STEP2_STRING_FIELDS:
        if str(basis[field]).lower() != str(state.facts[field]).lower():
            mismatched.append(field)
    if int(basis["occurrence_count"]) != state.facts["occurrence_count"]:
        mismatched.append("occurrence_count")
    if mismatched:
        state.hallucination_flag = True
        state.mismatched_fields = mismatched
        _force_needs_review(state, "step2")
        state.steps["2"] = "mismatch"
    else:
        state.steps["2"] = "ok"


def _norm(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).split())


def step3_quotes(state: GateState) -> None:
    """Every reason's quote must be a normalised substring of the block it names."""
    survivors: list[dict] = []
    dropped: list[dict] = []
    for index, reason in enumerate(state.reasons):
        block = state.blocks.get(reason["source"])
        if block is None:
            dropped.append({"index": index, "why": "unknown_source"})
            continue
        quote = _norm(reason["quote"])
        if not quote:
            dropped.append({"index": index, "why": "empty_quote"})
            continue
        if quote in _norm(block.plain) or quote in _norm(block.escaped):
            survivors.append(reason)
        else:
            dropped.append({"index": index, "why": "not_substring"})
    state.reasons = survivors
    state.dropped_reasons = dropped
    state.steps["3"] = f"dropped:{len(dropped)}"
    if not survivors:
        _force_needs_review(state, "step3")


def step4_fp_policy(state: GateState, rule_check: RuleCheck) -> None:
    """`false_positive` is kept only when every condition below holds; `missing` names all
    the ones that failed, not just the first. Applies only when verdict == "false_positive"
    at this point — no detector output feeds this step."""
    if state.verdict != "false_positive":
        state.steps["4"] = "n/a"
        return

    facts = state.facts
    missing: list[str] = []
    if str(facts["severity"]).lower() == "critical":
        missing.append("severity")
    if str(facts["ioc_reputation"]).lower() in _FP_IOC_BLOCKS:
        missing.append("ioc_reputation")
    if str(facts["asset_criticality"]).lower() in _FP_ASSET_BLOCKS:
        missing.append("asset_criticality")
    if str(facts["identity_privileged"]).lower() == "true":
        missing.append("identity_privileged")

    playbook_rule_applied = state.proposer_raw["structured_basis"]["playbook_rule_applied"]
    holds, why_not = rule_check(playbook_rule_applied)
    if not holds:
        missing.append("playbook_rule")
        if why_not is not None:
            state.warnings.append(why_not)

    if missing:
        state.missing = missing
        _force_needs_review(state, "step4")
        state.steps["4"] = "missing"
    else:
        state.steps["4"] = "ok"


def step5_detector(state: GateState, scan: Scanner) -> None:
    """Record, never decide: `injection_findings` is populated but the verdict is untouched."""
    state.injection_findings = scan(state.blocks.values())
    state.steps["5"] = f"findings:{len(state.injection_findings)}"


def run_steps_1_to_5(
    parsed: dict,
    facts: Mapping[str, Any],
    blocks: Mapping[str, Block],
    *,
    repaired: bool,
    rule_check: RuleCheck,
    scan: Scanner,
) -> GateState:
    """`start` + steps 2..5, in order. Assumes `parsed` already passed step 1."""
    state = start(parsed, facts, blocks, repaired=repaired)
    step2_basis(state)
    step3_quotes(state)
    step4_fp_policy(state, rule_check)
    step5_detector(state, scan)
    return state


def step6_verifier(state: GateState, verifier_parsed: dict | None) -> None:
    """Compare against `state.verdict` (the verdict *after* step 4), not the proposer's
    original claim — that is what the verifier prompt actually carried (P3-T09)."""
    if verifier_parsed is None:
        _force_needs_review(state, "step6")
        state.steps["6"] = "invalid"
        return

    state.verifier_verdict = verifier_parsed["structured_only_verdict"]
    if verifier_parsed["agree"] is False or state.verifier_verdict != state.verdict:
        _force_needs_review(state, "step6")
        state.steps["6"] = "disagree"
    else:
        state.steps["6"] = "agree"


def step7_output_guard(state: GateState) -> dict:
    """`proposer_raw` with `suggested_action`/`reasons` replaced by the gated values, passed
    through `output_guard.enforce()` — the final `triage_v2` result."""
    result = dict(state.proposer_raw)
    result["suggested_action"] = state.verdict
    result["reasons"] = list(state.reasons)
    enforced = output_guard.enforce(result)
    state.steps["7"] = "ok"
    return enforced


def finish(state: GateState, verifier_parsed: dict | None) -> dict:
    """Step 6 then step 7 — the counterpart to `run_steps_1_to_5` for the second half of the
    gate. Kept separate from the two step functions, which stay individually importable for
    P7's restricted re-run (B2/B3)."""
    step6_verifier(state, verifier_parsed)
    return step7_output_guard(state)


def gate_result(
    state: GateState, *, prompt_version: str, playbook_used_effective: str | None
) -> dict:
    """The document P4 displays and P7 re-gates from (planning decision 1)."""
    return {
        "version": 1,
        "proposed_verdict": state.proposed_verdict,
        "final_verdict": state.verdict,
        "forced": state.proposed_verdict != state.verdict,
        "forced_by": list(state.forced_by),
        "steps": dict(state.steps),
        "hallucination_flag": state.hallucination_flag,
        "mismatched_fields": list(state.mismatched_fields),
        "dropped_reasons": list(state.dropped_reasons),
        "missing": list(state.missing),
        "facts": dict(state.facts),
        "warnings": list(state.warnings),
        "verifier_verdict": state.verifier_verdict,
        "playbook_used_effective": playbook_used_effective,
        "prompt_version": prompt_version,
        "proposer_raw": state.proposer_raw,
    }
