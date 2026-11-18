"""The 7-step gate that turns a proposer/verifier LLM response into a triage_status.

Implements context pack §7.3 literally (`docs/plan/tasks/P3/P3-T08.prompt.md` pastes the same
seven steps). `security` may import only `infra` (G1), so three things the gate needs — schema
validation (P3-T05), the decision-table check (P3-T10, wrapping `kb.rule_holds`), and the
detector (P3-T07) — arrive as injected callables rather than imported; the verifier's parsed JSON
arrives as a plain argument for the same reason.

DEC-217 (BV-T1): ① gives only `true_positive` or `false_positive`, and every check the gate runs is a
warning shown beside that verdict. `verdict` is the model's own definite answer (`triage_v4`: the model
may not answer `needs_review`) from `start()` to step 7 and no step changes it. A failed check of step 2,
3, 4 or 6 FLAGS the run: it appends its own name (`"step2"`, …) to `flagged_by`, and what it found is
still recorded (`hallucination_flag`, `mismatched_fields`, `dropped_reasons`, `missing`, `warnings`,
`steps`). `needs_review` can no longer leave the gate: `output_guard` refuses it. Before DEC-217 a failed
check forced the verdict to `needs_review` (`forced_by`, `gate_result` version 1); those documents stay in
the database and the readers still read them (`llm.verdicts`).

DEC-219 (RR-T1, as amended) and DEC-225 (RR-T3): the one step that can change the verdict. `step3r_rag_rule` runs
after step 3 and before step 4. It reads the single top knowledge item of the lookup ①'s prompt held: its percentage
(`best_pct`), its side (`entry_side`: `incident` for a confirmed incident, `benign` for the four closed conclusions)
and how the percentage was made (`basis`: `match` for a kept match, `below_floor` for a candidate the rerank scored
under the floor). An incident at or over the threshold makes ①'s verdict `true_positive`, an incident under it
`false_positive`; a benign item at or over it `false_positive`; a benign item under it changes nothing. It is not a
gate force and not a failed check: `forced` stays false, `forced_by` stays empty and `flagged_by` is not touched;
`steps["3r"]` and `gate_result.rag_rule` are the record. `proposed_verdict` stays the model's own answer (the stored
record of it), which the verifier is sent and step 6 compares with; `verdict` is what ① ends with. `security` imports
only `infra`, so the rule is handed plain values (`best_pct | None`, `entry_side | None`, `threshold`, `basis | None`),
computed by `tier1/triage.py`. Tier 1 is not told that a rule exists (the Owner, 18/11): the readers that serve Tier 1
(`llm.verdicts`, `tier1.queue`, `tier1.analysis`) use the stored record to withhold, and say nothing of it.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Any

from app.security import output_guard
from app.security.wrap import REFERENCE_SOURCES, Block

Validator = Callable[[str, Any], list[str]]
RuleCheck = Callable[[str | None], tuple[bool, str | None]]
Scanner = Callable[[Iterable[Block]], list[Any]]

_STEP2_STRING_FIELDS = ("severity", "ioc_reputation", "asset_criticality", "identity_privileged")
_FP_IOC_BLOCKS = frozenset({"malicious", "suspicious"})
_FP_ASSET_BLOCKS = frozenset({"high", "unknown"})

#: DEC-225: the two sides of the top knowledge item the RAG rule reads (`tier1/triage.py` maps the entry's conclusion
#: to one of them: `confirmed_incident` is `incident`, the four closed conclusions are `benign`), and the two ways its
#: percentage was made. Plain strings on purpose: `security` imports only `infra`.
RAG_SIDES: tuple[str, ...] = ("incident", "benign")
RAG_BASES: tuple[str, ...] = ("match", "below_floor")


def _is_number(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _rag_rule_record(
    threshold: int = 0,
    best_pct: int | None = None,
    applied: bool = False,
    changed: bool = False,
    entry_side: str | None = None,
    rule_verdict: str | None = None,
    basis: str | None = None,
) -> dict[str, Any]:
    """`gate_result.rag_rule` (DEC-219, DEC-225): the defaults are the switch-off value every document carries."""
    return {
        "threshold": threshold,
        "best_pct": best_pct,
        "applied": applied,
        "changed": changed,
        "entry_side": entry_side,
        "rule_verdict": rule_verdict,
        "basis": basis,
    }


@dataclass
class GateState:
    proposer_raw: dict  # the parsed model JSON, never mutated
    facts: Mapping[str, Any]  # planning decision 7
    blocks: Mapping[str, Block]  # BuiltPrompt.block_index
    proposed_verdict: str
    # ①'s verdict: the model's answer, which only `step3r_rag_rule` (DEC-219) can replace
    verdict: str
    reasons: list[dict]  # surviving reasons
    steps: dict[str, str]
    flagged_by: list[str]  # the steps whose check failed, in step order
    missing: list[str]
    mismatched_fields: list[str]
    dropped_reasons: list[dict]
    hallucination_flag: bool
    warnings: list[str]
    injection_findings: list[Any]
    verifier_verdict: str | None
    #: DEC-218: the first call's schema-validator messages when step 1 was `repaired`, else `[]`. They may name a
    #: key the model invented, so they are for `gate_result` (the database) only and never for a prompt.
    step1_errors: list[str] = dataclass_field(default_factory=list)
    #: DEC-219 / DEC-225: `{threshold, best_pct, applied, changed, entry_side, rule_verdict, basis}`, what
    #: `step3r_rag_rule` was given and found. Before the step runs (and when no caller runs it) it is the switch-off
    #: value, so every document carries the key.
    rag_rule: dict[str, Any] = dataclass_field(default_factory=_rag_rule_record)


def step1_schema(
    parsed: dict | None, validate: Validator, *, repaired: bool
) -> tuple[str, list[str]]:
    """`parsed=None` (JSON did not parse) counts as invalid without calling `validate`."""
    if parsed is None:
        errors = ["<root>: invalid JSON"]
    else:
        errors = validate("triage_v4", parsed)
    if not errors:
        return "ok", []
    return ("failed" if repaired else "repair"), errors


def start(
    parsed: dict,
    facts: Mapping[str, Any],
    blocks: Mapping[str, Block],
    *,
    repaired: bool,
    step1_errors: Sequence[str] = (),
) -> GateState:
    """Build the initial state after step 1 has passed. `step1_errors` (DEC-218) are what the first call got
    wrong; they are kept only when step 1 was `repaired` - a run valid at once has none."""
    return GateState(
        proposer_raw=parsed,
        facts=facts,
        blocks=blocks,
        proposed_verdict=parsed["suggested_action"],
        verdict=parsed["suggested_action"],
        reasons=list(parsed["reasons"]),
        steps={"1": "repaired" if repaired else "ok"},
        flagged_by=[],
        missing=[],
        mismatched_fields=[],
        dropped_reasons=[],
        hallucination_flag=False,
        warnings=[],
        injection_findings=[],
        verifier_verdict=None,
        step1_errors=list(step1_errors) if repaired else [],
    )


def _flag(state: GateState, step_name: str) -> None:
    """A failed check raises a warning: the step's name joins `flagged_by`. The verdict is not touched."""
    if step_name not in state.flagged_by:
        state.flagged_by.append(step_name)


def step2_basis(state: GateState) -> None:
    """structured_basis vs DB facts, field by field, lower-cased strings, integer count. A count
    that is `None` is not compared (DEC-209 item 2): SOAR sent one representative of the case, so
    there is no number to check the model's against (DEC-208 item 4)."""
    basis = state.proposer_raw["structured_basis"]
    mismatched = []
    for field in _STEP2_STRING_FIELDS:
        if str(basis[field]).lower() != str(state.facts[field]).lower():
            mismatched.append(field)
    expected = state.facts["occurrence_count"]
    if expected is not None and int(basis["occurrence_count"]) != expected:
        mismatched.append("occurrence_count")
    if mismatched:
        state.hallucination_flag = True
        state.mismatched_fields = mismatched
        _flag(state, "step2")
        state.steps["2"] = "mismatch"
    else:
        state.steps["2"] = "ok"


def _norm(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).split())


def step3_quotes(state: GateState) -> None:
    """Every reason's quote must be a normalised substring of the block it names. A reason whose quote is
    not verified leaves the reasons the gate hands on (`dropped_reasons` records it); no survivor flags
    the run, and its result then carries `reasons: []`.

    DEC-223 (defence in depth for A3): a reason whose source is one of `wrap.REFERENCE_SOURCES` (the MITRE
    reference block) is dropped as `unknown_source` although the block is in `state.blocks`. That block is
    reference material, never evidence, and a quote taken from it would otherwise be a substring of it and pass.
    Step 1 (the schema's source enum) and step 7 (`output_guard.REASON_SOURCES`) keep such a reason out of a run
    already; this makes step 3 refuse it on its own, should either of them ever be widened."""
    survivors: list[dict] = []
    dropped: list[dict] = []
    for index, reason in enumerate(state.reasons):
        block = state.blocks.get(reason["source"])
        if block is None or reason["source"] in REFERENCE_SOURCES:
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
        _flag(state, "step3")


def step3r_rag_rule(
    state: GateState,
    best_pct: int | None,
    entry_side: str | None,
    threshold: int,
    basis: str | None = None,
) -> None:
    """The RAG rule (DEC-219, two-sided since DEC-225). It reads the single top knowledge item of the lookup ①'s
    prompt held: `best_pct` (its percentage: a kept match's `round(score * 100)`, or, for a lookup that kept none,
    the best scored candidate's, cut down), `entry_side` (`"incident"` | `"benign"`, from the entry's conclusion)
    and `basis` (`"match"` | `"below_floor"`: only recorded). It APPLIES when `threshold > 0`, `best_pct` is an
    integer and `entry_side` is one of the two, except for a `benign` item under the threshold (then the model's
    answer stands):

    * `incident`, `best_pct >= threshold`: ①'s verdict is `true_positive`; under the threshold, `false_positive`;
    * `benign`, `best_pct >= threshold`: `false_positive`.

    Equal applies (80 at threshold 80). `rule_verdict` is that verdict; `changed` is "applied and `rule_verdict`
    differs from the model's own answer" (`proposed_verdict`), and when the rule applies ①'s verdict
    (`state.verdict`) is the rule's. The step is `changed`, `applied` (the rule agreed with the model) or `n/a`. The
    rule reads the model's own answer, not the verdict so far, so a second call gives the same state. It runs
    wherever step 3 runs, and step 4 then evaluates the verdict it finds. It is neither a force (`forced` and
    `forced_by` are not touched: the record is `steps["3r"]` and `rag_rule`) nor a failed check (`flagged_by`, the
    reasons and `proposed_verdict` are not touched). A value that is not what it should be (a side outside
    `RAG_SIDES`, a percentage that is not an integer, a basis outside `RAG_BASES`) is recorded as `None`, and the
    rule does not apply to it."""
    pct = best_pct if _is_number(best_pct) else None
    side = entry_side if isinstance(entry_side, str) and entry_side in RAG_SIDES else None
    how = basis if isinstance(basis, str) and basis in RAG_BASES else None
    rule_verdict: str | None = None
    if threshold > 0 and pct is not None and side is not None:
        if pct >= threshold:
            rule_verdict = "true_positive" if side == "incident" else "false_positive"
        elif side == "incident":
            rule_verdict = "false_positive"
    applied = rule_verdict is not None
    changed = applied and rule_verdict != state.proposed_verdict
    if rule_verdict is not None:
        state.verdict = rule_verdict
    state.rag_rule = _rag_rule_record(threshold, pct, applied, changed, side, rule_verdict, how)
    state.steps["3r"] = "changed" if changed else "applied" if applied else "n/a"


def step4_fp_policy(state: GateState, rule_check: RuleCheck) -> None:
    """A `false_positive` verdict is checked against every condition below; `missing` names all the ones
    that failed, not just the first, and any of them flags the run. Evaluated for EVERY `false_positive`
    verdict, whatever step 2 or step 3 found (a flag no longer ends the policy check); `n/a` only for a
    `true_positive` verdict. It evaluates the verdict it finds (`state.verdict`): a `false_positive` the RAG
    rule produced (`step3r_rag_rule`, DEC-219) gets the same checks as one the model gave, and a `true_positive` the
    rule produced (DEC-225) is `n/a` like any other. No detector output feeds this step."""
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
        _flag(state, "step4")
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
    step1_errors: Sequence[str] = (),
    rag_best_pct: int | None = None,
    rag_entry_side: str | None = None,
    rag_threshold: int = 0,
    rag_basis: str | None = None,
) -> GateState:
    """`start` + steps 2..5, in order, the RAG rule (DEC-219, DEC-225) between 3 and 4. Assumes `parsed` already
    passed step 1. The defaults are the switch off: the rule's step is `n/a` and nothing else changes.
    """
    state = start(parsed, facts, blocks, repaired=repaired, step1_errors=step1_errors)
    step2_basis(state)
    step3_quotes(state)
    step3r_rag_rule(state, rag_best_pct, rag_entry_side, rag_threshold, rag_basis)
    step4_fp_policy(state, rule_check)
    step5_detector(state, scan)
    return state


def step6_verifier(state: GateState, verifier_parsed: dict | None) -> None:
    """Compare against `state.proposed_verdict`: the model's own answer, which is what the verifier prompt
    carried (P3-T09; `false_positive` or `true_positive`). Since DEC-219 that is not always the verdict ① ends
    with: the verifier is not asked about a verdict the RAG rule produced, it checks the model's claim. A verifier answer that is unusable (`None`) is `invalid` and flags the run; `agree` false, or a
    `structured_only_verdict` that differs from the model's verdict (the verifier may still answer
    `needs_review`), is `disagree` and flags it; otherwise `agree`."""
    if verifier_parsed is None:
        _flag(state, "step6")
        state.steps["6"] = "invalid"
        return

    state.verifier_verdict = verifier_parsed["structured_only_verdict"]
    if verifier_parsed["agree"] is False or state.verifier_verdict != state.proposed_verdict:
        _flag(state, "step6")
        state.steps["6"] = "disagree"
    else:
        state.steps["6"] = "agree"


def step7_output_guard(state: GateState) -> dict:
    """`proposer_raw` with `suggested_action`/`reasons` replaced by the gated values, passed
    through `output_guard.enforce()` — the final `triage_v4`-shaped result: ①'s verdict (the model's own, or the
    verdict the RAG rule put in its place; a `needs_review` raises `OutputGuardError`) and the reasons
    whose quote was verified (the model's, also when the rule changed the verdict). DEC-221: the five fields the
    model writes for the analyst (`summary`, `reading_attack`, `reading_benign`, `would_change`, `next_checks`) go
    through `proposer_raw` untouched and `output_guard.enforce` checks their types; no other step reads them.
    """
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
    """The document P4 displays and P7 re-gates from (planning decision 1). Version 2 (DEC-217): the
    proposed verdict is the model's answer and `flagged_by` names the steps whose check failed, in step order;
    no check forces anything. `step1_errors` (DEC-218, still version 2: a reader that does not know the key is
    not affected) is what the first call got wrong when the repair round fixed it, else `[]`; it may name a key
    the model invented and is never read into a prompt.

    DEC-219 (still version 2, same reason): `rag_rule` is on every document (the switch off: threshold 0, nothing
    applied). DEC-225 widens it to `{threshold, best_pct, applied, changed, entry_side, rule_verdict, basis}`:
    `best_pct` is the percentage the rule compared (a kept match's, or the below-floor candidate's), `entry_side`
    the top item's side (`incident` | `benign` | null), `rule_verdict` the verdict the rule gave when it applied
    (`true_positive` | `false_positive` | null) and `basis` how the percentage was made (`match` | `below_floor` |
    null). A DEC-219 document has the first four keys only and a version 1 document none: the readers
    (`llm.verdicts`) read what they find. `proposed_verdict` is the model's own answer, the stored record of it;
    `final_verdict` is the verdict after the RAG rule, so the two differ exactly when `rag_rule.changed` is true.
    The rule is not a gate force: `forced` stays false and `forced_by` stays empty on every new run, as since
    DEC-217. `flagged_by` is not touched by the rule either: it is not a failed check."""
    return {
        "version": 2,
        "proposed_verdict": state.proposed_verdict,
        "final_verdict": state.verdict,
        "forced": False,
        "forced_by": [],
        "flagged_by": list(state.flagged_by),
        "rag_rule": dict(state.rag_rule),
        "step1_errors": list(state.step1_errors),
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
