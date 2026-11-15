"""The verdict vocabularies of ① and ② (P14-T01, P14-T02, DEC-213) - one place that names them.

**①.** ``MODEL_ACTIONS`` is what the model may answer: a definite ``false_positive`` or
``true_positive`` (``triage_v3``'s ``suggested_action``). ① no longer offers the model a way to say
"I am not sure".

``GATED_ACTIONS`` is what a NEW ① run may hold after the gate (DEC-217): the same two. No gate step sets a
verdict of its own any more - a failed check only flags the run (``gate_result.flagged_by``, shown as a
warning beside the verdict) - so what ``security/output_guard.py`` lets through is the model's answer, with
one exception (DEC-219): below ``TRIAGE_RAG_FP_BELOW_PCT`` ``false_positive`` is ①'s default answer
(``gate_result.rag_rule``), the model's own answer staying in ``gate_result.proposed_verdict``. For such a run
Tier 1 is served the verdict ① ended with, and no confidence: ``rag_rule_applied``,
``served_proposed_action`` and ``served_confidence`` below.

``STORED_ACTIONS`` is what a STORED ① row may hold: the two, plus ``needs_review``, which the gate wrote
before DEC-217 (steps 2, 3, 4 and 6 forced it; the model's own definite answer is kept beside it as
``gate_result.proposed_verdict``). Old rows keep it - ``llm_runs`` is immutable - so it is what the CHECK
``ck_llm_runs_suggested_action`` (migration 022) still admits; ``served_action`` is what Tier 1 is shown
for such a row.

``REVIEW_ACTIONS`` is what the verifier may answer (``verifier_v2``: it may still say ``needs_review``)
and what a decision-table rule carries (``kb/lookup.py`` reads the signed YAML's ``then: escalate`` as
``true_positive``; ``builder.Verdict`` renders the same three in the verifier's prompt).

**②.** ``MODEL_CONCLUSIONS`` is what the model may answer: ``false_positive``, ``policy_violation`` or
``confirmed_incident`` (``investigate_v3``'s ``suggested_conclusion``). ② no longer offers the model
``need_more_data``: it names its best conclusion and lists what is missing in ``next_steps``.

``GATED_CONCLUSIONS`` is what ② may hold after the override: the same three, plus ``need_more_data``,
which only the system sets (``tier2/investigate.py`` writes it when no cited evidence verifies, or when
a high-severity injection finding meets a ``false_positive``; the model's own answer is kept beside it
as ``evidence_check.model_conclusion``). It is what ``tier2/investigation_view.CONCLUSION_LABELS``
labels and what the CHECK ``ck_llm_runs_suggested_conclusion`` admits - that CHECK is not changed by
P14: the override still writes ``need_more_data``.

``security`` and ``kb`` may import only ``infra`` (G1), so ``output_guard.SUGGESTED_ACTIONS`` transcribes
``GATED_ACTIONS`` and ``kb.lookup._ACTIONS`` transcribes ``REVIEW_ACTIONS``; ``tests/test_verdicts.py`` ties
the copies together, ties the tuples to ``output_schemas.json``, to ``builder.Verdict`` and to the CHECK.
``tests/test_conclusions.py`` does the same for ②'s two tuples, the schema file, the view and the CHECK.

The analyst's own action keeps its name: the route ``POST /api/tier1/alerts/{id}/escalate``,
``transitions.escalate``, the event ``tier1.escalated``, the status ``escalated_tier2`` and the gold
labels ``false_positive | benign | escalate`` are not ①'s verdict and are not renamed.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

MODEL_ACTIONS: tuple[str, ...] = ("false_positive", "true_positive")
GATED_ACTIONS: tuple[str, ...] = MODEL_ACTIONS
STORED_ACTIONS: tuple[str, ...] = ("false_positive", "needs_review", "true_positive")
REVIEW_ACTIONS: tuple[str, ...] = ("false_positive", "needs_review", "true_positive")

MODEL_CONCLUSIONS: tuple[str, ...] = ("false_positive", "policy_violation", "confirmed_incident")
GATED_CONCLUSIONS: tuple[str, ...] = MODEL_CONCLUSIONS + ("need_more_data",)

# ── which checks raised a warning on the model's verdict (P14-T03, DEC-217) ───────────────────────────

#: The fields gate step 4 (``security/gate.py``, ``step4_fp_policy``) can name in ``gate_result.missing``,
#: in the order it appends them.
FP_POLICY_FIELDS: tuple[str, ...] = (
    "severity",
    "ioc_reputation",
    "asset_criticality",
    "identity_privileged",
    "playbook_rule",
)

_FACTS_MISMATCH = "facts_mismatch"
_NO_VERIFIED_QUOTE = "no_verified_quote"
_VERIFIER_DISAGREES = "verifier_disagrees"
_VERIFIER_INVALID = "verifier_invalid"
_FP_POLICY_PREFIX = "fp_policy:"

#: Every reason ``held_reasons`` can return, in the gate's step order: step 2, step 3, step 4 (one per
#: field, in ``FP_POLICY_FIELDS`` order) and step 6 (``verifier_disagrees``, or ``verifier_invalid`` when
#: the verifier's answer was unusable). A literal on purpose: the UI words each one
#: (``strings.ts``, ``ai1.heldReason``) and its test reads this tuple from the source; the blind arm
#: hides the list with ``held_by``. ``tests/test_held_reasons.py`` ties it to ``FP_POLICY_FIELDS``.
#: DEC-217: the codes now mean "the checks that raised a warning" on a verdict that is the model's own;
#: the names (``HELD_REASONS``, ``held_reasons``, the wire field ``held_by``) are kept so the API does not move.
HELD_REASONS: tuple[str, ...] = (
    "facts_mismatch",
    "no_verified_quote",
    "fp_policy:severity",
    "fp_policy:ioc_reputation",
    "fp_policy:asset_criticality",
    "fp_policy:identity_privileged",
    "fp_policy:playbook_rule",
    "verifier_disagrees",
    "verifier_invalid",
)


def _strings(value: Any) -> list[str]:
    """The strings of a JSON list; anything that is not a list gives ``[]`` (a garbled ``gate_result``
    is read as saying nothing, never as an error)."""
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def held_reasons(gate_result: Mapping[str, Any] | None) -> list[str]:
    """The checks that raised a warning on ①'s verdict: the closed reasons of ``HELD_REASONS`` that
    ``gate_result`` records, in the gate's step order. Before DEC-217 the same checks held the model's
    answer back as ``needs_review``; the codes are the same and now mean "warning".

    The steps come from ``flagged_by`` (``gate_result`` version 2) when the document has it - a list - and
    from ``forced_by`` (version 1, the old gate's forces) otherwise; a ``flagged_by`` that is ``null`` or
    not a list counts as absent, because the queue's SQL projection hands over ``null`` for a version 1
    row. ``facts_mismatch`` is step 2, ``no_verified_quote`` step 3; step 6 is ``verifier_invalid`` when
    the gate recorded that the verifier's answer was unusable (``steps["6"] == "invalid"``,
    ``security/gate.py`` ``step6_verifier``) and ``verifier_disagrees`` for every other step-6 entry; step 4
    gives one ``fp_policy:<field>`` per entry of ``missing`` (in the order of ``missing``, which is the
    gate's). Only a value of the closed set leaves: an unknown step name or field, a duplicate, and a
    ``gate_result`` that is ``None`` or not a mapping all give less, never an error. A run no check
    flagged has an empty ``flagged_by`` (``forced_by`` in version 1) and ``missing``, so its list is
    empty."""
    if not isinstance(gate_result, Mapping):
        return []
    flagged = gate_result.get("flagged_by")
    steps_named = set(
        _strings(flagged if isinstance(flagged, list) else gate_result.get("forced_by"))
    )
    reasons: list[str] = []
    if "step2" in steps_named:
        reasons.append(_FACTS_MISMATCH)
    if "step3" in steps_named:
        reasons.append(_NO_VERIFIED_QUOTE)
    for field in _strings(gate_result.get("missing")):
        reason = _FP_POLICY_PREFIX + field
        if field in FP_POLICY_FIELDS and reason not in reasons:
            reasons.append(reason)
    if "step6" in steps_named:
        steps = gate_result.get("steps")
        invalid = isinstance(steps, Mapping) and steps.get("6") == "invalid"
        reasons.append(_VERIFIER_INVALID if invalid else _VERIFIER_DISAGREES)
    return reasons


def proposed_action(gate_result: Mapping[str, Any] | None) -> str | None:
    """The model's own definite answer, ``gate_result.proposed_verdict``, when it is one the model may
    give (``MODEL_ACTIONS``); ``None`` for anything else - no ``gate_result``, a missing key, and the
    ``needs_review`` / ``escalate`` the model can no longer answer."""
    if not isinstance(gate_result, Mapping):
        return None
    value = gate_result.get("proposed_verdict")
    return value if isinstance(value, str) and value in MODEL_ACTIONS else None


def rag_rule_applied(gate_result: Any) -> bool:
    """Whether the stored run says the RAG low-match rule (DEC-219) applied to it: ``gate_result.rag_rule`` is an
    object whose ``applied`` is the JSON boolean ``true``. Anything else - no ``rag_rule`` (a run from before the
    key, or a version 1 document), ``null``, a string, a ``true`` that is not a boolean - is "did not apply",
    never an error. Whether the rule also *changed* the model's answer is ``rag_rule.changed``; the serving rule
    below does not need it."""
    rule = gate_result.get("rag_rule") if isinstance(gate_result, Mapping) else None
    return isinstance(rule, Mapping) and rule.get("applied") is True


def served_proposed_action(gate_result: Mapping[str, Any] | None, served: str | None) -> str | None:
    """The "model's own answer" as the Tier 1 API serves it (the queue row's and the alert view's
    ``proposed_action``, ``Suggestion.gate.proposed_verdict``). Below the RAG threshold ``false_positive`` is
    ①'s default answer (DEC-219, amended), so for a run the rule applied to (``rag_rule_applied``, whether or not
    the model had answered ``false_positive`` itself) Tier 1 is served the verdict ① ended with - ``served``, the
    ``served_action`` of the same run - and never the model's own answer, which stays in the stored
    ``gate_result.proposed_verdict`` (the admin LLM page and the audit log show stored rows as they are). For
    every other run it is ``proposed_action(gate_result)``, exactly as before. ``served`` that is not one of
    ``MODEL_ACTIONS`` (no usable result) gives ``None`` for a rule-applied run: no verdict, not the model's.
    """
    if rag_rule_applied(gate_result):
        return served if isinstance(served, str) and served in MODEL_ACTIONS else None
    return proposed_action(gate_result)


def served_confidence(confidence: Any, gate_result: Mapping[str, Any] | None) -> Any:
    """The model's ``result.confidence`` as the Tier 1 API serves it (the alert view's ``suggestion.confidence``,
    the queue row's ``confidence``, and so what ``tier1/decide.py`` records with a decision). It is the model's
    confidence in ITS OWN answer, not in the default verdict ① ended with below the RAG threshold (DEC-219,
    amended), so for a run the rule applied to (``rag_rule_applied``) it is ``None``; for every other run it is
    ``confidence`` as stored. The stored ``result.confidence`` is untouched: the admin LLM page and the audit log
    show stored rows as they are."""
    return None if rag_rule_applied(gate_result) else confidence


def served_action(result: Any, gate_result: Mapping[str, Any] | None) -> str | None:
    """The verdict Tier 1 is shown for a STORED ① run (DEC-217, G3): the stored ``result.suggested_action``
    when it is one of ``MODEL_ACTIONS``; for a stored ``needs_review`` (a run the pre-DEC-217 gate held,
    ``llm_runs`` being immutable) the model's own answer, ``proposed_action(gate_result)``; ``None`` when
    neither exists - no ``result``, a value that is none of the three, or a held run whose ``gate_result``
    has no usable ``proposed_verdict``. Never ``needs_review``, and never a verdict ① did not stand behind:
    a stored definite answer is never replaced by ``proposed_verdict``.

    ``served_action_sql`` is the SQL twin of this function; ``tests/test_queue_held.py`` holds the two to the same
    answers."""
    stored = result.get("suggested_action") if isinstance(result, Mapping) else None
    if isinstance(stored, str) and stored in MODEL_ACTIONS:
        return stored
    if stored == "needs_review":
        return proposed_action(gate_result)
    return None


def served_action_sql(alias: str) -> str:
    """``served_action`` as a SQL expression over the ``llm_runs`` row (or LATERAL row) named ``alias``: the
    stored ``result->>'suggested_action'`` when it is one of ``MODEL_ACTIONS``; for a stored ``needs_review``
    the ``gate_result->>'proposed_verdict'`` when that is one of them; else NULL. The one copy: the queue list
    (``tier1/queue.py``) and the operations export's reading of ① at an escalation (``eval/ops_export.py``) both
    take it from here, so what Tier 1 was shown is read the same way everywhere. ``alias`` is a SQL identifier
    the caller wrote (``r``), never a request value."""
    actions = ", ".join(f"'{action}'" for action in MODEL_ACTIONS)
    stored = f"{alias}.result->>'suggested_action'"
    proposed = f"{alias}.gate_result->>'proposed_verdict'"
    return (
        f"CASE WHEN {stored} IN ({actions}) THEN {stored} "
        f"WHEN {stored} = 'needs_review' AND {proposed} IN ({actions}) THEN {proposed} END"
    )
