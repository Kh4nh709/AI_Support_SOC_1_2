"""The verdict vocabularies of ① and ② (P14-T01, P14-T02, DEC-213) - one place that names them.

**①.** ``MODEL_ACTIONS`` is what the model may answer: a definite ``false_positive`` or
``true_positive`` (``triage_v3``'s ``suggested_action``). ① no longer offers the model a way to say
"I am not sure".

``GATED_ACTIONS`` is what ① may hold after the gate: the same two, plus ``needs_review``, which only
the system sets (gate steps 2, 3, 4 and 6 force it; the model's own definite answer is kept beside it
as ``gate_result.proposed_verdict``). It is also what the verifier may answer (``verifier_v2``), what
a decision-table rule carries (``kb/lookup.py`` reads the signed YAML's ``then: escalate`` as
``true_positive``), what ``security/output_guard.py`` lets through, and what the CHECK
``ck_llm_runs_suggested_action`` (migration 022) admits.

**②.** ``MODEL_CONCLUSIONS`` is what the model may answer: ``false_positive``, ``policy_violation`` or
``confirmed_incident`` (``investigate_v3``'s ``suggested_conclusion``). ② no longer offers the model
``need_more_data``: it names its best conclusion and lists what is missing in ``next_steps``.

``GATED_CONCLUSIONS`` is what ② may hold after the override: the same three, plus ``need_more_data``,
which only the system sets (``tier2/investigate.py`` writes it when no cited evidence verifies, or when
a high-severity injection finding meets a ``false_positive``; the model's own answer is kept beside it
as ``evidence_check.model_conclusion``). It is what ``tier2/investigation_view.CONCLUSION_LABELS``
labels and what the CHECK ``ck_llm_runs_suggested_conclusion`` admits - that CHECK is not changed by
P14: the override still writes ``need_more_data``.

``security`` and ``kb`` may import only ``infra`` (G1), so ``output_guard.SUGGESTED_ACTIONS`` and
``kb.lookup._ACTIONS`` transcribe ``GATED_ACTIONS``; ``tests/test_verdicts.py`` ties the copies
together, and ties both tuples to ``output_schemas.json`` and to ``builder.Verdict``.
``tests/test_conclusions.py`` does the same for ②'s two tuples, the schema file, the view and the CHECK.

The analyst's own action keeps its name: the route ``POST /api/tier1/alerts/{id}/escalate``,
``transitions.escalate``, the event ``tier1.escalated``, the status ``escalated_tier2`` and the gold
labels ``false_positive | benign | escalate`` are not ①'s verdict and are not renamed.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

MODEL_ACTIONS: tuple[str, ...] = ("false_positive", "true_positive")
GATED_ACTIONS: tuple[str, ...] = ("false_positive", "needs_review", "true_positive")

MODEL_CONCLUSIONS: tuple[str, ...] = ("false_positive", "policy_violation", "confirmed_incident")
GATED_CONCLUSIONS: tuple[str, ...] = MODEL_CONCLUSIONS + ("need_more_data",)

# ── why ① held the model's verdict (P14-T03) ───────────────────────────────────────────────────────

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
_FP_POLICY_PREFIX = "fp_policy:"

#: Every reason ``held_reasons`` can return, in the gate's step order: step 2, step 3, step 4 (one per
#: field, in ``FP_POLICY_FIELDS`` order) and step 6. The UI words each one (``strings.ts``, ``ai1.heldReason``,
#: whose test compares its keys with this tuple), and the blind arm hides the list with ``held_by``.
HELD_REASONS: tuple[str, ...] = (
    _FACTS_MISMATCH,
    _NO_VERIFIED_QUOTE,
    *(_FP_POLICY_PREFIX + field for field in FP_POLICY_FIELDS),
    _VERIFIER_DISAGREES,
)


def _strings(value: Any) -> list[str]:
    """The strings of a JSON list; anything that is not a list gives ``[]`` (a garbled ``gate_result``
    is read as saying nothing, never as an error)."""
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def held_reasons(gate_result: Mapping[str, Any] | None) -> list[str]:
    """Why the gate held the model's definite answer as ``needs_review``: the closed reasons of
    ``HELD_REASONS`` that ``gate_result`` records, in the gate's step order.

    ``facts_mismatch`` is step 2 in ``forced_by``, ``no_verified_quote`` step 3, ``verifier_disagrees``
    step 6; step 4 gives one ``fp_policy:<field>`` per entry of ``missing`` (in the order of ``missing``,
    which is the gate's). Only a value of the closed set leaves: an unknown step name or field, a
    duplicate, and a ``gate_result`` that is ``None`` or not a mapping all give less, never an error. A
    verdict the gate kept has an empty ``forced_by`` and ``missing``, so its list is empty."""
    if not isinstance(gate_result, Mapping):
        return []
    forced_by = set(_strings(gate_result.get("forced_by")))
    reasons: list[str] = []
    if "step2" in forced_by:
        reasons.append(_FACTS_MISMATCH)
    if "step3" in forced_by:
        reasons.append(_NO_VERIFIED_QUOTE)
    for field in _strings(gate_result.get("missing")):
        reason = _FP_POLICY_PREFIX + field
        if field in FP_POLICY_FIELDS and reason not in reasons:
            reasons.append(reason)
    if "step6" in forced_by:
        reasons.append(_VERIFIER_DISAGREES)
    return reasons


def proposed_action(gate_result: Mapping[str, Any] | None) -> str | None:
    """The model's own definite answer, ``gate_result.proposed_verdict``, when it is one the model may
    give (``MODEL_ACTIONS``); ``None`` for anything else - no ``gate_result``, a missing key, and the
    ``needs_review`` / ``escalate`` the model can no longer answer."""
    if not isinstance(gate_result, Mapping):
        return None
    value = gate_result.get("proposed_verdict")
    return value if isinstance(value, str) and value in MODEL_ACTIONS else None
