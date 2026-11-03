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

MODEL_ACTIONS: tuple[str, ...] = ("false_positive", "true_positive")
GATED_ACTIONS: tuple[str, ...] = ("false_positive", "needs_review", "true_positive")

MODEL_CONCLUSIONS: tuple[str, ...] = ("false_positive", "policy_violation", "confirmed_incident")
GATED_CONCLUSIONS: tuple[str, ...] = MODEL_CONCLUSIONS + ("need_more_data",)
