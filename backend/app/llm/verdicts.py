"""①'s two verdict vocabularies (P14-T01, DEC-213) - one place that names them.

``MODEL_ACTIONS`` is what the model may answer: a definite ``false_positive`` or ``true_positive``
(``triage_v3``'s ``suggested_action``). ① no longer offers the model a way to say "I am not sure".

``GATED_ACTIONS`` is what ① may hold after the gate: the same two, plus ``needs_review``, which only
the system sets (gate steps 2, 3, 4 and 6 force it; the model's own definite answer is kept beside it
as ``gate_result.proposed_verdict``). It is also what the verifier may answer (``verifier_v2``), what
a decision-table rule carries (``kb/lookup.py`` reads the signed YAML's ``then: escalate`` as
``true_positive``), what ``security/output_guard.py`` lets through, and what the CHECK
``ck_llm_runs_suggested_action`` (migration 022) admits.

``security`` and ``kb`` may import only ``infra`` (G1), so ``output_guard.SUGGESTED_ACTIONS`` and
``kb.lookup._ACTIONS`` transcribe ``GATED_ACTIONS``; ``tests/test_verdicts.py`` ties the copies
together, and ties both tuples to ``output_schemas.json`` and to ``builder.Verdict``.

The analyst's own action keeps its name: the route ``POST /api/tier1/alerts/{id}/escalate``,
``transitions.escalate``, the event ``tier1.escalated``, the status ``escalated_tier2`` and the gold
labels ``false_positive | benign | escalate`` are not ①'s verdict and are not renamed.
"""

from __future__ import annotations

MODEL_ACTIONS: tuple[str, ...] = ("false_positive", "true_positive")
GATED_ACTIONS: tuple[str, ...] = ("false_positive", "needs_review", "true_positive")
