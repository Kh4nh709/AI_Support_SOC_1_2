"""Unconditionally enforce recommend-only output before a model result reaches an analyst.

`security` may import only `infra` (G1), so the closed sets below are §6.2's `triage_v4`
vocabulary transcribed here, not imported from `app.llm.schemas`. `enforce()` is the step-7
re-check: it never adds an action and never rewrites text — ① has no actions to strip, and the
legacy output_guard's "force `requires_human_approval`" has no counterpart in `triage_v4`.
`SUGGESTED_ACTIONS` is the vocabulary AFTER the gate (`llm/verdicts.py`'s `GATED_ACTIONS`): the
model's `false_positive | true_positive`, nothing else (DEC-217: no step sets a verdict of its own, so a
`needs_review` can no longer leave the gate).

DEC-221 (AP-T1): `triage_v4` is `triage_v3` plus five fields the model writes for the analyst. They are free text,
so there is no vocabulary to check: `enforce()` carries them through as they are and checks their TYPES - four
strings (`summary`, `reading_attack`, `reading_benign`, `would_change`) and `next_checks`, a non-empty list of
strings. A missing one, or one of the wrong type, is an `OutputGuardError` like any other violation: step 1 has
already refused it, so this is the second line.
"""

from __future__ import annotations

from typing import Any

SUGGESTED_ACTIONS = frozenset({"false_positive", "true_positive"})
CONFIDENCES = frozenset({"low", "medium", "high"})
SEVERITIES = frozenset({"critical", "high", "medium", "low"})
IOC_REPUTATIONS = frozenset({"malicious", "suspicious", "clean", "not_found", "skipped"})
ASSET_CRITICALITIES = frozenset({"high", "medium", "low", "unknown"})
IDENTITY_PRIVILEGED = frozenset({"true", "false", "unknown"})
REASON_SOURCES = frozenset(
    {
        "wazuh_raw_log",
        "rule_description",
        "correlation_samples",
        "kb_playbook",
        "context",
        "siem_context",
    }
)

STRUCTURED_BASIS_FIELDS = (
    "severity",
    "ioc_reputation",
    "asset_criticality",
    "identity_privileged",
    "occurrence_count",
    "playbook_rule_applied",
)
REASON_FIELDS = ("claim", "quote", "source")
#: The fields `triage_v4` added to `triage_v3` (DEC-221): four strings and a non-empty list of strings.
ANALYST_TEXT_FIELDS = ("summary", "reading_attack", "reading_benign", "would_change")
ANALYST_LIST_FIELD = "next_checks"
TOP_LEVEL_FIELDS = (
    "suggested_action",
    "confidence",
    "structured_basis",
    "reasons",
    "playbook_used",
    *ANALYST_TEXT_FIELDS,
    ANALYST_LIST_FIELD,
)


class OutputGuardError(ValueError):
    """Raised when a `triage_v4`-shaped result violates §6.2's closed sets or types after the gate."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise OutputGuardError(message)


def _enforce_structured_basis(raw: Any) -> dict:
    _require(isinstance(raw, dict), "structured_basis: expected object")
    for field in STRUCTURED_BASIS_FIELDS:
        _require(field in raw, f"structured_basis.{field}: missing")
    _require(raw["severity"] in SEVERITIES, "structured_basis.severity: invalid")
    _require(raw["ioc_reputation"] in IOC_REPUTATIONS, "structured_basis.ioc_reputation: invalid")
    _require(
        raw["asset_criticality"] in ASSET_CRITICALITIES,
        "structured_basis.asset_criticality: invalid",
    )
    _require(
        raw["identity_privileged"] in IDENTITY_PRIVILEGED,
        "structured_basis.identity_privileged: invalid",
    )
    occurrence_count = raw["occurrence_count"]
    _require(
        isinstance(occurrence_count, int) and not isinstance(occurrence_count, bool),
        "structured_basis.occurrence_count: expected integer",
    )
    playbook_rule_applied = raw["playbook_rule_applied"]
    _require(
        playbook_rule_applied is None or isinstance(playbook_rule_applied, str),
        "structured_basis.playbook_rule_applied: expected string or null",
    )
    return {field: raw[field] for field in STRUCTURED_BASIS_FIELDS}


def _enforce_reason(raw: Any) -> dict:
    _require(isinstance(raw, dict), "reasons[]: expected object")
    for field in REASON_FIELDS:
        _require(field in raw, f"reasons[].{field}: missing")
    _require(isinstance(raw["claim"], str), "reasons[].claim: expected string")
    _require(isinstance(raw["quote"], str), "reasons[].quote: expected string")
    _require(raw["source"] in REASON_SOURCES, "reasons[].source: invalid")
    return {field: raw[field] for field in REASON_FIELDS}


def _enforce_analyst_fields(result: dict) -> dict:
    """The five fields of `triage_v4` that are not in `triage_v3`, as they are: strings, and `next_checks` a
    non-empty list of strings. Nothing is rewritten, trimmed or cut (the server cuts `next_checks` where it
    serves it)."""
    for field in ANALYST_TEXT_FIELDS:
        _require(isinstance(result[field], str), f"{field}: expected string")
    next_checks = result[ANALYST_LIST_FIELD]
    _require(isinstance(next_checks, list), f"{ANALYST_LIST_FIELD}: expected array")
    _require(len(next_checks) > 0, f"{ANALYST_LIST_FIELD}: expected non-empty array")
    for item in next_checks:
        _require(isinstance(item, str), f"{ANALYST_LIST_FIELD}[]: expected string")
    return {
        **{field: result[field] for field in ANALYST_TEXT_FIELDS},
        ANALYST_LIST_FIELD: list(next_checks),
    }


def enforce(result: dict) -> dict:
    """Re-check `result` (a `triage_v4`-shaped dict) against §6.2's closed sets and types, drop keys
    outside the schema, and return a fresh dict. Raises `OutputGuardError` on any violation —
    this should be impossible after step 1, and a test proves the guard is live by feeding it
    a crafted object directly."""
    _require(isinstance(result, dict), "result: expected object")
    for field in TOP_LEVEL_FIELDS:
        _require(field in result, f"{field}: missing")
    _require(result["suggested_action"] in SUGGESTED_ACTIONS, "suggested_action: invalid")
    _require(result["confidence"] in CONFIDENCES, "confidence: invalid")
    structured_basis = _enforce_structured_basis(result["structured_basis"])
    _require(isinstance(result["reasons"], list), "reasons: expected array")
    reasons = [_enforce_reason(r) for r in result["reasons"]]
    playbook_used = result["playbook_used"]
    _require(
        playbook_used is None or isinstance(playbook_used, str),
        "playbook_used: expected string or null",
    )
    analyst = _enforce_analyst_fields(result)
    return {
        "suggested_action": result["suggested_action"],
        "confidence": result["confidence"],
        "structured_basis": structured_basis,
        "reasons": reasons,
        "playbook_used": playbook_used,
        **analyst,
    }
