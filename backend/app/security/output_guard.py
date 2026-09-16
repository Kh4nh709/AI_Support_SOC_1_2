"""Unconditionally enforce recommend-only output before a model result reaches an analyst.

`security` may import only `infra` (G1), so the closed sets below are §6.2's `triage_v2`
vocabulary transcribed here, not imported from `app.llm.schemas`. `enforce()` is the step-7
re-check: it never adds an action and never rewrites text — ① has no actions to strip, and the
legacy output_guard's "force `requires_human_approval`" has no counterpart in `triage_v2`.
"""

from __future__ import annotations

from typing import Any

SUGGESTED_ACTIONS = frozenset({"false_positive", "needs_review", "escalate"})
CONFIDENCES = frozenset({"low", "medium", "high"})
SEVERITIES = frozenset({"critical", "high", "medium", "low"})
IOC_REPUTATIONS = frozenset({"malicious", "suspicious", "clean", "not_found", "skipped"})
ASSET_CRITICALITIES = frozenset({"high", "medium", "low", "unknown"})
IDENTITY_PRIVILEGED = frozenset({"true", "false", "unknown"})
REASON_SOURCES = frozenset(
    {"wazuh_raw_log", "rule_description", "correlation_samples", "kb_playbook", "context"}
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
TOP_LEVEL_FIELDS = (
    "suggested_action",
    "confidence",
    "structured_basis",
    "reasons",
    "playbook_used",
)


class OutputGuardError(ValueError):
    """Raised when a `triage_v2`-shaped result violates §6.2's closed sets after the gate."""


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


def enforce(result: dict) -> dict:
    """Re-check `result` (a `triage_v2`-shaped dict) against §6.2's closed sets, drop keys
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
    return {
        "suggested_action": result["suggested_action"],
        "confidence": result["confidence"],
        "structured_basis": structured_basis,
        "reasons": reasons,
        "playbook_used": playbook_used,
    }
