"""Pure tests for app.tier1.visibility — the blind-branch filter (P4-T02).

`strip` is one pure function with two modes. The **matrix** (`test_matrix`) is
status (6) × `suggestion_visible` (2) × `mode` (2) = 24 cases, each asserting
the exact key set that survives on a fixture view carrying **every** key in
both denylists plus nested `correlation` rows/samples that carry `status`.
The expected sets are spelled out as literals here — not derived from the
module's constants — so a change to a constant is caught, not mirrored
(red case (f) of the card: drop `"source"` from `LABELING_DENYLIST` and the
labeling half of the matrix goes red together with
`test_labeling_mode_strips_source_for_every_value`).

No database, no marker: `make test` runs this file.
"""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from typing import Any

import pytest
from app.tier1.visibility import (
    ANALYST_HIDE,
    LABELING_DENYLIST,
    LABELING_PREFIXES,
    SHOW_STATES,
    is_decided,
    strip,
)

_T = datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC)

# docs/Schema/schema.sql ck_alerts_status, verbatim (the full closed set —
# `test_is_decided` walks all ten; the matrix uses the six the card names).
_ALL_STATUSES = (
    "received",
    "duplicate",
    "auto_closed",
    "enriching",
    "queued_tier1",
    "tier1_active",
    "escalated_tier2",
    "closed_fp",
    "closed_benign",
    "closed_confirmed",
)
_MATRIX_STATUSES = (
    "queued_tier1",
    "tier1_active",
    "closed_fp",
    "closed_benign",
    "escalated_tier2",
    "auto_closed",
)
_DECIDED = frozenset(
    {"closed_fp", "closed_benign", "closed_confirmed", "escalated_tier2", "auto_closed"}
)


def _fixture_view(source: str = "replay") -> dict[str, Any]:
    """A `get_alert_view`-shaped dict that carries every key of both denylists,
    two `llm_`/`verifier`-prefixed keys, and nested correlation rows/samples
    with `status` — plus the plain alert fields the labeller *may* see.
    `raw_log` deliberately contains the word `wazuh` and `description` the
    word `lab`, so the value-token test has to exercise its exemption."""
    return {
        # --- plain alert fields: survive every mode ---------------------------
        "alert_id": "p4t02-head",
        "requested_alert_id": "p4t02-head",
        "rule_id": "40112",
        "rule_level": 12,
        "description": "Multiple authentication failures in the lab followed by a success.",
        "category": "ssh_brute_force",
        "categories": ["ssh_brute_force"],
        "severity": "critical",
        "agent_name": "user1-IA1803",
        "origin_host": "user1-IA1803",
        "alert_time": _T,
        "event_time": None,
        "alert_user": "user1",
        "srcip": "127.0.0.1",
        "dstip": "",
        "src_port": 48104,
        "dst_port": 0,
        "decoder": "sshd",
        "mitre_ids": ["T1078", "T1110"],
        "rule_groups": ["syslog", "attacks"],
        "raw_log": "Aug 16 17:56:55 user1-IA1803 sshd[136570]: wazuh Accepted password for user1",
        "raw_log_truncated": False,
        "occurrence_count": 3,
        "first_seen_at": _T,
        "last_seen_at": _T,
        "targeted_accounts": ["root", "user1"],
        "playbook": "# playbook",
        "correlated_now": 2,
        # --- ANALYST_HIDE: dropped on a blind, undecided head -------------------
        "run_id": "11111111-1111-1111-1111-111111111111",
        "suggestion": {
            "run_id": "11111111-1111-1111-1111-111111111111",
            "suggested_action": "false_positive",
            "confidence": "high",
            "reasons": [{"claim": "c", "quote": "q", "source": "wazuh_raw_log"}],
            "gate": {"forced": False, "warnings": []},
            "correlated_at_analysis": 1,
            "created_at": _T,
        },
        "suggested_action": "false_positive",
        "confidence": "high",
        "gate_forced": False,
        "triage_status": "ready",
        # --- the rest of LABELING_DENYLIST: dropped in labeling mode only -------
        "suggestion_visible": False,
        "source": source,
        "status": "queued_tier1",
        "risk_score": 80,
        "risk_band": "Rất cao",
        "risk_score_components": {"severity": 70},
        "asset_context": {"present": False, "criticality": "unknown"},
        "identity_context": {"privileged": None},
        "ioc_context": {"reputation": "skipped"},
        "lookup_status": {"asset": "not_found"},
        "case_id": None,
        "autoclose_rule_id": None,
        "acknowledged_at": None,
        "acknowledged_by": None,
        "acknowledged_by_name": None,
        "closed_at": None,
        "sealed_at": None,
        "close_reason": None,
        "duplicate_of": None,
        "gate_result": {"forced": False},
        "verifier_result": {"agree": True},
        "llm_run_id": "11111111-1111-1111-1111-111111111111",
        "gate": {"forced": False},
        "correlated_at_analysis": 1,
        "triaged_count": 1,  # says how often ① ran (DEC-101)
        "needs_retriage": False,
        # --- LABELING_PREFIXES -------------------------------------------------
        "llm_confidence": "high",
        "verifier_verdict": "false_positive",
        # --- nested: correlation rows/samples carry *other* clusters' status ----
        "correlation": {
            "rows": [
                {
                    "rule_id": "5710",
                    "category": "ssh_brute_force",
                    "status": "closed_fp",
                    "cluster_count": 1,
                    "alert_count": 4,
                    "first_seen": _T,
                    "last_seen": _T,
                    "src_ip_count": 1,
                },
                {
                    "rule_id": "5503",
                    "category": "suspicious_login",
                    "status": "escalated_tier2",
                    "cluster_count": 1,
                    "alert_count": 1,
                    "first_seen": _T,
                    "last_seen": _T,
                    "src_ip_count": 1,
                },
            ],
            "samples": [
                {
                    "alert_id": "p4t02-other",
                    "rule_id": "5710",
                    "category": "ssh_brute_force",
                    "severity": "medium",
                    "status": "closed_fp",
                    "occurrence_count": 4,
                    "alert_time": _T,
                    "description": "sshd: Attempt to login using a non-existent user",
                    "raw_log": "Invalid user admin from 203.0.113.9",
                    "source": source,
                    "llm_note": "never shown",
                }
            ],
        },
    }


# The literal survivor sets (not derived from the module's constants).
_ALL_KEYS = frozenset(_fixture_view())
_ANALYST_BLIND_SURVIVORS = _ALL_KEYS - frozenset(
    {"suggestion", "suggested_action", "confidence", "gate_forced", "triage_status", "run_id"}
)
_LABELING_SURVIVORS = frozenset(
    {
        "alert_id",
        "requested_alert_id",
        "rule_id",
        "rule_level",
        "description",
        "category",
        "categories",
        "severity",
        "agent_name",
        "origin_host",
        "alert_time",
        "event_time",
        "alert_user",
        "srcip",
        "dstip",
        "src_port",
        "dst_port",
        "decoder",
        "mitre_ids",
        "rule_groups",
        "raw_log",
        "raw_log_truncated",
        "occurrence_count",
        "first_seen_at",
        "last_seen_at",
        "targeted_accounts",
        "playbook",
        "correlated_now",
        "correlation",
    }
)


def _walk_string_values(value: Any, *, skip_keys: frozenset[str] = frozenset()):
    """Yield `(key_path, string)` for every string leaf, skipping subtrees under
    `skip_keys`."""
    if isinstance(value, dict):
        for key, item in value.items():
            if key in skip_keys:
                continue
            for path, leaf in _walk_string_values(item, skip_keys=skip_keys):
                yield (f"{key}.{path}" if path else key), leaf
    elif isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            for path, leaf in _walk_string_values(item, skip_keys=skip_keys):
                yield (f"[{i}].{path}" if path else f"[{i}]"), leaf
    elif isinstance(value, str):
        yield "", value


def _walk_keys(value: Any):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _walk_keys(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _walk_keys(item)


# ---------------------------------------------------------------------------
# The constants themselves (P6-T02 / P4-T03 / P4-T05 import them by name)
# ---------------------------------------------------------------------------


def test_constant_sets_are_the_card_verbatim():
    assert SHOW_STATES == _DECIDED
    assert ANALYST_HIDE == {
        "suggestion",
        "suggested_action",
        "confidence",
        "gate_forced",
        "triage_status",
        "run_id",  # DEC-101
    }
    assert ANALYST_HIDE <= LABELING_DENYLIST
    assert {"triaged_count", "needs_retriage"} <= LABELING_DENYLIST  # DEC-101
    assert {
        "source",
        "status",
        "suggestion_visible",
        "risk_score",
        "risk_band",
    } <= LABELING_DENYLIST
    assert LABELING_PREFIXES == ("llm_", "verifier")
    assert isinstance(SHOW_STATES, frozenset)
    assert isinstance(ANALYST_HIDE, frozenset)
    assert isinstance(LABELING_DENYLIST, frozenset)


# ---------------------------------------------------------------------------
# The matrix — 24 cases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["analyst", "labeling"])
@pytest.mark.parametrize("suggestion_visible", [True, False])
@pytest.mark.parametrize("status", _MATRIX_STATUSES)
def test_matrix(status: str, suggestion_visible: bool, mode: str):
    view = _fixture_view()
    view["status"] = status
    view["suggestion_visible"] = suggestion_visible

    out = strip(view, status=status, suggestion_visible=suggestion_visible, mode=mode)

    if mode == "labeling":
        expected = _LABELING_SURVIVORS
    elif suggestion_visible is False and status not in _DECIDED:
        expected = _ANALYST_BLIND_SURVIVORS
    else:
        expected = _ALL_KEYS
    assert frozenset(out) == expected

    if mode == "analyst":
        # An equal copy of everything that survives, nested structures intact.
        for key in expected:
            assert out[key] == view[key]
        # `suggestion_visible` itself is never hidden from an analyst.
        assert out["suggestion_visible"] is suggestion_visible
    else:
        # Nothing forbidden anywhere in the tree, whatever the two flags say.
        for key in _walk_keys(out):
            assert key not in LABELING_DENYLIST, key
            assert not key.startswith(LABELING_PREFIXES), key


# ---------------------------------------------------------------------------
# Named tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("source", ["replay", "wazuh", "lab"])
def test_labeling_mode_strips_source_for_every_value(source: str):
    """DEC-019 / DEC-085: none of the three `alerts.source` values reaches a
    labeller *as a value* anywhere in the tree. `raw_log`/`description` are
    exempt (they carry free text that may contain the words) and the second
    assertion proves the exemption is exercised, not vacuous."""
    view = _fixture_view(source)
    assert view["source"] == source  # the control: the token is there going in

    out = strip(view, status="queued_tier1", suggestion_visible=True, mode="labeling")

    payload = json.dumps(out, default=str)
    assert '"source"' not in payload
    for path, leaf in _walk_string_values(out, skip_keys=frozenset({"raw_log", "description"})):
        for token in ("replay", "wazuh", "lab"):
            assert token not in leaf, f"{token!r} survives at {path}: {leaf!r}"

    # The exemption is real: the free-text fields still carry their words.
    assert "wazuh" in out["raw_log"]
    assert "lab" in out["description"]


def test_strip_never_mutates_input():
    view = _fixture_view()
    before = copy.deepcopy(view)

    blind = strip(view, status="queued_tier1", suggestion_visible=False, mode="analyst")
    shown = strip(view, status="closed_fp", suggestion_visible=False, mode="analyst")
    labeled = strip(view, status="queued_tier1", suggestion_visible=True, mode="labeling")

    assert view == before
    for out in (blind, shown, labeled):
        assert out is not view
        assert isinstance(out, dict)
    # The equal-copy branch is a new dict too, not the input handed back.
    assert shown == view and shown is not view


def test_labeling_recurses_into_correlation():
    view = _fixture_view()
    out = strip(view, status="queued_tier1", suggestion_visible=True, mode="labeling")

    rows = out["correlation"]["rows"]
    samples = out["correlation"]["samples"]
    assert len(rows) == 2 and len(samples) == 1
    for row in rows:
        assert "status" not in row
        assert row["rule_id"] in {"5710", "5503"}  # the rest of the row survives
    sample = samples[0]
    assert "status" not in sample
    assert "source" not in sample
    assert "llm_note" not in sample
    assert sample["alert_id"] == "p4t02-other"
    assert "suggestion" not in out  # gone whole, not hollowed out
    assert "triaged_count" not in out and "needs_retriage" not in out  # DEC-101
    assert out["occurrence_count"] == 3  # the cluster size itself is not ① metadata
    # A deeper nesting: dict → list → dict → list → dict.
    deep = {
        "a": [{"b": [{"status": "closed_fp", "keep": 1, "llm_x": 2, "verifier_y": 3}]}],
        "keep": "yes",
    }
    assert strip(deep, status="queued_tier1", suggestion_visible=True, mode="labeling") == {
        "a": [{"b": [{"keep": 1}]}],
        "keep": "yes",
    }


def test_analyst_mode_keeps_other_clusters_status():
    """Analyst mode hides the ① keys at the top level only — a correlated
    cluster's `status` is other clusters' history, which an analyst may see."""
    view = _fixture_view()
    out = strip(view, status="queued_tier1", suggestion_visible=False, mode="analyst")

    assert "triage_status" not in out
    assert "suggestion" not in out
    assert "run_id" not in out  # a blind row does not even say "① ran" (DEC-101)
    assert out["triaged_count"] == 1  # analyst mode hides the verdict, not the counts
    assert [row["status"] for row in out["correlation"]["rows"]] == ["closed_fp", "escalated_tier2"]
    assert out["correlation"]["samples"][0]["status"] == "closed_fp"
    assert out["status"] == "queued_tier1"  # the head's own status is not a ① key


def test_is_decided():
    for status in _ALL_STATUSES:
        assert is_decided(status) is (status in _DECIDED), status
    assert is_decided("not-a-status") is False


def test_strip_rejects_unknown_mode():
    with pytest.raises(ValueError):
        strip(_fixture_view(), status="queued_tier1", suggestion_visible=True, mode="admin")


def test_strip_scalars_and_empty_structures_untouched():
    view = {"n": 0, "f": 1.5, "b": True, "none": None, "empty": {}, "list": [], "t": ("x",)}
    out = strip(view, status="queued_tier1", suggestion_visible=True, mode="labeling")
    assert out == {"n": 0, "f": 1.5, "b": True, "none": None, "empty": {}, "list": [], "t": ("x",)}
    assert isinstance(out["t"], tuple)
