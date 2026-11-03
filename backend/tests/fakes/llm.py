"""Fake LLM adapter — a test double for the real backend/app/llm/adapter.py (arrives in P3).

Do not import backend/app/** here: this is a test double, not an implementation.
Canned payloads match context pack §6.2 (LLM output schemas) key-for-key.
"""

import copy
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LLMResult:
    content: str  # raw JSON string, exactly what choices[0].message.content would hold
    model: str
    usage: dict  # {"prompt_tokens": int, "completion_tokens": int, "total_tokens": int}
    latency_ms: int


class FakeLLM:
    """Records every call in `calls`; never touches the network and never sleeps."""

    def __init__(self, responses=None, *, model="fake-deepseek-1", raises=None):
        self._responses = list(responses) if responses is not None else []
        self._response_cursor = 0
        self.model = model
        self._raises = raises
        self.calls = []
        self.models = []  # the `model=` of each call, in order (None when the caller passed none)

    def complete(
        self,
        *,
        system: str,
        user: str,
        response_format=None,
        timeout_s=None,
        model: str | None = None,
    ) -> LLMResult:
        call_index = len(self.calls)
        self.calls.append(
            {
                "system": system,
                "user": user,
                "response_format": response_format,
                "timeout_s": timeout_s,
            }
        )
        # not in `calls`: that shape is pinned (`test_fakes_llm`, and `test_investigate` asserts that
        # ② passes no model); the model of each call is in `models`
        self.models.append(model)

        if self._raises is not None and call_index == 0:
            raise self._raises

        if self._response_cursor >= len(self._responses):
            raise AssertionError(
                f"FakeLLM: no response configured for call index {call_index} "
                f"({len(self._responses)} configured)"
            )

        raw = self._responses[self._response_cursor]
        self._response_cursor += 1
        content = json.dumps(raw) if isinstance(raw, dict) else raw

        return LLMResult(
            content=content,
            model=self.model,
            usage={
                "prompt_tokens": len(system) + len(user),
                "completion_tokens": len(content),
                "total_tokens": len(system) + len(user) + len(content),
            },
            latency_ms=1,
        )


_FIXTURE_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "alert_40112.json"
_CANONICAL_ALERT = json.loads(_FIXTURE_PATH.read_text())
_FULL_LOG = _CANONICAL_ALERT["_source"]["full_log"]
_ESCALATE_QUOTE = _FULL_LOG[_FULL_LOG.index("Accepted password") :]

TRIAGE_V2_ESCALATE = {
    "suggested_action": "escalate",
    "confidence": "high",
    "structured_basis": {
        "severity": "critical",
        "ioc_reputation": "skipped",
        "asset_criticality": "unknown",
        "identity_privileged": "unknown",
        "occurrence_count": 1,
        "playbook_rule_applied": "sbf-3",
    },
    "reasons": [
        {
            "claim": "SSH authentication succeeded after multiple prior failures on the same rule.",
            "quote": _ESCALATE_QUOTE,
            "source": "wazuh_raw_log",
        }
    ],
    "playbook_used": "ssh_brute_force",
}

TRIAGE_V2_FALSE_POSITIVE = {
    "suggested_action": "false_positive",
    "confidence": "medium",
    "structured_basis": {
        "severity": "low",
        "ioc_reputation": "clean",
        "asset_criticality": "low",
        "identity_privileged": "false",
        "occurrence_count": 3,
        "playbook_rule_applied": None,
    },
    "reasons": [
        {
            "claim": "The rule description flags this as a routine, expected event.",
            "quote": "Multiple authentication failures followed by a success.",
            "source": "rule_description",
        }
    ],
    "playbook_used": None,
}

VERIFIER_V1_AGREE = {
    "agree": True,
    "structured_only_verdict": "escalate",
    "reason": "Structured facts alone (critical severity, sbf-3 rule condition) already justify escalate.",
}

VERIFIER_V1_DISAGREE = {
    "agree": False,
    "structured_only_verdict": "needs_review",
    "reason": "Structured facts do not satisfy any decision-table rule condition for the proposed verdict.",
}

# P14-T01 (DEC-213): ①'s model answer is `false_positive | true_positive` (`triage_v3`) and the
# verifier's is `false_positive | needs_review | true_positive` (`verifier_v2`). The payloads above
# stay: `triage_v2` and `verifier_v1` are still in `output_schemas.json` for `eval/`.
TRIAGE_V3_TRUE_POSITIVE = {**copy.deepcopy(TRIAGE_V2_ESCALATE), "suggested_action": "true_positive"}

VERIFIER_V2_AGREE = {
    "agree": True,
    "structured_only_verdict": "true_positive",
    "reason": "Structured facts alone (critical severity, sbf-3 rule condition) already justify true_positive.",
}

VERIFIER_V2_DISAGREE = copy.deepcopy(VERIFIER_V1_DISAGREE)

INVESTIGATE_V2_OK = {
    "summary": "Repeated SSH authentication failures from 127.0.0.1 against user1 culminated in a successful login.",
    "attack_narrative": "The source attempted several failed logins in quick succession before authenticating "
    "successfully, consistent with a brute-force attempt that succeeded.",
    "suggested_conclusion": "confirmed_incident",
    "confidence": "high",
    "gia_thuyet": [
        {
            "noi_dung": "The successful login followed a credential-guessing attempt against user1.",
            "evidence_for": ["Rule 40112 fired on multiple failures followed by a success."],
            "evidence_against": [
                "No corroborating login from a second, unrelated source was observed."
            ],
        }
    ],
    "evidence": [
        {
            "alert_id": "1786903016.121311",
            "quote": _ESCALATE_QUOTE,
            "why": "Shows the successful authentication that followed the reported failures.",
        }
    ],
    "next_steps": [
        "Rotate credentials for user1.",
        "Review sshd logs for the source IP over the prior 7 days.",
    ],
    "playbook_used": "ssh_brute_force",
}

# P14-T02 (DEC-213): ②'s model answer is `false_positive | policy_violation | confirmed_incident`
# (`investigate_v3`). The payload above stays, valid under both: `investigate_v2` is still in
# `output_schemas.json` for `eval/`, and its conclusion is a definite one.
INVESTIGATE_V3_OK = copy.deepcopy(INVESTIGATE_V2_OK)
