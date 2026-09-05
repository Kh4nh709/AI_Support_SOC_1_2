"""Proves the fake LLM adapter (backend/tests/fakes/llm.py) behaves as P3 will need."""

import json

import pytest

from tests.fakes.llm import (
    INVESTIGATE_V2_OK,
    TRIAGE_V2_ESCALATE,
    TRIAGE_V2_FALSE_POSITIVE,
    VERIFIER_V1_AGREE,
    VERIFIER_V1_DISAGREE,
    FakeLLM,
)

# context pack §6.2 — top-level keys per schema, transcribed as literals.
# backend/app/llm/templates/output_schemas.json does not exist yet (P3 creates it);
# the legacy llm/templates/output_schemas.json uses the old triage/investigate
# names and must not be used as a source here.
TRIAGE_V2_KEYS = {"suggested_action", "confidence", "structured_basis", "reasons", "playbook_used"}
STRUCTURED_BASIS_KEYS = {
    "severity",
    "ioc_reputation",
    "asset_criticality",
    "identity_privileged",
    "occurrence_count",
    "playbook_rule_applied",
}
REASON_KEYS = {"claim", "quote", "source"}
VERIFIER_V1_KEYS = {"agree", "structured_only_verdict", "reason"}
INVESTIGATE_V2_KEYS = {
    "summary",
    "attack_narrative",
    "suggested_conclusion",
    "confidence",
    "gia_thuyet",
    "evidence",
    "next_steps",
    "playbook_used",
}


def test_responses_consumed_in_order():
    llm = FakeLLM(responses=[{"a": 1}, "raw-string-body"])

    first = llm.complete(system="sys", user="u1")
    second = llm.complete(system="sys", user="u2")

    assert json.loads(first.content) == {"a": 1}
    assert second.content == "raw-string-body"


def test_dict_response_is_json_encoded():
    llm = FakeLLM(responses=[{"k": "v"}])

    result = llm.complete(system="sys", user="u")

    assert isinstance(result.content, str)
    assert json.loads(result.content) == {"k": "v"}


def test_str_response_is_returned_verbatim_even_if_malformed_json():
    llm = FakeLLM(responses=["{not valid json"])

    result = llm.complete(system="sys", user="u")

    assert result.content == "{not valid json"


def test_exhausting_responses_raises_assertion_error_naming_call_index():
    llm = FakeLLM(responses=[{"a": 1}])
    llm.complete(system="sys", user="u1")

    with pytest.raises(AssertionError, match="1"):
        llm.complete(system="sys", user="u2")


def test_raises_is_honoured_on_first_call():
    boom = RuntimeError("transient upstream failure")
    llm = FakeLLM(responses=[{"a": 1}], raises=boom)

    with pytest.raises(RuntimeError, match="transient upstream failure"):
        llm.complete(system="sys", user="u1")

    # the retried call still gets the configured response
    result = llm.complete(system="sys", user="u2")
    assert json.loads(result.content) == {"a": 1}


def test_calls_records_every_invocation():
    llm = FakeLLM(responses=[{"a": 1}, {"b": 2}])

    llm.complete(
        system="sys-1", user="user-1", response_format={"type": "json_object"}, timeout_s=5
    )
    llm.complete(system="sys-2", user="user-2")

    assert llm.calls == [
        {
            "system": "sys-1",
            "user": "user-1",
            "response_format": {"type": "json_object"},
            "timeout_s": 5,
        },
        {"system": "sys-2", "user": "user-2", "response_format": None, "timeout_s": None},
    ]


def test_complete_never_touches_network_or_sleeps():
    # implicit in every other test: FakeLLM has no socket/sleep dependency at all.
    # this test asserts the shape of the result instead, which is the observable proxy.
    llm = FakeLLM(responses=[{"a": 1}], model="fake-deepseek-1")

    result = llm.complete(system="sys", user="u")

    assert result.model == "fake-deepseek-1"
    assert isinstance(result.usage, dict)
    assert set(result.usage) == {"prompt_tokens", "completion_tokens", "total_tokens"}
    assert isinstance(result.latency_ms, int)


@pytest.mark.parametrize(
    "payload,expected_keys",
    [
        (TRIAGE_V2_ESCALATE, TRIAGE_V2_KEYS),
        (TRIAGE_V2_FALSE_POSITIVE, TRIAGE_V2_KEYS),
        (VERIFIER_V1_AGREE, VERIFIER_V1_KEYS),
        (VERIFIER_V1_DISAGREE, VERIFIER_V1_KEYS),
        (INVESTIGATE_V2_OK, INVESTIGATE_V2_KEYS),
    ],
)
def test_canned_payload_has_exactly_the_schema_top_level_keys(payload, expected_keys):
    assert set(payload) == expected_keys


def test_triage_v2_escalate_structured_basis_shape():
    basis = TRIAGE_V2_ESCALATE["structured_basis"]

    assert set(basis) == STRUCTURED_BASIS_KEYS
    assert basis["severity"] == "critical"
    assert basis["ioc_reputation"] == "skipped"
    assert basis["asset_criticality"] == "unknown"
    assert basis["identity_privileged"] == "unknown"
    assert basis["occurrence_count"] == 1
    assert basis["playbook_rule_applied"] == "sbf-3"


def test_triage_v2_escalate_matches_canonical_alert():
    assert TRIAGE_V2_ESCALATE["suggested_action"] == "escalate"
    assert TRIAGE_V2_ESCALATE["playbook_used"] == "ssh_brute_force"
    assert len(TRIAGE_V2_ESCALATE["reasons"]) == 1
    reason = TRIAGE_V2_ESCALATE["reasons"][0]
    assert set(reason) == REASON_KEYS
    assert reason["source"] == "wazuh_raw_log"


def test_triage_v2_escalate_quote_is_substring_of_fixture_full_log():
    with open("backend/tests/fixtures/alert_40112.json") as f:
        fixture = json.load(f)
    full_log = fixture["_source"]["full_log"]

    quote = TRIAGE_V2_ESCALATE["reasons"][0]["quote"]

    assert quote in full_log
