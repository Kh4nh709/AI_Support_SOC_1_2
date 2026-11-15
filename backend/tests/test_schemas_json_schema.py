"""`schemas.json_schema(name)` — the JSON Schema of a named §6.2 schema, built from the compact notation
`output_schemas.json` holds (DEC-218, `docs/superpowers/specs/2026-11-15-llm-json-schema-output-design.md`
section 3 and 7). PURE: no database, no socket.

What is pinned here: the generated `triage_v3` equals the schema the Director probed the provider with
(section 7, copied below as a literal, not generated); `verifier_v2` converts; every schema of the file
converts; and a walk of the compact schema and the generated one side by side finds, at every node, the
shape the table of section 3 says (an object lists all its keys as required and forbids others; an enum has
the file's values, in the file's order).
"""

from __future__ import annotations

import copy
import json
import re

import pytest
from app.llm import schemas

from tests.fakes.llm import (
    INVESTIGATE_V3_OK,
    TRIAGE_V3_TRUE_POSITIVE,
    VERIFIER_V2_AGREE,
)

# Section 7 of the spec, verbatim. It is a literal on purpose: a converter that drifted from the table of
# section 3 must fail against it, not against itself.
TRIAGE_V3_JSON_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["suggested_action", "confidence", "structured_basis", "reasons", "playbook_used"],
    "properties": {
        "suggested_action": {"type": "string", "enum": ["false_positive", "true_positive"]},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "structured_basis": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "severity",
                "ioc_reputation",
                "asset_criticality",
                "identity_privileged",
                "occurrence_count",
                "playbook_rule_applied",
            ],
            "properties": {
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                "ioc_reputation": {
                    "type": "string",
                    "enum": ["malicious", "suspicious", "clean", "not_found", "skipped"],
                },
                "asset_criticality": {
                    "type": "string",
                    "enum": ["high", "medium", "low", "unknown"],
                },
                "identity_privileged": {"type": "string", "enum": ["true", "false", "unknown"]},
                "occurrence_count": {"type": "integer"},
                "playbook_rule_applied": {"type": ["string", "null"]},
            },
        },
        "reasons": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["claim", "quote", "source"],
                "properties": {
                    "claim": {"type": "string"},
                    "quote": {"type": "string"},
                    "source": {
                        "type": "string",
                        "enum": [
                            "wazuh_raw_log",
                            "rule_description",
                            "correlation_samples",
                            "kb_playbook",
                            "context",
                            "siem_context",
                        ],
                    },
                },
            },
        },
        "playbook_used": {"type": ["string", "null"]},
    },
}


def test_triage_v3_equals_the_schema_the_director_probed_with():
    assert schemas.json_schema("triage_v3") == TRIAGE_V3_JSON_SCHEMA


def test_the_required_lists_and_the_enums_follow_the_file_order():
    """Equality of dicts ignores key order but not list order: `required` and every `enum` are lists."""
    generated = schemas.json_schema("triage_v3")
    compact = schemas.load()["triage_v3"]
    assert generated["required"] == list(compact)
    assert generated["properties"]["structured_basis"]["required"] == list(
        compact["structured_basis"]
    )
    assert generated["properties"]["confidence"]["enum"] == ["low", "medium", "high"]


def test_verifier_v2_is_converted():
    assert schemas.json_schema("verifier_v2") == {
        "type": "object",
        "additionalProperties": False,
        "required": ["agree", "structured_only_verdict", "reason"],
        "properties": {
            "agree": {"type": "boolean"},
            "structured_only_verdict": {
                "type": "string",
                "enum": ["false_positive", "needs_review", "true_positive"],
            },
            "reason": {"type": "string"},
        },
    }


@pytest.mark.parametrize("name", sorted(schemas.load()))
def test_every_schema_in_the_file_converts(name):
    generated = schemas.json_schema(name)
    assert generated["type"] == "object"
    json.dumps(generated)  # it goes to the provider as JSON


def test_an_unknown_name_is_a_key_error_like_validate_and_render():
    with pytest.raises(KeyError):
        schemas.json_schema("triage_v99")


def test_it_returns_a_fresh_object_each_call():
    first = schemas.json_schema("triage_v3")
    first["properties"]["confidence"]["enum"].append("extreme")
    assert schemas.json_schema("triage_v3") == TRIAGE_V3_JSON_SCHEMA


def test_the_notation_table_one_row_at_a_time():
    """Each row of section 3's table, on a node written here, through the module's own node converter's
    public door: a schema of one file is not needed to see the row, so a tiny one is made and read back."""
    compact = {
        "an_object": {"inner": "string"},
        "an_array": ["string"],
        "a_non_empty_array": ["string (minItems 1)"],
        "an_enum": "a|b|c",
        "a_nullable_enum": "a|b|null",
        "a_string": "string",
        "a_note": "verbatim substring of one block",
        "a_nullable_string": "string|null",
        "an_integer": 0,
        "a_boolean": True,
        "another_boolean": False,
    }
    assert schemas.json_schema_of(compact) == {
        "type": "object",
        "additionalProperties": False,
        "required": list(compact),
        "properties": {
            "an_object": {
                "type": "object",
                "additionalProperties": False,
                "required": ["inner"],
                "properties": {"inner": {"type": "string"}},
            },
            "an_array": {"type": "array", "items": {"type": "string"}},
            "a_non_empty_array": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "an_enum": {"type": "string", "enum": ["a", "b", "c"]},
            "a_nullable_enum": {"type": ["string", "null"], "enum": ["a", "b", None]},
            "a_string": {"type": "string"},
            "a_note": {"type": "string"},
            "a_nullable_string": {"type": ["string", "null"]},
            "an_integer": {"type": "integer"},
            "a_boolean": {"type": "boolean"},
            "another_boolean": {"type": "boolean"},
        },
    }


# --- the walk, side by side -------------------------------------------------------------------------


def _walk(compact, generated, path="<root>"):
    """The compact node and the generated one, in step. Raises AssertionError at the first disagreement."""
    if isinstance(compact, dict):
        assert generated["type"] == "object", path
        assert generated["additionalProperties"] is False, path
        assert generated["required"] == list(compact), f"{path}: every key required, in file order"
        assert list(generated["properties"]) == list(compact), path
        for key, sub in compact.items():
            _walk(sub, generated["properties"][key], f"{path}.{key}")
    elif isinstance(compact, list):
        assert generated["type"] == "array", path
        item = compact[0]
        wants_min = isinstance(item, str) and "(minitems 1)" in item.lower()
        assert generated.get("minItems") == (1 if wants_min else None), path
        _walk(item, generated["items"], f"{path}[]")
    elif isinstance(compact, bool):
        assert generated == {"type": "boolean"}, path
    elif isinstance(compact, int):
        assert generated == {"type": "integer"}, path
    else:
        alternatives = compact.split("|")
        is_enum = "string" not in alternatives and all(
            re.fullmatch(r"[a-z_]+", a) for a in alternatives
        )
        if is_enum:
            assert generated["enum"] == [None if a == "null" else a for a in alternatives], path
            assert generated["type"] == (
                ["string", "null"] if "null" in alternatives else "string"
            ), path
        elif compact == "string|null":
            assert generated == {"type": ["string", "null"]}, path
        else:
            assert generated == {"type": "string"}, path


@pytest.mark.parametrize("name", sorted(schemas.load()))
def test_a_walk_of_the_compact_schema_and_the_generated_one_agree_at_every_node(name):
    _walk(schemas.load()[name], schemas.json_schema(name), name)


def test_the_non_empty_array_of_investigate_v3_carries_min_items_one():
    """The one place the notation says it: `evidence_against: ["string (minItems 1)"]`. The validator
    refuses an empty list there, and so must the schema the provider enforces."""
    generated = schemas.json_schema("investigate_v3")
    assert generated["properties"]["gia_thuyet"]["items"]["properties"]["evidence_against"] == {
        "type": "array",
        "items": {"type": "string"},
        "minItems": 1,
    }
    assert (
        generated["properties"]["gia_thuyet"]["items"]["properties"]["evidence_for"].get("minItems")
        is None
    )


# --- the generated schema and the validator say the same about the product's own payloads ----------


@pytest.mark.parametrize(
    "name,payload",
    [
        ("triage_v3", TRIAGE_V3_TRUE_POSITIVE),
        ("verifier_v2", VERIFIER_V2_AGREE),
        ("investigate_v3", INVESTIGATE_V3_OK),
    ],
)
def test_the_payloads_the_validator_accepts_are_shaped_as_the_generated_schema_says(name, payload):
    """No JSON-schema library is imported (`schemas.py` says why), so this reads the generated schema by
    hand for the two things a provider checks first: the required list and the closed key set."""
    assert schemas.validate(name, payload) == []
    generated = schemas.json_schema(name)
    assert set(generated["required"]) == set(payload) == set(generated["properties"])


def test_the_validator_stays_what_it_was_on_the_same_inputs():
    """The converter sits next to the interpreter and shares nothing with it but the file: a payload with a
    misspelt key is still reported value-free by `validate`, as the repair round expects."""
    wrong = copy.deepcopy(TRIAGE_V3_TRUE_POSITIVE)
    wrong["reasones"] = wrong.pop("reasons")
    assert schemas.validate("triage_v3", wrong) == ["reasons: missing", "reasones: unexpected key"]
