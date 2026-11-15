"""DEC-221, card AP-T1 - the model's two new output schemas, `triage_v4` and `investigate_v4`
(`docs/superpowers/specs/2026-11-15-ai-analysis-panel-redesign.md` section 4). PURE: no database, no socket.

What is pinned here: both schemas validate a good answer and name each fault of a bad one (value-free, like
every message of `llm/schemas.py`); the version 3 objects are still in the file, untouched, for the rows
already stored; the JSON Schema generated for each (DEC-218's converter) is the one the notation says, copied
below as a literal and not generated; and the compact notation needed nothing new - every node of both schemas
is one the interpreter's docstring already lists.
"""

from __future__ import annotations

import copy

import pytest
from app.llm import schemas

from tests.fakes.llm import (
    INVESTIGATE_V3_OK,
    INVESTIGATE_V4_OK,
    TRIAGE_V3_TRUE_POSITIVE,
    TRIAGE_V4_FALSE_POSITIVE,
    TRIAGE_V4_NEW_FIELDS,
    TRIAGE_V4_TRUE_POSITIVE,
)

NEW_TRIAGE_KEYS = ["summary", "reading_attack", "reading_benign", "would_change", "next_checks"]


def _bad(base: dict, mutate) -> dict:
    out = copy.deepcopy(base)
    mutate(out)
    return out


# --------------------------------------------------------------------------- the file


def test_the_two_new_schemas_are_in_the_file_and_the_old_ones_stay():
    loaded = schemas.load()
    assert {"triage_v3", "investigate_v3", "triage_v4", "investigate_v4"} <= set(loaded)
    # version 3 untouched: the rows stored with it are read against it
    assert list(loaded["triage_v3"]) == [
        "suggested_action",
        "confidence",
        "structured_basis",
        "reasons",
        "playbook_used",
    ]
    assert loaded["investigate_v3"]["next_steps"] == ["string"]
    assert "timeline" not in loaded["investigate_v3"]
    assert "likelihood" not in loaded["investigate_v3"]["gia_thuyet"][0]


def test_triage_v4_is_triage_v3_plus_five_fields_and_nothing_else_moved():
    loaded = schemas.load()
    v3, v4 = loaded["triage_v3"], loaded["triage_v4"]
    assert list(v4) == list(v3) + NEW_TRIAGE_KEYS
    assert {key: v4[key] for key in v3} == v3
    assert [v4[key] for key in NEW_TRIAGE_KEYS[:4]] == ["string"] * 4
    assert v4["next_checks"] == ["string (minItems 1)"]


def test_investigate_v4_is_investigate_v3_with_the_four_changes():
    loaded = schemas.load()
    v3, v4 = loaded["investigate_v3"], loaded["investigate_v4"]
    assert v4["timeline"] == [
        {"alert_id": "string", "what": "string", "tactic": "string", "technique": "string|null"}
    ]
    assert v4["scope"] == {"hosts": ["string"], "accounts": ["string"]}
    assert v4["gia_thuyet"] == [{**v3["gia_thuyet"][0], "likelihood": "low|medium|high"}]
    assert v4["next_steps"] == [{"step": "string", "priority": "high|medium|low"}]
    unchanged = ("summary", "attack_narrative", "suggested_conclusion", "confidence")
    unchanged += ("evidence", "playbook_used")
    assert {key: v4[key] for key in unchanged} == {key: v3[key] for key in unchanged}
    assert set(v4) == set(v3) | {"timeline", "scope"}


# --------------------------------------------------------------------------- validate: triage_v4


@pytest.mark.parametrize("payload", [TRIAGE_V4_TRUE_POSITIVE, TRIAGE_V4_FALSE_POSITIVE])
def test_triage_v4_accepts_a_good_answer(payload):
    assert schemas.validate("triage_v4", payload) == []


def test_triage_v4_accepts_the_no_playbook_answer_with_no_reasons_but_the_new_fields():
    """DEC-215: with no playbook the model answers `false_positive` with `reasons: []`; the five new fields
    are still there, so the schema is satisfied."""
    answer = {**copy.deepcopy(TRIAGE_V4_FALSE_POSITIVE), "reasons": [], "playbook_used": None}
    assert schemas.validate("triage_v4", answer) == []


def test_a_version_3_answer_is_not_a_version_4_one_and_the_five_fields_are_named():
    assert schemas.validate("triage_v4", TRIAGE_V3_TRUE_POSITIVE) == [
        f"{key}: missing" for key in NEW_TRIAGE_KEYS
    ]
    assert schemas.validate("triage_v3", TRIAGE_V4_TRUE_POSITIVE) == [
        f"{key}: unexpected key" for key in NEW_TRIAGE_KEYS
    ]


@pytest.mark.parametrize("key", NEW_TRIAGE_KEYS)
def test_triage_v4_names_each_missing_new_field(key):
    answer = _bad(TRIAGE_V4_TRUE_POSITIVE, lambda a: a.pop(key))
    assert schemas.validate("triage_v4", answer) == [f"{key}: missing"]


@pytest.mark.parametrize("key", NEW_TRIAGE_KEYS[:4])
@pytest.mark.parametrize("value", [None, 3, ["a"], {"a": "b"}, True])
def test_triage_v4_text_fields_must_be_strings(key, value):
    answer = _bad(TRIAGE_V4_TRUE_POSITIVE, lambda a: a.__setitem__(key, value))
    assert schemas.validate("triage_v4", answer) == [f"{key}: expected string"]


def test_triage_v4_next_checks_is_a_non_empty_list_of_strings():
    empty = _bad(TRIAGE_V4_TRUE_POSITIVE, lambda a: a.__setitem__("next_checks", []))
    assert schemas.validate("triage_v4", empty) == ["next_checks: expected non-empty array"]
    not_a_list = _bad(TRIAGE_V4_TRUE_POSITIVE, lambda a: a.__setitem__("next_checks", "one"))
    assert schemas.validate("triage_v4", not_a_list) == ["next_checks: expected array"]
    wrong_item = _bad(TRIAGE_V4_TRUE_POSITIVE, lambda a: a.__setitem__("next_checks", ["ok", 2]))
    assert schemas.validate("triage_v4", wrong_item) == ["next_checks[1]: expected string"]


def test_triage_v4_still_refuses_the_old_faults_and_an_unknown_key():
    answer = _bad(
        TRIAGE_V4_TRUE_POSITIVE,
        lambda a: (a.__setitem__("suggested_action", "needs_review"), a.__setitem__("extra", "x")),
    )
    assert schemas.validate("triage_v4", answer) == [
        "suggested_action: expected one of false_positive|true_positive",
        "extra: unexpected key",
    ]


def test_a_message_never_carries_the_offending_text():
    secret = "S3CRET-TEXT-FROM-THE-MODEL"
    answer = _bad(TRIAGE_V4_TRUE_POSITIVE, lambda a: a.__setitem__("next_checks", [secret, 5]))
    problems = schemas.validate("triage_v4", answer)
    assert problems == ["next_checks[1]: expected string"]
    assert all(secret not in p for p in problems)


# --------------------------------------------------------------------------- validate: investigate_v4


def test_investigate_v4_accepts_a_good_answer():
    assert schemas.validate("investigate_v4", INVESTIGATE_V4_OK) == []


def test_investigate_v4_accepts_empty_timeline_scope_lists_and_a_null_technique():
    answer = copy.deepcopy(INVESTIGATE_V4_OK)
    answer["timeline"] = []
    answer["scope"] = {"hosts": [], "accounts": []}
    answer["next_steps"] = []
    assert schemas.validate("investigate_v4", answer) == []
    answer = copy.deepcopy(INVESTIGATE_V4_OK)
    answer["timeline"][0]["technique"] = None
    assert schemas.validate("investigate_v4", answer) == []


def test_a_version_3_answer_is_not_a_version_4_one_for_the_investigator():
    problems = schemas.validate("investigate_v4", INVESTIGATE_V3_OK)
    assert problems == [
        "timeline: missing",
        "scope: missing",
        "gia_thuyet[0].likelihood: missing",
        "next_steps[0]: expected object",
        "next_steps[1]: expected object",
    ]


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda a: a.pop("timeline"), ["timeline: missing"]),
        (lambda a: a.__setitem__("timeline", {}), ["timeline: expected array"]),
        (lambda a: a["timeline"][0].pop("alert_id"), ["timeline[0].alert_id: missing"]),
        (lambda a: a["timeline"][0].__setitem__("what", 1), ["timeline[0].what: expected string"]),
        (
            lambda a: a["timeline"][0].__setitem__("tactic", None),
            ["timeline[0].tactic: expected string"],
        ),
        (
            lambda a: a["timeline"][0].__setitem__("technique", 7),
            ["timeline[0].technique: expected string or null"],
        ),
        (lambda a: a["timeline"][0].pop("technique"), ["timeline[0].technique: missing"]),
        (lambda a: a["timeline"][0].__setitem__("time", "x"), ["timeline[0].time: unexpected key"]),
        (lambda a: a.pop("scope"), ["scope: missing"]),
        (lambda a: a.__setitem__("scope", []), ["scope: expected object"]),
        (lambda a: a["scope"].pop("hosts"), ["scope.hosts: missing"]),
        (lambda a: a["scope"].__setitem__("accounts", "root"), ["scope.accounts: expected array"]),
        (lambda a: a["scope"].__setitem__("hosts", [1]), ["scope.hosts[0]: expected string"]),
        (lambda a: a["scope"].__setitem__("ips", []), ["scope.ips: unexpected key"]),
        (lambda a: a["gia_thuyet"][0].pop("likelihood"), ["gia_thuyet[0].likelihood: missing"]),
        (
            lambda a: a["gia_thuyet"][0].__setitem__("likelihood", "certain"),
            ["gia_thuyet[0].likelihood: expected one of low|medium|high"],
        ),
        (
            lambda a: a["gia_thuyet"][0].__setitem__("evidence_against", []),
            ["gia_thuyet[0].evidence_against: expected non-empty array"],
        ),
        (lambda a: a["next_steps"][0].pop("priority"), ["next_steps[0].priority: missing"]),
        (
            lambda a: a["next_steps"][0].__setitem__("priority", "urgent"),
            ["next_steps[0].priority: expected one of high|medium|low"],
        ),
        (lambda a: a["next_steps"][0].pop("step"), ["next_steps[0].step: missing"]),
        (
            lambda a: a["next_steps"][1].__setitem__("step", ["a"]),
            ["next_steps[1].step: expected string"],
        ),
        (lambda a: a["next_steps"].__setitem__(0, "a string"), ["next_steps[0]: expected object"]),
        (
            lambda a: a.__setitem__("suggested_conclusion", "need_more_data"),
            [
                (
                    "suggested_conclusion: expected one of "
                    "false_positive|policy_violation|confirmed_incident"
                )
            ],
        ),
    ],
)
def test_investigate_v4_names_each_fault(mutate, expected):
    answer = _bad(INVESTIGATE_V4_OK, mutate)
    assert schemas.validate("investigate_v4", answer) == expected


def test_the_two_new_schemas_render_for_a_system_prompt():
    triage = schemas.render("triage_v4").splitlines()
    assert triage[-5:] == [
        "summary: string",
        "reading_attack: string",
        "reading_benign: string",
        "would_change: string",
        "next_checks[]: string",
    ]
    assert (
        triage[: len(schemas.render("triage_v3").splitlines())]
        == schemas.render("triage_v3").splitlines()
    )
    investigate = schemas.render("investigate_v4").splitlines()
    for line in (
        "timeline[]:",
        "  alert_id: string",
        "  technique: string|null",
        "scope:",
        "  hosts[]: string",
        "  likelihood: low|medium|high",
        "next_steps[]:",
        "  step: string",
        "  priority: high|medium|low",
    ):
        assert line in investigate


# --------------------------------------------------------------------------- the JSON Schema (DEC-218)

_STR = {"type": "string"}
_NULLABLE = {"type": ["string", "null"]}

TRIAGE_V4_NEW_JSON_SCHEMA_PROPERTIES = {
    "summary": _STR,
    "reading_attack": _STR,
    "reading_benign": _STR,
    "would_change": _STR,
    "next_checks": {"type": "array", "items": _STR, "minItems": 1},
}

INVESTIGATE_V4_JSON_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "summary",
        "attack_narrative",
        "timeline",
        "scope",
        "suggested_conclusion",
        "confidence",
        "gia_thuyet",
        "evidence",
        "next_steps",
        "playbook_used",
    ],
    "properties": {
        "summary": _STR,
        "attack_narrative": _STR,
        "timeline": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["alert_id", "what", "tactic", "technique"],
                "properties": {
                    "alert_id": _STR,
                    "what": _STR,
                    "tactic": _STR,
                    "technique": _NULLABLE,
                },
            },
        },
        "scope": {
            "type": "object",
            "additionalProperties": False,
            "required": ["hosts", "accounts"],
            "properties": {
                "hosts": {"type": "array", "items": _STR},
                "accounts": {"type": "array", "items": _STR},
            },
        },
        "suggested_conclusion": {
            "type": "string",
            "enum": ["false_positive", "policy_violation", "confirmed_incident"],
        },
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "gia_thuyet": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["noi_dung", "evidence_for", "evidence_against", "likelihood"],
                "properties": {
                    "noi_dung": _STR,
                    "evidence_for": {"type": "array", "items": _STR},
                    "evidence_against": {"type": "array", "items": _STR, "minItems": 1},
                    "likelihood": {"type": "string", "enum": ["low", "medium", "high"]},
                },
            },
        },
        "evidence": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["alert_id", "quote", "why"],
                "properties": {"alert_id": _STR, "quote": _STR, "why": _STR},
            },
        },
        "next_steps": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["step", "priority"],
                "properties": {
                    "step": _STR,
                    "priority": {"type": "string", "enum": ["high", "medium", "low"]},
                },
            },
        },
        "playbook_used": _NULLABLE,
    },
}


def test_triage_v4_json_schema_is_triage_v3s_plus_the_five_properties():
    v3 = schemas.json_schema("triage_v3")
    v4 = schemas.json_schema("triage_v4")
    assert v4["type"] == "object"
    assert v4["additionalProperties"] is False
    assert v4["required"] == v3["required"] + NEW_TRIAGE_KEYS
    assert v4["properties"] == {**v3["properties"], **TRIAGE_V4_NEW_JSON_SCHEMA_PROPERTIES}


def test_investigate_v4_json_schema_is_what_the_notation_says():
    assert schemas.json_schema("investigate_v4") == INVESTIGATE_V4_JSON_SCHEMA


def test_the_old_json_schemas_are_unchanged_by_the_new_ones():
    assert schemas.json_schema("triage_v3")["required"] == [
        "suggested_action",
        "confidence",
        "structured_basis",
        "reasons",
        "playbook_used",
    ]
    assert schemas.json_schema("investigate_v3")["properties"]["next_steps"] == {
        "type": "array",
        "items": _STR,
    }


def test_every_object_the_two_schemas_send_forbids_other_keys_and_requires_its_own():
    """The provider's strict mode wants `additionalProperties: false` and every key required, at every object."""

    def walk(node, where):
        if node.get("type") == "object":
            assert node["additionalProperties"] is False, where
            assert sorted(node["required"]) == sorted(node["properties"]), where
            for key, sub in node["properties"].items():
                walk(sub, f"{where}.{key}")
        elif node.get("type") == "array":
            walk(node["items"], f"{where}[]")

    for name in ("triage_v4", "investigate_v4"):
        walk(schemas.json_schema(name), name)


def test_the_interpreter_reads_both_new_schemas_with_the_notations_it_has():
    """No new notation: every leaf of both schemas is one of the interpreter's kinds (enum, string,
    nullable string, free string with a note) and every container an object or a one-item array."""

    def walk(node, where):
        if isinstance(node, dict):
            for key, sub in node.items():
                walk(sub, f"{where}.{key}")
        elif isinstance(node, list):
            assert len(node) == 1, where
            walk(node[0], f"{where}[]")
        elif isinstance(node, (bool, int)):
            pass  # `0` (integer) and `true` / `false` (boolean) are rows of the docstring's table too
        else:
            assert isinstance(node, str), where
            kind, _extra = schemas._classify_string_spec(node)
            assert kind in {"enum", "string", "nullable_string", "note_string"}, where

    walk(schemas.load()["triage_v4"], "triage_v4")
    walk(schemas.load()["investigate_v4"], "investigate_v4")


def test_the_new_fields_fixture_is_exactly_the_five_keys():
    assert list(TRIAGE_V4_NEW_FIELDS) == NEW_TRIAGE_KEYS
