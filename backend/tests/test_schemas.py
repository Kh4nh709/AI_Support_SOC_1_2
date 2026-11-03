"""Tests for app.llm.schemas — the §6.2 output-schema interpreter (P3-T05)."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest
from app.llm import schemas

from tests.fakes.llm import (
    INVESTIGATE_V2_OK,
    TRIAGE_V2_ESCALATE,
    TRIAGE_V2_FALSE_POSITIVE,
    TRIAGE_V3_TRUE_POSITIVE,
    VERIFIER_V1_AGREE,
    VERIFIER_V1_DISAGREE,
    VERIFIER_V2_AGREE,
    VERIFIER_V2_DISAGREE,
)

ROOT = pathlib.Path(__file__).resolve().parents[2]
TEMPLATES_DIR = ROOT / "backend" / "app" / "llm" / "templates"


def test_file_parses_and_has_five_schemas():
    """`triage_v3` and `verifier_v2` (P14-T01) are the product's; `triage_v2` and `verifier_v1`
    stay, unused by the product, because the evaluation reads them (DEC-213)."""
    loaded = schemas.load()
    assert set(loaded) == {
        "triage_v2",
        "triage_v3",
        "verifier_v1",
        "verifier_v2",
        "investigate_v2",
    }


@pytest.mark.parametrize(
    "name,payload",
    [
        ("triage_v2", TRIAGE_V2_ESCALATE),
        ("triage_v2", TRIAGE_V2_FALSE_POSITIVE),
        ("triage_v3", TRIAGE_V3_TRUE_POSITIVE),
        ("triage_v3", TRIAGE_V2_FALSE_POSITIVE),
        ("verifier_v1", VERIFIER_V1_AGREE),
        ("verifier_v1", VERIFIER_V1_DISAGREE),
        ("verifier_v2", VERIFIER_V2_AGREE),
        ("verifier_v2", VERIFIER_V2_DISAGREE),
        ("investigate_v2", INVESTIGATE_V2_OK),
    ],
    ids=[
        "TRIAGE_V2_ESCALATE",
        "TRIAGE_V2_FALSE_POSITIVE",
        "TRIAGE_V3_TRUE_POSITIVE",
        "TRIAGE_V3_FALSE_POSITIVE",
        "VERIFIER_V1_AGREE",
        "VERIFIER_V1_DISAGREE",
        "VERIFIER_V2_AGREE",
        "VERIFIER_V2_DISAGREE",
        "INVESTIGATE_V2_OK",
    ],
)
def test_fake_payloads_validate_clean(name, payload):
    assert schemas.validate(name, payload) == []


def test_enum_violation_names_path_and_vocabulary_not_value():
    problems = schemas.validate("triage_v2", {"suggested_action": "maybe"})

    assert problems[0].startswith(
        "suggested_action: expected one of false_positive|needs_review|escalate"
    )
    assert not any("maybe" in p for p in problems)


def test_missing_key_is_reported():
    payload = dict(TRIAGE_V2_ESCALATE)
    del payload["playbook_used"]

    problems = schemas.validate("triage_v2", payload)

    assert "playbook_used: missing" in problems


def test_extra_key_is_reported():
    payload = dict(TRIAGE_V2_ESCALATE)
    payload["unexpected_field"] = "whatever"

    problems = schemas.validate("triage_v2", payload)

    assert "unexpected_field: unexpected key" in problems


def test_int_rejects_bool():
    payload = json.loads(json.dumps(TRIAGE_V2_ESCALATE))
    payload["structured_basis"]["occurrence_count"] = True

    problems = schemas.validate("triage_v2", payload)

    assert "structured_basis.occurrence_count: expected integer" in problems


def test_nullable_string():
    payload = json.loads(json.dumps(TRIAGE_V2_ESCALATE))

    # None is valid for a "string|null" field.
    payload["playbook_used"] = None
    assert schemas.validate("triage_v2", payload) == []

    # Anything that is neither a string nor None is not.
    payload["playbook_used"] = 7
    problems = schemas.validate("triage_v2", payload)
    assert "playbook_used: expected string or null" in problems
    assert not any("7" in p for p in problems)


def test_min_items_one():
    payload = json.loads(json.dumps(INVESTIGATE_V2_OK))
    payload["gia_thuyet"][0]["evidence_against"] = []

    problems = schemas.validate("investigate_v2", payload)

    assert "gia_thuyet[0].evidence_against: expected non-empty array" in problems


def test_empty_reasons_is_valid():
    # §6.2 carries no minItems on triage_v2.reasons — an empty list is schema-valid
    # (gate step 3 of the pipeline, not this module, handles "zero reasons left").
    payload = json.loads(json.dumps(TRIAGE_V2_ESCALATE))
    payload["reasons"] = []

    assert schemas.validate("triage_v2", payload) == []


def test_render_is_deterministic():
    for name in ("triage_v2", "triage_v3", "verifier_v1", "verifier_v2", "investigate_v2"):
        assert schemas.render(name) == schemas.render(name)


def test_render_of_the_product_schemas_names_the_new_vocabularies():
    triage = schemas.render("triage_v3").splitlines()
    assert "suggested_action: false_positive|true_positive" in triage
    verifier = schemas.render("verifier_v2").splitlines()
    assert "structured_only_verdict: false_positive|needs_review|true_positive" in verifier
    # everything but that one line reads as the schema it renames
    assert [ln for ln in triage if not ln.startswith("suggested_action:")] == [
        ln for ln in schemas.render("triage_v2").splitlines() if not ln.startswith("suggested_")
    ]


def test_render_uses_nested_indentation_and_array_marker():
    rendered = schemas.render("triage_v2")
    lines = rendered.splitlines()

    assert "suggested_action: false_positive|needs_review|escalate" in lines
    assert "structured_basis:" in lines
    assert "  severity: critical|high|medium|low" in lines
    assert "reasons[]:" in lines
    assert (
        "  source: wazuh_raw_log|rule_description|correlation_samples|kb_playbook|context"
        "|siem_context"
    ) in lines


def test_unknown_schema_name_raises_key_error():
    with pytest.raises(KeyError):
        schemas.validate("triage_v1", {})
    with pytest.raises(KeyError):
        schemas.render("no_such_schema")


def test_every_system_template_contains_JSON():
    for filename in ("triage_system.txt", "verifier_system.txt", "investigate_system.txt"):
        text = (TEMPLATES_DIR / filename).read_text(encoding="utf-8")
        assert "JSON" in text, f"{filename} is missing the literal word JSON"


def test_verifier_system_template_is_short_and_vietnamese():
    text = (TEMPLATES_DIR / "verifier_system.txt").read_text(encoding="utf-8")
    lines = text.splitlines()

    assert len(lines) <= 25
    assert "verifier" in text
    assert "untrusted_data" in text


def test_check_script_agrees_with_context_pack():
    result = subprocess.run(
        [sys.executable, "scripts/check_output_schemas.py", "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "output_schemas.json == context pack §6.2" in result.stdout


# ---------------------------------------------------------------------------
# normalise() — P7-T09
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("answer,spelled", [(True, "true"), (False, "false")])
def test_normalise_spells_a_boolean_identity_privileged_as_its_string(answer, spelled):
    payload = json.loads(json.dumps(TRIAGE_V2_ESCALATE))
    payload["structured_basis"]["identity_privileged"] = answer

    assert schemas.validate("triage_v2", payload) == [
        "structured_basis.identity_privileged: expected one of true|false|unknown"
    ]
    normalised = schemas.normalise("triage_v2", payload)

    assert normalised["structured_basis"]["identity_privileged"] == spelled
    assert schemas.validate("triage_v2", normalised) == []
    assert payload["structured_basis"]["identity_privileged"] is answer  # input not mutated


def test_normalise_leaves_every_other_mismatch_for_validate():
    payload = json.loads(json.dumps(TRIAGE_V2_ESCALATE))
    payload["suggested_action"] = False  # "false" only prefixes false_positive: exact match
    payload["structured_basis"]["occurrence_count"] = True  # an integer leaf
    payload["unexpected_field"] = False  # a key outside the schema

    normalised = schemas.normalise("triage_v2", payload)

    assert normalised == payload
    problems = schemas.validate("triage_v2", normalised)
    assert "suggested_action: expected one of false_positive|needs_review|escalate" in problems
    assert "structured_basis.occurrence_count: expected integer" in problems
    assert "unexpected_field: unexpected key" in problems


@pytest.mark.parametrize(
    "name,payload",
    [
        ("triage_v2", TRIAGE_V2_ESCALATE),
        ("triage_v2", TRIAGE_V2_FALSE_POSITIVE),
        ("triage_v3", TRIAGE_V3_TRUE_POSITIVE),
        ("verifier_v1", VERIFIER_V1_AGREE),
        ("verifier_v1", VERIFIER_V1_DISAGREE),
        ("verifier_v2", VERIFIER_V2_AGREE),
        ("investigate_v2", INVESTIGATE_V2_OK),
    ],
    ids=[
        "TRIAGE_V2_ESCALATE",
        "TRIAGE_V2_FALSE_POSITIVE",
        "TRIAGE_V3_TRUE_POSITIVE",
        "VERIFIER_V1_AGREE",
        "VERIFIER_V1_DISAGREE",
        "VERIFIER_V2_AGREE",
        "INVESTIGATE_V2_OK",
    ],
)
def test_normalise_is_the_identity_on_valid_payloads(name, payload):
    assert schemas.normalise(name, payload) == payload
