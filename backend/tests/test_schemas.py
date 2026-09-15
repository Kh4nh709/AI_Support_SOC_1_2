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
    VERIFIER_V1_AGREE,
    VERIFIER_V1_DISAGREE,
)

ROOT = pathlib.Path(__file__).resolve().parents[2]
TEMPLATES_DIR = ROOT / "backend" / "app" / "llm" / "templates"


def test_file_parses_and_has_three_schemas():
    loaded = schemas.load()
    assert set(loaded) == {"triage_v2", "verifier_v1", "investigate_v2"}


@pytest.mark.parametrize(
    "name,payload",
    [
        ("triage_v2", TRIAGE_V2_ESCALATE),
        ("triage_v2", TRIAGE_V2_FALSE_POSITIVE),
        ("verifier_v1", VERIFIER_V1_AGREE),
        ("verifier_v1", VERIFIER_V1_DISAGREE),
        ("investigate_v2", INVESTIGATE_V2_OK),
    ],
    ids=[
        "TRIAGE_V2_ESCALATE",
        "TRIAGE_V2_FALSE_POSITIVE",
        "VERIFIER_V1_AGREE",
        "VERIFIER_V1_DISAGREE",
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
    for name in ("triage_v2", "verifier_v1", "investigate_v2"):
        assert schemas.render(name) == schemas.render(name)


def test_render_uses_nested_indentation_and_array_marker():
    rendered = schemas.render("triage_v2")
    lines = rendered.splitlines()

    assert "suggested_action: false_positive|needs_review|escalate" in lines
    assert "structured_basis:" in lines
    assert "  severity: critical|high|medium|low" in lines
    assert "reasons[]:" in lines
    assert "  source: wazuh_raw_log|rule_description|correlation_samples|kb_playbook|context" in (
        lines
    )


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
