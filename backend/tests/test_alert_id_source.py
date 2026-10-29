"""INT-T02 / DEC-211 R6 item A — the alert id's shape has one definition, `app.infra.ids`.

The webhook (`infra/intake.py`) may not import `llm.builder` (`infra` imports nothing from the app,
G1), so the pattern lives in `infra`, and the builder and the linter take it from there. These tests
pin that the three are one object, that the function the webhook calls judges as the pattern does, and
that the layering test still sees `infra` clean. Pure: no database.
"""

from __future__ import annotations

import ast
import pathlib

import pytest
from app.infra import ids, intake
from app.llm import builder as B
from app.security import linter as L

from tests.test_import_rules import violations_in

APP = pathlib.Path(__file__).resolve().parent.parent / "app"

WAZUH = "1790888852.28168897"
SOAR = "gl-01K7ZD2Q5T8YJ3VNQ4E6R9XWBM-6f1c2a4e-8d3b-4c7a-9e21-5b0a7d6c3f84"


def test_the_builder_the_linter_and_the_webhook_share_one_pattern_object() -> None:
    assert B.ID_PATTERNS["alert_id"] is ids.ALERT_ID_PATTERN
    assert L._ID_PATTERNS[0] is ids.ALERT_ID_PATTERN


def test_the_webhook_judges_with_the_function_of_that_module() -> None:
    assert intake.is_alert_id is ids.is_alert_id


@pytest.mark.parametrize("value", [WAZUH, SOAR, "1.2", "0.0"])
def test_a_wazuh_id_and_a_real_soar_id_are_alert_ids(value: str) -> None:
    assert ids.is_alert_id(value)
    assert B.Id("alert_id", value).value == value  # ① renders it


@pytest.mark.parametrize(
    "value",
    [
        "",
        "not-a-soar-id",
        "gl-TEST-100191-1793289654049",  # the n8n test generator: not widened (R6 item A)
        SOAR.replace("01K7ZD2Q5T8YJ3VNQ4E6R9XWBM", "01k7zd2q5t8yj3vnq4e6r9xwbm"),  # lower-case ULID
        SOAR.replace(
            "6f1c2a4e-8d3b-4c7a-9e21-5b0a7d6c3f84", "6F1C2A4E-8D3B-4C7A-9E21-5B0A7D6C3F84"
        ),
        SOAR.replace("XWBM", "XWBI"),  # no I in Crockford's alphabet
        WAZUH + "\n",  # `$` alone would let a trailing newline through
        " " + WAZUH,
        "1790888852",
        "1790888852.",
        ".28168897",
        SOAR + "-extra",
    ],
)
def test_anything_else_is_not_an_alert_id_and_the_builder_refuses_it_too(value: str) -> None:
    assert not ids.is_alert_id(value)
    with pytest.raises(ValueError):
        B.Id("alert_id", value)


@pytest.mark.parametrize("value", [None, 0, 123, 1.5, True, [WAZUH], {"id": WAZUH}, b"1.2"])
def test_a_value_that_is_not_a_string_is_not_an_alert_id_and_does_not_raise(value: object) -> None:
    assert ids.is_alert_id(value) is False


def test_infra_ids_imports_nothing_from_the_app() -> None:
    """G1: `infra` imports no other package of the app; the one module both sides share is a leaf."""
    source = (APP / "infra" / "ids.py").read_text(encoding="utf-8")
    assert violations_in(source, "infra.ids") == []
    imported = {
        alias.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert imported <= {"__future__", "re"}, imported


def test_the_intake_module_takes_the_shape_from_infra_and_not_from_the_llm_package() -> None:
    source = (APP / "infra" / "intake.py").read_text(encoding="utf-8")
    assert "from app.infra.ids import is_alert_id" in source
    assert "app.llm" not in source
    assert violations_in(source, "infra.intake") == []
