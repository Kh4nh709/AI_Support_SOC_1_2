"""P13-T02 / DEC-210 — `rag.subject`: what a `rag_lookup` or `knowledge_draft` job is about.

A job's `subject_id` is `alert:<alert_id>` or `case:<case_uuid>`. `parse_subject` is the one place
that reads it back: it accepts nothing else, and a refusal never echoes the text (a job's subject
is data a caller built). Pure: no database.
"""

from __future__ import annotations

import dataclasses
import uuid

import pytest
from app.rag.subject import Subject, parse_subject

from tests.soar_payloads import sc03

CASE = "3f2b8c1e-5d4a-4e7b-9a60-1c2d3e4f5a6b"


def test_an_alert_subject_with_a_wazuh_id() -> None:
    assert parse_subject("alert:1789200000.300001") == Subject("alert", "1789200000.300001")


def test_an_alert_subject_with_the_graylog_id_of_the_sc03_sample() -> None:
    gl = sc03()["id"]
    assert parse_subject(f"alert:{gl}") == Subject("alert", gl)


def test_a_case_subject_is_a_uuid() -> None:
    assert parse_subject(f"case:{CASE}") == Subject("case", CASE)


def test_a_case_uuid_is_read_back_in_lower_case() -> None:
    assert parse_subject(f"case:{CASE.upper()}") == Subject("case", CASE)


def test_the_key_is_the_text_the_job_carries() -> None:
    assert Subject("alert", "1789200000.300001").key == "alert:1789200000.300001"
    assert Subject("case", CASE).key == f"case:{CASE}"
    assert parse_subject(Subject("case", CASE).key) == Subject("case", CASE)


def test_a_uuid_object_round_trips() -> None:
    value = uuid.uuid4()
    assert parse_subject(f"case:{value}").id == str(value)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "alert",
        "alert:",
        "case:",
        ":1789200000.300001",
        "ticket:1789200000.300001",
        "ALERT:1789200000.300001",
        "alert: 1789200000.300001",
        "alert:1789200000.300001 ",
        "alert:1789200000.300001\n",
        "alert:a b",
        "alert:a\x00b",
        "alert:" + "x" * 201,
        "case:not-a-uuid",
        f"case:{CASE}\n",
        f"case:{CASE} ",
        f"case: {CASE}",
        f"case:{CASE.replace('-', '')}",
        f"case:{{{CASE}}}",
        f"case:urn:uuid:{CASE}",
        f"case:{CASE}-1",
        "alert:é",
    ],
)
def test_anything_else_is_a_value_error(text: str) -> None:
    with pytest.raises(ValueError):
        parse_subject(text)


@pytest.mark.parametrize("value", [None, 5, b"alert:1.2", ["alert:1.2"]])
def test_a_value_that_is_not_text_is_a_value_error(value: object) -> None:
    with pytest.raises(ValueError):
        parse_subject(value)  # type: ignore[arg-type]


def test_a_refusal_does_not_echo_the_text() -> None:
    secret = "token-4f9a1c7e-do-not-print"
    with pytest.raises(ValueError) as caught:
        parse_subject(f"ticket:{secret}")
    assert secret not in str(caught.value)


def test_a_subject_is_frozen_and_hashable() -> None:
    subject = Subject("alert", "1789200000.300001")
    with pytest.raises(dataclasses.FrozenInstanceError):
        subject.id = "x"  # type: ignore[misc]
    assert {subject: 1}[Subject("alert", "1789200000.300001")] == 1


def test_a_kind_other_than_alert_or_case_cannot_be_built() -> None:
    with pytest.raises(ValueError):
        Subject("ticket", "1")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        Subject("alert", "")
