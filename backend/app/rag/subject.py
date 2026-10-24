"""What a `rag_lookup` or `knowledge_draft` job is about (P13-T02, DEC-210).

A job's `subject_id` is `alert:<alert_id>` or `case:<case_uuid>` (single-flight is the partial unique
index on `(job_type, subject_id)`). `parse_subject` is the one place that reads it back. It accepts
nothing else, and a refusal never echoes the text: the subject is data a caller built.

An alert id is any run of printable ASCII (a Wazuh id `<epoch>.<n>`, a Graylog id `gl-…`, and the
shapes the tests use); a case id is a hyphenated UUID, read back in lower case.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

#: Printable ASCII without a space, at most 200 characters (the longest id seen is 69).
_ALERT_ID = re.compile(r"[\x21-\x7e]{1,200}")
_CASE_UUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_KINDS = ("alert", "case")


@dataclass(frozen=True)
class Subject:
    kind: Literal["alert", "case"]
    id: str

    def __post_init__(self) -> None:
        if self.kind not in _KINDS:
            raise ValueError("Subject: kind must be 'alert' or 'case'")
        if not isinstance(self.id, str) or not self.id:
            raise ValueError("Subject: id must be a non-empty string")

    @property
    def key(self) -> str:
        """The text a job carries: `alert:<id>` or `case:<uuid>`."""
        return f"{self.kind}:{self.id}"


def parse_subject(text: str) -> Subject:
    """`alert:<alert_id>` or `case:<case_uuid>` -> `Subject`; `ValueError` on anything else."""
    if not isinstance(text, str):
        raise ValueError(  # noqa: TRY004 — the contract is ValueError for anything else
            "subject: expected the text 'alert:<id>' or 'case:<uuid>'"
        )
    kind, separator, identifier = text.partition(":")
    if separator and kind == "alert" and _ALERT_ID.fullmatch(identifier):
        return Subject("alert", identifier)
    if separator and kind == "case" and _CASE_UUID.fullmatch(identifier):
        return Subject("case", identifier.lower())
    raise ValueError("subject: expected 'alert:<id>' or 'case:<uuid>'")
