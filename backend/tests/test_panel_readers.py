"""DEC-221, card AP-T1 - every reader of a stored ① or ② answer reads both versions (3 and 4), and no model-written
field of version 4 reaches a prompt. PURE: no database, no socket (the one reader that needs a connection, the
knowledge drafter, has its database test in `test_rag_draft.py`).

Readers found (grep for `next_steps`, `gia_thuyet`, `attack_narrative`, `reasons`, `structured_basis`, the schema
names, over `backend/app`, `eval/`, `scripts/`) and what this file pins for each:

* `tier2/investigation_view.py` serves `next_steps` as a list of strings: each row's `step` of a version 4 run, the
  strings themselves of a version 3 one; the keys it does not know (`timeline`, `scope`, `likelihood`) change nothing
  of what it served;
* `tier2/dossier.py` puts the case's previous ② result in block 8, and `rag/draft.py` puts ①'s and ②'s latest result in
  the draft prompt: both give the model the version 3 shape of a run, so a field the model wrote for the analyst
  (`summary`, `reading_*`, `would_change`, `next_checks`, `timeline`, `scope`, `likelihood`) is never fed back;
* `scripts/e2e_llm_stub.py` answers version 4 for both tiers.
"""

from __future__ import annotations

import copy
import datetime as dt
import json
import pathlib
import uuid

import pytest
from app.llm import builder, results, schemas
from app.rag import draft as rag_draft
from app.security import linter, wrap
from app.tier2 import dossier

from tests.fakes.llm import (
    INVESTIGATE_V3_OK,
    INVESTIGATE_V4_OK,
    TRIAGE_V3_TRUE_POSITIVE,
    TRIAGE_V4_TRUE_POSITIVE,
)

ROOT = pathlib.Path(__file__).resolve().parents[2]
NONCE = "0123456789abcdef"
CREATED = dt.datetime(2026, 11, 15, 9, 30, tzinfo=dt.UTC)

#: A text no real answer holds, in every model-written field that is new in version 4: if it shows in a prompt,
#: a field was fed back.
SENTINEL = "ZQX-SENTINEL-MODEL-WORDS"


def _v4_triage_with_sentinel() -> dict:
    answer = copy.deepcopy(TRIAGE_V4_TRUE_POSITIVE)
    for key in ("summary", "reading_attack", "reading_benign", "would_change"):
        answer[key] = f"{SENTINEL} {key}"
    answer["next_checks"] = [f"{SENTINEL} next_checks"]
    return answer


def _v4_investigation_with_sentinel() -> dict:
    answer = copy.deepcopy(INVESTIGATE_V4_OK)
    answer["timeline"][0]["what"] = f"{SENTINEL} timeline"
    answer["scope"] = {"hosts": [f"{SENTINEL}-host"], "accounts": [f"{SENTINEL}-account"]}
    answer["gia_thuyet"][0]["likelihood"] = "low"
    return answer


# --------------------------------------------------------------------------- next_step_texts


def test_next_step_texts_of_a_version_3_run_are_the_strings_themselves():
    assert results.next_step_texts(["a", "b"]) == ["a", "b"]
    assert results.next_step_texts([]) == []


def test_next_step_texts_of_a_version_4_run_are_each_rows_step():
    rows = [{"step": "a", "priority": "high"}, {"step": "b", "priority": "low"}]
    assert results.next_step_texts(rows) == ["a", "b"]


def test_next_step_texts_of_what_is_not_a_list_or_a_row_is_empty_or_skipped():
    assert results.next_step_texts(None) == []
    assert results.next_step_texts("a step") == []
    assert results.next_step_texts({"step": "a"}) == []
    assert results.next_step_texts([{"priority": "high"}, {"step": 3}, "kept", {"step": "x"}]) == [
        "kept",
        "x",
    ]


# --------------------------------------------------------------------------- the version 3 views


def test_the_version_3_view_of_a_version_4_triage_answer_is_the_version_3_answer():
    assert results.triage_v3_view(TRIAGE_V4_TRUE_POSITIVE) == TRIAGE_V3_TRUE_POSITIVE
    assert schemas.validate("triage_v3", results.triage_v3_view(TRIAGE_V4_TRUE_POSITIVE)) == []


def test_the_version_3_view_of_a_version_3_triage_answer_is_itself():
    assert results.triage_v3_view(TRIAGE_V3_TRUE_POSITIVE) == TRIAGE_V3_TRUE_POSITIVE


def test_the_version_3_view_of_a_version_4_investigation_is_the_version_3_answer():
    view = results.investigate_v3_view(INVESTIGATE_V4_OK)
    assert view == INVESTIGATE_V3_OK
    assert schemas.validate("investigate_v3", view) == []


def test_the_version_3_view_of_a_version_3_investigation_is_itself():
    assert results.investigate_v3_view(INVESTIGATE_V3_OK) == INVESTIGATE_V3_OK


def test_a_view_takes_nothing_but_a_mapping_and_leaves_its_argument_alone():
    original = copy.deepcopy(INVESTIGATE_V4_OK)
    results.investigate_v3_view(original)
    assert original == INVESTIGATE_V4_OK
    assert results.triage_v3_view(None) is None
    assert results.investigate_v3_view("x") == "x"


# --------------------------------------------------------------------------- the dossier's block 8


def _block8(result) -> str:
    previous = (uuid.uuid4(), result, CREATED)
    return dossier._block8_notes_and_previous([], previous, NONCE)


def test_block_8_of_a_version_3_run_is_what_it_always_was():
    body = f"{dossier._iso(CREATED)}\n{json.dumps(INVESTIGATE_V3_OK, ensure_ascii=False, sort_keys=True)}"
    block = wrap.untrusted_block(body, "proposer", nonce=NONCE).rendered
    expected = f"{dossier.HEADING_NOTES}\n{dossier.HEADING_PREVIOUS_RUN}\n{block}"
    assert _block8(INVESTIGATE_V3_OK) == expected


def test_block_8_of_a_version_4_run_is_byte_for_byte_the_block_of_its_version_3_form():
    assert _block8(INVESTIGATE_V4_OK) == _block8(INVESTIGATE_V3_OK)


def test_no_new_field_of_a_version_4_run_reaches_the_prompt_through_block_8():
    block = _block8(_v4_investigation_with_sentinel())
    assert SENTINEL not in block
    for key in ("timeline", "scope", "likelihood", '"priority"'):
        assert key not in block
    # what a version 3 run gave the model it still gives: the steps, as the strings they were
    assert "Rotate credentials for user1." in block


def test_block_8_still_passes_the_linter_for_a_version_4_run():
    text = _block8(INVESTIGATE_V4_OK)
    assert (
        linter.lint(
            text,
            nonce=NONCE,
            constants=builder.TEMPLATE_CONSTANTS | dossier.DOSSIER_TEMPLATE_CONSTANTS,
            enums=builder.ENUM_VALUES,
        )
        == []
    )


# --------------------------------------------------------------------------- the knowledge drafter


@pytest.mark.parametrize(
    ("pipeline", "version_4", "version_3"),
    [
        ("triage", TRIAGE_V4_TRUE_POSITIVE, TRIAGE_V3_TRUE_POSITIVE),
        ("investigate", INVESTIGATE_V4_OK, INVESTIGATE_V3_OK),
    ],
)
def test_the_drafter_reads_a_run_of_either_version_as_the_version_3_text(
    pipeline, version_4, version_3
):
    as_v3 = json.dumps(version_3, ensure_ascii=False, sort_keys=True)
    assert rag_draft._ai_text(pipeline, version_3) == as_v3
    assert rag_draft._ai_text(pipeline, version_4) == as_v3


def test_no_new_field_reaches_the_drafters_prompt():
    for pipeline, answer in (
        ("triage", _v4_triage_with_sentinel()),
        ("investigate", _v4_investigation_with_sentinel()),
    ):
        assert SENTINEL not in rag_draft._ai_text(pipeline, answer)


# --------------------------------------------------------------------------- the tripwire

#: The model-written fields of version 4 that are new text for the analyst. A module of `backend/app` that names one is
#: one of these: the schemas and the templates that ask for them, the guard that types them, the readers above and the
#: docstrings of the gate and the drafter. A prompt builder is not, and a new reader that appears here must be read by
#: someone who knows the rule (spec 4): these words are never fed back into a prompt.
ANALYST_FIELD_NAMES = ("reading_attack", "reading_benign", "would_change", "next_checks")
MAY_NAME_THEM = {
    "llm/results.py",
    "llm/templates/output_schemas.json",
    "llm/templates/triage_system.txt",
    "rag/draft.py",
    "security/gate.py",
    "security/output_guard.py",
}


def test_only_the_expected_modules_name_the_analyst_fields():
    app = ROOT / "backend" / "app"
    found = {
        str(path.relative_to(app))
        for path in app.rglob("*")
        if path.suffix in {".py", ".json", ".txt"}
        and any(name in path.read_text("utf-8") for name in ANALYST_FIELD_NAMES)
    }
    assert found == MAY_NAME_THEM
