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

import ast
import copy
import datetime as dt
import json
import pathlib
import re
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
    # DEC-221, AP-T2: the Tier 1 alert view's analysis serves the model's texts to the page as text. It imports no
    # prompt builder (`test_the_analysis_module_imports_nothing_that_builds_a_prompt`) and joins this list deliberately.
    "tier1/analysis.py",
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


# --------------------------------------------------------------------------- who reads `result` from llm_runs
#
# The model-written text is only ever safe if no new reader of a stored answer can carry it into a prompt without
# somebody who knows the rule looking at it (the last review of AP-T1 asked for this pin). A reader of a stored answer
# is a module of `backend/app` that selects the `result` column of `llm_runs`: found here by reading the SQL text in
# its string constants (docstrings left out), because that is where a statement has to name the table and the column.
# A writer (`INSERT`) is not a reader.

_RESULT_COLUMN = re.compile(
    r"[\s,(.]result[\s,)\-]"
)  # `SELECT result FROM`, `r.result,`, `(result IS NULL)`
_RESULT_PATH = re.compile(
    r"\.result\s*->"
)  # `{alias}.result->>'suggested_action'`: a fragment built for a SELECT

#: Each module below was read when it was put here. `tier1/queue.py` builds the alert view and the queue (and hands
#: the row to `tier1/analysis.py`, which reads no table); `tier2/investigation_view.py`, `tier2/case_view.py` and
#: `web/routers/tier2_runs.py` serve ②'s result; `tier2/dossier.py` and `rag/draft.py` put a stored answer in a prompt
#: AS ITS VERSION 3 FORM (`results.*_v3_view`, pinned above); `llm/verdicts.py` is the SQL twin of `served_action`;
#: `web/routers/admin_llm.py` is the admin page; `infra/health.py` counts the NULL ones.
MAY_READ_RESULT = {
    "infra/health.py",
    "llm/verdicts.py",
    "rag/draft.py",
    "tier1/queue.py",
    "tier2/case_view.py",
    "tier2/dossier.py",
    "tier2/investigation_view.py",
    "web/routers/admin_llm.py",
    "web/routers/tier2_runs.py",
}


def _docstring_ids(tree: ast.AST) -> set[int]:
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            first = node.body[0] if node.body else None
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                ids.add(id(first.value))
    return ids


def _reads_result_from_llm_runs(source: str) -> bool:
    tree = ast.parse(source)
    skip = _docstring_ids(tree)
    texts = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip
    ]
    selects = [t for t in texts if not t.lstrip().upper().startswith("INSERT")]
    if any(_RESULT_PATH.search(t) for t in selects):
        return True
    names_table = any(re.search(r"\bllm_runs\b", t) for t in texts)
    return names_table and any(_RESULT_COLUMN.search(t) for t in selects)


def test_only_the_expected_modules_read_result_from_llm_runs():
    app = ROOT / "backend" / "app"
    found = {
        str(path.relative_to(app))
        for path in app.rglob("*.py")
        if _reads_result_from_llm_runs(path.read_text("utf-8"))
    }
    assert found == MAY_READ_RESULT


@pytest.mark.parametrize(
    ("source", "reads"),
    [
        ('Q = "SELECT result FROM llm_runs WHERE run_id = %s"', True),
        ('Q = "SELECT r.run_id, r.result, r.gate_result FROM llm_runs r"', True),
        ('COLS = "run_id, created_at, stopped_by, result, evidence_check"\nT = "llm_runs"', True),
        ("def f(alias):\n    return f\"{alias}.result->>'suggested_action'\"", True),
        ('Q = "SELECT gate_result, verifier_result FROM llm_runs"', False),
        ('Q = f"INSERT INTO llm_runs ({cols}) VALUES"\nCOLS = ["result", "gate_result"]', False),
        ('"""SELECT result FROM llm_runs (a docstring)."""\nX = 1', False),
        ('Q = "SELECT result FROM something_else"', False),
        ('KEY = "result"', False),
    ],
)
def test_the_scan_that_finds_a_reader_of_result_finds_what_it_should(source, reads):
    assert _reads_result_from_llm_runs(source) is reads


def test_the_analysis_module_imports_nothing_that_builds_a_prompt():
    """It serves the model's texts to a page; nothing it imports can put them in a prompt."""
    tree = ast.parse((ROOT / "backend" / "app" / "tier1" / "analysis.py").read_text("utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
            imported.update(f"{node.module}.{alias.name}" for alias in node.names)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    for forbidden in (
        "app.llm.builder",
        "app.llm.triage",
        "app.llm.investigate",
        "app.llm.adapter",
        "app.security.wrap",
        "app.tier2",
        "app.rag.draft",
    ):
        assert not any(
            name == forbidden or name.startswith(forbidden + ".") for name in imported
        ), forbidden
