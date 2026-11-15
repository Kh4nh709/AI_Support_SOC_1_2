"""DEC-221, card AP-T1 - the UI e2e stack's LLM stub answers version 4 for both tiers, so the stack runs the product's
own schemas (`scripts/e2e_llm_stub.py` picks its answer from the schema named in the system prompt). PURE.
"""

from __future__ import annotations

import importlib.util
import pathlib

from app.llm import schemas
from app.llm import triage as T

ROOT = pathlib.Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------- the e2e stub


def _stub():
    spec = importlib.util.spec_from_file_location(
        "e2e_llm_stub_ap_t1", ROOT / "scripts" / "e2e_llm_stub.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_e2e_stub_answers_version_4_for_pipeline_one():
    system = T._system_prompt(T.TRIAGE_TEMPLATE, "triage_v4")
    answer = _stub().answer_for(system, "## Alert\nalert_id: 1.2 · severity: low\n")
    assert schemas.validate("triage_v4", answer) == []
    assert answer["suggested_action"] == "false_positive"


def test_the_e2e_stub_answers_version_4_for_pipeline_two():
    stub = _stub()
    system = "x\n\n## Schema investigate_v4\n" + schemas.render("investigate_v4")
    answer = stub.answer_for(system, "no blocks here")
    assert schemas.validate("investigate_v4", answer) == []
    assert answer["suggested_conclusion"] == "false_positive"
    assert all(set(row) == {"step", "priority"} for row in answer["next_steps"])
