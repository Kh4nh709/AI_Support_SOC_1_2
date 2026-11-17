"""DEC-223 fix round 1 (Ruling M10) - the documents that say how the MITRE reference reaches the trial, and what it
changes, say it the way the code does. PURE: reads `docs/runbook.md`, the spec, DEC-223, the context pack,
`.env.example` and the comment of the key in `infra/config.py`; no database, no socket.

* I1: the trial's `ui` is a built image, so the deployment steps recreate `app` and `worker`, restart `rag-worker`
  (DEC-099: a merge under `backend/app`) and rebuild `ui`, in that order, in the runbook and in the spec's section 10;
* m1: where a document says the gate is unchanged it says the one exception, step 3 refusing `mitre_reference` as a
  reason's source (the gate itself says so, `security/gate.py`);
* m2: the key is read by ① (at most 6 entries) and ② (at most 10), in `.env.example` and in the config's comment;
* m3: the runbook's token figures are the measured ones for both pipelines;
* m4: the plan names no home path.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def read(*parts: str) -> str:
    return (REPO.joinpath(*parts)).read_text(encoding="utf-8")


RUNBOOK = read("docs", "runbook.md")
SPEC = read("docs", "superpowers", "specs", "2026-11-17-mitre-local-reference-design.md")
PLAN = read("docs", "superpowers", "plans", "2026-11-17-mitre-local-reference.md")
DECISIONS = read("docs", "plan", "DECISIONS.md")
PACK = read("docs", "plan", "00-context-pack.md")
ENV_EXAMPLE = read(".env.example")
CONFIG = read("backend", "app", "infra", "config.py")

STEPS = (
    "docker compose up -d --force-recreate app worker",
    "docker compose restart rag-worker",
    "docker compose up -d --build ui",
)


def runbook_section() -> str:
    start = RUNBOOK.index("### MITRE ATT&CK reference (DEC-223)")
    return RUNBOOK[start : RUNBOOK.index("### Grouping switch (DEC-165)", start)]


def spec_section() -> str:
    start = SPEC.index("## 10. Deploying on the trial (Owner)")
    return SPEC[start : SPEC.index("## 11.", start)]


def dec_entry() -> str:
    start = DECISIONS.index("## DEC-223 ·")
    nxt = DECISIONS.find("\n## DEC-", start + 1)
    return DECISIONS[start:] if nxt == -1 else DECISIONS[start:nxt]


def test_the_runbook_deploys_the_backend_the_rag_worker_and_the_built_ui_in_that_order() -> None:
    section = runbook_section()
    where = [section.index(step) for step in STEPS]
    assert where == sorted(
        where
    ), "recreate app and worker, restart rag-worker, rebuild ui: in that order"
    assert (
        section.index("PROMPT_INCLUDE_MITRE_REFERENCE=true") < where[0]
    )  # the .env line comes before the recreate
    assert section.index("Merge the branch") < section.index("PROMPT_INCLUDE_MITRE_REFERENCE=true")
    assert "built image" in section and "DEC-099" in section
    assert "does not depend on the switch" in section and "fails until step 5" in section
    assert "docker compose ps app worker rag-worker ui" in section


def test_the_spec_says_the_same_in_its_section_10() -> None:
    section = spec_section()
    where = [section.index(step) for step in STEPS]
    assert where == sorted(where)
    assert "built image" in section and "DEC-099" in section


def test_the_runbook_names_no_address_of_the_lab_and_runs_no_docker_it_is_not_told_to() -> None:
    section = runbook_section()
    assert not re.search(
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", section.replace("127.0.0.1", "")
    )
    assert "http://127.0.0.1:8081/" in section  # the trial's ui, loopback


def test_every_document_that_says_the_gate_is_unchanged_names_step_3() -> None:
    assert (
        "step 3 of the gate now refuses a reason whose source is `mitre_reference`" in dec_entry()
    )
    non_goal = SPEC[SPEC.index("- Changing the category mapping, the gate") :][:400]
    assert "step 3 refuses a reason whose source is `mitre_reference`" in re.sub(
        r"\s+", " ", non_goal
    )
    key = PACK[PACK.index("PROMPT_INCLUDE_MITRE_REFERENCE=false(") :].split("\n", 1)[0]
    assert "the gate only refuses it as a reason's source, in its step 3" in key


def test_the_key_is_read_by_one_and_two_with_their_caps_in_the_example_file_and_the_config() -> (
    None
):
    line = next(
        x for x in ENV_EXAMPLE.splitlines() if x.startswith("PROMPT_INCLUDE_MITRE_REFERENCE=")
    )
    assert "the ① prompt and the ② dossier" in line and "at most 6 entries in ①, 10 in ②" in line
    comment = CONFIG[: CONFIG.index("PROMPT_INCLUDE_MITRE_REFERENCE: bool")].rsplit("DEC-223", 1)[1]
    comment = re.sub(r"\s*#\s*", " ", comment)  # the comment as one line
    assert "at most 6 entries" in comment and "at most 10)" in comment
    assert "② dossier" in comment and "step 3" in comment
    key = PACK[PACK.index("PROMPT_INCLUDE_MITRE_REFERENCE=false(") :].split("\n", 1)[0]
    assert "at most 6 entries" in key and "at most 10 entries" in key


def test_the_runbook_gives_the_token_figures_of_both_pipelines() -> None:
    section = runbook_section()
    assert "about 700 tokens for two ids and about 1,470 for ten" in section
    assert re.search(r"in ② about 410 for two ids and about 1,320 for ten", section)
    assert "about 1,500 for ten" not in section


def test_the_plan_names_no_home_path() -> None:
    assert "/home/" not in PLAN
    assert "the coders' private PostgreSQL binaries (outside the repository)" in PLAN
