# MITRE local reference (DEC-223) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When an alert carries MITRE technique ids, the prompts of ① and ② carry MITRE's own text for those ids from a local file, so the model does not invent it.

**Architecture:** A tool turns the official ATT&CK bundle (outside the repository) into a small committed extract under `kb/mitre/`; a loader in `app/kb/mitre.py` answers lookups the way `ingest/category.py` matches ids (exact, then parent); the ① prompt and the ② dossier render a reference section behind one switch, and ②'s served timeline is checked against the reference.

**Tech Stack:** Python 3.12, FastAPI backend (psycopg), React + TypeScript frontend, pytest, vitest.

**Spec:** `docs/superpowers/specs/2026-11-17-mitre-local-reference-design.md` (binding; read it before your task).

## Global Constraints

- Branch `feature/mitre-local-reference` (from `8c812c7`); trial only; never `main`, never the trial checkout or its containers.
- No network call from the app, the worker, the tool or any test (spec A1). The bundle is read from `/project/project/mitre-attack/enterprise-attack-20.1.json` (sha256 `539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5`); it is never committed (A5).
- Reference text is MITRE's, cleaned and cut, never reworded (A2). A revoked or deprecated id is shown with its own name, tactics and description; no status and no replacement is shown or stored.
- With `PROMPT_INCLUDE_MITRE_REFERENCE` off (the default) every prompt and every dossier is byte for byte what it is today (A4): existing prompt tests stay green untouched.
- `backend/app/llm/templates/output_schemas.json` and the three system prompt templates are not edited.
- Every part of a ① prompt goes through `PromptBuilder`; new fixed strings are template constants in `llm/builder.py`.
- No secret, DSN, lab address or alert payload in a committed file. Tests call no model.
- Commits `DEC-223 T<N>: …`, ending with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.
- Db tests on a private throwaway PostgreSQL cluster (127.0.0.1, trust auth, the coders' private PostgreSQL binaries (outside the repository), data dir deleted afterwards), never `soc_test`, live or trial. `make` targets need `PY=../AI_Support_SOC_1_2/.venv/bin/python`.

## Review Focus

- An alert with ten ids, with an id that fails the id pattern, with an id not in the reference, with the same id twice: the section stays within its cap and says each case as the spec does.
- The extract file missing or damaged in the container: the alert is still triaged, without the section, with the warning.
- A reason that quotes the reference block: it must not pass as a basis (spec A3).
- The reference text holding characters the prompt linter or the nonce wrapper treats specially (backticks, angle brackets, a nonce-like string): the build does not fail.
- A case of forty alerts and thirty distinct ids: the dossier keeps its cap and its budget.

---

### Task 1: The extract tool, the committed extract, the loader

**Files:**
- Create: `scripts/mitre_extract.py`, `kb/mitre/enterprise-attack.json` (generated), `kb/mitre/README.md` (source, version, sha256, MITRE's copyright and terms line), `backend/app/kb/mitre.py`
- Test: `backend/tests/test_mitre_extract.py`, `backend/tests/test_kb_mitre.py`

**Interfaces:**
- Consumes: the bundle path above; `app.kb.lookup.KB_ROOT`; the three technique tables of `app.ingest.category`.
- Produces (`app.kb.mitre`):
  - `MITRE_FILE: Path` = `KB_ROOT / "mitre" / "enterprise-attack.json"`
  - `@dataclass(frozen=True) class Entry: id: str; name: str; tactics: tuple[str, ...]; parent: str | None; status: str; description: str`
  - `@dataclass(frozen=True) class Found: entry: Entry; via: str` (`"exact"` or `"parent"`)
  - `lookup(technique_id: str, *, path: Path | None = None) -> Found | None` (None: not in the reference, or no reference)
  - `version(*, path: Path | None = None) -> str | None` (None: no usable reference)
  - `reset_cache() -> None` (tests)
  - `DESCRIPTION_MAX_CHARS = 600`
- Produces (`scripts/mitre_extract.py`): `build_extract(bundle: dict, *, source_sha256: str, source_url: str) -> dict`, `clean_description(text: str) -> str`, `main(argv) -> int` (exit 0 written, 2 usage or not an ATT&CK Enterprise bundle).

- [ ] **Step 1: Write the failing tests** (spec §9, first three bullets): a hand-made bundle with a live technique, a sub-technique, a deprecated one, a revoked one, a description with `(Citation: X)`, a Markdown link, `<code>` tags and a first paragraph over 600 characters; a non-ATT&CK file refused; two runs byte-identical; loader lookups (live, sub-technique with `parent`, revoked and deprecated answered with their own text, an id found only through its parent → `via == "parent"`, unknown → None, missing file and malformed file → `version() is None` and `lookup` None); on the committed extract: header `version == "20.1"`, `source_sha256` as above, 706 live techniques, and every key of `WINDOWS_TECHNIQUE_TO_CATEGORY`, `TECHNIQUE_TO_CATEGORY`, `EXTENDED_TECHNIQUE_TO_CATEGORY` resolves with `via == "exact"` and a non-empty description, counts 229 live / 132 revoked / 11 deprecated.
- [ ] **Step 2: Run them, see them fail.**
- [ ] **Step 3: Implement the tool and the loader** (spec §4). Extract keys per technique: `name`, `tactics`, `parent`, `status`, `platforms`, `description`; header: `domain`, `version`, `modified`, `source_sha256`, `source_url`, `copyright`, `terms`, `extracted_by`. Sorted keys, `ensure_ascii=False`, a trailing newline.
- [ ] **Step 4: Generate the extract** from the real bundle and commit it with its README.
- [ ] **Step 5: `make test`, `make lint`; commit.**

### Task 2: The reference section of the ① proposer prompt

**Files:**
- Modify: `backend/app/infra/config.py` (key `PROMPT_INCLUDE_MITRE_REFERENCE`, boolean, default false, like `PROMPT_INCLUDE_SIEM_CONTEXT`), `.env.example` through `scripts/gen_env_example.py`'s source if that is how keys get there, `backend/app/llm/builder.py` (constants), `backend/app/security/wrap.py` (`"mitre_reference"` in `BLOCK_SOURCES`), `backend/app/llm/triage.py` (`_mitre_section`, the budget step), the place ① scans blocks for injection findings (the reference block is left out)
- Test: `backend/tests/test_triage_prompt_mitre.py` (new), and the existing prompt tests untouched

**Interfaces:**
- Consumes: `app.kb.mitre.lookup`, `version`.
- Produces: `MITRE_REFERENCE_MAX_ENTRIES = 6` in `llm/triage.py`; warnings `mitre_reference:<version>`, `mitre_unknown_id`, `mitre_reference_unavailable`, `mitre_reference_dropped` (the budget cut, first of the cut steps); the rendering helper `render_mitre_entries(ids: Sequence[str], *, limit: int) -> tuple[str, list[str]]` (the block's text and the warnings) for Task 3 to reuse.

- [ ] **Step 1: Write the failing tests** (spec §9, ① bullet): off → `build_proposer_prompt` output equal to today's for an alert with ids; on → the section sits after the playbook section and before the learned section, holds one entry per id in the alert's order, six entries at most and the rest as `<id> <name>` lines, a sub-technique names its parent, an id found through its parent says so, an unknown id gives its line and `mitre_unknown_id`, a duplicate id is rendered once, no valid id → no section, a missing extract → no section and `mitre_reference_unavailable`, over budget → the section is the first thing cut (`mitre_reference_dropped`), the prompt linter passes, the injection scan reports nothing for the block, and a proposer answer whose reason names source `mitre_reference` does not come through the output contract as a kept reason.
- [ ] **Step 2: Run them, see them fail.**
- [ ] **Step 3: Implement** (spec §5, §8). Entry format, one per id: `<id> <name>`; for a sub-technique ` (sub-technique of <parent id> <parent name>)` on the same line; `tactics: a, b`; the description. The heading and the two sentences are Vietnamese template constants (say: quoted from the local MITRE ATT&CK document, version N; speak of a technique only as this text does; general reference, not evidence about this alert, never quoted in `reasons`). The version reaches the sentence as a `fact()` or a constant, never as free text.
- [ ] **Step 4: `make test`, the covering db tests, `make lint`; commit.**

### Task 3: The ② dossier, the served timeline, the Tier 2 page, the records

**Files:**
- Modify: `backend/app/tier2/dossier.py` (the reference section), `backend/app/tier2/investigation_view.py` (`technique_name`, `technique_known`, the check `technique_not_in_reference`), the frontend timeline component of Tier 2 and `frontend/src/strings.ts`, `docs/plan/DECISIONS.md` (DEC-223), `docs/runbook.md` (the switch, and how to refresh the extract for a new ATT&CK version)
- Test: backend tests beside the dossier's and the view's own; a vitest test of the timeline row

**Interfaces:**
- Consumes: `render_mitre_entries` (Task 2), `app.kb.mitre.lookup`.
- Produces: `MITRE_REFERENCE_MAX_ENTRIES_CASE = 10`; served timeline entries gain `technique_name: str | None` and `technique_known: bool | None` (None when the value is not an id).

- [ ] **Step 1: Write the failing tests** (spec §9, ② and view bullets): off → dossier text unchanged; on → one section with the distinct valid ids of the case's alerts, most frequent first (ties by id), ten entries at most, the unknown-id line, no section without ids, dropped before any alert material when the dossier is over its budget; the view: `T1110.001` known → name served, `T9999` → `technique_known` false and the check counted, `""`, null and prose → as today; the UI row shows `<id> · <name>` and the note for an unknown id, with every value rendered as text.
- [ ] **Step 2: Run them, see them fail.**
- [ ] **Step 3: Implement** (spec §6, §7); write DEC-223 and the runbook lines.
- [ ] **Step 4: `make test`, the covering db tests, `make lint`, `make ui-lint`, `make ui-test`; commit.**
