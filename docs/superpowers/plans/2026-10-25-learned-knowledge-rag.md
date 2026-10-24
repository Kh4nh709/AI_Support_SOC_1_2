# Learned knowledge and RAG (P13) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **This build (DEC-201, DEC-210):** one Coder subagent (`coder-sonnet55`: Sonnet 5.5, xhigh, isolated worktree) and one independent Reviewer subagent per task.
> - The Director manages from `../AI_Support_SOC_rag`, branch `director/rag-knowledge`: it dispatches, merges, runs one mutation of its own per merge, commits each review verbatim and keeps STATE.
> - A Coder's first step is `git merge --ff-only director/rag-knowledge`.

**Goal:** Turn analysts' conclusions into admin-approved knowledge in `kb_learned/`, and give ① and ② the decision history and the most similar approved entries on every run, with no change to ①/② when the switches are off.

**Architecture:**
- **A new package `backend/app/rag/`** holds the database-only parts (fingerprint, history, candidates, entries) and the DeepSeek parts (ranking, drafting, publishing).
- **A separate `rag-worker` process** runs two new job types. Each worker reclaims only its own job types.
- **① and ② read a stored, validated lookup at prompt time and never wait.**
- **The admin console gains `/admin/knowledge`.**

**Tech Stack:**
- Python 3.12 (`/project/project/AI_Support_SOC_1_2/.venv`), FastAPI 0.141, psycopg 3, PostgreSQL 16 (full-text search, `simple` configuration).
- React 19, TanStack Query 5, Tailwind 4, Vitest, MSW, Playwright.
- DeepSeek through `llm/adapter.DeepSeekAdapter`.

**Spec:** `docs/superpowers/specs/2026-10-24-learned-knowledge-rag-design.md` (DEC-210). Read it with this plan; the spec's section numbers are cited as "spec §n".

## Global Constraints

**Switches and keys** (context pack §6.3):
- `RAG_ENABLED` and `KNOWLEDGE_DRAFT_ENABLED` default `false`. With both off, behaviour, ①'s prompt and ②'s dossier are byte-identical to the base `d680f33`.
- The other new keys and their defaults:
  - `RAG_MODEL=""` (empty means `LLM_MODEL_PROPOSER`);
  - `RAG_TRIAGE_DELAY_S=45`;
  - `RAG_CASE_REFRESH_H=24`;
  - `RAG_HISTORY_DAYS=90`;
  - `RAG_MONTHLY_USD_CAP=3`;
  - `KNOWLEDGE_QUEUE_MAX=200`.
- They are `.env` keys only, not web settings.

**Vocabularies:**
- Levels are ASCII enum values: `rat_giong`, `giong`, `hoi_giong`. This is the plan's spelling of the spec's "rất giống / giống / hơi giống", because `llm/schemas.py` enum tokens must match `^[a-z_]+$`.
- Entry conclusions: `closed_fp`, `closed_benign`, `concluded_fp`, `concluded_policy_violation`, `confirmed_incident`.
- New block sources: `kb_learned`, `decision_history`, `analyst_note`.
- New job types: `rag_lookup`, `knowledge_draft`. A job subject is `alert:<alert_id>` or `case:<case_uuid>`.
- New `llm_runs` values:
  - pipelines `rag_lookup` (role `retriever`) and `knowledge_draft` (role `drafter`);
  - subject type `alert` or `case`, unchanged.
- New event types: `knowledge.drafted`, `knowledge.approved`, `knowledge.rejected`, `knowledge.retired`, `knowledge.merged`, `rag.lookup_failed`, `rag.integrity_failed`.

**Files:**
- Entries live under `kb_learned/` at the repo root, as `kb_learned/entries/<category>/<entry_id>.md`; retired ones under `kb_learned/retired/`.
- The folder is git-ignored except `kb_learned/README.md`.
- The tag vocabulary is tracked: `backend/app/rag/tags.yaml`.

**Untouched:**
- `triage_v2`, `verifier_v1`, `investigate_v2` and `llm/templates/*_system.txt`;
- the gate's rules and `kb/`;
- `eval/` (never edited);
- `docker-compose.yml`. The Owner's checkout carries an uncommitted change to it, so compose changes ship as a new file, `docker-compose.rag.yml`.

**Import rule:** `"rag": {"infra", "audit", "security", "llm", "kb", "domain"}`. `tier1`, `tier2` and `web` may import `rag`. `rag` imports no tier and no `web`.

**Only approved content and closed fields reach a ①/② prompt.** The ranking agent's reasons go to `rag_results.match_notes`, for admin display only.

**Untrusted text:** analyst text, log text and SOAR free text reach a model only through `security/wrap.untrusted_block`. Free-text validation is V3, V4 and V5 of spec §7.7. The whole-prompt linter runs on rendered prompts as today.

**Tests and process:**
- DB tests carry `@pytest.mark.db` and run on a private scratch PostgreSQL 16 (`pgserver`, TCP 127.0.0.1, trust auth, own data dir). Never the live cluster; never print a DSN; count with `pgrep -fc`.
- The fake LLM adapter only (`backend/tests/fakes/llm.py`).
- Every guard is shown red once on a scratch copy (DEC-025/027).
- Suites: `make lint`, `make test`, `make test-db`, `make ui-test`, all with `PY=/project/project/AI_Support_SOC_1_2/.venv/bin/python`. Known baseline: two `test_backup_restore.py` failures (no libxml).
- Copy: Vietnamese user-facing copy goes in `frontend/src/strings.ts`. `dangerouslySetInnerHTML` stays 0. No new runtime dependency.

## Review Focus

1. **The first day, with an empty store and no history.**
   - Expected: the lookup is `empty`.
   - ① and ② render the "nothing found" sentence and run normally; no error or 500 on any admin tab.
   - Tests in T03 and T07.
2. **A Wazuh alert with no `enrichment` block** (pull mode, or a legacy row).
   - Expected: the fingerprint and the history work without SOAR fields; history level 0 is skipped.
   - Tests in T02.
3. **An entry retired, or its file edited, between the lookup and the ①/② run.**
   - Expected: that match is dropped at prompt time; the rest render.
   - Tests in T07 and T08.
4. **Two admins approving the same draft at once, or a double click.**
   - Expected: exactly one entry, one file and one `knowledge.approved`; the second request gets 409.
   - Test in T05.
5. **A large case** (`MAX_ALERTS_PER_CASE` heads, long raw logs) **pushing ②'s dossier over `CASE_PROMPT_BUDGET_TOKENS`.**
   - Expected: the learned section is cut first, before any existing cut step.
   - Test in T08.

---

## File structure

| Path | Responsibility | Task |
|---|---|---|
| `docs/Schema/020_learned_knowledge.sql` (+ regenerated `docs/Schema/schema.sql`) | every schema change | T01 |
| `backend/app/infra/{config.py,jobs.py,worker.py}`, `backend/app/audit/events.py`, `backend/app/security/wrap.py`, `backend/app/llm/builder.py`, `backend/tests/test_import_rules.py`, context pack §6.3, `.env.example`, `docs/runbook.md` key table | frozen vocabulary, keys, typed reclaim | T01 |
| `backend/app/rag/{__init__.py,subject.py,tags.py,tags.yaml,generalise.py,fingerprint.py,history.py,entries.py,candidates.py}` | database-only retrieval | T02 |
| `backend/app/rag/{budget.py,runs.py,agent.py,schemas.json,match.py,lookup.py,templates/match_system.txt}`, `backend/app/web/rag_handlers/{__init__.py,lookup.py}`, `backend/app/web/rag_worker.py`, `backend/app/llm/schemas.py` (one public function) | ranking and the lookup job | T03 |
| `backend/app/rag/{draft.py,templates/draft_system.txt}`, `backend/app/web/rag_handlers/draft.py`, `backend/app/domain/transitions.py` (draft enqueue) | drafting and merging | T04 |
| `backend/app/rag/publish.py`, `backend/app/web/routers/admin_knowledge.py`, `backend/app/web/routers/admin_overview.py`, `backend/app/infra/health.py` | approval, publication, admin API, health | T05 |
| `frontend/src/features/admin/Knowledge*.tsx`, `frontend/src/api/admin.ts`, `frontend/src/strings.ts`, `frontend/src/routes.tsx`, `AdminLayout.tsx`, `LlmPage.tsx`, `OverviewBlocks.tsx`, `frontend/e2e/` | the admin page | T06 |
| `backend/app/domain/transitions.py` (lookup + delayed triage), `backend/app/tier1/triage.py`, `backend/app/llm/triage.py`, `backend/app/audit/llm_runs.py` | ① integration | T07 |
| `backend/app/domain/transitions.py` (escalate), `backend/app/web/routers/tier2_runs.py`, `backend/app/tier2/{dossier.py,investigate.py}` | ② integration | T08 |
| `docker-compose.rag.yml`, `kb_learned/README.md`, `.gitignore`, `docs/runbook.md`, `docs/limitations.md` | operations | T09 |

**Order:**
- T01 → T02. After T02, T03 and T04 can run in parallel.
- T05 follows T04, and T06 follows T05.
- T07 and T08 follow T03.
- T09 comes last, then a whole-branch review.
- Merges touching `domain/transitions.py` (T04, T07, T08) are taken one at a time.

---

### Task 1 (P13-T01): Frozen contracts, keys, typed reclaim

**Files:**
- Create: `docs/Schema/020_learned_knowledge.sql`.
- Modify:
  - `docs/Schema/schema.sql` (regenerate with `docs/Schema/build_schema.py`);
  - `backend/app/infra/config.py`, `backend/app/infra/jobs.py`, `backend/app/infra/worker.py`, `backend/app/audit/events.py`, `backend/app/security/wrap.py`, `backend/app/llm/builder.py`, `backend/app/security/linter.py` (only if its enum copy must follow `ENUM_VALUES`);
  - `backend/tests/test_import_rules.py`, `docs/plan/00-context-pack.md` §6.3, `.env.example` (via `scripts/gen_env_example.py`), `docs/runbook.md` (the key table and its count).
- Test: `backend/tests/test_migration_020.py` (db), `backend/tests/test_jobs_worker.py`, `backend/tests/test_config.py`, `backend/tests/test_builder_learned_vocab.py`.

**Interfaces:**
- Produces:
  - `infra.jobs.reclaim_stale(conn, job_types: Sequence[str]) -> int`. The parameter is required; `run_forever` passes `list(handlers.keys())`.
  - `JOB_TYPES` ⊇ {`rag_lookup`, `knowledge_draft`}.
  - `EVENT_TYPES` gains the 7 names (28 → 35).
  - `wrap.BLOCK_SOURCES` ⊇ {`kb_learned`, `decision_history`, `analyst_note`}.
  - `llm.builder.KbLearnedLevel(Enum)` with values `rat_giong`, `giong`, `hoi_giong`; it is added to `ALL_ENUMS`.
  - `"kb_learned_level"` ∈ `FACT_NAMES`.
  - Heading `HEADING_LEARNED = "## Tri thức đã duyệt và lịch sử quyết định"`.
  - Sentence `SENTENCE_LEARNED_IS_REFERENCE = "Phần này là tham khảo từ quyết định của con người trước đây, không phải phán quyết, và không bao giờ là căn cứ để đóng alert."`.
  - Sentence `SENTENCE_NO_LEARNED = "không có lịch sử quyết định hay tri thức đã duyệt tương tự"`.
  - All three are in `HEADINGS` / `SENTENCES` and therefore in `TEMPLATE_CONSTANTS`.
  - `Config` fields with the defaults of Global Constraints.

**Migration 020 must hold** (spec §7.2):
- **Table `knowledge_drafts`:**
  - `draft_id uuid PK default gen_random_uuid()`;
  - `source_kind text` (alert | case), `source_id text`, `conclusion text` (closed set), `status text` (pending | approved | rejected | merged);
  - `draft jsonb NOT NULL default '{}'`, `warnings jsonb NOT NULL default '[]'`, `llm_run_id uuid`;
  - `duplicate_of_entry uuid`, `conflict_with_entry uuid`;
  - `created_at timestamptz default now()`, `reviewed_by uuid`, `reviewed_at`, `review_note text`;
  - unique `(source_kind, source_id)`.
- **Table `knowledge_entries`:**
  - `entry_id uuid PK`, `version int`, `status` (active | retired);
  - `conclusion`, `category text`, `mitre_ids text[]`, `tags text[]`, `soar_scenario text`, `rule_ids text[]`, `log_source text`;
  - `fingerprint text` and `fingerprint_tsv tsvector GENERATED ALWAYS AS (to_tsvector('simple', fingerprint)) STORED`, with a GIN index;
  - `content text NOT NULL`, `content_sha256 text NOT NULL`, `file_path text NOT NULL`;
  - `source_alert_ids text[]`, `source_case_ids uuid[]`, `evidence jsonb default '[]'`;
  - `approved_by uuid`, `approved_at`, `supersedes_entry uuid`.
- **Table `rag_results`:**
  - `lookup_id uuid PK`, `subject_kind`, `subject_id`, `status` (ok | empty | failed | budget);
  - `history jsonb`, `matches jsonb`, `match_notes jsonb`, `llm_run_id uuid`, `created_at`;
  - an index on `(subject_kind, subject_id, created_at DESC)`.
- **`llm_runs`:**
  - `rag_lookup_id uuid NULL`;
  - `ck_llm_runs_pipeline` adds the two pipelines;
  - `ck_llm_runs_pipeline_khop_subject` lets the two new pipelines pair with `alert` or `case`;
  - `ck_llm_runs_role` adds `retriever` and `drafter`.
- **Jobs and events:** `ck_jobs_job_type` adds the two job types; `ck_audit_event_type` adds the 7 events (35 names, the 28 first, in order).
- **The expression index** `ix_alerts_soar_dedup_key` on `((raw_payload #>> '{enrichment,case,dedup_key}'))`.
- **Grants:** `app_rw` gets `SELECT, INSERT, UPDATE` on the three tables. Follow 019's grant comment.

- [ ] **Step 1: Write the failing tests.**
  - `test_migration_020.py` (db):
    - every table, column, constraint and index above exists;
    - a `knowledge_draft` run with subject type `alert` is accepted, and a `triage` run with subject type `case` is still refused;
    - `ck_audit_event_type` holds 35 names;
    - a second apply is refused by `schema_migrations`, as for 019.
  - `test_jobs_worker.py::test_reclaim_stale_takes_only_its_types`: a stale `triage` row is untouched by `reclaim_stale(conn, ["rag_lookup"])` and reclaimed by `reclaim_stale(conn, ["triage"])`.
  - `test_jobs_worker.py::test_run_forever_reclaims_only_its_handlers`.
  - `test_config.py`: the eight keys, their defaults, a `false`/`true` parse and a negative int refused.
  - `test_builder_learned_vocab.py`:
    - `fact("kb_learned_level", KbLearnedLevel.RAT_GIONG) == "kb_learned_level: rat_giong"`;
    - the three constants are in `TEMPLATE_CONSTANTS`;
    - the linter accepts a rendered line `kb_learned_level: giong`.
- [ ] **Step 2: Run them and watch them fail.** `make test-db PY=… ` and `$PY -m pytest -c backend/pyproject.toml backend/tests/test_jobs_worker.py backend/tests/test_config.py backend/tests/test_builder_learned_vocab.py`. Expected: FAIL.
- [ ] **Step 3: Implement** the migration, then `python docs/Schema/build_schema.py` to regenerate `schema.sql`. Then the Python mirrors, the keys, §6.3 + `gen_env_example.py`, the runbook key rows, and the import rule for `rag`. Create `backend/app/rag/__init__.py` with only a docstring.
- [ ] **Step 4: Run the four suites.** Expected: green (plus the known libxml pair).
- [ ] **Step 5: Commit**, `P13-T01: …`.

### Task 2 (P13-T02): Retrieval without AI: fingerprint, history, entries, candidates

**Files:**
- Create in `backend/app/rag/`: `subject.py`, `tags.py`, `tags.yaml`, `generalise.py`, `fingerprint.py`, `history.py`, `entries.py`, `candidates.py`.
- Test: `backend/tests/test_rag_generalise.py`, `backend/tests/test_rag_fingerprint.py` (db), `backend/tests/test_rag_history.py` (db), `backend/tests/test_rag_candidates.py` (db).

**Interfaces:**
- Consumes: T01's tables and keys.
- Produces:
  - **`rag.subject`:** `Subject(kind: Literal["alert","case"], id: str)` (frozen dataclass); `parse_subject(text: str) -> Subject`, which raises `ValueError` on anything other than `alert:<id>` / `case:<uuid>`; `Subject.key -> str`.
  - **`rag.tags`:** `load_tags() -> frozenset[str]` (from `tags.yaml`); `tags_from_rule_groups(groups: Sequence[str]) -> tuple[str, ...]`.
  - **`rag.generalise`:**
    - `placeholderise(text: str, hostnames: Iterable[str]) -> str`. It replaces IPv4 and IPv6 (`<IP_NGOAI>` or `<IP_NOI_BO>`, by `ipaddress.is_private`), e-mails (`<EMAIL>`), `DOMAIN\user` (`<USER>`), the given hostnames (`<HOST>`), `gl-…` and Wazuh ids (`<ALERT_ID>`), hex hashes of 32 characters or more (`<HASH>`), and digit runs (`<N>`).
    - `literal_findings(text: str, hostnames: Iterable[str]) -> list[str]`: the V3 fault names, never the matched values.
  - **`rag.fingerprint`:**
    - `Fingerprint(category: str, mitre_ids: tuple[str, ...], rule_ids: tuple[str, ...], soar_scenario: str | None, log_source: str, tags: tuple[str, ...], text: str)`.
    - `alert_fingerprint(conn, alert_id: str) -> Fingerprint` and `case_fingerprint(conn, case_id: str) -> Fingerprint` (the union over the case's heads).
    - `text` joins the closed fields, the rule descriptions and `placeholderise(raw_log)[:2000]`.
  - **`rag.history`:**
    - `History(level: int | None, key_name: str | None, total: int, by_conclusion: dict[str, int], last_seen: datetime | None, examples: tuple[str, ...])`.
    - `Exclusion(alert_ids: frozenset[str], case_ids: frozenset[str])`; `self_exclusion(conn, subject: Subject) -> Exclusion`.
    - `decision_history(conn, subject: Subject, cfg) -> History`.
    - `render_history(h: History) -> str`, one `key: value` line per field, used inside the `decision_history` block.
  - **`rag.entries`:**
    - `KB_LEARNED_ROOT = Path(__file__).resolve().parents[3] / "kb_learned"`.
    - `Entry` (the columns of `knowledge_entries`).
    - `sha256_text(s: str) -> str`.
    - `entry_by_id(conn, entry_id) -> Entry | None`.
    - `file_matches(entry: Entry, root: Path = KB_LEARNED_ROOT) -> bool`.
    - `render_entry_markdown(fields: Mapping[str, Any]) -> str`: YAML front matter with the closed fields and `entry_id`/`version`, then the sections Tóm tắt, Dấu hiệu phân biệt, Lần sau cần kiểm, Giới hạn.
  - **`rag.candidates`:** `candidates(conn, fp: Fingerprint, exclusion: Exclusion, *, limit: int = 20) -> list[Entry]`. It takes active entries whose `category`, `mitre_ids` or `soar_scenario` overlap, plus the top `plainto_tsquery('simple', …)` hits on `fingerprint_tsv`, de-duplicated, minus any entry whose `source_alert_ids`/`source_case_ids` meet the exclusion, at most `limit`.

**History semantics (spec §7.6):**
- **The key levels**, tried in order (first with data wins):
  - 0: the `enrichment.case.dedup_key` without its `|yyyyMMdd-HH` suffix;
  - 1: the cluster key (`rule_id`, `srcip`, `dstip`, `agent_name`);
  - 2: `soar_scenario` + `agent_name`;
  - 3: `rule_id` + `agent_name`;
  - 4: `rule_id` + (`srcip` or `alert_user`);
  - 5: `category` + `agent_name`.
- **What is counted:** head alerts only (`duplicate_of IS NULL`) with `first_seen_at` within `RAG_HISTORY_DAYS`.
- **The conclusion of a counted alert:**
  - `case_id IS NULL` and status `closed_fp` / `closed_benign` → `tier1_closed_fp` / `tier1_closed_benign`;
  - in a case whose status is `investigating` → `escalated_open`;
  - in a concluded case → the case's status.
- **Self-exclusion:** the subject alert, its head and the head's duplicates, its case and that case's alerts. For a case subject: the case and its alerts.

- [ ] **Step 1: Failing tests.**
  - `test_rag_generalise.py`:
    - each placeholder, using the values of both team samples (`docs/plan/tasks/P12/*.json`): `79.79.78.202` → `<IP_NGOAI>`, `FPT\hr01` → `<USER>`, `Windows_Endpoint` → `<HOST>` when given;
    - `literal_findings` names `ipv4`, `account`, `hostname`, `alert_id`, `hash` and never echoes a value.
  - `test_rag_fingerprint.py`: SC03 gives `category == "recon"`, `mitre_ids == ("T1046",)`, `soar_scenario == "SC03"`, and no `79.79.` in `text`. A Wazuh alert with no `enrichment` gives `soar_scenario is None`.
  - `test_rag_history.py`:
    - each key level picked when only its data exists;
    - the distribution counts;
    - the window;
    - the exclusion of the subject, its cluster and its case;
    - level 0 skipped without SOAR data;
    - an empty history gives `total == 0, level is None`.
  - `test_rag_candidates.py`:
    - overlap and full-text hits are merged;
    - at most 20;
    - retired entries never appear;
    - an entry drafted from the subject is excluded.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Suites green.**
- [ ] **Step 5: Commit.**

### Task 3 (P13-T03): The ranking agent and the lookup job on `rag-worker`

**Files:**
- Create in `backend/app/rag/`: `budget.py`, `runs.py`, `agent.py`, `schemas.json`, `match.py`, `lookup.py`, `templates/match_system.txt`.
- Create in `backend/app/web/`: `rag_handlers/__init__.py`, `rag_handlers/lookup.py`, `rag_worker.py`.
- Modify: `backend/app/llm/schemas.py`, which gains one public function.
- Test: `backend/tests/test_rag_budget.py` (db), `backend/tests/test_rag_match.py`, `backend/tests/test_rag_lookup_job.py` (db), `backend/tests/test_rag_worker.py`.

**Interfaces:**
- Consumes: T02 (all), `llm.adapter.DeepSeekAdapter`, `llm.triage.prompt_version`, `security.wrap`, `security.linter.lint`, `security.detector`.
- Produces:
  - **`llm.schemas.validate_against(schema: Mapping[str, Any], obj: Any) -> list[str]`:** the existing validator over a given node.
  - **`rag.budget`:**
    - `rag_spent_usd(conn) -> float`: this month, pipelines `rag_lookup` and `knowledge_draft`.
    - `global_exhausted(conn, cfg) -> bool`: global spend ≥ the effective cap; a `SettingsUnavailable` counts as exhausted.
    - `rag_limits(conn, cfg) -> settings.Limits`: `cap_usd = RAG_MONTHLY_USD_CAP`; the timeout comes from `settings.effective_limits`.
  - **`rag.runs.write_rag_run(conn, *, run_id, pipeline, role, subject: Subject, system_prompt, user_message, result, gate_result, injection_findings, input_tokens, output_tokens, latency_ms, model_id, prompt_version, cost_usd, stopped_by) -> uuid.UUID`.**
  - **`rag.agent.call_json(adapter, *, system: str, user: str, nonce: str, schema_name: str, extra_constants: frozenset[str], model: str, cfg) -> AgentResult`:**
    - every RAG call passes `model = cfg.RAG_MODEL or cfg.LLM_MODEL_PROPOSER`;
    - one call and at most one repair, as `llm/investigate.investigate` does;
    - the user message is linted first (`PermanentError` on a violation);
    - `AgentResult(parsed: dict | None, schema_errors: list[str], usage: dict, model: str | None, latency_ms: int)`.
  - **`rag.match`:**
    - `Match(entry_id: str, level: KbLearnedLevel, content_sha256: str)`.
    - `rank(adapter, fp: Fingerprint, cands: Sequence[Entry], *, cfg) -> tuple[list[Match], dict, AgentResult]`. The second element is `match_notes` (`entry_id → reason`).
    - `validate_matches(raw: dict, cands: Sequence[Entry]) -> tuple[list[Match], list[str]]`: V-R1's candidate membership, V-R2, and faults by name.
  - **`rag.lookup`:**
    - `run_lookup_job(conn, job: Job, *, adapter=None) -> None`.
    - `LookupResult(lookup_id: uuid.UUID, status: str, history: History, matches: tuple[Match, ...], created_at: datetime)`.
    - `latest_lookup(conn, subject: Subject) -> LookupResult | None`.
    - `PromptMaterial(lookup_id: uuid.UUID, history_text: str | None, entries: tuple[tuple[KbLearnedLevel, str], ...])`.
    - `prompt_material(conn, result: LookupResult | None) -> PromptMaterial | None`. It re-checks each match: the entry is `active`, `sha256_text(content) == content_sha256 ==` the stored hash. It drops failures.
      - It returns `None` for no row, `failed` or `budget`.
      - For `empty`, and for `ok` whose matches all failed with no history, it returns a `PromptMaterial` with `history_text=None, entries=()`. That renders the "nothing found" sentence (Review Focus 1).
  - **`web.rag_handlers.iter_handlers()` / `iter_timeouts()`:** the same contract as `web.handlers`, over its own package.
  - **`web.rag_worker.main(argv)`:** `run_forever` with the RAG handlers only. It seeds nothing.

**`schemas.json`** holds `rag_match_v1`: `{"matches": [{"entry_id": string, "level": enum(rat_giong, giong, hoi_giong), "reason": string ≤ 160}] ≤ 3}`.

**The lookup job, in order:**
1. Raise the idle timeout as `tier1/triage._raise_idle_timeout` does.
2. Parse the subject.
3. Compute `self_exclusion`, `decision_history` and the fingerprint.
4. **Budget:** if `global_exhausted` or `rag_spent_usd ≥ cap`, write a `budget` row (history kept) and stop.
5. **No candidates:** write `ok` if the history has data, else `empty`.
6. Otherwise `rank` with `DeepSeekAdapter(cfg, spent_usd=partial(rag_spent_usd, conn), limits=partial(rag_limits, conn, cfg))`, model `cfg.RAG_MODEL or cfg.LLM_MODEL_PROPOSER`.
7. `validate_matches`; then `file_matches` for each kept match. A mismatch drops the match and writes `rag.integrity_failed` with `{entry_id}`.
8. Write the run (`rag_lookup` / `retriever`) and the `rag_results` row in one transaction.
9. **Transient errors:**
   - before the last attempt: write the run row, commit, re-raise (the `tier2/investigate.py` pattern);
   - on the last attempt: a `failed` row plus `rag.lookup_failed`.

**The ranking prompt:** the fingerprint as a `context` block, and each candidate's `content` as a `kb_learned` block with attribute `entry_id`. The system template is `match_system.txt` and must contain the word JSON.

- [ ] **Step 1: Failing tests.**
  - `test_rag_budget.py`:
    - the RAG spend counts only the two pipelines;
    - exhausted when the global cap is reached or when settings are unreadable.
  - `test_rag_match.py`:
    - an unknown id dropped;
    - an id not in the candidates dropped;
    - a bad level dropped;
    - more than 3 cut to 3;
    - duplicates dropped;
    - the reasons never in `Match`.
  - `test_rag_lookup_job.py`:
    - `empty` on an empty store;
    - `ok` with history and no candidates;
    - `ok` with a match;
    - `budget`;
    - `failed` after the last attempt, with `rag.lookup_failed`;
    - an entry file edited → the match dropped and `rag.integrity_failed`;
    - the `llm_runs` row has pipeline `rag_lookup`, role `retriever`;
    - `prompt_material` returns `None` for `failed` and for `budget`, and an empty `PromptMaterial` for `empty`;
    - it drops a match whose entry was retired after the lookup.
  - `test_rag_worker.py`:
    - `iter_handlers()` keys equal {`rag_lookup`, `knowledge_draft`} once T04 lands (until then, {`rag_lookup`});
    - the main `web.handlers.iter_handlers()` contains neither.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Suites green.**
- [ ] **Step 5: Commit.**

### Task 4 (P13-T04): Drafts from conclusions, with merge and conflict

**Files:**
- Create: `backend/app/rag/draft.py`, `backend/app/rag/templates/draft_system.txt`, `backend/app/web/rag_handlers/draft.py`.
- Modify: `backend/app/rag/schemas.json` (adds `knowledge_draft_v1`); `backend/app/domain/transitions.py` (in `decide` and `conclude_case` only).
- Test: `backend/tests/test_rag_draft.py` (db), `backend/tests/test_transitions_draft_enqueue.py` (db).

**Interfaces:**
- Consumes: T02, T03 (`rank`, `call_json`, `write_rag_run`, the budget).
- Produces:
  - **`rag.draft.SourceRecord`:**
    - `subject: Subject`;
    - closed fields: `conclusion`, `category`, `mitre_ids`, `rule_ids`, `soar_scenario`, `log_source`;
    - `hostnames: frozenset[str]`;
    - `facts_text: str`;
    - `analyst_texts: tuple[str, ...]`: the decision reason, `cases.conclusion_reason` and `case_notes` bodies;
    - `ai_texts: tuple[str, ...]`: ①'s latest proposer result for the alert, or ②'s latest result for the case, as JSON.
  - **`rag.draft.source_record(conn, subject) -> SourceRecord`.**
  - **`rag.draft.validate_draft(draft: Mapping, source: SourceRecord, *, tags: frozenset[str]) -> list[str]`:** V1–V5 of spec §7.7, fault names only.
  - **`rag.draft.run_draft_job(conn, job, *, adapter=None) -> None`.**
  - In `transitions.decide` and `transitions.conclude_case`: `enqueue(conn, "knowledge_draft", Subject(...).key)` when `config.load().KNOWLEDGE_DRAFT_ENABLED`. `escalate` enqueues nothing.

**`knowledge_draft_v1`:** the fields and bounds of spec §7.4. The model fills only `title`, `tags`, `summary`, `distinguishing_signals`, `check_next_time` and `confidence_note`. The job copies the closed fields from `SourceRecord`.

**The draft job, in order:**
0. **Idempotency:** if a `knowledge_drafts` row already exists for `(source_kind, source_id)`, return. The table's unique key is the backstop; a reclaimed job must not draft twice.
1. Build the source record.
2. Find candidates with an empty exclusion.
3. If there are candidates, `rank`.
4. **Merge rule:**
   - a `rat_giong` match with an equal conclusion → `merged` with `duplicate_of_entry`; append `{subject, at}` to that entry's `evidence`; event `knowledge.merged`; no draft call;
   - a `rat_giong` match with a different conclusion → continue, and set `conflict_with_entry`.
5. The draft call: analyst texts as `analyst_note` blocks, AI texts as `context` blocks, facts as a `context` block. Template `draft_system.txt`.
6. `validate_draft`. A failure is retried once.
7. **Storing:**
   - a draft that passes is stored `pending` with event `knowledge.drafted`;
   - a draft that fails twice is stored `pending` with `draft = {}` and `warnings` = the faults;
   - with no budget, it is stored `pending` with `draft = {}` and `warnings = ["budget"]`;
   - the run row is written as pipeline `knowledge_draft`, role `drafter`.

- [ ] **Step 1: Failing tests.**
  - `test_rag_draft.py`:
    - each V rule red on a crafted draft: a schema miss; a changed `conclusion`; an IP in `summary`; a detector phrase ("ignore previous instructions") in `check_next_time`; an `<untrusted_data` tag; over-length;
    - merge: same conclusion → `merged`, the evidence appended, no draft call made (the fake adapter records zero draft calls);
    - conflict: a different conclusion → `pending` with `conflict_with_entry`;
    - two failures → empty, with warnings;
    - a second run of the same job writes nothing (idempotency);
    - budget;
    - the analyst's reason reaches the model only inside an `analyst_note` block.
  - `test_transitions_draft_enqueue.py`:
    - `decide` and `conclude_case` enqueue `knowledge_draft` (`alert:…` / `case:…`) only with the switch on;
    - `escalate` never does;
    - the enqueue is rolled back with a refused conclusion.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Suites green.**
- [ ] **Step 5: Commit.**

### Task 5 (P13-T05): Approval, publication, admin API, health

**Files:**
- Create: `backend/app/rag/publish.py` (also runnable as `python -m app.rag.publish --rebuild`), `backend/app/web/routers/admin_knowledge.py`.
- Modify: `backend/app/web/routers/admin_overview.py`, `backend/app/infra/health.py`.
- Test: `backend/tests/test_rag_publish.py` (db), `backend/tests/test_admin_knowledge.py` (db), `backend/tests/test_health.py`.

**Interfaces:**
- Consumes: T02 (`render_entry_markdown`, `KB_LEARNED_ROOT`, `sha256_text`), T04 (`validate_draft`, `source_record`).
- Produces:
  - **`rag.publish`:**
    - `approve(conn, draft_id: uuid.UUID, admin_id: str, *, edited: Mapping | None = None, root: Path = KB_LEARNED_ROOT) -> uuid.UUID`.
      - It locks the draft `FOR UPDATE`. A status other than `pending` raises `StaleDraft`, which maps to 409.
      - It applies `edited` to the model fields only and re-runs `validate_draft`; faults raise `DraftInvalid(faults)`, which maps to 422.
      - It renders the content and inserts the entry. It writes the file through a temporary name, `fsync` and `rename`. It sets the draft to `approved` and writes `knowledge.approved` (`{entry_id}`), in the caller's transaction.
      - If the file write fails, it raises before commit.
    - `reject(conn, draft_id, admin_id, reason: str) -> None`. The reason is 1–500 characters; it writes `knowledge.rejected`.
    - `retire(conn, entry_id, admin_id, reason: str) -> None`. It moves the file to `retired/` and writes `knowledge.retired`.
    - `rebuild(conn, root: Path = KB_LEARNED_ROOT) -> int`. It rewrites every active entry's file from `content` and returns the count.
  - **Routes**, all `claims: Admin`:
    - `GET /api/admin/knowledge/drafts?status=pending|merged|rejected|approved`. Pending lists conflicts first, then the oldest first.
    - `GET /api/admin/knowledge/drafts/{draft_id}` returns `{draft, source}`.
      - `source` holds the same JSON the Tier-1 alert route or the Tier-2 case and investigation routes return for that subject, built by calling their view functions (`tier1.queue.get_alert_view`, `tier2.case_view`, `tier2.investigation_view.build_investigation`).
      - It also holds the decision event, the notes, the SOAR `enrichment` block, and `conflict_entry` (a rendered entry or `null`).
    - `POST /api/admin/knowledge/drafts/{draft_id}/approve` with body `{edited?: {...}}` → `{entry_id}`; 409; 422 `{faults: [...]}`.
    - `POST /api/admin/knowledge/drafts/{draft_id}/reject` with body `{reason}`.
    - `GET /api/admin/knowledge/entries?status=active|retired`.
    - `GET /api/admin/knowledge/entries/{entry_id}` → the entry plus `evidence`.
    - `POST /api/admin/knowledge/entries/{entry_id}/retire` with body `{reason}`.
    - `GET /api/admin/knowledge/tags`.
  - **Overview:** `GET /api/admin/overview` gains the section `knowledge: {pending: int, conflicts: int}`.
  - **Health checks**, SQL only (`infra` imports no `rag`):
    - `knowledge_queue`: pending > `KNOWLEDGE_QUEUE_MAX` alarms;
    - `knowledge_integrity`: any `rag.integrity_failed` in the last 24 h alarms;
    - `rag_budget`: this month's RAG spend ≥ `RAG_MONTHLY_USD_CAP` alarms.

- [ ] **Step 1: Failing tests.**
  - `test_rag_publish.py`:
    - approve writes one file whose sha256 equals the row's;
    - edit-and-approve re-validates (an IP typed by the admin → `DraftInvalid`);
    - two concurrent approves (two connections) → exactly one entry and one `StaleDraft`;
    - reject requires a reason;
    - retire moves the file, and a later `candidates` call never returns the entry;
    - `rebuild` restores deleted files;
    - a file-write failure (a read-only root) leaves no entry row.
  - `test_admin_knowledge.py`:
    - every route as admin;
    - 403 as `tier1`;
    - the detail page's `source` holds the alert view for an alert draft, and the case plus investigation views for a case draft;
    - the pending order (conflicts first);
    - 409 and 422 bodies.
  - `test_health.py`: each of the three checks green and red.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Suites green.**
- [ ] **Step 5: Commit.**

### Task 6 (P13-T06): The admin page `/admin/knowledge`

**Files:**
- Create: `frontend/src/features/admin/KnowledgePage.tsx`, `KnowledgeDraftView.tsx`, `KnowledgeEntryView.tsx`, and their `*.test.tsx`; `frontend/e2e/admin-knowledge.spec.ts`.
- Modify:
  - `frontend/src/api/admin.ts`, with functions mirroring T05's routes: `listKnowledgeDrafts`, `getKnowledgeDraft`, `approveKnowledgeDraft`, `rejectKnowledgeDraft`, `listKnowledgeEntries`, `getKnowledgeEntry`, `retireKnowledgeEntry`, `getKnowledgeTags`;
  - `frontend/src/strings.ts`, `frontend/src/routes.tsx` (lazy route), `AdminLayout.tsx` (nav item "Tri thức"), `OverviewBlocks.tsx` (pending and conflict counts);
  - `LlmPage.tsx`: labels for the pipelines `rag_lookup` / `knowledge_draft` and the roles `retriever` / `drafter`.

**Interfaces:**
- Consumes: T05's JSON shapes exactly.
- **Layout (spec §7.5):**
  - Tabs: Chờ duyệt (with conflict badges), Đã duyệt, Đã gộp, Từ chối, Đã gỡ.
  - **The draft view has two columns:**
    - Left, the analyst's work: reuse the Tier-1 alert sections and the Tier-2 case and investigation components, read-only, with no action buttons.
    - Right, the draft form: editable model fields, a tag picker over `getKnowledgeTags`, the closed fields read-only, and the warnings.
  - **Actions:** Duyệt, Sửa rồi duyệt, Từ chối (a dialog with a required reason), Gỡ (on an entry, with a reason). They use the existing `ConfirmDialog`.
  - A 422 shows the faults next to the fields; a 409 shows "bản nháp đã được xử lý".

- [ ] **Step 1: Failing tests.**
  - Vitest with MSW:
    - each tab lists;
    - conflicts are shown first;
    - approve, edit-and-approve, reject and retire send the right bodies;
    - 422 faults are rendered on fields;
    - 409 copy;
    - a `tier1` user is redirected (the existing admin guard);
    - every tab renders its empty state with no error on an empty store (Review Focus 1).
  - e2e `admin-knowledge.spec.ts`, against the scratch app, in the existing e2e harness: one pending draft → edit and approve → it appears under Đã duyệt → retire it.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run `make ui-lint`, `make ui-test`, `make ui-build` and `make ui-e2e`** (the last holds the per-user lock on ports 18000 and 18080). The backend suites stay green.
- [ ] **Step 5: Commit.**

### Task 7 (P13-T07): ① uses the lookup

**Files:**
- Modify:
  - `backend/app/domain/transitions.py` (`finish_enrichment`; the `auto_closed` branch of `open_alert`);
  - `backend/app/tier1/triage.py`;
  - `backend/app/llm/triage.py`;
  - `backend/app/audit/llm_runs.py`.
- Test: `backend/tests/test_triage_rag.py` (db), `backend/tests/test_transitions_rag_enqueue.py` (db).

**Interfaces:**
- Consumes: T03 (`latest_lookup`, `prompt_material`, `PromptMaterial`, `render_history`), T01's vocabulary.
- Produces:
  - **Transitions, with `RAG_ENABLED`:**
    - `enqueue(conn, "rag_lookup", "alert:<id>")`;
    - `enqueue(conn, "triage", alert_id, scheduled_at=sql.SQL("now() + {} * interval '1 second'").format(sql.Literal(cfg.RAG_TRIAGE_DELAY_S)))`.
    - Without the switch: exactly today's call.
  - **`EvalSwitches.rag: bool = False`.** `DEPLOYED` is unchanged. `run_triage_job` calls `evaluate_alert(..., switches=replace(DEPLOYED, rag=cfg.RAG_ENABLED))`.
  - **`evaluate_alert`:** when `switches.rag`, `material = prompt_material(conn, latest_lookup(conn, Subject("alert", alert_id)))`, passed as `learned=material`. `TriageEvaluation` gains `rag_lookup_id: uuid.UUID | None`.
  - **`llm.triage.LearnedLike`** (a Protocol: `history_text: str | None`, `entries: Sequence[tuple[KbLearnedLevel, str]]`).
  - **`build_proposer_prompt(..., learned: LearnedLike | None = None)`.** With `None` the output is byte-identical to today. Otherwise `_learned_section` is rendered after the playbook section and before the request:
    - `HEADING_LEARNED`;
    - the history as the block `decision_history`, if any;
    - for each entry, a line `fact("kb_learned_level", level)`;
    - one `kb_learned` block holding the entries in the same order, each prefixed `[1]`, `[2]`, `[3]`;
    - then `SENTENCE_LEARNED_IS_REFERENCE`, or `SENTENCE_NO_LEARNED` alone when `learned` holds nothing.
  - **The budget cut order:** the learned section is cut first (the entries, then the history), before the existing steps. Each cut is recorded in the prompt's warnings.
  - **`audit.llm_runs.write_run(..., rag_lookup_id: uuid.UUID | None = None)`.** The proposer row carries it; the verifier row is `None`. The verifier prompt never gets the section.

- [ ] **Step 1: Failing tests.**
  - `test_transitions_rag_enqueue.py`:
    - with the switch, `rag_lookup` is enqueued and `triage.scheduled_at ≈ now() + 45 s`, on both enqueue paths;
    - without it, the rows are identical to today's.
  - `test_triage_rag.py`:
    - with the switch off, the proposer prompt and `prompt_version` equal those built without `learned`, and no `rag_results` query runs (statement recorder);
    - with an `ok` lookup: the section, the facts and the block, and `rag_lookup_id` on the proposer run;
    - with no row, `failed` or `budget`: no section, `rag_lookup_id` null;
    - with `empty`: the heading and `SENTENCE_NO_LEARNED` only, and `rag_lookup_id` set (Review Focus 1);
    - an entry retired after the lookup is dropped;
    - an entry id written into `playbook_rule_applied` ends `needs_review` with `unknown_rule` (gate unchanged);
    - over budget, the entries are cut first;
    - the verifier prompt has no section;
    - `DEPLOYED.rag is False`.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Suites green.**
- [ ] **Step 5: Commit.**

### Task 8 (P13-T08): ② uses the lookup

**Files:**
- Modify: `backend/app/domain/transitions.py` (`escalate`), `backend/app/web/routers/tier2_runs.py` (`api_analyze`), `backend/app/tier2/dossier.py`, `backend/app/tier2/investigate.py`.
- Test: `backend/tests/test_investigate_rag.py` (db), `backend/tests/test_tier2_analyze_rag.py` (db).

**Interfaces:**
- Consumes: T03 (`latest_lookup`, `prompt_material`), T07 (`LearnedLike`).
- Produces:
  - **`escalate`:** with `RAG_ENABLED`, `enqueue(conn, "rag_lookup", f"case:{case_id}")` in its transaction.
  - **`api_analyze`:** with `RAG_ENABLED`, it enqueues `rag_lookup` for the case when `latest_lookup` is `None` or older than `RAG_CASE_REFRESH_H`, before its commit. It never changes the 202 body or `run_id`.
  - **`dossier.build(conn, case_id, *, nonce, cfg=None, learned: LearnedLike | None = None)`:**
    - with `None`, byte-identical to today;
    - otherwise `_block10_learned` comes after block 8, with its heading in `DOSSIER_TEMPLATE_CONSTANTS`, the history as a `decision_history` block, and each entry as a `kb_learned` block with its level fact;
    - over `CASE_PROMPT_BUDGET_TOKENS`, block 10 is dropped first, as a new first truncation step.
  - **`run_investigate_job`:** with `RAG_ENABLED`, `material = prompt_material(conn, latest_lookup(conn, Subject("case", case_id)))`. The `llm_runs` row carries `rag_lookup_id`.

- [ ] **Step 1: Failing tests.**
  - `test_tier2_analyze_rag.py`:
    - analyze enqueues a lookup when none exists, or when the latest is older than 24 h, and not otherwise;
    - the 202 body and `run_id` are unchanged;
    - `escalate` enqueues `case:<uuid>` only with the switch.
  - `test_investigate_rag.py`:
    - the switch off gives a byte-identical dossier and no query;
    - `ok` gives block 10 and `rag_lookup_id`;
    - a retired entry is dropped;
    - over budget, block 10 is dropped first (Review Focus 5);
    - ② never waits: the job runs at once without a lookup row;
    - `_check_evidence` refuses a quote taken from a `kb_learned` block.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Suites green.**
- [ ] **Step 5: Commit.**

### Task 9 (P13-T09): Operations and documentation

**Files:**
- Create: `docker-compose.rag.yml`, `kb_learned/README.md`.
- Modify: `.gitignore` (`kb_learned/*`, `!kb_learned/README.md`), `docs/runbook.md`, `docs/limitations.md`.
- Test: `backend/tests/test_runbook_rag.py`, `backend/tests/test_compose_rag.py`.

**Interfaces:**
- **`docker-compose.rag.yml`:**
  - adds the service `rag-worker`: same image, `command: python -m app.web.rag_worker`, `kb_learned` mounted read-only, the base app's env and the other mounts;
  - adds `./kb_learned:/srv/kb_learned` read-write to `app`;
  - leaves `worker` untouched.
  - It is enabled by `COMPOSE_FILE=docker-compose.yml:docker-compose.rag.yml` in `.env`.
- **Runbook section "Learned knowledge and RAG (DEC-210)",** commands that are not run by the agent:
  - `mkdir kb_learned` with the host user's ownership;
  - migration 020 (`make migrate`, then `select count(*) from schema_migrations` = 20);
  - `COMPOSE_FILE`, then `docker compose up -d`;
  - switching `KNOWLEDGE_DRAFT_ENABLED` first, then `RAG_ENABLED` after the first approved entries;
  - the checks:
    - `printenv`;
    - a `rag_results` query;
    - `llm_runs` per pipeline;
    - the overview's knowledge counts;
  - rollback: the switches off, then `up -d`. Entries stay; no data is removed.
  - After `make db-restore`: `python -m app.rag.publish --rebuild`.
- **`docs/limitations.md`:**
  - with `RAG_ENABLED=true`, the eval harness's B4 is not the live deployment (spec §7.8);
  - full-text search uses the `simple` configuration (no accent folding);
  - the queue volume is an expectation, not measured;
  - the RAG's spend is part of the global cap.

- [ ] **Step 1: Failing tests.**
  - `test_compose_rag.py` parses both YAML files and checks:
    - `rag-worker` exists, with its command;
    - its `kb_learned` mount ends `:ro`;
    - `app` has it read-write;
    - `worker`'s effective volumes (base plus override) contain no `kb_learned`.
  - `test_runbook_rag.py`: the section exists, and names the migration count 20, `COMPOSE_FILE`, `--rebuild`, the switch order and the read-only rollback.
- [ ] **Step 2: Run them and watch them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Suites green.**
- [ ] **Step 5: Commit.**

### After T09: the whole-branch review

The Director dispatches one independent Reviewer on `git diff d680f33..director/rag-knowledge` against the spec, the Global Constraints and the Review Focus. Fix rounds repeat until it approves. The Director writes `docs/plan/tasks/P13/P13-report.md`, with the Owner's steps copied from the runbook section.
