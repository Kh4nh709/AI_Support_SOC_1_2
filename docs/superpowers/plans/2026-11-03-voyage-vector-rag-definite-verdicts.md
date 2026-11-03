# Voyage vector RAG and definite verdicts (P14) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **This build (DEC-201, DEC-213):** one Coder subagent (`coder-sonnet55`: Sonnet 5.5, xhigh, isolated worktree) and one independent Reviewer subagent per task.
> - The Director manages from `../AI_Support_SOC_voyage`, on branch `director/voyage-rag`, cut from `main` `af56b13`. It dispatches, merges, runs one mutation of its own per merge, commits each review verbatim and keeps STATE.
> - A Coder's first step is `git merge --ff-only director/voyage-rag`.
> - **Trial only [Owner, 03/11].** The branch is **never merged into `main`**. It is deployed to the trial stack only, and live stays at `af56b13`.

**Goal:**
- ① and ② always give a definite verdict. It is stored and scored, while the unchanged gate still holds risky ones for a person.
- Approved knowledge is found through Voyage embeddings in an independent pgvector, and scored by Voyage rerank. Each match reaches the prompt with a percentage.
- An admin lab page and a measurement tool compare ① and ② with the RAG off and on.

**Architecture:**
- **Part A** changes ①'s and ②'s vocabulary and prompts (`triage_v3`, `verifier_v2`, `investigate_v3`), never the gate's rules. There is no compatibility layer for old `escalate` rows: the trial database is wiped first (spec §4.1, §11).
- **Part B:**
  - adds `vectordb` (pgvector), reachable only from `rag-worker`;
  - adds a Voyage REST client on `httpx` and a `knowledge_embed` job;
  - replaces the LLM ranker inside `rag_lookup` with hybrid candidates plus Voyage rerank.
- **Part C** adds lab runs and labels (a migration, an admin API, an admin page) and `eval/lab_measure.py`. The tool re-runs ① and ② compute-only, once with the RAG off and once on.

**Tech Stack:**
- Python 3.12 (`/project/project/AI_Support_SOC_1_2/.venv`), FastAPI 0.141, psycopg 3, PostgreSQL 16 for the main database.
- `pgvector/pgvector` (PostgreSQL 16) for `vectordb`.
- The Voyage REST API (`/embeddings`, `/rerank`) through `httpx`.
- React 19, TanStack Query 5, Tailwind 4, Vitest, MSW, Playwright.

**Spec:** `docs/superpowers/specs/2026-11-03-voyage-vector-rag-definite-verdicts-design.md` (DEC-213, approved by the Owner 03/11). Read it with this plan. Its sections are cited as "spec §n".

## Global Constraints

**Vocabularies (frozen, DEC-213):**
- **①'s model answer.** `suggested_action` ∈ `false_positive | true_positive`. After the gate it is one of `false_positive | needs_review | true_positive`.
- **No old ① rows [Owner, 03/11].** The trial database is wiped before deployment. Nothing reads or translates a stored `escalate`, and migration 022 refuses to run while one exists.
- **Not renamed:**
  - the analyst's action `escalate`: `POST /api/tier1/alerts/{id}/escalate`, `transitions.escalate` and the event `tier1.escalated`;
  - the status `escalated_tier2`;
  - the gold labels `false_positive | benign | escalate` (`tier1/labels.py`, `triage_labels`).
- **②'s model answer.** `suggested_conclusion` ∈ `false_positive | policy_violation | confirmed_incident`. After the override it may also be `need_more_data`.
- **Schema names.** `triage_v3`, `verifier_v2` and `investigate_v3` are added. `triage_v2`, `verifier_v1` and `investigate_v2` stay in `output_schemas.json`, unused by the product, because `eval/` reads them.
- **Failure kinds** (a lookup, the notice, the health check): `rate_limit | timeout | auth | quota | provider_error | vectordb_unreachable`.
- **New job type `knowledge_embed`.** Its subject is the entry's uuid as text. Only `rag-worker` claims and reclaims it.
- **New builder fact and warning.** The fact `trung_pct` is an integer from 0 to 100. The builder warning `rag_not_applied:<failure kind>` goes in `citation_warnings`.
- **Lab:**
  - purposes `kb | test`;
  - labels `true_positive | false_positive`;
  - events `lab.run_created` and `lab.labeled`.

**Keys.** They go into `infra/config.py`, context pack §6.3 and `.env.example`, which goes from 76 to 87 keys. They are `.env` keys only.

| Key | Default |
|---|---|
| `VOYAGE_API_KEY` | `""` |
| `VOYAGE_BASE_URL` | `https://api.voyageai.com/v1` |
| `RAG_EMBED_MODEL` | `voyage-4` |
| `RAG_EMBED_DIMS` | `1024`, one of 256 / 512 / 1024 / 2048 |
| `RAG_RERANK_MODEL` | `rerank-2.5` |
| `RAG_MIN_SCORE` / `RAG_LEVEL_GIONG` / `RAG_LEVEL_RAT_GIONG` | `0.50` / `0.65` / `0.80` |
| `VOYAGE_PRICE_EMBED_PER_M` / `VOYAGE_PRICE_RERANK_PER_M` | `0.06` / `0.05` |
| `VECTOR_DATABASE_URL` | `""`, set by Compose for `rag-worker` only |

- **The three thresholds are provisional** until calibration (spec §6). They must satisfy 0 ≤ MIN ≤ GIONG ≤ RAT_GIONG ≤ 1, otherwise `ConfigError`.
- **`VECTOR_DB_PASSWORD`** is a Compose-only variable, like `APP_RW_PASSWORD`.

**Migrations:**
- `022` comes with T01, `023` with T04 and `024` with T09.
- Each follows `docs/Schema/021_archive.sql`: it records itself, and `docs/Schema/schema.sql` is regenerated the way 021's task did it.
- No old row is rewritten or deleted.

**Untouched:**
- `docker-compose.yml`. Compose changes go in `docker-compose.rag.yml`.
- Every file under `kb/`.
- Existing `eval/` files, except one line in `eval/metrics.py` (T01).
- The webhook contract: 201 / 409 / 400 / 401 / 403 / 413, and DEC-211's 503.
- The gate's rules. `security/gate.py` changes vocabulary only.

**Security:**
- **Where RAG material goes.** It reaches a prompt only in the user message, inside untrusted blocks.
- **What goes to Voyage.** Fingerprint text and entry digests only.
- **Voyage's own words.** Its messages are never stored, logged or shown. Only the closed failure kinds are.
- **Secrets.** `VOYAGE_API_KEY`, `VECTOR_DB_PASSWORD` and every DSN are never printed. `Config.__repr__` hides them, as it hides `LLM_API_KEY`.
- **The blind arm (DEC-101)** hides every new ①/② field: the model's verdict, the held reasons, the percentage and the notice.

**Import rules** (`backend/tests/test_import_rules.py`):
- `rag` keeps its list and may use `httpx`.
- The new package is `"lab": {"infra", "audit", "tier1"}`.
- `eval/lab_measure.py` is a composition root and may import any `app.*`.

**Every task's suites:**
- `make lint`, `make test`, and `make test-db` (only the 2 known libxml failures allowed).
- UI tasks also run `make ui-lint ui-test ui-build` and `make ui-e2e PW_ARGS=<their spec>`.
- `PY=.venv/bin/python` on every target.

## Review Focus

1. **Voyage answers out of order, with a missing or repeated `index`, or with a vector of the wrong length.**
   - Results are mapped by `index`, never by position. A candidate with no score is dropped, never given another's.
   - A wrong-length vector is `provider_error`.
   - Tests in T05 (client) and T06 (lookup).
2. **An entry approved while `vectordb` or Voyage is down,** so its `knowledge_embed` job fails.
   - The job retries per `JOB_BACKOFF`.
   - Meanwhile the entry is still a candidate through the database search, and can be matched.
   - `vector_index --check` lists it as missing.
   - Tests in T05 and T06.
3. **`RAG_EMBED_MODEL` or `RAG_EMBED_DIMS` changed after vectors were stored.**
   - Search reads only rows of the configured model and size. pgvector raises an error when vectors of different sizes are compared.
   - `--check` reports the others stale, and `--rebuild` replaces them.
   - Test in T05.
4. **Migration 022 on a database that still holds a `triage` run saying `escalate`.** This happens when the wipe was skipped, or an alert arrived between the wipe and the deploy.
   - 022 stops with one message, giving the count and pointing to the wipe (spec §11), and changes nothing: the old CHECK is still in place.
   - Test in T01.
5. **Lab windows that overlap, an alert outside every window, an unlabelled alert.**
   - An overlapping run is refused with 409.
   - Labelling an alert outside every window is refused with 409.
   - Unlabelled subjects are reported as "unlabelled", never counted as FP.
   - Tests in T09 and T11.

---

## File structure

| Path | Responsibility | Task |
|---|---|---|
| `backend/app/llm/verdicts.py`, `llm/templates/output_schemas.json` (`triage_v3`, `verifier_v2`), `llm/builder.py`, `llm/triage.py`, `llm/templates/{triage,verifier}_system.txt`, `security/{gate.py,output_guard.py}`, `kb/lookup.py`, `tier1/triage.py`, `eval/metrics.py` (one line), `docs/Schema/022_true_positive.sql` | ①'s definite verdict and the rename | T01 |
| `output_schemas.json` (`investigate_v3`), `llm/investigate.py`, `llm/templates/investigate_system.txt`, `tier2/{dossier.py,investigate.py,investigation_view.py}` | ②'s definite conclusion | T02 |
| `tier1/{queue.py,visibility.py,digest.py}`, `web/routers/{admin_llm.py,admin_digest.py}`, `frontend/src/{api/tier1.ts,strings.ts}`, `frontend/src/features/tier1/{aiState.ts,DecisionPanel.tsx,agreement.ts}`, ②'s case AI block, `features/admin/{LlmPage.tsx,DigestPage.tsx,auditSummary.ts}`, `frontend/e2e/blind.spec.ts` | showing the verdict and why it was held | T03 |
| `docs/Schema/023_vector_rag.sql`, `infra/{config.py,jobs.py}`, `docker-compose.rag.yml`, `.env.example`, context pack §6.3, runbook key table | Part B contracts | T04 |
| `rag/{failures.py,voyage.py,vector_store.py,vector_index.py}`, `web/rag_handlers/embed.py`, `web/rag_worker.py`, `rag/{publish.py,draft.py}` (enqueue) | Voyage client, vector store, embed job, index CLI | T05 |
| `rag/{match.py,lookup.py,schemas.json}`, `llm/{builder.py,triage.py}`, `tier1/triage.py`, `tier2/{dossier.py,investigate.py}`, `infra/health.py` | the lookup with Voyage; %, notice data, health | T06 |
| `tier1/{queue.py,visibility.py}`, `tier2/investigation_view.py`, `web/routers/admin_knowledge.py`, the frontend AI blocks, `features/admin/Knowledge*.tsx`, `strings.ts`, e2e | showing % and the notice | T07 |
| `docs/runbook.md`, `docs/limitations.md` | operations | T08 |
| `docs/Schema/024_lab.sql`, `backend/app/lab/{__init__.py,runs.py,labels.py}`, `web/routers/admin_lab.py`, `audit/events.py`, `web/main.py`, `web/routers/admin_audit.py` | lab runs and labels | T09 |
| `frontend/src/features/admin/Lab*.tsx`, `api/admin.ts`, `routes.tsx`, `AdminLayout.tsx`, `strings.ts`, `frontend/e2e/admin-lab.spec.ts` | the page "Gán nhãn lab" | T10 |
| `tier2/investigate.py` (`evaluate_case`), `eval/lab_measure.py` | compute-only ② and the measurement | T11 |

**Order:**
- **Wave 1:** T01 and T04, in parallel (disjoint files).
- **Then:**
  - T02 follows T01, and T03 follows T02.
  - T05 follows T04.
  - T06 follows T01 and T05.
  - T07 follows T03 and T06.
  - T08 follows T07.
  - T09 follows T04, and T10 follows T09.
  - T11 follows T03, T06 and T09.
- **Merges taken one at a time,** because these files are shared:
  - `llm/builder.py` and `llm/triage.py` (T01, T06);
  - `tier1/queue.py` and `visibility.py` (T03, T07);
  - `tier2/investigate.py` (T02, T06, T11);
  - `docs/Schema/schema.sql` (T01, T04, T09).
- **At most 4 agents at once.**

**Before T01 (the Director):**
1. `git branch director/voyage-rag af56b13`, then add the worktree.
2. Commit the spec and this plan there.
3. Write DEC-213 in `docs/plan/DECISIONS.md`. It amends DEC-210, and names the frozen-contract changes listed in Global Constraints.
4. Add the P14 phase row and the task rows to `STATE.md`.

---

### Task 1 (P14-T01): ①'s definite verdict and the rename to `true_positive`

**Files:**
- Create: `backend/app/llm/verdicts.py`, `docs/Schema/022_true_positive.sql`.
- Modify:
  - `backend/app/llm/templates/output_schemas.json` (add `triage_v3`, `verifier_v2`);
  - `backend/app/llm/builder.py` (`Verdict`);
  - `backend/app/llm/triage.py` (schema names, verifier prompt);
  - `backend/app/llm/templates/triage_system.txt`, `verifier_system.txt`;
  - `backend/app/security/gate.py` (step 1's schema name, docstrings);
  - `backend/app/security/output_guard.py` (`SUGGESTED_ACTIONS`);
  - `backend/app/kb/lookup.py` (`_ACTIONS`, the load-time mapping);
  - `backend/app/tier1/triage.py` (schema names);
  - `eval/metrics.py` (`OUTCOME_OF`, one line);
  - `docs/Schema/schema.sql`.
- Test:
  - new: `backend/tests/test_verdicts.py`, and `backend/tests/test_migration_022.py` (db);
  - updated where they name `escalate` as ①'s verdict: `test_gate.py`, `test_kb_lookup.py`, `test_llm_triage.py`, `test_triage_job.py`, `test_eval_metrics.py`.

**Interfaces:**
- Produces:
  - `llm.verdicts.MODEL_ACTIONS: tuple[str, ...] = ("false_positive", "true_positive")`.
  - `llm.verdicts.GATED_ACTIONS: tuple[str, ...] = ("false_positive", "needs_review", "true_positive")`.
  - `llm.builder.Verdict` members `FALSE_POSITIVE`, `NEEDS_REVIEW`, `TRUE_POSITIVE`. `ESCALATE` is gone.
  - `kb.lookup` decision-table rules carry an action in `GATED_ACTIONS`. A YAML `then: escalate` loads as `true_positive`, and the YAML files are not edited (spec §4.1).

**Behaviour:**
- **The schemas.**
  - `triage_v3` is `triage_v2` with `suggested_action: "false_positive|true_positive"`.
  - `verifier_v2` is `verifier_v1` with `structured_only_verdict: "false_positive|needs_review|true_positive"`.
- **A model answer of `needs_review` or `escalate`** fails step 1 and goes through the existing repair round. A second failure is `stopped_by='schema'`, as today.
- **Gate steps 2–6 are unchanged** and still force `needs_review`. `gate_result.proposed_verdict` is the model's definite answer.
- **`triage_system.txt`:**
  - The model must conclude `false_positive` or `true_positive`. The analyst and the system decide what happens.
  - No sentence offers `needs_review`.
  - The word `JSON` stays, because the adapter requires it.
  - The Coder writes the Vietnamese wording; the Owner reads it in review.
- **Migration 022, in one transaction:**
  1. A `DO` block counts `triage` runs whose `result->>'suggested_action' = 'escalate'`. If there are any, it raises `022: <n> triage runs still say escalate — wipe the trial database first (spec §11); nothing changed`.
  2. Otherwise it replaces `ck_llm_runs_suggested_action` with the strict set `false_positive | needs_review | true_positive`.

- [ ] **Step 1: Failing tests.**
  - `test_verdicts.py`:
    - `MODEL_ACTIONS == ("false_positive", "true_positive")`;
    - `GATED_ACTIONS == ("false_positive", "needs_review", "true_positive")`.
  - **Schemas:**
    - `triage_v3` refuses `needs_review` and `escalate`, and accepts `true_positive`;
    - `verifier_v2` accepts `needs_review`.
  - **Gate:**
    - a `true_positive` proposal with a basis mismatch ends `needs_review`, with `proposed_verdict == "true_positive"` and `forced_by == ["step2"]`;
    - an FP on a high-criticality asset is still forced at step 4.
  - **kb:**
    - `kb/decision_tables/recon.yaml`'s `then: escalate` rules load with action `true_positive`;
    - the verifier prompt renders `then: true_positive`;
    - the YAML file's bytes are unchanged.
  - **Triage job:**
    - a fake model answering `needs_review` twice ends `stopped_by='schema'`;
    - answering `true_positive` stores `result.suggested_action == "true_positive"`.
  - **Template:** the line of `triage_system.txt` that lists the allowed values lists exactly `false_positive | true_positive`.
  - **`test_migration_022.py` (db):**
    - on a clean database: a `triage` run with `true_positive` is accepted; ones with `escalate` and `maybe` are refused;
    - on a database holding one `escalate` run: 022 raises the message, the old constraint is still in place, and the row is untouched (Review Focus 4).
  - **eval:** `eval.metrics.OUTCOME_OF["true_positive"] == "escalate"`.
- [ ] **Step 2: Run** `make test` and `make test-db`. Expected: the new tests fail.
- [ ] **Step 3: Implement** the files above.
- [ ] **Step 4: Run** `make lint`, `make test` and `make test-db`. Expected: green.
  - `grep -rn '"escalate"' backend/app` lists only the analyst action and the gold labels. Paste the list in the report.
- [ ] **Step 5: Commit.**

### Task 2 (P14-T02): ②'s definite conclusion

**Files:**
- Modify:
  - `backend/app/llm/templates/output_schemas.json` (add `investigate_v3`);
  - `backend/app/llm/investigate.py` (schema name);
  - `backend/app/llm/templates/investigate_system.txt`;
  - `backend/app/tier2/dossier.py` (the `need_more_data` sentence at :135);
  - `backend/app/tier2/investigate.py`;
  - `backend/app/tier2/investigation_view.py`.
- Test: `backend/tests/test_investigate.py`, `test_investigation_view_api.py`, `test_dossier.py`.

**Interfaces:**
- Consumes: T01's `output_schemas.json` as merged.
- Produces:
  - `investigate_v3` is `investigate_v2` with `suggested_conclusion: "false_positive|policy_violation|confirmed_incident"`.
  - Every `investigate` run with a parsed result stores `evidence_check["model_conclusion"]`, the model's own value. `original_conclusion` stays as today when the override fires.
  - `tier2.investigation_view` adds `model_conclusion: str | None` and `held_by: list[str]`. `held_by` values are `no_verified_evidence` and `high_severity_injection_finding`.

**Behaviour:**
- **The prompts.** The system template and the dossier sentence tell the model to name its best conclusion and to list what is missing in `next_steps`. Neither tells it to answer `need_more_data`.
- **Unchanged:** the override (zero verified evidence; a high injection finding with FP) and `ck_llm_runs_suggested_conclusion`.

- [ ] **Step 1: Failing tests.**
  - A model answering `need_more_data` is refused by the schema and repaired.
  - **Zero verified evidence:**
    - the final conclusion is `need_more_data`;
    - `model_conclusion` is the model's answer;
    - the view's `held_by == ["no_verified_evidence"]`.
  - **A high injection finding plus FP:** `held_by == ["high_severity_injection_finding"]`.
  - **An old run** without `model_conclusion` renders `model_conclusion: None`, with no error.
  - **Neither the template nor the dossier** contains `need_more_data` as an instruction.
- [ ] **Step 2: Run, red.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the suites, green.**
- [ ] **Step 5: Commit.**

### Task 3 (P14-T03): Showing the definite verdict and why it was held

**Files:**
- Backend:
  - `backend/app/llm/verdicts.py` (held reasons);
  - `backend/app/tier1/{queue.py,visibility.py,digest.py}`;
  - `backend/app/web/routers/{admin_llm.py,admin_digest.py}`.
- Frontend:
  - `frontend/src/api/tier1.ts`, `frontend/src/strings.ts`;
  - `frontend/src/features/tier1/{aiState.ts,DecisionPanel.tsx,agreement.ts}`;
  - `frontend/src/features/tier2/InvestigationColumn.tsx`, which renders ②'s suggestion on the case page;
  - `frontend/src/features/admin/{LlmPage.tsx,DigestPage.tsx,auditSummary.ts}`;
  - `frontend/e2e/blind.spec.ts`.

**Interfaces:**
- Consumes: T01's vocabulary, T02's view keys.
- Produces:
  - **`llm.verdicts.held_reasons(gate_result: Mapping[str, Any] | None) -> list[str]`,** in step order:
    - `facts_mismatch` (step 2);
    - `no_verified_quote` (step 3);
    - one `fp_policy:<field>` per entry of step 4's `missing` (`severity`, `ioc_reputation`, `asset_criticality`, `identity_privileged`, `playbook_rule`);
    - `verifier_disagrees` (step 6).
  - **The alert view and the queue rows** gain `proposed_action: str | None` (`gate_result.proposed_verdict`) and `held_by: list[str]`.
  - **Every reader that compared ①'s verdict with `"escalate"`** (digest, admin LLM page, agreement, UI labels) now compares it with `"true_positive"`.

**UI copy** (spec §4.3):
- **Verdict labels:** `true_positive` → "TP", `false_positive` → "FP".
- **Alert page:**
  - kept: "AI kết luận: **TP** (độ tin cậy cao)";
  - held: "AI kết luận: **FP** (độ tin cậy trung bình) — hệ thống giữ lại cho người xem vì: …", with the reasons joined by ", ".
- **Reason labels:**

  | Reason | Label |
  |---|---|
  | `facts_mismatch` | "AI khai dữ kiện lệch với hệ thống" |
  | `no_verified_quote` | "không có dẫn chứng kiểm chứng được" |
  | `fp_policy:severity` | "alert mức critical" |
  | `fp_policy:ioc_reputation` | "IOC độc hại hoặc đáng ngờ" |
  | `fp_policy:asset_criticality` | "tài sản quan trọng hoặc chưa rõ" |
  | `fp_policy:identity_privileged` | "tài khoản đặc quyền" |
  | `fp_policy:playbook_rule` | "không khớp bảng quyết định đã duyệt" |
  | `verifier_disagrees` | "bộ kiểm tra không đồng ý" |

- **Case page:** "AI kết luận: <②'s existing label>". When held:
  - `no_verified_evidence`: "… — hệ thống giữ lại vì: không có bằng chứng kiểm chứng được";
  - `high_severity_injection_finding`: "… — hệ thống giữ lại vì: phát hiện dấu hiệu chèn lệnh mức cao".
- **`agreement.ts`:** ① `true_positive` agrees with a human escalation.
- **Blind arm:** `proposed_action` and `held_by` are hidden by `visibility`. The UI shows no "AI kết luận".

- [ ] **Step 1: Failing tests.**
  - **Backend:**
    - a `true_positive` run is shown as TP in the queue list, the alert view, the digest and the admin LLM page;
    - a step-4 `gate_result` with `missing: ["asset_criticality"]` gives `held_by == ["fp_policy:asset_criticality"]`;
    - a blind view has neither key.
  - **Vitest:**
    - the AI block renders "TP";
    - a held line shows two reasons;
    - `true_positive` agrees with a human escalation, and `false_positive` agrees with a human FP close.
  - **`blind.spec.ts`:** a blind alert shows no "AI kết luận".
- [ ] **Step 2: Run, red.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, green.** Suites plus `make ui-e2e PW_ARGS=e2e/blind.spec.ts`.
- [ ] **Step 5: Commit.**

### Task 4 (P14-T04): Part B contracts: migration 023, keys, `knowledge_embed`, the `vectordb` service

**Files:**
- Create: `docs/Schema/023_vector_rag.sql`.
- Modify:
  - `backend/app/infra/config.py` (11 keys, validation, `__repr__`);
  - `backend/app/infra/jobs.py` (`JOB_TYPES`);
  - `docker-compose.rag.yml`;
  - `.env.example` (regenerated, plus the `VECTOR_DB_PASSWORD` comment line);
  - `docs/plan/00-context-pack.md` §6.3;
  - `docs/runbook.md`'s key table;
  - `docs/Schema/schema.sql`.
- Test: the existing config, jobs, `.env.example` and `test_compose_rag.py` tests, and a new `test_migration_023.py` (db).

**Interfaces:**
- Produces:
  - **`Config`** gains the 11 keys of Global Constraints. `ConfigError` is raised when the threshold order or `RAG_EMBED_DIMS` is wrong.
  - **`JOB_TYPES`** contains `knowledge_embed`. Its handler and claim come in T05.
  - **Migration 023:**
    - `ck_jobs_job_type` gains `knowledge_embed`;
    - `rag_results.failure_kind text NULL` with `CHECK (failure_kind IS NULL OR (status = 'failed' AND failure_kind IN (<the 6 kinds>)))`;
    - `rag_results.ranked jsonb NULL`, a list of `{entry_id, score}`.
  - **Compose (`docker-compose.rag.yml`):**
    - **Service `vectordb`:**
      - image `pgvector/pgvector:<an existing 0.8.x-pg16 tag, pinned>`;
      - `POSTGRES_USER: vector`, `POSTGRES_DB: vectors`;
      - `POSTGRES_PASSWORD: ${VECTOR_DB_PASSWORD:?set VECTOR_DB_PASSWORD in .env (runbook, DEC-213)}`. Compose then stops with that message, naming no secret, if the trial's `.env` lacks it. The branch runs on the trial only, so no other stack meets this;
      - volume `vectordata:/var/lib/postgresql/data`;
      - healthcheck `pg_isready -U vector -d vectors`;
      - `restart: unless-stopped`;
      - **no `ports`**.
    - **`rag-worker`** gains `VECTOR_DATABASE_URL: postgresql://vector:${VECTOR_DB_PASSWORD}@vectordb:5432/vectors`. It has no `depends_on` on `vectordb`: an unreachable `vectordb` is a failure kind, not a start failure.

- [ ] **Step 1: Failing tests.**
  - **Config:**
    - each key's default;
    - `RAG_MIN_SCORE=0.9` with `RAG_LEVEL_GIONG=0.65` raises `ConfigError`;
    - `RAG_EMBED_DIMS=1000` raises `ConfigError`;
    - `repr(cfg)` contains neither the Voyage key nor the vector DSN.
  - **`test_compose_rag.py`:**
    - `vectordb` has no `ports`, and its password is the required `${VECTOR_DB_PASSWORD:?…}` form;
    - only `rag-worker` has `VECTOR_DATABASE_URL`;
    - `app` and `worker` do not;
    - `docker-compose.yml` is unchanged.
  - **`.env.example`:** regenerates clean, with 87 keys.
  - **`test_migration_023.py`:**
    - a `knowledge_embed` job is accepted;
    - `failure_kind` on an `ok` row is refused;
    - an unknown kind is refused;
    - `failed` with `rate_limit` is accepted.
- [ ] **Step 2: Run, red.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the suites, green.**
- [ ] **Step 5: Commit.**

### Task 5 (P14-T05): The Voyage client, the vector store, the `knowledge_embed` job and the index CLI

**Files:**
- Create: `backend/app/rag/{failures.py,voyage.py,vector_store.py,vector_index.py}`, `backend/app/web/rag_handlers/embed.py`.
- Modify:
  - `backend/app/web/rag_handlers/__init__.py` and `backend/app/web/rag_worker.py`: claim and reclaim `knowledge_embed`;
  - `backend/app/rag/publish.py`: enqueue in `approve_published` and `retire_published`;
  - `backend/app/rag/draft.py`: enqueue wherever an entry's content changes. The Coder lists every `UPDATE knowledge_entries` site in the report.
- Test:
  - `backend/tests/test_rag_voyage.py`, over `httpx.MockTransport` with recorded response shapes;
  - `backend/tests/test_rag_vector_store.py`: pure tests over a fake cursor, plus a db module that is skipped unless `VECTOR_TEST_DATABASE_URL` is set;
  - `backend/tests/test_rag_embed_job.py` (db);
  - `backend/tests/test_rag_vector_index.py`.

**Interfaces:**
- Consumes: T04's keys and job type.
- Produces:
  - **`rag.failures`:**
    - `FAILURE_KINDS: tuple[str, ...]` (the 6, in Global Constraints order);
    - `TRANSIENT_KINDS = frozenset({"rate_limit", "timeout", "provider_error", "vectordb_unreachable"})`;
    - `class RagUnavailable(Exception)` with `.kind: str`. `str(exc) == kind`, never a provider's message.
  - **`rag.voyage`** (`VOYAGE_TIMEOUT_S = 15`):
    - `Usage(total_tokens: int, model: str, latency_ms: int)`, a frozen dataclass.
    - `embed(texts: Sequence[str], *, input_type: Literal["query", "document"], cfg: Config, client: httpx.Client | None = None) -> tuple[list[list[float]], Usage]`.
      - POST `{VOYAGE_BASE_URL}/embeddings`, body `{"input", "model": RAG_EMBED_MODEL, "input_type", "output_dimension": RAG_EMBED_DIMS}`, header `Authorization: Bearer <key>`.
      - Vectors are ordered by each item's `index`. A missing or repeated index, or a length other than `RAG_EMBED_DIMS`, raises `RagUnavailable("provider_error")`.
      - An empty key raises `RagUnavailable("auth")` without sending anything.
    - `rerank(query: str, documents: Sequence[str], *, cfg: Config, client: httpx.Client | None = None) -> tuple[dict[int, float], Usage]`.
      - POST `{VOYAGE_BASE_URL}/rerank`, body `{"query", "documents", "model": RAG_RERANK_MODEL, "top_k": len(documents), "truncation": true}`.
      - Returns `{index: relevance_score}`. An unknown index, or a score outside [0, 1], is dropped and counted in the log.
    - **Errors:**

      | Condition | Kind |
      |---|---|
      | 429 | `rate_limit` |
      | 401, 403 | `auth` |
      | 402 | `quota` |
      | `httpx.TimeoutException` | `timeout` |
      | any other transport error, 5xx, other 4xx, malformed body | `provider_error` |

    - **Field names.** Check them against Voyage's API reference (docs.voyageai.com, embeddings and reranker) before coding, and pin the recorded response shapes in the tests.
    - `cost_usd(embed_tokens: int, rerank_tokens: int, cfg: Config) -> float`, at the two price keys, rounded to 5 decimals.
  - **`rag.vector_store`:**
    - `connect(cfg) -> psycopg.Connection` (autocommit). An empty DSN or a failure raises `RagUnavailable("vectordb_unreachable")`.
    - `ensure_schema(vconn) -> None`:
      - `CREATE EXTENSION IF NOT EXISTS vector`;
      - `CREATE TABLE IF NOT EXISTS entry_vectors (entry_id uuid PRIMARY KEY, content_sha256 text NOT NULL, model text NOT NULL, dims int NOT NULL, embedding vector NOT NULL, embedded_at timestamptz NOT NULL DEFAULT now())`.
      - The column is an untyped `vector`, and the search is an exact scan.
    - `upsert(vconn, *, entry_id: str, content_sha256: str, model: str, vector: Sequence[float]) -> None`, with `dims = len(vector)`.
    - `delete(vconn, entry_id: str) -> None`.
    - `stored(vconn) -> dict[str, tuple[str, str, int]]`, mapping an entry id to (hash, model, dims).
    - `nearest(vconn, vector: Sequence[float], *, model: str, limit: int = 20) -> list[str]`:
      - `WHERE model = %s AND dims = %s ORDER BY embedding <=> %s::vector LIMIT %s`;
      - the vector is passed as a text literal: no new Python dependency.
  - **`web.rag_handlers.embed.run_embed_job(conn, job: Job, *, client: httpx.Client | None = None, vconn: psycopg.Connection | None = None) -> None`:**
    - **Entry active, and the stored row missing or differing in hash, model or dims:** embed `match.entry_digest(entry)` as `document`, then upsert.
    - **Entry not active, or missing:** delete its row.
    - **A failure:** a transient kind raises `TransientError(kind)`; `auth` or `quota` raises `PermanentError(kind)`.
    - **No `llm_runs` row** [Director's call: about 300 tokens per approval, under $0.01 for the whole lab]. It logs the tokens only.
  - **The enqueue.** `enqueue(conn, "knowledge_embed", str(entry_id))` runs inside the same transaction as each publish or draft change.
  - **`python -m app.rag.vector_index --check | --rebuild`** (run in `rag-worker`):
    - `--check` prints `active`, `current`, `missing`, `stale` and `orphan`. It exits 0 only when the last three are 0.
    - `--rebuild` runs `ensure_schema`, embeds every entry that needs it in batches of 32, upserts, and deletes orphans. It prints the counts and the tokens.
    - Neither prints a DSN or the key.

- [ ] **Step 1: Failing tests.**
  - **Client:**
    - out-of-order indices are mapped by index;
    - a missing index and a wrong length are `provider_error` (Review Focus 1);
    - 429, 401, 402, a timeout and a 500 map to their kinds;
    - an empty key sends no request;
    - the provider's message never appears in `str(exc)` or the logs;
    - `cost_usd` matches the prices.
  - **Store (pure):**
    - `nearest` filters by model and dims (Review Focus 3);
    - `vector_literal` round-trips.
  - **Store (db, needs pgvector):** upsert, nearest order, delete, and dims isolation.
  - **Embed job:**
    - approve → a row;
    - retire → no row;
    - an unchanged hash → no request;
    - `vectordb_unreachable` → `TransientError` (Review Focus 2);
    - `auth` → `PermanentError`.
  - **Index:** `--check` counts missing, stale and orphan; `--rebuild` fixes them, batches by 32, and exits 0.
  - **Publish and draft:** each content change enqueues exactly one `knowledge_embed`, in the same transaction.
- [ ] **Step 2: Run, red.**
- [ ] **Step 3: Implement.** The pgvector db module needs a scratch server.
  - Use the throwaway `pgserver` the other DB tests use. It bundles pgvector: run `CREATE EXTENSION vector` there.
  - If that fails, report NEEDS_CONTEXT. The Director then hands the Owner a `docker run` for a scratch `pgvector/pgvector` container.
  - Record the run in the report.
- [ ] **Step 4: Run** the suites, green, and the pgvector module with `VECTOR_TEST_DATABASE_URL` set.
- [ ] **Step 5: Commit.**

### Task 6 (P14-T06): The lookup with Voyage: hybrid candidates, rerank, percentage, failures, prompts

**Files:**
- Modify:
  - `backend/app/rag/match.py`: rerank selection. Remove `rank`, `validate_matches`, `select_candidates` and `build_user`; keep `entry_digest` and `MAX_MATCHES`.
  - `backend/app/rag/schemas.json`: remove `rag_match_v1`.
  - `backend/app/rag/lookup.py`;
  - `backend/app/llm/builder.py`: the `trung_pct` fact, and `prompt_entries` triples;
  - `backend/app/llm/triage.py`, `backend/app/tier1/triage.py`;
  - `backend/app/tier2/{dossier.py,investigate.py}`;
  - `backend/app/infra/health.py`.
- Delete: `backend/app/rag/templates/match_system.txt`.
- Test: `backend/tests/test_rag_match.py`, `test_rag_lookup_job.py`, `test_triage_rag.py` and `test_investigate_rag.py`, rewritten for rerank; the health tests.

**Interfaces:**
- Consumes: T04's keys and columns; T05's `voyage`, `vector_store` and `failures`.
- Produces:
  - `rag.match.Match(entry_id: str, level: KbLearnedLevel, content_sha256: str, score: float)`, with `pct -> int` = `round(score * 100)`.
  - `rag.match.level_for(score: float, cfg: Config) -> KbLearnedLevel | None`:
    - `rat_giong` when ≥ `RAG_LEVEL_RAT_GIONG`;
    - `giong` when ≥ `RAG_LEVEL_GIONG`;
    - `hoi_giong` when ≥ `RAG_MIN_SCORE`;
    - `None` below that.
  - `rag.match.score(fp: Fingerprint, cands: Sequence[Entry], *, cfg: Config, client: httpx.Client | None = None) -> tuple[list[tuple[Entry, float]], Usage]`: best first; ties keep the candidates' order.
  - `rag.match.keep(scored: Sequence[tuple[Entry, float]], cfg: Config) -> list[Match]`: at most `MAX_MATCHES`, only those with a level.
  - `rag.lookup.PromptMaterial.entries: tuple[tuple[KbLearnedLevel, int, str], ...]`: level, pct and text.
  - `rag.lookup.latest_status(conn, subject: Subject) -> tuple[str, str | None] | None`: the newest lookup's status and failure kind.
  - **A `rag_results` row:**
    - `matches` items are `{entry_id, level, content_sha256, score}`;
    - `ranked` holds every scored candidate, best first;
    - `match_notes` is `{}`;
    - `failure_kind` is set on `failed`.

**The lookup job.** It keeps P13's first steps: idle timeout, subject, archived, late, history, fingerprint, exclusion and budget. Then:
1. **An empty `VOYAGE_API_KEY`** gives `failed` / `auth`, with no request.
2. **Candidates:**
   - embed `fp.text` as `query`;
   - `vector_store.nearest(…, limit=20)`;
   - load those entries from the main database, active and not excluded;
   - union them with `candidates(conn, fp, exclusion)`: vector hits first, de-duplicated, at most 40;
   - run the existing hash-and-file check on each.
3. **No candidates:** `ok` with history, otherwise `empty`. No rerank call.
4. **`score`, then `keep`.** Then, in one transaction:
   - the `llm_runs` row: `rag_lookup` / `retriever`, `system_prompt=""`, `user_message=fp.text`, `result={"ranked": …}`, `model_id=f"{RAG_EMBED_MODEL}+{RAG_RERANK_MODEL}"`, `input_tokens` = embed plus rerank tokens, `output_tokens=0`, `cost_usd=voyage.cost_usd(…)`;
   - the `rag_results` row.
5. **`RagUnavailable(kind)`:**
   - `rate_limit` on the job's first attempt raises `TransientError`. The job retries after 10 s; a run that finds ① already done is "late", as today.
   - Otherwise:
     - write a `failed` row with `failure_kind`, and the event `rag.lookup_failed` `{subject, failure_kind}`;
     - ① and ② run without RAG;
     - there is never an LLM ranker.

**Prompts:**
- **The learned entries.** In ①'s learned section, and in ②'s block 10, each entry is preceded by its level fact and `trung_pct: <pct>`, best first. The limits and the cut order are unchanged.
- **When the newest lookup failed** (with `RAG_ENABLED`): ① and ② add `rag_not_applied:<kind>` to `citation_warnings` and render no learned section.
- **With `RAG_ENABLED=false`,** the prompts are byte-identical to the output of T01 and T02.

**Health.** A new check, `rag_lookup_failures`, alarms when 5 or more lookups failed in the last 60 minutes. It is n/a while the RAG is off.

- [ ] **Step 1: Failing tests.**
  - **Matches and levels:**
    - `level_for` at 0.49, 0.50, 0.65 and 0.80;
    - `keep` holds ≤ 3, best first;
    - a candidate Voyage gave no score is dropped (Review Focus 1);
    - the hybrid merge puts vector hits first and de-duplicates.
  - **The lookup job:**
    - an entry with no vector is still found through the database search and matched (Review Focus 2);
    - a vector hit for a retired entry is ignored.
  - **Rows:**
    - `ok` stores `score` and `ranked`, and the run row's cost;
    - `failed` stores `failure_kind` and writes `rag.lookup_failed`;
    - a first-attempt `rate_limit` raises `TransientError`.
  - **Prompts:**
    - ① renders `trung_pct: 87`;
    - a failed newest lookup adds `rag_not_applied:timeout` to ①'s and ②'s warnings, with no learned section;
    - with RAG off the prompts are byte-identical.
  - **Health:** red at 5 failures, green at 4, n/a with RAG off.
- [ ] **Step 2: Run, red.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the suites, green.** `grep -rn "rag_match_v1\|match_system" backend` returns nothing.
- [ ] **Step 5: Commit.**

### Task 7 (P14-T07): Showing the percentage and the "RAG not applied" notice

**Files:**
- Backend: `backend/app/tier1/{queue.py,visibility.py}`, `backend/app/tier2/investigation_view.py`, `backend/app/web/routers/admin_knowledge.py`.
- Frontend: the alert and case AI blocks from T03, `frontend/src/features/admin/Knowledge*.tsx`, `strings.ts`, the health labels, and e2e.

**Interfaces:**
- Consumes: T03's AI blocks, T06's rows and warnings.
- Produces:
  - **The alert view and the case view** gain `rag: {"best_pct": int | None, "not_applied": str | None}`. `not_applied` is the failure kind from the latest ①/② run's `citation_warnings`. The key is hidden in the blind arm.
  - **The admin knowledge lookup detail** lists `ranked` scores where the agent's reasons used to be.

**Copy:**
- **Percentage:** "trùng {pct}% với tri thức đã duyệt".
- **Notice:** "⚠ Không áp dụng RAG cho alert này: {label} — AI đã phân tích không có tri thức tham khảo." On the case page it says "case này".
  - Each label names its source, which refines spec §4.3's "lỗi Voyage (…)", because `vectordb` is not Voyage.

  | Kind | Label |
  |---|---|
  | `rate_limit` | "Voyage vượt giới hạn tốc độ" |
  | `timeout` | "Voyage quá thời gian chờ" |
  | `auth` | "thiếu hoặc sai API key Voyage" |
  | `quota` | "Voyage hết hạn mức" |
  | `provider_error` | "lỗi phía Voyage" |
  | `vectordb_unreachable` | "không kết nối được vector DB" |

- **Health check label:** "Tra cứu RAG thất bại liên tục".

- [ ] **Step 1: Failing tests.**
  - **API:**
    - `best_pct` comes from the latest ①'s material;
    - `not_applied` comes from `rag_not_applied:auth`;
    - a blind view has no `rag` key.
  - **Vitest:** the percentage line; the notice for each kind; the case wording.
  - **e2e:** an alert with a failed lookup shows the notice; a blind alert shows neither the percentage nor the notice.
- [ ] **Step 2: Run, red.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, green.** Suites plus the UI targets.
- [ ] **Step 5: Commit.**

### Task 8 (P14-T08): Operations and documentation

**Files:** `docs/runbook.md` (a new section, "Voyage vector RAG (DEC-213)"), `docs/limitations.md`, and the runbook guard tests (the `test_runbook_*` pattern of P13-T09).

**The runbook section** ("trial only, never on live", in its first line), in order:
1. **The keys:**
   - generate `VECTOR_DB_PASSWORD` with `openssl rand -hex 24` and write it to the trial's `.env` with `printf`, never `echo`;
   - set `VOYAGE_API_KEY`.
2. **The wipe check.** No `triage` run says `escalate`. Otherwise run the wipe first (spec §11), because 022 refuses.
3. **`docker compose up -d`.** It creates `vectordb` and recreates `rag-worker`.
4. **`make migrate`** applies 021–024 to the trial.
5. **`docker compose exec rag-worker python -m app.rag.vector_index --rebuild`,** then `--check`.
6. **After `make db-restore`:** rebuild.
7. **The free-tier limits** are read on the Voyage dashboard before a lab run.
8. **Rollback:** `RAG_ENABLED=false`, then `docker compose stop vectordb`.

**Limitations to add:**
- the free tier cannot opt out of training;
- Voyage's retention is unverified;
- an unseen scenario is not measured;
- approval-time embeddings are outside the budget;
- the thresholds are provisional until calibration.

- [ ] **Step 1: Failing guard tests.**
  - The section exists, with the rebuild and check commands.
  - The password is written with `printf`, never with `echo`.
  - No line prints `$VOYAGE_API_KEY` or a DSN.
- [ ] **Step 2: Run, red.**
- [ ] **Step 3: Write the docs.**
- [ ] **Step 4: Run, green.**
- [ ] **Step 5: Commit.**

### Task 9 (P14-T09): Lab runs and labels (backend)

**Files:**
- Create: `docs/Schema/024_lab.sql`, `backend/app/lab/{__init__.py,runs.py,labels.py}`, `backend/app/web/routers/admin_lab.py`.
- Modify:
  - `backend/app/audit/events.py` (`EVENT_TYPES`);
  - `backend/app/web/main.py` (the router);
  - `backend/app/web/routers/admin_audit.py` (the two events' group and labels, as P13-T01 placed its events);
  - `backend/tests/test_import_rules.py`;
  - `docs/Schema/schema.sql`.
- Test: `backend/tests/test_lab_runs.py`, `test_lab_labels.py`, `test_admin_lab_api.py`, `test_migration_024.py` (all db).

**Interfaces:**
- **Migration 024:**
  - `lab_runs`:
    ```
    lab_runs(run_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
             name text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 80),
             purpose text NOT NULL CHECK (purpose IN ('kb','test')),
             starts_at timestamptz NOT NULL, ends_at timestamptz NOT NULL,
             created_by uuid NOT NULL REFERENCES users(user_id),
             created_at timestamptz NOT NULL DEFAULT now(),
             CHECK (ends_at > starts_at),
             EXCLUDE USING gist (tstzrange(starts_at, ends_at, '[)') WITH &&))
    ```
  - `lab_labels(alert_id text PRIMARY KEY REFERENCES alerts(alert_id), run_id uuid NOT NULL REFERENCES lab_runs(run_id), label text NOT NULL CHECK (label IN ('true_positive','false_positive')), labeled_by uuid NOT NULL REFERENCES users(user_id), labeled_at timestamptz NOT NULL DEFAULT now())`.
  - `app_rw` grants as in 017's pattern.
  - `ck_audit_event_type` gains `lab.run_created` and `lab.labeled`.
- **`lab.runs`:**
  - `LabRun(run_id: str, name: str, purpose: str, starts_at: datetime, ends_at: datetime)`;
  - `create_run(conn, *, name: str, purpose: str, starts_at: datetime, ends_at: datetime, admin_id: str) -> LabRun`, raising `RunOverlap` or `InvalidRun`;
  - `list_runs(conn) -> list[LabRun]`;
  - `run_of(conn, received_at: datetime) -> LabRun | None`.
- **`lab.labels`:**
  - `set_label(conn, alert_id: str, label: str, admin_id: str) -> str`, which returns the run id and raises `UnknownAlert` or `OutsideEveryRun`;
  - `clear_label(conn, alert_id: str, admin_id: str) -> None`;
  - `run_alerts(conn, run_id: str, *, after: str | None = None, limit: int = 100) -> list[dict]`: each item is `tier1.visibility.strip(view, …, mode="labeling")` plus `label`.
- **Events:**
  - `lab.run_created` `{run_id, name, purpose}`;
  - `lab.labeled` `{alert_id, run_id, label}`, with `label` null when a label is cleared.
- **API** (admin only, the existing admin role dependency):

  | Request | Answers |
  |---|---|
  | `GET /api/admin/lab/runs` | 200, with total and labelled counts |
  | `POST /api/admin/lab/runs` | 201; 409 `overlap`; 422 |
  | `GET /api/admin/lab/runs/{run_id}/alerts?after=&limit=` | 200; 404 |
  | `PUT /api/admin/lab/labels/{alert_id}` with `{label}` | 200; 404; 409 `outside_every_run`; 422 |
  | `DELETE /api/admin/lab/labels/{alert_id}` | 204 |

  The `alert_id` path parameter takes the same pattern as the existing alert routes.

- [ ] **Step 1: Failing tests.**
  - An overlapping run gives 409 (Review Focus 5).
  - An alert outside every window gives 409.
  - **Relabelling** changes the label and writes one event; clearing writes `label: null`.
  - **A run's alerts:**
    - are only those received inside its window;
    - none carries `suggested_action`, `proposed_action`, `held_by` or `rag`.
  - **Permissions:** a tier1 or tier2 user gets 403.
  - **The migration:** refuses `ends_at <= starts_at` and an unknown purpose.
- [ ] **Step 2: Run, red.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the suites, green.**
- [ ] **Step 5: Commit.**

### Task 10 (P14-T10): The admin page "Gán nhãn lab"

**Files:**
- Create: `frontend/src/features/admin/LabRunsPage.tsx`, `LabRunPage.tsx` and their tests; `frontend/e2e/admin-lab.spec.ts`.
- Modify: `frontend/src/api/admin.ts`, `frontend/src/routes.tsx`, `frontend/src/features/admin/AdminLayout.tsx` (nav: "Gán nhãn lab"), `frontend/src/strings.ts`.

**Interfaces:** consumes T09's API.

**The page:**
- **`/admin/lab`:**
  - a runs table: name; purpose ("Xây kho" / "Chấm điểm"); window; "Đã gán x/y";
  - a create form: name, purpose, start, end. A 409 shows "Khung giờ trùng với lần chạy khác".
- **`/admin/lab/:runId`:**
  - the run's alerts, oldest first, showing the blind view's time, rule, level, description and host fields;
  - buttons "TP — tấn công thật", "FP — không phải tấn công" and "Bỏ nhãn";
  - the progress counter.
  - **No ① output anywhere.**

- [ ] **Step 1: Failing tests.**
  - **Vitest:** the table; the 409 message; a label click updates the counter.
  - **e2e:** create a run, label two alerts, reload and see both labels; the page contains no "AI kết luận".
- [ ] **Step 2: Run, red.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `make ui-lint ui-test ui-build` and `make ui-e2e PW_ARGS=e2e/admin-lab.spec.ts`, green.
- [ ] **Step 5: Commit.**

### Task 11 (P14-T11): Compute-only ② and the measurement tool

**Files:**
- Modify: `backend/app/tier2/investigate.py`.
- Create: `eval/lab_measure.py`, and `backend/tests/test_lab_measure.py` (beside `test_run_configs.py`).

**Interfaces:**
- Consumes: T01–T03 (verdicts, `held_by`), T06 (`rag_results`, warnings), T09 (`lab_runs`, `lab_labels`).
- Produces:
  - **`tier2.investigate.evaluate_case(conn, case_id: str, *, adapter: Any | None, cfg: Config, rag: bool) -> CaseEvaluation | None`.**
    - It runs `SELECT`s only.
    - `CaseEvaluation(outcome: str, result: dict | None, model_conclusion: str | None, final_conclusion: str | None, held_by: list[str], rag_lookup_id: uuid.UUID | None, rag_not_applied: str | None, usage: dict)`.
    - `run_investigate_job` becomes `evaluate_case(…, rag=cfg.RAG_ENABLED)` plus exactly the writes it makes today. The existing tests stay green unchanged.
  - **`eval/lab_measure.py`:**
    - `main(argv: Sequence[str] | None = None) -> int`.
    - Options: `--env-file` (default `.env`), `--out` (default `eval/results/lab/`), `--yes`.
    - Without `--yes` it prints the spending estimate and exits 5, the convention of `run_configs`' `EXIT_APPROVAL`.

**`measure [--test-runs NAME …] [--kb-cutoff ISO] [--tiers 1,2]`:**
- **Subjects:**
  - ①: the labelled alerts of the test runs. The default is every `test` run.
  - ②: the cases with a head alert in a test run.
- **Truth:**
  - ① uses the alert's label.
  - A case is TP when any head alert is labelled TP. It is unlabelled when no head alert is TP and any head alert is unlabelled.
- **Two runs per subject:**
  - ①: `evaluate_alert(…, switches=replace(DEPLOYED, rag=False))`, then `rag=True`. The RAG-on run uses the lookup stored when the subject arrived (spec §6).
  - ②: `evaluate_case(rag=False)`, then `rag=True`.
- **The model's TP:** at ①, `proposed_action == "true_positive"`; at ②, `model_conclusion == "confirmed_incident"`.
- **The report** (Markdown and JSON, the same numbers), per tier and per arm:
  - n, and the unlabelled subjects excluded;
  - accuracy, TP recall and TP precision;
  - held, split into "model wrong and held" and "model right and held";
  - RAG coverage (subjects with ≥ 1 match) and the mean best percentage;
  - failed lookups, by kind, plus "no lookup";
  - leaks:
    - `same_run`: a matched entry's source alert lies in the subject's run;
    - `after_cutoff`: the entry's `approved_at` is later than `--kb-cutoff`, which defaults to the earliest test run's `starts_at`;
  - the cost spent.

**`calibrate --runs NAME … [--rerank-model M]`:**
- It reads the named `kb` runs' labelled alerts and their stored `rag_results.ranked`. With `--rerank-model`, it scores them again with Voyage rerank, over the candidates' digests read from the main database.
- It prints, for t = 0.30, 0.35, …, 0.95:
  - **coverage:** the share whose best score is ≥ t;
  - **agreement:** the share whose best entry's conclusion agrees with the label. `confirmed_incident` agrees with TP; the other four conclusions agree with FP.
- It writes nothing to the database.

**Never printed:** a DSN or a key.

- [ ] **Step 1: Failing tests.**
  - **`evaluate_case`:** it writes nothing (the row counts are unchanged), and its result is the job's.
  - **`measure`** on a scratch lab (2 runs, 6 alerts, 1 case, a fake adapter):
    - the exact accuracy, recall and precision;
    - the unlabelled subjects excluded (Review Focus 5);
    - `same_run` and `after_cutoff` flagged;
    - a failed lookup counted under its kind.
  - **`calibrate`:** the table from stored `ranked`.
  - **The approval gate:** without `--yes` it exits 5.
- [ ] **Step 2: Run, red.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the suites, green.**
- [ ] **Step 5: Commit.**

### After T11

- **The whole-branch review,** as P13 had.
- **The Director's trial deploy block** for the Owner:
  1. Check the trial was wiped (no `escalate` runs). Otherwise wipe it again.
  2. Move the trial checkout to `director/voyage-rag`.
  3. Run the T08 runbook section. Its `make migrate` takes the trial from 20 to 24.
  4. `restart` the app and the workers, and run `up -d --build ui`.
  5. Point n8n's webhook at `:8001` before the first lab run.
- **Never merged into `main`; live is never deployed** [Owner, 03/11]. The branch stays as the trial's code.
