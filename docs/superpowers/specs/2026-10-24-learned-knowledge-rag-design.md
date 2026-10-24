# Learned knowledge and RAG for ① and ② — design

Date: 24/10/2026. Status: **approved by the Owner on delivery** ("Xong thì duyệt và tất cả việc plan + code + review còn lại là của bạn", 24/10). Base: `director/soar-intake` (`ba31def`, P12 — SOAR intake). Decision record: DEC-210.

**Who decided what.**
- **[Owner]** marks what the Owner said.
- **[Director's call]** marks what the Owner left to the Director: "Phần còn lại bạn quyết định giúp tôi".
- A builder check read this document against the code at `ba31def`. Revision 2 below settles its nine questions and its eleven corrections, all as Director's calls.
- The builder may change a Director's call only by a DEC.

## 1. Intent

Analysts at Tier 1 and Tier 2 conclude about 100 alerts and cases a day **[Owner]**. Their decisions are the most valuable knowledge the SOC produces. Today ① (Tier-1 auto-triage) and ② (Tier-2 investigation) forget them: every alert is analysed as if it were the first of its kind.

The feature turns those decisions into **reviewed knowledge** and gives it back to ① and ② at the next similar alert or case:
- "this has been seen before, and this is how it was concluded";
- "this is the knowledge an admin approved about this kind of event".

The system **only supports** the analyst **[Owner]**. It does not second-guess an analyst's conclusion, does not personalise per analyst, and never decides on its own.

## 2. The flow [Owner, steps 1–5; Director's call, which conclusions draft]

1. **An analyst concludes.** Two kinds of conclusion produce knowledge:
   - **Tier 1 closes an alert** (`tier1.decided`: `closed_fp` / `closed_benign`);
   - **Tier 2 concludes a case** (`tier2.concluded`: `concluded_fp` / `concluded_policy_violation` / `confirmed_incident`).

   A Tier-1 **escalation** produces no draft. Every escalation opens a case, and the case's own conclusion carries the knowledge. Escalations still count in the decision history (§7.6).
2. **A separate agent (DeepSeek) writes a knowledge draft** from that conclusion and the data behind it. The draft's status is `pending`.
3. **An admin reviews it in the admin console.** Next to each draft, the page shows **everything the analyst worked with**:
   - the alert (or the case and all its alerts), the cluster, the correlated alerts;
   - the SOAR context;
   - ①'s suggestion and ②'s result;
   - the decision, its reason and the notes.

   The admin then chooses **approve**, **edit and approve**, or **reject**.
4. **An approved entry is published to a folder like `kb/`**: `kb_learned/`, beside `kb/`. It never replaces `kb/` **[Owner]**.
5. **The code asks the RAG automatically** for every ① run and every ② run **[Owner]**:
   - has this happened before?
   - what was concluded then?
   - which approved knowledge is similar, and how closely?

   The answer goes through a **validation step against poisoning** **[Owner]**. It then goes into ①'s or ②'s prompt.

## 3. Goals

- **G1.** ① and ② see the history of similar past decisions and the approved knowledge about them, in their prompt.
- **G2.** Nothing written by an AI reaches a prompt before an admin has approved it.
- **G3.** An admin can judge a draft from one page.
- **G4.** The RAG module is isolated. When it is down, slow, over budget or switched off, ① and ② run as today. They do not wait longer than a fixed delay, and are never reclaimed or run twice because of it.
- **G5.** The admin queue stays reviewable at about 100 conclusions a day.

## 4. Non-goals

- Redesigning the blind-arm measurement (DEC-101). **The Owner redesigns it** [Owner]. This feature provides only the hooks: a switch, plus a record per run of the lookup used.
- Checking whether an analyst was right **[Owner]**. The admin review is the only filter.
- Personalisation per analyst **[Owner]**. There is one shared store.
- Embeddings, a local model, or a vector database **[Owner: ATTT-M1 cannot run an embedding model; DeepSeek only]**.
- Fine-tuning or changing a model.
- Letting the model decide when to call the RAG (tool calls) **[Owner, confirmed]**.
- Changing `kb/`, its playbooks or its decision tables.
- Changing the output schemas `triage_v2` and `investigate_v2` **[Director's call, §7.8]**.
- Editing `eval/` (off-limits).

## 5. Anti-goals (failure even if it "works")

- **A1.** A RAG answer becomes a reason to close an alert.
- **A2.** RAG delays ① past its lock, makes ① fail, makes ① run twice, or loses a ① run.
- **A3.** Attacker-controlled text reaches a prompt as an instruction. That text can come from a log line, a username, a file path, or an analyst's note that quotes a log.
- **A4.** An entry changed after approval reaches a prompt.
- **A5.** An alert is shown knowledge or history drawn from itself, its cluster or its case.
- **A6.** The admin gets 100 new drafts a day and stops reading them.

## 6. Constraints from the existing system

**Frozen contracts change only by DEC-210, in migration `020_learned_knowledge.sql`:**
- job types (`JOB_TYPES`, `ck_jobs_job_type`);
- event types (`ck_audit_event_type`);
- `llm_runs`:
  - `ck_llm_runs_pipeline` (today `triage|investigate`);
  - `ck_llm_runs_pipeline_khop_subject` (pipeline ↔ subject type);
  - `ck_llm_runs_role` (today `proposer|verifier|investigator`);
- `security/wrap.py` `BLOCK_SOURCES`;
- `llm/builder.py` `TEMPLATE_CONSTANTS` and the ①/② prompt templates (a new `prompt_version`);
- the import-rule table (`backend/tests/test_import_rules.py`);
- context pack §6.3 keys;
- `infra/jobs.reclaim_stale`'s signature (§7.1).

**Untouched:** the output schemas (`triage_v2`, `investigate_v2`, `llm/templates/output_schemas.json`) and the gate's rules.

**Status writes:** only `domain/transitions.py` writes `alerts.status` / `cases.status`. This feature writes neither. It adds `enqueue` calls inside three of its functions, in the same transaction, as `finish_enrichment` → `triage` already does.

**Lock timing:** ①'s job holds a transaction across up to two model calls (each with one repair) under `JOB_LOCK_TIMEOUT_S` (DEC-202). Its margin holds only while a single worker can reclaim it (DEC-202 amendment, `infra/settings.py`). No RAG work may run inside ①'s or ②'s job, and no other worker may reclaim them.

**Text and spend:**
- Analyst text, log text and SOAR's free text are untrusted.
- There is one DeepSeek account.
- `eval/` may not be edited. Infra and docker changes are run by the Owner.
- The SOAR intake (P12) is the main source: ids `gl-…`, context and scenario in `alerts.raw_payload → enrichment`.

## 7. Design

### 7.1 Module, service, isolation [Director's call]

- **Package `backend/app/rag/`.**
  - It uses `llm/adapter.DeepSeekAdapter` (reused) with its own model key `RAG_MODEL` (default: the proposer's model).
  - Import rule: `rag` may import `infra`, `audit`, `security`, `llm`, `kb`, `domain`. `tier1`, `tier2` and `web` may import `rag`. `rag` imports no tier.
- **Service `rag-worker`.**
  - Same image; command `python -m app.web.rag_worker`; its own handler table, discovered from `backend/app/web/rag_handlers/`.
  - Those handlers are **not** under `web/handlers/`, which the main worker mounts entirely.
  - It claims only `rag_lookup` and `knowledge_draft`. The main worker claims neither.
- **Reclaim by type (required by A2).**
  - `infra.jobs.reclaim_stale(conn, job_types)` reclaims only stale jobs of the given types.
  - Each worker passes its own handler keys, as it already does for `claim_job`.
  - Without this change, `rag-worker` would reclaim a ① job that is still running.
- **Switches** (context pack §6.3), each defaulting to off, so merging changes nothing:
  - **`RAG_ENABLED=false`:** no lookup is enqueued, `triage` is not delayed, and no block is added. ①'s prompt and behaviour stay byte-identical (pinned by a test).
  - **`KNOWLEDGE_DRAFT_ENABLED=false`:** no draft job is enqueued on a conclusion.
- **More keys** (`.env` only, not web settings):
  - `RAG_TRIAGE_DELAY_S` (default 45);
  - `RAG_CASE_REFRESH_H` (24);
  - `RAG_HISTORY_DAYS` (90);
  - `RAG_MONTHLY_USD_CAP` (3, a tenth of the default global cap of 30);
  - `KNOWLEDGE_QUEUE_MAX` (200).
- **Spend:**
  - The RAG adapter stops a call (`LLMBudgetExceeded`) when either the RAG's month spend reaches `RAG_MONTHLY_USD_CAP`, or the global spend reaches the global cap (read through `infra/settings.py` as today, fail-closed).
  - RAG spend counts toward the global cap, so it can take at most its sub-cap from ① and ②.
  - RAG runs are written to `llm_runs` with pipeline `rag_lookup` (role `retriever`) or `knowledge_draft` (role `drafter`). Their subject is the alert or the case. The admin LLM usage page lists them.

### 7.2 Data [Director's call]

**`knowledge_drafts`:**
- `draft_id`;
- `source_kind` (`alert` | `case`) and `source_id`;
- `conclusion` (closed);
- `status` (`pending` | `approved` | `rejected` | `merged`);
- `draft` (JSON, §7.4), `warnings` (JSON), `llm_run_id`;
- `duplicate_of_entry`, `conflict_with_entry`;
- `created_at`, `reviewed_by`, `reviewed_at`, `review_note`.

**`knowledge_entries`:**
- `entry_id`, `version`, `status` (`active` | `retired`);
- the closed fields: `conclusion`, `category`, `mitre_ids`, `tags`, `soar_scenario`, `rule_ids`, `log_source`;
- `fingerprint` (text) and `fingerprint_tsv` (`tsvector`, `simple` configuration, GIN index);
- **`content`**: the full published Markdown, front matter included;
- `content_sha256`, `file_path`;
- `source_alert_ids[]`, `source_case_ids[]`, `evidence` (JSON list of merged sources);
- `approved_by`, `approved_at`, `supersedes_entry`.

**`rag_results`:**
- `lookup_id`;
- `subject_kind` / `subject_id`;
- `status` (`ok` | `empty` | `failed` | `budget`);
- `history` (JSON, §7.6);
- `matches` (JSON: `[{entry_id, level, content_sha256}]`), plus `match_notes` (the agent's reasons, **admin display only**);
- `llm_run_id`, `created_at`.

**Index:** an expression index on `alerts ((raw_payload #>> '{enrichment,case,dedup_key}'))` for the history query.

**Jobs:** `rag_lookup` (subject `alert:<id>` or `case:<uuid>`) and `knowledge_draft` (subject `alert:<id>` or `case:<uuid>`; an alert is decided once and a case concluded once, so single-flight holds).

**Events:**
- `knowledge.drafted`, `knowledge.approved`, `knowledge.rejected`, `knowledge.retired`, `knowledge.merged`;
- `rag.lookup_failed`, `rag.integrity_failed`.

**Files:**
- `kb_learned/entries/<category>/<entry_id>.md` is the **published artifact**. The app writes it on approval; retiring moves it to `kb_learned/retired/`.
- `kb_learned/` is git-ignored, except its `README.md`.
- **The database is the source of the content**: `knowledge_entries.content` and its hash.
- `python -m app.rag.publish --rebuild` rewrites every file from the database. It is the restore step after `make db-restore`. Backups stay `pg_dump` only.
- Compose:
  - `app` mounts `./kb_learned` read-write and `rag-worker` read-only;
  - `worker` must **not** mount it. It inherits `app`'s volumes today through `<<: *backend`, so its volume list is written out explicitly.

**The closed tag vocabulary** is code, tracked in git: `backend/app/rag/tags.yaml`.

### 7.3 When a draft is written [Director's call]

**Where it is enqueued.** `transitions.decide` (Tier 1 closes) and `transitions.conclude_case` (Tier 2) enqueue `knowledge_draft` in the same transaction as the conclusion, when `KNOWLEDGE_DRAFT_ENABLED`. Escalate does not. A case drafts once, not once per alert.

**The job (rag-worker):**
1. **Build the source record.**
   - Closed fields: the conclusion, category, MITRE ids, rule ids, `soar_scenario`, log source.
   - The facts of the alert or case.
   - ①'s and ②'s latest results.
   - The analyst's reason and notes, as **untrusted blocks**.
2. **Search the active entries** with the lookup's candidate search (§7.6, tier 3), excluding nothing (the source is new).
3. **Apply the merge rule (G5):**
   - If the agent rates an active entry `rất_giống` **and** its `conclusion` equals this one: the draft is stored `merged` with `duplicate_of_entry`. No admin action is needed. The entry's `evidence` gains this source, and its `content` is unchanged.
   - If it rates an entry `rất_giống` but the conclusion differs: the draft is `pending` with `conflict_with_entry`, and goes first in the queue.
   - Otherwise: `pending`.
4. **Write the draft.** One DeepSeek call writes it as `knowledge_draft_v1` JSON (§7.4), validated by V1–V5 (§7.7).
   - A failure is retried once.
   - On a second failure the draft is stored `pending` with no text and the validation errors in `warnings`. The admin can write it by hand or reject it.

### 7.4 What an entry says [Director's call]

`knowledge_draft_v1`, every field bounded:

| field | type | source |
|---|---|---|
| `title` | text ≤ 120 | model |
| `conclusion` | closed: `closed_fp`, `closed_benign`, `concluded_fp`, `concluded_policy_violation`, `confirmed_incident` | copied from the decision, never from the model |
| `category`, `mitre_ids`, `soar_scenario`, `rule_ids`, `log_source` | closed or id-shaped | copied from the data, never from the model |
| `tags` | ⊆ `backend/app/rag/tags.yaml` | proposed by the model, editable by the admin |
| `summary` | text ≤ 600 | model |
| `distinguishing_signals` | ≤ 6 × text ≤ 160 | model |
| `check_next_time` | ≤ 6 × text ≤ 160 | model |
| `confidence_note` | text ≤ 200 | model |

**Generalisation (V3).** The free-text fields contain none of the following:
- a literal IPv4 or IPv6 address, or an e-mail address;
- a `DOMAIN\user` account;
- a hostname from the inventory or the source record;
- a `gl-…` or Wazuh alert id;
- a hex hash of 32 characters or more.

The model writes placeholders instead: `<IP_NGOAI>`, `<IP_NOI_BO>`, `<USER>`, `<HOST>`. The concrete values stay in the source record (shown to the admin) and in the closed fields.

### 7.5 Admin review page [Owner: full context; Director's call: layout]

The page is `/admin/knowledge`, admin only, in the admin console v1.1 style.

- **Tabs:** Chờ duyệt (conflicts first, then the oldest), Đã duyệt, Đã gộp, Từ chối, Đã gỡ.
- **A draft opens on two columns.**
  - Left, the analyst's work:
    - the alert view (`tier1.queue.get_alert_view`), or the case view (`tier2.case_view`) with the investigation view;
    - the decision event, its reason and the person;
    - ①'s suggestion and gate result, and ②'s result and evidence check;
    - the notes;
    - the SOAR context;
    - for a conflict, the conflicting entry side by side.
  - Right, the draft: every model field editable, the tags as a picker over the closed vocabulary, the closed fields read-only, and the warnings.
- **Actions:**
  - **Duyệt** and **Sửa rồi duyệt**: V1–V5 run again on the final text. Approval is refused while any rule fails. On success the file is written and the entry row is inserted, in one transaction with its audit event. If the file write fails, the transaction rolls back.
  - **Từ chối**, with a required reason.
  - **Gỡ** on an approved entry: it retires the entry and moves the file. A retired entry is never retrieved.
- The blind arm: every draft source is a decided alert or a concluded case, for which the admin may see ①'s suggestion (DEC-206).

### 7.6 The lookup and "how similar" [Owner: the three questions; Director's call: the method, DeepSeek only]

**When it runs, and how ① and ② get it (A2):**
- **①:** with `RAG_ENABLED`, `finish_enrichment` and the auto-closed branch of `open_alert` enqueue `rag_lookup` now. They enqueue `triage` with `scheduled_at = now() + RAG_TRIAGE_DELAY_S` instead of now. Both enqueues are in the same transaction as today's (E6 holds).
  - ① **does not wait**. When it starts, it uses the alert's newest `rag_results` row if its status is `ok`; otherwise it runs without the block.
  - There is no `Reschedule`, no extra job row, and no crash window.
- **②:**
  - `transitions.escalate` enqueues `rag_lookup` for the new case in the same transaction.
  - `POST /api/tier2/cases/{id}/analyze` also enqueues one when the case's newest lookup is older than `RAG_CASE_REFRESH_H`, or when there is none.
  - ② **never waits**. It uses the newest `ok` row for the case, if any.
  - ②'s run-id contract (`uuid5(job_id)`) is untouched.

**The job builds two parts:**

1. **Decision history.** No AI. These are analyst decisions themselves, so no approval is needed. Only closed fields and counts are read, never analysts' text.
   - Keys are tried from tightest to loosest; the first one with data wins:
     - **0**: the same SOAR `dedup_key` without its hour bucket (the `|yyyyMMdd-HH` suffix). This is the exact recurrence of the same event: "seen before".
     - **1**: the same cluster key (rule, source IP, destination IP, host).
     - **2**: the same `soar_scenario` and host.
     - **3**: the same rule and host.
     - **4**: the same rule and the same source IP or user.
     - **5**: the same category and host.
   - It returns: the key level, the number of past decisions, their distribution (Tier-1 `closed_fp`, `closed_benign`, `escalated`; Tier-2 conclusions), the last date, and up to 3 example ids.
   - It looks back `RAG_HISTORY_DAYS`.
2. **Similar knowledge** (agentic).
   - **Fingerprint.** Text built by code from closed fields only: category, MITRE ids, rule id and description, `soar_scenario`, decoder, tags derived from the rule groups, and the log template with IPs, users, hosts and numbers replaced by placeholders.
   - **Candidates.** Active entries whose closed fields overlap (category, MITRE or `soar_scenario`), plus the top hits of PostgreSQL full-text search on the fingerprint. At most 20. This step is a database search, not a model.
   - **Agent.** One DeepSeek call receives the fingerprint and the candidates' published content, inside untrusted blocks. It returns `rag_match_v1`: up to 3 `{entry_id, level: rất_giống | giống | hơi_giống, reason}`, or none.

**Self-exclusion (A5).** The history and the candidates exclude:
- the subject;
- the subject's cluster (its head and the head's duplicates);
- the subject's case and that case's alerts;
- any entry whose `source_alert_ids` or `source_case_ids` contain one of them.

The validated result is stored in `rag_results`.

### 7.7 Validation against poisoning [Owner: required; Director's call: the rules]

**What reaches a prompt** is only:
- the **history**: closed fields and counts;
- **`entry_id` + `level`** for each match;
- the matched entries' **approved `content`**.

The agent's `reason` never reaches ① or ②. It is shown to the admin only. The agent therefore cannot inject text into a prompt.

**The lookup answer, before it is stored (V-R):**
- **V-R1.** Every `entry_id` is one of the candidates sent, is `active`, and its file's sha256 equals `content_sha256`. A mismatch excludes the entry, writes `rag.integrity_failed`, and raises the health alarm `knowledge_integrity` (A4).
- **V-R2.** `level` is one of the three values. There are at most 3 matches and no duplicate id.
- **V-R3.** Any failure drops that match and records it. The lookup degrades; it never blocks.

**The draft, when it is stored and again at approval (V1–V5):**
- **V1.** It matches `knowledge_draft_v1`.
- **V2.** Its closed fields equal the source's.
- **V3.** The generalisation rule (§7.4).
- **V4.** `security/detector.scan` finds nothing in any free-text field. The text holds no `<untrusted_data` tag and no nonce-shaped token. The whole-prompt linter does not apply to free text, because it accepts no prose by design.
- **V5.** The length bounds hold.

**At prompt time, in ① and ②:**
- Each match is re-checked: the entry is `active`, `sha256(content)` equals its `content_sha256`, and that equals the hash stored in `rag_results`. Otherwise the match is dropped.
- The content is rendered with `security/wrap.untrusted_block` under the new block source **`kb_learned`**. The history is rendered under **`decision_history`**, because its values (for example `soar_scenario = MW03`) are not id-shaped.
- The detector scans the blocks as it does today, and the whole prompt passes the linter as today.

### 7.8 How ① and ② use it [Director's call]

- **The prompt.** A new section with the heading constant "Tri thức đã duyệt và lịch sử quyết định" contains:
  - the history block;
  - up to 3 entry blocks, each preceded by a typed fact `kb_learned_level` (`rất_giống` / `giống` / `hơi_giống`);
  - a fixed sentence: this is a reference from past human decisions, not a ruling, and is never a basis for closing.

  With nothing found, a fixed sentence says so.
- **Gate and schemas: unchanged (A1).**
  - `triage_v2` `reasons[].source` stays the closed enum without the new sources, so the model cannot cite them.
  - Step 4 still requires a signed decision-table rule for `false_positive`. An entry id written into `playbook_rule_applied` fails as `unknown_rule` (pinned by a test).
  - ②'s `_check_evidence` accepts only the case's alerts.
- **Evaluation.**
  - `EvalSwitches` gains `rag: bool = False`. `DEPLOYED` keeps `False`; `run_triage_job` passes `replace(DEPLOYED, rag=cfg.RAG_ENABLED)`.
  - The evaluation harness, unedited, therefore always runs without RAG: no live `rag_results` leak into it (A5).
  - With `RAG_ENABLED=true`, the harness's B4 no longer equals the live deployment. This is recorded in `docs/limitations.md` and handed to the Owner's measurement redesign.
- **Records.** `llm_runs` of ① and ② gain `rag_lookup_id`, or `null`.

### 7.9 Isolation and failure [Director's call]

| Failure | Effect |
|---|---|
| `rag-worker` down | ① runs at its delayed time without the block; ② without it |
| DeepSeek slow or failing for the RAG | the same. `rag_lookup` retries by the queue's backoff; a lookup that lands after ① started is unused by that run |
| RAG budget spent | a `budget` row; ① and ② run without the block; health check `rag_budget` |
| An entry file changed after approval | that entry excluded; `rag.integrity_failed`; health alarm |
| `RAG_ENABLED=false` | today's behaviour, byte for byte |
| Draft agent failing | the conclusion is already committed; the draft is `pending`, with no text and the errors |
| A database restored without files | `knowledge_integrity` alarms; `python -m app.rag.publish --rebuild` restores the files |

### 7.10 Volume [Director's call]

At about 100 conclusions a day:
- the merge rule and per-case drafting are expected to bring the queue well under 100 a day once the store has some weeks of entries (an expectation, not measured);
- the overview shows the queue length;
- the health check `knowledge_queue` alarms above `KNOWLEDGE_QUEUE_MAX`;
- ① costs one extra DeepSeek call per head while `RAG_ENABLED` (the lookup), bounded by the sub-cap.

## 8. The Director's calls, for reading

1. **Retrieval and similarity.** Code triggers the retrieval. DeepSeek judges similarity over candidates found by a database search, with no embeddings.
2. **What needs approval.** History counts come straight from analyst decisions and need no approval. Entries need approval.
3. **Isolation.** A separate `rag-worker`, two new job types, and **reclaim filtered by type**.
4. **No waiting.** ① starts 45 s later and uses the lookup if it is ready. ② never waits; a case is looked up at escalation and refreshed after 24 h.
5. **Only approved content and closed fields reach a prompt.** The agent's reasons never do.
6. **No change to output schemas or the gate.** A RAG match cannot be cited, and cannot be a basis for `false_positive`.
7. **Entries are generalised:** no literal IPs, users or hosts.
8. **Drafts come from Tier-1 closes and Tier-2 conclusions only.** Very similar drafts with the same conclusion are merged; conflicting ones go first.
9. **Storage.** The database holds the content; the files are the published copy, rebuilt from the database after a restore.
10. **Defaults.** Both switches are off by default. The eval harness runs without RAG. One migration (020) holds every schema change.

## 9. Left to the builder

- Exact names beyond the ones above.
- The first content of `backend/app/rag/tags.yaml`, derived from `ingest/category.py` and the SOAR scenarios.
- Prompt wording inside the fixed constants.
- The page's visual details.
- The task split.

## 10. Verification expected

- Each switch in both states.
- A byte-identical ① prompt and behaviour with `RAG_ENABLED=false`.
- `reclaim_stale` filtered by type: the rag-worker never reclaims a `triage` or `investigate` row.
- `triage` delayed only with `RAG_ENABLED`.
- ① running without a lookup row, and with a `failed` or `budget` row.
- ②'s run id unchanged.
- Self-exclusion at every level.
- V-R and V1–V5 each red once, on a scratch copy (DEC-025).
- An edited file excluded and alarmed; `--rebuild` restoring files.
- An entry id in `playbook_rule_applied` ending in `needs_review` (`unknown_rule`).
- The eval switch default.
- The blind-arm pages unchanged.
- The admin page's e2e: approve, edit and approve, reject, retire, and the conflict view.
- RAG cost counted under the sub-cap and the global cap.
