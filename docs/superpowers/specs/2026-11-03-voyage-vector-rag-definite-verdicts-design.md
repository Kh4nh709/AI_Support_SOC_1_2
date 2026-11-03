# Voyage AI vector retrieval and definite verdicts for ① and ② — design

- **Date:** 2026-11-03
- **Status:** **approved by the Owner on 03/11/2026**, with two changes folded in:
  - ①'s `escalate` is renamed `true_positive` (4.1).
  - A Voyage failure turns the RAG off for that alert and shows a "RAG not applied" notice (5.3).
  The Owner also asked for the current database to be wiped before the lab (section 11).
- **Two further rulings, 03/11, after the plan:**
  - **No backward compatibility with old data.** The old database is wiped precisely so the AI's verdict can be changed cleanly (4.1).
  - **Trial only.** The build is **never merged into `main`** and runs on the trial only (5.7).
- **Becomes:** DEC-213. It amends DEC-210 and its spec, `docs/superpowers/specs/2026-10-24-learned-knowledge-rag-design.md`, where they conflict. Everything else in DEC-210 still holds.
- **Decided by:** the Owner, in conversation on 03/11. Items marked **[Owner]** are the Owner's words or choices. Items marked **[Director's call]** were decided by the Director and are open to the Owner's veto when reading.

---

## 1. Intent

### What the thesis needs

The thesis describes the learning loop as **RAG with embeddings and a vector database** [Owner]. The loop, in the Owner's words, works like this:

1. A case is concluded by SOC Tier 2.
2. An admin approves it into the knowledge base.
3. Later alerts, when the AI analyses them at ① and at ②, are given the approved cases that resemble them, **with a similarity percentage**.
4. An alert that matches an earlier concluded case should get the right conclusion on the first pass.
5. None of this needs fine-tuning or retraining the model.

### What exists today, and what changes

The loop itself was built in P13 (DEC-210): conclusion → draft → admin approval → entry → lookup for later alerts. Only the way entries are found and ranked changes:

- **Today:** closed-field overlap plus Postgres full-text search finds the candidates, and an LLM ranking call (GLM/DeepSeek) chooses among them. There are no embeddings.
- **After this design:** **Voyage AI embeddings** (through an API key [Owner]) and an **independent pgvector database** [Owner] find the candidates, and **Voyage rerank** scores them.

### Definite verdicts

The Owner wants the AI to **always reach a definite conclusion** at ① and ② (FP or TP), not "needs review" [Owner]. Two reasons:

- The accuracy percentage of the lab experiment becomes straightforward to compute.
- The RAG's effect can be measured on those conclusions.

What the system *does* with a conclusion still goes through the existing gate. When the gate holds an alert back, it waits for human review [Owner].

### How success is measured

The Owner's success picture:

- **The lab.** The team simulates attacks in a lab, and knows which alerts are real attacks.
- **The knowledge base.** About **50–100 concluded and approved alerts/cases** are built from some attack runs.
- **The test runs.** Separate attack runs of the **same scenarios** are then scored. Each simulation is its own run [Owner].
- **Expected results, RAG off:** ① and ② identify **60–70 %** correctly.
- **Expected results, RAG on:** **80–90 %**.

These figures are the Owner's expectations, **not acceptance criteria for the build**. The build is done when the measurement produces honest numbers, whatever they are.

## 2. Three parts, in this order

| Part | What | Why this order |
|---|---|---|
| **A** | Definite verdicts at ① and ② | The RAG-off baseline (60–70 %) needs definite verdicts to be scored. It can be measured as soon as A lands, while B is being built. |
| **B** | Voyage embeddings + independent pgvector + Voyage rerank, replacing the candidate search and the LLM ranker | The RAG-on run needs it. |
| **C** | The lab measurement: the same test set, RAG off vs on, per tier | It needs A, and B for the second run. |

A and B touch different code (A: `llm/`, `security/gate.py`, `tier1/`, `tier2/`, the UI; B: `rag/`, compose, a new database). They can be built in parallel. Each part is a separate set of cards.

## 3. Goals, non-goals, anti-goals

### Goals
- **G1.** ①'s model always answers FP or TP. ②'s model always answers FP, policy violation or confirmed incident. Each answer comes with a confidence.
- **G2.** The model's answer is stored and shown even when the gate holds the alert, so it can be scored.
- **G3.** Approved knowledge entries are embedded with Voyage and stored in a separate pgvector database. Every ① and ② lookup finds candidates by vector similarity and scores them with Voyage rerank.
- **G4.** ① and ② prompts carry up to 3 matched entries, each with a **similarity percentage**.
- **G5.** A repeatable measurement on the same labelled test set, RAG off and RAG on, for ① and ②.

### Non-goals
- **Fine-tuning or retraining any model** [Owner].
- **Comparing against alerts that were not approved.** The vector index holds admin-approved entries only [Owner].
- **Letting the AI's conclusion act past the gate.** A held alert waits for a person [Owner].
- **A local embedding model, such as `voyage-4-nano`.** The Owner chose the API.
- **Changing the decision-history block** (`rag/history.py`). Analyst-decision counts stay as they are.
- **Changing the draft pipeline.** Drafts are still written by the LLM (`RAG_MODEL`), validated by V1–V5, and approved at `/admin/knowledge`.
- **Changing how Tier 1 and Tier 2 act on alerts.** ① never closes an alert itself: auto-close is a separate, rule-based step at ingest (`ingest/autoclose.py`), and an analyst decides every queued alert. Definite verdicts therefore do not close more alerts.

### Anti-goals (failure even if it "works")
- **A match percentage that can push an alert past the gate.** The gate stays monotone: it may only force `needs_review` / `need_more_data`, never lift them.
- **Scoring on the alerts the knowledge base was built from.** The test runs must be separate attack runs [Owner]. A score on KB-source alerts is a leak, not a result.
- **The vector database becoming a source of truth.** It is a derived index. Losing it costs a rebuild, never knowledge.
- **Anything reaching Voyage that the existing redaction would not let reach the LLM.** This includes raw logs, hostnames, usernames and owners.
- **A secret, a DSN or an API key printed on screen, in logs or in a report.**

## 4. Part A — definite verdicts

### 4.1 ① (triage)

| | Today | After |
|---|---|---|
| Model's allowed `suggested_action` | `false_positive \| needs_review \| escalate` | `false_positive \| true_positive` [Owner] |
| Gate | Steps 2, 3, 4, 6 may force `needs_review` | **Unchanged** [Owner] |
| What `needs_review` means | "the model is unsure" or "the gate held it" | Only "the gate held it" |
| Stored | `gate_result.proposed_verdict` and `final_verdict` | Unchanged (already stores both) |

- **The rename [Owner, 03/11: "cho phép đổi luôn"].** ①'s verdict `escalate` becomes **`true_positive`**, meaning "a real attack: escalate to Tier 2". It is shown as **TP**.
  - **What is renamed:** ①'s *verdict vocabulary* only. That is:
    - the output schema;
    - the verifier's schema;
    - `llm.builder.Verdict`;
    - the decision-table action as the gate and the prompt see it (`kb/lookup.py`'s `_ACTIONS`);
    - the gate;
    - the queue, the visibility filter and the UI where they show ①'s suggestion;
    - the two prompts;
    - the tests.
  - **What is not renamed:** everything about the *analyst's* escalation. The route `POST /api/tier1/alerts/{id}/escalate`, `transitions.escalate`, the event `tier1.escalated` and the status `escalated_tier2` all stay. The gold-label vocabulary of `tier1/labels.py` and `triage_labels` (`false_positive | benign | escalate`) stays. ②'s conclusions stay.
  - **The decision tables in `kb/` [Director's call].** They are signed policy (`reviewed_by: "NCK + MNN"` on 10 tables) and are not edited. Their `then: escalate` is read by the loader as the verdict `true_positive`.
  - **No old rows [Owner, 03/11].** The trial database is wiped before the build is deployed (section 11): *"xóa db cũ để thuận lợi cho việc điều chỉnh kết luận AI"*. So:
    - nothing reads an old `escalate`, and there is no compatibility layer;
    - migration 022 makes the CHECK on ①'s stored verdict strict (`false_positive | needs_review | true_positive`).
    - A migration is still needed, because the constraint lives in the schema. It refuses, changing nothing, while any `triage` run still says `escalate`, which happens only if the wipe was skipped.
  - **`eval/` (a consequence of the rename).** `eval/metrics.py`'s `OUTCOME_OF` maps a verdict to an outcome and knows `escalate`. It gains `"true_positive": "escalate"`, or `eval/`'s scoring breaks. That is the only change to existing `eval/` files (section 6 otherwise keeps them untouched).
- **The schema.** `triage_v2` becomes **`triage_v3`**, with `suggested_action` narrowed to `false_positive | true_positive`. A `needs_review` from the model is then a schema error, and goes through the existing repair round.
- **The verifier.** `verifier_v1` is part of the gate. It becomes `verifier_v2` only for the rename (`false_positive | needs_review | true_positive`) and keeps its three values. A verifier that answers `needs_review` disagrees, and step 6 forces `needs_review`, as today.
- **The system prompt** (`llm/templates/triage_system.txt`):
  - Its opening says *"Nhiệm vụ của bạn là ĐỀ XUẤT, không phải quyết định. Analyst Tier 1 là người quyết."* It must now say that the model **must conclude FP or TP**, while the analyst and the system still decide what happens.
  - The builder drafts the Vietnamese wording. The Owner reads it in review.
- **The prompt version.** It changes. Runs with the old and the new prompt are not compared as one series.

### 4.2 ② (investigate)

| | Today | After |
|---|---|---|
| Model's allowed `suggested_conclusion` | `false_positive \| policy_violation \| confirmed_incident \| need_more_data` | `false_positive \| policy_violation \| confirmed_incident` [Owner] |
| Override (`tier2/investigate.py`) | Zero verified evidence → `need_more_data`; a high injection finding plus FP → `need_more_data` | **Unchanged** |
| Stored | `original_conclusion` **only when overridden** | **Always** store the model's own conclusion beside the final one |

- **The schema.** `investigate_v2` becomes **`investigate_v3`**.
- **The prompt.** Its sentence *"Nếu dữ liệu cần thiết không có ở đây, hãy trả lời `need_more_data`"* (`investigate_system.txt`), and the matching sentence in `tier2/dossier.py:135`, must change. The model now names its best conclusion and states what is missing in `next_steps`.

### 4.3 What the analyst sees

On the alert page (①) and the case page (②), when the suggestion is visible:

- **When the gate keeps the verdict:**
  - *"AI kết luận: **TP** (độ tin cậy cao) — trùng 87 % với tri thức đã duyệt #…"*
  - The percentage part appears only when there was a match.
- **When the gate held it:**
  - *"AI kết luận: **FP** (độ tin cậy trung bình) — **hệ thống giữ lại cho người xem** vì: tài sản quan trọng"*
  - The reason comes from `forced_by` / `missing`, in the Vietnamese labels the UI already uses where they exist.
- **When the RAG was not applied** because Voyage failed (5.3) [Owner, 03/11], a notice beside the conclusion:
  - *"⚠ Không áp dụng RAG cho alert này: lỗi Voyage (<loại lỗi>) — AI đã phân tích không có tri thức tham khảo."*
  - On the case page the wording says "case".
  - The error kind is a closed value (`rate_limit`, `timeout`, `auth`, `quota`, `provider_error`, `vectordb_unreachable`), never the provider's message.
  - *(Refined while planning:)* the shown label names its source, for example "Voyage vượt giới hạn tốc độ" or "không kết nối được vector DB", because a `vectordb` failure is not Voyage's.
- **The blind arm** (DEC-101, `suggestion_visible = false`) hides all of this, the percentages and the notice included, exactly as it hides the suggestion today.

### 4.4 Consumers of the verdict

Everything that reads `suggested_action` / `suggested_conclusion` today keeps working: the queue, the health checks, the digest, `eval/`, the UI. The values they see are a subset of before: `needs_review` and `need_more_data` still occur when the gate or the override forces them. The builder lists every reader and confirms this. Where a reader counts "the model said needs_review", it now counts "held".

## 5. Part B — Voyage embeddings and an independent pgvector

### 5.1 The vector database [Owner: an independent pgvector]

**The service.**
- A new Compose service, **`vectordb`**, in `docker-compose.rag.yml`.
- Image `pgvector/pgvector` on Postgres 16. The builder pins the tag.
- Its own named volume and its own superuser and app credentials.
- **No `ports:`**: nothing is published to the host or the LAN.
- Only `rag-worker` is given its DSN (`VECTOR_DATABASE_URL`). `app`, `worker` and `ui` have none.
- **`rag-worker` does not depend on `vectordb`** [Director's call, planning 03/11]. An unreachable `vectordb` is the failure kind `vectordb_unreachable`, not a start failure, so drafts keep working.

**The table.** One table, for example:
```
entry_vectors(
  entry_id       uuid PRIMARY KEY,      -- knowledge_entries.entry_id in the main database
  content_sha256 text NOT NULL,         -- the entry's hash when it was embedded
  model          text NOT NULL,         -- e.g. voyage-4
  dims           int  NOT NULL,
  embedding      vector(1024) NOT NULL,
  embedded_at    timestamptz NOT NULL DEFAULT now()
)
```
- The corpus is small (tens to hundreds of rows), so an exact scan is fine. An HNSW index is optional.
- How this schema is created and migrated is the builder's call: a tiny migration of its own, or create-if-absent when `rag-worker` starts. It must not join the main database's migration chain.

**A derived index.** The main database stays the only source of truth for an entry's content, status and hash [Director's call]:
- Every row found in `vectordb` is **re-checked against the main database** before use. The entry must still be active, the hash must match, and the published file must match (the existing V-R1 / A4 checks). A stale or orphan vector is simply ignored.
- **A rebuild command** (for example `python -m app.rag.vector_index --rebuild`) embeds every active entry from scratch.
- `vectordb` needs **no backup of its own**. After `make db-restore`, or after losing the volume, rebuild it. The runbook says so.

### 5.2 Writing: when an entry is approved, edited, merged or retired

1. **Approval.** The admin approve route (in `app`) commits the entry as today. In the same transaction it enqueues a new job type, **`knowledge_embed`** (subject: the entry id), claimed and reclaimed only by `rag-worker`.
   - Adding the job type is a frozen-contract change: the job type list and `reclaim_stale`'s type filter. It is recorded in DEC-213.
2. **Embedding.** `rag-worker` embeds the entry's **digest** with `input_type = "document"`. The digest is `match.entry_digest`: closed fields, title and summary. The worker upserts `entry_vectors` with the entry's current `content_sha256`.
3. **Changes.** An edit, merge or retirement enqueues the same job:
   - The job embeds again when the entry is active and its hash differs from the stored one.
   - It deletes the row when the entry is no longer active.
4. **Backfill.** The entries approved before this change (2 active on the trial today) are embedded by the rebuild command at deployment.

### 5.3 Reading: the `rag_lookup` job

This replaces `candidates()` + `rank()`. Everything before it (archived, late, budget) and after it (writing `rag_results`) stays.

1. **Fingerprint.** Built as today (`rag/fingerprint.py`: closed fields, rule descriptions, one generalised log line).
2. **Embed the fingerprint** with `input_type = "query"`.
3. **Vector search** in `vectordb`: the 20 nearest by cosine distance.
4. **Hybrid merge [Director's call].** Union the vector hits with today's database candidates (closed-field overlap plus full-text, `rag/candidates.py`), then de-duplicate. Exact rule-id and scenario matches, which full-text finds reliably, are then never lost to an embedding miss.
5. **Exclusion and integrity**, both as today:
   - Drop self-sourced entries (A5).
   - Re-read every candidate from the main database: it must be active, its hash must match, and its file must match.
6. **Voyage rerank.** The query is the fingerprint text and the documents are the candidates' digests. Each document gets a `relevance_score` from 0 to 1.
7. **Keep at most 3** (`MAX_MATCHES`) with a score ≥ `RAG_MIN_SCORE`.
   - **The percentage** is `round(score × 100)`.
   - **The level** (`rat_giong` / `giong` / `hoi_giong`) is derived from the score by two thresholds, so the prompt format and `KbLearnedLevel` stay.
   - The `Match` is still built from the candidate, never from provider output.
8. **Record.**
   - `rag_results.matches` gains each match's `score`.
   - `match_notes` is empty: a reranker writes no text. The admin page shows the score instead.
   - The Voyage calls are recorded where the RAG budget can count them (see 5.6).

**What leaves the read path.** The LLM ranking call (`rag/match.py`'s `rank`, the `rag_match_v1` schema and its template) is no longer used for lookups [Owner, 03/11]. The LLM is still used for drafts.

**When Voyage fails [Owner, 03/11].**
- **The RAG is turned off for that alert (or case),** and the UI says so (4.3).
  - Any failure counts: an error, a timeout, a 401, a 402, a 429, or `vectordb` unreachable.
  - The lookup is recorded `failed`, with a closed error kind.
  - ① and ② run without the RAG, as they already do for a failed lookup, and never wait.
- **No fallback to the LLM ranker** [Owner].
- **One retry for a 429 [Director's call].** It is retried once if it can still finish before ① starts (inside `RAG_TRIAGE_DELAY_S`). Otherwise it is a failure like any other.
- **What the run records.** ①'s and ②'s run rows record whether the RAG was applied, and if not, the error kind. The notice is read from there.
- **The health check [Director's call].** The existing health checks gain one that alarms when lookups fail repeatedly within an hour. The admin then sees a dead key or a rate limit without opening alerts one by one.
- **Why failures matter here:** the free tier's rate limits are not published (5.5). A lab run that sends many alerts at once could hit them, and every failed lookup lowers the RAG-on score for a reason that has nothing to do with retrieval. The measurement tool therefore reports how many lookups failed (section 6).

### 5.4 Into the prompt

- **Where.** The matched entries go where they go today: the `kb_learned` block in the **user message**, inside the nonce-wrapped untrusted block. They do not go into the system prompt [Director's call].
  - The Owner said "system prompt". That would hand approved-but-analyst-written text the authority of an instruction.
  - For the model's use of the reference, the two places are equivalent.
- **Each entry line.** Its existing closed level fact, plus a **new closed integer fact for the percentage** (for example `trung_pct: 87`), then the approved content.
  - The fact goes through `builder.fact()` like every other fact, so the linter accepts it.
- **Limits.** Unchanged: `ENTRY_LIMIT_BYTES` = 4 000 per entry, 3 entries, and ①'s total budget.
- **Basis for a verdict.** DEC-210's rule stays: a RAG match is not a citable source, and cannot be the basis of a `false_positive` the gate keeps.
  - The model may weigh the match. The gate still decides.
  - Section 8 flags what this means for the FP side of the score.

### 5.5 What is sent to Voyage, and the account

**What is sent:**
- **Fingerprint text.** Closed fields, MITRE ids, rule ids and rule descriptions, and one log line generalised by `rag/generalise.py` (IP, user, host and number replaced by placeholders), ≤ 2 000 characters.
- **Entry digests.** Admin-approved, already redacted by V1–V5.

**What is never sent:** a raw log, a hostname, a username, an owner, or an analyst's free text that did not pass approval.

**The account: the free tier, no payment method [Owner, 03/11].** What follows from it:
- **Training.** MongoDB (Voyage's owner) may use data sent to its self-serve API to improve Voyage models. Opting out requires a payment method on file, so **on this account it cannot be turned off**. The data sent is the redacted material above. The thesis must say that it may be used for training.
- **Retention.** No retention period is documented. The thesis should state this as unverified.
- **Rate limits.** The published limits (2 000 requests per minute, 2–8M tokens per minute) are Tier 1, which requires a payment method. The free tier's limits are not published. Before the lab run, the Owner reads them on the Voyage dashboard. The design copes with low limits (5.3, section 6), but they may slow a large run.
- **Upgrading later.** Adding a payment method changes nothing in the code: the free tokens still apply, and the training opt-out becomes available.

### 5.6 Configuration

**New keys**, to be added to `.env.example`, which currently has 76 keys. The builder updates the count and the tests that pin it.

| Key | Default | Meaning |
|---|---|---|
| `VOYAGE_API_KEY` | empty | Empty with the RAG on means the lookup is `failed` / `auth`, sending no request, and the UI says so (5.3). *Ruled 04/11 after the T04 review:* this follows the Owner's "báo thông báo lỗi". It was "skipped, as with no model". |
| `VOYAGE_BASE_URL` | `https://api.voyageai.com/v1` | |
| `RAG_EMBED_MODEL` | `voyage-4` | Documented multilingual. Entries are Vietnamese; fingerprints are mostly English. |
| `RAG_EMBED_DIMS` | `1024` | |
| `RAG_RERANK_MODEL` | `rerank-2.5` | Documented multilingual. `rerank-3` is compared during calibration (C). |
| `RAG_MIN_SCORE`, plus two level thresholds | provisional, set by the builder | Calibrated on the lab KB; the Owner may tune them. |
| `VECTOR_DATABASE_URL`, `VECTOR_DB_PASSWORD` | — | `rag-worker` only. |

**Budget.** Voyage spend counts inside `RAG_MONTHLY_USD_CAP`, which already counts inside `LLM_MONTHLY_USD_CAP`, at Voyage's prices. Today these are $0.06 per 1M tokens for `voyage-4` and $0.05 per 1M for rerank. Voyage token counts come from its responses.
- **[Director's call]** Record each lookup's Voyage usage as the existing `llm_runs` row (`pipeline = rag_lookup`, `role = retriever`), with the Voyage model names. The budget code and the admin's cost views then keep working. The builder confirms this fits the frozen `llm_runs` contract, or proposes the smallest change that does.

- **Approval-time embeddings [Director's call, planning 03/11]** (`knowledge_embed`) are not written to `llm_runs`: about 300 tokens per approval, under $0.01 for the whole lab. Their tokens are logged. The lookup's calls, which are the bulk, are counted.

**`RAG_MODEL`** keeps its meaning for drafts only.

**Dependencies.** Call Voyage's REST API with `httpx`, which the `openai` SDK already brings in, or with the `voyageai` SDK. Builder's call; no heavy dependency.

### 5.7 Deployment (the Owner runs the infrastructure)

**On the trial first.** The Owner runs these steps from command blocks the Director supplies:
1. Set the new `.env` keys.
2. Run `docker compose up -d`: it creates `vectordb` and recreates `rag-worker`.
3. Create the vector schema.
4. Run the rebuild command.
5. Check it.

**Trial only [Owner, 03/11: "Ko merge vào main mà chỉ chạy trên trial"].**
- The build branch is never merged into `main`, and live is never deployed with it.
- Live stays at `main` `af56b13`.

## 6. Part C — the lab measurement

- **The test set.** Alerts from attack runs that were **not** used to build the knowledge base [Owner], of the same scenarios.
- **Ground truth: labelled by hand on an admin page [Owner, 03/11].** A new admin page, *"Gán nhãn lab"*, carries it. The details below are the [Director's call]:
  - **Lab runs.** An admin records each lab run: a name, a start and end time, and its purpose (`kb`, building the knowledge base, or `test`, being scored). An alert belongs to a run when it was received inside the run's window. That is how "which attack run" is known.
  - **Labels.** The page lists a run's alerts. The admin marks each one **TP** (a real attack) or **FP** (not an attack). An unlabelled alert is not scored and is counted as such.
  - **Blind.** The page shows the alert and not ①'s output, through `tier1.visibility.strip(..., mode="labeling")` as the existing labelling page does, so the label is not biased by the AI.
  - **Storage.** Two new tables in the main database: `lab_runs` and `lab_labels` (alert id, run, label, who, when). Recording a label is an audited admin action.
  - **A case's truth.** A case is a real attack when any of its alerts is labelled TP.
  - **Not reused:** the existing blind labelling page (P6-T02, `/api/admin/labels`). It serves the G1/G2 gold sets from `eval/` CSV files. The new page follows its pattern but not its data.
- **The tool.**
  - It runs ① over every test alert twice, RAG off and RAG on, and ② over every test case twice.
  - It reuses the compute-only paths that already exist: `tier1.triage.evaluate_alert(..., switches=EvalSwitches(rag=…))`, which writes nothing, and its ② counterpart (see `eval/investigate_measure.py`).
  - **Which lookup.** For the RAG-on run, the tool uses the lookup each subject got **when it arrived**, which `evaluate_alert` already reads.
    - That lookup could only see entries approved before the subject arrived, so later approvals cannot leak into it.
    - A subject with no usable lookup is counted under "failed lookups" and scored without RAG. It is not looked up again.
    - *(Refined from "a fresh lookup" while planning, 03/11.)*
  - **[Director's call]** The tool is a new file. It does not modify `eval/`'s existing files, which P13 kept off-limits; the Owner may say otherwise.
- **The report, per tier and per run (off/on):**
  - accuracy of the **model's own conclusion** against ground truth, with TP recall and precision;
  - how often the gate or override held, split into "the model was wrong and the gate held it" and "the model was right and the gate held it anyway";
  - RAG coverage: how many subjects had a match at or above `RAG_MIN_SCORE`, and the mean percentage;
  - **a leak check:** for each test subject, whether any matched entry was sourced from the same attack run. Any such row is flagged, not silently counted;
  - **failed lookups:** how many lookups failed (a 429 or any other error), since a failed lookup is scored as "RAG on" with no RAG in it.
- **Calibration.** The same tool, run on a held-out slice of the KB runs, is where `RAG_MIN_SCORE`, the two level thresholds and `rerank-2.5` vs `rerank-3` are chosen. It must not be the test set.
- **A frozen knowledge base [Director's call].** The tool takes a KB cut-off time. An entry approved after it is flagged like a leak.
  - This covers test-run alerts that analysts conclude and an admin approves *while* the measurement is still being made.
  - In practice: do not approve drafts from test runs until the measurement is done.
- **Scoring ②'s three answers [Director's call].** `confirmed_incident` counts as "a real attack". `false_positive` and `policy_violation` both count as "not an attack". The UI's own label for `policy_violation` reads *"Có vi phạm nội quy, không phải tấn công"*.
- **Which cases ② is scored on [Director's call].** ② is scored over the cases that exist for the test runs: those escalated by analysts in the normal flow. An alert that is never escalated has no ② score; it is scored at ① only.

## 7. Standing constraints

- **The webhook contract is unchanged:** 201 / 409 / 400 / 401 / 403 / 413, and DEC-211's 503.
- **No old data is deleted.** Old `rag_results`, `llm_runs` and entries stay.
- **No secret, password, DSN or API key is printed.**
- **The Owner is asked first** before anything irreversible (dropping a column or table, a database reset).
- **Infrastructure, container and database writes on live or trial are Owner-run.** The Director hands over command blocks.
- **Build process:** a Coder subagent (Sonnet 5.5, xhigh, own worktree) and an independent Reviewer subagent for every card. The Director manages, merges into the build branch and re-checks (DEC-201).
- **Never merged into `main`, never on live** [Owner, 03/11]. The trial is the only stack that runs this build.

## 8. Risks the Owner should know before reading the numbers

1. **The FP side may improve less than the TP side.** DEC-210 says a RAG match cannot be the basis of an FP the gate keeps, and gate step 4's FP policy is unchanged. When the lab's benign alerts sit on high-value or unknown assets, the gate holds an FP however well the RAG matches.
   - The model's *own* conclusion is still scored (A, G2), so this shows up as "held", not as "wrong".
   - Even so, if the RAG-on number falls short of 80–90 %, look here first.
2. **50–100 entries in total is small.** With few entries per scenario, one wrong approved entry shifts results a lot. Admin review is the only filter, as in DEC-210.
3. **Same scenarios across runs** makes matching easy by design. That is the claim being tested. The leak check keeps it honest about *runs*.
   - **The Owner chose not to include an unseen scenario in the test set** (03/11). How the system does on an attack it has never seen is therefore not measured.
   - The thesis should state this as a limitation. Our expectation, not a measurement, is that it behaves as with the RAG off.
4. **Free-tier rate limits** (5.5) may fail lookups during a burst. The report counts them, so they are visible rather than hidden in the score.

## 9. Left to the builder

- Card breakdown, file layout and test plan.
- How the `vectordb` schema is created and migrated.
- HNSW or exact scan.
- `httpx` or the `voyageai` SDK.
- The exact Vietnamese wording of the two prompts and the UI strings. The Owner reads them in review.
- The provisional thresholds before calibration.
- The full list of `suggested_action` / `suggested_conclusion` readers, and confirmation that each still works (4.4).
- The runbook section for `vectordb` and the rebuild.

## 10. The Owner's answers (03/11) and what is still open

**Answered:**
- **Ground truth:** labelled by hand on an admin page (section 6).
- **Voyage account:** the free tier (5.5).
- **An unseen scenario in the test set:** no (section 8).
- **The rename of ①'s `escalate`:** allowed, "cho phép đổi luôn" (4.1).
- **A Voyage failure:** the RAG is off for that alert, with a notice, and there is no fallback to the LLM ranker (5.3).
- **Everything else:** approved as written.
- **After the plan (03/11):**
  - no compatibility with old `escalate` data, because the database is wiped (4.1);
  - never merged into `main`, trial only (5.7).

**Still open, not blocking the plan:**
- The free tier's actual rate limits, read on the Voyage dashboard before the lab run.
- Existing `eval/` files are not touched, except the one line the rename needs (4.1).

## 11. Wiping the trial database for the lab [Owner, 03/11]

- **Which database:** the **trial** stack's (`soc-trial`, `127.0.0.1:55433`, `soc_dev`) only. Live is not touched.
- **How much:** **all of it** [Owner]. The database is dropped and recreated from the migrations of the trial checkout.
  - The 7 accounts are recreated with the same usernames, roles and display names. The Owner types the passwords again.
  - Everything else goes: alerts, cases, jobs, `llm_runs`, audit events, the 112 gold labels, the 9 eval runs, and the knowledge entries and drafts.
  - Live still holds the 112 gold labels and the 9 eval runs, and the backup holds everything.
- **When:** **now, 03/11, before the build** [Owner]. This also stops the trial's backlog of about 212 000 alerts that were being triaged by GLM.
- **How:** an Owner-run script, handed over in the conversation of 03/11, in this order:
  1. Guards that refuse anything but the trial.
  2. A backup with the server's own `pg_dump` 16, read back before anything is touched.
  3. A typed confirmation.
  4. Stop `app`, `worker` and `rag-worker`.
  5. `DROP DATABASE … WITH (FORCE)`, then `CREATE DATABASE`.
  6. `make migrate`.
  7. Rename `kb_learned/entries` aside (nothing deleted).
  8. Restart.
  9. `seed-users`.
  10. Checks.
- **For the build:**
  - The trial checkout is at `0d1e40c` (20 migrations). Main is `af56b13` (21, DEC-212's `archived`).
  - The build branches from `main` `af56b13` and is never merged back.
  - The trial is moved to the build's tip, and its migrations applied, when A/B/C are deployed. Migration 022 needs the wipe to have happened (4.1). If anything wrote `escalate` between the wipe and the deploy, the wipe is run again first.
  - Lab runs start only after that. Anything received before is outside every lab run's window, so it is never lab data.
- **Before the first lab run:** n8n's webhook is pointed at the trial (`:8001`).
