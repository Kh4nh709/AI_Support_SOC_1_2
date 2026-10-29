VERDICT: APPROVE

# INT-T01 review: `worktree-agent-a767d9aab94241efd` @ 28ff21b

Reviewed in my own detached worktrees: one at 28ff21b, plus one each at ba31def (main), 923c6b2 (P13) and 738722b (soar-followup). I used them to build the ① prompt on every branch and compare the bytes. No branch was edited, committed, merged or pushed. Nothing under `eval/` was touched.

I found no Critical or Important issue. The five conflicts keep both sides. The 402 path ends the designed way in every pipeline. Every ① proposer row carries `rag_lookup_id`. The DEC renumbering is clean. `main` still fast-forwards. There are four Minor findings and three Nits. Each is either inherited from one parent or a place where the code of one side does not yet know about a feature of the other. None of them blocks the merge.

## Findings

### 1. Minor: the ① *system* message is not byte-identical to main's or P13's when `PROMPT_INCLUDE_SIEM_CONTEXT=false`. Only the user message is.
- Where: `backend/app/llm/templates/output_schemas.json:17`, rendered into the system prompt by `backend/app/llm/triage.py:281-284` (`_system_prompt`). The check that misses it is `backend/tests/test_triage_prompt_rag_siem.py:124` (`test_with_both_off_it_is_the_message_main_built`), which compares `.user` only. The commit message of 1dfedda says "RAG off and the flag off = main's".
- What I checked. I built the prompt on each branch with the same fixture (`tests.test_llm_triage._inp/_cfg/_correlation`, the fixed `NONCE`, the real playbook, the SC03 enrichment) and compared the bytes:
  - **User message:** identical in every case the task asks for: main = integration with both off; P13 (learned=OK) = integration with siem off; soar-followup = integration with RAG off (flag on and flag off).
  - **System message:** identical to soar-followup's, but it differs from main's and P13's by `|siem_context` in the `triage_v2` `reasons[].source` enum. That holds whatever the flag says.
- How it fails. The 13 extra bytes add 5 to `estimated_tokens` (2978 on main, 2983 on the integration). So within 5 tokens of `PROMPT_TOTAL_BUDGET_TOKENS`, the integration with both off cuts where main does not. Reproduced with the budget set to 2980: main sends the whole prompt, while the integration (and soar-followup) drops the correlation samples (`correlation_samples_dropped`). The user message then differs from main's.
- Cause: inherited. This is S2's §6.2 contract change (DEC-211 item 4), and soar-followup has it already. The merge did not introduce it, and the merge cannot remove it without changing S2's design.
- Suggested fix: a Director ruling. Either:
  - (a) restate the acceptance criterion as "user message byte-identical; the system message carries DEC-211's enum value; the token estimate is +5", and correct 1dfedda's claim and the test docstring, ideally with an assertion that pins the one-token system diff; or
  - (b) if full identity with the flag off is wanted (a clean "no SIEM context" ablation), render `triage_v2` without `siem_context` when the flag is off. That is an S2 design change, outside INT-T01.

### 2. Minor: `credential_access` (S1) has no behaviour tag in P13's closed tag vocabulary, and the test that should have caught this hardcodes its list
- Where:
  - `backend/app/rag/tags.yaml:11` says the behaviour tags are "the resolver's categories (ingest/category.py)", but there is no tag for credential access.
  - `backend/tests/test_rag_tags.py:42` (`test_every_category_of_the_resolver_has_a_behaviour_tag`) checks a literal set, not `llm.builder.Category`, so it stayed green after S1 added `Category.CREDENTIAL_ACCESS` (`backend/app/llm/builder.py:68`).
- How it fails:
  1. An analyst closes a T1003 alert (category `credential_access`) as FP or benign.
  2. The `knowledge_draft` prompt lists only the vocabulary (`draft_system.txt:40-42`).
  3. The draft gets at best target tags (`windows_host`, `privileged_account`) and no behaviour tag. If the model writes `credential_access` or `credential_dumping`, V1 answers `v1_tags:unknown_tag`, which costs a retry or leaves a faulted draft for the admin.
  - Retrieval still works, because `rag/candidates.py` matches on category, MITRE and scenario overlap. So the cost is draft quality and admin work, not a wrong verdict.
- Suggested fix:
  - Add `credential_access: Credentials read from memory or the OS store, such as LSASS dumping (T1003).` to `tags.yaml`. That makes 24 tags, inside the test's 15–25 bound. `tags.yaml` is Owner-reviewed code, so this is the Owner's or Director's call.
  - Make the test derive the categories from `Category` (minus `unknown`) through an explicit category→tag map, so the next new category turns it red.

### 3. Minor: S8's "switch provider" instructions do not know about `rag-worker` (or `RAG_MODEL`), and they describe only ①'s 402 outcome
- Where: `docs/runbook.md:447` (the **Model API down** row ends "then `docker compose up -d --force-recreate worker`") and `README.md:79` ("Sau khi đổi: `docker compose up -d --force-recreate worker app`"), with `README.md:81`.
- How it fails:
  1. After a 402, the Owner follows S8's text, changes `LLM_BASE_URL` / `LLM_API_KEY` / the models in `.env`, and recreates `worker` (and `app`).
  2. `rag-worker` (`docker-compose.rag.yml`, `env_file: .env`, read when the container is created) keeps the old provider.
  3. Every lookup is then stored `failed` (run `permanent`), and every draft is an empty `llm_permanent` draft, until someone recreates it.
  - If `RAG_MODEL` was set explicitly rather than left empty, it also still names the old provider's model.
  - After R4, a 402 also gives ② `stopped_by='permanent'`, failed lookups, and empty `llm_permanent` drafts that need "Soạn lại" once the balance is back. Neither text says so.
  - P13's own generic rows already name `rag-worker`. This row was written on a branch that never saw it.
- Suggested fix:
  - Make both commands "`docker compose up -d --force-recreate worker` (and `rag-worker` when the second compose file is in use; change `RAG_MODEL` too if it is not empty)".
  - Add one sentence on the 402 outcomes for ② and the RAG, and on re-drafting the empty drafts with **Soạn lại**.

### 4. Minor: V3 does not refuse the asset *owner* that S5 now puts in ①'s `context` block for SOAR alerts, so it can reach an approvable learned entry
- Where:
  - `backend/app/rag/draft.py:332-366` and `:390-411`: `_alert_source` / `_case_source` give V3 only `hostnames` and `usernames` (the alert user, plus inventory identities the texts name).
  - `backend/app/llm/triage.py:369-373` renders `owner=… role=…` inside the `context` block.
  - `backend/app/soar/pipeline.py:302` (S5) fills it from `enrichment.asset.owner`.
- How it fails:
  1. SOAR sends `enrichment.asset.in_inventory=true, owner="nguyen.van.a"` (or a person's full name). The asset lookup is `found`, so ①'s context line carries `owner=nguyen.van.a`.
  2. ① cites that line in a reason (`source: context`), and the analyst closes the alert as FP.
  3. The draft job puts ①'s result JSON into `ai_texts`, and the model writes "máy của nguyen.van.a…" into `summary`.
  4. V3's checks (IPs, emails, `DOMAIN\user`, hostnames, `usernames`) do not match a bare owner. In SOAR mode `identities` is unused, so no identity names it.
  5. The draft passes V1–V5, and an admin can approve an entry carrying a person's name. That entry then goes into the prompts of other alerts.
  - Before the merge, in SOAR mode (`ENRICHMENT_ENABLED=false`), ①'s prompt held no owner at all, because DEC-208's context has none. With `ENRICHMENT_ENABLED=true`, the inventory owner already had the same gap in P13, so this is pre-existing but widened by S5.
  - Admin approval remains the backstop.
- Suggested fix: add the record's asset owner(s) to the names V3 refuses (`alerts.asset_context->>'owner'` for an alert, and the heads' owners for a case), either in `usernames` or in a new set, with a test. Or the Director rules that owner text is acceptable in learned entries. `role` reads as a generalisation, so it can stay.

### 5. Nit: on `/admin/knowledge`, `source.enrichment` is redacted, but `source.alert.soar` (S3) shows the same enrichment unredacted
- Where: `backend/app/web/routers/admin_knowledge.py:321-341` (`_enrichment` → `_safe`; `_alert_source` → `queue.get_alert_view`) and `backend/app/tier1/queue.py:657`.
- Scenario: a TI value `http://u:p@host/x` shows as `[đã ẩn]` in the enrichment panel and in clear under `alert.soar.ti[].value`. No new audience sees it: the analyst page shows the same, and `alert.raw_log` was never redacted. The module docstring's promise is just no longer the whole story.
- Suggested fix: pass `alert["soar"]` through `_safe` in `_alert_source`, or say in the docstring that the alert view is the analyst's, unredacted.

### 6. Nit: `stopped_by='unavailable'` has no label (inherited from soar-followup)
- Where: `frontend/src/strings.ts:196` (`tier1 … stoppedBy`) and `:1055` (admin LLM `stopped`). The admin LLM page shows the raw code `unavailable`.
- Suggested fix: add `unavailable: "nhà cung cấp LLM từ chối (hết số dư / hạn mức, 402)"` to both maps.

### 7. Nit: DEC-211 wording after the integration
- `docs/plan/DECISIONS.md:3572` (item 7) still says the runbook key count is "now 68"; the runbook correctly says 76. An appended "(76 with DEC-210's eight)" would stop a reader tripping on it.
- The §6.3 lines for `PROMPT_INCLUDE_SIEM_CONTEXT` and `WEBHOOK_SOURCE_MAX_AGE_H` (`docs/plan/00-context-pack.md:112,115`, mirrored in `.env.example`) cite "S2" and "S7" without a DEC number, while P13's lines cite DEC-210. This is optional, because `.env.example` must then be regenerated.

## Checked and fine

**Conflict resolution** (`git show --remerge-diff 436ae92`). All five files keep both sides:
- `llm/triage.py`: `learned` and `include_siem_context` both kept, the docstring paragraphs merged, and the call site passes both.
- `wrap.BLOCK_SOURCES`: the ten-name union, pinned by `test_block_sources_match_ten_names`.
- `DECISIONS.md`: both entries kept, in date order.
- `runbook.md`: both texts kept, with a key count of 76.

**① prompt block order**: `rule_description, wazuh_raw_log, context, siem_context, correlation_samples, kb_playbook, decision_history, kb_learned`, then the request.
- `output_guard.REASON_SOURCES` gains only `siem_context`, so learned text is never a reason source.
- The budget cuts the learned section first, entries then history. `siem_context` is bounded only by its own 8 KB cap, which against the 40k budget is fine and as designed.
- User-message byte identity holds across branches in all three directions (finding 1 covers the system message).

**`LLMUnavailable(LLMPermanent)`**: every catch site checked.
- **① (`tier1/triage.py`):** catches `LLMUnavailable` before anything else at the proposer (:762) and the verifier (:816). Nothing on ①'s path catches `LLMPermanent`.
- **② (`tier2/investigate.py:517`):** now `permanent`. It was `linter` on soar-followup, which was a real bug there.
- **RAG lookup (`rag/lookup.py:411`):** `failed` + `permanent`, with `rag_lookup_id` set.
- **Knowledge draft (`rag/draft.py:1089/1206`):**
  - the rank call records `permanent` + `rank_unavailable`;
  - the draft call gives an empty draft with `llm_permanent`;
  - `_rate_limited` does not mistake a 402 (via `__cause__`) for a 429;
  - `publish.redraft` accepts both warnings.
- **Web routes:** the `PermanentError` catches in `web/main.py:51`, `admin_rules.py:295/315` and `rag/publish.py:392` are not on an LLM path. No route calls the adapter.
- **`eval/`:** `investigate_measure.py:566` now records a 402 as `permanent_error`, which is main's behaviour (soar-followup gave `error`). `run_configs` gets ①'s `unavailable` outcome through `evaluate_alert`, the same as soar-followup.

**`llm_runs` writers**: all of ①'s proposer rows pass `rag_lookup_id`: builder_violation, cap, unavailable, transient, schema, the three verifier-failure proposer rows, and ok. Verifier rows never pass it, which is P13's rule. ②'s `write_row` passes it. The lookup's runs carry their own lookup id, and draft runs carry none (the comment in migration 020).

**soar-followup features vs P13 code**:
- **S0:** the webhook transaction only inserts `intake` and enqueues `pipeline`. P13's lookup enqueue and delayed `triage` enqueue run later in the worker's `pipeline` job, outside the 3 s / 5 s timeouts.
- **S7:** `rag-worker` seeds no chain, claims only `rag_lookup` and `knowledge_draft`, never runs `health` and never touches `source_heartbeat`.
- **S3:** the `soar` key is in `LABELING_DENYLIST`, and `/admin/knowledge` uses analyst mode (see Nit 5).
- **S1:** `credential_access` is a valid `kb_learned/` directory name, and P13's admin UI shows category codes raw (see finding 2 for tags). `MAPPING_VERSION` is not read anywhere outside `ingest/category.py`.

**Counts and docs**:
- `.env.example`: 76 keys (66 on main, +8 P13, +2 S). The runbook keys table has exactly the same 76 keys. `gen_env_example --check` is green (70 §6.3 keys).
- `health.check`: thirteen checks, matching the runbook ("thirteen") and `test_health.py:999`.
- `make lint` is green: env, `schema.sql`, `output_schemas` == §6.2, ruff, black.

**DEC renumbering**:
- Occurrences of `DEC-210`: 187 on P13; 190 on the integration (187 + three new INT-T01 references, all meaning P13).
- Per file, the counts are unchanged except the files those three new references live in. The only P13 lines reworded are the two conflict sites (`wrap.py` comment, `test_wrap` docstring), and both still cite DEC-210 for the learned sources.
- None of soar-followup's 9 `DEC-210` references is left (no variant spellings either). `DEC-211` appears 15 times, each meaning the SOAR follow-up.
- Order in `DECISIONS.md` is DEC-210 (25/10), then DEC-211 (27/10), with R4 appended to DEC-211.

**Fast-forward**: `main` (ba31def) is an ancestor of 28ff21b. The merge parents are 923c6b2 and 738722b, which are the current tips of `director/rag-knowledge` and `director/soar-followup`.

**Suites I ran on 28ff21b** (non-DB only):
- `make test`: 4745 passed, 20 skipped, 3206 deselected.
- `make lint`: green.
- `npm run typecheck`: green.
- `npm test -- --run`: 65 files, 3154 passed.

**Not run by me** (they need a database): the DB tests that prove the behaviour above end to end. These include `test_triage_job`, `test_triage_rag`'s new 402 rows, `test_investigate`'s 402 test, `test_rag_lookup_job`, `test_rag_draft`'s two 402 tests, `test_health`, `test_webhook_concurrency` and the admin-knowledge tests. The Director should have `make test-db` evidence from a scratch test cluster on 28ff21b before merging.

**Process note**: `make test` (the non-DB suite) is not entirely DB-free. 17 tests in `backend/tests/test_investigate.py` that are not marked `db` probe the default `TEST_DATABASE_URL`, which is `127.0.0.1:55432/soc_test`, the live port. Both of my runs found it unreachable and those tests skipped. No database was used.
