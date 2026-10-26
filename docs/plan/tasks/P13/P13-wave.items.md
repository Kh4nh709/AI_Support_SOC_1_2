# P13: parked items, triaged by the Director for the whole-branch fix wave (25/10)

The whole-branch reviewer's findings get added to this list. The fix wave is one dispatch, followed by one scoped re-review.

## FIX in the wave

1. **Forged entry numbering, for ① and ② (T07 M3).** Detect a line matching `^\s*\[\d+\]`:
   - **V4:** refuse it in drafts and in an admin's edits, with the fault `v4_numbering:<field>`; add the rule to `FAULT_VOCABULARY`; add a frontend fault text.
   - **At prompt time:** drop an entry whose content contains such a line, as defence in depth, in both ① and ②.
2. **The reasons source (T07 M2).** Amend `SENTENCE_LEARNED_IS_REFERENCE`, which is user message only, so it says the section is never cited as a `source` in `reasons`. Output schemas stay frozen. Keep ① and ② consistent, and keep the eval harness free of RAG.
3. **The delay test (T07 M1).** Assert the `scheduled_at` SQL text, `now() + … * interval '1 second'`.
4. **T07 nits:**
   - N1: the docstrings that say a "stale" lookup gives today's prompt;
   - N3: drop unknown `by_conclusion` keys in `_history_of` / `render_history`;
   - N4: document in the T06 labels that an all-cut lookup has no id.
5. **`knowledge_integrity` (T05 M2).** Count only entries that are still `active`.
6. **`rebuild` (T05 N1).**
   - Require `file_path == entries/<category>/<entry_id>.md`.
   - Skip and warn on an `OSError` per entry.
   - Exit non-zero if anything was skipped.
7. **Draft detail (T05 N3).** A case draft whose `source_id` is not a UUID gives 404 (or nulls), never a 500.
8. **The renderer (T02).** `_bullets` escapes a leading `#` the way `_paragraph` does.
9. **The invisible set (T04).**
   - Add U+1D159 to `EXTRA_INVISIBLE_RANGES`.
   - Add a Cf sample outside DI (U+0600, U+13430), so the category test is pinned on its own.
10. **`db-restore` (T09).** In the Makefile, add `-$(COMPOSE) stop rag-worker` before the drop; the leading `-` tolerates the override being off.
11. **The runbook (T09).**
    - `:15`: the `requirements.txt` clause also rebuilds and recreates `rag-worker`.
    - `:426`: "ten checks" ×2 becomes "thirteen".
    - Add a note: with `RAG_ENABLED` on and no working RAG model, ① is still delayed by `RAG_TRIAGE_DELAY_S`.
12. **The 020 comment (T07).** Fix the comment on `llm_runs.rag_lookup_id` in `docs/Schema/020_learned_knowledge.sql` and regenerate `schema.sql`. 020 is applied nowhere live yet, so editing the comment is safe. Make sure no checksum test breaks.
13. **`SAFE_ID` (T06).** It must not admit `.` or `..` as a whole id.

14. **② reads the newest `ok`/`empty` row (T08 M1).** In addition, `_queue_case_lookup_if_stale` treats a newest `failed`/`budget` row as stale.
15. **DB-free pins skip without a DB (T08 M2).** In `test_investigate_rag.py`, request the autouse cleanup's `_test_database` only for `db`-marked tests, so the DB-free pins run in `make test`. **Acceptance:** under plain `make test` (with no DB), these two mutations go red: (a) the block-10 gate `learned is not None` removed in `dossier.py`; (b) `HEADING_LEARNED` dropped from `DOSSIER_TEMPLATE_CONSTANTS`. Both survive today.
16. **Move the shared contract (T08 N1).** Move `LearnedLike` and `MAX_LEARNED_ENTRIES` to `llm.builder`; ① and ② import them from there.
17. **"Ten blocks" (T08 N4 and T08 concern 3).** Update the `dossier.py` docstring, context pack §7.6 and `docs/phase-7-tier2.md`.
18. **Raise in ① too (T07 N2, consistent with T08).** ① checks `isinstance(level, KbLearnedLevel)` and raises `TypeError`, as ② does.
19. **Item 1 also covers history-key lines.** It refuses lines shaped like history keys, `^\s*(level|key_name|total|by_conclusion|last_seen|examples)\s*:`, in approved text. Item 2's sentence covers both "đóng alert" and "kết luận case".

### From the whole-branch review (`whole-branch-review-r1.md`)
20. **I1: drafts must not end empty when the model cannot be asked.** In `rag/draft.py`:
    - **Over budget:** `Reschedule` the job to the start of next month (DB clock: `date_trunc('month', now()) + interval '1 month'`), instead of `_store_empty`.
    - **A 429 (`LLMPermanent` whose cause has `status_code == 429`):** `Reschedule` with a bounded backoff (for example 15 min × attempt, at most 6 attempts), then store the draft empty as today.
    - **`job_backlog` must not alarm** on a future-scheduled job. Check that it counts only due jobs.
    - **A new admin route, `POST /api/admin/knowledge/drafts/{id}/redraft`:** only for a `pending`, text-less draft whose warnings are all in {budget, llm_transient, llm_permanent, rank_unavailable}, otherwise 409. It deletes or resets the draft row and enqueues `knowledge_draft` for its subject. Audit it with `knowledge.redraft_requested {draft_id}`; if a new event type needs a migration change, add it to 020 (unapplied), along with the audit group, label and summary. Add a "Soạn lại" button on such drafts in `KnowledgeDraftView`.
    - **Correct `runbook :306`.**
21. **Minor 1: lookup priority and late lookups.** `run_lookup_job` skips an alert (no model call; it writes nothing, or a `skipped` result if the schema allows) when `alerts.triage_status` is no longer pending/queued for ①. `rag_worker` claims `rag_lookup` before `knowledge_draft`. Without touching `infra.jobs.claim_job`'s default order for `worker`, call claim first with `[rag_lookup]`, then with `[knowledge_draft]`.
22. **Minor 2: V3 catches bare user names.** Pass the record's `alert_user` values, plus usernames from `identities` for the subject's hosts or users, to `literal_findings`, in the same way hostnames are passed. Test it with "Tài khoản hr01".
23. **Minor 3: a savepoint around the lookup read.** In ① (`tier1/triage.py`) and ② (`tier2/investigate.py`), wrap `latest_lookup` + `prompt_material` in `conn.transaction()` and fall back to `None` on a DB error.
    - Mind ②'s REPEATABLE READ: a savepoint is fine inside it.
    - Runbook: before restoring a pre-020 dump, set both switches to false.
24. **Minor 4: rollback drains the RAG queue.** Add the drain step, with its count query (`job_type in ('rag_lookup','knowledge_draft') and status in ('pending','running')` must be 0), before removing the override. Pin it in `test_runbook_rag.py`.
25. **Minor 5: restart `rag-worker` after any merge under `backend/app`.** Change `docker-compose.rag.yml:33` and `runbook :15`, `:108`.
26. **Minor 6: two fixes in `kb_learned/README.md`.** Line 10 becomes `retired/<category>/<id>.md`. Line 23: no versioning; to change an entry, retire it.
27. **Nit: `rag_results` is append-only.** Revoke UPDATE on it in 020 (unapplied), and regenerate `schema.sql`. Check first that nothing updates it.
28. **`runbook :98`:** list exactly what breaks on a 019 host with the switches off: `knowledge_queue` alarms, the overview knowledge section errors, `/admin/knowledge` returns 500.
29. **`docs/limitations.md` (xlix):**
    - the ranking agent reads log text an attacker can shape; it can steer the match, force a merge or force a conflict, so audit the "Đã gộp" tab;
    - one `rag-worker` only, because of the merge race and because a draft job can outlive `JOB_LOCK_TIMEOUT_S` and be re-paid;
    - one `app_rw` role serves all three services.

## Accept, and record in the P13 report's limitations
- **Two rag-workers:** a merge/draft race (T04 M2). One `rag-worker` is the supported deployment.
- **Integrity events** are duplicated on transient retries (T03 N3, T04 M1). The health check counts distinct entries.
- **The adapter:** a 4xx or 429 gives a permanent failure with no queue retry (T03 M7, inherited).
- **The admin page:**
  - 200 rows per tab;
  - browser Back and the sidebar do not guard a dirty form;
  - the Vietnamese copy awaits the Owner's review;
  - case drafts do not show ①'s head suggestions (that needs a T05 payload change).
- **The injection detector** is English-only, apart from one Vietnamese pattern (already in limitations, xlviii).
- **B4** is not the live deployment once RAG is on (already in xlvii).

## Skip (nits, or lab scale)
- **T01:** the nits.
- **T02:**
  - the collation and index for the level-0 query;
  - M4–M9;
  - the `_ACCOUNT` false positives;
  - the 1000-character read limit.
- **T03:** M4–M6, N1, N2, N4, and the repair suffix.
- **T04:** M3 (plan-mandated) and the nits.
- **T06:** the a11y and copy nits, the e2e seed, and the `SuggestionDetail` double rendering (unreachable).
- **T09:** M8 (cross-check the services named in the runbook).
