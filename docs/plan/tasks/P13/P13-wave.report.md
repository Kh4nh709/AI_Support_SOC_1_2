# P13 whole-branch fix wave: implementer's report

The implementer returned this report as text, and the Director saved it.

**Status:** DONE_WITH_CONCERNS.
- **Branch:** `worktree-agent-ad473e5e96c773f0d`, tip `4665cee`.
- **Commits:** 24, on top of `f870c54`.
- Nothing under `eval/` changed.

## 1. Items

| Item | Commit | What changed |
|---|---|---|
| 1 + 19 | `8a36a9d` | V4 rule `v4_structure:<field>` (`FAULT_VOCABULARY`, the draft template, `strings.ts`), applied after `strip_invisible` and NFKC. `llm.builder.prompt_entries` drops a forged entry, for ① and ②. A fully rendered entry never trips the rule. |
| 2 | `b0eeadf` | New reference sentence, in the user message only. The schemas and templates are frozen. |
| 3 | `0442f3f` | The delay is pinned by its `scheduled_at` SQL text. |
| 4 | `29ea6dc` | N1 docstrings; N3 closed history keys (`key_name` checked); N4 note. |
| 5 | `68e650a` | `knowledge_integrity` counts active entries only. |
| 6 | `4603006` | `rebuild` writes the canonical path only, skips per entry (including on `OSError`), and exits 1 if it skipped anything. |
| 7 | `b965b40` | A non-UUID case source id gives no case, and no 500. |
| 8 | `d6769a3` | `_bullets` escapes a leading `#`. |
| 9 | `f89ec95` | Adds U+1D159; Cf samples U+0600 and U+13430. |
| 10 | `18d50fc` | `db-restore` stops `rag-worker` (see deviation 1). |
| 11 | `4665cee` | Runbook: `:15`, "thirteen", the no-RAG-model delay note. |
| 12 | `109ab5a` | 020's `rag_lookup_id` comment; `schema.sql` regenerated. No migration checksum test exists. |
| 13 | `0994997` | `SAFE_ID` refuses `.` and `..`. |
| 14 | `efd162f` | `latest_lookup(statuses=)`; ② uses `USABLE_STATUSES`; a newest `failed` or `budget` row counts as stale. |
| 15 | `e6e2445` | The autouse fixture asks for the DB only for `db` tests. New DB-free pins. |
| 16 + 18 | `3587511` | `LearnedLike` and `MAX_LEARNED_ENTRIES` move to `llm/builder.py`, plus `prompt_entries`. ① raises `TypeError` on a bad level. |
| 17 | `cf91fa9` | "Ten blocks" (see deviation 2). |
| 20 | `5d13c92`, `efc9008`, `bc67b32` | Details below. |
| 21 | `6ac1894` | A lookup is skipped when `triage_status` is no longer `pending`; `run_forever(claim_order=)` with `CLAIM_ORDER = [[rag_lookup], [knowledge_draft]]`. |
| 22 | `2091d0e` | `literal_findings(users=)`; the record carries `alert_user` plus the identities its texts name. |
| 23 | `a071629` | `lookup_material()` runs in a savepoint, with a `None` fallback, only on the switch-on branch. |
| 24, 25, 26, 28, 29 | `4665cee` | The drain with its count query; restart after any merge under `backend/app`; the README; the list of what breaks on 019; limitation (xlix). |
| 27 | `109ab5a` | `rag_results` is append-only: UPDATE, DELETE and TRUNCATE are revoked. |

**Item 20 in detail:**
- **Over budget:** reschedule to next month, on the DB clock. If the settings cannot be read, back off instead.
- **429** at rank or draft: back off 15 min × attempt, at most 6 times.
- **Any other 4xx (including 402):** store the draft at once, with no reschedule.
- **Redraft:** a new route and a "Soạn lại" button.
- **Event:** `knowledge.redraft_requested` (36 types now).
- **Grants:** DELETE on `knowledge_drafts`.
- **Runbook:** `:306` updated.
- **Pinned:** a pending job scheduled in the future is not `job_backlog`.

## 2. Tests (scratch PG 16.2)

| Suite | Result |
|---|---|
| lint | clean |
| test | 4527 passed |
| test-db | 3159 passed + 2 libxml |
| ui-lint | clean |
| ui-test | 3109 passed |
| ui-build | built |

## 3. Guards
Every new guard was shown red on a scratch copy. Item 15:
- (a) the block-10 gate → `test_no_database_without_learned_there_is_no_tenth_block` is red;
- (b) the heading constant → `test_the_learned_heading_is_a_dossier_template_constant` is red.

## 4. Deviations
1. Item 10 uses `{ … stop rag-worker || true; }` inside the recipe chain, instead of a leading `-`.
2. `docs/phase-7-tier2.md` has no block count, so it was left alone. The runbook's Tier-2 paragraph was changed instead.
3. When the settings cannot be read, the job backs off and then stores the draft as over budget, rather than waiting until next month.
4. Item 22 only checks the identities that the record's own texts name.
5. Redraft returns 409 `drafts_disabled` while drafting is switched off.
6. Items 15 and 3 needed new DB-free pins.
7. The invisible-character table moved to `app/security/invisible.py`.
8. The rule is named `v4_structure`.

## 5. Concerns
- **On a 402 today (unchanged by this wave):**
  - ① propagates `LLMPermanent`, so the job fails permanently, with no `llm_runs` row, and `triage_status` stays `pending`;
  - ② writes a row with `stopped_by='permanent'`;
  - `rag_lookup` stores a `failed` row.
- **`knowledge_integrity` on a 019 host** fails closed as well (the runbook says so).
- **The rollback drain count** stays above 0 while a draft job waits for next month's budget (the runbook covers this).
- **The reboot wiped the scratchpad.** `pgserver` was rebuilt from PyPI.
- **Clean-up:** the PG is stopped and the symlink removed.
