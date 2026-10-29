# INT-T01 report (Coder hand-back, verbatim)

STATUS: DONE_WITH_CONCERNS
Branch worktree-agent-a767d9aab94241efd, tip 28ff21b. Worktree: /project/project/AI_Support_SOC_1_2/.claude/worktrees/agent-a767d9aab94241efd. Clean tree, no push, STATE.md untouched. Private PG stopped and its data dir removed.
Commits above 923c6b2 (my five on top of the soar-followup history):
436ae92 merge, b52bf40 DEC-211, d22b397 402, 1dfedda ① both features, 28ff21b rag_lookup_id. All carry the Co-Authored-By trailer.

1. CONFLICTS (all keep both sides)
- llm/triage.py: _render_proposer and build_proposer_prompt take include_siem_context and learned; the call site passes both; the docstring has one paragraph per parameter.
- wrap.py and test_wrap.py: BLOCK_SOURCES is the union (10 names). The test is test_block_sources_match_ten_names with an accurate docstring; the comment names both additions.
- DECISIONS.md: both entries kept, P13's DEC-210 first.
- runbook.md: both sections kept. "The 74 keys" became "The 76 keys". `.env.example` has 76 KEY= lines (70 are §6.3 keys, 6 compose-only); test_runbook_env_keys pins the sentence to its 76 rows.
- Health-check count: your premise is wrong. `triage_unavailable` was already on main (10 checks on main and on soar-followup). Merged health.py has 13 (10 plus P13's 3), and the runbook already said "thirteen". Its Alarms table has 13 rows, so no edit. "All ten checks ok" in the runbook is a dated 29/09 observation and stays.
- Auto-merged files (.env.example, config.py, health.py, builder.py, tier1/triage.py, test_health.py, 00-context-pack.md, strings.ts) merged correctly. `make lint` passes, and the full suites passed at the bare merge commit (see 3).

2. RULINGS
- R2 (1dfedda): new test_triage_prompt_rag_siem.py, 9 tests.
  - With both on, block order is rule_description, wazuh_raw_log, context, siem_context, correlation_samples, kb_playbook, decision_history, kb_learned.
  - Removing the learned section leaves soar-followup's message byte for byte. Removing the siem block leaves P13's. With both off it equals main's GOLDEN_USER.
  - The budget cuts entries, then history, then the old steps. S2 has no budget cut, so its block is whole and no cut warning names siem.
  - Every existing golden passed unchanged; I changed no fixture.
- R3 (b52bf40): heading and the 9 soar-added references became DEC-211: adapter docstring, 2 comments in soar/pipeline.py, 3 test docstrings, 2 runbook lines. P13's 187 DEC-210 references are unchanged (same count as director/rag-knowledge). No test pinned the strings. DEC-211 follows DEC-210 and its date stays 2026-10-27.
- R4 (d22b397): `class LLMUnavailable(LLMPermanent)`. R4 is appended verbatim to DEC-211. test_402_is_unavailable_a_kind_of_permanent asserts issubclass.
  - Tests added: (a) ② gives stopped_by='permanent'. (b) The lookup stores a failed row recorded permanent, with rag_lookup_id and the event. (c1) Draft call: empty draft, warning llm_permanent, and publish.redraft takes it. (c2) Rank call plus draft call: warnings [rank_unavailable, llm_permanent], both runs permanent, redraft accepted.
  - ① check: tier1/triage.py catches only LLMBudgetExceeded, LLMUnavailable and TransientError (lines ~760/762 proposer, ~807/816 verifier). llm/triage.py propose/verify catch nothing. `LLMPermanent` appears nowhere in tier1. Existing ① 402 tests pass unchanged.
  - Other LLMPermanent catchers: tier2/investigate.py, rag/lookup.py, rag/draft.py (x2), and eval/investigate_measure.py:566.
- R5 (28ff21b): the only real defect I found. S8's two `unavailable` rows (proposer 402, verifier 402) were written on a branch that never saw P13's rag_lookup_id column, so they left it out. Both now pass rag_lookup_id=ev.rag_lookup_id. Two db tests added in test_triage_rag.py. After a verifier 402 the proposer row carries the id and the verifier row does not, which is P13's rule.
- R5 checked and fine, no change:
  - V3 vs S5: V3 never listed owner or role. They already rendered in the `context` block from the inventory on main, and rag/ reads no asset_context. No new exposure.
  - S0 intake: webhook goes through finish_enrichment to _enqueue_triage, with P13's delay, unchanged.
  - Block sources, health, keys and strings counts: pinned by tests that pass.
  - Admin knowledge source.alert now carries view["soar"] (S3). Admin-only, same JSON as the analyst route, unredacted next to the redacted source.enrichment. I left it.

3. TESTS (PY=/project/project/AI_Support_SOC_1_2/.venv/bin/python)
- make lint: pass. gen_env_example (70 §6.3 keys), schema, output schemas, ruff, black (286 files).
- make test: 4745 passed, 20 skipped, 3206 deselected, 2 xfailed. At the bare merge commit it was 4736 passed.
- make test-db (private PG 16.2, TCP 127.0.0.1, trust auth, port 48128): 3203 passed, 2 failed. The 2 are the baseline libxml tests: test_restore_refuses_a_non_empty_target_without_force and test_round_trip_restores_into_a_second_database. At the bare merge commit it was 3197 passed and the same 2.
- make ui-lint: eslint, tsc and prettier pass; npm audit reports 0 vulnerabilities.
- make ui-test: 65 files, 3154 tests passed.
- make ui-build: ok.
- make ui-e2e: 25 passed on the private PG (via PGHOST/PGPORT/PGUSER). The scan found no secret.
- node_modules: cmp showed package-lock.json and package.json identical to admin-v1-1. The symlink is removed, and so are dist/ and test-results/.

4. GUARDS SHOWN RED
- Tests first, before the fix, same tree, nothing weakened:
  - 402 tests: ② 'linter' == 'permanent' failed; lookup recorded 'linter'; draft ['linter'] vs ['llm_permanent']; rank plus draft ['rank_unavailable','linter']; the adapter issubclass assertion failed.
  - rag_lookup_id: both tests failed with None where the lookup id was expected.
- Scratch copies under /tmp/int-t01-scratch (unique names, deleted afterwards; the real llm/triage.py compared byte-identical to the original):
  - Dropping `learned=` at the call site failed 4 prompt tests.
  - Moving the learned section before the playbook, and the siem block after the correlation, failed the placement test.
  - Moving the learned cut steps after the old steps failed the budget-order test.
  - Dropping "siem_context" from wrap.py failed test_block_sources_match_ten_names.

5. DEVIATIONS
- The merge commit holds only the 5 resolutions plus the runbook key count. The DEC-211 rename is the next commit (R3), so the merge commit itself still has two DEC-210 headings.
- The health-check count needed no change (see 1).

6. CONCERNS
- backend/app/rag/tags.yaml has no behaviour tag for S1's new category `credential_access`. P13's test_every_category_of_the_resolver_has_a_behaviour_tag uses a hard-coded list, so it cannot catch this. A draft for such an alert gets no matching behaviour tag. Adding a tag is a closed-vocabulary decision, so I did not do it. The vocabulary has 23 tags against a 15 to 25 limit.
- eval/investigate_measure.py:566 catches LLMPermanent, so a 402 there is now recorded stopped_by="permanent_error" instead of "error". I did not touch eval/.
- ②'s UI label for `permanent` reads "model refused the request, not retryable" for a no-balance 402. That is a consequence of R4.
- DEC-211's own text says "count now 68" (item 7) and calls S8 "report only, no code" (item 9). I left both as written. The merged runbook count is 76, and S8 is in fact code.
- P13's existing test test_an_out_of_balance_account_402_is_stored_empty_at_once_and_can_be_redrafted_after_a_top_up spells a 402 as a plain LLMPermanent. It still passes; the new tests use the real LLMUnavailable.

## Director's merge check (29/10)
Mutations on a detached copy of 28ff21b, against a private PG 16.2 (127.0.0.1:48231); each restored after its run:
1. `class LLMUnavailable(PermanentError)` (the parent dropped): 5 red, namely ②'s 402 test, the lookup's 402 test, both draft 402 tests and test_adapter's issubclass test.
2. `"siem_context"` dropped from `BLOCK_SOURCES`: 9 red (test_block_sources_match_ten_names and 8 in test_triage_prompt_rag_siem.py).
3. `learned=material` dropped at the ① call site in `tier1/triage.py`: 19 red in test_triage_rag.py (db). The non-DB suite does not catch this one; `make test-db` does.

## Fix round 1 (Coder, dd00af2) and the Director's check (29/10)
The Coder's fix round, on top of 6e83124, one commit per finding:
- F4 debcb9b
- F2 d54f03a
- F3 8818aef
- F5 fa2ad0f
- F6 5be4a2c
- F1 4899e9e
- F7 and R5 9d2e286
- dd00af2, the type test's anchor after F5

The re-review (APPROVE, 1 Minor + 2 Nits) is appended to INT-T01.review.md.

The Director's check:
4. The asset owner dropped from V3's names for an alert (`conn, [alert_user], [facts…` in `rag/draft.py:379`): 3 red in test_rag_draft.py (db).
- `make test-db` on dd00af2 against a private PG 16.2 (127.0.0.1:48231): 3209 passed and 2 failed. The two failures are the baseline libxml tests in test_backup_restore.py, the same as at 28ff21b.

Rulings on the re-review:
- **R1** (an owner that is a short team name, such as "IT", "SOC" or "Kế toán", refuses that word in drafts): accepted for now.
  - It fails safe: nothing leaks, and a draft is reworded or rejected.
  - Whether a team owner may appear in a learned entry is a policy question for the Owner. If the answer is yes, the follow-up is a stricter rule for owners only (login-shaped, or at least 4 characters, or a team-word stop list), and the `IT` assertion is pinned again to match.
- **R2** (the admin table label is long) and **R3** (two parentheses in DEC-211 item 7): left as they are.
