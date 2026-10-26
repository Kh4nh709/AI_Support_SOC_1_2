# P13 whole-branch review (`d680f33..f870c54`)

Reviewer: an independent subagent (general-purpose, Opus). The Director committed this review verbatim in substance.

## Verdict: NEEDS FIXES

There is 1 Important finding, and nothing is Critical. End to end the flow holds, poisoning is closed, and the switch-off path is safe. The DB-free suite passes on the tip.

## The end-to-end trace

Every seam checks out (✅):

| Seam | Where |
|---|---|
| Subject keys: written, parsed and read with consistent case | `transitions.py:213,469,623,695`; `subject.py:42-52`; `tier1/triage.py:683`; `tier2/investigate.py:463`; `tier2_runs.py:81` |
| Fingerprint text vs the candidate search: the same `_build`; `simple` on both sides | `fingerprint.py:222`; `candidates.py:57` |
| `content_sha256` / `file_path` vs `file_matches` | `publish.py:454`; `entries.py:170` |
| Lookup statuses vs `prompt_material` (② is wave item 14) | `lookup.py:447` |
| The draft JSON vs publish: six fields by name, closed fields from the source | — |
| Levels: enum, schema, merge rule and facts agree | — |
| Job types and reclaim: two disjoint handler tables covering all 8 types | `jobs.py:199`; `worker.py:61-64` |
| A5 self-exclusion | — |
| Eval: `DEPLOYED` with `rag=False`; no RAG jobs from the adversarial loader | — |

**Switches off:**
- No new jobs, prompts, INSERTs or transition SQL. The new SQL is only the health reads, the overview section and the admin routes.
- One switch-independent change: ②'s `_repair_line` fix.
- On a 019 host, ① and ② still work. `knowledge_queue` alarms (fail-closed), the overview section shows an error, and `/admin/knowledge` returns a 500. `runbook :98` claims more breaks than that.

**Poisoning:** only `entry.content` (approved, hash re-checked) and the closed history fields reach ① or ②. Notes, drafts, `review_note`, reasons, `match_notes`, the fingerprint and `enrichment` never do. Tags are closed, and A1 holds.

**Permissions:** the admin routes require Admin, and only `app` writes files.

**Concurrency:** all covered.

**Review Focus:** RF1–RF5 are all pinned, mostly by db tests.

## Important

**I1. A draft whose model cannot be asked becomes a permanent, text-less `pending` draft, and the merge rule is skipped.**
- **Where:** `rag/draft.py:946`, `:993`, `:1098`, `:1112`.
- **What happens:**
  - `_exists` makes later jobs no-ops, and no re-draft action exists.
  - The $3 sub-cap is shared with a lookup on every alert, so reaching it is normal, and so is a 429 burst (T03 M7).
  - From then on every conclusion is manual admin work, `knowledge_queue` alarms, and A6/G5 fail.
  - `runbook :306` implies that such drafts get filled later. They do not.
- **Fix:**
  - on `_over_budget`, and on `LLMPermanent` with a 429 cause, `Reschedule` instead of `_store_empty`;
  - an admin "re-draft" for text-less drafts whose warnings are all in {budget, llm_transient, llm_permanent, rank_unavailable};
  - correct the runbook row.

## Minor
1. **A late lookup is still paid for, and lookups wait behind drafts** (`jobs.py:109`). Skip an alert whose `triage_status` is no longer pending, and claim `rag_lookup` before `knowledge_draft`.
2. **V3 does not catch bare user names** (`draft.py:492`). `literal_findings("Tài khoản hr01 …")` returns `[]`. Give V3 the record's `alert_user` values and the `identities` usernames.
3. **The lookup read in ① and ② is not in a savepoint** (`tier1/triage.py:683`, `tier2/investigate.py:463`). Any DB error there fails the job. With the switches on over a restored pre-020 dump, ingestion, decisions and escalations fail too (`ck_jobs_job_type`).
   - Use a savepoint and fall back to None.
   - The runbook should say: switches off before restoring a pre-020 dump.
4. **`job_backlog` alarms forever after a rollback** that removes `rag-worker` while RAG jobs are pending (`runbook :134`). Drain the queue first, with a count query that must return 0.
5. **The restart rule for `rag-worker` is too narrow** (`docker-compose.rag.yml:33`, `runbook :15,108`). It also loads `llm/`, `security/`, `infra/`, `audit/` and `domain/`, so restart it after any merge under `backend/app`.
6. **`kb_learned/README.md`:**
   - `:10` should say `retired/<category>/<id>.md`;
   - `:23` "approve a new version": no versioning path exists, so the only option is to retire the entry.
7. **The ranking agent reads log text an attacker can shape** (`match.py` context). It can steer which entry is shown and at which level, force an auto-merge (which skips the admin and inflates the evidence), or force a conflict. This is a limitation; the "Đã gộp" tab is where merges get audited.
8. **Nits:**
   - `020:148` grants UPDATE on `rag_results`, which nothing uses; make the table append-only;
   - one `app_rw` role serves all three services;
   - `_history_of` does not check `key_name` (this is already wave item 4).

## Wave items to reclassify
- **The adapter's 429 → permanent:** it matters for drafts. Fix it inside `rag/` as part of I1.
- **Two rag-workers:** keep it accepted, and add a second reason. A draft job can make up to six calls and run past `JOB_LOCK_TIMEOUT_S`, so a second worker would reclaim and re-pay it. Nothing prevents `--scale rag-worker=2`.

## What the P13 report must tell the Owner
1. **The rollout order:**
   - migrate 020 and check that the count is 20;
   - create `kb_learned/` with the right owner, set `COMPOSE_FILE`, run `up -d`, rebuild `ui`, restart `worker`;
   - switch drafts on, approve the first entries, then switch RAG on;
   - never switch on while the schema is behind;
   - to roll back: switches off, drain the queue, then remove the override.
2. **What analysts will see:** ① waits 45 s, even when `rag-worker` or the model is down. A late lookup is not used but is still paid for. ② uses the lookup from escalation, refreshed after 24 h.
3. **Spend:** it is unmeasured, and whether $3 lasts a month is unknown. Once the cap is hit, drafts become manual work (I1, until it is fixed).
4. **Measurement:**
   - B4 is not the live deployment;
   - online agreement figures are contaminated, the blind arm included;
   - `prompt_version` does not change, so split runs by `rag_lookup_id` (filtering by `pipeline`) and by the dates the switches changed;
   - the 45 s delay also shifts ①'s correlation window.
5. **The gate is the admin's approval.** V4 is mostly English, V3 misses bare user names (Minor 2), and the ranker can be steered (Minor 7).
6. **SQL only:** no page shows a lookup's matches, its `match_notes`, or which runs used which entries.
7. **Entries cannot be edited, only retired.** After a restore: stop `rag-worker`, run `--rebuild` in `app`, start `rag-worker`. The integrity alarm lasts 24 h.
8. **One switch-independent change:** ②'s repair-line fix.
9. **The accepted limitations from `wave-items.md`.**

## Director's rulings (25/10)
- **Fix in the wave:** items 20–29 in `wave-items.md`:
  - I1, all three parts;
  - Minors 1–6;
  - the nit revoking UPDATE on `rag_results`;
  - the `runbook :98` correction;
  - a limitation for Minor 7;
  - the second reason for "two rag-workers";
  - the single `app_rw` role.
- **The P13 report** carries "What the P13 report must tell the Owner", points 1–9.
# P13 fix wave: scoped re-review (`f870c54..4665cee`)

The re-reviewer was an independent subagent (general-purpose, Opus). The Director committed this re-review verbatim, in substance.

## Verdict: APPROVE

Nothing is Critical or Important. There are 2 Minors and some nits.

**How it was checked:**
- the pure suite at the tip;
- the frontend admin and api tests (2270 passed);
- `tsc` and eslint, both clean;
- item 15's mutations (a) and (b), each red under the DB-free run;
- probes of the regex, V3 and the renderer.

## Items 1–29: all ADDRESSED

| Item | Where |
|---|---|
| 1 | `llm/builder.py:300,315`; `rag/draft.py:221,531`; `strings.ts:1925`. A forged line in the middle of an admin edit is folded by `_tidy`, so it never opens a line. |
| 2 | `builder.py:196`; used only on the switch-on path (`llm/triage.py:448`, `dossier.py:1258`) |
| 3 | `test_transitions_rag_enqueue.py:186` |
| 4 | `lookup.py:176`, `history.py:334` |
| 5 | `health.py:349` |
| 6 | `publish.py:644,723` |
| 7 | `admin_knowledge.py:347` |
| 8 | `entries.py:237` |
| 9 | `security/invisible.py:53` |
| 10 | `Makefile:163` |
| 11 | the runbook rows |
| 12 | `020:28`; no checksum |
| 13 | `KnowledgeEntryView.tsx:49` |
| 14 | `lookup.py:95`, `investigate.py:465`, `tier2_runs.py:93` |
| 15 | (a) and (b) are red |
| 16 + 18 | `builder.py:279,332` |
| 17 | the `dossier.py` docstring, `00-context-pack.md:171`, runbook `:481` |
| 19 | the same regex as item 1 |
| 20 | see below |
| 21 | `lookup.py:317`, `rag_worker.py:29`. `pending` is the correct state; case lookups still run; the main `worker` is unchanged. |
| 22 | `draft.py:309`; `re.escape` is applied to the names |
| 23 | `lookup.py:478`; switch-on only; a savepoint inside REPEATABLE READ |
| 24 | `runbook:134` (see Minor 1) |
| 25 | `compose:33`, runbook `:15`, `:108` |
| 26 | README `:10`, `:22` |
| 27 | `020:159-164`; nothing updates or deletes as `app_rw` |
| 28 | `runbook:98` |
| 29 | `limitations.md:878` |

**Item 20 in detail:**
- **Code:** `draft.py:899,907,931`; the route and button at `admin_knowledge.py:474`, `publish.py:514`, `KnowledgeDraftView.tsx:356`; the event at `020:242`; due jobs only in `health.py:142`.
- **The 402 ruling is met.** A 402 is stored at once as `[llm_permanent]` or `[rank_unavailable, llm_permanent]`. It is redraftable, never rescheduled, and pinned.

**All 8 deviations are accepted.**

**Switch-off byte identity holds.** `prompt_entries(None)` returns `()`. The sentence and the savepoint are on the switch-on path only. No golden or eval fixture changed.

**The regex:**
- It is case-sensitive: "Total:" and "Level:" are not flagged.
- `［1］`, `[１]`, leading invisibles, U+2028 and `\r` are all caught.
- A rendered entry never trips it.
- Residual bypasses (a nit): U+0301 placed before `[1]`, `【1】`, `⁽1⁾`, and `LEVEL:`.

## Minor
1. **The rollback advice in `runbook:134` and `:306` says to raise the cap.** That does not release a draft that is waiting for next month, because its `scheduled_at` is fixed, and with a cap of 0 it reschedules forever. Say "wait for the month to turn", or give the Owner-run `delete from jobs where job_type='knowledge_draft' and status='pending' and scheduled_at > now()`.
2. **V3 false positives** (`draft.py:309`):
   - an `alert_user` such as `SYSTEM`, `root` or `admin` refuses every draft that uses the word;
   - the placeholders in the facts (`<USER>`, `<HOST>`) are matched by identities named `user` or `host`.

   The result is a text-less draft with a V3 warning, which is not redraftable. Fix: take the placeholders out of the haystack, and add a stop-list of built-in accounts.

## Nits
- stale "35" comments in `strings.ts:1099` and `auditSummary.ts:1`;
- the `draft.py:76` docstring.

## Notes for the P13 report
- **Month-start spend:** drafts deferred for budget all come due at 00:00:01 on the 1st.
- **`_attempt`:** it counts budget reschedules too, so a 429 after a redraft may be stored at once.
- **The DELETE grant** on drafts covers all three services; 017's defaults already allowed it on Compose.
- **On a 402, ① fails permanently** for every alert. This predates P13.

## Director's ruling (26/10)
- **APPROVE.**
- **A follow-up to the same wave dispatch, which the Director verifies directly** (the diff is small, docs plus one function):
  - Minor 1;
  - Minor 2, both parts;
  - the nits.
- **The regex residual bypasses go to the limitations.** The admin's review is the gate.
