# P14 final fix wave — the one scoped re-review (independent Reviewer, opus = claude-opus-5-5, verbatim) — c7d7f62..7fed7ef

### Item Verdicts

1. **A1: `evaluate_alert(as_of=)` bounds ①'s burst count, both correlation queries and the RAG-on lookup, and `None` is unchanged.** ADDRESSED.
   - The parameter is at `backend/app/tier1/triage.py:690-697`. `BURST_COUNT_BEFORE_SQL` at `:288` is the old text plus `AND a.received_at < %s`; the query function is at `:291-300`.
   - With `None`, the old calls and arity are kept (`:734-737`, `:751-754`, `:790-796`).
   - `_learned_before` (`:602`) makes one read, `latest_lookup(before=as_of)`, of the newest row of any status, as ①'s product read does.
   - Correlation side: `backend/app/domain/correlation.py:59,62,109-116,119,142,188`.
   - **Risk 1 check:** I dumped every module-level string constant of the 11 touched modules, plus the None-path statements and parameters (`rows_query`, `samples_query`, `cluster_ids_query`, `burst_count_query`), at c7d7f62 and at 7fed7ef.
     - No existing value changed. There are only additions, plus `_SECRET_FIELDS`.
     - `run_triage_job` still calls `evaluate_alert` without `as_of` (`triage.py:965`).
     - No template or golden file is in the diff.
   - **Risk 2 check:** I printed the bounded statements. `received_at < %(as_of)s` follows the status predicate. The window's OR is parenthesised, so the bound excludes exactly the alerts with `received_at >= as_of`. In the lab tool's decision SQL, the unqualified `received_at` resolves to `alerts n` only.

2. **A2: ②'s block 5 is bounded the same way.** ADDRESSED.
   - `backend/app/tier2/dossier.py:458-498`, `:605-625`, `:1428-1434`.
   - `_CORRELATION_ROWS_SQL` and `_CORRELATION_SAMPLES_SQL` are identical to c7d7f62 (same compare as item 1).

3. **A3: ①'s `as_of` is the first ① proposer run, else `received_at + RAG_TRIAGE_DELAY_S`; the source is recorded and counted.** ADDRESSED.
   - `eval/lab_measure.py:720-747` takes `min(created_at)` over pipeline `triage`, role `proposer`, with the fallback. It is used at `:1151`, `:1158`, `:1164` and `:1761`; the counts are at `:1771-1775` and the Markdown line at `:1519-1527`. Rows carry it at `:335-336` and `:359-362`.
   - `llm_runs.created_at` is `DEFAULT now()`, and every ① row is written with `role="proposer"` (`tier1/triage.py:968-985`).
   - Check: the burst lab's JSON has `as_of_sources {first_look: 1, delay: 2}`; its Markdown says "1 by the first ① proposer run…, 2 by received_at + RAG_TRIAGE_DELAY_S (45 s)".

4. **A4: the tests (with and without `as_of`, the scratch-lab first-look burst, red first).** ADDRESSED.
   - `backend/tests/test_received_bound_as_of.py` holds 12 tests.
   - `backend/tests/test_lab_measure_wave.py:189` shows the burst at 1/2/3; `:213` shows B1's later lookup as "none".
   - Red logs: `scratchpad/wave/c1_red.log` and `b_red.log`.
   - **Risk 2 check (would the tests fail on the old code):** I ran seven mutations that accept `as_of` but ignore the bound, on an exported 7fed7ef. Each ran against test_received_bound_as_of, test_lab_measure_wave and test_lab_measure on my own throwaway PG 16.2.

     | Mutation | Tests red |
     |---|---|
     | correlation bound dropped | 4 |
     | burst bound dropped | 4 |
     | block-5 bound dropped | 3 |
     | `_learned_before` without `before` | 4 |
     | lab count with `received_before=None` | 1 (the moved pin) |
     | `seen_for(before=None)` | 1 |
     | `run_alert` passing `as_of=None` | 2 |

     Unmutated, those three files plus test_health give 186 passed.
   - **Risk 3 check, the `{t2}` pin against the seed** (`test_lab_measure.py:842-1000`): t1 and t2 share an agent, and so do t3 and t5.
     - t1 (received 6.5 h, first look 6.6 h + 1 min): t2 was received at 7.0 h, after it, so it is out.
     - t2 (received 7.0 h, first look 7.1 h + 1 min): t1 was received at 6.5 h and escalated at 8.8 h, after the first look, so it is counted.
     - t3 (first look 7.6 h + 1 min): t5 was received at 8.5 h, so it is out.
     - t4 has no neighbour.
     - ②'s `{c2}` is unchanged: t5 was received before 8.8 h and escalated at 9.6 h.
     - The `received_before=None` mutation turns exactly this pin red, so the move comes from the ruled bound. The seed's first-look rows (`:969`) keep the lookups before `as_of`; only one assertion in the file moved.

5. **A5: the wording (CAVEAT and header, item 50, runbook Measuring, (li).3).** ADDRESSED.
   - The CAVEAT at `eval/lab_measure.py:164-172` is one sentence covering: bounded inputs, current status, an estimate that over- and under-counts, and `history_same_run`.
   - Module docstring: `:56-78`. Correlation line: `:1548-1552`.
   - `docs/runbook.md:462`: the "first-look accuracy" claim is gone. `docs/limitations.md:970-985`.

6. **B6: `evaluation_error` in the Markdown, and an error row's failed kind kept in `by_kind`.** ADDRESSED.
   - `eval/lab_measure.py:1457`, `:418-423`, `:450`, `:832-842`, `:1158`.
   - Check: in the scratch lab, the Markdown says "evaluation error (no prompt known) | - | 0", the same as the JSON.

7. **B7: nulls when the leak pass did not run.** ADDRESSED.
   - `eval/lab_measure.py:342-368`, `:1347`, `:1398`.
   - `leaks_computed` is False only when `with_leaks` itself raised (`:1846-1850`).
   - `test_a_partial_report_has_null_leaks…` passed in my run.

8. **B8: "during", and the `summarise` docstring.** ADDRESSED. `eval/lab_measure.py:1562` and `:376-377`.

9. **B9: the matched-only paired line, in the JSON and the Markdown.** ADDRESSED.
   - `eval/lab_measure.py:467-484`, `:1363-1366`, `:1540-1545`.
   - **Risk 4 check:** I kept both lab reports. The JSON `paired_with_matches` {n 3, off 2, on 3} matches the Markdown "66.7 % (2/3) … 100.0 % (3/3)", and the burst lab's {n 0, None} matches "n/a (0/0)". The `as_of_sources` and `evaluation_error` numbers also match.

10. **B10 (M2): a cut that drops the entries counts no match, and the page's `best_pct` is None.** ADDRESSED.
    - The warning is stored with the run. `built.warnings` (`llm/triage.py:612,637`) is written as `citation_warnings` on every ① proposer row (`tier1/triage.py:384,434,985…`) and read from that row (`tier1/queue.py:162-165`).
    - `llm/rag_view.py:77-88`; `eval/lab_measure.py:811,1165`.
    - ② drops its whole learned block (`dossier.py:1511-1514`), so it has no twin case.

11. **B11: "the Voyage key is missing or was refused (auth)".** ADDRESSED. `eval/lab_measure.py:2074-2081` and `docs/runbook.md:455`.

12. **B12: the late 429, coded or documented.** ADDRESSED (documented, which the brief allows).
    - `backend/app/rag/lookup.py:44-57`, `docs/limitations.md:937-941`, `docs/runbook.md:462`, `eval/lab_measure.py:178-183,1529-1530`.
    - The late path returns before any write (`rag/lookup.py:511-518`). The wave report says which option was taken.

13. **C13: the lookup's run-row sentence.** ADDRESSED. `backend/app/rag/lookup.py:36-41`. It agrees with the code: a paid first-attempt 429 commits its run row before `TransientError` (`:531-546`).

14. **C14: `_read_or_none` says four checks, 020 and 023.** ADDRESSED. `backend/app/infra/health.py:348,356-363`. There are exactly 4 `_read_or_none` callers.

15. **C15 (M4): `provider_error` in the health check.** ADDRESSED.
    - `backend/app/infra/errors.py:24`; `health.py:69,469-473`; `rag/lookup.py:92` re-exports it.
    - The deviation is sound: `backend/tests/test_import_rules.py:44` (`"infra": set()`) forbids `infra → rag`. There is one definition, and no copy of the value.

16. **C16 (M1): jobs.py.** ADDRESSED. `backend/app/infra/jobs.py:28-31`.

17. **C17: the admin_knowledge docstring.** ADDRESSED. `backend/app/web/routers/admin_knowledge.py:38-47`. The code agrees: `:394-402` uses `found.failure_kind or UNKNOWN_FAILURE_KIND`.

18. **C18: the admin_lab line is wrapped.** ADDRESSED. `backend/app/web/routers/admin_lab.py:17-19`.

19. **C19: the three DSNs are in `_SECRET_FIELDS`.** ADDRESSED.
    - `backend/app/infra/config.py:46-48`; `dump()` is at `:258-264`.
    - **Risk 5 check:** I grepped backend/app, eval, scripts and tests. `dump()` is called only by `__repr__`. Nothing uses `_SECRET_FIELDS` elsewhere, no product code applies `asdict` to a Config, and `gen_env_example` does not use Config. Connections read the fields, which keep the real value.

20. **C20: the `RAG_MODEL` wording.** ADDRESSED.
    - `.env.example:89`, `backend/app/infra/config.py:221-223`, `docs/plan/00-context-pack.md:141`.
    - `scripts/gen_env_example.py` `existing_values()` carries the whole value-and-comment tail of each line, so that line is the comment's only source. The generator test passed.

21. **D21: the refocus.** ADDRESSED.
    - `frontend/src/features/admin/LabRunPage.tsx:86-93`; tests at `LabRunPage.test.tsx:905-928` and `:930`.
    - **Risk 6 check:** on an exported copy (lockfile matched by `cmp`), removing the `focus()` call turns the covering test red, and so does dropping `preventScroll`.

22. **D22: the invalidate after a cancelled full refetch.** ADDRESSED.
    - `LabRunPage.tsx:103-112`; tests at `LabRunRace.test.tsx:225,254`.
    - Mutation: with no invalidate, test 1 goes red. Invalidating after a cancelled "Tải thêm" too turns test 2 red.
    - It cannot loop: only a successful write's `labelled` invalidates.
    - It cannot drop the page's own label: the read starts after the server answered, and test 1 asserts row 2 is TP.

23. **D23: the labModel test.** ADDRESSED. `frontend/src/features/admin/labModel.test.ts:370`: the `it.each` stays and the absent-names test is gone.

24. **E24: step 5 force-recreates `app` and `worker`, with the reason.** ADDRESSED.
    - `docs/runbook.md:342` gives the reason; the paste is at `:347`. The guard is at `backend/tests/test_runbook_voyage.py:509-523`.
    - The ui's nginx re-resolves `app` (`frontend/nginx.conf:13-14`), so the recreate leaves no stale upstream.

25. **E25: the usage check.** ADDRESSED. `docs/runbook.md:384-390`, the exact query in a paste of its own. "Step 6's query" exists (the `rag_results` count).

26. **E26: T08's last minors.** ADDRESSED.
    - Step 4's recovery and its else branch are under the backup paste (`docs/runbook.md:327`).
    - The GATES comment is at `test_runbook_voyage.py:235-238`; the step-4 test exists at `:422`.
    - The sum is at `:433` and the Money paragraph at `:464`.
    - **Risk 7 check:** 443 pure tests passed on the exported head, including GATES, both runbook guard files, test_import_rules and test_config.

### New Breakage in the Wave
- **Minor.** `eval/lab_measure.py:178-183,1529-1530` prints `NO_LOOKUP_NOTE` under ②'s table too.
  - Its explanation ("after ① had finished … stored nowhere … nor `rag_lookup_failures`") is ①-only.
  - A case lookup is never "late" (`backend/app/rag/lookup.py:395-404`): its retry stores its row, and the health check sees a failed one. What ② can hide is a row stored after its first run.
  - This is wording only; no number is affected.
- **Minor (latent).** With `RAG_TRIAGE_DELAY_S=0`, which is allowed (`backend/app/infra/config.py:409`), the fallback makes `as_of == received_at` (`eval/lab_measure.py:743`).
  - The strict bound (`backend/app/tier1/triage.py:288`) then drops the subject's own row, so the burst count is 0 for a lone alert.
  - It affects only subjects with no ① run. The trial uses 45.
- **Minor (disclosure).** The CAVEAT (`eval/lab_measure.py:164-172`) and the runbook Measuring paragraph (`docs/runbook.md:462`) state that the inputs are bounded without the `DEDUP_ENABLED=true` exception.
  - Only the module docstring (`:76-78`) and (li).3 (`docs/limitations.md:982`) say it.
  - The wave report's "said in … the runbook" overstates this. The trial runs DEDUP off.

### Out-of-Scope Observations
- `before=as_of` with transaction-start `created_at` can admit a lookup, or a neighbour, whose transaction began before ①'s and committed after ①'s read.
  - Production ①'s first proposer row stores the `rag_lookup_id` it actually used, and the tool does not consult it.
  - It is rare, and is disclosed only in the wave report's Concerns.
- ①'s playbooks and decision tables (`kb/`) are read as they are at measurement time, not as of the first look.

### Verdict
**Wave:** All items are addressed, with no new Critical or Important breakage.
- Nothing remains open. The three Minors block neither the trial deployment nor the use of `measure`'s numbers. The ② note's wording is worth fixing before the report's text is quoted.
- The wave report shows the suite summary lines (wave-report.md:33-39). My focused runs agree: 443 pure tests, 186 db tests and 83 UI tests passed.
- My throwaway PostgreSQL is stopped, the symlink is removed, and the voyage checkout is untouched.
- Passes: I read the seven per-commit diffs once, then reviewed in five passes: C1's SQL and the None path; the lab tool (A3–A5, B); the C fixes; the lab page; the runbook.
