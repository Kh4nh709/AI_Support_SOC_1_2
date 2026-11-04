# P14 final fix wave — brief (the Director's rulings on the whole-branch review)

The whole-branch review is `final-review.md` in this directory (verbatim). Read it first. Its file:line references are at `222e25b`; T08's runbook has since merged (`ad8e5c9`), so the runbook line numbers below are at the current tip. Each item: what to change, and the test that proves it.

## A. C1 — ① sees no alert received after its first look (Critical for the measurement)

1. `tier1.triage.evaluate_alert(conn, alert_id, *, adapter, cfg, switches=DEPLOYED, as_of=None)`.
   - `as_of=None` is today's behaviour, byte-identical: same SQL text, same prompts. Every existing golden and byte pin stays green unchanged.
   - With `as_of`:
     - `BURST_COUNT_SQL` (triage.py:260-269) counts only alerts with `received_at < as_of`.
     - Both correlation queries (`domain/correlation.py` `rows_query` and `samples_query`, :98-129) add `received_at < as_of`.
     - The RAG-on arm reads the newest lookup created before `as_of` (`rag.lookup.latest_lookup(before=as_of)`), as ② does.
   - Keep the bounded variants as separate statements (or one optional clause) so the None path's SQL text is unchanged. T11 did the same for ②.
2. ②'s block 5: `tier2/dossier.py` `_CORRELATION_*_SQL` (:457-482) gets the same `received_at < as_of` bound when `evaluate_case` has an `as_of`. The None path is unchanged.
3. `eval/lab_measure.py` gives ① its `as_of`:
   - the `created_at` of the alert's first ① proposer run (`llm_runs`, pipeline triage, role proposer);
   - else `received_at + RAG_TRIAGE_DELAY_S`.
   - The row records which of the two was used (count both in the report).
4. Tests:
   - With `as_of`, an alert of the same burst or ±2 h window received after it is not counted, listed or sampled, for ① (burst count, correlation rows, samples) and for ② (block 5).
   - Without `as_of`, nothing changes (the existing pins).
   - The scratch-lab test shows ①'s burst count at first look.
   - Show the new tests red first.
5. Wording:
   - The report's `CAVEAT` and its header say that ①'s and ②'s inputs are bounded at the first look. What remains are neighbours' CURRENT status (decided after arrival, counted per subject) and the decision history (`history_same_run`).
   - Fold in deferred item 50: the count is an estimate. It over-counts because the section's caps are not replayed, and under-counts because some decisions have no date.
   - Runbook "Measuring" and limitations (li): replace the old "first-look" sentence with the bounded inputs as now true, plus the remaining status exposure.

## B. The measurement report (eval/lab_measure.py)

6. Item 51:
   - `evaluation_error` appears in the Markdown table too, with the same numbers as the JSON.
   - An error row whose newest lookup `failed` is still counted under `failed_lookups.by_kind`.
7. Item 52: when the leak pass did not run, the per-row JSON writes `null` for `leaks`, `history_same_run` and `unplaceable`, not `[]`/`false`/`0`.
8. Item 53: "the run stopped before the leak pass" becomes "during" (:1373 at 222e25b). Fix the `summarise` docstring too.
9. Recommendation 2: per tier, a second paired line over the subjects whose RAG-on prompt carried at least one match (where the RAG could act). It gives accuracy off/on on that same set and n. Show it in the JSON and the Markdown.
10. M2: ①'s budget cut can drop the learned entries but keep the history (`learned_entries_dropped`, llm/triage.py:599-621). When that warning is on the run:
    - the measurement's `Seen.matches` counts nothing (no coverage, no mean %, no leak flags from matches);
    - the alert view's `best_pct` (llm/rag_view.py) is None, if the warning is stored with the run.
    - Check where the warning is stored and say so.
11. M3: lab_measure.py:1877's message "Voyage refused the request (auth)" becomes "the Voyage key is missing or was refused (auth)".
12. Item 28: a late retried lookup after a 429 writes no `failed` row, so neither `rag_lookup_failures` nor the report's by-kind count sees it.
    - If one small change in `rag/lookup.py` records a `failed`/`rate_limit` row (and its integrity events) when the retried attempt is abandoned, with no prompt change, do it with a test.
    - Otherwise document it: in limitations, and in the report's "no lookup" line ("may hide a 429").
    - Say which you did.

## C. Small code and docstring fixes

13. Item 26: rag/lookup.py:36-38's "one run row" sentence (a retried lookup writes two; a 429-late one writes none).
14. Item 27: infra/health.py:356-359's "three checks … 020" docstring.
15. M4: infra/health.py's `coalesce(…, 'unknown')` for a failed row with no kind uses `rag.lookup.UNKNOWN_FAILURE_KIND` (provider_error), like the lookup, the UI and the measurement. Import it; do not copy the value.
16. M1: infra/jobs.py:28-32's stale "no handler … neither worker claims it".
17. Item 46: admin_knowledge.py:43-45's module docstring.
    - `failure_kind` of a pre-023 failed row is now `provider_error`.
    - Say "the row ① reads"; for ② the view of usable statuses differs.
18. Item 33: admin_lab.py:17, the 155-column docstring line, wrapped like its neighbours.
19. Deferred 2/⚠️2: add `DATABASE_URL`, `DATABASE_URL_OWNER` and `TEST_DATABASE_URL` to `infra/config.py`'s `_SECRET_FIELDS`, so `Config.__repr__`/`dump()` mask them.
    - First check every caller of `dump()`/`repr` (gen_env_example, context-pack checks, tests) and keep them green.
    - Show a test that a DSN with a password is masked.
20. `.env.example` (and context pack §6.3, if it is generated from the same description): `RAG_MODEL` is "the model of the knowledge-draft calls". The lookup calls no model. Change it in `infra/config.py`'s description and regenerate. Never hand-edit a generated file.

## D. The admin lab page (frontend)

21. Item 41 (`LabRunPage.tsx:80-86`): the "Tải thêm" refocus takes the focus from wherever the admin put it.
    - Refocus only when `document.activeElement` is `body`/null (or the button), with `{ preventScroll: true }`.
    - Make the covering test fail without the `focus()` call. Today it passes without it, because jsdom keeps focus on a disabled button; assert `activeElement` explicitly.
22. Item 42 (`LabRunPage.tsx:93-99`): when the read that `labelled` cancelled was a full refetch (not a "Tải thêm"), follow `setQueryData` with `invalidateQueries({ queryKey })`. The read that lands then comes after the write. Add a test.
23. Item 43 (`labModel.test.ts:375-381`): drop the assertion that the two removed names are absent. The `it.each` over unused strings stays.

## E. The runbook (docs/runbook.md, Voyage section) and its guards

24. M3:
    - Step 5 recreates `app` and `worker` so they see the new `.env` keys: `docker compose up -d --force-recreate app worker`, not `restart`.
    - Say why: `calibrate --rerank-model` runs in `app` and needs `VOYAGE_API_KEY`.
    - Update the guard.
25. Recommendation 3: after the first lab lookups, check Voyage usage against the dashboard's RPM/TPM.
    - The check: `select count(*), max(input_tokens), avg(input_tokens) from llm_runs where pipeline = 'rag_lookup'`.
    - Each alert costs two requests, and rerank tokens grow with up to 40 candidates.
    - If the free tier cannot carry the lab's alert rate, pace the runs.
26. T08's last minors:
    - Step 4's failed-copy recovery moves into the paragraph after the backup paste (before the `ls -t` paste), with an else branch: if the pre-lab dump is in neither place, run `bash scripts/backup.sh` alone, then find the pre-lab dump.
    - The `GATES` comment no longer says step 4 has "nothing to wait for". Step 4's gate is pinned by its own test.
    - The monthly cap is per tool run. The tool writes no `llm_runs`, so the paste-2 small run, a `--tiers 1` run and earlier lab runs this month are not counted. At the estimate paste say: read the figures against the cap as their sum plus this month's earlier lab runs.
    - Keep every check-then-act pair in its own pastes. The `GATES` guard stays green.

## Not in this wave

Every other deferred minor stays as the review classified it ("leave"). Do not refactor `eval/lab_measure.py` into two files. Do not change `eval/`'s existing files. Do not touch migrations, `docker-compose*.yml` or the live stack.
