# P14-wave report - the final fix wave (DEC-213)

**Status: DONE.** Every item A1-E26 is done; item 12 is documented, not coded (below). Branch `worktree-agent-a16b9bc7a05874ea6`, worktree `/project/project/AI_Support_SOC_1_2/.claude/worktrees/agent-a16b9bc7a05874ea6`, built on `c7d7f62` (fast-forward). Code tip `3e7808c`; the tip is this report's commit.

## Items

| Item | Commit | What changed |
|---|---|---|
| 1 (A1) | f5de640 | `evaluate_alert(..., as_of=None)`. With it: `BURST_COUNT_BEFORE_SQL` (`received_at < as_of`), `correlation.rows_query/samples_query/summarize_for_prompt(as_of=)`, and the RAG-on arm reads the newest lookup created before it (`_learned_before`, one read, ① reads the newest of any status). `as_of=None`: same SQL text and parameters, checked against the pre-wave modules (`scratchpad/wave/cmp_sql.py`); calls keep their old arity (two tests monkeypatch `burst_count(conn, alert, cfg)`). |
| 2 (A2) | f5de640 | `dossier._CORRELATION_*_BEFORE_SQL`, used by `build(as_of=)`; the two old constants are unchanged. |
| 3 (A3) | d35b1b8 | `lab_measure`: `AlertSubject.as_of/as_of_source`; first `triage`/`proposer` `llm_runs.created_at` (`first_look`), else `received_at + RAG_TRIAGE_DELAY_S` (`delay`). Rows carry `as_of` (UTC) and `as_of_source`; tier 1 has `as_of_sources {first_look, delay}` + `triage_delay_s`, and the Markdown says them. The decision-count estimate is bounded by the same instant (`received_before=`) and dated from `as_of`, not `received_at`. |
| 4 (A4) | f5de640, d35b1b8 | `test_received_bound_as_of.py` (12), burst-lab tests in `test_lab_measure_wave.py`: a burst's later alerts and a later stage are not counted, listed, sampled or in block 5; a burst of 3 shows 1/2/3 at first look; B1's later lookup is "none". |
| 5 (A5) | d35b1b8, fcef0d2 | `CAVEAT` (still one sentence), module docstring, runbook Measuring, limitations (li).3: bounded inputs; what remains is the neighbours' current status and the history; the count is an estimate (over-counts: caps not replayed; under-counts: undated decisions); DEDUP on is not bounded. |
| 6 (B6) | d35b1b8 | `evaluation_error` row in the Markdown table; an error row keeps its newest lookup's failed kind (`Seen("error", kind)`, `error_seen`) in `by_kind` and in `evaluation_error`. |
| 7 (B7) | d35b1b8 | `ArmRow.to_json(leaks_computed=False)`: `leaks`, `history_same_run`, `unplaceable` are `null`. |
| 8 (B8) | d35b1b8 | "stopped during the leak pass"; `summarise` docstring. |
| 9 (B9) | d35b1b8 | `paired_with_matches` per tier (JSON) and "Paired, where the RAG could act" (Markdown). |
| 10 (B10) | d35b1b8 | M2, below. |
| 11 (B11) | d35b1b8 | "the Voyage key is missing or was refused (auth)" (quota keeps "refused the request"); runbook exit 3 row. |
| 12 (B12) | fcef0d2 | Documented, not coded (below). |
| 13-18 (C) | 7c5a8be, fcef0d2 | Lookup run-row sentence counts attempts; `_read_or_none` "four checks, 020 and 023"; M4 health `provider_error`; M1 jobs.py; admin_knowledge docstring ("the row ① reads", pre-023 = `provider_error`); admin_lab line wrapped. |
| 19 (C) | 7c5a8be | `DATABASE_URL`, `DATABASE_URL_OWNER`, `TEST_DATABASE_URL` in `_SECRET_FIELDS`. The only `dump()` caller is `__repr__` (an AST test holds that); a DSN with a password is masked in repr/str/dump, the field keeps the value. |
| 20 (C) | 7c5a8be | `RAG_MODEL` = "the model of the knowledge-draft calls" in `config.py`'s comment, context pack §6.3 and `.env.example`; generator `--check` passes. |
| 21-23 (D) | 35ea88e | Refocus only when `activeElement` is null/body/the button, `{preventScroll: true}`; invalidate after a write that cancelled a refetch (not a "Tải thêm"); the two-names-absent test dropped. |
| 24-26 (E) | 3e7808c | Step 5 `up -d --force-recreate app worker` + why; step 8 usage check paste; step 4 recovery under the backup paste with the else branch; `GATES` comment; Measuring: estimates read as their sum plus earlier lab runs. |

## The four rulings
- **10 (M2).** Done. The warning `learned_entries_dropped` is stored with the run: `built.warnings` is written as `llm_runs.citation_warnings` on every ① row (`test_triage_rag` pins it). So `rag_view.rag_view` (used by `tier1/queue` and `investigation_view`, both already pass the warnings) returns `best_pct None` for it, and `lab_measure` passes `entries_dropped` to `seen_for` (no matches; the history still counts). The constant `LEARNED_ENTRIES_DROPPED_WARNING` is in `llm/builder.py`.
- **12 (late 429).** Documented, not coded. The retry cannot tell why it is a retry (`Job` has no `last_error`; only the jobs row has), "late, writes nothing" is the pinned design (`test_a_retried_lookup_that_finds_triage_done_is_late_not_failed`), the first attempt's integrity events live in a rolled-back transaction, and a row stored after ①'s first look would be outside `before=as_of`, so the report's by-kind count could not see it anyway. Said in the lookup docstring, limitations (l).3, runbook Measuring, and under every RAG-on table ("may hide a 429").
- **19.** Done (above). **20.** The generator does not take descriptions from `config.py`: it keeps the value (and comment) `.env.example` already carries and takes the key set and §6.3 parentheticals from the pack. So the comment was changed on that carried line and in §6.3 (the source), then the generator was re-run (no diff) and `--check` passes.

## Tests (private PG 16.2 + pgvector 0.6.2, trust, 127.0.0.1, random port; stopped at the end)
- `make lint`: `All checks passed!` / `336 files would be left unchanged.` (env example, schema and output-schema checks pass).
- `make test`: `5726 passed, 20 skipped, 4290 deselected, 2 xfailed, 1 warning in 34.98s`
- `make test-db` (both DSNs): `2 failed, 4287 passed, 5749 deselected, 1 warning in 425.56s (0:07:05)`; the 2 are `test_backup_restore.py:479` and `:521` (libxml), the baseline.
- `make ui-lint`: eslint, tsc clean; `All matched files use Prettier code style!`; `found 0 vulnerabilities`.
- `make ui-test`: `Test Files  73 passed (73)` / `Tests  3743 passed (3743)`. `make ui-build`: `✓ built in 1.15s`.
- `make ui-e2e` (admin-lab, blind, tier1, tier2, rag): `14 passed (57.8s)`; `ui_e2e_scan: no secret in 2 file(s) (8 secret(s) of the run searched for)`. Symlink, `dist/`, `test-results/` removed.
- New tests: `test_received_bound_as_of` 12, `test_lab_measure_wave` 21, `test_rag_view_wave` 5, `test_wave_small_fixes` 14, `test_runbook_voyage_wave` 5; UI: +2 (`LabRunPage`, plus the focus test strengthened) +2 (`LabRunRace`), 1 dropped (`labModel`).

## Guards shown red (logs and scripts in `/tmp/claude-1001/-project-project-AI-Support-SOC-1-2/0bb456f5-e8e1-406d-8ede-1e60a8cc5f36/scratchpad/wave/`)
- C1, on today's code before any change: `c1_red.log` (12 failed, `TypeError ... as_of` and the later stage visible). Lab tool, db: `b_red.log` (14 failed). Lab tool, pure, on a scratch tree with the pre-wave `lab_measure.py`/`rag_view.py`: 9 failed.
- C (`red_c.sh`, product files at `c7d7f62`): 10 failed. E (`red_e.sh`, runbook at `c7d7f62`): 6 failed, and the `GATES`-comment guard red against the old comment. D (`red_ui.sh`, four one-line mutations of a scratch `LabRunPage.tsx`): no `focus()` call -> the covering test fails (`activeElement` is body); focus whatever is active -> the "leaves the focus" test fails; no `invalidateQueries` -> item 42's test fails; invalidate after every write -> 7 tests fail.

## Pins moved (each by the brief's own order, except 1)
1. `test_lab_measure.py`: `seed_lab` seeds each labelled alert's first ① proposer run (its lookups sit 6 minutes after arrival, which `received_at + 45 s` would put after `as_of`), and `test_the_report_counts_the_subjects_whose_correlation_showed_a_later_decision` expects `{t2}` (was t1, t2, t3): t1 no longer sees t2 and t3 no longer sees t5, received after their first look. No other assertion moved.
2. `test_runbook_voyage.py`: Measuring needle `first-look` (the claim item 5 removes) replaced by the new paragraph's needles; step 5 `restart` -> `--force-recreate` (item 24); `GATES` comment (item 26).
3. `test_health.py`: `unknown 1` -> `provider_error 1` (item 15). 4. `labModel.test.ts` test dropped (item 23). 5. The focus test of `LabRunPage.test.tsx` strengthened (item 21).

## Deviations
- **Item 15.** Not an import of `rag.lookup.UNKNOWN_FAILURE_KIND`: `test_import_rules` allows `infra` no import at all, and changing it needs a DECISIONS id. The word is defined once in `infra/errors.py`; `rag.lookup` imports and re-exports it (same name for ①, ②, the admin page, the measurement); `infra/health.py` imports it from `infra`. A test holds the three equal and that there is one definition.
- **Item 3.** ①'s decision-count `since` is `as_of`, not `received_at` (a decision after the first look is the exposure); ②'s rows get `as_of_source: "first_run"`.

## Concerns
- `llm_runs.created_at` (the ① first look) and `rag_results.created_at` default to the transaction's `now()`: a lookup that commits after ①'s transaction started but whose transaction started earlier would count as before `as_of`. Rare; ② has the same property.
- With `DEDUP_ENABLED=true` the alert's own `occurrence_count` is the stored one (not bounded); the trial runs it off. Said in the docstring, the runbook and (li).3.
- pgvector 0.8.0 (the trial's image) was not run here (0.6.2 green). The runbook edits were checked statically, as T08's were; nothing was run on a trial or live stack.
