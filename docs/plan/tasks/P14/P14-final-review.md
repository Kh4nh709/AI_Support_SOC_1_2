# P14 whole-branch review (independent Reviewer, opus = claude-opus-5-5, verbatim) — range 1e2c4f5..222e25b

### Strengths

I reviewed the branch in seven passes: (1) the verdict and contract vocabularies; (2) migrations and schema, run on a scratch PostgreSQL 16; (3) Part B's lookup and failure path, with the pgvector tests run; (4) the blind arm; (5) `eval/lab_measure.py` and `evaluate_case`; (6) the trial deploy path, checking T08's runbook against compose, the Makefile, the scripts and the trial checkout (read-only); (7) the deferred minors.

- **Vocabularies are consistent across cards.**
  - `llm/verdicts.py` is the single home of both tiers' tuples. The output guard, `kb/lookup._ACTIONS`, `builder.Verdict`, the schemas, the CHECK and the UI copy all agree.
  - `escalate` survives only in the analyst's escalation action, `tier1.escalated`, `escalated_tier2`, the gold labels, the signed YAML (read via `_YAML_RENAMED`) and `eval/`'s outcome label (`metrics.OUTCOME_OF`, `ops_export` CASE).
  - `triage_v3`, `verifier_v2` and `investigate_v3` are used everywhere, including the e2e stub.
- **Migrations verified by running them.**
  - On a scratch database at 020, `migrate.sh` printed exactly the runbook's lines: `applying 021_archive` … `024_lab`, then `migrate: 4 applied, 20 already present`, and the count was 24.
  - With one held ① `escalate` row it applied 021, then 022 refused with the documented message and exit 3. The old CHECK stayed and `schema_migrations` stopped at 021.
  - A fresh build (`schema.sql`, "recorded 24 base migrations") and the upgraded database have identical `pg_dump -s` output. `build_schema.py --check` passes.
- **Failure handling is closed end to end.**
  - `RagUnavailable` carries only its kind and is raised `from None`.
  - Voyage replies are mapped by `index`, and a vector of the wrong length is `provider_error`.
  - `vectordb` connection loss is distinguished from statement errors (`_unreachable`).
  - The failure kind flows unchanged: `failed` row → `rag_not_applied:<kind>` on every ①/② row → `rag_view` (filtered to `FAILURE_KINDS`) → `RagNotice` (draws nothing for an unknown kind) → health check → `Seen.failure_kind`.
  - The LLM ranker is not reachable from the lookup (`draft_rank` is used by drafts only).
- **pgvector tests now run on the merged branch.** The four RAG db modules (`test_rag_vector_store`, `test_rag_embed_job`, `test_rag_vector_index`, `test_rag_lookup_job`) passed: 296 tests, including all 57 `[pgvector]` variants and the store's db half, on PG 16.2 with pgvector 0.6.2.
- **The vector store is safe to lose.** It is a derived index: every vector hit is re-read from the main DB (`candidates.by_ids` checks active and A5; `_intact` checks the hash and file). The embed job's `FOR SHARE` re-check plus `Reschedule` closes the retire-during-call race. Network isolation (`internal: true`, no ports) is enforced and tested.
- **The blind arm is enforced on the server.**
  - `proposed_action`, `held_by` and `rag` are in `ANALYST_HIDE` and are added before every strip.
  - The queue pops `gate_held` before stripping.
  - WebSocket messages carry ids only.
  - The lab list is an allowlist plus `strip(mode="labeling")`.
  - The UI reads these keys only in the `ready` and `decided` states.
- **The measurement is careful.**
  - `READ ONLY` transactions; DSNs blanked from the held `Config`; the spend guard.
  - ②'s `as_of`: blocks 6 and 8 and the lookup are filtered before it.
  - Leak flags (`same_run`, `after_cutoff`, `history_same_run`, unplaceable); a paired line; PARTIAL reports; exit codes that match the runbook table.
- **T08's runbook steps match the code.** Checked statically against the trial (by counting, no values printed): `COMPOSE_FILE` and `COMPOSE_PROJECT_NAME` match, host DSNs are on 127.0.0.1:55433, both switches are true, DEDUP is off, the pre-lab dump exists, and `app` binds 0.0.0.0 so it has no boot race. Expected outputs match `backup.sh`, `db-restore` and `vector_index`.

### Issues

#### Critical (Must Fix)

**C1. The measurement gives ① (and, less, ②) information that production ① never had, and the report does not disclose it.**

Where:
- `backend/app/tier1/triage.py:251-252`: "No upper bound" on `BURST_COUNT_SQL` (:260-269), used at :688 when `DEDUP_ENABLED=false`, which is the trial's setting.
- `backend/app/domain/correlation.py:98-129`: `rows_query` and `samples_query` cover a ±2 h `alert_time` window with no `received_at` bound. Samples are ordered `occurrence_count DESC, alert_time DESC`, and with DEDUP off every count is 1.
- `evaluate_alert` (:674) is called with no `as_of`.
- ②: `dossier._CORRELATION_*_SQL` (:457-482) is not bounded by `as_of` either ("every other block is built as ever").

What goes wrong when `measure` runs after a test run:
- ①'s `occurrence_count` counts every later alert of the burst. Nine tables gate their FP rule on `occurrence_lt: 50`, so the decision table, gate step 4's `playbook_rule` and the verifier facts can all flip.
- The correlation rows count the later stages of the attack.
- The five samples are the newest alerts in the ±2 h window, i.e. the later stages, raw logs included and citable as `correlation_samples` reasons.

Why it matters:
- Both arms get the same hindsight, so the paired delta is roughly fair (it may be compressed by a ceiling effect).
- The absolute ① accuracy and TP recall, the figures the Owner compares with 60–70 % / 80–90 %, are not ①'s production accuracy.
- None of the disclosures mention it: `CAVEAT` (`eval/lab_measure.py:149-155`), limitations (li).3 (T08) and the runbook all name only neighbours' current status and the history.
- The runbook's "For ①'s first-look accuracy, run its measurement before analysts work the test runs' alerts" (T08 `docs/runbook.md:421`) cannot deliver first-look accuracy: running early removes only the decided-status exposure.
- This is a plan-level gap: the T11 ruling added `as_of` for ② only.

Fix:
- Give ① an `as_of` mirroring ②: the alert's first ① proposer run `created_at`, falling back to `received_at + RAG_TRIAGE_DELAY_S`.
- When it is given, add `received_at < as_of` to the burst count and to both correlation queries, and the same for ②'s block 5. Keep the queries byte-identical for `as_of=None`, as T11 did.
- If the Owner prefers disclosure only: add this exposure to `CAVEAT`, (li).3 and the runbook, count the subjects whose window or burst holds alerts received after their ① time, and drop the "first-look" claim.
- This does not block deploying the trial stack. It blocks using `measure`'s numbers.

#### Important (Should Fix)

None beyond C1. The cross-card contracts, migrations, failure path, blind arm and deploy steps all held.

#### Minor (Nice to Have)

- **M1.** `backend/app/infra/jobs.py:28-32` still says "P14-T04 registers NO handler … until P14-T05 adds one neither worker claims or reclaims it". This is stale since T05.
- **M2.** ①'s budget cut can drop the entries but keep the history (`learned_entries_dropped`, `llm/triage.py:599-621`). The run then keeps `rag_lookup_id`, so the page's `best_pct` (`llm/rag_view.py:54-60`) and `lab_measure`'s `Seen.matches` (coverage, mean %, leak flags; `eval/lab_measure.py:708-720`) still count matches that never reached the prompt. This is rare at the 40k budget. Fix: honour that warning (the evaluation has `built.warnings`).
- **M3.** `eval/lab_measure.py:1877` says "Voyage refused the request (auth)" even when no request was sent because the container has no key.
  - T08 step 5 only runs `restart app worker`. If Compose does not recreate `app` on the `.env` change, `app` lacks the `VOYAGE_API_KEY` written in step 1, and `calibrate --rerank-model` exits 3 with a misleading message.
  - Fix: reword to "missing or refused", and use `up -d --force-recreate app worker` in step 5 (or add a note).
- **M4.** The health check words a pre-023 failed row as `unknown` (`infra/health.py`, `coalesce(..., 'unknown')`), while the lookup, the UI and the measurement say `provider_error`. Harmless on the wiped trial.

### Deferred minors (from deferred-for-final.txt)

- **1 (64)** `test_constraints.py` docker-only, 3 older failures: still real → leave (environment; pre-P14 cases; in no suite).
- **2 (70)**
  - ⚠️1: gone (implemented as ruled).
  - ⚠️2: `Config.__repr__`/`dump()` show `DATABASE_URL`, `DATABASE_URL_OWNER` and `TEST_DATABASE_URL` → still real, pre-existing; no product path prints it and `lab_measure` blanks them → optional 3-name `_SECRET_FIELDS` hardening in the wave.
  - ⚠️3: gone (T08 step 1 runs `config --quiet` without and with the password).
  - ⚠️5: gone.
- **3 (72)** `{**base, **override}` loops skip base `app`: still real → leave (test robustness).
- **4 (85)** "vector" substring ban in `docker-compose.yml`: still real → leave.
- **5 (95)** duplicated gate helpers: still real → leave.
- **6 (96)** `test_backup_restore` never runs (libxml): still real → leave (environment).
- **7 (97)** ⚠️3 as line 1 → leave; ⚠️5 FP gloss → Owner FYI, leave.
- **8 (104)** 023's tree leaves out 022: gone in effect (shared helper; 024's `at-023` tree and my 020→024 run exercise them together).
- **9 (112)** NUL in a path → 500 in `require_role`: still real, pre-existing, no bypass → leave (main-line fix, not P14).
- **10 (124)** tie test skips on a nonzero `pg_restore` exit: still real → leave.
- **11 (132)** cross-module test doubles: still real → leave.
- **12 (133)** ⚠️3 pgvector 0.8.0 never run: still real → deploy check (0.6.2 green here). ⚠️4 libxml → environment. ⚠️5 drain query: gone (T08 step 9 lists `knowledge_embed`).
- **13 (143)** small copies (T09 M6): leave.
- **14 (144)** redundant queries (T09 M7): leave.
- **15 (155)** `FOR SHARE` held across the vectordb upsert (`embed.py:121-136`): still real → leave (bounded by the 10 s statement timeout; a retire can be retried).
- **16 (156)** `--force` retire window: still real, bounded by the lookup's re-check and the next `--check` → leave.
- **17 (157)** `--force`-alone test nit: leave.
- **18 (166)** the rule is now one (`held_causes`): gone. The `found[cause]` KeyError on a new `HELD_BY` value is latent → `.get` if the wave touches the file, else leave.
- **19 (167)** injection-cause literal (`investigation_view.py:104`): still real → leave.
- **20 (168)** redundant tests: leave.
- **21 (169)** block 8 dumps the previous run's held `need_more_data` (`dossier.py:1272-1277`): still real for re-runs → leave (the measurement's `as_of` excludes previous runs).
- **22 (177)** pre-023 failed row → `provider_error` (ruled), and the idle-timeout copies: leave (see M4).
- **23 (192)** integrity events lost on the 429-late path: still real → fold into 28.
- **24 (193)** T06 test hygiene: leave.
- **25 (195)** libxml pair: environment.
- **26 (200)** `lookup.py:36-38` "one run row" sentence: still real → fix in the wave (docstring).
- **27 (201)** `health.py:356-359` "three checks … 020": still real → fix in the wave.
- **28 (202)** a late retry after a 429 writes no `failed` row, so neither `rag_lookup_failures` nor the report's by-kind count sees it: still real → fix in the wave if cheap (on a late retried attempt, store the `failed`/`rate_limit` row and its integrity events; no prompt changes), else document that "no lookup" can hide a 429.
- **29 (203)** cross-module import; DB-state-dependent assertion: leave (passed on a fresh scratch DB).
- **30 (234)** `test_schema_v3_019`'s own tree builder: leave.
- **31 (235)** `tier1/labels.py` event after the savepoint, pre-existing: leave.
- **32 (240)** same as 9: leave.
- **33 (248)** `runs.py` docstring mostly fixed; `admin_lab.py:17` 155-column line → fold into the docstring batch.
- **34 (259)** pgvector variants never run on the merged branch: gone (run here, green).
- **35 (266)** substring projection pin; no step-6 blind test: leave (the strip is gate-agnostic).
- **36 (268)** queue `held_by` drawn nowhere: still real, ruled → leave.
- **37 (285)** starlette warning; broad source checker: leave.
- **38 (302)** `lab_measure.py` size (now 1,959 lines): leave until after the lab.
- **39 (308)** `best_pct` counts a re-check-dropped entry: still real, ruled → leave (see M2 for the budget twin).
- **40 (313)** the ruling itself: n/a.
- **41 (314)** NB1 refocus steals focus (`LabRunPage.tsx:80-86`): still real → fix in the wave.
- **42 (315)** NB2 a cancelled refetch's news is dropped (`LabRunPage.tsx:93-99`; `adminKeys.ts:121-122` does not invalidate the run): still real → fix in the wave.
- **43 (316)** NB3 `labModel.test.ts:375-381`: still real → fix in the wave.
- **44 (317)** torn-refetch counter one short: still real → leave (cosmetic; needs an API change).
- **45 (323)** same as 39: leave.
- **46 (334)** `admin_knowledge.py:43-45` docstring says `failure_kind` is null for a pre-023 row: still real → fix in the wave.
- **47 (335)** `labelOf` fallback; test with a null kind: leave (harmless).
- **48 (336)** the blind test could assert the view is populated: leave.
- **49 (343)** payload scan without an index: leave (lab-sized DB).
- **50 (355)** estimate wording missing from `CAVEAT`/Correlation line (`lab_measure.py:149-155`, :1360-1364): still real → fix in the wave, together with C1's disclosure.
- **51 (356)** `evaluation_error` missing from the Markdown (`lab_measure.py:1282-1286`); an error row's failed lookup is not in `by_kind`: still real → fix in the wave.
- **52 (357)** per-row JSON writes `[]`/`false`/`0` when the leak pass did not run (`lab_measure.py:303-322`): still real → fix in the wave.
- **53 (358)** "before" should be "during" (`lab_measure.py:1373`): fix in the wave. The guard regex nit: leave.

### Declined to judge

- **Bulk labelling, and ① weighting by burst size** (DEDUP off lets one burst dominate n): spec §6 defines per-alert labels and scores; a design choice for the Owner.
- **No "RAG not applied" notice for `budget`, no-lookup or late subjects:** spec §4.3/§5.3 limit the notice to Voyage/vectordb failures.
- **The case page shows `rag`/`model_conclusion`/`held_by` with no blind arm:** DEC-101's blind arm is ①'s, and this was ruled.
- **Runbook `psql "$DATABASE_URL"` and `make db-restore` put DSNs on process argv:** pre-existing runbook-wide pattern on a single-user host; the spec forbids printing them.
- **②'s inputs include the escalation's title, tier-1 events and pre-`as_of` tier-2 notes in both arms:** that is ②'s production input, and §6 scores ② on escalated cases.
- **The free tier may train on fingerprints and digests:** the Owner's decision, recorded in limitations (l).
- **Trial setup quirks** (`HOST_UID` unset with `kb_learned` at 0777; the trial `db` restores the primary's `latest.dump` on an empty volume): pre-existing trial override, not P14 code.
- **`eval/smoke_test.py` still on `triage_v2`; `investigate_measure.py` renders the v3 template with the v2 schema:** existing `eval/` files are untouched by rule; the latter is in (li).6.
- **The admin LLM page shows a null outcome for a successful `rag_lookup` run:** pre-existing P13 display.
- **pgvector 0.8.0 is only exercised on the trial:** no local image, and I may not run docker.
- **`MAX_CANDIDATES = 40` and two Voyage requests per lookup against unpublished free-tier limits:** risk accepted in spec §5.5/§8.4; see Recommendations.
- **`rag.lookup_failed` (with its kind) on the admin audit page for blind, undecided alerts:** admin-only, and present since 020.

### Recommendations

1. **Wave contents:**
   - C1: the `as_of` for ①, plus ②'s block-5 bound; or disclosure plus a count, if ruled.
   - Deferred items 26, 27, 46, 50 (with C1's wording), 51, 52, 53 and 41–43.
   - M1–M3.
   - Optional: items 28 and the 2/⚠️2 `_SECRET_FIELDS` hardening.
2. **Report:** add a paired line over the subjects whose RAG-on prompt carried at least one match, i.e. where the RAG could act. Today's paired line mixes in failed and no-lookup subjects. Consider a by-rule breakdown, since bursts dominate n.
3. **Before the first lab run:** after a few lookups, read `select count(*), max(input_tokens), avg(input_tokens) from llm_runs where pipeline = 'rag_lookup'` and compare it with the dashboard's RPM and TPM. Each alert costs 2 requests, and rerank tokens grow with up to 40 candidates. If the tier cannot carry the lab's alert rate, pace the runs or add a payment method; spec §5.5 says the free tokens still apply.
4. **T08 fix round:** the in-flight split of steps 5, 7 and 9 into check-then-act pastes is right. Also make step 5 recreate `app` and `worker` (M3).

### Assessment

**Ready to deploy to the trial?** With fixes

**Reasoning:** Verdicts, retrieval, failure handling, the blind arm, migrations and the deploy runbook are sound, and I verified them by running the migrations and the pgvector variants. The one must-fix is C1: undisclosed hindsight in ①'s (and ②'s) inputs would put production-unfaithful absolute numbers in the thesis. It must be fixed, or disclosed and counted by ruling, before `measure` is used; the stack itself can be deployed.
