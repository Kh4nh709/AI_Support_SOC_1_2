# P11-T20 — Minor findings parked for the whole-branch fix round

The independent reviews found these Minors and approved without them, so none of them blocks a merge. The Director parks them here so that one fix round, with an independent re-review, closes them before P11 ends. Each line names its source review.

## Backend

| # | Source | Item |
|---|---|---|
| 1 | P11-T01 r2 | `_schema_without_019` copies every migration except 019; it should copy only migrations numbered below 019, with `before` from that count |
| 2 | P11-T01 r2 | the `records_itself` tests of 013–018 read the shared database built from `schema.sql`, so they are blind to a missing self-record. Live is unaffected |
| 3 | P11-T01 r2 | `scripts/migrate.sh` reads a failed `schema_migrations` lookup as "not applied", and fails loudly. Pre-existing |
| 4 | P11-T05 r2 | `test_admin_overview.py:879` counts `admin.job_retried` events without a subject filter, so it depends on test order |
| 5 | P11-T05 r2 | `admin_overview.py:38` has a docstring line of 150 characters |
| 6 | P11-T03 r2 N3 | the audit change entry should carry `stored` when the effective value was clamped |
| 7 | P11-T03 r2 N1 | the `infra/settings.py` docstrings still say "two sends"; DEC-202's amendment says ① makes up to four |
| 8 | P11-T02 r2 n1 | pin `reason: "actor_no_longer_admin"` in the stale-actor test |
| 9 | P11-T02 r2 n2 | pin `("text/x+json", False)` in the content-type list |
| 10 | P11-T02 r1 m4 | stale actor on create, reset, unlock and display-name-only PATCH. This needs an actor lock and a lock-order analysis |
| 11 | P11-T09 r1 dev. 5 | reserve the usernames `system` and `llm` in P11-T02's create validation |
| 12 | P11-T09 r1 F2 | cap `ConcludeIn.reason` on `/api/tier2/.../conclude` (500 characters, as tier1 does) |
| 13 | P11-T07 r1 F5 | FastAPI decodes a malformed JSON body before the role check: a 422 with no `authz.denied`. Record it in limitations, or add a body-reading dependency order |
| 14 | P11-T04 r1 m1 | `pct` floored (`ROUND_DOWN`) so that `pct >= 100` exactly when `spent >= cap`; update `test_month_pct_and_projection_on_a_frozen_now` |
| 15 | P11-T04 r1 m2 | bound the `stopped` key (`length <= 32` else `other`), with a test |
| 16 | P11-T04 r1 m3 | the projection floored at one day (`max(elapsed_s, 86400)`) |
| 17 | P11-T04 r1 m4 | three tests: `with_result` against `stopped_by`, more than 200 quota users, and the `limits_out` failure degrading |
| 18 | P11-T04 r1 m5 | the calendar-month test made independent of the day of the month |
| 19 | P11-T04 r1 obs. | an index on `llm_runs (created_at)`: a later migration. It mainly helps `month_spend_usd` before every model attempt |
| 20 | P11-T07 r2 N1 | `tier1/digest.py` `_rows_from` runs one `latest_suggestion` query per row; use one batched reader in `tier1/queue.py` (`DISTINCT ON (subject_id) … = ANY(%s)`), for `build` and `reopened_by_review` |
| 21 | P11-T07 r2 N2 | test: two "Sai" rows on one day, and each 200 names the posted alert (`reopened_by_review` honours `alert_id`) |
| 22 | P11-T07 r2 N3 | test: a ① run between the route's first read and the review appears in the 200's row (the 200 is the list's row, not the snapshot) |
| 23 | P11-T07 r2 N4 | the `admin_digest.py` module docstring still names the removed `alert_status` |
| 24 | P11-T06 r1 F1 | test: rows hit by two blocks count once, under the first, and `sum(counts) == matched` |
| 25 | P11-T06 r1 F2 | test: a rule closing exactly one row gives `hard_block_tally: null` (the boundary at 1) |
| 26 | P11-T06 r1 F4 | `test_pages_rules.py:969-983` pins `width_pct == 25.0`, which holds only under the inconsistent formula (row 27) |
| 27 | P11-T06 r1 F4 | **defect, pre-P11:** `autoclose.rule_width_report` divides `sum(occurrence_count)` by `count(*)` rows (`autoclose.py:524`), against its own docstring, so the width can exceed 100 %. Fix it to the docstring's definition and adjust `test_autoclose.py:854-872` |
| 28 | P11-T08 r1 F1 | test: undo never takes the caller's newer `digest` or `disagreement` label, only `gold_offline` (the source filter in `undo_last`) |
| 29 | P11-T08 r1 F2 | test: NUL and control characters in the undo body → 403 or 422, label intact |
| 30 | P11-T08 r1 F3 | test: the Jinja undo while frozen writes no event |
| 31 | P11-T09 r2 N2 | redaction: a value rule (a string holding `scheme://user:pass@` is redacted under any key), `passwd`/`pwd` as suffixes, never redact a bool or null; spec §5.8 to match |
| 32 | P11-T20 r1 m1 | `tier1/queue.py:150,205`: tie-break `run_id DESC` in `latest_suggestion` and `latest_suggestions`, plus a tie test |
| 33 | P11-T20 r1 m2 | re-wrap `admin_llm.py:51` and `admin_users.py:71` at 100 characters |
| 34 | P11-T20 r1 m3 | width tests: exactly at the threshold is not reported (`HAVING >`); a head older than the window is not in the denominator |
| 35 | P11-T20 r1 n1 | `docs/phase-3-auto-close.md:277-288`: footnote that the denominator is the heads' `sum(occurrence_count)` (`rule_width_report`) |
| 36 | P11-T20 r1 n2 | CLI `infra/auth.py:create_user` refuses `system`/`llm` too, same set as the web |
| 37 | P11-T20 r1 n3 | `scripts/migrate.sh:53`: guard the base-migration count lookup like the others |
| 38 | P11-T10 r2 n1 | `frontend/src/api/adminTypes.test.ts:113-118` `dictKeys`: throw on an unterminated string (`indexOf` −1 restarts the scan forever); optionally skip `\"` and add `\s*` to the nine anchors |
| 39 | P11-T10 Director | `reserved` leaves `readFromElsewhere` in `adminStrings.test.ts` (P11-T20 part 1 is merged, the backend writes it) |
| 40 | P11-T13 r1 m1 | LLM page stopped tile: sum over rows with `role !== "verifier"` (a ① verifier failure writes `stopped_by` on both rows) or show per pipeline; update `LlmPage.test.tsx:390` |
| 41 | P11-T13 r1 m2 | LLM limits: after a successful save focus falls to `<body>` (the opener is disabled); focus the cap field or the toast, plus a test |
| 42 | P11-T13 r1 m3 | `LlmPage.test.tsx:1491-1495`: drop or rename the two 422 fixtures the handler cannot send (`empty`, `unknown` on a real field) |
| 43 | P11-T13 r1 n1 | unit words " tr" and " s" in `llmFigures.ts:42,52` move to `S.admin.llmPage` |
| 44 | P11-T13 r1 n3 | `S.ai2.quotaExhausted` (`strings.ts:451`) says "hôm nay"; the ② quota is a rolling 24 h (decision 8) |
| 45 | P11-T14 r1 (outside) | `format.test.ts` host-zone test fails under a plain `npx vitest --run` (only the npm script sets `TZ=UTC`; host is +07): set `process.env.TZ = "UTC"` in `vite.config.ts` or a vitest `globalSetup` |
| 46 | P11-T14 r1 F1/F2 (Director ruling) | every console write latched against a same-tick double click with the shared `useSubmitLatch` (from P11-T14's fix round): adopt it in the T11, T12, T13 and T15 pages' writes, with a same-tick test each |
| 47 | P11-T11 r1 M1 | Overview: focus falls to `<body>` after a successful retry and after `not_failed`/404; move it to the "Job lỗi" heading or the notice, plus a test |
| 48 | P11-T11 r1 M2 | Overview: close the retry/reload dialog and show the toast/result before awaiting the overview refetch (up to ~30 s busy today), as `LlmLimits.tsx` does |
| 49 | P11-T11 r1 M3 | `OverviewPage.test.tsx:963-993`: the LLM-card failure tests assert the single h1 (mutation 6 survived) |
| 50 | P11-T11 r1 F1 | backend: `llm_month` section (`spent_usd`, `cap_usd`, `pct`) on `GET /api/admin/overview`, failing alone; the cost card reads it instead of `llm/usage?range=month` |
| 51 | P11-T11 r1 N2–N4 | `routes.test.tsx:154` mock to the top; shell 404 text says "tải lại trang" after a reload; toast placement consistent with `LlmPage` |
| 52 | P11-T15 r1 nits | Digest: drop the bad-day notice from `history.state` after showing it; `DataTable` gains a `rowProps` hook so Digest (and `CasesPage`, `OverviewBlocks`) can use it |
| 53 | P11-T16 r1 observation (DEC-204) | backend `admin_audit.py`: redact `label` and `confidence` in every `label.created` payload for every viewer, with a test through the real route (two labellers, A's label never in B's answer) |
| 54 | P11-T16 r1 obs. | `tier1/labels.py` `_g1_samples` sends each sample's `raw_log` uncut (not capped at 32 KB): cap it like the representative's, a later change |
| 55 | P11-T16 r1 obs. (for P11-T18) | the e2e "three paths only" check on `/admin/labels` must allow the shell's own `GET /api/auth/me` and the live socket; the T16 test mounts the page alone, the right scope for Review Focus 5 |
