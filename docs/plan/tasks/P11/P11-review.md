# Whole-branch review — P11 admin console v1.1

## Round 1: independent Reviewer subagent at f6fea37 (20/10/2026). Verdict: CHANGES

Base `577ef18`, tip `f6fea37` (`git merge --ff-only f6fea37` in the Reviewer's own worktree). 187 files, +60 154 / −223. Read: the spec, the plan, DEC-200 to DEC-205, the P11 rows of STATE, every `P11-T*.review.md` and `*.report.md`, and `P11-T20-parked.md`. The card reviews were not redone. This round covers the spec as a whole, the seams between cards, the release as the Owner will deploy it, and the parked rows. P11-T19 (the retirement) is on its own stacked branch (DEC-205), so the Jinja pages and the cookie are expected here.

### Spec to code

Held, with code and a test that would fail:
- **§3 frontend rules.**
  - Every write in `api/admin.ts` sends a JSON body (`{}` for unlock, retry, reload and undo).
  - Every write goes through `useSubmitLatch`: user dialogs, user create, LLM limits, rule preview, create and toggle, digest rows, labels save and undo, retry, reload.
  - Every mutation calls `invalidateAfter`.
  - Errors are read through `adminErrorOf` and `parseAdminDetail`. The pages branch on the parsed `AdminError` only.
- **§5.1 users.**
  - The column list never holds `password_hash`.
  - The last-admin and self guards run under `FOR UPDATE` over the active admins, with the actor re-checked under that lock.
  - Role change, deactivation and reset stamp `sessions_invalid_before` (`clock_timestamp()`). The e2e saw the socket close 59 s after a role change.
  - `system` and `llm` are reserved on the web and in the CLI.
  - The JSON content type is required on every write.
- **§5.2 and DEC-202 limits.**
  - `effective_limits` is fail-closed and reads inside a savepoint.
  - The adapter turns `SettingsUnavailable` into `LLMBudgetExceeded`, so the run is `stopped_by='cap'`.
  - The ② route answers 503 and the `monthly_cost` health check fails when the limits cannot be read.
  - `timeout_max = max(10, min(600, (JOB_LOCK_TIMEOUT_S − 60) // 2))`. The PUT refuses above it, and a stored value is clamped on read, with `stored` in the audit entry.
  - Upserts and the `admin.settings_changed` event share one transaction, under an advisory lock.
  - The grep test finds no limit key name in code outside `config` and `settings`.
- **§5.3, §5.4 and §5.8 aggregates.**
  - Each section or block runs in its own savepoint after `SET LOCAL statement_timeout`; the audit total has its own 1 s.
  - Row caps: 50 failed jobs, 20 recent runs, audit page at most 100.
  - `llm_month` (DEC-203) fails alone.
  - The audit redaction carries the suffix rule, DEC-203 (unanchored URL rule, `passwd`/`pwd`, flags never hidden) and DEC-204 (`label` and `confidence` hidden in `label.created`).
  - Every `EVENT_TYPES` name is in exactly one group.
- **§5.5–5.7.** `hard_block_tally`, `width_threshold_pct`, the digest JSON API, and the labels undo (409 `frozen`, 404 `nothing_to_undo`) with `_bind`. Also `frozen` and `candidates_present` in `labels/next`.
- **§6 roles.** Each new module has a test that lists its routes and asserts the admin dependency (users, llm, overview, digest, audit, labels).
- **§7 e2e.** All ten scenarios are present and green, plus 2b, 4b and 4c. Scenario 8 runs on a scratch copy of the app with an empty scratch `eval/`.

Not held, or allowed by neither the spec nor a DEC:
- **I1:** the audit page and the LLM usage `recent` list show ① suggestions on blind, undecided heads.
- **M2:** no route-guard test for `admin_rules.py` or the inventory reload, and no app-wide test for `/api/admin/*`.
- **M3:** the limits PUT answer differs from what the spec text says.
- **Nit 2:** spec §2's "every aggregate read" is not met by `rules/simulate` and the digest GET (both predate v1.1).

### Seams

- **`api/admin.ts` against the handlers at the tip.** No drift found:
  - spot-checked users, the limits PUT, overview, digest, labels and audit;
  - `adminTypes.test.ts` and `adminTypesSource.ts` compare every type with the keys the backend builds;
  - `AuditActorRole` matches `ck_audit_actor_role` plus `admin`.
- **`ADMIN_INVALIDATES`.** Each write invalidates what it changes:
  - rule create and toggle → the digest of every day (`rules_enabled`);
  - limits → the overview (`llm_month`);
  - digest review → the overview (funnel and waiting);
  - every write that records an audit event → the audit page (the inventory reload records none).
  
  The display-name change does not invalidate the LLM page's quota names. That is cosmetic and is not raised.
- **`S.admin.reason` against the handlers.** Every reason a handler writes is in `ADMIN_REASONS`:
  - users: `username_taken`, `last_active_admin`, `self_change`, `not_found`, `empty`, `invalid`, `too_short`, `too_long`, `reserved`;
  - llm: `unknown`, `not_integer`, `out_of_range`, `limits_unavailable`, `timeout`, `query_failed`;
  - retry: `not_failed`, `already_queued`;
  - digest: `bad_day`, `not_in_digest`, `already_reviewed`, `not_auto_closed`;
  - labels: `frozen`, `nothing_to_undo`;
  - legacy plain texts through `LEGACY_DETAIL`.
  
  `actor_no_longer_admin` is written only in the `authz.denied` payload; the answer is 403 `forbidden`.
- **Migration 019.**
  - The `settings` columns, the `ck_settings_key` names and `FIELD_OF_KEY` agree.
  - `users.last_login_at` is written by `login` and read by the users list.
  - The audit event set goes from 27 to 28 names.
  - `schema.sql` is regenerated (`build_schema.py --check` passes).
  - The `app_rw` grant is explicit.
- **Runbook and `make migrate`.** `migrate.sh` applies 019 after 018 by its glob. The expected counts in `runbook.md:12`, `db-docker.md` and `migration-runbook.md` say 2/1/0 applied. The deploy order itself is missing from the runbook (I2).

### The release as deployed

- **nginx on 8080.**
  - The CSP is unchanged, the build inlines no font (`assetsInlineLimit: 0`), and `dist/index.html` has one external module script.
  - No admin component uses `style=`, `setAttribute`, `innerHTML` or `dangerouslySetInnerHTML`.
  - The seven lazy chunks are same-origin `/assets/*`, served by `try_files $uri =404`. `index.html` is `no-cache`, and `LazyPage` turns a failed chunk fetch into a reload offer.
  - `/api/` and `/api/ws` are proxied as in v1.0. The worst-case overview (10 sections at 3 s each, two of them with two statements) is under nginx's 60 s default read timeout.
  - The e2e runs `vite preview`, and its CSP check opens only `/` (M5).
- **Order (DEC-205).** Fast-forward `main`, then `make migrate`, then `up -d --build ui`, then `restart app worker`.
  - Old code on the 019 schema is safe: one new table, one nullable column, a wider CHECK.
  - New code on the 018 schema is not safe (I2):
    - every login fails at `infra/auth.py:170` (`last_login_at` is missing), which is an HTTP 500;
    - `effective_limits` raises, so every ① run in that window is `stopped_by='cap'` (`triage.py:820`) and those alerts lose their suggestion;
    - ② analyze answers 503, the `monthly_cost` health check fails and raises its alarm, and the users list fails.
  - `up -d --build ui` very likely recreates `app` with the new code too: the backend image copies `backend/app`, and `ui` depends on `app`. So running the UI step before migrate springs the same trap.
  - The runbook on this branch says none of this. Its restart row (`runbook.md:15`) says only "after a merge, restart". `runbook.md:24` still names the Jinja `/admin/rules` as the admin's landing page, and the React console is not mentioned.
  - P11-T19 F4 says the deploy step lives only on the retire branch.
- **Rollback.** 019 can stay under the v1.0 code. Limits saved on the web are then ignored, so the cap falls back to `.env`. Not written anywhere.

### Parked rows judged

| Rows | Judgement |
|---|---|
| 2, 19 | recorded only. Stay (test blindness on old migrations; a performance index) |
| 10, 13 | recorded as limitations (xliii) and (xliv). Stay |
| 52 (second half), 54, 58, 63, 64, 65, 66, 67, 68, 72, 73 | test strength, focus and wording, line lengths, `rowProps`, sample `raw_log` size. Stay |
| 55 | closed by P11-T18 (the e2e allows `/api/auth/me` and the socket) |
| 57 | **must not stay framed as "by design for admins"**. For gold labelling (decided alerts) the framing holds. For the online blind arm it contradicts context pack §6.4, and v1.1 opens exactly that path (I1). Fix I1 first, then write the limitations entry |
| 62 | second redaction layer (`redis://:pw@h`, `password=` key/value strings, `?token=`; also an `Authorization: Bearer` value under a key that is not secret-named, probed). No payload writer produces these today. Stay |
| 69, 70 | belong with the retire branch. Stay |
| 71 | e2e only; the run's secrets are random and the scan catches them. Stay |

### Findings

**I1 — Important — blind arm (DEC-101, context pack §6.4).** `backend/app/web/routers/admin_audit.py:339`, `backend/app/web/routers/admin_llm.py:309-329`, `frontend/src/features/admin/auditSummary.ts:202`.

Evidence:
- `00-context-pack.md:130`: "The suggestion of ① is removed from any response (all roles) while `suggestion_visible = false` and the alert is not yet decided." `tier1/visibility.py` enforces it for admins too on the queue and alert pages, and spec §1 lists the blind arm as unchanged.
- **Audit route.** It hides keys only for `label.created`. `triage.suggested` (`triage.py:958-966`: `suggested_action`, `confidence`, `forced`, `run_id`) and `llm.gate_forced` (`proposed`, `final`) are returned as written.
  - Probe: `_payload('{"suggested_action":"escalate","confidence":0.91,...}', 80, 'triage.suggested')` returns it unchanged.
  - The page's default view (the last 24 h, all groups) shows them, and the summary line renders the action.
- **LLM usage route.** `_RECENT_SQL` builds `outcome` from the proposer's `suggested_action` with `subject_id` and never joins `alerts`. Merely listing the run also says "① ran", which DEC-101 hides on a blind row.
- **Exposure.** `EVAL_BLIND_FRACTION` defaults to 0.5. The pilot's two analysts each hold an admin account (`runbook.md:391`).
- **Prior reviews missed it.** P11-T09's review assumed "admins already read tier1 alert detail", but that detail is stripped for blind undecided heads for every role. Parked row 57 calls it by design. Neither checked the blind arm.
- **Lesser case.** The digest's `reopened_by_review` rows (`tier1/digest.py:279-291`) keep `suggested_action` for a reopened alert, which is blind again by `visibility.py`. That suggestion was visible while it was auto-closed, so this one is minor.

Fix:
- **Audit route.** LEFT JOIN `alerts` on `subject_id` for `triage.suggested` and `llm.gate_forced`. When `NOT a.suggestion_visible AND a.status NOT IN SHOW_STATES`, hide the keys of `visibility.ANALYST_HIDE` plus `proposed`, `final` and `forced_by` (or the whole payload) with `REDACTED`.
- **LLM usage route.** In `_RECENT_SQL`, LEFT JOIN `alerts` for `subject_type='alert'`, and under the same condition return `outcome` NULL (and preferably `subject_id` NULL).
- **Tests and red step.** Route tests with a blind undecided head, a blind decided head, a visible head and a reopened blind head; a red step by mutation.
- **The alternative.** If the Owner accepts the exposure for admins, record it in a DEC that amends §6.4, with a limitations entry, before release.

**I2 — Important — release-order trap, the runbook is silent.** `docs/runbook.md:15`, `:24`; consequences at `backend/app/infra/auth.py:170`, `backend/app/infra/settings.py:154-167`, `backend/app/tier1/triage.py:820`.

Evidence: see "The release as deployed". DEC-205 item 2 and STATE hold the order; the runbook the Owner reads does not, and P11-T19 F4 puts the deploy step only on the retire branch.

Fix: add an "Admin console v1.1 — deploy (DEC-205)" block to `docs/runbook.md` on this branch:
1. Fast-forward `main`.
2. `set -a; . ./.env; set +a; make migrate PY=.venv/bin/python` → expect `migrate: 1 applied, 18 already present`.
3. `psql "$DATABASE_URL_OWNER" -Atc "select count(*) from schema_migrations"` → `19`. Do not go on before this holds.
4. `docker compose up -d --build ui`.
5. `docker compose restart app worker`.

Then:
- one sentence on what a restart before step 2 breaks (logins, ① runs recorded `stopped_by='cap'`, ② 503, the health alarm);
- a rollback note: 019 stays, and the web limits are ignored by the old code, so the cap falls back to `.env`;
- line 24 corrected: the React console is at `:8080/admin`, and the Jinja admin pages stay on 8000 until the retire branch.

**M1 — Minor — a POST with no body still retries a job.** `backend/app/web/routers/admin_overview.py:341`. The route reads no body, so a same-site no-cors `fetch` carrying only the `soc_session` cookie can re-queue a failed job. `admin_users.py:214` closed this shape for the users routes, and the labels and digest routes are closed by their Pydantic bodies. The impact is small (a model run under the cap), and P11-T19 removes the cookie. Fix: require the JSON content type, as `_require_json_type` does; the client already sends `{}`. Or record it until the retire branch merges.

**M2 — Minor — no route-guard test for the rules routes or the inventory reload, and none app-wide.** No test lists the routes of `admin_rules.py` (`/api/admin/rules*`, §5.5) or `web/main.py:35` (the inventory reload) and asserts `require_role("admin")`. No test walks every `/api/admin/*` route of the app. Fix: one test over `iter_routers()` plus `main.app`'s own routes. FastAPI 0.141's `app.routes` misses the included routers, so walk the routers. Every path under `/api/admin/` must carry a dependency whose closure is `require_role("admin")`.

**M3 — Minor — spec text drift.** `docs/superpowers/specs/2026-10-18-admin-console-v1-1-design.md:307` says `200 {effective, source}`. The handler, its tests and `putLlmLimits` use `{limits: LimitsOut}`, with `sources`, `clamped` and `bounds`. Fix: the spec line.

**M4 — Minor — `last_error` is not checked for credentials.** `backend/app/web/routers/admin_overview.py:219`. `failed_jobs[].last_error` is cut to 200 characters and returned raw. §6 says no answer carries a DSN, and the audit applies DEC-203's value rule to the same text in `admin.job_retried`. No writer puts a DSN there today. Fix: pass it through `admin_audit.is_secret_value` and return `REDACTED` on a match, with a test.

**M5 — Minor — the CSP is never exercised on the admin pages.** `frontend/e2e/smoke.spec.ts:45-61` opens only `/`. The lazy admin chunks never load under nginx's CSP in any test. Reading the code found no inline style or script. Fix: the smoke test signs in as admin and opens `/admin/overview` and `/admin/audit` under the injected CSP, asserting no violation.

**Nit 1.** `docs/Schema/019_admin_console.sql:19` gives the timeout bound as "10–600". DEC-202 made it `10–min(600, (JOB_LOCK_TIMEOUT_S−60)//2)`. Changing the comment would need `schema.sql` regenerated; the change is optional.

**Nit 2.** `POST /api/admin/rules/simulate` (with the tally) and `GET /api/admin/digest` run with no `statement_timeout` or savepoint. Spec §2 says every aggregate read does; §6 names only overview, usage and audit. Both predate v1.1.

### Suites

At `f6fea37`, `PY=/project/project/AI_Support_SOC_1_2/.venv/bin/python`, `TEST_DATABASE_URL=postgresql://soc@127.0.0.1:55611/soc_p11_whole_review_test`.

- `make lint`: `All checks passed!` / `All done! ✨ 🍰 ✨` / `221 files would be left unchanged.`, exit 0. It includes `schema.sql khớp migrations · 1606 dòng`.
- `make test`: `2800 passed, 3 skipped, 2093 deselected, 2 xfailed, 1 warning in 32.22s`, exit 0.
- `make test-db`, whole: `2 failed, 2090 passed, 2806 deselected, 1 warning in 257.67s (0:04:17)`. The 2 failures are the known XML pair, `test_restore_refuses_a_non_empty_target_without_force` (`:479`) and `test_round_trip_restores_into_a_second_database` (`:521`), both `unsupported XML feature`.
- `make ui-lint`: `All matched files use Prettier code style!` / `found 0 vulnerabilities`, exit 0.
- `make ui-test`: `Test Files  60 passed (60)` / `Tests  2693 passed (2693)`, exit 0.
- `make ui-build`: `dist/assets/index-BI4TkJ7H.js  427.04 kB │ gzip: 129.16 kB` / `✓ built in 799ms`, exit 0. Seven page chunks, 11–23 kB each.
- `make ui-e2e`, whole, one run: `21 passed (2.0m)` / `ui_e2e_scan: no secret in 2 file(s) (8 secret(s) of the run searched for)`, exit 0. The socket closed 59 s after the role change.
- **Real `eval/` (`/project/project/AI_Support_SOC_1_2/eval`).** Snapshot of inode, size, mtime and sha256 for all 92 entries, before the suites and after the e2e: identical (aggregate `34bfadbb…760b` both times). For example, `gold_v1.sha256` is inode 21497484, 83 bytes, mtime 2026-09-28 17:46:03 UTC, sha256 `96c43e73…45cd`; `gold_candidates.csv` is inode 21496357, 10 905 bytes, sha256 `8ce69042…f45f7e`. The worktree's own `eval/` gained only `__pycache__` from `make test` (gitignored), all written before the e2e started.
- `git status --short` and `git diff`: empty.

## Round 2: independent Reviewer subagent at af42e94 (20/10/2026). Verdict: CHANGES

Tip `af42e94`, the Coder's part 4: ten commits on `59b12b2`, reached by `git merge --ff-only af42e94` from `f6fea37`. Also read: DEC-206 and spec §5.3/§5.8 at the director tip `6674af1`, and "## Part 4" of `P11-T20.report.md`.

### Findings of round 1, closed?

| Round 1 | Status | Evidence |
|---|---|---|
| I1 blind arm (audit, usage) | **closed for the payloads; one gap left (N1)** | `admin_audit.py` LEFT JOINs `alerts` for `triage.suggested`, `llm.gate_forced` and `autoclose.reviewed` after the page is cut. On a blind, undecided alert the keys of `SUGGESTION_HIDE` become the marker at any depth, whatever the value. `SUGGESTION_HIDE` is `visibility.ANALYST_HIDE` plus `forced`, `proposed`, `final`, `forced_by` and `missing`. Usage `recent` cuts the 20 newest first, then nulls `outcome` and `subject_id`. Both statements take `visibility.SHOW_STATES` as a parameter, and a sweep over 10 statuses × 2 arms compares both routes with `visibility.strip`. Attacks tried: (1) other writers: only `tier1.decided` carries suggestion keys, and it is written on decided alerts, which cannot become blind again because A17 leaves only `auto_closed` (`transitions.py:584`); (2) key variants: `normalise_key` folds case, `_` and `-`, and the depth and null tests pass; (3) a status change between the read and the join: one statement, one snapshot; (4) a reopened blind alert: hidden again, with tests; (5) the frontend: `auditSummary` reads nothing else of a withheld payload, and the LLM page says "đã ẩn" with no link |
| I1 lesser case, the digest's reopened rows | closed | `digest.suggestion_withheld` asks `visibility.strip` itself. Reopened blind, undecided rows have `suggested_action` null and `disagreement` false, and ① is not read for them. The POST answer and its snapshot fallback (`withhold_if_blind`), and the 409 `already_reviewed` row (through `_row_now`), go through it as well |
| I2 runbook | closed | `## Admin console v1.1 — deploy (DEC-205)`: the five steps in order, step 3 `= 19` with "do not go on", step 4 explains why it comes after step 3, a paragraph on what an early restart breaks, and a rollback paragraph. Line 24 now names `:8080/admin`. The "start everything" row and `docs/db-docker.md` say db-up, migrate, up, which agrees with `docs/migration-runbook.md` §3.4–3.5. `test_runbook_deploy.py` pins the five steps in order |
| M1 | closed | `deps.require_json_type` is the single definition (`admin_users` delegates to it). It is declared after `require_role` on retry and reload, so a tier1 caller still gets 403 with `authz.denied`. A missing body and form posts are refused with 422 and write nothing (the Coder's red step, 9 cases) |
| M2 | closed | `test_admin_routes_guard.py` walks `iter_routers()` plus `main.app`'s own routes, finds the closure `require_role("admin")` returns, and checks its walk against the OpenAPI paths. Reviewer mutation: guard removed from `api_simulate_rule` → `routes under /api/admin/ with no require_role('admin'): ['POST /api/admin/rules/simulate']` |
| M3 | closed (director tip `6674af1`) | spec §5.2 says `{limits: LimitsOut}` |
| M4 | closed for the overview; see N2 for the audit row | `_shown_error` judges the first 4,000 characters and returns the marker for the whole text, or the text cut to 200 |
| M5 | closed | the smoke test opens `/admin/overview` and `/admin/audit` under the injected CSP; it passed in the whole e2e run below |
| Nit 1 | closed | the 019 comment gives the DEC-202 bound; `schema.sql` is regenerated (`khớp migrations · 1607 dòng`) |
| Nit 2 | not addressed (it predates v1.1) | — |

No regression found in the round-1 seams. The types in `api/admin.ts` are unchanged; `subject_id`, `outcome` and `suggested_action` were already nullable, and only their comments changed. `ADMIN_INVALIDATES` is unchanged. No new reason code. Migration 019 and `schema.sql` agree.

### DEC-206 judged

- **Item 1 (the rule; no second copy).** Holds in substance. The state list is `visibility.SHOW_STATES`, passed in as a parameter. The digest asks `visibility.strip` itself. Audit and usage restate the condition (`NOT suggestion_visible AND status <> ALL(...)`) in SQL; the sweep tests over every status and arm would catch drift (N4).
- **Item 2 (the event or run stays listed).** Half right:
  - "① runs on every head in both arms" is true: `soar/pipeline.py:87-135` sets `suggestion_visible` at intake, and the triage job does not branch on it. So a listed `triage.suggested` or run does not tell the arm.
  - "The verdict and its confidence are hidden" is not true for `llm.gate_forced`. The gate only ever forces the verdict to `needs_review` (`security/gate.py:9-11`, `:88-90`), and `triage.py:968-979` writes the event only when it did. Its presence under the alert's id says ①'s final verdict is `needs_review`, which is the suggestion DEC-101 hides. The fix hides the same bit as `forced` inside `triage.suggested`, so the two are inconsistent.
  - Likewise, a listed `llm.builder_violation` says ① produced no verdict: the `triage_status` fact that `ANALYST_HIDE` hides on the queue.
  - The usage list does it right: it drops `subject_id` precisely so that a listed run is not tied to the alert. The audit keeps the subject, and `?subject=<id>` filters by it.
  - See N1.
- **Item 3 (decided alerts are shown).** Holds; it matches `visibility.SHOW_STATES`.

### New findings

**N1 — Important — a blind-arm verdict is inferable from the event list.** `backend/app/web/routers/admin_audit.py` `_PAGE` (rows stay listed); the test `test_audit_hides_the_suggestion_of_a_blind_undecided_head` asserts it.
- Evidence: as above. A listed `llm.gate_forced` under a blind, undecided alert's `subject_id` means the final verdict is `needs_review`; a listed `llm.builder_violation` means ① produced none. Both show on the default audit view (the model group, last 24 h) and under `?subject=<alert id>`.
- Fix: in the inner page query, leave out the rows of `triage.suggested`, `llm.gate_forced` and `llm.builder_violation` whose alert is blind and undecided, and leave them out of the total too. That is a join on `alerts`' primary key, restricted to those three types. They come back once the alert is decided. Keep `autoclose.reviewed` listed with its keys masked (it is a person's event). Amend DEC-206 item 2, and test through the route (blind and undecided: absent from the page and the total; decided: present).
- Alternative: an Owner DEC that accepts it, with a limitations entry.

**N2 — Minor — a credential can be cut out of reach of the redaction in an append-only row.** `backend/app/web/routers/admin_overview.py:371`.
- The retry still writes `left(last_error, 200)` into the `admin.job_retried` payload. A DSN that runs across character 200 loses its `@`, so the audit's read-time value rule cannot see it, and the row is append-only. This is the same split M4 fixed for the overview.
- Fix: read 4,000 characters and write `_shown_error(...)` into the payload, with a test of a split DSN.

**N3 — Nit — misplaced spec line.** At `6674af1`, the spec's DEC-206 line for usage `recent` (around line 338) sits in §5.4's list of overview sections, not in §5.3. Move it.

**N4 — Nit — the condition is restated in SQL.** Audit and usage restate the blind-arm condition in SQL instead of calling `visibility`. The sweep tests hold it to `visibility.strip`. Recorded only.

### Mutations

The six backend mutations ran on a scratch copy (`git archive HEAD`) through `make test-db` with `TESTS=` set; the baseline on the copy gave `105 passed`. The frontend one ran on a scratch copy of `frontend/`. The worktree was never edited.

| # | Mutation | Result |
|---|---|---|
| R1 | `autoclose.reviewed` dropped from `SUGGESTION_EVENT_TYPES` | `2 failed, 30 passed` |
| R2 | audit condition `AND al.status <> 'queued_tier1'` (a blind head waiting in the queue is shown) | `6 failed, 26 passed` |
| R3 | usage `subject_id` never withheld | `3 failed, 29 passed` |
| R4 | digest `withheld=frozenset()` (reopened rows never withheld) | `9 failed, 96 passed` |
| R5 | `SUGGESTION_HIDE` keeps only `suggestedaction` of visibility's keys | `5 failed, 27 passed` |
| F1 | `auditSummary` `triage.suggested` ignores the marker | 5 tests failed |
| M2 | `claims: Admin` removed from `api_simulate_rule` | `test_admin_routes_guard.py` fails, naming `POST /api/admin/rules/simulate` |

### Suites

At `af42e94`, with `PY=/project/project/AI_Support_SOC_1_2/.venv/bin/python` and `TEST_DATABASE_URL=postgresql://soc@127.0.0.1:55611/soc_p11_whole_review_test`:
- `make lint`: `schema.sql khớp migrations · 1607 dòng` / `All checks passed!` / `224 files would be left unchanged.`, exit 0.
- `make test`: `2832 passed, 3 skipped, 2157 deselected, 2 xfailed, 1 warning in 23.69s`, exit 0.
- `make test-db`, whole: `2 failed, 2154 passed, 2838 deselected, 1 warning in 266.22s (0:04:26)`. The 2 failures are the known XML pair (`test_restore_refuses_a_non_empty_target_without_force`, `test_round_trip_restores_into_a_second_database`, `unsupported XML feature`).
- `make ui-lint`: `All matched files use Prettier code style!` / `found 0 vulnerabilities`, exit 0.
- `make ui-test`: `Test Files  60 passed (60)` / `Tests  2709 passed (2709)`, exit 0.
- `make ui-build`: `dist/assets/index-CUoF7o10.js  427.35 kB │ gzip: 129.23 kB` / `✓ built in 673ms`, exit 0.
- `make ui-e2e`, whole: `22 passed (2.1m)` / `ui_e2e_scan: no secret in 2 file(s) (8 secret(s) of the run searched for)`, exit 0. The new admin CSP smoke test is among the 22.
- Real `eval/` (`/project/project/AI_Support_SOC_1_2/eval`): inode, size, mtime and sha256 of all 92 entries identical before and after (aggregate `34bfadbb…760b`); `gold_v1.sha256` still has inode 21497484, 83 bytes, sha256 `96c43e73…45cd`. The worktree's own `eval/` is unchanged since round 1.
- `git status --short` and `git diff`: empty.

## Round 3: independent Reviewer subagent at abffc87 (20/10/2026). Verdict: APPROVE

Tip `abffc87` (`git merge --ff-only abffc87` from `af42e94`). New since round 2: `cb68fd4` (a merge of `d95e955`, DEC-206 item 2 amended, spec §5.3 line moved), `c93f25a` (N1), `b046a4e` (N2), `af92c75` (frontend comments), `f9837c2` (e2e scenario 5), `abffc87` (report). Also read: DEC-206's second amendment (failed jobs) on `director/admin-v1-1`.

### Findings of round 2, closed?

| Round 2 | Status | Evidence |
|---|---|---|
| **N1** a blind verdict told by the event list | **closed** | `admin_audit.py`: `BLIND_OMITTED_EVENT_TYPES = {triage.suggested, llm.gate_forced, llm.builder_violation}`. `_BLIND_OMIT` is in `_filters`, so it is in the inner page selection, before the `LIMIT`. The total shares the clauses, with `_BLIND_OMIT_COUNT` in its place. `autoclose.reviewed` stays listed and masked. The state list is `visibility.SHOW_STATES`, passed as a parameter. |
| — the two spellings agree | proven | Page: `NOT (t ∈ O AND COALESCE((SELECT NOT sv AND st <> ALL(S) FROM alerts WHERE id = subj), false))`. Total: `NOT EXISTS (SELECT 1 FROM alerts WHERE id = subj AND t ∈ O AND NOT sv AND st <> ALL(S))`. Case by case: t ∉ O, kept by both; no `alerts` row, kept by both (COALESCE false; EXISTS false); a row, both leave the event out exactly when `NOT sv AND st <> ALL(S)` is true, and a NULL inside keeps it in both (COALESCE → false; a WHERE on NULL selects nothing). `alert_id` is the primary key, so the scalar subquery has at most one row. `test_audit_the_two_spellings_of_the_omission_count_the_same_rows` counts with both and with the route's own cursor chain. |
| — paging and the cursor | whole | The filter is applied before the `LIMIT`. Tests: full pages when a run of omitted rows sits at a page boundary; cursor chains at limits 1, 3, 4 and 7 list each visible row once, with the same `total` on every page. Reviewer mutation Q1 shows the total is held. |
| — plan-shape test, deviation 2 | still sound | Only the literal `::text[]` (the states array) is stripped. A payload cast prints as `(...payload)::text`, which is not stripped and still fails the test. |
| — inference attack, re-tried | no other tell found | `tier1.decided`, `tier1.escalated`, `case.*`: written on decided alerts, and none can become blind again (A17 leaves only `auto_closed`). `alert.*` and `autoclose.reviewed` are not ①'s. ①'s job failures carry exception texts (a timeout, the `TransientError` text); a verifier schema failure is a recorded run (`stopped_by='schema'`), not a failed job. Residual, recorded only: the API's `audit_id` sequence has gaps where rows were left out, so a deliberate reader of the raw API could guess from a two-id gap at a triage moment that `llm.gate_forced` was written. The page shows `audit_id` only in an aria-label. One sentence in the limitations entry of parked row 57 is suggested. |
| **N2** the retry wrote a split DSN into an append-only event | **closed** | `api_retry_job` reads `left(last_error, 4000)` and writes `_shown_error(...)` into `admin.job_retried`. Tests: split at 200, inside 200, past 200 → marker; read back through `GET /api/admin/audit` → marker; the job row keeps the full text. Reviewer mutation Q4 fails them. |
| N3 (Nit) spec line misplaced | closed | `d95e955` moves it to §5.3 |
| N4 (Nit) blind condition restated in SQL | stands, recorded only | Three statements restate `NOT sv AND st <> ALL(SHOW_STATES)`; the sweep tests and `test_neither_statement_holds_a_decided_state_of_its_own` keep it to `visibility.strip` |
| e2e scenario 5 (the coin flip) | deterministic | `newAlertId(arm)` picks the id by `sha256` parity, which is `_suggestion_visible` at the stack's `EVAL_BLIND_FRACTION=0.5`: "cap" is visible and "cap-blind" is blind. The blind half asserts the "đã ẩn" row, no link, and the id nowhere in the DOM. The other alerts posted with no arm are asserted only in the database or by human-event rows (scenario 9 filters by actor; `autoclose.reviewed` is listed in both arms). Two whole runs, both 22 passed. |
| DEC-206, second amendment (failed jobs) | accepted | `job.exhausted` and the overview's `failed_jobs` for a blind, undecided alert tell that ① failed, which is the `triage_status` "unavailable" fact, but never a leaning. The admin has to see the job to retry it. Leaving out `llm.builder_violation`, which no one acts on, while keeping these is a consistent line. Condition: the limitations entry it names (parked row 57, retire branch). The amendment is a doc commit on `director/admin-v1-1` only; it lands at the merge. |

### New findings

None at Important or Minor. The `audit_id`-gap residual and N4 are recorded above as accepted observations.

### Mutations

Reviewer mutations on a scratch copy (`git archive HEAD`), run through `make test-db` with `TESTS=` set, restored after each. Baseline on the copy: `140 passed, 8 deselected`.

| # | Mutation | Result |
|---|---|---|
| Q1 | `_BLIND_OMIT_COUNT` without `AND al.status <> ALL(show_states)` (the total ignores the decided states) | `7 failed, 32 passed` |
| Q2 | `llm.gate_forced` dropped from `BLIND_OMITTED_EVENT_TYPES` | `4 failed, 35 passed` |
| Q3 | `_BLIND_OMIT`'s `COALESCE(..., false)` → `true` (a subject with no alert row is left out) | `2 failed, 37 passed` |
| Q4 | the retry writes `judged_error[:_ERROR_CHARS]` instead of `_shown_error(judged_error)` | `5 failed, 96 passed` |

### Suites

At `abffc87`, with `PY=/project/project/AI_Support_SOC_1_2/.venv/bin/python` and `TEST_DATABASE_URL=postgresql://soc@127.0.0.1:55611/soc_p11_whole_review_test`:
- `make lint`: `schema.sql khớp migrations · 1607 dòng` / ruff `All checks passed!` / `224 files would be left unchanged.`, exit 0.
- `make test`: `2836 passed, 3 skipped, 2168 deselected, 2 xfailed, 1 warning in 20.84s`, exit 0.
- `make test-db`, whole: `2 failed, 2165 passed, 2842 deselected, 1 warning in 242.53s (0:04:02)`. The two failures are the known XML pair, `test_restore_refuses_a_non_empty_target_without_force` and `test_round_trip_restores_into_a_second_database` (`unsupported XML feature`).
- `make ui-lint`: `All matched files use Prettier code style!` / `found 0 vulnerabilities`, exit 0.
- `make ui-test`: `Test Files  60 passed (60)` / `Tests  2709 passed (2709)`, exit 0.
- `make ui-build`: `dist/assets/index-CUoF7o10.js  427.35 kB │ gzip: 129.23 kB` / `✓ built in 771ms`, exit 0.
- `make ui-e2e`, whole, run 1: `22 passed (2.1m)` / `ui_e2e_scan: no secret in 2 file(s) (8 secret(s) of the run searched for)`, exit 0.
- `make ui-e2e`, whole, run 2: `22 passed (2.1m)` / `ui_e2e_scan: no secret in 2 file(s) (8 secret(s) of the run searched for)`, exit 0.
- Real `eval/` (`/project/project/AI_Support_SOC_1_2/eval`): inode, size, mtime and sha256 of all 92 entries identical before the suites and after both e2e runs (aggregate `34bfadbb…760b`). The worktree's own `eval/` is unchanged too.
- `git status --short` and `git diff`: empty.

## Director, 20/10/2026

- **Round 1 rulings.**
  - **I1:** fixed on the server, not accepted. The context pack §6.4 rule binds every role, so DEC-206 was recorded for it.
  - **I2:** the deploy block goes into the v1.1 runbook.
  - **M3:** the Director fixed the spec line.
  - **Nit 2:** parked as row 74.
- **Round 2 rulings.**
  - **N1:** the Reviewer was right that DEC-206 item 2 was half wrong. The amendment leaves the three telling event types out of the audit for blind, undecided alerts.
  - **The Coder's open point** ("① produced nothing" on a failed job): accepted in a second amendment, because the admin must see the job to retry it.
  - **N3:** the Director moved the spec line.
- **Merged** part 4 (`abffc87`) as `8497530`.
- **Director mutation:** `llm.builder_violation` dropped from `BLIND_OMITTED_EVENT_TYPES` (`admin_audit.py:179`).
  - `test_admin_audit.py` alone stays green: 574 passed.
  - `test_admin_blind_arm.py` catches it: 6 failed, 39 passed.
  - Restored.
- **For the retire branch.** The limitations entry of parked row 57 (`docs/limitations.md` (xlv) on P11-T19) must be rewritten for DEC-206 and its two amendments, with the `audit_id` gap residual in one sentence.
