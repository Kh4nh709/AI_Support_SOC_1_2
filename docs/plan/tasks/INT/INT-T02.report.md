# INT-T02 report (Coder hand-back, verbatim)

STATUS: DONE. All six items are built and every gate is green. Branch worktree-agent-ab3e189b6a8932d74, tip c551dd4 (6 commits on 48efabd, fast-forwarded cleanly). The tree is clean and nothing is pushed. Nothing under eval/ and no STATE.md were touched.

## Items
1. **794cedf, webhook refuses off-pattern ids.**
   - Red step: with the new tests in place and `intake.py` unfixed, 17 failed. These were 201 or 409 instead of 400, plus a psycopg 500 for an object id.
   - Design: the pattern now lives once, in a new leaf module `backend/app/infra/ids.py` (`ALERT_ID_PATTERN` and `is_alert_id()`, which checks `isinstance(str)` then `fullmatch`). `infra` may import nothing from the app (G1, `test_import_rules`), and changing `ALLOWED` needs a DEC. A shared module under `infra` is the only place that needs no rule change. `builder.ID_PATTERNS["alert_id"]`, `security.linter._ID_PATTERNS[0]` and `intake` all use that one object. The linter's private copy of it is gone. `test_alert_id_source.py` pins that they are one object.
   - Behaviour: `intake.receive` now takes the existing path: reason `id`, a `rejected_alerts` row, 400 `{"detail":{"missing":"id"}}`, nothing in intake, alerts or jobs. The response bytes are unchanged.
   - Tests: cover `not-a-soar-id`, `gl-TEST-100191-1793289654049`, lower-case ULID, upper-case uuid, ULID with an `I`, trailing newline, int/float/bool/list/object ids, an indexer-hit body and a heartbeat doc. The two valid shapes are still 201.
   - Callers: `intake.receive` has one app caller, `web/routers/webhook.py:99`. I scoped the check by grep over `backend/app`, `scripts`, `eval/` (read-only grep) and the e2e fixtures, which use Wazuh-form ids. The puller has its own path. Other callers are tests only.
   - Existing tests that posted off-pattern ids now use Wazuh-form ids: `test_webhook.py`'s `_uid`, `test_webhook_concurrency.py`, 2 ids in `test_health.py`, 1 in `test_pipeline.py`.
   - I also added one paragraph to the runbook's SOAR intake section saying what the webhook takes.
2. **e2ae9b3, ① says why it stopped.**
   - New key `llm_stopped_by` on the alert view. `queue.latest_stopped_by` reads the same newest proposer run as `latest_suggestion`. `aiStateOfView` passes it to `Unavailable`, so the F6 label shows.
   - Blind arm: the key is in `visibility.ANALYST_HIDE`, so it also reaches `LABELING_DENYLIST`. It starts with `llm_`, so `LABELING_PREFIXES` drop it too. The blind check in `aiStateOfView` runs before the reason is read.
   - Pinned at four levels: visibility unit, `get_alert_view` (blind, then decided, then labeling), API for tier1/tier2/admin (the value is not in the body), and UI/AlertPage (a stray key on a blind view stays `hidden`).
   - The queue row is unchanged: the row's `unavailable` carries no reason, and a test says so.
   - `AlertView` TS type and tests updated. There was no separate AlertView type-anchor test. `adminTypes.test.ts` only anchors `admin.ts`'s types.
3. **2043990, 402 wording.**
   - ②'s `permanent` is now "nhà cung cấp hoặc mô hình từ chối yêu cầu (ví dụ hết số dư, 402), không thử lại". The draft warning `llm_permanent` has the same text, capitalised.
   - ②'s label lives in two places that `strings.test.ts` holds equal: `S.ai2.stoppedBy` and the backend `STOPPED_TEXT` in `investigation_view.py`. I changed both.
   - Left alone: the admin LLM table's short words (pinned short) and ①'s own `permanent` label, since ① records a 402 as `unavailable`.
4. **e23ebfd, runbook.**
   - Step 1 reads `git merge --ff-only director/integration`. `main` is an ancestor of it. I added a "Not possible to fast-forward: stop and tell the Director" note.
   - Counts unchanged: migration 020 is the only new one, so steps 2 and 3 still read `1 applied, 19 already present` and `20`.
   - Added an intro paragraph on what the integration brings besides DEC-210 (webhook 400, `siem_context` in ①'s prompt, the alert page). Step 6 now says "This release changes `frontend/`".
   - Step 4: the directory must be writable by `HOST_UID`. When the checkout user is not that user, run `chmod 777 kb_learned` and then read the check line again. Both right-looking lines are named (`drwxr-xr-x` with the right uid, or `drwxrwxrwx`), with ATTT-M1's 1001/1000. It warns that a `chown` to `HOST_UID` would stop git updating `kb_learned/README.md`. The `sudo chown` stays only to hand a root-owned directory back to the checkout user.
   - Also updated: `kb_learned/README.md` gave the same old fix, and one db-restore sentence says why the rebuild runs in `app` on this host.
   - Pins: step 1 changed; step 4's old chown pin replaced by three new tests.
5. **eb54e52, copy fixes.**
   - (a) `case_detail` now carries `last_run = {created_at, has_result}` of the newest ② `llm_runs` row (`case_view.last_run`). The summary shows that time, plus "— không có kết quả" when the run had no result. `last_analyzed_at` is untouched and still drives `ongoing` and the timeline.
   - (b) The `heartbeat` label is "Alert gần nhất từ nguồn", in the row and in the empty-range hint that quotes it. I checked this test red against the old strings.
6. **c551dd4, DEC-211 R6 (Owner, 29/10).** Records A = (b), B = (1) and C, after R5. It also notes that A closes item 9's open question about the `gl-TEST-…` id.

## Suites
- `make lint test`: ruff and black clean; 4778 passed, 20 skipped, 2 xfailed.
- `make test-db` (private PG 16 on 127.0.0.1:56741): 3243 passed, 2 failed. Both are the known libxml failures in `test_backup_restore.py`. Baseline on 48efabd was 3209 passed and the same 2.
- `make ui-lint ui-test`: eslint, tsc and prettier clean, 0 vulnerabilities; 65 files, 3175 tests passed.
- `make ui-e2e`: 25 passed (2.1m), including `blind.spec` and the CSP tests, and the secret scan was clean.
- Cleanup done: the private PG is stopped and its data deleted, and the `node_modules` symlink, `dist/` and `test-results/` are removed.

## Chose not to do, and observations
- The case list page's "Phân tích gần nhất" column still reads `last_analyzed_at`, so it still says "chưa phân tích" after a stopped run. The card named the case page only. The case timeline also still ignores a stopped run.
- If ① is switched off (`disabled`), no new run is written, so `llm_stopped_by` can show the reason of an older run. It is accurate to the newest run, as specified.
- The `\d` in the alert-id pattern matches Unicode digits. The pattern is exact as ruled, and builder and webhook agree, so I left it.
- Existing bug, not touched: a webhook body with a valid id but no `timestamp` raises `KeyError` and returns a 500.
