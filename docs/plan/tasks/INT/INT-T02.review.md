VERDICT: APPROVE

# INT-T02 review: `worktree-agent-ab3e189b6a8932d74` @ c551dd4 (6 commits on 48efabd)

Reviewed in my own detached worktree at c551dd4. Nothing was edited, committed or pushed. Nothing under `eval/` was touched (the range does not change `eval/`). No database was used.

All six card items are built as asked. I found no Critical or Important issue. There are three Minors: one is pre-existing and out of the card's scope, one is copy. There are three Nits.

## Findings

### 1. Minor: the "exact" alert id pattern accepts any Unicode decimal digit, so the webhook now accepts look-alike ids
- Where: `backend/app/infra/ids.py:25-28`. `\d` in a `str` pattern without `re.ASCII` matches every Unicode `Nd` digit.
- I checked it directly. `is_alert_id` and `builder.Id("alert_id", …)` both accept:
  - `𝟏𝟕𝟗𝟎𝟖𝟖𝟖𝟖𝟓𝟐.𝟐𝟖𝟏𝟔𝟖𝟖𝟗𝟕` (mathematical bold digits);
  - `１７８６９０３０１６.１２１３１１` (fullwidth digits);
  - `١٧٨٦.١٢` (Arabic-Indic digits).
  - With `re.ASCII` the same pattern refuses all three and still takes the real Wazuh and SOAR ids.
- How it fails:
  1. A key holder, or a SOAR sender with an encoding bug, posts an alert whose id is the bold-digit twin of `1790888852.28168897`.
  2. It is answered 201 and stored as a *different* alert. The `(manager_id, source_alert_id)` uniqueness check does not see a duplicate, so no 409.
  3. ① renders the id and the linter passes it.
  4. In the UI it can read as the real id, depending on the font.
  - This is not a regression. Before INT-T02 the webhook took any non-empty id, and the linter's and builder's old copies had the same `\d`, so **the linter's behaviour is unchanged**. But the card and `ids.py` call the shape "exact", and this is the one place where that is not true.
  - Nothing in the app or migrations has an ASCII-only check on `alert_id`. The only one is `frontend/e2e/fixtures.ts:180`, which is test code. So nothing breaks downstream.
- Suggested fix (Director's call, because it narrows the linter as well):
  - Compile `ALERT_ID_PATTERN` with `re.ASCII`, or spell the digits `[0-9]`. Because it is one object, intake, the builder and the linter narrow together.
  - Real prompts are unaffected: ids reach ① only from intake and the puller, and both are ASCII from now on.
  - Add a non-ASCII-digit case to `test_alert_id_source.py`'s refusal list.
  - The other `\d` id patterns (`rule_id`, `agent_id`, `mitre`) have the same property, and fixing them is a separate decision.

### 2. Minor, pre-existing (out of INT-T02's scope): a valid id with no, or a non-ISO, `timestamp` is a 500 with no rejected row
- Where: `backend/app/infra/intake.py:126`, `sort_key = _replay_sort_key(str(alert_obj["timestamp"]))`. It runs after the id and `rule.id` checks and before any SQL. The route (`web/routers/webhook.py:120-135`) catches only `PayloadTooLarge`, `Rejected`, `Duplicate` and the two timeout classes.
- It is real. Reproduced without a database by calling `intake.receive(None, body, …)` with an id and a `rule.id` that both pass the checks:
  - no `timestamp`: `KeyError 'timestamp'`;
  - `"timestamp": "yesterday"`: `ValueError`;
  - `"timestamp": 1730000000` (epoch number): `ValueError`.
- How it fails: a SOAR sender that drops the field or sends epoch numbers gets 500s.
  - 500 is outside the webhook's frozen status set (DEC-040; DEC-211 R1 chose 503 over 500 for exactly that reason).
  - `Conn` rolls everything back, so no `rejected_alerts` row is written. That is a silent drop (phase-1 "never a silent drop"), and it is invisible to the `rejected_alerts` query the runbook just added (`docs/runbook.md:267`).
  - Wazuh and the SOAR fixtures always carry an ISO `timestamp`, which is why it has not shown up.
- Suggested fix, as a separate card, not in INT-T02 (whose rule is "every other response byte-identical"):
  - Catch it in `receive` with a new reason `timestamp`: a rejected row, then 400 `{"detail": {"missing": "timestamp"}}`. 400 is in the frozen set, but the new `missing` value needs a ruling.
  - Test the three bodies above.

### 3. Minor: the new heartbeat label is right for webhook mode but wrong for pull mode, the default
- Where: `frontend/src/strings.ts:704` (`heartbeat: "Alert gần nhất từ nguồn"`), the hint at `:627`, and the pin in `OverviewPage.test.tsx`.
- How it fails:
  - With `PULL_ENABLED=true` the check reads `source_heartbeat.last_seen_at`. The puller stamps that after **every** successful pull, with or without hits (`infra/puller.py:304`). The detail reads "last heartbeat N min ago" (`infra/health.py:117-135`).
  - So on a pull-mode system with no alert for hours, the row reads "Alert gần nhất từ nguồn: last heartbeat 0.3 min ago". The empty-range hint then sends the admin to a row that says an alert just came in.
  - The old label was wrong only in webhook mode; the new one is wrong only in pull mode. The card asked for a label "neutral between pull and webhook mode".
- Suggested fix: a label that is true of both, such as "Tín hiệu gần nhất từ nguồn" or "Nguồn gửi tín hiệu gần nhất", and the hint and the test to match. The test's `not.toMatch(/kéo|pull/i)` guard can stay.

### 4. Nit: the case list and the case page now disagree on "Phân tích gần nhất"
- Where: `frontend/src/features/tier2/CasesPage.tsx:95` reads `last_analyzed_at`; `CasePage.tsx` `lastAnalysedText` reads `last_run`. Both are headed `S.case.col.lastAnalysed` "Phân tích gần nhất".
- What you see: a case whose only ② run stopped on a 402 shows "chưa phân tích" in the list and "<time> — không có kết quả" on its page.
- It doesn't matter much. The list still truthfully says there is no analysis result, and re-running ② on a 402 fails again harmlessly. But one column title now has two meanings.
- Suggested fix: either give the list the same rule (one `LATERAL` / `DISTINCT ON` read of the newest `investigate` row per case) or say in the list's code comment that it means "a run with a result". The commit message already says the list was kept on purpose, so this is a ruling, not a bug.

### 5. Nit: `S.case.noResult` is dead outside tests, and `analysedNoResult` repeats its text
- Where: `frontend/src/strings.ts:462-463`. `noResult` is read only by `CasePage.test.tsx`. `analysedNoResult` spells "không có kết quả" again instead of reusing it.
- Suggested fix: `analysedNoResult: (when) => \`${when} — ${S.case.noResult}\`` (or a module constant), or drop `noResult`.

### 6. Nit: the runbook's "SOAR sender that suddenly gets 400s" query misses indexer-hit-shaped posts
- Where: `docs/runbook.md:267`, `select raw_payload->>'id', count(*) … group by 1`. `_insert_rejected` stores the whole document. For a `{"_source": {...}}` post, the id is at `raw_payload->'_source'->>'id'`, so that row groups under `NULL`.
- SOAR posts bare objects, so this is cosmetic.
- Suggested fix: `coalesce(raw_payload->>'id', raw_payload->'_source'->>'id')`.

## Checked and fine

**Item 1, one source of truth**:
- `builder.ID_PATTERNS["alert_id"]`, `linter._ID_PATTERNS[0]` and the object `intake` judges with are the same `infra.ids.ALERT_ID_PATTERN`, pinned with `is` by `test_alert_id_source.py`.
- The regex text is byte-identical to the two old copies, and the linter still uses `fullmatch`, so its behaviour is unchanged.
- `is_alert_id` uses `fullmatch`, so the trailing newline that `$` lets through is refused, and a non-`str` value is refused before the regex runs.
- `infra/ids.py` imports only `re` (G1), and `security`→`infra` and `llm`→`infra` are both allowed by the §4 table. `make lint` and `test_import_rules` are green.
- The 400 body is unchanged (`{"detail": {"missing": "id"}}`). The id check still comes before `rule.id` and the heartbeat branch. The only response that changes is a body whose id is off-pattern *and* has no rule: it now says `id` instead of `rule.id`, which is what ruling A implies.
- `gl-TEST-…` is refused, and the real Wazuh and SOAR ids (the fixtures' `gl-01M5…` ones included) still pass.

**Item 1, callers and changed test ids**:
- `intake.receive` has one product caller, the webhook route; the puller and replay have their own insert path.
- The only test ids changed are `_uid` in `test_webhook.py` and `test_webhook_concurrency.py`, two in `test_health.py` and one in `test_pipeline.py`. Each was only a label. The concurrency test's no-rule body keeps exercising the `rule.id` refusal, because its id is now valid; with the old id it would have hit the new `id` refusal instead. So no change of id hides a regression.
- `test_soar_intake_switches` (`1789100000.{n}`), the SOAR fixtures and the e2e fixtures (asserted `^\d+\.\d+$`) already used valid ids.
- The heartbeat-with-bad-id case is tested.

**Item 2, `llm_stopped_by` and visibility**:
- `latest_stopped_by` uses the same `WHERE` / `ORDER BY` / `LIMIT 1` as `_SUGGESTION_SQL`, so it reads the same run. Verifier rows don't count, and it is set before `visibility.strip`.
- The key is in `ANALYST_HIDE`, so a blind, undecided head loses it at the top level. It is also in `LABELING_DENYLIST` (⊇ `ANALYST_HIDE`) and matches the `llm_` prefix, so the labelling page drops it twice.
- The tests prove that a blind head's body holds no `unavailable` value under any key, for tier1, tier2 and admin; that a decision brings the key back; and that a duplicate gets its head's value.
- The queue row is unchanged. Tier 2's views don't carry it. `/admin/knowledge`'s `_alert_view` gets it only for decided alerts, which are visible anyway.
- `aiStateOfView` reads the key only after the suggestion and blind checks.

**Item 3**: ②'s `STOPPED_TEXT["permanent"]` and `S.ai2.stoppedBy` are held equal by `strings.test.ts`. The draft's `llm_permanent` wording covers both a 402 and the 429-exhausted case. The admin table's short word is unchanged and pinned.

**Item 4**: step 1 now merges `director/integration`.
- `main` (ba31def) is an ancestor of 48efabd, and 48efabd of c551dd4.
- `020_learned_knowledge.sql` is the only migration added since `main`, so the 19→20 counts stand.
- Step 4 and `kb_learned/README.md` agree on "writable by `HOST_UID`, `chmod 777` when the checkout user differs", and both explain why not to `chown`. The ATTT-M1 note on the host-side `--rebuild` is consistent with that.

**Item 5(a)**:
- `case_view.last_run` filters `pipeline = 'investigate'`, so the case's `rag_lookup` and `knowledge_draft` rows are excluded.
- `subject_id` is compared as text, but every caller passes a lower-case `str(uuid)`.
- `last_analyzed_at`, `ongoing` and the timeline are unchanged. An older server's answer without `last_run` falls back to the old behaviour.
- A ② retry's committed `transient` row shows as "không có kết quả" until the next attempt. That is documented in the docstring.

**Item 6**: DEC-211 R6 records A = (b), B = (1) and C, after R5, and closes item 9's `gl-TEST` question. The DEC-210 text is untouched.

**Suites I ran on c551dd4**:
- `make test`: 4778 passed, 20 skipped (the same DSN-probe skips as before; nothing was reachable).
- `make lint`: green (env 70 §6.3 keys, schema, output schemas, ruff, black).
- `tsc --noEmit`: 0. `eslint`: 0. `prettier --check`: clean.
- UI tests: 65 files, 3175 passed.

**Not run by me** (they need a database): the DB tests in `test_webhook`, `test_queue`, `test_tier1_api`, `test_case_view_api` and `test_investigation_view_api`. You said you ran the DB suite.

## Re-review (fix round 1)

VERDICT: APPROVE

Scope: 368a4d7..2753203. That is 2665e6a (F1), a36805d (F2 + N6), 690cb15 (F3), f6c0b29 (N4 + N5) and 2753203 (the R6 addendum). Read in my own detached worktree at 2753203. Nothing was committed. One mutation check was reverted with `git checkout`, and the worktree has been removed.

Every ruling is built as ruled. The UTF-16/32 issue the Coder raised is real (R1); it is non-blocking but fits this round. There is one Nit.

### R1. Minor (new; the Coder's question): a JSON body that is not UTF-8 parses, and then gives a 500 or is lost after a 201
- **Real: yes.** `json.loads(body)` on `bytes` (`backend/app/infra/intake.py:116`) detects UTF-8, UTF-16 and UTF-32 and decodes them. Only afterwards does `raw_text = body.decode("utf-8")` run (`:148`, G9). I reproduced it without a DB by calling `intake.receive(None, …)` with a body whose id, rule and timestamp are all valid:
  - **UTF-16 or UTF-32 with a BOM:** every check passes, then `body.decode("utf-8")` raises `UnicodeDecodeError` (byte 0xff). The answer is a 500, and nothing is written, because `Conn` rolls back.
  - **UTF-16-LE or UTF-32-LE without a BOM:** the decode *succeeds*, because the bytes are ASCII plus NULs. The `INSERT INTO intake (… raw_text …)` at `:171` then fails client-side in psycopg with `DataError: PostgreSQL text fields cannot contain NUL (0x00) bytes` (I checked against the installed psycopg 3.3.4). Again a 500 and no row.
  - **UTF-8 with a BOM:** accepted with a 201. `raw_text` keeps U+FEFF. The pipeline's `json.loads(raw_text)` (`soar/pipeline.py:91`) then raises `JSONDecodeError: Unexpected UTF-8 BOM`. So the sender was told 201 and the alert never becomes an alert. I am reasoning about the job's end state; it needs a DB to watch.
- **Does it belong in this round?** Yes, I would take it. It is the same class as F2: an unclean body that becomes a 500 with no rejected row, or a silent loss. It is in the same function, the fix is a few lines, and it uses an existing reason (`not_json`), so no new response shape is needed. It does not block.
- **Suggested fix:**
  - Decode strictly first and parse the text, in the existing `try`: `text = body.decode("utf-8")` and then `doc = json.loads(text)`, with `UnicodeDecodeError` and `JSONDecodeError` giving the existing `not_json` row and 400.
  - Then use `raw_text = text`. That is byte-for-byte G9's `body.decode("utf-8")`, so every valid UTF-8 body is unchanged.
  - `json.loads(str)` also refuses a leading BOM and raw control characters, so all three cases above become `not_json`. RFC 8259 §8.1 requires UTF-8 for JSON sent over a network. Accepting a UTF-8 BOM through `utf-8-sig` would also be lawful, but that is a ruling; refusing it is the simple rule.
  - Tests: the five bodies above, giving 400 `not_json` and one rejected row each.
- **Left out of this fix:** a `\u0000` *escape* inside a JSON string still parses into a NUL. `jsonb` rejects that, so `_insert_rejected`'s `Jsonb(doc)` on a refused body, or the pipeline's jsonb write on an accepted one, would still fail. That is a separate, rarer follow-up, and it needs a DB to confirm the exact error.

### R2. Nit: the timestamp rule is a little looser than the runbook says, and narrower for one exotic number
- Where: `intake._sort_key_of` / `puller._replay_sort_key`, and `docs/runbook.md` "The `timestamp` it takes".
- Python 3.12's `fromisoformat` (the same minor version as the `python:3.12-slim` image) also accepts `"20260920"`, `"2026-W38"` and `"0001-01-01T00:00:00+14:00"`. The last gives a negative sort key. So "not an ISO date-time is refused" means Python's ISO parser, not just the forms Wazuh and SOAR send.
- The other way: a JSON *number* such as `20260920` used to pass through `str()` and give a 201, and is now a 400 (non-string). That is what you ruled, and no real sender sends it.
- No action needed. Optionally, say "what Python's `datetime.fromisoformat` reads" in the runbook.

### Checked and fine (fix round 1)
- **F1:** `ALERT_ID_PATTERN` is compiled with `re.ASCII`. It is still the one object shared by the builder, the linter and intake. The regex text is unchanged, and there is no `\w`, `\s` or `\b` in it that the flag could also change.
  - Tests at all three levels: the id source (bold, fullwidth, Arabic-Indic and mixed ids are refused, and the builder refuses them too), the linter (the look-alike is `free_text`; the real Wazuh and SOAR ids pass), and the webhook (four parametrized cases).
  - Mutation: removing `re.ASCII` makes `test_alert_id_source` and `test_linter` red.
- **F2:**
  - `_sort_key_of` gives `None` for an absent or null timestamp, a non-`str`, and anything that raises `ValueError`, `OverflowError` or `OSError`. I probed the 13 bad values in the tests, plus extreme years.
  - It is called after the `id` and `rule.id` checks and before any write or decode, so the order is `id` → `rule.id` → `timestamp`, which a test pins.
  - It writes a rejected row with reason `timestamp` and raises `Rejected("timestamp")`. The route turns that into the existing `{"detail": {"missing": <reason>}}` shape with its new value.
  - Valid bodies are unchanged. The same sort key comes from the same function, it is no longer passed through `str()`, and `raw_text`, `manager_id` and the heartbeat branch are unchanged.
  - Every other response is byte-identical. A heartbeat or an indexer hit with a bad timestamp is now a 400 instead of a 500.
  - The ISO forms Wazuh and SOAR send are 201 (the control test).
- **N6:** the runbook query now reads `coalesce(raw_payload->>'id', raw_payload->'_source'->>'id')` and groups by both reasons.
- **F3:** the label is "Tín hiệu gần nhất từ nguồn" in the row and in the hint. The test renders both modes' detail strings and forbids `kéo`, `pull` and `alert` in the label.
- **N4:**
  - `list_cases`'s own SQL, `ORDER BY` and `LIMIT`/`OFFSET` are untouched. The only addition is one `DISTINCT ON (subject_id)` read of `investigate` rows for the page's ids, and none when the page is empty.
  - `last_run` is now `last_runs` of one id, so the page and the list cannot disagree. Ids are compared as lower-case `str(uuid)`.
  - `lastAnalysedText` is shared, with each place keeping its own time format, and it falls back for an older server's answer.
- **N5:** `analysedNoResult` is removed, and "không có kết quả" exists only as `S.case.noResult`.
- **R6 addendum:** one line in DEC-211, after R6.
- **Blind arm and visibility:** no visibility, queue or alert-view file changed in this round.

**Suites I ran on 2753203:**
- `make test`: 4784 passed, 20 skipped (the same unreachable default-DSN probes).
- `make lint`: green.
- `tsc`, `eslint`, `prettier`: clean.
- UI tests: 65 files, 3178 passed.

**Not run by me:** the DB-marked webhook and case-list tests. You ran the DB suite.
