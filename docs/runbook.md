# Runbook — AI Support SOC v3
This file is P8's deliverable (`docs/plan/prompts/P8.md`): P4-T07 created it with the `## Pilot` section only, and P8 extends it with its own sections (start/stop, env keys, backup/restore, alarms, common failures).

## Pilot

Addressed to the two people who run it — the Owner and the advisor (context pack §11: no agent starts the pilot, seeds an account, or tells the advisor the rule). Every command below is pasted **from the primary checkout** (`/project/project/AI_Support_SOC_1_2`, branch `main`, `.env` present); an agent's worktree has no `.env` and must never be the place these run. Commands, not prose: the seconds are the deliverable (`docs/lab-run-log.md`).

Open one shell for the checks and keep it for the whole pilot:

```bash
cd /project/project/AI_Support_SOC_1_2 && set -a; . ./.env; set +a; echo "${DATABASE_URL:+env ok}"
```

→ `env ok`. Every `psql "$DATABASE_URL"` and `curl … "$INDEXER_URL"` below reads that shell's variables; nothing here restates a value from `.env` (DEC-070). The worker and the app each get their **own** terminal (`make run-worker`, `make run-app`) — they are foreground processes.

### 0 · What this pilot is — and is not

Two analysts work the Tier-1 queue in a browser on `127.0.0.1:8000`: the Owner signed in as `tier1`, the advisor as `tier2`; each also holds an `admin` account, which is P6's labelling account and is not used to decide alerts. Half of the alerts (`EVAL_BLIND_FRACTION=0.5`, chosen per alert by `sha256(alert_id)` at intake, `soar/pipeline.py`) show **no** ① suggestion — the **blind branch** — and the suggestion is removed at the API, not in the page, so no role and no page can see it before the alert is decided; the report (P8) compares decisions **by branch and by person**. Nothing in this pilot is a controlled experiment — architecture §6: *"Thí điểm trực tuyến … là mô tả, không phải kiểm định"* — the numbers are descriptive, and the section that reports them says so in its first sentence.

**Dates.** The pilot runs from the day P4-T05 merges (23/09 evening at the earliest — `docs/plan/tasks/P4/P4-tasks.md` §10 item 5) until P8 closes it. The start day and time are written into `docs/plan/STATE.md` by the Owner (§2 below); no other date counts.

### 1 · Preconditions — each with the command that proves it

Run top to bottom; stop at the first row whose `expected` does not hold. The **in `main` before** column names the task whose merge the row waits for (`git log --oneline main | grep -c 'Merge branch .task/<id>'` → `1`).

| # | check | command | expected |
|---|---|---|---|
| a | `.env` carries a `JWT_SECRET` (in `main` before: P4-T01 ✓ 20/09) | `grep -c '^JWT_SECRET=.\+' .env` | `1`. If `0`: `python3 -c "import secrets; print(secrets.token_hex(32))"` → paste as `JWT_SECRET=<value>` into `.env` — never into `.env.example`, never into chat. Until it is set the login answers `503 auth disabled: JWT_SECRET unset`. Re-run the shell prelude after editing `.env`. |
| b | migrations current | `psql "$DATABASE_URL_OWNER" -Atc "select count(*) from schema_migrations"` | `17`. Less → `make migrate` from the primary checkout, then re-check. |
| c | inventory loaded (DEC-083) | `psql "$DATABASE_URL" -Atc "select (select count(*) from assets), (select count(*) from identities)"` | `4\|2` (`HR-computer`, `IA1803`, `user1-IA1803`, `wazuh.manager`; `root`, `user1`). If `0\|0`: `PYTHONPATH=backend python3 -c "from app.infra.db import connect; from app.enrichment.inventory import load; c = connect(); print(load(c)); c.commit()"` — or `POST /api/admin/reload-inventory` signed in as `admin`. |
| d1 | worker process alive | `pgrep -af 'python3 -m app.web.worker'` | one line ending `-m app.web.worker` (two if `make`'s `sh -c` wrapper is still alive — both are the same worker). None → in its **own terminal**, from the primary checkout: `make run-worker` (leave it running; the puller is the `pull` job the worker enqueues for itself every `PULL_INTERVAL_S=60`). Both were **down from the 16/09 reboot to 19/09** (DEC-089) — this row is not a formality. |
| d2 | puller pulling — cursor advances | `psql "$DATABASE_URL" -Atc "select last_sort, last_pull_at, last_error from source_cursor"` — run it, wait two minutes (`sleep 120`), run it again | `last_pull_at` later on the second run; `last_error` empty (a third field printed blank). A non-empty `last_error` names the indexer problem — fix that, not the worker. |
| d3 | live alerts arriving | `psql "$DATABASE_URL" -Atc "select count(*) from alerts where source='wazuh'"` | rising from **3,941** (the 19/09 figure, unchanged since 15/09). ≈ 3,400 live documents wait in the indexer, so the first minutes after `make run-worker` are catch-up — a jump of thousands is expected, not a fault. |
| d4 | intake drained | `psql "$DATABASE_URL" -Atc "select count(*) from intake where processed_at is null"` | falling to `0` and staying near it (G12: every intake row gets `processed_at` or `error` within 60 s while the worker is alive). |
| e | manager alive — through the indexer, **never the file** (DEC-091) | `curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" "$INDEXER_URL/wazuh-alerts-*/_count" -H 'Content-Type: application/json' -d '{"query":{"term":{"rule.id":"100999"}}}'` | `{"count":N,…}` with `N` rising by **one every 10 minutes** (the heartbeat is a 600 s `full_command` stanza — DEC-068). Run it twice ten minutes apart if in doubt. An exit code `60` means `INDEXER_CA` does not match `INDEXER_URL`; `401` means the read-only account — both are `.env` facts, not pilot facts. |
| f | the seed CLI is in this checkout (in `main` before: P4-T01 ✓ 20/09), then **run block 1f below once** | `PYTHONPATH=backend python3 -m app.infra.auth seed-users --help >/dev/null && echo cli ok` | `cli ok`; then block **1f** prints four `created: <username> (<role>)` lines and exits `0`. |
| f′ | the `users` table shows the four accounts | `psql "$DATABASE_URL" -Atc "select username, role, is_active from users order by 1"` | four rows — one `tier1`, one `tier2`, two `admin` — each `\|t`. |
| g | ① is running (in `main` before: **P3-T10**; live suggestions need **P3-T11**'s live run) | `psql "$DATABASE_URL" -Atc "select count(*) from llm_runs where role='proposer'"` | `> 0`, and rising as the worker's `triage` handler drains the pending `triage` jobs. **If `0` the pilot can still start** — every alert then reads *"Chưa có gợi ý ①"* and the blind branch measures nothing yet; say so in `STATE.md` beside the start time, and P8 dates the ① coverage from the first `llm_runs` row. |
| h | the app is up (in `main` before: P4-T04 for `/login`, **P4-T05** for `/queue` and `/alerts/{id}` — the pilot cannot start without T05) | in its **own terminal**, from the primary checkout: `make run-app 2>&1 \| tee -a ~/pilot-app.log` — then, in the checks shell: `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/login` | `200`. The `tee` keeps uvicorn's access log for §7 (the `409` count); `~/pilot-app.log` is outside the repository on purpose. |
| h′ | the app loaded `JWT_SECRET` | `curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8000/api/auth/login -H 'Content-Type: application/json' -d '{"username":"precheck-nobody","password":"x"}'` | `401` (invalid credentials for a user that does not exist — it counts against no account). `503` means the app was started before row **a** was done: restart it. |

**Block 1f — the seed command** (row **f**; once, from the primary checkout; `.env`'s `DATABASE_URL` is the `app_rw` DSN, and migration 017 lets it insert into `users`):

```bash
PYTHONPATH=backend python3 -m app.infra.auth seed-users --env-file .env \
  --user <OWNER_T1_USERNAME> tier1 "<Owner display name>" \
  --user <ADVISOR_T2_USERNAME> tier2 "<Advisor display name>" \
  --user <OWNER_ADMIN_USERNAME> admin "<Owner display name>" \
  --user <ADVISOR_ADMIN_USERNAME> admin "<Advisor display name>"
```

**Each password is typed at the `password for <username>:` prompt the CLI opens** (`getpass`) — never on the command line, and never as an inline `SEED_PASSWORD_<USERNAME>` assignment in front of the command: that lands in shell history (Director at E5, DEC-095; the env form exists for non-interactive tests only). A re-run prints `exists, skipped: <username>` four times and changes nothing (an existing hash is never overwritten). The four usernames must stay distinct after upper-casing with `-` → `_` — the CLI refuses a collision. The two `admin` accounts are P6's labelling accounts (26–27/09); write the four usernames into `STATE.md`'s "20/09 — KIỂM 2/2" line.

Rows **a–f′** can be done today; **g** waits for P3-T10; **h** waits for P4-T05 and is the last thing before §2.

### 2 · The start — one action

The Owner opens `http://127.0.0.1:8000/login`, signs in with the `tier1` account, opens the first alert in the queue, presses **"Tiếp nhận"**, and decides it (*"Dương tính giả"* / *"Lành tính"* with a reason, or escalates). **That first decision is the pilot start.** Write the date and time (`date '+%F %T'` in the checks shell) into `docs/plan/STATE.md` under the P4 phase row, commit from the primary checkout — nothing else counts as the start: not `make run-app`, not the login, not a decision by the advisor.

### 3 · The rule for the advisor — say it aloud, before the first alert

Vietnamese: **"Quyết trước; không bao giờ mở `llm_runs`, không hỏi ① đã nói gì, trước khi bấm quyết định. Khoảng một nửa alert không hiện gợi ý — đó là thiết kế, không phải lỗi."**

English: **"Decide first; never open `llm_runs` or ask what ① said before you press decide. About half the alerts show no suggestion — by design, not a bug."**

The same rule binds the Owner. The consequence (the Director's incident table, `docs/plan/prompts/director.md`): an alert whose ① output was seen before it was decided — in `llm_runs`, in a digest, in a chat — has its decision **discarded from the blind-branch analysis**, and the case is recorded in a DEC. Say when it happens; it is a recorded exclusion, not a fault.

### 4 · What day 1 looks like — and why nobody "fixes" it

- **(a) The queue opens with the 383 replayed heads** (`replay` 307 + `wazuh` 76 at 19/09). Every one was enriched **before** the inventory was loaded on 15/09, so all 383 carry `asset = unknown` / `lookup_status.asset = not_found`, and G8′'s asset block pinned every one of them to the queue (DEC-083 — enrichment is written at the A5/A6 edge and there is no `queued_tier1 → enriching` transition, so no supported path changes it). They are **real alerts with a known enrichment gap**: decide them normally, on what the raw log and the correlation say. **Do not re-enrich, do not delete, do not skip them.** P8 names them as a limitation and reports them in or out per its chapter (§6).
- **(b) New live alerts are enriched correctly** (the inventory has been loaded since 15/09) — and ≈ **79 %** of them come from one Windows endpoint, `HR-computer` (SCA / EventChannel noise; 79.4 % of the 14/09 sample — DEC-066). This is the estate, not a defect, and it is **not a reason to add a filter** (`docs/plan/prompts/planner-run-P4-2026-09-19.md` §2): a filtered pilot would measure the filter. Decide the noise as noise — that is what the false-positive half of the evaluation is for.
- **(c) The risk column is a band, never a number** — Thấp · Vừa · Cao · Rất cao (`docs/phase-4-enrichment.md:198-207`), shown with the alert's own severity. The score is not on the page by design.
- **(d) ⚑ beside a suggestion** means the gate forced the verdict (`gate.forced`; the detail page says which step, *"cổng đã ép: …"*). Expected on this corpus: the 383 heads all miss `asset_criticality`, so ① on them is forced to `needs_review` — the gate working, not ① failing.
- **(e) *"Gợi ý ① ẩn — nhánh mù"*** on a detail page is the blind branch: whatever ① said — or has not yet said — about that alert is hidden until it is decided, and so is whether ① ran at all (`triage_status` and `run_id` are stripped with the suggestion — DEC-101). *"Chưa có gợi ý ①"* appears only on the visible branch and means ① has not run on that alert yet (row **g**). In the queue the ① column shows `—` in both cases.

### 5 · Daily checks — two minutes, each morning

In the checks shell (prelude from the top of this section already run):

| check | command | expected | when it is off |
|---|---|---|---|
| ① ran in the last day | `psql "$DATABASE_URL" -Atc "select count(*) from llm_runs where created_at > now() - interval '1 day' and role='proposer'"` | `> 0` | flat at `0` → the worker's `triage` handler is not wired or the worker is down: `pgrep -af app.web.worker`; if alive, check P3-T10 is in `main` and restart the worker. |
| queue shape | `psql "$DATABASE_URL" -Atc "select triage_status, count(*) from alerts where status='queued_tier1' group by 1"` | mostly `ready`; `pending` shrinking | `pending` growing for a day → same as the row above. `unavailable` rows are alerts on which ① gave up (retries exhausted, budget cap, linter stop — P3-T10) — read why with `psql "$DATABASE_URL" -Atc "select stopped_by, count(*) from llm_runs where role='proposer' and result is null group by 1"` and `psql "$DATABASE_URL" -Atc "select last_error from jobs where job_type='triage' and status='failed' order by created_at desc limit 5"`; do not re-queue by hand. |
| decisions happened | `psql "$DATABASE_URL" -Atc "select count(*) from audit_events where event_type='tier1.decided' and created_at > now() - interval '1 day'"` | `> 0` on a pilot day | `0` → nobody decided yesterday; note the gap in `STATE.md`, do not backfill. |
| intake drained | `psql "$DATABASE_URL" -Atc "select count(*) from intake where processed_at is null"` | ≈ `0` | growing → worker down → `make run-worker` in its terminal (row **d1**); it catches up on its own. |
| manager heartbeat | the `_count` of row **e** | rising by one every 10 minutes | flat → the manager or its `full_command` stanza stopped; a manager-side fact for the Owner (context pack §11), not a pilot fault. Decisions continue on what is queued. |
| puller errors | `psql "$DATABASE_URL" -Atc "select count(*) from source_cursor where last_error is not null"` | `0` | `1` → `psql "$DATABASE_URL" -Atc "select last_error from source_cursor"` names the indexer problem (certificate, credentials, index missing); fix `.env` or the indexer, restart the worker. |

### 6 · What P8 excludes from the pilot numbers — and why

P8's export (`eval/pilot_export.py`) excludes these **itself**; the Owner does not keep them out by hand, does not skip them, and does not decide them differently:

- **`source='lab'` rows** — the 22–24/09 lab scenarios on the same host, retagged after each run by `eval/lab_tag.py` from the seconds in `docs/lab-run-log.md` (DEC-085). They are G2's, not the pilot's. Decide them like any other alert if they reach the queue during the pilot; the tag separates them later.
- **Reopened alerts** — any alert with an `alert.reopened` audit event: the ① verdict was visible in the digest before the second decision, so it is blind no longer, and P8 drops it from the blind-branch agreement metric (P4 planning decision 7).
- **The 383 pre-inventory heads** (§4 a) — a named limitation; P8's chapter says whether they are in or out of each table, with the sentence attached.
- **Decisions on the visible branch** are reported as *"có thể thiên lệch"* (`docs/chot-v3-14-ngay.md` §A3; architecture §6): the analyst saw ① before deciding. They are counted, per person, and labelled — never pooled with the blind branch.

### 7 · Limitations of this pilot, stated

- **The session cookie is not `Secure`** — the app binds `127.0.0.1:8000` without TLS (`Makefile` `run-app`), so `soc_session` is `HttpOnly`, `SameSite=Lax`, `Secure` off; and there is no CSRF token beyond `SameSite=Lax`. Acceptable for two users on one host; stated for the record (P4 planning decision 8).
- **`REVIEW_DELTA_TOLERANCE=20`** and **`RETRIAGE_FACTOR=10` / `RETRIAGE_ABS_DELTA=200`** are unvalidated v1 constants. The pilot's evidence about them is the number of `409` conflicts on decide. They are **not audited** — `select count(*) from audit_events where event_type='authz.denied'` counts refused roles, not conflicts — so count them from the app log kept by row **h**: `grep -c ' 409 ' ~/pilot-app.log`. Note the number in `STATE.md` at the end of the pilot.
- **The two analysts are the author and the advisor** (`docs/chot-v3-14-ngay.md` §A3): the blind branch controls what they see, not who they are.
- The day-1 queue (§4 a) and the `HR-computer` share of the live stream (§4 b) are limitations of the same pilot and are listed with these in P8 (`P4-tasks.md` §11 item 4).

### 8 · Stop / rollback

- **Pause or stop the pilot:** `Ctrl-C` in the `make run-app` terminal stops the UI and nothing else. **Leave the worker running** — it keeps ingesting and ① keeps running, and both are wanted for the lab (22–24/09) and for P8's export. To resume, `make run-app` again (row **h**) — sessions survive a restart (they are tokens checked against `users`, not server memory).
- **Nothing in P4 needs a rollback of data.** Every decision is one `tier1.decided` audit row (append-only) plus a status the state machine owns; a wrong decision is corrected the way the design says — reopen when the state machine allows it, or a note in the DEC — never by an `UPDATE`.
- **Stop the worker only for the host**, never for the pilot: `Ctrl-C` in its terminal; `make run-worker` brings it back and the puller resumes from `source_cursor.last_sort` (row **d2**).
