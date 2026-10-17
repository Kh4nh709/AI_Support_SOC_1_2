# Admin console v1.1: design spec

- **Date:** 18/10/2026
- **Status:** approved by the Owner on 18/10, recorded as **DEC-200**. Built on branch `director/admin-v1-1` (§9).
- **Decisions:**
  - DEC-159: the admin console's content.
  - DEC-161: the console is v1.1, after the React v1.0 flows.
  - The Owner's four answers of 18/10:
    - LLM limits are editable on the web;
    - the audit log is a page, read-only;
    - failed-job retry and inventory reload live on the overview page;
    - `users.last_login_at` is added.
  - The Owner's approval of 18/10 takes every proposal of §10 as the decision.
  - DEC-200 records this spec. DEC numbering from 200 up was agreed with the other Director session, which holds 126–199.
- **Visual reference:** the claude.ai canvas "SOC Console UI", `https://claude.ai/artifact/MyBdt1oRM9jXUpM1ZLnBNy`.
  - The page artboards are `AdminOverview`, `AdminUsers`, `AdminLlm`, `AdminRules`, `AdminDigest`, `AdminLabels` and `AdminAudit`.
  - `AdminStates` holds every dialog, error, empty and loading state.
  - The canvas carries illustrative data only.
- **Builds on:** the React UI v1.0 spec, `docs/superpowers/specs/2026-09-30-react-ui-v1-design.md`. Its architecture, authentication, client, CSP and test rules apply unchanged unless this spec says otherwise.

## 1. Goal and scope

**Goal.** The admin works entirely in the React UI on port 8080. That means:
- the three new admin areas of DEC-159: users and roles, LLM usage and limits, and the system overview;
- the three Jinja admin pages ported to React: auto-close rules, the daily digest and blind labelling;
- a read-only audit log.

After that, the last Jinja page is retired, and with it the session cookie.

**In v1.1.**
- Seven admin pages under one sidebar (§4).
- The backend additions of §5.
- Retirement of the Jinja admin pages, `/login`, `/logout` and the cookie (§8).

**Not in v1.1.**
- The Tier-2 investigation assistant (DEC-160). It has its own plan. The LLM page shows its row only once its pipeline exists (§4.3).
- Per-permission grants. "Cấp quyền" stays one of three fixed roles (DEC-159 item 1).
- Editing any configuration key other than the three LLM limits of §5.2.
- Audit export, audit retention changes, deleting audit rows. The table stays append-only (migration 017).
- A mobile layout.

**Unchanged.**
- Every role check is server-side through `require_role`. A refusal writes `authz.denied`.
- The blind arm (DEC-101) and blind labelling (DEC-019): `visibility.strip(mode="labeling")` is untouched, and the React labelling page renders only what the API returns.
- The cost guard stays fail-closed. The gold set `gold_v1` stays frozen.
- The CLI `python -m app.infra.auth` stays as the break-glass path for accounts.

## 2. Architecture and deployment

- **Frontend.** The same `frontend/` service, nginx config, CSP and toolchain as v1.0 §2.
  - New feature folder `features/admin/`; new typed client `api/admin.ts`.
  - No new runtime dependency. Charts are plain SVG or CSS bars like the canvas, not a charting library, so the CSP and bundle are unchanged.
- **Backend.**
  - New routers under `backend/app/web/routers/admin_*.py`, each guarded by `require_role("admin")` (`web/deps.py:112`).
  - Every aggregate read runs in a savepoint of the request's transaction (`conn.transaction()`) after `SET LOCAL statement_timeout`. The default is `3s`; a route that needs more says so in its task. `infra/db.transaction()` (`infra/db.py:36`) is not used inside a request: it issues its own `BEGIN`/`COMMIT` and would commit the request's transaction.
- **Migration.** One new file, `docs/Schema/019_admin_console.sql`: the settings table, the new event type (§5.2) and `users.last_login_at` (§5.1). On 18/10, `018` is the last migration on every branch. The Owner applies it with `make migrate PY=.venv/bin/python`. Tests that pin a migration count are updated in the same task.
- **After each backend merge**, the Owner runs `docker compose restart app worker`. The code is bind-mounted, and a compose change needs `up -d` instead.

## 3. Frontend structure, routes, data flow

**Layout.**
- `features/admin/AdminLayout.tsx` is the left sidebar of the canvas, with seven links and the current page marked `aria-current="page"`.
- One file per page: `OverviewPage`, `UsersPage`, `LlmPage`, `RulesPage`, `DigestPage`, `LabelsPage`, `AuditPage`.
- `features/admin/dialogs/` holds the confirmation dialogs. Each is a real `<dialog>` element, or one with `role="dialog"`, with focus trapped and Esc to cancel.
- Shared pieces are reused from `components/`: `DataTable`, `Badge`, `KeyValueGrid`, `LogBlock`, `Toast`, `PageError`.
- New Vietnamese strings go in `strings.ts`, including the hard-block labels now in `web/routers/admin_rules.py:60-66` and the verdict labels in `admin_digest.py:67`.

**Routes.**

| Path | Roles | Notes |
|---|---|---|
| `/admin` | admin | Redirects to `/admin/overview`. |
| `/admin/overview` | admin | §4.1 |
| `/admin/users` | admin | §4.2 |
| `/admin/llm` | admin | §4.3 |
| `/admin/rules` | admin | §4.4 |
| `/admin/digest` | admin | §4.5. `?day=YYYY-MM-DD` is kept in the URL. |
| `/admin/labels` | admin | §4.6 |
| `/admin/audit` | admin | §4.7. The filters are kept in the URL. |

- `RequireRole` turns tier1 and tier2 away exactly as v1.0 does: to `/queue`, with the `ForbiddenNotice` "Bạn không có quyền vào trang đó". The `AdminStates` 403 card is that notice. The API still refuses them on its own and writes `authz.denied`.
- **Header.** "Quản trị (UI cũ)" (`components/AppHeader.tsx:13-42`) is replaced by an in-app "Quản trị" link, admin only.
- **Admin home.** `/` for an admin goes to `/admin/overview` instead of `/cases` (`auth/redirect.ts`, `roleHome`), decision 7.

**Data flow.**
- TanStack Query owns every read. There are no optimistic updates. Every mutation invalidates the queries it touches and shows a toast.
- **Overview:** refetched every 60 s while the tab is visible.
- **LLM page:** refetched every 60 s.
- **Other pages:** fetched on entry and after their own mutations.
- No new WebSocket channel.
- **Errors** follow the v1.0 client (`api/client.ts`).
  - `401` ends the session.
  - `403`, `404`, `409`, `422` and `503` show the server's `detail` where `AdminStates` places it: in the dialog, at the field, or as a toast.
  - A `409` whose `detail` is an object carries a machine-readable `reason`, which `strings.ts` maps to the Vietnamese text.

## 4. Pages

Each page follows its artboard. Its non-default states are the matching section of `AdminStates`. Times are shown in `DISPLAY_TZ` with `format.ts`.

### 4.1 Overview (`AdminOverview`)

`GET /api/admin/overview?range=24h|7d|30d` (§5.4).

- **KPI tiles:**
  - alerts received in range, with the heads after dedup;
  - clusters waiting for Tier 1, with the oldest;
  - open cases;
  - LLM cost this month against the cap.
- **Alerts by day:** heads and duplicates as stacked bars.
- **Processing funnel:** auto-closed, waiting, Tier-1 active, closed by Tier 1, escalated, and ① coverage (`ready / heads`).
- **By source:** `wazuh`, `lab`, and rejected intake.
- **Top agents:** five.
- **System health:** the newest `system_health` row, failing checks first, e.g. "8/10 ổn".
- **Failed jobs.**
  - Columns: `status='failed'`, type, subject, attempts, last error truncated to 200 characters, time.
  - A "Chạy lại" button with a confirmation dialog (§5.4).
- **Inventory.**
  - Active assets, identities and IoCs, and the last load time.
  - A "Nạp lại kiểm kê" button with a confirmation dialog. It calls the existing `POST /api/admin/reload-inventory` (`web/main.py:35`).
  - The result shows the `LoadReport` counts (`enrichment/inventory.py:93`) and its warnings.
  - A `422` shows the file errors and says the database did not change.
- **Each section fails alone.** The API returns `null` plus an error for that section, and the page draws the block error of `AdminStates` while the other blocks render.

### 4.2 Users and roles (`AdminUsers`)

`GET /api/admin/users` and the writes of §5.1.

- **Table:** username, display name, role, status (active, locked until HH:MM, inactive), last login ("chưa đăng nhập" when null) and one action.
  - The action is "Đặt lại mật khẩu" for an active account, "Mở khoá" for a locked one and "Kích hoạt lại" for an inactive one.
  - A row menu also offers "Vô hiệu hoá".
- **Role changes** use the select in the row, then the confirmation dialog: "mọi phiên đang mở bị đăng xuất".
- On the admin's own row, the role select and "Vô hiệu hoá" are disabled. The server still enforces this (§5.1).
- **Read-only matrix of role → function.** It is static text in `strings.ts`, the canvas's nine rows.
- **Create panel:** username, display name, role (three radios with their one-line descriptions), temporary password and its repeat.
  - Client-side checks mirror the server's: the minimum length of 12 (decision 1), and the repeat matching.
  - The password is sent once and never shown again.
- **Search** filters client-side on username and display name. The list is small.

### 4.3 LLM and limits (`AdminLlm`)

`GET /api/admin/llm/usage?range=24h|7d|30d|month` and `PUT /api/admin/llm/limits` (§5.2, §5.3).

- **Tiles:**
  - Cost this month against the cap, with a bar and a linear projection labelled as such. At ≥ 80 % it turns amber; at ≥ 100 % red, with the stopped notice.
  - Calls by pipeline.
  - Tokens in and out.
  - Calls stopped without a result, with the main `stopped_by`.
- **By pipeline and role:** calls, with result, stopped by, latency p50 and p95, cost.
  - Rows: ① proposer, ① verifier, ② investigate.
  - The chat row appears only when `llm_runs.pipeline` admits it. Today the CHECK is `triage|investigate` (`003_jobs_audit_llm.sql:90`), so v1.1 shows no chat row unless DEC-160 lands first.
  - "Tool call: 0" with its sentence (DEC-159 item 2) stays (decision 4).
- **Limits panel.** Three numbers with their effective value and source: "từ .env" or "sửa trên web bởi X lúc Y".
  - "Lưu hạn mức" opens the confirmation dialog listing only the changed values, old → new.
  - Lowering the cap below this month's spend shows the "Vẫn lưu" warning.
  - `422` errors appear at the field.
  - When the API reports the limits as unreadable, the panel is read-only and shows the fail-closed notice.
- **Quota used, by person:** ② runs in the **last 24 hours**, against the per-person limit.
  - This is the rule the server applies today: `tier2_runs._analyze_quota_count` counts `case.analyzed` rows with `created_at > now() - interval '1 day'`.
  - The UI says "24 giờ gần nhất" and never "reset at midnight" (decision 8).
- **Recent calls:** the last 20, as time, pipeline and role, subject, tokens, latency, outcome, cost. The subject links to the alert or case. No prompt or model output is ever returned.

### 4.4 Auto-close rules (`AdminRules`)

Uses the existing `GET|POST|PATCH /api/admin/rules` and `POST /api/admin/rules/simulate`, plus the additions of §5.5.

- **The six hard blocks** are always shown at the top, in `_HARD_BLOCK_ORDER` order.
- **Rules table:**
  - name and reason;
  - conditions as `field op value` chips;
  - the 7-day width warning "⚠ x% > ngưỡng%", shown when the row's `width_pct` is non-null, against `AUTOCLOSE_RULE_WIDTH_PCT`;
  - created time, state, and an enable/disable button with a confirmation dialog.
- **Create in two steps.**
  1. Name, reason and conditions. Conditions are entered through a row builder (field / operator / value) whose choices come from `autoclose._WHITELIST` (`ingest/autoclose.py:55-70`), so an operator a field does not allow cannot be picked.
  2. "Xem trước" calls `simulate`. "Tạo rule" is enabled only for the exact conditions last previewed.
- **Preview:** clusters closed in 30 days, alerts including duplicates, the split by severity and by asset criticality, and up to 20 sample alerts linking to `/alerts/:id`.
  - When `clusters = 0`, the hard-block tally (§5.5) says how many matched clusters each block stopped, or that none matched.
- **States:** no rules; `422` at the condition; `404` on toggle; previewing.

### 4.5 Daily digest (`AdminDigest`)

`GET /api/admin/digest?day=` and `POST /api/admin/digest/{alert_id}/review` (§5.6). Both are already in §6.4 of the context pack; v1.1 implements them.

- **Day picker** and "Hôm nay (đến giờ)". A summary line gives clusters, reviewed, waiting, and ① disagreements.
- **Table:**
  - auto-close rule name, rule id and category, description, severity, agent, occurrences, time span;
  - ①'s suggestion, with "⚠ ① không đề xuất đóng" when `disagreement`;
  - Đúng / Sai / Không chắc.
- **After a review** the row shows the verdict, who reviewed it and when.
  - "Sai" adds "đã mở lại về hàng đợi Tier 1", because `digest.review` reopens it and flags the rule as suspected wrong.
- **States:**
  - no rule enabled;
  - no cluster that day;
  - invalid day (the UI falls back to the default day);
  - `409 already_reviewed` (the row is replaced by the recorded verdict);
  - `409 not_auto_closed` (the buttons are replaced by the sentence);
  - `422`.

### 4.6 Blind labelling (`AdminLabels`)

Uses the existing `GET /api/admin/labels/next` and `POST /api/admin/labels`, plus `POST /api/admin/labels/undo` (§5.7).

- **The current state is frozen.** `eval/gold_v1.sha256` exists (`tier1/labels.py:52`), so the page opens on the frozen state of `AdminStates`: progress 56/56, no labelling and no undo.
- **The labelling screen is still built**, for a future `gold_v2`, exactly as the Jinja page shows it:
  - category, severity, rule and level, cluster id;
  - the representative alert (time, agent, user, source and destination addresses, description);
  - the raw log, with the 32 KB display cut notice;
  - occurrences and span;
  - correlation ±2 h, with rows and collapsible samples;
  - the playbook;
  - label (false_positive / benign / escalate), confidence 1–3, a note of at most 200 characters with a counter;
  - "Lưu nhãn và sang cụm tiếp" and "Hoàn tác nhãn vừa gán".
- **Blindness is the API's job.** The page renders only the fields `next` returns, and adds nothing from any other route.
  - It must not call the alert or queue APIs for the same id.
  - A test asserts that the page's network log contains no other `/api/` call while labelling.
- **States:** frozen, finished, no candidates, `409` frozen on undo, no label chosen.

### 4.7 Audit log (`AdminAudit`)

`GET /api/admin/audit` (§5.8), read-only.

- **Filters:**
  - time range: 24 h, 7 days, 30 days;
  - event group (§5.8);
  - actor, as a username or `system` or `llm`;
  - subject, as an alert, case, rule, user or job id.

  The filters are kept in the URL.
- **Table:**
  - time;
  - the event, as a Vietnamese label from `strings.ts` with the raw `event_type` under it;
  - the actor with a role badge;
  - the subject, linking to its page where one exists;
  - a one-line summary built client-side from the payload, per event type.
- **Rows expand** to show the payload as text in a `LogBlock`.
- **Pagination** is "Trước / Sau" over the API's cursor. The total is shown when the API returns it (§5.8).
- **States:** no match, with "Xoá lọc"; query timeout ("thu hẹp bộ lọc"); loading; error.

## 5. Backend additions for v1.1

Each item is a card: one Coder on Sonnet 5.5 xhigh and one Reviewer (DEC-151). Each card names its red steps.

The changes to the frozen contracts are listed in §5.9 and recorded by DEC-200. Everything else is additive: no existing field or route changes meaning, except the cookie removal of §8.

### 5.1 Users and roles

- **Migration:** `users.last_login_at timestamptz NULL`.
  - `infra/auth.login` sets it to `now()` in the same `UPDATE` that resets `failed_logins` on success (`infra/auth.py:159`).
  - No grant change: `app_rw` holds table-level rights on every table (migration 017, lines 55 and 60).
- **`GET /api/admin/users`** returns `user_id, username, display_name, role, is_active, locked_until, failed_logins, last_login_at, created_at`, ordered by username.
  - It never returns `password_hash`. A test asserts that no key matching `password|hash` is in the response.
- **`POST /api/admin/users`**, with the body `{username, display_name, role, password}`.
  - It calls `infra/auth.create_user` (`infra/auth.py:225`), which gains an optional actor. From the web, the `admin.user_created` row carries `actor_role='admin'` and the admin's `actor_id`; the CLI keeps `'system'` and `NULL`.
  - `201 {user_id}`.
  - `409 {reason: "username_taken"}`.
  - `422` for a role outside `tier1|tier2|admin`, a password under the minimum length, or a username outside `^[a-z0-9._-]{3,32}$`. That pattern admits every current account.
- **`PATCH /api/admin/users/{user_id}`**, with any of `{role, display_name, is_active}`.
  - A change of role, or `is_active → false`, sets `sessions_invalid_before = now()` in the same transaction. Old tokens then die, and the WebSocket closes within 60 s (v1.0 §6).
  - **Guards**, under `SELECT … FOR UPDATE` over the active admin rows, so two concurrent demotions cannot both pass:
    - demoting or deactivating the last active admin → `409 {reason: "last_active_admin"}`;
    - an admin changing their own role or `is_active` → `409 {reason: "self_change"}`.
  - `404` for an unknown id.
  - Writes `admin.user_updated` with `{before, after}` over the changed fields only. It carries no credential.
- **`POST /api/admin/users/{user_id}/password`** with `{password}`.
  - It reuses `set_password`'s hashing.
  - It also sets `sessions_invalid_before = now()` (decision 3).
  - An admin may reset their own password here. It ends their own sessions too, and the dialog says so before the click.
  - Writes `admin.user_updated` with `{action: "password_reset"}`.
  - The password appears in no log line and no audit payload. A test greps the captured logs.
- **`POST /api/admin/users/{user_id}/unlock`** clears `failed_logins` and `locked_until`, and writes `admin.user_updated` with `{action: "unlock"}`.
- **Red steps:**
  - remove the `FOR UPDATE`, run two concurrent demotions, and both succeed;
  - drop the self guard;
  - put the hash in the list response;
  - skip `sessions_invalid_before`, and an old token still works.

### 5.2 Editable LLM limits

- **Migration.**
  - A table `settings`:
    - `key text PRIMARY KEY CHECK (key IN ('LLM_MONTHLY_USD_CAP','ANALYZE_QUOTA_PER_USER_DAY','LLM_TIMEOUT_S'))`;
    - `value integer NOT NULL CHECK (value > 0)`;
    - `updated_at timestamptz NOT NULL DEFAULT now()`;
    - `updated_by uuid NOT NULL REFERENCES users(user_id)`.

    All three keys are integers in `Config` today (`infra/config.py:156-164`). 019 grants `SELECT, INSERT, UPDATE ON settings TO app_rw` explicitly. Migration 017's default privileges bind only the role that ran 017, so a different applying role would otherwise leave `app_rw` with nothing (P11-T01 review, finding 5). A test writes a setting as `app_rw` to prove it.
  - `ck_audit_event_type` gains `admin.settings_changed`. The set goes from 27 to 28 names. `audit/events.py`'s `EVENT_TYPES` and the context pack §6.1 list are updated together.
- **Accessor `infra/settings.py`.**
  - `effective_limits(conn, cfg) -> Limits(cap_usd, quota_per_24h, timeout_s, source)`.
  - A row in `settings` wins. Otherwise the `.env` value from `Config` applies. `source` says which, for each key.
  - It is read on every use: one primary-key read of at most three rows. There is no cache, so a save takes effect on the next call.
- **Fail-closed.** If the read itself fails, the accessor raises `SettingsUnavailable`, and:
  - the adapter treats it like the cap being reached: no socket is opened and the run is `stopped_by='cap'` (`llm/adapter.py:166`);
  - `POST /api/tier2/cases/{id}/analyze` answers `503` "hạn mức không đọc được";
  - the `monthly_cost` health check fails with that detail.

  An absent row is not a failure. It means "not overridden".
- **Every reader moves to the accessor:**
  - the adapter's cap check and timeouts (`llm/adapter.py:138,162,166`);
  - `llm/investigate.py:291,307`;
  - the ② quota (`web/routers/tier2_runs.py:100`);
  - `infra/health.py:183`.

  A test greps for the three key names outside `infra/config.py` and `infra/settings.py` and expects none.
- **`PUT /api/admin/llm/limits`**, with any of the three keys as integers.
  - It validates the bounds of decision 2. In one transaction it upserts the changed keys and writes one `admin.settings_changed` row with `{changes: [{key, old, new}]}`.
  - `200 {effective, source}`. An unchanged body writes nothing.
  - `422 {field, reason}` per invalid key.
- **Red steps:**
  - make the accessor return the `.env` value on a read error: a run that should be refused opens a socket on the fake adapter;
  - write the setting without the audit row;
  - leave one reader on `cfg` directly: the grep test fails.

### 5.3 LLM usage

- **`GET /api/admin/llm/usage?range=`** is read-only, from `llm_runs` and `audit_events`. It returns:
  - `month`:
    - `spent_usd`, by the same query as `audit/llm_runs.py:116`, `created_at >= date_trunc('month', now())`;
    - `cap_usd` (effective);
    - `pct`;
    - `projected_usd`, a linear projection over the elapsed days.
  - `by_pipeline_role`: for each `(pipeline, role)`, `calls`, `with_result` (`result IS NOT NULL`), the `stopped_by` counts, input and output tokens, `latency_ms` p50 and p95 (`percentile_cont`), and `cost_usd`.
  - `quota`: `{limit, window: "24h", users: [{username, used, remaining}]}`, from `case.analyzed` rows, as `_analyze_quota_count`.
  - `recent`: the last 20 runs, as `created_at, pipeline, role, subject_type, subject_id, input_tokens, output_tokens, latency_ms, outcome, cost_usd`.
    - `outcome` is the verdict or conclusion from `result`, or `stopped:<stopped_by>`.
    - It never includes `system_prompt`, `user_message`, `agent_trace` or `result`'s text fields. A test asserts that their keys are absent.
  - `limits`: the `effective_limits` value. `null` plus `limits_error` when unreadable.
  - `tool_calls: 0`.

### 5.4 Overview, failed jobs, retry

- **`GET /api/admin/overview?range=`.** Each section is computed in its own statement with its own timeout. A failing section returns `null` and adds `{section, error}` to `errors[]`; the others still return. The sections:
  - `alerts_by_day`: total, heads and duplicates per day in `DISPLAY_TZ`.
  - `by_source`: alerts and heads per `source`; `rejected` from `rejected_alerts`.
  - `top_agents`: five.
  - `funnel`: counts by alert status, plus `triage_coverage` (`ready`, `unavailable`, `pending` over heads).
  - `cases_open`.
  - `health`: the newest `system_health` row, `{checked_at, ok, checks}` (`infra/health.py`).
  - `failed_jobs`: at most 50 rows with `status='failed'`, as `job_id, job_type, subject_id, attempts, last_error` (truncated to 200 characters) and `locked_at`, newest first.
  - `inventory`: active assets, identities and IoCs, and `max(loaded_at)`.
- **`POST /api/admin/jobs/{job_id}/retry`** is already in §6.4, and v1.1 implements it.
  - Only a `failed` job is retried: `status='pending'`, `attempts=0`, `scheduled_at=now()`, `locked_at=NULL`.
  - Writes `admin.job_retried` with `{job_id, job_type, attempts_before, last_error}`.
  - `404` for an unknown job.
  - `409 {reason: "not_failed"}`.
  - `409 {reason: "already_queued"}` when another job for the same `(job_type, subject_id)` is already `pending` or `running`. The partial unique index `ON jobs (job_type, subject_id) WHERE status IN ('pending','running')` would reject the update anyway; the route answers `409`, not `500`.

### 5.5 Rules: the hard-block tally in the API

- `POST /api/admin/rules/simulate` calls the same `_hard_block_tally` (`web/routers/admin_rules.py:174`) the Jinja preview uses. The function stays in that module, which keeps its `/api/*` routes after §8.
- The `simulate` response gains `hard_block_tally: {matched, blocks: [{code, count}]}` when `clusters == 0`, and `null` otherwise. The labels stay in the UI.
- Each row of `GET /api/admin/rules` gains `width_threshold_pct`, the value of `AUTOCLOSE_RULE_WIDTH_PCT`. That puts the threshold in the response instead of hard-coding it in the UI.
- Both are additive.

### 5.6 Digest JSON API

Built on `tier1/digest.py` (`build`, `review`), which the Jinja page already uses.

- **`GET /api/admin/digest?day=`**: the default day is today in `DISPLAY_TZ`.
  - Returns `{day, today, rules_enabled, rows}`.
  - Each row is `DigestRow` plus `reviewed_by_name` and `reviewed_at` when reviewed.
  - `422` for a malformed day. The UI then falls back, as the Jinja page does.
- **`POST /api/admin/digest/{alert_id}/review`**, with `{day, verdict: correct|wrong|unsure}`.
  - `200 {row, reopened}`.
  - `409 {reason: "already_reviewed", row}`.
  - `409 {reason: "not_auto_closed"}`, from `StaleState` (`tier1/digest.py:59`).
  - `422` for a bad verdict or day.
  - `404` for an alert not in that day's digest.

### 5.7 Labels: undo

- **`POST /api/admin/labels/undo`** calls `labels.undo_last` for the caller.
  - `200 {undone_cluster_id, done, total}`.
  - `409 {reason: "frozen"}` while `FREEZE_MARKER` exists.
  - `404` when the caller has nothing to undo.
- `GET /api/admin/labels/next` gains `frozen` and `candidates_present` if its payload lacks them.
- `_bind` keeps tying the labeller to the token.
- No other field is added to the labelling payload.

### 5.8 Audit log

- **`GET /api/admin/audit?range=&group=&actor=&subject=&cursor=&limit=`.**
  - `limit` defaults to 50, max 100.
  - Ordered by `audit_id` descending. That is insertion order, and the primary key serves it, so no new index is needed.
  - `cursor` is the last `audit_id` seen.
- **Each event** is returned as `audit_id, created_at, event_type, actor_role, actor_username` (joined from `users`, `null` for system and llm), `subject_id`, and `payload`.
- **Payload redaction.** Keys named `password`, `password_hash`, `token`, `secret`, `dsn` or `api_key`, at any depth, are replaced by `"[đã ẩn]"`. Payloads should never carry them (DEC-159 item 6); this is the second layer.
- **`total`** is a `count(*)` under its own short timeout, and `null` when it times out.
- **A query timeout** answers `503 {reason: "timeout"}`.
- **The groups**, defined in one table in the module and mirrored in `strings.ts`:

| Group | Event types |
|---|---|
| users | `admin.user_created`, `admin.user_updated`, `authz.denied` |
| configuration | `admin.autoclose_rule_toggled`, `admin.settings_changed`, `autoclose.reviewed`, `rule.suspected_wrong`, `label.created` |
| alerts and cases | `alert.*`, `tier1.*`, `case.opened`, `case.truncated`, `tier2.concluded` |
| model | `triage.suggested`, `case.analyzed`, `llm.gate_forced`, `llm.builder_violation` |
| system | `job.exhausted`, `admin.job_retried`, `health.alarm` |

- **A test** asserts that every name in `EVENT_TYPES` belongs to exactly one group.

### 5.9 Frozen-contract changes, recorded by DEC-200

| Contract | Change |
|---|---|
| §6.1 schema | new table `settings`; `users.last_login_at`; `ck_audit_event_type` + `admin.settings_changed` (27 → 28) |
| §6.3 config | `LLM_MONTHLY_USD_CAP`, `ANALYZE_QUOTA_PER_USER_DAY`, `LLM_TIMEOUT_S` may be overridden at run time by `settings`; `.env` stays the default |
| §6.4 API, new | `GET\|POST /api/admin/users`, `PATCH /api/admin/users/{id}`, `POST /api/admin/users/{id}/password`, `POST /api/admin/users/{id}/unlock`, `GET /api/admin/llm/usage`, `PUT /api/admin/llm/limits`, `GET /api/admin/overview`, `POST /api/admin/labels/undo`, `GET /api/admin/audit` |
| §6.4 API, implemented as listed | `GET /api/admin/digest`, `POST /api/admin/digest/{alert_id}/review`, `POST /api/admin/jobs/{id}/retry` |
| §6.4 API, additive fields | `simulate` gains `hard_block_tally`; `GET /api/admin/rules` rows gain `width_threshold_pct`; `labels/next` may gain `frozen` and `candidates_present` |
| §6.4 API, removed (§8) | the HTML routes `/login`, `/logout`, `/`, `/admin/rules*`, `/admin/digest*`, `/admin/labels*`; the `Set-Cookie` of `POST /api/auth/login` |

## 6. Security requirements

- **Admin only.** Every route of §5 uses `require_role("admin")`. A test lists the router's routes and asserts each one carries the dependency.
- **Credentials.** No response, log line or audit payload carries a password, hash, token, DSN or key.
  - Passwords travel only in request bodies.
  - The audit API redacts as §5.8.
  - The settings table holds three integers and nothing else.
- **Sessions.**
  - Role change, deactivation and password reset set `sessions_invalid_before`.
  - The WebSocket of an affected user closes within 60 s, the v1.0 rule.
- **The last admin** cannot be removed, by the server's locked check (§5.1).
- **Cost guard fail-closed** as §5.2. A limit change is audited with old and new values, and the cap cannot be set to 0.
- **Read-only aggregates.** Every overview, usage and audit query runs with a statement timeout and a row cap.
- **Labelling stays blind.** The React page shows only `labels/next`'s fields (§4.6).
- **Rendering** follows v1.0 §6:
  - text only, with `dangerouslySetInnerHTML` counted at 0;
  - payloads shown as text in `LogBlock`;
  - the same CSP.

## 7. Testing

- **Backend.** The project's rules apply.
  - A demonstrated red step for every guard (DEC-025/027).
  - Scratch databases named per agent, never `soc_test` (DEC-104), reached through the TCP DSN of DEC-105.
  - The fake LLM adapter only.
  - Each card's red steps are listed in §5.
- **Frontend.** Vitest, React Testing Library and MSW cover:
  - every state in `AdminStates`;
  - every dialog's confirm and cancel;
  - `409` reasons mapped to text;
  - `422` at the field;
  - the read-only limits panel when `limits` is `null`;
  - the labelling page's no-extra-request rule;
  - `RequireRole` for tier1 and tier2;
  - axe on each page;
  - the `dangerouslySetInnerHTML` count.
- **End to end.** Playwright on a scratch stack, as P10-T12:
  1. admin logs in and lands on the overview;
  2. creates a tier1 user, who logs in;
  3. changes that user's role, and the user's open session and socket end;
  4. demoting the last admin gives `409`;
  5. lowers the cap below the month's spend, and the next fake ① run is `stopped_by='cap'`;
  6. previews, creates and disables a rule;
  7. reviews a digest row "Sai", and the alert is back in the Tier-1 queue;
  8. labels one cluster and undoes it on an unfrozen scratch set, then sees `409` once the marker exists;
  9. the audit page shows the events of steps 2–8;
  10. a tier1 user opening `/admin/users` gets the 403 notice, and the API refuses.

## 8. Retiring the Jinja admin pages and the cookie

This runs once the e2e suite is green and the Owner has used the React admin pages.

- **Removed:**
  - the HTML routes of `admin_rules.py`, `admin_digest.py` and `labels.py`, keeping their `/api/*` routes;
  - `pages.py` (`/login`, `/logout`, `/`);
  - the templates and `base.html`;
  - `web/templating.py` if nothing else imports it;
  - the page-only tests in `test_pages_rules.py`, `test_pages_digest.py`, `test_labels.py` and `test_pages_login.py`.
- **The cookie.**
  - `POST /api/auth/login` stops setting it.
  - `deps.read_token` reads only the `Authorization` header.
  - `set_session_cookie` and `clear_session_cookie` are removed.
  - `test_api_login_sets_cookie_and_returns_token` (`test_auth.py:482`) is rewritten to assert there is no `Set-Cookie`.
- **Port 8000** then serves `/api/*`, `/webhook/alerts` and `/health` only.
- **Runbook.** The runbook's admin section points to port 8080.
- **The order.** The cookie goes only when no Jinja page is left. If a port slips, §8 waits; v1.1 never ships two admin UIs.

## 9. Order and process

**Start: 18/10, on the Owner's approval.**

**Base.** v1.0 was not closed on 18/10. P10-T13 and P10-T17 had finished their work, but neither was merged:
- P10-T17's branch `worktree-agent-a78f2124e8255304a`, tip `577ef18`, holds P10-T13's approved tip and P10-T17 with its fix round 1;
- the scoped re-review had said "ready to merge after P10-T13";
- the Director re-read fix round 1 on 18/10 (`24ac3df` escalate race, `0b35556` digest path id, `bd80a2f` docs) and found it correct.

v1.1 therefore starts from `577ef18`, so merging `director/admin-v1-1` lands v1.0's last two cards and v1.1 together.

Baseline on that tip (18/10, scratch PostgreSQL 16):

| Check | Result |
|---|---|
| `make lint` | exit 0 |
| `make test` | 2166 passed |
| DB suite | 1354 passed, 2 failed: the two `test_backup_restore.py` XML cases, because the scratch server has no libxml, as recorded by P10-T17 |
| `make ui-lint` | exit 0 |
| `make ui-test` | 783 passed |

**Order, by dependency.** The plan `docs/superpowers/plans/2026-10-18-admin-console-v1-1.md` holds the tasks.

| Wave | Tasks |
|---|---|
| 1 (backend) | migration 019 · §5.1 users · §5.2 settings, accessor and limits · §5.5 rules · §5.6 digest API · §5.7 labels undo · §5.8 audit · §5.3 LLM usage · §5.4 overview and job retry |
| 2 | the frontend admin shell: layout, routes, `api/admin.ts`, header and home change |
| 3 (one task per page) | overview · users · LLM · rules · digest · labels · audit |
| 4 | e2e suite · §8 retirement · runbook · whole-branch review |

**Process (DEC-201, the Owner, 18/10: "Task nào code nên đưa sub-agent code và sub-agent review độc lập. Bạn chỉ nên là người quản trị").**
- Each coding task goes to a Coder subagent (Sonnet 5.5, xhigh) in its own worktree, then to an independent Reviewer subagent. CHANGES goes back to the same Coder.
- The Director only manages: it writes the briefs, merges approved branches with its own mutation check and the suites, commits each verdict, and keeps STATE.
- At most four agents run at once.
- A whole-branch review by an independent Reviewer closes the build. Its findings go back to Coders until none is left.
- P11-T01 was built by the Director before this ruling (it began as "tự làm và review liên tục", DEC-200 item 7), and it gets the same independent review.
- The Owner fast-forwards `main` to `director/admin-v1-1`, runs `make migrate`, rebuilds `ui`, and restarts `app` and `worker`.
- **Cut order if the build slips:**
  1. axe, kept as a report instead of a gate;
  2. the audit filters beyond time and group;
  3. latency p50/p95 on the LLM page;
  4. the top-agents table.

  §8 is never cut once started.

## 10. Decisions (Owner, 18/10)

The Owner approved the proposals as written.

1. **Minimum password length: 12.** DEC-159 left it to this spec. It applies to the web create and reset routes. The CLI keeps its own rule.
2. **Bounds for the editable limits:**
   - cap: 1–1000 USD per month;
   - ② quota: 1–200 runs per person per 24 h;
   - timeout: 10–600 s.
3. **A password reset also ends the user's sessions.**
4. **"Tool call".** The page shows 0, with the sentence "mô hình không gọi công cụ nào". DEC-159's question about another meaning stays open.
5. **The chat row** of the LLM page appears only when DEC-160's pipeline exists.
6. **Dates:** v1.1 starts on 18/10 (§9).
7. **The admin's home** becomes `/admin/overview` instead of `/cases`.
8. **The ② quota window** stays a rolling 24 h. There is no behaviour change. The canvas card now says "24 giờ gần nhất".
