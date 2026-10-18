# Admin console v1.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **This build (DEC-201):** subagent-driven. One Coder subagent (Sonnet 5.5, xhigh, isolated worktree) and one independent Reviewer subagent per task. The Director manages from `../AI_Support_SOC_1_2-admin-v1-1`, branch `director/admin-v1-1`: it dispatches, merges and keeps STATE. P11-T01 was built by the Director before DEC-201 and is reviewed the same way.

**Goal:** The admin does all of their work in the React UI on port 8080. This covers seven admin pages, their backend routes, and the retirement of the last Jinja pages and the session cookie.

**Architecture:**
- Backend: new admin routers under `backend/app/web/routers/`, discovered by `iter_routers()`, each guarded by `require_role("admin")`.
  - One migration, `019_admin_console.sql`.
  - One fail-closed accessor, `infra/settings.py`, for the three editable LLM limits.
- Frontend: a `features/admin/` folder with a shared `AdminLayout` and one page per artboard, reading typed functions in `api/admin.ts` through TanStack Query.

**Tech Stack:**
- Backend: Python 3.12 (`/project/project/AI_Support_SOC_1_2/.venv`), FastAPI 0.141, psycopg 3, PostgreSQL 16.
- Frontend: React 19, react-router 7, TanStack Query 5, Tailwind 4, Vitest, MSW, Playwright.

**Spec:** `docs/superpowers/specs/2026-10-18-admin-console-v1-1-design.md` (DEC-200). Read it with this plan.

## Global Constraints

**Backend**
- Use `Conn` from `web/deps.py`, never a raw `Depends(get_conn)`. It keeps `scope="function"`, so a 2xx means committed.
- A write that must survive a 4xx is `conn.commit()`ed before the raise.
- Every new admin route takes `claims: Admin`, where `Admin = Annotated[Claims, Depends(require_role("admin"))]`.
- An `{alert_id}` path parameter is `deps.AlertId`, and a `{user_id}` or `{job_id}` parameter is typed (`uuid.UUID`, `int`), so a malformed id is a 422 before any SQL.
- Audit rows go through `audit/events.write_event`. An event type must be in `EVENT_TYPES` and in `ck_audit_event_type`.
- `infra/*` imports nothing from `app.*` outside `infra` (G1, `test_import_rules.py`).

**Tests**
- DB tests carry `@pytest.mark.db`.
- The database is `TEST_DATABASE_URL=postgresql://soc@127.0.0.1:55611/soc_admin11_test`: a private scratch PostgreSQL 16 (pgserver), started TCP-only with trust auth, never the live cluster.
- Tests never read `.env`. Use the fake LLM adapter only.
- Every guard is shown red once (DEC-025/027).

**Copy and rendering**
- Copy is Vietnamese and lives in `frontend/src/strings.ts`.
- Times are shown through `format.ts` in `Asia/Ho_Chi_Minh`.
- `dangerouslySetInnerHTML` count stays 0 (`guards.test.ts`). No new runtime npm dependency, and the CSP is unchanged.

**Values**
- Password minimum length: **12** (web create and reset).
- Limit bounds: `LLM_MONTHLY_USD_CAP` 1–1000, `ANALYZE_QUOTA_PER_USER_DAY` 1–200, `LLM_TIMEOUT_S` 10–600, all integers.
- The ② quota window is a rolling 24 h (`created_at > now() - interval '1 day'`). The UI says "24 giờ gần nhất".

**Commands** (run in the worktree, with `PY=/project/project/AI_Support_SOC_1_2/.venv/bin/python`):

| Command | Expected |
|---|---|
| `make lint PY=$PY` | exit 0 |
| `make test PY=$PY` | exit 0 |
| `TEST_DATABASE_URL=… make test-db PY=$PY` | only the two known `test_backup_restore.py` XML failures (no libxml in pgserver) |
| `make ui-lint` | exit 0 |
| `make ui-test` | exit 0 |
| `make ui-build` | exit 0 |

**Commits.** Each commit is prefixed `P11-Txx:`, adds explicit paths only, and carries the session's attribution lines.

## Review Focus

1. **Two admins act at once.**
   - A demotes B while B demotes A, or both demote the third admin. At least one active admin must remain: one request gets `409 last_active_admin`. (P11-T02, concurrent test on committed data.)
2. **The limits cannot be read.**
   - The settings table is missing (code deployed before `make migrate`) or the read fails.
   - No LLM socket may open: ① is `stopped_by='cap'` and ② answers 503. Nothing silently falls back to `.env`. (P11-T03, red step.)
3. **Hostile text in an audit payload or a log.**
   - Markup, control characters, a 1 MB string, a nested `password` key: rendered as text, the key redacted, nothing executed. (P11-T09 redaction test; P11-T17 render test.)
4. **A digest day at the time-zone edge.**
   - An alert closed at 23:59 local is on that day, and one at 00:00 on the next. A malformed or impossible day (`2026-02-30`) is a 422, never a 500. (P11-T07.)
5. **Blind labelling stays blind in React.**
   - While labelling, the page makes no `/api/` request other than `labels/next`, `labels` and `labels/undo`. No field outside `VIEW_KEYS` is rendered. (P11-T16, MSW request log.)

---

## Wave 1 — backend

### P11-T01: Migration 019 (settings, last login, event type)

**Files:**
- Create `docs/Schema/019_admin_console.sql`.
- Modify `docs/Schema/schema.sql` (regenerated by `build_schema.py`).
- Modify `backend/app/audit/events.py` (`EVENT_TYPES`, 28 names).
- Modify every test pinning the migration list or the 27-name set (find them with `grep -rln "018_alerts_notify\|27" backend/tests`).
- Modify the context pack's §6.1 event list (`grep -rn "label.created" docs/plan/*.md`).
- Test: `backend/tests/test_schema_v3_019.py`.

**Interfaces:**
- Produces:
  - table `settings(key text PK, value integer NOT NULL CHECK (value > 0), updated_at timestamptz NOT NULL DEFAULT now(), updated_by uuid NOT NULL REFERENCES users(user_id))`, with key CHECK over the three names;
  - `users.last_login_at timestamptz NULL`;
  - event type `admin.settings_changed`.

- [ ] **Step 1:** Write `test_schema_v3_019.py` (db):
  - `settings` rejects an unknown key, `value <= 0` and a missing `updated_by`, and accepts an upsert by `app_rw`;
  - `users.last_login_at` exists and is nullable;
  - `ck_audit_event_type` accepts `admin.settings_changed` and still rejects `admin.nonsense`;
  - `EVENT_TYPES` equals the CHECK's set, read from `pg_constraint`.
- [ ] **Step 2:** Run it: it fails, because there is no migration.
- [ ] **Step 3:** Write `019_admin_console.sql` in the house style:
  - a header comment;
  - `BEGIN`/`COMMIT` handled by `migrate.sh`, so check how 018 does it;
  - for the CHECK, `ALTER TABLE audit_events DROP CONSTRAINT ck_audit_event_type, ADD CONSTRAINT … CHECK (event_type IN (… 28 names …))`.
- [ ] **Step 4:** Regenerate `schema.sql`, update `EVENT_TYPES` and the pinned counts and lists, then run the new test and the schema tests: all green.
- [ ] **Step 5:** Red step: drop `admin.settings_changed` from the migration's list; the CHECK test fails. Restore it.
- [ ] **Step 6:** Run lint, `make test` and the DB suite, then commit.

### P11-T02: Users and roles API

**Files:**
- Modify `backend/app/infra/auth.py`:
  - `login` stamps `last_login_at`;
  - `create_user(..., actor_id=None)`;
  - new `admin_set_password` and `unlock`.
- Create `backend/app/web/routers/admin_users.py`.
- Test: `backend/tests/test_admin_users.py`.

**Interfaces:**
- Consumes `deps.Conn`, `deps.require_role`, `write_event`.
- Produces these routes:

| Route | Answers |
|---|---|
| `GET /api/admin/users` | `{users: [UserRow]}`, where `UserRow` is `{user_id, username, display_name, role, is_active, locked_until, failed_logins, last_login_at, created_at}` |
| `POST /api/admin/users` | body `{username, display_name, role, password}` → `201 {user_id}`; `409 {reason:"username_taken"}`; `422` |
| `PATCH /api/admin/users/{user_id}` | body ⊆ `{role, display_name, is_active}` → `200 UserRow`; `409 {reason:"last_active_admin"\|"self_change"}`; `404` |
| `POST /api/admin/users/{user_id}/password` | body `{password}` → `204`; `404`; `422` |
| `POST /api/admin/users/{user_id}/unlock` | `204`; `404` |

- `PASSWORD_MIN_CHARS = 12` and `USERNAME_RE = r"^[a-z0-9._-]{3,32}$"` live in the router module.

- [ ] **Step 1:** Write the tests:
  - list shape, and no key matching `password|hash`;
  - create, then the `admin.user_created` row has `actor_role='admin'` and the admin's id;
  - duplicate username is 409;
  - short password, bad role and bad username are each 422;
  - PATCH role writes `admin.user_updated` `{before, after}` and sets `sessions_invalid_before` (a token issued before it fails `auth.verify`);
  - PATCH `is_active=false` the same;
  - PATCH display_name only does not touch the sessions;
  - self change is 409;
  - last active admin is 409;
  - a **concurrent** case on committed data: two connections each demote a different admin of two, and exactly one succeeds;
  - reset password: the new one works, the old token dies, the password is in no audit payload and no captured log;
  - unlock clears both columns;
  - `login` stamps `last_login_at`;
  - every route answers 403 to tier1, with `authz.denied` written.
- [ ] **Step 2:** Run: every test fails (no routes).
- [ ] **Step 3:** Implement. The guard in PATCH runs in one transaction:
  1. `SELECT user_id FROM users WHERE role='admin' AND is_active FOR UPDATE`;
  2. if the target is an active admin and the change removes admin or deactivates, and the count is 1, answer 409.

  The target row is read `FOR UPDATE` first. Unknown id is 404.
- [ ] **Step 4:** Run the tests: green.
- [ ] **Step 5:** Red steps, each shown failing, then restored:
  - (a) drop `FOR UPDATE`: the concurrent test fails;
  - (b) drop the self guard;
  - (c) add `password_hash` to the list select;
  - (d) skip `sessions_invalid_before` on a role change.
- [ ] **Step 6:** Suites, then commit.

### P11-T03: Editable LLM limits, fail-closed

**Files:**
- Create `backend/app/infra/settings.py`.
- Modify:
  - `backend/app/llm/adapter.py`: a `limits` callable replaces the reads of `cfg` for cap and timeout;
  - `backend/app/tier1/triage.py:666` and `backend/app/tier2/investigate.py:430`: pass `limits=`;
  - `backend/app/llm/investigate.py:291,307`;
  - `backend/app/web/routers/tier2_runs.py:100`;
  - `backend/app/infra/health.py:183`.
- Create `backend/app/web/routers/admin_llm.py` (the `PUT` here; the `GET` usage is P11-T04).
- Tests: `backend/tests/test_settings.py`, `backend/tests/test_admin_llm_limits.py`.

**Interfaces:**
```python
# infra/settings.py
KEYS = ("LLM_MONTHLY_USD_CAP", "ANALYZE_QUOTA_PER_USER_DAY", "LLM_TIMEOUT_S")
BOUNDS = {"LLM_MONTHLY_USD_CAP": (1, 1000), "ANALYZE_QUOTA_PER_USER_DAY": (1, 200), "LLM_TIMEOUT_S": (10, 600)}
class SettingsUnavailable(Exception): ...
@dataclass(frozen=True)
class LimitSource:
    source: Literal["env", "web"]
    updated_at: datetime | None
    updated_by: str | None   # user_id
@dataclass(frozen=True)
class Limits:
    cap_usd: int
    quota_per_24h: int
    timeout_s: int
    sources: dict[str, LimitSource]   # by key name
def from_config(cfg: Config) -> Limits: ...                       # every source "env"
def effective_limits(conn: psycopg.Connection, cfg: Config) -> Limits: ...  # raises SettingsUnavailable
```
- `DeepSeekAdapter(cfg, *, limits: Callable[[], Limits] | None = None, ...)`. `None` means `from_config(cfg)`.
  - In `complete()`, a `SettingsUnavailable` from `limits()` raises `LLMBudgetExceeded("limits unreadable — fail closed")`.
- `PUT /api/admin/llm/limits` takes a body with optional integer keys `cap_usd`, `quota_per_24h`, `timeout_s`.
  - `200 {limits: LimitsOut}`, with `LimitsOut = {cap_usd, quota_per_24h, timeout_s, sources: {key: {source, updated_at, updated_by_name}}}`.
  - `422 {field, reason: "not_integer"|"out_of_range", min, max}`.
  - `503 {reason: "limits_unavailable"}`.

- [ ] **Step 1:** Tests:
  - `effective_limits` with no rows equals `from_config`;
  - one row overrides one key and sets its source to `web`;
  - the read runs in a savepoint, so a missing table raises `SettingsUnavailable` and leaves the caller's transaction usable (pin with a following `SELECT 1`);
  - the adapter with `limits` raising never calls the client (a fake client counting calls) and raises `LLMBudgetExceeded`;
  - the adapter uses `limits().timeout_s` for the deadline and `limits().cap_usd` for the cap;
  - analyze's quota uses the override, and answers 503 when unreadable;
  - health `monthly_cost` uses the override, and fails with "không đọc được hạn mức" when unreadable;
  - PUT bounds, non-integer (`"30"` and `30.5` are both 422), an empty body writes nothing, a change writes one `admin.settings_changed` with `{changes:[{key, old, new}]}`, and an unchanged value is not in `changes`;
  - the grep guard: no `\.(LLM_MONTHLY_USD_CAP|ANALYZE_QUOTA_PER_USER_DAY|LLM_TIMEOUT_S)\b` in `backend/app/**/*.py` outside `infra/config.py` and `infra/settings.py`.
- [ ] **Step 2:** Run: red.
- [ ] **Step 3:** Implement. The accessor reads `SELECT key, value, updated_at, updated_by FROM settings` inside `with conn.transaction():`, so it is a savepoint when nested. Any `psycopg.Error` becomes `SettingsUnavailable`.
- [ ] **Step 4:** Green.
- [ ] **Step 5:** Red steps:
  - the accessor returns `from_config` on error: the fake-client test sees a call;
  - the PUT writes the row without the event;
  - one reader is put back on `cfg`: the grep guard fails.
- [ ] **Step 6:** Suites, then commit.

### P11-T04: LLM usage API

**Files:** modify `backend/app/web/routers/admin_llm.py`. Test: `backend/tests/test_admin_llm_usage.py`.

**Interfaces:** `GET /api/admin/llm/usage?range=24h|7d|30d|month` returns:
```
{ range, month: {spent_usd, cap_usd|null, pct|null, projected_usd},
  by_pipeline_role: [{pipeline, role, calls, with_result, stopped: {<stopped_by>: n}, input_tokens, output_tokens,
                      latency_p50_ms, latency_p95_ms, cost_usd}],
  quota: {limit|null, window: "24h", users: [{username, display_name, used, remaining|null}]},
  recent: [{run_id, created_at, pipeline, role, subject_type, subject_id, input_tokens, output_tokens, latency_ms,
            outcome, cost_usd}],
  limits: LimitsOut|null, limits_error: string|null, tool_calls: 0 }
```
- `outcome`: for triage, `result->>'suggested_action'`; for investigate, `result->>'suggested_conclusion'`; otherwise `stopped:<stopped_by>`, or `null`.
- A bad `range` is 422.

- [ ] **Step 1:** Tests:
  - seeded `llm_runs` across pipelines and roles give the right counts, p50/p95 and cost;
  - range filters by `created_at`;
  - `recent` holds at most 20 rows, newest first, and none of `system_prompt|user_message|agent_trace|result` appears as a key anywhere in the response;
  - quota counts only the last 24 h of `case.analyzed` per user;
  - unreadable limits give `limits: null` plus `limits_error`, with the rest still served;
  - non-admin is 403.
- [ ] **Step 2:** Red, then implement. Aggregates run in a savepoint (`conn.transaction()`) after `SET LOCAL statement_timeout = '5s'`; never `infra/db.transaction()` inside a request (it issues BEGIN/COMMIT).
- [ ] **Step 3:** Green, then the red step: select `result` into `recent` and the key test fails.
- [ ] **Step 4:** Suites, then commit.

### P11-T05: Overview API and job retry

**Files:** create `backend/app/web/routers/admin_overview.py`. Test: `backend/tests/test_admin_overview.py`.

**Interfaces:**
- `GET /api/admin/overview?range=24h|7d|30d` returns `{range, errors: [{section, error}], alerts_by_day, by_source, top_agents, funnel, cases_open, health, failed_jobs, inventory}`. Each section is `null` when its query failed.
  - `alerts_by_day`: `[{day, total, heads, duplicates}]`.
  - `by_source`: `{rows: [{source, alerts, heads}], rejected}`.
  - `top_agents`: `[{agent_name, alerts}]`, at most 5.
  - `funnel`: `{by_status: {status: n}, triage: {ready, unavailable, pending, none}}`.
  - `waiting`: `{count, oldest_received_at}` — heads in `queued_tier1`, not synthetic, not limited by the range (added in P11-T05 fix round 1).
  - `cases_open`: `int`.
  - `health`: `{checked_at, ok, checks}`, or `null` when no row exists yet.
  - `failed_jobs`: `[{job_id, job_type, subject_id, attempts, last_error, locked_at, created_at}]`, at most 50, ordered by the last attempt (`COALESCE(locked_at, created_at) DESC, job_id DESC`).
  - `inventory`: `{assets, identities, iocs, loaded_at}`.
- `POST /api/admin/jobs/{job_id}/retry` (`job_id: int`):
  - `200 {job_id, status: "pending"}`;
  - `404`;
  - `409 {reason:"not_failed"|"already_queued"}`.

- [ ] **Step 1:** Tests:
  - each section on seeded data;
  - the day bucket follows `DISPLAY_TZ`;
  - one section forced to fail (monkeypatch its function to raise) leaves `null`, an `errors` entry, and the other sections intact;
  - failed jobs truncate `last_error` to 200 characters;
  - retry moves a failed job to pending with `attempts=0` and writes `admin.job_retried`;
  - retry of a pending job is `409 not_failed`;
  - retry while a sibling is pending is `409 already_queued`, with no 500 and the job unchanged;
  - unknown id is 404;
  - non-admin is 403.
- [ ] **Step 2:** Red, then implement. Each section runs in its own savepoint (`conn.transaction()`) with `SET LOCAL statement_timeout`; never `infra/db.transaction()` inside a request.
- [ ] **Step 3:** Green, then the red step: drop the sibling check and the test sees a 500 (UniqueViolation).
- [ ] **Step 4:** Suites, then commit.

### P11-T06: Rules API additions

**Files:** modify `backend/app/web/routers/admin_rules.py`. Test: add to `backend/tests/test_pages_rules.py` (its API section).

**Interfaces:**
- `POST /api/admin/rules/simulate` gains `hard_block_tally: {matched, blocks: [{code, count}]} | null`. It is non-null only when `clusters == 0`, ordered as `_hard_block_tally` returns.
- `GET /api/admin/rules` rows gain `width_threshold_pct: int`.

- [ ] **Step 1:** Tests:
  - a rule matching only hard-blocked rows gives `clusters 0` and the tally counts;
  - a rule matching nothing gives `matched 0`;
  - a rule that closes rows gives `hard_block_tally: null`;
  - the threshold equals the config value.
- [ ] **Step 2:** Red, implement, green.
- [ ] **Step 3:** Red step: always return `null` and the tally test fails.
- [ ] **Step 4:** Commit.

### P11-T07: Digest JSON API

**Files:** modify `backend/app/web/routers/admin_digest.py`; modify `backend/app/tier1/digest.py` only if a reviewer-name join is needed there. Test: `backend/tests/test_admin_digest_api.py`.

**Interfaces:**
- `GET /api/admin/digest?day=YYYY-MM-DD` returns `{day, today, rules_enabled, rows: [DigestRowOut]}`.
  - `DigestRowOut` is the `DigestRow` fields plus `reviewed_by_name` and `reviewed_at`.
  - A malformed day is `422 {reason:"bad_day"}`.
- `POST /api/admin/digest/{alert_id}/review`, body `{day, verdict}`:
  - `200 {row: DigestRowOut, reopened: bool}`;
  - `409 {reason:"already_reviewed", row}`;
  - `409 {reason:"not_auto_closed"}`;
  - `404 {reason:"not_in_digest"}`;
  - `422`.

- [ ] **Step 1:** Tests:
  - the day bounds in `DISPLAY_TZ` (23:59 and 00:00);
  - `2026-02-30` is 422;
  - a correct review writes the row, and the second one is `409 already_reviewed` carrying the recorded verdict;
  - `wrong` reopens the alert (status `queued_tier1`) and `reopened: true`;
  - an alert no longer auto-closed is `409 not_auto_closed`;
  - an alert of another day is 404;
  - a control character in the id is 404;
  - non-admin is 403.
- [ ] **Step 2:** Red, implement on `digest.build` and `digest.review`, green.
- [ ] **Step 3:** Red step: drop the day check on review and the 404 test fails.
- [ ] **Step 4:** Commit.

### P11-T08: Labels undo API

**Files:** modify `backend/app/web/routers/labels.py`. Test: add to `backend/tests/test_labels.py`.

**Interfaces:**
- `POST /api/admin/labels/undo` returns `200 {undone_cluster_id, done, total}`, `409 {reason:"frozen"}` or `404 {reason:"nothing_to_undo"}`.
- `GET /api/admin/labels/next` gains `frozen: bool` and `candidates_present: bool`.

- [ ] **Step 1:** Tests:
  - undo after a label returns the cluster and the progress goes down by one;
  - undo with nothing is 404;
  - undo with the freeze marker is 409 (`freeze_marker` monkeypatched to a temp file);
  - `next` carries both flags;
  - the `next` payload's `cluster` keys are exactly `VIEW_KEYS` minus what `labeling` strips (the existing allowlist test still passes).
- [ ] **Step 2:** Red, implement, green, then the red step (ignore the marker), then commit.

### P11-T09: Audit API

**Files:** create `backend/app/web/routers/admin_audit.py`. Test: `backend/tests/test_admin_audit.py`.

**Interfaces:**
- `GROUPS: dict[str, tuple[str, ...]]` (spec §5.8 table, exact names).
- `REDACT_KEYS = frozenset({"password", "password_hash", "token", "secret", "dsn", "api_key"})`.
- `GET /api/admin/audit?range=24h|7d|30d&group=&actor=&subject=&cursor=&limit=` returns `{events: [{audit_id, created_at, event_type, actor_role, actor_username, subject_id, payload}], next_cursor, total}`.
- `actor` is a username, `system` or `llm`. An unknown username gives an empty list.

- [ ] **Step 1:** Tests:
  - every `EVENT_TYPES` name is in exactly one group;
  - group, actor, subject and range filters;
  - the cursor pages without overlap;
  - `limit` above 100 is 422;
  - redaction at depth (dict in list in dict);
  - a forced statement timeout gives `503 {reason:"timeout"}`;
  - `total` is `null` when its count times out (monkeypatch);
  - non-admin is 403.
- [ ] **Step 2:** Red, implement, green, then the red step (redaction only at the top level, and the depth test fails), then commit.

## Wave 2 — frontend shell

### P11-T10: Admin shell

**Files:**
- Create:
  - `frontend/src/features/admin/AdminLayout.tsx`;
  - `frontend/src/features/admin/ConfirmDialog.tsx`;
  - `frontend/src/features/admin/adminKeys.ts`;
  - `frontend/src/api/admin.ts`.
- Modify:
  - `frontend/src/routes.tsx`;
  - `frontend/src/auth/redirect.ts` (`roleHome`: admin goes to `/admin/overview`);
  - `frontend/src/components/AppHeader.tsx` (in-app "Quản trị" link replaces the legacy link);
  - `frontend/src/strings.ts` (an `admin` section).
- Tests:
  - `frontend/src/features/admin/AdminLayout.test.tsx`;
  - `ConfirmDialog.test.tsx`;
  - update `routes.test.tsx`, `redirect.test.ts` and `AppHeader.test.tsx`.

**Interfaces:**
- `AdminLayout({ children })` renders the sidebar, with seven `NavLink`s in the canvas order and the active one with `aria-current="page"`.
- `ConfirmDialog({ title, children, confirmLabel, tone?: "danger" | "primary", busy, error, onConfirm, onCancel })`.
  - `role="dialog"`, `aria-modal`, `aria-labelledby`.
  - Focus moves to the dialog on open and returns on close; Esc cancels; Tab is kept inside.
- `adminKeys = { overview: (range) => ["admin", "overview", range], users: ["admin", "users"], llm: (range) => ["admin", "llm", range], rules: ["admin", "rules"], digest: (day) => ["admin", "digest", day], labels: ["admin", "labels"], audit: (filters) => ["admin", "audit", filters] }`.
- `api/admin.ts`: one typed function per route of P11-T02…T09, plus `reloadInventory()`. Every admin write sends a JSON body: `unlock` is `api(…/unlock, {method: "POST", json: {}})`, because the route refuses a bare POST with 422 (P11-T02 review, m3).
- Routes: `/admin` redirects to `/admin/overview`, and the seven pages are guarded by `RequireRole roles={["admin"]}`.

- [ ] **Step 1:** Tests:
  - the sidebar order and `aria-current`;
  - tier1 on `/admin/users` lands on `/queue` with the forbidden notice;
  - admin `/` goes to `/admin/overview`;
  - the header shows "Quản trị" for admin only and no `:8000` link;
  - the dialog's focus, Esc and Tab trap, and the confirm button disabled while busy.
- [ ] **Step 2:** Red, implement, green, `ui-lint`, commit.

## Wave 3 — one page per task

Each page task has the same five steps:
1. Write MSW-backed tests for the normal render and every `AdminStates` card of its section, every dialog's confirm and cancel, the 409 and 422 mappings, and axe.
2. See them fail.
3. Build the page from `DataTable`, `Badge`, `KeyValueGrid`, `LogBlock`, `Toast`, `PageError` and `ConfirmDialog`.
4. Green, then `ui-lint`.
5. Commit.

| Task | Page | Its states (AdminStates section) |
|---|---|---|
| P11-T11 | `OverviewPage.tsx`, `/admin/overview` | KPI tiles (the waiting tile reads `waiting`; the API lists only days and statuses that occur, so zero-fill; `errors[].error` is `timeout` or `query_failed`); by day; funnel; by source; top agents; health with failing first; failed jobs with retry dialog, `409 not_failed`/`already_queued`, empty; inventory with reload dialog, result counts and warnings, 422 file errors; one block failing alone; range selector; empty range |
| P11-T12 | `UsersPage.tsx`, `/admin/users` | unlock sends `json: {}`; the stale-actor 403 and `409 self_change`/`last_active_admin` have texts; display names refuse format characters (Cf/Zl/Zp) server-side, 422 `invalid` at the field; table with "chưa đăng nhập", locked until; row actions by state; role change dialog; deactivate dialog; reset password dialog (12 chars, repeat, own-account warning); unlock dialog; `409 last_active_admin` and `self_change` texts; own row's controls disabled; create form errors (409 taken, 422s); search with no result; role → function matrix |
| P11-T13 | `LlmPage.tsx`, `/admin/llm` | the red stopped notice is driven by `spent_usd >= cap_usd`, never by `pct` (P11-T04 review m1); a verifier row's outcome is the verifier's own verdict; the month starts at the database session's midnight; the limits form reads `limits.bounds` for each max (DEC-202) and shows `clamped`; tiles with ≥ 80 % amber and ≥ 100 % red stopped notice; by pipeline and role; quota "24 giờ gần nhất" with exhausted user; recent calls linking to alert or case; no calls; limits form with sources, 422 at the field, confirm dialog listing old → new only, the below-spent warning, fail-closed read-only panel; tool calls 0 sentence |
| P11-T14 | `RulesPage.tsx`, `/admin/rules` | six hard blocks; table with chips and width warning against `width_threshold_pct`; toggle dialog; 404 on toggle; create in two steps with condition builder from the whitelist (`autoclose._WHITELIST`, copied as a typed table and pinned by a test against the backend list); preview, samples linking to `/alerts/:id`; tally when 0; 422 at the condition; "Tạo rule" only for the last previewed conditions |
| P11-T15 | `DigestPage.tsx`, `/admin/digest` | day picker and today; summary; rows with disagreement style; three verdict buttons; reviewed rows; "Sai" adds the reopened sentence; no rule enabled; no cluster; bad day fallback; the two 409s; 422 |
| P11-T16 | `LabelsPage.tsx`, `/admin/labels` | frozen state (current); labelling screen for an unfrozen set (all `VIEW_KEYS` fields, raw log with 32 KB notice, correlation rows and samples, playbook); form (label, confidence, note counter 200); undo; finished; no candidates; 409 frozen; no label chosen; the request log test of Review Focus 5 |
| P11-T17 | `AuditPage.tsx`, `/admin/audit` | filters in the URL; groups; actor and subject; table with role badges, summary line per event type, subject links; expandable payload in `LogBlock`; cursor paging; total or none; no match with "Xoá lọc"; 503 timeout; hostile payload text rendered as text |

The whitelist pin (P11-T14):
- `backend/tests/test_rules_whitelist_pin.py` reads `frontend/src/features/admin/ruleFields.ts` as text;
- it asserts that every field and operator pair equals `autoclose._WHITELIST`;
- so the UI cannot offer a pair the server refuses.

## Wave 4 — close

### P11-T18: End-to-end admin suite

**Files:** create `frontend/e2e/admin.spec.ts`; modify `frontend/e2e/fixtures.ts` if a seed helper is needed.

- [ ] **Step 1:** Write the scenarios of spec §7 (unlock through the real client, which sends `json: {}`), on the existing scratch stack (`make ui-e2e`, which starts its own database, API, worker and the LLM stub). The cluster is the `TEST_DATABASE_URL` one (55611).
- [ ] **Step 2:** Run them; fix what fails. `make ui-e2e` must pass whole, the v1.0 specs included.
- [ ] **Step 3:** Commit.

### P11-T19: Retire the Jinja admin pages and the cookie

**Files:**
- Modify:
  - `backend/app/web/routers/admin_rules.py`, `admin_digest.py`, `labels.py`: drop the HTML routes and their helpers;
  - `backend/app/web/routers/pages.py`: delete it, or keep only what `/api` needs;
  - `backend/app/web/deps.py`: drop the cookie functions, and make `read_token` header-only;
  - `backend/app/web/routers/auth.py`: no `set_session_cookie`;
  - `backend/tests/*` that test the removed pages or the cookie;
  - `docs/runbook.md` admin section.
- Delete `backend/app/web/templates/*`, and `web/templating.py` if nothing imports it.

- [ ] **Step 1:**
  - `test_auth.py`: login answers with no `Set-Cookie`, and a request carrying only a `soc_session` cookie is 401;
  - a route-list test: no HTML route is left (`openapi()` paths plus the non-API routes), and port 8000 serves `/api/*`, `/webhook/alerts` and `/health` only.
- [ ] **Step 2:** Red, remove, green.
- [ ] **Step 3:** Grep `templates|templating|soc_session|set_session_cookie` in `backend/app`: none.
- [ ] **Step 4:** Update the runbook: admin at `http://<host>:8080/admin`, and the Owner commands after merge (`make migrate`, then `docker compose up -d --build ui`, then `docker compose restart app worker`).
- [ ] **Step 5:** Suites, then commit.

### P11-T20: Whole-branch review and close

- [ ] **Step 1:** `git diff 577ef18..HEAD` read file by file against the spec: every requirement mapped to code and a test. Write the gaps into `docs/plan/tasks/P11/P11-review.md`.
- [ ] **Step 2:** Fix every finding, each with its test. Re-run every suite.
- [ ] **Step 3:** Repeat Step 1 on the fix diff until it finds nothing.
- [ ] **Step 4:** Update STATE (rows done, Owner actions), then DEC-200's "Propagated to", then the report `docs/plan/tasks/P11/P11-report.md` with the suite numbers and the red steps.
- [ ] **Step 5:** Commit. Hand the Owner the ordered merge and deploy commands.
