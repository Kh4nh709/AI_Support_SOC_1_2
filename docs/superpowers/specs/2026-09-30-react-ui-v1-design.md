# React UI v1.0: design spec

- **Date:** 30/09/2026
- **Status:** design approved section by section by the Owner in brainstorming. This written spec is pending the Owner's review.
- **Decisions:** DEC-157 (schedule, scope), DEC-161 (v1.0/v1.1 split, JWT Bearer), DEC-162 (WebSocket queue). DEC-158, DEC-159 and DEC-160 are the v1.1 designs this spec does not build.
- **Visual reference:** the claude.ai canvas "SOC Console UI", `https://claude.ai/artifact/MyBdt1oRM9jXUpM1ZLnBNy`. The artboards `Main`, `Queue`, `Login`, `Case` and `AiStates` are v1.0. `CaseChat` and the three `Admin*` artboards are v1.1.

## 1. Goal and scope

**Goal.** Replace the Jinja/htmx Tier-1 and Tier-2 pages with a separate React service that calls the backend's JSON API. Each alert page puts two things in separate columns:
- the **alert information** the human needs to decide;
- the **AI analysis**: ① on the alert page, ② on the case page.

Tier-1 analysts, then Tier-2, use it for the human pilot, and it is tested against real logs and real lab attacks before v1.0.

**In v1.0.**
- Login.
- The Tier-1 queue: real-time, filterable.
- The alert detail: the alert column plus the ① column.
- The Tier-1 decisions: acknowledge, close as false positive or benign, escalate, reopen.
- The Tier-2 case list and case page: heads, notes, conclusion, and the ② column with run, poll and evidence marks.
- The backend additions of §5.
- Retirement of the Jinja Tier-1 and Tier-2 pages (§8).

**Not in v1.0; v1.1 per DEC-161.**
- The Tier-2 investigation assistant: agent, tools with approvals, knowledge agent, memory. It is designed in DEC-160 and does not start before 15/10.
- The admin console (DEC-159): users, LLM usage and limits, overview.
- Porting the Jinja admin pages (auto-close rules, digest, labelling). They keep running on port 8000 with their own `/login`.
- Free-text search in the queue.

**Unchanged.**
- The blind arm (DEC-101): the ① suggestion is stripped server-side while `suggestion_visible = false` and the alert is undecided. The UI never infers or fetches it.
- The ① and ② pipelines, the gate, the cost guard, the audit trail.
- The pilot runs on the React Tier-1 flow once it is live (DEC-157 item 4).

## 2. Architecture and deployment

- **Source.** `frontend/` at the repository root: Vite, React 19 and TypeScript. `package-lock.json` is committed.
- **Libraries.** React Router, TanStack Query and Tailwind CSS, with the palette and type from the canvas.
- **Fonts.** IBM Plex Sans and Plex Mono are bundled via `@fontsource`. There is no Google Fonts request.
- **The `ui` service** in `docker-compose.yml`:
  - A multi-stage build: `node:22-alpine` runs `npm ci && npm run build`, and `nginx:alpine` serves `dist/`.
  - Ports: `127.0.0.1:8080:80`. It is bound to localhost only.
  - `depends_on: [app]`.
- **nginx** (`frontend/nginx.conf`):
  - `/` serves the SPA; an unknown path serves `index.html`.
  - `/api/` proxies to `http://app:8000` and passes `Authorization` through. It is the same origin, so there is no CORS.
  - `/api/ws` proxies the WebSocket upgrade: `proxy_http_version 1.1`, the `Upgrade`/`Connection` headers, and `proxy_read_timeout 1h`.
  - Security headers: `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.
- **Development.** `npm run dev`, with Vite proxying `/api` (WebSocket included) to `127.0.0.1:8000`.
- **Target.** Desktop only, at 1280 px and wider, on current Chromium and Firefox. There is no mobile layout in v1.0.
- **CSP compatibility.**
  - No library that injects `<style>` or `<script>` at run time.
  - The TanStack Query devtools are excluded from the production build.
  - React's `style` props are set through the CSSOM, which `style-src 'self'` allows.
- **Toolchain.**
  - Node 22 is pinned (`engines` and `.nvmrc`), and the lockfile is committed.
  - `npm ci` is used in Docker and in the merge script.
  - `npm audit --omit=dev` is reported by `ui-lint`, as a report, not a gate.
  - The scaffold card installs Playwright's Chromium (`npx playwright install chromium`) and records any system package it needs as an Owner action.
- **Makefile targets.** They run inside `frontend/` and are also called by the Director's merge test script.
  - `ui-lint`: eslint, `tsc --noEmit`, `prettier --check`.
  - `ui-test`: Vitest.
  - `ui-e2e`: Playwright.
  - `ui-build`.
- **Owner actions.**
  - `docker compose up -d --build ui` the first time, because it is a compose change.
  - `docker compose build app worker && docker compose up -d app worker` after the WebSocket dependency lands (§5.5).

## 3. Frontend structure, routes, authentication, data flow

**Layout of `frontend/src/`**
- `api/client.ts`: the one `fetch` wrapper.
  - It uses the base `/api` and adds `Authorization: Bearer <token>`.
  - It parses JSON.
  - `401` clears the session and navigates to `/login`.
  - `409`, `422`, `429` and `503` surface the server's `detail` unchanged to the calling component.
- `api/auth.ts`, `api/tier1.ts`, `api/tier2.ts`: typed functions, one per route. The TypeScript types are hand-written against the real responses, because many routes return untyped `dict`s.
- `auth/`: `AuthProvider` and the `RequireRole` guard.
  - The session is `{token, role, username, expires_at}`, held in memory and mirrored to `sessionStorage` under one key. It is never put in `localStorage`.
  - At `expires_at` the session is cleared.
  - On load, the session is re-read from `GET /api/auth/me` (§5.1), not trusted from storage.
  - **Several tabs.** `sessionStorage` is per tab, so an alert opened in a new tab would ask for a login again. A new tab therefore asks the open tabs for the session over a `BroadcastChannel`, and any tab answers with it. Logout is broadcast, so every tab closes its session. Nothing goes to `localStorage`.
- `live/`: the WebSocket client (§3.2).
- `features/tier1/`: the queue page, the alert page, the decision panel.
- `features/tier2/`: the case list, the case page, the ② column.
- `components/`:
  - the app header with role-based navigation, the live indicator and logout;
  - severity and status badges;
  - a key/value grid;
  - a log block that renders text only;
  - a data table;
  - the AI column and its states;
  - toasts;
  - a page error boundary.
- `strings.ts`: every Vietnamese label, including the alert status labels now in `web/routers/alerts_pages.py:STATUS_LABELS` and the ② mark and overrule labels.

### 3.1 Routes

| Path | Roles | Notes |
|---|---|---|
| `/login` | public | `POST /api/auth/login`. `401`: "Sai tên đăng nhập hoặc mật khẩu". `423`: "Tài khoản bị khoá đến HH:MM", from `locked_until`. `503`: "Đăng nhập đang tắt". |
| `/queue` | tier1, tier2, admin | Read for all three roles, the same as the API. |
| `/alerts/:alertId` | tier1, tier2, admin | Only tier1 sees the decision panel, the same as the API's POST guards. |
| `/cases`, `/cases/:caseId` | tier2, admin | |
| `/` | any signed-in role | tier1 goes to `/queue`; tier2 and admin go to `/cases`. For admin, the header also links "Quản trị (UI cũ)" to port 8000. |

### 3.2 Data flow and real time

- TanStack Query owns every read. The server is the source of truth: there are no optimistic updates.
- **The queue is real time (DEC-162).**
  1. After connecting to `/api/ws`, the client sends `{type: "auth", token}` as its first message.
  2. On `{type: "alerts.changed", ids | many}` it invalidates the queue query, and the open alert's query when its id is listed.
  3. It reconnects with exponential backoff, capped at 30 s, and does a full refetch on reconnect.
  4. While the socket is down, the queue falls back to 30 s polling.
  5. The header shows "Trực tiếp" or "Mất kết nối".
- **The alert page:**
  - It is refetched on its WebSocket id.
  - While the view has no ① result and is on the visible arm, it also polls every 10 s.
  - After any decision it refetches the alert and the queue.
- **The ② column** polls every 3 s while its state is running, and stops on done, failed or stalled, as the Jinja page does.
- **The blind arm** is read from the response only. When the suggestion keys are absent and `suggestion_visible` is false on an undecided alert, the column shows the "ẩn" state. The client has no other path to a suggestion.

## 4. Pages

Each page follows its canvas artboard. Copy is Vietnamese. Dates are shown in `DISPLAY_TZ` (Asia/Ho_Chi_Minh).

**Queue** (`Queue` artboard): `GET /api/tier1/queue?page=&page_size=&band=&category=&agent=&status=` (§5.2).
- **Filters:** the **risk band** ("Mức" is `risk_band`, the column the queue is sorted by, not the alert's `severity`), category, agent, and status: waiting, or "mine" (`tier1_active` held by me). There is no free-text search.
- **Counts by risk band** come from the response (§5.2).
- **Row columns:** risk band, description with rule id, category, agent, occurrence count, last seen, ①.
- **The ① cell:**
  - `suggested_action (confidence)`, plus ⚑ when `gate_forced`;
  - "ẩn — nhánh mù" when the keys are stripped;
  - "chưa có" on the visible arm with no result.
- **Pagination.**

**Alert detail** (`Main` artboard): `GET /api/tier1/alerts/{id}`, the same `queue.get_alert_view(mode="analyst")` the Jinja page renders.
- **Left column, "THÔNG TIN ALERT".** A section is shown only when the view carries its data, and nothing is invented.
  - The summary header: severity, category, status, rule and level, agent, occurrence count, first and last seen.
  - Event details.
  - The raw log, in a text-only `<pre>`, with copy.
  - Targeted accounts.
  - Correlation ±2 h: rows and samples.
  - Enrichment: asset, identity, IOC, lookup status.
  - The playbook.
  - The decision panel (tier1 only).
- **Right column, "PHÂN TÍCH AI ①".** Five states:
  - ready: verdict, confidence, gate and verifier, reasons with quote and source, gate steps, facts used, model/time/cost;
  - hidden (blind);
  - pending;
  - unavailable (`stopped_by`, for example schema);
  - decided: my decision beside ①'s.
- **Decision panel.** It follows the same order as the Jinja page and `tier1/decide.py`: "the first acknowledger wins", and `decided_by` is the acknowledger.
  - A `queued_tier1` alert shows only **"Nhận xử lý"** (`POST .../acknowledge`).
  - Decide and escalate are enabled only while the alert is `tier1_active` and acknowledged by me.
  - An alert acknowledged by someone else is read-only and shows who holds it.
  - This keeps the pilot's acknowledge → decide timing meaningful.
  - After a decision, a toast shows what the response says: how many correlated alerts the fan-out closed with it, or the new case with a link to `/cases/:id`.
  - An escalated alert's page shows a link to its case (`case_id`).
  - `POST .../decide` with `false_positive` or `benign`, a reason, and `seen_occurrence_count` equal to the count the page showed.
  - `POST .../escalate` with a title and a severity.
  - `POST .../reopen` with a reason.
  - Error handling:
    - `409` shows the server's message and refetches, for example "số lần xuất hiện đã đổi, xem lại";
    - `422` shows the message inline at the field;
    - `503` shows "Hết thời gian xử lý, chưa ghi gì — thử lại".
  - The buttons are disabled while a request is in flight.

**Case list:** `GET /api/tier2/cases?offset=&limit=`. It shows title, status, severity, cluster and occurrence counts, created and last analysed times. Investigating cases come first.

**Case page** (`Case` artboard): `GET /api/tier2/cases/{id}` (§5.4) and `GET /api/tier2/cases/{id}/investigation` (§5.3).
- **Left column:**
  - "Còn tiếp diễn" when `ongoing` is true, with `ongoing_last_seen` and a hint to re-run ②;
  - the heads table, each head linking to `/alerts/:id`, with its risk band, status label (`HEAD_STATUS_LABELS`), last seen, and its raw log, marked truncated when `raw_log_truncated`;
  - `CONFIRMED_INCIDENT_SCOPE_NOTE` beside the "Xác nhận sự cố" choice (moved into `strings.ts`);
  - the timeline;
  - notes with the author's name, and add note (`POST .../notes`);
  - the conclusion. `POST .../conclude` takes one of `concluded_fp` "Dương tính giả", `concluded_policy_violation` "Vi phạm chính sách" or `confirmed_incident` "Xác nhận sự cố", plus a reason. A `409` shows who concluded, and when.
- **Right column, "PHÂN TÍCH AI ②".** The investigation view's state:
  - **idle:** the "Phân tích" button;
  - **running:** poll;
  - **stalled:** "Chưa được xử lý sau N phút — kiểm tra worker" and "Kiểm tra lại";
  - **failed:** "Phân tích thất bại — có thể thử lại";
  - **done:** the suggested conclusion and confidence, summary, narrative, hypotheses, supporting evidence and counter-evidence each with its mark (verified or `quote_not_found`, `not_in_case`, `quote_too_short`), the warning shown when counter-evidence is empty, the overrule sentence, next steps, injection warnings, and model/tokens/cost.
- **"Phân tích"** is `POST .../analyze`, which answers `202`. `429` means the quota is exhausted; `409` means already running, or the case is concluded.
- **A concluded case** shows its last result and no button.

## 5. Backend additions for v1.0

Each item is a card: one Coder on Sonnet 5.5 xhigh and one Reviewer. Each is a frozen-contract change recorded by this spec and DEC-161/162. All are additive; no existing field or route changes meaning.

1. **`GET /api/auth/me`.**
   - Any signed-in role.
   - Returns `{user_id, username, display_name, role, expires_at}` from the verified token and the `users` row.
   - `401` as `current_user`.
2. **Queue filters and counts.**
   - `queue.list_queue` and `GET /api/tier1/queue` accept optional `band` (the risk band), `category`, `agent` and `status ∈ {queued, mine}`. `mine` means `tier1_active` acknowledged by the caller.
   - The response gains `counts_by_band`, `{critical, high, medium, low}` over the unpaged set with every filter except `band`, so the chips still show the other bands' counts.
   - Unfiltered calls return exactly what they return today.
   - The blind-arm strip is unchanged.
3. **`GET /api/tier2/cases/{case_id}/investigation`** (tier2, admin).
   - The ② view the Jinja partial computes today: state, run id, result, evidence rows with marks, overrule text, stopped text, snapshot versus current values.
   - It comes from one shared module, `tier2/investigation_view.py`, which the helpers in `web/routers/case_analyze_pages.py` move into: `_derive_view`, `_evidence_rows`, `_overrule_text`, `_snapshot`, `_present_run` and the stall rule.
   - The Jinja page calls the same module until §8 retires it.
   - Returns `404` for an unknown case.
4. **Case detail names and page fields.** `GET /api/tier2/cases/{id}` gains:
   - `concluded_by_name`;
   - `author_name` on each note;
   - the per-head supplement fields the Jinja page adds (`cases_pages._enrich_heads`): `raw_log`, `raw_log_truncated`, `risk_band` (never the bare `risk_score`), `last_seen_at`;
   - `ongoing` and `ongoing_last_seen`, computed by the same rule as `_enrich_heads` (a head still `escalated_tier2` with `last_seen_at` newer than `last_analyzed_at`, or `created_at` when the case was never analysed).

   The rule moves into a shared function, used by both routes until §8.
5. **Real-time channel (DEC-162).**
   - **Migration:** a trigger on `alerts`, `AFTER INSERT OR UPDATE` of the queue- and page-visible columns, runs `pg_notify('alerts_changed', json {alert_id, op})`.
   - **Route:** `GET /api/ws`, a WebSocket in an async router. It uses one LISTEN connection per app process and an in-process hub.
     - Messages are coalesced to at most one per 500 ms per socket, with ids only; past a cap they become `{many: true}`.
     - Authentication is the first message, within 5 s. The token goes through `infra/auth.verify`, which is re-run every 60 s and at expiry.
     - The token is never taken from the URL.
   - **Dependency:** `websockets` is added to `backend/requirements.txt`, because uvicorn is installed without `[standard]` today.
   - **Cases:** v1.0 keeps them on refetch-after-mutation. A `cases` trigger is v1.1.
   - **Migration number and application.**
     - It is `docs/Schema/018_*.sql`.
     - The Owner applies it to the live database with `make migrate PY=.venv/bin/python`, as for every migration.
     - Tests and checks that pin "17 migrations" are updated by the same card, such as the restore-drill guard of P8-T07.
     - The signed P8-T02 drill record stays as history.
6. **The pilot's metrics in `eval/ops_export.py`.** Today every §6 human-decision metric prints either "not measured" or "descriptive, n = …", with the stale reason "the Tier-1 console was deprioritized (DEC-116)". Nothing computes the pilot's figures, so a pilot run on React would produce no result. This card:
   - reads the pilot window: its start is recorded by the Director in STATE when the Owner starts, and its end is the cut-off;
   - computes, per arm (`suggestion_visible`) and per person:
     - decisions by type;
     - the median acknowledge → decide time;
     - ①'s agreement with the human decision on the **blind arm only** (humans there did not see ①);
   - splits each figure by `alerts.source`, so the lab attack days (`lab`) and live traffic (`wazuh`) stay distinguishable;
   - prints every figure with its n and denominator;
   - updates the stale reasons: ② was built and run (DEC-154), and the digest is live (P5). The ② usefulness rating stays "not measured", because v1.0 has no rating control.
   - Its tests use a scratch database with seeded decisions.

The cookie that `POST /api/auth/login` sets stays unchanged in v1.0; the Jinja admin pages still use their own cookie login. React ignores the cookie. Removing it belongs to v1.1, with the last Jinja pages.

## 6. Security requirements

- **Alert and log text is untrusted.**
  - It is rendered as React text only. `dangerouslySetInnerHTML` does not appear, and a test counts it at 0.
  - There is no `eval`, and no runtime third-party script.
  - CSP as §2.
- **Token handling as §3.**
  - The token never goes in a URL or a log line.
  - Logout calls `POST /api/auth/logout`, which invalidates every earlier token via `sessions_invalid_before`, then clears storage.
  - A WebSocket belonging to a logged-out or deactivated user closes within 60 s.
- **The blind arm is enforced server-side.**
  - The WebSocket carries ids only.
  - An e2e test proves a blind alert's suggestion appears nowhere in the DOM, the network responses or the socket frames before the decision, and appears after it.
- **Roles.** The UI hides what the role cannot do, but the API is the enforcement: every POST keeps its `require_role`.
- **Ports.** `ui` binds to 127.0.0.1 only.

## 7. Testing

- **Backend.**
  - The existing rules apply: scratch databases per agent (never `soc_test`), and a demonstrated red step for every guard and acceptance item (DEC-025/027).
  - Tests do not read `.env` unless they name it.
  - Tests use the fake LLM adapter only.
- **Frontend unit and integration.** Vitest, React Testing Library and MSW cover:
  - every AI column state;
  - the ② states;
  - the decision flows with `409`, `422` and `503`;
  - login `401`, `423` and `503`;
  - `RequireRole`;
  - the live-indicator and fallback behaviour;
  - accessibility with axe on each page;
  - the `dangerouslySetInnerHTML` count test.
- **End to end.** Playwright runs the real app and the real `ui` against a scratch database seeded through the existing test fixtures, with the fake adapter. Nothing synthetic touches the live system.
  - Scenarios:
    1. login, logout and expiry;
    2. a webhook-posted alert appears in an open queue within 2 s;
    3. the blind arm: hidden, decide, visible;
    4. decide with a changed occurrence count gives `409` and a re-check;
    5. escalate, then the case appears for tier2;
    6. ② analyze, poll, done, with marks;
    7. conclude, and a concurrent-conclude `409`.
- **Real logs and real attacks, 04–06/10.**
  - The Owner runs the lab attack scenarios and normal activity. Attack runs and container writes are the Owner's.
  - The Director watches read-only: queries and the UI.
  - Every defect goes into `docs/plan/ui-real-data-test.md`: steps, expected, actual, severity. Each becomes a fix card with a Coder and a Reviewer, and is re-tested the same day where possible.
  - Attack windows are tagged the way the lab already does it (`lab_tag.py`, run by the Owner), so the pilot figures (§5.6) can separate attack-day decisions from live traffic.
  - The admin still signs in separately on port 8000 for the Jinja admin pages. That is a known v1.0 seam and is not a defect.

## 8. Retiring the Jinja Tier-1/Tier-2 pages (day 4, 03/10)

This runs once the e2e suite is green and the Owner has used the React Tier-1 flow.

- **Removed:**
  - the page routes for the queue, the alert page and its decision fragments, the case list, the case page, notes, conclude, the investigation and analyze pages (`alerts_pages.py`, `cases_pages.py`, `case_analyze_pages.py`);
  - their templates;
  - their page-only tests.
- **Kept:**
  - every `/api/*` route and its tests;
  - `tier2/investigation_view.py`;
  - the admin pages (`/admin/rules`, `/admin/digest`, `/admin/labels`), `/login`, `/logout` and `base.html`, with its navigation trimmed to admin links.
- A tier1 or tier2 user who opens port 8000 after login gets a page pointing to port 8080.

## 9. Schedule and process

The Owner's schedule: 4 days to build, then 3 days of real-log and real-attack testing with fixes (DEC-163). The code cut-off is 07/10 12:00 (DEC-157).

| When | Work |
|---|---|
| 30/09 afternoon | Plan and cards. Dispatch §5.1, §5.2, §5.5 and the frontend scaffold (build, lint, test, Docker, nginx, compose, Makefile). |
| 01/10 | §5.3 and §5.4. Auth and login, the queue with its live client, the alert page with the decision panel. Owner: `make migrate`, then `up -d --build ui`, then rebuild `app` and `worker`. **The pilot starts on React Tier-1** once this flow is merged, and the Director records the start time in STATE. |
| 02/10 | The case list and case page with the ② column; §5.6, the pilot metrics; the e2e suite. |
| 03/10 | §8 retirement, the runbook section for `ui`, the full suite. Build complete. |
| 04–06/10 | Real logs and real attacks, the defect log, fix cards, re-tests. |
| 07/10 12:00 | Cut-off. P8-T06 close-out: operations export with pilot figures, `docs/limitations.md`, tag `v1.0`. |

- **Process (DEC-151).** One Coder on Sonnet 5.5 xhigh and one Reviewer per card, each Coder in its own worktree. At most about four agents at once (the session-limit memory). The Director merges with its own mutation checks; the Owner fast-forwards and runs the compose commands.
- **Cut order if the build slips:**
  1. the axe checks, kept as a report instead of a gate;
  2. the "mine" queue filter;
  3. the case timeline;
  4. the WebSocket, falling back to 5 s polling of the queue.

  Retirement (§8) is never cut: v1.0 must not ship two Tier-1 UIs.

## 10. Open points for the Owner

- **`PULL_INTERVAL_S`** is 60 s. Lowering it, or having Wazuh post to `/webhook/alerts`, decides the end-to-end delay from a Wazuh event to the queue. The UI's own share is under 1 s. This is a `.env` or Wazuh configuration choice, and it is the Owner's.
- **The canvas** is shared as "anyone with the link". It holds only illustrative data.
