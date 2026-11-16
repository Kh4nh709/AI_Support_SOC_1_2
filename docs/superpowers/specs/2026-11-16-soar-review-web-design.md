# "Phản hồi SOAR" on the web (replaces the Telegram buttons) — design

Date: 2026-11-16 · Branch `feature/soar-review-web`, cut from the trial line `director/trial-binary-verdict`
@ `d6df9fe` · Not deployed, not merged anywhere · Decision number: assigned when built

## 1 · Why

The thesis system is SIEM (Graylog) → SOAR (n8n) → AI Support SOC (this repo). The SOAR is "act-first":
on an alert n8n itself blocks an IP on pfSense, sinkholes a domain, isolates a host, disables an AD account,
turns `xp_cmdshell` off or kills a process, and then opens a **review ticket** for the analyst on duty:
keep / undo for an action that can be undone, keep / false positive for a killed process. Today the ticket is
a Telegram message with two buttons. The Owner (16/11/2026) wants the ticket and its buttons on this web:
n8n pushes tickets to the web; when a person presses a button the backend calls n8n, and n8n acts.

Scope: the web only (backend + UI). The n8n side is built by someone else to the two contracts below.

**Must not change:** `/webhook/alerts`, the intake / clustering / triage / LLM pipeline, the existing tables.
One exception, forced by "use the existing audit mechanism": the audit event names live in the CHECK
`ck_audit_event_type` of `audit_events`, so the migration replaces that CHECK with the same names plus the
new ones, exactly as migrations 019, 020, 021 and 024 did. No column, no row of an old table changes.

## 2 · Contract A: n8n → web, `POST /webhook/soar-notices`

Served by the app itself (trial: port 8001, like `/webhook/alerts`; the UI's nginx proxies only `/api/`).

Checks, in this order, before the body is read (as `/webhook/alerts`): `SOAR_NOTICE_API_KEY` empty → `503`;
header `X-API-Key` missing or wrong (constant-time comparison) → `401`; source IP outside
`SOAR_NOTICE_IP_ALLOWLIST` (JSON list of IP/CIDR; empty = deny all) → `403` (log the IP, never the key).
A body over `MAX_PAYLOAD_BYTES` → `413`. No blocking database call on the event loop (see `webhook.py`).

Body (`schema_version` "1.0"; any "1.x" is accepted, another major is a 400):

```json
{
  "schema_version": "1.0",
  "event": "created | updated | reminder",
  "kind": "review | notice",
  "id": "K7QM2XHP",
  "sent_at": "2026-11-13T21:40:05.123+07:00",
  "status": "open | kept | undone | false_positive | expired | info",
  "severity": "info | warning | error",
  "title": "ĐÃ TỰ XỬ LÝ",
  "simulated": false,
  "case": { "id": "~4096", "number": 65 },
  "action": { "type": "block_ip", "text": "Chặn IP 79.79.78.202 trên pfSense", "target": "79.79.78.202", "via": "pfsense", "agent": null },
  "host": "pfSense.home.arpa", "agent_id": "003", "user": null, "src_ip": "79.79.78.202", "domain": null,
  "scenario": { "id": "SC03", "name": "Quét cổng từ bên ngoài" },
  "score": 50,
  "note": "Đã chặn 79.79.78.202 trên pfSense, tự gỡ 22:40",
  "created_at": "2026-11-13T21:40:03.000+07:00",
  "auto_expire_at": "2026-11-13T22:40:03.000+07:00",
  "remind_every_minutes": 0, "next_remind_at": null,
  "decided_by": null, "decided_at": null, "result": null,
  "buttons": [ { "decision": "keep", "label": "✅ Giữ chặn" }, { "decision": "undo", "label": "↩️ Gỡ chặn IP" } ]
}
```

Rules of the payload

- `id`: a review (`kind=review`) is 8 characters of `[A-HJ-NP-Z2-9]`; a notice (`kind=notice`) is `N` + 12
  characters (accepted: ASCII letters, digits, `_`, `-`; the n8n side has not fixed its alphabet). Unique and
  stable across resends.
- `action.type` ∈ `block_ip`, `sinkhole_domain`, `isolate_host`, `disable_user`, `disable_xp_cmdshell`,
  `kill_process`; `action.via` ∈ `pfsense`, `wazuh`, null. `decision` ∈ `keep`, `undo`, `fp`.
- `kind=notice`: `status=info`, `buttons=[]`, `case` and `action` may be absent.
- Required: `schema_version`, `event`, `kind`, `id`, `sent_at`, `status`. For a review also `action.type` and
  `buttons` (a list; each item a `decision` of the set and a text `label`). Every other field may be null or
  absent. An unknown field is ignored. `severity` null or absent is stored as `info`. A timestamp must carry
  an offset. `score` is a finite number or null (stored rounded to an integer). `status` `processing` is the
  web's own and is a 400 from n8n. Texts are capped (title 200, the others 2,000 characters; longer is a 400).
- A wrong body is `400 {"detail": {"errors": [{"field": "...", "reason": "..."}]}}`, every fault listed.

Processing (one transaction, the row locked)

| case | answer | stored |
| --- | --- | --- |
| no row with this `id` | `201 {"id", "created": true}` | the row, `last_sent_at = sent_at`, `raw` = the body as sent |
| a row, `sent_at` older than `last_sent_at` | `200 {"id", "created": false, "ignored": true, "reason": "stale"}` | nothing |
| a row in `undone`, `false_positive` or `expired`, and the body says `open` | `200 {…, "ignored": true, "reason": "terminal"}` | nothing |
| a row that is `kept`, the body says `open`, and its `sent_at` is older than the stored `decided_at` | `200 {…, "ignored": true, "reason": "decided"}` | nothing |
| otherwise | `200 {"id", "created": false}` | every field of the body replaces the stored one; `raw`, `last_sent_at`, `updated_at` |

- An update that arrives while the web holds the row (`processing`): when its `status` equals the status the
  row had before the lock, it says nothing new about the state, so the other fields are updated and the lock is
  left alone (the press in flight finishes normally). With any other status n8n has decided: the update is
  applied, the lock columns are cleared, and the decision request in flight then finds its compare-and-set
  does not match and answers with the row as it now is (section 4).
- A text PostgreSQL cannot store (a NUL, an unpaired surrogate), in a value or a key, is a 400.
- An `updated` or `reminder` for an unknown `id` creates the row (`201`).
- One exception to "every field replaces the stored one": `decided_by`, `decided_at` and `result` that arrive
  null or absent keep the stored value, so a push that does not repeat who decided cannot erase the web's
  record. `last_error` is the web's own and no push touches it.
- `created_at` of the body is n8n's time of the ticket; when absent the first `sent_at` stands in.
- Every request that passes the three checks and parses writes one audit event (section 6).

## 3 · Contract B: web → n8n when a person presses a button

`POST {N8N_APPROVAL_URL}` (default `http://79.79.79.14:5678/webhook/soar-approval`), header
`X-SOAR-Secret: <N8N_APPROVAL_SECRET>`, `Content-Type: application/json`, timeout
`N8N_APPROVAL_TIMEOUT_SECONDS` (45; the configuration refuses a value over 100, and the client returns within
that time plus a few seconds whatever the server does, so a live call can never look like a stale lock).

```json
{ "source": "web", "review_id": "K7QM2XHP", "decision": "undo", "callback": "undo:K7QM2XHP",
  "user": "<username>", "user_role": "tier2", "note": "<optional>", "requested_at": "<ISO, UTC>" }
```

| n8n answers | meaning | the client returns |
| --- | --- | --- |
| `200 {"ok": true, "status": "kept\|undone\|false_positive", "result", "message"}` | done | `ok` |
| `200 {"ok": false, "status", "result", "message"}` | the action failed; the ticket keeps its state | `failed` |
| `409 {"ok": false, "status", "message"}` | already handled elsewhere | `conflict` |
| `401`, `404`, `5xx`, a timeout, a network error, a body that is not this JSON, a `200 ok:true` whose `status` is not one of the three | temporary | `unavailable` |

The client is its own module with an injected transport, so tests use a fake; it logs the outcome, the status
code and the duration, never the secret, the URL's query or an exception text that could carry them. An empty
`N8N_APPROVAL_SECRET`, or an `N8N_APPROVAL_URL` set to empty (an absent key takes the default), means "not configured": the decision route answers
`503 {"detail": "soar approval not configured"}` before it locks anything.

## 4 · The API (signed-in users; Bearer token as every `/api` route)

The served review object (all routes):

```
{ id, kind, status, severity, title, simulated, case_id, case_number,
  action_type, action_text, action_target, action_via, action_agent,
  host, agent_id, user_name, src_ip, domain, scenario_id, scenario_name, score, note,
  buttons: [{decision, label}], created_at, auto_expire_at, remind_every_minutes, next_remind_at,
  decided_by, decided_at, result, last_error, locked_by, locked_at, last_sent_at, received_at, updated_at,
  allowed_decisions: ["keep" | "undo" | "fp"],   // for THIS caller: valid for the state AND allowed for the role
  strong_warning: bool }                          // action_type = isolate_host, or host is a domain controller
```

- `status` as served is the **effective** status: a `processing` row whose `locked_at` is older than two
  minutes is served with the status it had before the lock (and `locked_by`/`locked_at` null). Reads write
  nothing.
- `strong_warning`: `action_type == "isolate_host"`, or `host` names a host of `SOAR_AD_HOSTS` (JSON list,
  default `["AD-server"]`: the lab's domain controller). The comparison is on a normalised name: control,
  zero-width and bidi characters and surrounding whitespace removed, a trailing dot removed, case folded;
  the whole name or its first DNS label matches (`AD-server.home.arpa` is the domain controller).
- `locked_by` and `decided_by` are usernames. `created_at` is never null (section 2). `updated_at` moves on
  every write of the row: a webhook update, the lock, the finish. A notice and a `processing` row have
  `allowed_decisions: []`. The `review` inside a 409 is this same object for the caller.
- Timestamps are ISO 8601 with offset `+00:00`, as the other routes serve them.

`GET /api/soar/reviews` — `status` (repeatable), `kind`, `action_type`, `case_number`, `from`, `to`
(`created_at`, inclusive / exclusive), `q` (case number when numeric, a leading `#` ignored; otherwise a case-insensitive substring
of `src_ip`, `host`, `action_target`, `user_name`, `domain`; at most 100 characters, `%`/`_` escaped),
`page` (≥ 1), `page_size` (default 50, ceiling 200): the queue's convention. Answer
`{"rows": [review], "total", "page", "page_size"}`, newest `created_at` first (then `id`).

`GET /api/soar/reviews/count` — `status` (repeatable, default `open`). Answer
`{"count": n, "latest_received_at": "<ISO>|null"}` over the reviews (`kind=review`) in those states.
`received_at` is the web's own clock when it first stored the row (n8n's `created_at` can be older than a
ticket already shown when a delivery is late); the UI compares `latest_received_at` with the last one it saw
to know a new ticket arrived.

`GET /api/soar/reviews/{id}` — the review plus `raw` (the last body n8n sent), `history`
(`[{at, event, actor, actor_role, payload}]`, the audit events whose subject is this id: the newest 200,
oldest first among them, with `history_truncated` true when older ones were left out) and `related_alerts` (section 5). Unknown id: `404`.

`POST /api/soar/reviews/{id}/decision` — body `{"decision": "keep|undo|fp", "note": "<optional, ≤ 500>"}`.

1. Role: `SOAR_ROLES_KEEP` (default `tier1,tier2,admin`), `SOAR_ROLES_UNDO` (`tier2,admin`), `SOAR_ROLES_FP`
   (`tier1,tier2,admin`). A role not allowed for the decision asked: `403`, with the `authz.denied` event the
   other routes write.
2. Unknown id `404`. Valid decisions: `open` → the decisions of `buttons`; `kept` → `undo` only, and never for
   `kill_process`; anything else (also a notice) → `409 {"detail": {"reason": "invalid_state", "review": …}}`.
3. Lock, one statement: `UPDATE … SET prev_status = status, status = 'processing', locked_by, locked_at =
   now() WHERE id = … AND (status = <the status just validated> OR (status = 'processing' AND locked_at <
   now() - interval '2 minutes' AND prev_status = <that status>))`, and `updated_at` still the value read in
   step 2 (a push in between makes the lock miss). `prev_status` keeps its value when a stale lock is taken
   over. No row → `409 {"detail": {"reason":
   "locked" | "invalid_state", "review": …}}`. Commit, so the lock is visible and no transaction is open
   during the call.
4. Call n8n (contract B) off the event loop.
5. Finish with a compare-and-set on `(id, status='processing', locked_by, locked_at)`:
   - `ok`: `status` from n8n, `result`, `decided_by` = the username, `decided_at` = now, `last_error` null.
   - `failed`: `status` back to `prev_status`, `last_error` = n8n's `message` (or `result`).
   - `unavailable`: `status` back to `prev_status`, `last_error` = a short fixed sentence naming the kind
     (timeout, network, HTTP status, bad answer).
   - `conflict`: `status` from n8n when it is one of `open, kept, undone, false_positive, expired`, else back
     to `prev_status`; `result`/`message` kept.
   - compare-and-set matched nothing (n8n's own `updated` webhook won the race): nothing written.
   - n8n's texts are cleaned before they are stored (NUL removed, unpaired surrogates replaced, cut at
     2,000). If the finish cannot be written, a second attempt writes the truthful outcome with a fixed
     text: a press never leaves the lock behind.
6. Answer `200 {"outcome": "ok|failed|unavailable|conflict", "message": "<text for the person>|null",
   "review": <the row as it now is>}`. HTTP errors are only the local ones (401, 403, 404, 409, 422, 503).
7. One audit event per press that passed the role check (section 6).

Every route that changes something takes JSON only (`require_json_type`), as the repo's other routes do: with
the Bearer token in `sessionStorage` and no cookie, that is the repo's CSRF rule.

## 5 · Alerts of the same case (A12)

A SOAR alert stores its case in `alerts.raw_payload → enrichment → case` (`case_number`, `case_id`,
`thehive_alert_id`, `dedup_key`; read today by `tier1/soar_view.py`). On the trial 294 alerts carry a numeric
`case_number` (29 cases). The detail route therefore returns, for a review with a `case_number`,
`related_alerts`: the alerts whose `enrichment.case.case_number` equals it, newest first, at most 50, each
`{alert_id, alert_time, agent_name, description, severity, status, occurrence_count}` (names and meanings
as in the queue row; no AI field, so the blind arm sees nothing new), plus `related_total`. No index is added to `alerts`
(the rule above); the lookup is a filtered scan, measured at well under a second on the trial's 7,784 alerts,
and it runs only for the detail view. A review without a case number has `related_alerts: []`.

## 6 · Storage, configuration, audit

Migration `docs/Schema/025_soar_reviews.sql` (run as the owner, after 024):

- Table `soar_reviews`: `id text PRIMARY KEY`, `kind`, `status`, `severity`, `title`, `simulated boolean`,
  `case_id`, `case_number bigint`, `action_type`, `action_text`, `action_target`, `action_via`,
  `action_agent`, `host`, `agent_id`, `user_name`, `src_ip`, `domain`, `scenario_id`, `scenario_name`,
  `score integer`, `note`, `buttons jsonb`, `created_at timestamptz`, `auto_expire_at`,
  `remind_every_minutes integer`, `next_remind_at`, `decided_by`, `decided_at`, `result`, `last_error`,
  `locked_by`, `locked_at`, `prev_status`, `last_sent_at timestamptz`, `received_at timestamptz` (the web's
  clock at the insert, never changed), `raw jsonb`, `updated_at timestamptz`.
  CHECKs on the closed sets (`kind`, `status` incl. `processing`, `severity`, `action_type`, `action_via`,
  `prev_status`); a `processing` row has `locked_by`, `locked_at` and `prev_status`. `prev_status` is the one
  column beyond the Owner's list: a stale lock is released to the state the row had, and only the row can say
  which that was. `received_at` is the other: the new-ticket signal needs the web's own arrival time.
- Indexes: `(status)`, `(created_at DESC)`, `(case_number)`.
- Rights: `app_rw` SELECT, INSERT, UPDATE; DELETE and TRUNCATE revoked.
- `ck_audit_event_type`: the 40 names of 024 in 024's order, then `soar.review_received` and
  `soar.review_decided`.

Audit (`audit.events.write_event`, subject = the review id):

- `soar.review_received`, actor `system`: `{event, kind, outcome: created|updated|ignored, reason, status,
  sent_at}`.
- `soar.review_decided`, actor the person: `{actor_role, decision, note, outcome: ok|failed|unavailable|conflict|
  invalid_state|locked, status_before, status_after, message}`.
- Both get a Vietnamese label on the admin audit page, as every event name has.

Configuration (`infra/config.py`, `.env.example`; the two secrets, `SOAR_NOTICE_API_KEY` and
`N8N_APPROVAL_SECRET`, redacted like the others; `N8N_APPROVAL_URL` is not a secret, and the client still never
logs it):
`SOAR_NOTICE_API_KEY`, `SOAR_NOTICE_IP_ALLOWLIST`, `N8N_APPROVAL_URL`, `N8N_APPROVAL_SECRET`,
`N8N_APPROVAL_TIMEOUT_SECONDS` (45), `SOAR_ROLES_KEEP`, `SOAR_ROLES_UNDO`, `SOAR_ROLES_FP` (comma lists of
`tier1`, `tier2`, `admin`; an unknown role stops the start-up), `SOAR_AD_HOSTS`.

## 7 · The page "Phản hồi SOAR" (`/soar`, all three roles; Vietnamese, every word in `strings.ts`)

- **Menu**: a link "Phản hồi SOAR" in the header with a badge of the open reviews (the count route every
  30 s). A new ticket (a later `latest_received_at`) plays a short tone (WebAudio, no asset) and shows a
  browser Notification; permission is asked once, from a switch on the page that can also turn both off (the
  choice is kept in `localStorage`, read and written inside try/catch). The repo's guard "no `localStorage`
  in source" (ruling R5: the session token is never persisted) gets exactly one exception, the file
  `features/soar/storage.ts`, pinned by tests: it names `localStorage` only in four fixed calls on two fixed
  keys, its exports and its importers are listed, and what it stores is a flag and notice ids.
- **Table**: time, case #, scenario, host, target (`action_target`), action, score (red ≥ 70, orange ≥ 40,
  yellow < 40; the number is always printed, colour is never the only carrier), status, and a "GIẢ LẬP" tag
  when `simulated`. The list refetches every 20 s (no WebSocket).
- **Buttons**: one per entry of `buttons` whose `decision` is in `allowed_decisions`, with n8n's `label` as
  text. So after "Giữ" the undo button is still there, a notice has none, and a role without the right sees
  none. While a request runs: "Đang xử lý…", buttons disabled; a row another person holds (`processing`)
  shows who.
- **Confirmation**: undo and fp open a dialog with a note field (≤ 500); keep sends at once. The dialog's
  warning is stronger when `strong_warning`, worded by the action being undone ("Gỡ cách ly máy chủ AD …" only
  for an isolation). The dialog follows the live row: if the ticket changes while it is open, it says so and
  asks again.
- **Result**: `outcome ok` → the new status; `failed` / `unavailable` → the message in an error line on the
  row (for example "GỠ THẤT BẠI: …") and the buttons again; `conflict` → the status n8n gave, with a note
  that it was handled elsewhere; a local 409 → the row is refreshed.
- **Timers**: "Tự gỡ lúc HH:mm" with a countdown when `auto_expire_at` is ahead (for `open`, `processing`
  and `kept`: the page shows what n8n says); past it with the status
  still `open`: "Chờ SOAR đóng phiếu" (the web never changes the status itself). Isolation and account
  lock with `remind_every_minutes > 0`: "Đang giữ · nhắc mỗi N phút", highlighted once `next_remind_at` is
  past.
- **Notices** (`kind=notice`): a line per notice above the table, coloured by `severity` (error red,
  warning orange, info grey) with the word of the severity, each dismissible (dismissed ids kept in
  `localStorage`); the filter "Thông báo" lists them all.
- **Filters**: Đang mở (`open`, `processing`) · Đã xử lý (`kept`, `undone`, `false_positive`) · Hết hạn
  (`expired`) · Thông báo (`kind=notice`); a search box for case #, IP, host.
- **Detail panel**: every field, the history, who decided, `result`, `last_error`, and links to the alerts
  of the same case (`/alerts/<id>`).
- Everything n8n sent is rendered as text (no `dangerouslySetInnerHTML`, no URL built from it except the
  encoded alert id of our own database).

## 8 · Tests

Backend (red first): the webhook's 503 / 401 / 403 / 400 (each fault), 201, 200, stale ignored, terminal not
reopened, unknown fields ignored, the 413, the update that lands on a `processing` row; the decision with a
fake n8n: keep, undo, fp on `kill_process`, undo refused on `kill_process`, wrong role 403, invalid state
409, two concurrent requests → one call to n8n, `ok:false` → previous state + `last_error`, timeout →
previous state, n8n 409 → status synced, a stale lock (over two minutes) released by the next press, the
webhook winning the race; the list filters, the count, the detail with history and related alerts; the audit
events; the configuration (defaults, an unknown role, the timeout ceiling, the secrets redacted); the
migration (the table, CHECKs, rights, the 42 names). The full db suite on the merged tree is the gate.

Frontend (Vitest, the repo's kit): buttons by state and `allowed_decisions`; the confirmation dialog and its
strong warning; "Đang xử lý…" and each outcome; the timers at fixed clocks; the badge and the new-ticket
signal; notices and their dismissal; the filters; text-only rendering of hostile strings; axe.

## 9 · Calls the Director made (for the Owner to check)

- The branch is cut from the trial line's newest tip (`d6df9fe`, which carries the approved panel redesign),
  since the web the Owner named is the trial.
- The audit CHECK is replaced (section 1); `prev_status` and `SOAR_AD_HOSTS` are additions to the Owner's
  lists (sections 6 and 4), and so is `received_at`.
- The decision route answers `200` with an `outcome` whenever n8n was asked, so the UI always gets the row
  and a message; HTTP errors are kept for what the web itself refuses.
- A terminal row is protected only against `open` (the Owner's rule as written); another change n8n sends
  for it is applied.
- n8n must post to the app's own port (trial `:8001`), not to the UI's `:8081`.
