# P4 · UI + auth + blind branch — task cards

Phase objective: two analysts can work Tier-1 in a browser; the blind branch is enforced at the
API; the pilot starts.
Written **19/09/2026** (Planner P4), against `prompts/P4.md` as swept 19/09 (DEC-090) **and**
`prompts/planner-run-P4-2026-09-19.md`. Where a DEC and the brief disagree, the DEC wins and the
divergence is named in §1.

**DEC-007 item 7 / DEC-009 — which copy of a card is authoritative.** Each task has a full
`docs/plan/tasks/P4/<TASK_ID>.prompt.md` and a shorter entry in this file. **The prompt is the
card**; this file is the Planner's index — estimates, waves, dependencies, risk notes, the pilot's
Owner actions and the hand-off. Where this file restates an acceptance command it matches the prompt
verbatim or does not appear. A divergence is a Director defect, not a Coder's judgement call.

---

## ⚠️ Budget note — `must` is 22 h against the brief's 1 day; wall-clock ≈ 4 working days at two slots

| | |
|---|---|
| Sum of `must` estimates | **22 h** (7 `must` cards; T08 webhook is `should`, 2.5 h) |
| Day budget (`prompts/P4.md`: 1 day) | 8 h |
| Overbooking | **+175 %** against the 8 h day (22 h where the × 1.3 rule allows 10.4 h) — the re-plan threshold is 30 %, so this note is required and present |
| Wall-clock at **two** P4 slots (DEC-088: P3's tail and P6 hold the third) | **≈ 4 days** — 20/09 T01 · 21/09 T02 ‖ T04 · 22/09 T03 (+ T07 in an idle slot) · 23/09 T05 · 24/09 T06 ‖ T08 |
| Longest chain | T01 (4) → T03 (4.5) → T05 (5) → T06 (1.5) = **15 h** — four review/merge gates, which is the real limit (DEC-048: batch them) |
| The chain that matters more | **T01 → {T02, T04} → P6-T02**: the labelling page needs exactly these three P4 cards in `main` (`P6-T02.prompt.md:17`), and labelling is fixed at 26–27/09. T01 merges 20/09 evening, T02 and T04 merge 21/09 evening, **P6-T02 is dispatchable 22/09** — the day DEC-090's slot plan gives it |
| Calendar | P4 was dated 18/09 (DEC-071) and is planned on 19/09 after a 3.3-day outage (DEC-089/090); the brief's "1 day" is history. The **pilot starts when T05 merges (23/09 evening at the earliest)** — the Owner logs in as `tier1` and decides real alerts; T06 is the gate's end-to-end proof the next morning |
| `should` | T08 webhook (P2-T12 re-homed, 2.5 h, off the gate); the timing-safe dummy verify on unknown usernames inside T01; the SRI hash on the HTMX tag inside T04; the "gợi ý dựa trên N cụm … hiện có M" delta sentence inside T05 |

**What the arithmetic means.** Nothing in P4 is cut and nothing is proposed for a cut: the brief's
three cut candidates (queue filters, pagination beyond OFFSET, flash-message polish) are **not
built** in the first place — the queue has no filters, pagination is OFFSET, the 409 flash is one
partial. If the week runs long, the order to drop is **T08** (`should`, off the gate) → **T06** (its
tests are the Director's gate evidence, but T05's own acceptance already exercises every page through
`TestClient`; T06 adds the composed end-to-end flow) — never T01/T02/T04, which P6-T02 waits for.

---

## 1 · What changed since the brief — the addendum's five items, checked against `main` @ `21773ff` (19/09)

| Fact | Measured | What it changes |
|---|---|---|
| **DEC-079 — P2 is closed; the brief's "skeleton" list is wrong in both directions.** | `wc -l`: `infra/auth.py` 1, `tier1/queue.py` 1, `tier1/decide.py` 1, `infra/intake.py` 1 — **P4 writes these four**. `tier1/triage.py` 1 and `audit/llm_runs.py` 1 are **P3-T10's** (`P3-T10.prompt.md:15`); `tier1/digest.py`, `infra/health.py`, `infra/notify.py` are **P5's**. Real and reused: `web/main.py` 57 (one route, `get_conn`), `web/worker.py` 38, `domain/transitions.py` 621 (`acknowledge`, `decide`, `escalate`, `reopen` — every state edge P4 needs already exists), `domain/correlation.py` 170 (`summarize_for_prompt`), `kb/lookup.py` (`get_playbook`), `audit/events.py` (`write_event`, 27 event types incl. `authz.denied`, `admin.user_created`), `infra/config.py` (`JWT_SECRET`, `JWT_TTL_HOURS`, `LOGIN_MAX_FAILS`, `LOCKOUT_MINUTES`, `REVIEW_DELTA_TOLERANCE`, `WEBHOOK_*`, `DISPLAY_TZ` all present) | P4 touches no P3/P5 file (§9); `tier1/decide.py` is a thin layer over `domain.transitions` (planning decision 4); `web/main.py` is rewritten once, by T01 (planning decision 1) |
| **DEC-082/083 — the pilot's queue is the replayed corpus, not G1.** | `soc_dev` 19/09: `alerts` 95,952 = `replay` 92,011 + `wazuh` 3,941; **`queued_tier1` 383** (heads: `replay` 307 + `wazuh` 76), `duplicate` 95,569; **`users` 0**; **`llm_runs` 0**; `assets` 4 · `identities` 2 · `iocs` 0. All 383 stored heads carry `asset_context.criticality = 'unknown'` (enriched before the inventory was loaded — DEC-083) | the queue page's first content is those 383 heads, every one `needs_review`-shaped by construction; the pilot checklist (T07) says so; fixtures are carded against that shape (`raw_log` p50 91 chars, p95 603) |
| **DEC-085 — `alerts.source` is a live three-valued column.** | `source ∈ wazuh|lab|replay`; `lab` is written post hoc by `eval/lab_tag.py` (P6-T05, in review) | the `labeling` mode's forbidden-value test names **all three** values; the matrix has a row per value |
| **DEC-086 — G1 = 300 + \|G2\|; the labelling routes are P6-T02's.** | `P6-T02.prompt.md:17,28` depends on P4's auth dependency, `tier1/visibility.py`'s `labeling` mode and the base layout | §4's wave order; **P6-T02's card is amended today** (banner at its top): it creates `web/routers/labels.py` and touches **no** `web/main.py` (planning decision 1); the names it imports are `app.web.deps.require_role`, `app.tier1.visibility.strip`, `templates/base.html` |
| **DEC-088 — two P4 slots at a time.** | 3-session cap; P6-T01 and P6-T04 running; P3-T09 takes a slot when P3-T03 merges | the wave table plans two; T01 is alone on 20/09 (the third slot is P3-T09's or P6's) |
| **DEC-070** | `INDEXER_URL=https://wazuh.indexer:19200` (a name) | no P4 card touches `.env.example` or §6.3; no indexer value is restated anywhere in these cards |
| **DEC-066 Q5 executed** | `conf/inventory.yaml` carries `HR-computer` + `wazuh.manager`; `validate()` → `[]` | not an Owner action here — it is done |
| **Host (addendum §4)** | worker and puller **not running** since the 16/09 reboot; `alerts` unchanged since 15/09; the indexer holds ≈ 7,350 documents — ≈ 3,400 live documents un-ingested; `alerts.json` unreadable by `user1` (mode 640) — **nothing in P4 reads it** | Owner action with proof commands in T07's checklist and in §10 |
| **The stop condition is currently true** | `llm_runs` = **0** rows; P3-T09 → T10 → T11 are `todo` | every suggestion-visible test inserts its own `llm_runs` row **in P3-T10's shape** (planning decision 5 quotes it), so P4's tests do not wait for P3; what waits is the pilot's real suggestions. If P3-T10 lands a different shape, the four expressions P4 reads are named in one place (`tier1/queue.py`, planning decision 5) |
| **Two host facts the brief did not carry** | `.env` has **no `JWT_SECRET`** (`grep -c '^JWT_SECRET' .env` → 0; `.env.example:69` lists it empty); `python-multipart` **0.0.32 is importable on this host and absent from `backend/requirements.txt`** — the P1 `jsonschema` trap, and FastAPI's `Form()` needs it | Owner action: set `JWT_SECRET` (§10); INBOX item for the dependency (§8), T04 written for the recommended answer |

**Not touched by this phase, and said so nobody looks:** `kb/decision_tables/*.yaml` (10/10
`reviewed_by: null` — P4 reads playbooks, never tables); the indexer; `alerts.json`; ② and anything
under `tier2/`; `tier1/digest.py` (P5).

**STATE.md `## Agent actions` rows addressed to Planner P4 — swept, with the verdict:**
- **Planner P4/P6 (DEC-019), the P4 half** — the filter's `labeling` mode strips `alerts.source` and the matrix has it: **absorbed**, T02 design note 3 + acceptance 2 (`test_labeling_mode_strips_source_for_every_value` over `replay`, `wazuh`, `lab`; the matrix is role × status × visibility × mode). The P6 half was absorbed by Planner P6 on 16/09 (`P6-T02.prompt.md` design note 4).

---

## 2 · Dispatch state — read this before dispatching anything

**Precondition for T01: none.** Measured on `main` @ `21773ff`: `domain/transitions.py`,
`audit/events.py`, `infra/config.py`, `web/main.py`, `enrichment/inventory.py` are on `main`;
migration 016's `users` columns (`password_hash`, `sessions_invalid_before`, `failed_logins`,
`locked_until`) are applied on `soc_dev` and in `docs/Schema/schema.sql`. `git branch` has no
`task/P4-*`. Open branches (`P3-T03/T07/T08`, `P6-T01/T04/T05`) touch no P4 file (§9).

| | |
|---|---|
| Dispatchable now | **P4-T01** (4 h, the head of both chains) · **P4-T02** (3.5 h — logic + tests, no route, no auth dependency; if a second P4 slot exists on 20/09 it runs beside T01) · **P4-T07** (1 h, docs) |
| After T01 merges | **P4-T04** (2.5 h) · **P4-T08** (`should`, after the INBOX §8 item is answered — it is written for option A) |
| After T01 **and** T02 merge | **P4-T03** (4.5 h) · **P6-T02** (P6's card; needs T04 too) |
| After T03 and T04 merge | **P4-T05** (5 h) |
| After T05 merges | **P4-T06** (1.5 h) — the gate's end-to-end proof; **pilot start** is the Owner's action the same day |
| Blocked on an Owner action | nothing on the code. **The pilot** needs: `JWT_SECRET` in `.env`, users seeded (T01's CLI), worker + puller running, the advisor told the blind-branch rule (§10) |
| INBOX items this plan raises (§8) | one — `python-multipart` enters `backend/requirements.txt` (Director's: a library choice). T04 carries the line and is re-cut in one paragraph if refused |

---

## 3 · Rules every card follows (so the Reviewer can grep for them)

1. Every pytest line is `python3 -m pytest -c backend/pyproject.toml …` (DEC-005). Every db-marked line sets `TEST_DATABASE_URL=postgresql:///soc_p4t<nn>_test` inline, passes `-rs`, adds no `-q`, and states `N passed` with **`skipped` absent for that file** (DEC-023 item 8). Whole-suite runs are judged on **exit 0** — `make test` carries `test_dispatch_state.py`'s off-`main` skip on every branch (DEC-080).
2. A named test is grepped with `-vv` (DEC-074).
3. Every acceptance names its **red step**, and the red step discriminates (DEC-025, DEC-077).
4. **No test opens a socket beyond local PostgreSQL.** HTTP is exercised with `fastapi.testclient.TestClient` on `app.web.main.app` with `app.web.deps.get_conn` overridden to the `db` fixture (P2-T08's pattern, `test_reload_inventory.py:40-46`); the LLM is never called — `llm_runs` rows are inserted by the test.
5. No test reads the real `.env` (DEC-047); `JWT_SECRET` in tests is a literal set through `monkeypatch.setenv` or a `Config` built with `dataclasses.replace`. **Never point a test or a manual run at `soc_dev`.**
6. **Every read of `alerts` uses an explicit column list** (G10). **Only `domain/` writes `alerts.status`** (G2) — `tier1/decide.py` calls `domain.transitions` and `test_import_rules.py` plus a grep guard prove it.
7. Import rules hold (`ALLOWED` in `test_import_rules.py`): `infra → nothing`, `tier1 → domain|llm|kb|security|infra|audit`, `web → everything`. **Consequence (planning decision 2):** `infra/auth.py` is pure — it cannot write an audit event; the FastAPI dependencies that do (`authz.denied`) live in `web/deps.py`.
8. **Frozen contracts:** no new §6.3 key (`RETRIAGE_FACTOR`/`RETRIAGE_ABS_DELTA` are module constants in `tier1/queue.py`, planning decision 6), no new event type (`authz.denied`, `admin.user_created`, `alert.acknowledged`, `tier1.decided`, `tier1.escalated`, `case.opened`, `alert.reopened` all exist), no new §6.4 operation (HTML pages are pages, not API operations — planning decision 9), no migration.
9. `superseded.yaml` scans these cards (DEC-049): no bare `pytest`, no dead migration range, no retired host/service name, no indexer address form.
10. **Every 4xx that must persist a write commits before it raises** (planning decision 3): failed-login counters, lockouts and `authz.denied` events are written and `conn.commit()`ed before the `HTTPException`, because `get_conn` rolls back on any exception.

---

## 4 · Critical path, waves and the calendar

Estimates are for the card as written; dependencies are the `Depends on:` field of each prompt, and
where this diagram and a field disagree, the field wins (DEC-007 item 6). Two P4 slots (DEC-088).

```
20/09   T01 auth + deps + main.py + seed CLI (4)        [T02 queue + visibility (3.5) if a 2nd slot frees]   T07 docs (1) in any idle slot
21/09   T02 (if not yet)  ‖  T04 base layout + login/logout pages (2.5) ←T01
        ── T01 + T02 + T04 in main by 21/09 evening  ──►  P6-T02 dispatchable 22/09 (P6's slot)
22/09   T03 tier1 REST + decide (4.5) ←T01,T02        ‖  T08 webhook (should, 2.5) ←T01, INBOX
23/09   T05 queue + detail pages + partials (5) ←T03,T04      ── pilot starts when T05 merges (Owner logs in as tier1)
24/09   T06 E2E through the HTML routes (1.5) ←T05     ── the exit gate's proof; Director's gate row
```

**Why T01 heads everything.** Every route needs `require_role`; every page needs the session
cookie; P6-T02 needs the `admin` role; the pilot needs `users` rows. Its 4 h are the first thing to
dispatch and the only P4 work on 20/09 (the third slot is P3-T09's or P6's).

**Why T02 has no route and no auth.** `tier1/queue.py` + `tier1/visibility.py` are pure functions
over a connection and a dict; carding them without the router lets T02 run in parallel with T01 and
lets P6-T02 import the filter the moment T02 merges. The routes that expose them are T03's.

**Why T04 is small.** P6-T02 needs the base layout and nothing else from the pages; a queue page
needs T02's `list_queue` and would tie T04 to T02's merge. So T04 = base layout + login/logout +
`/` redirect; the queue and detail **pages** are T05's, after T03's API exists.

**Why T05 waits for T03 and T04.** The detail page renders `queue.get_alert_view` (T02, filtered),
posts to `tier1/decide.py` (T03) through HTMX partials, and extends `base.html` (T04). It is the
integration point of the phase; everything before it is a leaf.

---

## 5 · Environment measured today (19/09), and where it changes a card

| Claim | Measured | Consequence |
|---|---|---|
| `users` | **0 rows**; columns `user_id, username, display_name, role, is_active, created_at, password_hash, sessions_invalid_before, failed_logins, locked_until`; `ck_users_role IN (tier1, tier2, admin)`; `password_hash NOT NULL` (migration 011: argon2id `t=3, m=64 MiB, p=4`, backfill hash matches nothing) | T01's CLI creates rows with those parameters; a user is one role — the Owner holds two accounts (tier1 + admin), the advisor two (tier2 + admin) |
| `audit_events` CHECKs | `actor_role ∈ system\|llm\|analyst\|admin`; `system → actor_id IS NULL`; `analyst\|admin → actor_id NOT NULL` | `require_role`'s `authz.denied` maps `tier1\|tier2 → analyst`, `admin → admin`; the seed CLI writes `admin.user_created` as `system` with `actor_id NULL` |
| `domain.transitions.decide` | signature `decide(conn, alert_id, user_id, *, decision, reason, seen_occurrence_count, llm_suggestion, llm_confidence)`; payload `decision, reason, occurrence_count, llm_suggestion, llm_confidence`; `StaleState` on wrong status or delta > `REVIEW_DELTA_TOLERANCE` (20); `SELECT … FOR UPDATE` first | the brief's payload needs **two more fields** (`gate_forced`, `suggestion_visible`) — **T03 adds them as keyword arguments with `None` defaults** (planning decision 4); `test_transitions.py` is untouched and stays green |
| `domain.transitions.escalate` | **no status guard on the trigger** — it reads the trigger, inserts the case, updates `… AND case_id IS NULL`; a sealed (closed) trigger fails on `ck_alerts_h3_escalate_khong_seal` (an `IntegrityError`, not `StaleState`); a `received`/`enriching` trigger would pass | **T03 guards before calling** (`SELECT status … FOR UPDATE`, `status ∈ (queued_tier1, tier1_active)` else 409) — a finding, not a P2 defect to reopen: the DB catches the sealed case loudly; the unsealed case has no route to it before P4 |
| `domain.transitions.acknowledge` | A7 with `AND acknowledged_at IS NULL`; a second caller gets `StaleState` | T03's `acknowledge` is **idempotent at the API**: already `tier1_active` → `200` with the first acknowledger, never 409 (phase-6 P6-2) |
| `domain.transitions.reopen` | A17 `auto_closed → queued_tier1` only; `reason` mandatory (`ValueError` when empty) | T03 maps `ValueError` → 422, `StaleState` → 409 |
| `web/main.py` | `app = FastAPI()`, `get_conn` (commit on success / rollback on exception / close), one route `POST /api/admin/reload-inventory` **without auth**; `test_reload_inventory.py:40-46` overrides `main.get_conn` | T01 rewrites it (planning decision 1), wraps the route with `require_role("admin")`, and updates that test's fixture to also override the auth dependency |
| `get_conn` rolls back on any exception | an `HTTPException` raised after a write loses the write | planning decision 3: lockout counters and `authz.denied` commit before raising; `decide`'s 409 details are read **before** the raise inside the same (rolled-back) transaction and travel in the exception |
| Phase-6 queue SQL | `LEFT JOIN llm_runs r ON r.subject_id = a.alert_id AND r.pipeline = 'triage'` — ambiguous once ① writes **two** rows per alert (proposer + verifier, P3-T10) | T02 joins **the latest `role = 'proposer'` row** with a `LEFT JOIN LATERAL (… ORDER BY created_at DESC LIMIT 1)` (planning decision 5) |
| `RETRIAGE_FACTOR = 10`, `RETRIAGE_ABS_DELTA = 200` | in `docs/kien-truc-tong-quat-va-chi-tiet.md:323-324` and `phase-2:321`; **not** in §6.3 and not in `Config` | module constants in `tier1/queue.py` (planning decision 6); adding them to `Config` would be a §6.3 change |
| Risk display band | `docs/phase-4-enrichment.md:198-207`: 0–24 Thấp · 25–49 Vừa · 50–74 Cao · 75–100 Rất cao; **never the bare number**; `NULL` → no band | `queue.risk_band(score)`; the templates render the band + `severity`, and a test asserts the raw number is not in the HTML |
| `llm_runs` row shape ① will write (P3 planning decision 1, `P3-T10.prompt.md`) | `role='proposer'`, `pipeline='triage'`, `result` = the `triage_v2` object with `suggested_action` = **the gated verdict**, `reasons` = surviving reasons; `gate_result` = `{proposed_verdict, final_verdict, forced, forced_by, steps, missing, hallucination_flag, dropped_reasons, facts, warnings, verifier_verdict, prompt_version, proposer_raw}`; `verifier_result` on the `role='verifier'` row | T02 reads exactly `result->>'suggested_action'`, `result->>'confidence'`, `result->'reasons'`, `gate_result->>'forced'`, `gate_result->>'forced_by'`, `gate_result->>'proposed_verdict'`, `gate_result->>'verifier_verdict'`, `gate_result->'warnings'`, `gate_result->'facts'->>'correlated_clusters'`, `run_id`, `created_at` — one function, one place to change if P3-T10 lands differently |
| `python-multipart` | 0.0.32 importable, not in `backend/requirements.txt`; `fastapi` 0.141.1, `starlette` 1.6.0, `jinja2` 3.1.2, `argon2-cffi` 25.1.0, `PyJWT` 2.7.0, `httpx` 0.28.1 pinned | INBOX §8; T04's Files list carries the requirements line |
| `.env` on this host | `JWT_SECRET` absent; `WEBHOOK_API_KEY`/`WEBHOOK_IP_ALLOWLIST` absent (both default empty → fail closed) | Owner sets `JWT_SECRET` before `make run-app`; T01's login answers `503 auth disabled: JWT_SECRET unset` until then — never "no auth" |
| The live stream the pilot will see | 14/09 sample: `HR-computer` 79.4 % of documents (Windows SCA/EventChannel), `wazuh.manager`, `user1-IA1803`; both live hosts in the inventory (DEC-066) | T07's checklist says what the queue will look like and that this is **not** a reason to filter (addendum §2) |

---

## 6 · Planning decisions (tactical — Director may promote to a DEC)

1. **`web/main.py` is rewritten once, by T01, into a discovering composition root; every later card adds one module under `backend/app/web/routers/` and touches no shared file.** `web/routers/__init__.py` (T01) exposes `iter_routers() -> list[APIRouter]`: `pkgutil.iter_modules(__path__)` sorted by name, `importlib.import_module` each, and **every** module must expose `router: APIRouter` — a module without one is an `AttributeError` at import time (fail fast, no `try/except ImportError`). `main.py` does `for r in iter_routers(): app.include_router(r)`. Why: five P4 cards, P6-T02 and P4-T08 each add routes; the alternative is one `include_router` line per card in one file, which is exactly the two-cards-one-file collision E5 forbids and DEC-038 had to rule sequential in P2. `get_conn` moves to `web/deps.py` and is re-exported from `main.py` unchanged in identity (`from app.web.deps import get_conn`), so `test_reload_inventory.py`'s `main.get_conn` override still hits the same object. **P6-T02's card is amended accordingly** (its Files list: `web/routers/labels.py`, no `main.py` edit).
2. **Auth is split by the import rule.** `infra/auth.py` (T01) is pure: `hash_password`, `verify_password` (argon2id, `time_cost=3, memory_cost=65536, parallelism=4` — migration 011's parameters), `login(conn, username, password, cfg) -> Session` (lockout in the same function), `issue_token(user, cfg) -> str` (HS256; payload `sub, role, iat, exp`; `iat` a float epoch), `verify(conn, token, cfg) -> Claims` (decode → `SELECT user_id, username, role, is_active, sessions_invalid_before FROM users WHERE user_id = %s` → inactive or `iat <= sessions_invalid_before` → `Unauthorized`), `logout(conn, user_id)` (`sessions_invalid_before = now()`), and the CLI. `web/deps.py` (T01) is the FastAPI glue: `get_conn`, `get_config`, `current_user(request, conn, cfg) -> Claims` (bearer header first, then the `soc_session` cookie), `require_role(*roles)` — `403` **after** writing `authz.denied` and committing (rule 10). `infra` imports nothing from the app, so it cannot write the audit event; `web` may import everything, so it does.
3. **Writes that must survive a 4xx commit before the raise.** `get_conn` rolls back on any exception, including `HTTPException`. Three writes must survive one: the failed-login counter and lockout (`users.failed_logins`, `locked_until`), the `authz.denied` audit row, and nothing else. The route calls `conn.commit()` explicitly and then raises; the dependency's rollback is then a no-op. `decide`'s 409 is the other way round: the numbers for the body are read inside the transaction (`SELECT occurrence_count, status, acknowledged_by, close_reason …`) and carried in `DecisionConflict`; the rollback that follows is correct — nothing was meant to persist.
4. **`tier1/decide.py` is a thin, guarded layer over `domain.transitions`; the two payload fields the brief adds go into `transitions.decide` as keyword arguments with `None` defaults.** `acknowledge(conn, alert_id, actor)` → idempotent (`tier1_active` already → the stored acknowledger, 200); `decide(conn, alert_id, actor, *, decision ∈ false_positive|benign, reason, seen_occurrence_count)` → maps to `closed_fp|closed_benign`, reads the latest proposer run (`llm_suggestion`, `llm_confidence`, `gate_forced`, `llm_run_id`) and the row's `suggestion_visible`, calls `transitions.decide(…, llm_suggestion=…, llm_confidence=…, gate_forced=…, suggestion_visible=…, llm_run_id=…)`, and converts `StaleState` into `DecisionConflict(kind ∈ cluster_grew|already_decided|not_active, occurrence_count, seen_occurrence_count, delta, tolerance, decided_by, decision, decided_at)`; `escalate(conn, alert_id, actor, *, title, severity=None)` → guards `status ∈ (queued_tier1, tier1_active)` under `FOR UPDATE` (§5: `transitions.escalate` has none), then `transitions.escalate`; `reopen(conn, alert_id, actor, *, reason)` → `transitions.reopen`. `domain/transitions.py` gains three keyword arguments on `decide` (`gate_forced: bool | None = None`, `suggestion_visible: bool | None = None`, `llm_run_id: str | None = None`) written into the `tier1.decided` payload as `gate_forced`, `suggestion_visible`, `llm_run_id`; existing callers and `test_transitions.py` are untouched. `tier1.decided` is therefore the evaluation join the brief asks for: `decision, reason, occurrence_count, llm_suggestion, llm_confidence, gate_forced, suggestion_visible, llm_run_id`.
5. **One function reads ① for every consumer.** `tier1/queue.py` (T02) has `latest_suggestion(conn, alert_id) -> Suggestion | None` and the queue's `LEFT JOIN LATERAL (SELECT run_id, result, gate_result, created_at FROM llm_runs WHERE subject_id = a.alert_id AND pipeline = 'triage' AND role = 'proposer' ORDER BY created_at DESC LIMIT 1) r ON true`; the fields are §5's list. `Suggestion` = `{run_id, suggested_action, confidence, reasons: [{claim, quote, source}], gate: {forced, forced_by, proposed_verdict, final_verdict, verifier_verdict, warnings: [...]}, correlated_at_analysis: int | None, created_at}`. The detail view carries `suggestion: Suggestion | None` plus `triage_status`; the queue row carries `suggested_action`, `confidence`, `gate_forced`. Test fixtures insert `llm_runs` rows in exactly this shape (P3-T10's), quoted in T02's card, so the tests run with `llm_runs` empty on `soc_dev`.
6. **`needs_retriage` uses the v1 constants as module constants.** `RETRIAGE_FACTOR = 10`, `RETRIAGE_ABS_DELTA = 200` in `tier1/queue.py` with a comment naming `docs/phase-2-chong-trung-lap.md:321`; putting them in `Config` is a §6.3 change and P2/P3 did not need them. The phase-6 predicate is copied verbatim.
7. **The visibility filter is one pure function, applied inside `tier1/queue.py`'s two readers, never in a template.** `visibility.strip(view: dict, *, status: str, suggestion_visible: bool, mode: Literal["analyst", "labeling"]) -> dict` (T02). Analyst mode: when `suggestion_visible is False and status not in SHOW_STATES` the keys `suggestion`, `suggested_action`, `confidence`, `gate_forced`, `triage_status` are removed (the dict is rebuilt, never mutated) — for **every** role, so the role is not a parameter; `suggestion_visible` itself stays visible (the analyst may know they are on the blind arm; they may not know what the model said). `SHOW_STATES = {closed_fp, closed_benign, closed_confirmed, escalated_tier2, auto_closed}` — `auto_closed` is in because D8's digest (P5) reviews auto-closed clusters *against* ①; a reopened alert (A17 → `queued_tier1`) is blind again, and T07's checklist tells P8 to exclude reopened alerts from the blind-branch agreement metric. Labeling mode: **regardless of `suggestion_visible` and status**, remove every key in `LABELING_DENYLIST` = the analyst set ∪ `{suggestion_visible, source, status, risk_score, risk_band, risk_score_components, asset_context, identity_context, ioc_context, lookup_status, case_id, autoclose_rule_id, acknowledged_at, acknowledged_by, closed_at, sealed_at, close_reason, duplicate_of, gate_result, verifier_result, llm_run_id, run_id}` **recursively** through nested dicts and lists (correlation rows carry `status`; a sample carries `status`), plus any key starting with `llm_` or `verifier`. `list_queue` and `get_alert_view` call it in analyst mode; P6-T02 calls it in labeling mode on its own allowlisted dict (belt and braces). The matrix test: status (6) × `suggestion_visible` (2) × mode (2), and for labeling mode the three `source` values.
8. **Per-request DB check on every authenticated request, one SELECT by PK.** `verify` never trusts the token's `role` claim alone — the role and `is_active` come from the row, and a token whose `iat` is at or before `sessions_invalid_before` is dead. `iat` is a float so a logout and a new login inside the same second do not collide. Tokens are HS256 with `JWT_SECRET`; an empty secret makes `login` answer `503 auth disabled: JWT_SECRET unset` (fail closed, like the webhook's empty key — DEC-040's shape). The cookie is `soc_session`, `HttpOnly`, `SameSite=Lax`, `Secure` **off** because the app binds `127.0.0.1:8000` with no TLS (Makefile `run-app`) — a P8 limitation sentence, stated in T04 and in T07's checklist, not silently.
9. **HTML pages are pages, not §6.4 operations.** `GET /login`, `POST /login`, `POST /logout`, `GET /`, `GET /queue`, `GET /alerts/{id}`, `POST /alerts/{id}/{acknowledge|decide|escalate|reopen}` (HTMX partials) are the browser UI over the seven §6.4 tier1/auth operations; they call the same `tier1/decide.py` functions and add nothing the API cannot do. P6-T02 took the same position for `/admin/labels`. No INBOX item is owed for them.
10. **The 409 carries N and M, and the flash says what to do.** `DecisionConflict` → `409 {"kind", "occurrence_count": M, "seen_occurrence_count": N, "delta", "tolerance", "decided_by", "decision", "decided_at"}`; the HTML partial renders *"Cụm đã tăng từ N lên M bản sao trong lúc bạn đọc — xem lại rồi xác nhận"* with a refreshed hidden `seen_occurrence_count = M`, or *"Đã được <ai> quyết <gì> lúc <khi nào>"* — never a silent overwrite (phase-6 P6-2). A `statement_timeout` on a large fan-out → `503`, whole transaction rolled back (phase-6 error table); the route sets `SET LOCAL statement_timeout = '3s'` first.
11. **Acknowledge is a separate POST, never a side effect of GET.** The detail page renders the decision form only when the alert is `tier1_active` (or shows *"Tiếp nhận"* when `queued_tier1`); opening the page changes nothing (the brief: "acknowledge as separate POST"). Two analysts opening the same alert both see it; the first *"Tiếp nhận"* wins the SLA mark; the second sees who has it (phase-6 P6-2).
12. **The seed CLI is `python3 -m app.infra.auth`, passwords never on argv.** `seed-users --user USERNAME ROLE "Display Name"` (repeatable) reads each password from `SEED_PASSWORD_<USERNAME_UPPER>` or `getpass`; existing usernames are **skipped, never overwritten**; `set-password USERNAME` and `deactivate USERNAME` are the only other subcommands; every creation writes `admin.user_created` (`system`, payload `{username, role}`). The Owner runs it from the primary checkout with `--env-file .env` (the `app_rw` DSN can INSERT into `users` — migration 017 grants it). Four accounts are expected: Owner `tier1`, advisor `tier2`, Owner `admin`, advisor `admin` (P6 item (1); `P6-T02` planning decision 7).
13. **T08 is P2-T12 re-homed, not rewritten.** The card's body is P2-T12's with the two `⟨KEY⟩`s filled from DEC-040 (`WEBHOOK_API_KEY`, `WEBHOOK_IP_ALLOWLIST`), the route moved into `web/routers/webhook.py` (planning decision 1), and the intake INSERT written in `infra/intake.py` with `via='webhook'` (the puller's `_insert_alert` is private and `pull`-specific; `is_heartbeat` is public and reused). `tasks/P2/P2-T12.prompt.md` gets a banner pointing here; its STATE row is renamed.

---

## 7 · Exit-gate coverage

| Gate item (`prompts/P4.md:32`, `01-plan.md:11`) | Covered by | Notes |
|---|---|---|
| Login works end-to-end | **T01** (API), **T04** (page), **T06** (the flow) | 5 wrong passwords → 423; logout invalidates; inactive → 401 |
| Queue, detail, decide/escalate/reopen work end-to-end | **T02** (queue logic), **T03** (API + decide), **T05** (pages + partials), **T06** (one test walks login → queue → detail → acknowledge → decide → fan-out → queue empty; a second walks escalate; a third reopen) | the Director runs T06's file as the gate check |
| Blind alerts return no suggestion at the API for any role | **T02** (`visibility.strip`, matrix) + **T03** (`GET /api/tier1/alerts/{id}` as tier1, tier2, admin on a blind alert with an `llm_runs` row → no `suggestion` key; after `decide` → present; `tier1.decided` payload carries the four join fields) | the "for any role" half is a three-role test, not a sentence |
| Pilot started (Owner action) | **T07** (the checklist) + §10 | the Owner logs in as `tier1` and decides real alerts; nothing else counts |

---

## 8 · INBOX items raised by this plan

- `2026-09-19 · P4-T04 · DECISION_REQUEST` — **`python-multipart==0.0.32` enters `backend/requirements.txt`.** FastAPI's `Form(...)` and `await request.form()` need it; it is importable on this host and absent from the pinned file (the P1 `jsonschema` trap, DEC-025's shape: green here, red on a clean checkout). Options: **A (recommended)** pin it — one line in a file that is P0-T02's product, not a §6 contract, and the library the framework itself documents for forms; **B** parse `application/x-www-form-urlencoded` bodies by hand with `urllib.parse.parse_qs(await request.body())` in one helper (`web/deps.py:form_fields`) — stdlib, no dependency, but every form route and every test goes through a home-made parser and multipart is impossible. T04 is written for **A**; under B its Files list loses the requirements line and gains the helper (one paragraph). Frozen contract affected: none. Needed by 21/09 (T04's dispatch).

Not an INBOX item, but named for the record: **`transitions.escalate` has no status guard on the trigger** (§5). T03 guards. If the Director wants the guard inside `domain/` (the G2 place for it), that is a one-line P2 follow-up with its own card, not part of P4.

---

## 9 · Task table

| Task | Title | Priority | Est. | Depends on | Owner action? |
|---|---|---|---|---|---|
| P4-T01 | `infra/auth.py` (argon2id, JWT HS256 8 h, lockout, per-request DB check, `logout`, seed CLI) + `web/deps.py` (`get_conn`, `current_user`, `require_role` with `authz.denied`) + `web/routers/{__init__,auth}.py` (`POST /api/auth/login`, `POST /api/auth/logout`) + `web/main.py` rewritten as a discovering composition root, `reload-inventory` wrapped with `admin` | must | 4 h | — | **yes** — `JWT_SECRET` into `.env`; run `seed-users` for four accounts |
| P4-T02 | `tier1/queue.py` (`list_queue` OFFSET-paged with the phase-6 ordering and `needs_retriage`, `risk_band`, `latest_suggestion`, `get_alert_view` with correlation/targeted accounts/playbook) + `tier1/visibility.py` (`strip`, analyst + `labeling` modes) + tests incl. the matrix and the three-value `source` test | must | 3.5 h | — | no |
| P4-T03 | `tier1/decide.py` (`acknowledge` idempotent, `decide` with the 409 body, `escalate` guarded, `reopen`) + `domain/transitions.py` (`decide` gains `gate_forced`, `suggestion_visible`, `llm_run_id`) + `web/routers/tier1.py` (the six `/api/tier1/*` operations) + tests | must | 4.5 h | P4-T01, P4-T02 | no |
| P4-T04 | `web/templates/{base,login}.html`, `web/templating.py` (Jinja2 env, autoescape, HTMX from cdnjs pinned, `DISPLAY_TZ` filter, flash partial), `web/routers/pages.py` (`GET /login`, `POST /login` → cookie, `POST /logout`, `GET /` → `/queue`), `python-multipart` pinned (INBOX) | must | 2.5 h | P4-T01 (+ the INBOX answer) | no |
| P4-T05 | `web/templates/{queue,alert,_flash,_decision_form,_suggestion}.html` + `web/routers/alerts_pages.py` (`GET /queue`, `GET /alerts/{id}`, the four HTMX partial POSTs with 409 flash N/M) + tests through the pages | must | 5 h | P4-T03, P4-T04 | **yes** — the pilot starts when this merges |
| P4-T06 | `backend/tests/test_e2e_tier1.py` — three end-to-end flows through the HTML routes on a composed tree; the gate's proof | must | 1.5 h | P4-T05 | no |
| P4-T07 | `docs/runbook.md` — section "Pilot" (preconditions with proof commands, start, daily checks, exclusions for P8, the blind-branch rule for the advisor) | must | 1 h | — | **yes** — execute it |
| P4-T08 | `infra/intake.py` + `web/routers/webhook.py` (`POST /webhook/alerts`) — P2-T12 re-homed with `WEBHOOK_API_KEY` / `WEBHOOK_IP_ALLOWLIST` (DEC-040) | should | 2.5 h | P4-T01 | no (keys stay empty → `503` until the Owner sets them) |

File scope is disjoint by construction: **T01** owns `backend/app/infra/auth.py`, `backend/app/web/main.py`, `backend/app/web/deps.py`, `backend/app/web/routers/__init__.py`, `backend/app/web/routers/auth.py`, `backend/tests/test_auth.py`, `backend/tests/test_reload_inventory.py` (fixture update); **T02** owns `backend/app/tier1/queue.py`, `backend/app/tier1/visibility.py`, `backend/tests/test_queue.py`, `backend/tests/test_visibility.py`; **T03** owns `backend/app/tier1/decide.py`, `backend/app/domain/transitions.py`, `backend/app/web/routers/tier1.py`, `backend/tests/test_decide.py`, `backend/tests/test_tier1_api.py`; **T04** owns `backend/app/web/templating.py`, `backend/app/web/templates/base.html`, `backend/app/web/templates/login.html`, `backend/app/web/templates/_flash.html`, `backend/app/web/routers/pages.py`, `backend/requirements.txt`, `backend/tests/test_pages_login.py`; **T05** owns `backend/app/web/routers/alerts_pages.py`, `backend/app/web/templates/queue.html`, `backend/app/web/templates/alert.html`, `backend/app/web/templates/_decision_form.html`, `backend/app/web/templates/_suggestion.html`, `backend/tests/test_pages_alerts.py`; **T06** owns `backend/tests/test_e2e_tier1.py`; **T07** owns `docs/runbook.md`; **T08** owns `backend/app/infra/intake.py`, `backend/app/web/routers/webhook.py`, `backend/tests/test_webhook.py`. P6-T02 (amended today) owns `backend/app/web/routers/labels.py`, `backend/app/tier1/labels.py`, `backend/app/web/templates/labels.html`, `backend/tests/test_labels.py`. No file appears in two cards.

---

### P4-T01 · auth, deps, routers package, `main.py`, seed CLI
- Priority: must · Estimate: 4 h · Depends on: —
- Goal: `infra/auth.py` (planning decision 2), `web/deps.py`, `web/routers/` with `auth.py`, `main.py` rewritten (planning decision 1) and `reload-inventory` wrapped with `admin`; `python3 -m app.infra.auth seed-users`.
- Files — modify: `backend/app/infra/auth.py`, `backend/app/web/main.py`, `backend/tests/test_reload_inventory.py`. Create: `backend/app/web/deps.py`, `backend/app/web/routers/__init__.py`, `backend/app/web/routers/auth.py`, `backend/tests/test_auth.py`.
- Contracts touched: none (`POST /api/auth/login`, `POST /api/auth/logout` are §6.4 operations being implemented; `JWT_*`, `LOGIN_MAX_FAILS`, `LOCKOUT_MINUTES` read).
- Risk / notes: the head of both chains; `authz.denied` and the lockout counter commit before raising (planning decision 3); `JWT_SECRET` empty → 503 fail-closed.

### P4-T02 · queue + visibility filter
- Priority: must · Estimate: 3.5 h · Depends on: —
- Goal: `list_queue`, `risk_band`, `latest_suggestion`, `get_alert_view` (planning decisions 5–7) and `visibility.strip` with both modes; the role × status × visibility × mode matrix; the three-value `source` test.
- Files — modify: `backend/app/tier1/queue.py`. Create: `backend/app/tier1/visibility.py`, `backend/tests/test_queue.py`, `backend/tests/test_visibility.py`.
- Contracts touched: none.
- Risk / notes: no route, no auth — runs beside T01; P6-T02 imports `strip(mode="labeling")` from here.

### P4-T03 · tier1 REST + decide
- Priority: must · Estimate: 4.5 h · Depends on: P4-T01, P4-T02
- Goal: `tier1/decide.py` (planning decisions 4, 10, 11), the three payload kwargs on `transitions.decide`, `web/routers/tier1.py` with `GET /api/tier1/queue`, `GET /api/tier1/alerts/{id}`, `POST /api/tier1/alerts/{id}/acknowledge|decide|escalate|reopen`; the blind-branch API test for three roles.
- Files — modify: `backend/app/tier1/decide.py`, `backend/app/domain/transitions.py`. Create: `backend/app/web/routers/tier1.py`, `backend/tests/test_decide.py`, `backend/tests/test_tier1_api.py`.
- Contracts touched: none (six §6.4 operations implemented; `tier1.decided` payload extended, no new event type).
- Risk / notes: `test_transitions.py` must stay green untouched (defaults `None`); `escalate` is guarded here (§5).

### P4-T04 · base layout + login/logout pages
- Priority: must · Estimate: 2.5 h · Depends on: P4-T01 (+ INBOX §8 answered)
- Goal: `templating.py` (Jinja2 env, autoescape on, HTMX pinned from cdnjs, `local_time` filter on `DISPLAY_TZ`, `flash` partial), `base.html`, `login.html`, `pages.py` (`GET /login`, `POST /login` → `soc_session` cookie, `POST /logout`, `GET /` → 303 `/queue`), `python-multipart` pinned.
- Files — create: `backend/app/web/templating.py`, `backend/app/web/templates/base.html`, `backend/app/web/templates/login.html`, `backend/app/web/templates/_flash.html`, `backend/app/web/routers/pages.py`, `backend/tests/test_pages_login.py`. Modify: `backend/requirements.txt` (one line).
- Contracts touched: none.
- Risk / notes: P6-T02 extends `base.html`; the cookie is not `Secure` (127.0.0.1, no TLS — P8 limitation).

### P4-T05 · queue + detail pages + HTMX partials
- Priority: must · Estimate: 5 h · Depends on: P4-T03, P4-T04
- Goal: `GET /queue` (rows with band + severity, `needs_retriage` first, OFFSET pager), `GET /alerts/{id}` (raw_log, correlation ±2 h, targeted accounts, playbook, ① block when visible with reasons + quotes + gate summary + the N/M delta sentence, enrichment context, decision form with `seen_occurrence_count`), partials for acknowledge/decide/escalate/reopen, the 409 flash with N and M; tests through the pages incl. "the raw risk number is not in the HTML" and "a blind alert's page has no suggestion text".
- Files — create: `backend/app/web/routers/alerts_pages.py`, `backend/app/web/templates/queue.html`, `backend/app/web/templates/alert.html`, `backend/app/web/templates/_decision_form.html`, `backend/app/web/templates/_suggestion.html`, `backend/tests/test_pages_alerts.py`.
- Contracts touched: none.
- Risk / notes: the pilot starts when this merges; Vietnamese labels in templates, code English; `raw_log` rendered escaped inside `<pre>`, never `|safe`.

### P4-T06 · end-to-end through the HTML routes
- Priority: must · Estimate: 1.5 h · Depends on: P4-T05
- Goal: `test_e2e_tier1.py` — three flows on one `TestClient` with a real session cookie: (1) login → queue → detail → acknowledge → decide `benign` with fan-out → queue empty → `tier1.decided` payload has the four join fields; (2) escalate → case + `case_alerts` + correlated head leaves the queue; (3) reopen from `auto_closed` only; plus the blind check through the page for a blind alert with an `llm_runs` row and after decision.
- Files — create: `backend/tests/test_e2e_tier1.py`.
- Contracts touched: none.
- Risk / notes: run by the Director as the gate check; deliberately a separate file so it runs on the composed tree (DEC-047's lesson).

### P4-T07 · pilot checklist
- Priority: must · Estimate: 1 h · Depends on: —
- Goal: `docs/runbook.md` with one section, "Pilot": preconditions with proof commands (`JWT_SECRET`, seeded users, worker + puller running and the cursor advancing, inventory loaded, `make run-app`), what the queue will look like on day 1 (383 replay heads `asset = unknown` — DEC-083; `HR-computer` ≈ 79 % of the live stream — not a reason to filter), the start (Owner logs in as `tier1` and decides real alerts), the blind-branch rule for the advisor (never open `llm_runs` before deciding), daily checks, what P8 excludes (`source='lab'`, reopened alerts, the 383 pre-inventory heads), the cookie/TLS limitation.
- Files — create: `docs/runbook.md`.
- Contracts touched: none.
- Risk / notes: P8 extends the same file; every command in it is one the Owner can paste.

### P4-T08 · webhook (P2-T12 re-homed)
- Priority: should · Estimate: 2.5 h · Depends on: P4-T01
- Goal: P2-T12's card with `WEBHOOK_API_KEY` / `WEBHOOK_IP_ALLOWLIST` filled (DEC-040): `infra/intake.py:receive`, `POST /webhook/alerts` (`503` when the key is empty, `401` writing nothing, `403` outside the allowlist, `413` before parsing, `400` with the field name + `rejected_alerts`, `409` on a repeat, `201` + a `pipeline` job in the same transaction, heartbeat → `201` no job, G9 byte identity).
- Files — modify: `backend/app/infra/intake.py`. Create: `backend/app/web/routers/webhook.py`, `backend/tests/test_webhook.py`.
- Contracts touched: none (`POST /webhook/alerts` is §6.4; the two keys are §6.3 since DEC-040).
- Risk / notes: off the gate; last in the order; the keys stay empty on this host until the Owner sets them, so the route answers `503` and exposes nothing.

---

## 10 · Owner actions this phase (one line each, only what a human can do)

1. **Now, before `make run-app` ever runs:** `python3 -c "import secrets; print(secrets.token_hex(32))"` → paste as `JWT_SECRET=<value>` into `.env` (git-ignored; never into `.env.example`). Until it is set, `POST /api/auth/login` answers `503 auth disabled`.
2. **Before the lab (22/09) and before the pilot:** start the worker and the puller from the primary checkout (`make run-worker`; the puller is the `pull` job it enqueues) and prove the catch-up: `psql "$DATABASE_URL" -Atc "select last_sort, last_pull_at from source_cursor"` advancing across two runs 2 min apart, and `select count(*) from alerts where source='wazuh'` rising from 3,941.
3. **When P4-T01 merges (20/09):** from the primary checkout, `PYTHONPATH=backend python3 -m app.infra.auth seed-users --env-file .env --user <owner-t1> tier1 "<name>" --user <advisor-t2> tier2 "<name>" --user <owner-admin> admin "<name>" --user <advisor-admin> admin "<name>"` — four accounts; the two `admin` ones are P6's labelling accounts (P6 item (1)). Passwords **at the `getpass` prompt** the CLI opens for each user (P4-T01.prompt.md:30); an inline `SEED_PASSWORD_<USER>=… command` form lands the password in shell history and is not used here (Director at E5, DEC-095).
4. **Before the pilot:** tell the advisor the blind-branch rule in one sentence — *decide first; never open `llm_runs` or ask what ① said before deciding* — and that half the alerts show no suggestion by design.
5. **When P4-T05 merges (23/09 evening at the earliest):** `make run-app`, open `http://127.0.0.1:8000/login`, log in as `tier1`, decide real alerts. **That is the pilot start** — write the date and time into `STATE.md`.
6. **Answer INBOX `2026-09-19 · P4-T04` (Director's) by 21/09** — the Owner only if the Director escalates it.

---

## 11 · Hand-off to P5, P6 and P8

1. **P6-T02 imports three names from P4:** `app.web.deps.require_role("admin")` (and `current_user` for the session-bound `labeler`), `app.tier1.visibility.strip(view, status=…, suggestion_visible=…, mode="labeling")`, and `templates/base.html` via `app.web.templating.templates`. It creates `web/routers/labels.py` (discovered automatically) and touches no `main.py`. Its card is amended today with those names (banner at the top of `P6-T02.prompt.md`).
2. **P5's digest page and admin rules screen** add `web/routers/<name>.py` modules and `templates/*.html` extending `base.html`; `require_role("admin")` is the dependency; `POST /api/admin/reload-inventory`'s wrapping in T01 (was written `GET` until 19/09 — the route is `POST`, `web/main.py:47`; Director at E5) is the pattern. `tier1/digest.py` reads `latest_suggestion` (T02) for the ① verdict beside the auto-close rule — `SHOW_STATES` includes `auto_closed` for exactly that (planning decision 7).
3. **P8's pilot export** joins `audit_events(event_type = 'tier1.decided')` on `subject_id` with `payload->>'llm_suggestion'`, `payload->>'gate_forced'`, `payload->>'suggestion_visible'`, `payload->>'llm_run_id'` (planning decision 4); excludes `alerts.source = 'lab'` (DEC-085), reopened alerts (`alert.reopened` exists for the subject), and — as a named limitation — the 383 heads enriched before the inventory was loaded (DEC-083).
4. **Limitations this phase produces for P8:** the session cookie is not `Secure` (no TLS on `127.0.0.1`); no CSRF token beyond `SameSite=Lax` on a two-user localhost pilot; `REVIEW_DELTA_TOLERANCE = 20` and `RETRIAGE_FACTOR/ABS_DELTA` are unvalidated v1 constants (phase-6 "việc còn lại"); the pilot's day-1 queue is 383 pre-inventory heads; ≈ 79 % of live documents are one Windows endpoint's SCA/EventChannel noise.
