# SOAR intake — switches Implementation Plan

> **Process (DEC-201, DEC-207 item 8):** one Coder subagent (`coder-sonnet55`: Sonnet 5.5, xhigh, own isolated worktree) and one independent Reviewer subagent (`general-purpose`, own worktree) per task. The Director's session manages from `../AI_Support_SOC_soar`, branch `director/soar-intake`: it dispatches, merges, runs one mutation of its own at the merge, commits each review verbatim, and keeps STATE. The Coder's first step is `git merge --ff-only director/soar-intake`.

**Goal:** Alerts arrive from the external SOAR/n8n stream, which has already enriched, grouped and auto-closed them. This project stops doing those four things (dedup, indexer pull, internal enrichment, auto-close) when the Owner turns the flags off. With the flags at their defaults nothing changes.

**Decision:** DEC-207, in `docs/plan/DECISIONS.md`. Read it with this plan.

**Checkpoint:** tag `checkpoint/pre-soar-intake` at `a0398c2`. Nothing in this plan moves it.

## Global Constraints

- **Defaults.** Every new key defaults to `true`. A `.env` that names none of them must behave exactly as at `a0398c2`. A test shows it.
- **No deletion.** The code of dedup, the puller, `enrichment/` and `ingest/autoclose.py`, and the tables, stay. No migration.
- **Frozen contracts.** Config keys are a frozen contract (context pack §6.3); this task adds three keys and says so in the report. Event types, job types, routes and the import rules are not touched.
- **Import rules.** `infra/*` imports nothing from `app.*` outside `infra` (`test_import_rules.py`).
- **Time.** Control timestamps are the database's `now()`.
- **Tests.** DB tests carry `@pytest.mark.db`. Use a private scratch PostgreSQL 16 for `TEST_DATABASE_URL`, never the live cluster; never print a DSN or a password. Tests never read `.env`. LLM calls go through the fake adapter (`backend/tests/fakes/llm.py`).
- **Every guard shown red once (DEC-025/027).** For each switch, break the condition on a scratch copy and watch the new test fail. Do not weaken the real check in place.
- **Do not touch** `eval/` in any way.

## P12-T01: Switches and heartbeat

**Files — modify:**
- `backend/app/infra/config.py`: add `PULL_ENABLED`, `AUTOCLOSE_ENABLED`, `ENRICHMENT_ENABLED` as `bool = True`, next to `DEDUP_ENABLED` (field at `:132`, loader at `:259`), read with `as_bool(name, True)`.
- `backend/app/web/worker.py`: seed the `pull` job (`:42`) only when `PULL_ENABLED`.
- `backend/app/infra/puller.py`: `pull_job` (`:316`) returns `None` when `PULL_ENABLED` is false, before any client is built. The return type becomes `Reschedule | None`. A `pull` row already pending then ends after one run and is not re-armed. `backfill` and `replay` (CLI) do not read the flag.
- `backend/app/soar/pipeline.py`:
  - `AUTOCLOSE_ENABLED=false`: do not call `autoclose.load_rules` (`:91`) or `autoclose.evaluate` (`:120`); the alert goes through the `received` branch (`:136-151`).
  - `ENRICHMENT_ENABLED=false`: `_build_context` (`:154`) issues no SQL and returns `AlertContext(False, "unknown", None, None, None, "skipped", {"asset": "skipped", "identity": "skipped", "ioc": "skipped"})`. Check the field order and the vocabulary against `domain/alert.py` and `llm/builder.py` before you write it.
  - Risk still runs (`compute_risk_score`, `:118`).
- `backend/app/infra/intake.py`: after a non-heartbeat alert is inserted and enqueued (`:134-146`), call `_update_heartbeat(conn, saw_alert=True)`. A `Duplicate` (409) does not stamp.
- `backend/app/infra/health.py`: `_check_inventory_empty` (`:228`) takes `cfg`; with `ENRICHMENT_ENABLED=false` it returns `ok=True` and the detail `"n/a — enrichment off"`.
- `.env.example`, `docs/runbook.md` (the key table, the §6.3 count, a short "SOAR intake" section next to the DEDUP_ENABLED one at `:152-161`: how to switch, `up -d` not `restart`, how to check with `printenv`, the three rollback levels from DEC-207 item 6), `docs/limitations.md` (DEC-207 item 3's three consequences).
- Tests: `test_config.py`, `test_runbook_env_keys.py`, `test_pipeline.py`, `test_puller.py`, `test_worker_handlers.py`, `test_webhook.py` or `test_intake*.py`, `test_health.py`.

**Steps:**
- [ ] **Step 1: tests, red first.**
  - Config: the three keys exist, default `true`, parse `false`.
  - Defaults: with no flag set, the existing pipeline, puller and health tests pass unchanged.
  - Pull: flag off, the worker's start-up seeds no `pull` row; `pull_job` returns `None` and never builds a client or opens a connection to the indexer (inject a `client_factory` that fails the test if called); flag on, it returns `Reschedule(PULL_INTERVAL_S)` as before.
  - Auto-close: flag off, a rule that would match does not close the alert, `status` ends `queued_tier1`, a `triage` job exists, no `autoclose_rules` query ran; flag on, unchanged. A `critical` alert and an `high` asset behave the same either way (nothing closes).
  - Enrichment: flag off, no statement mentioning `assets`, `identities` or `iocs` reaches the connection (record the SQL with a cursor wrapper or `psycopg` logging); `alerts.lookup_status` is all `skipped`, `asset_context.present` is false, `risk_score_components` carries no asset, identity or IoC addend; flag on, unchanged.
  - Dedup: with `DEDUP_ENABLED=false` and the three new flags off, two alerts with the same cluster key are two heads, each with its own `triage` job. (This pins the combination the Owner will run.)
  - Heartbeat: a webhook alert stamps `source_heartbeat.last_seen_at` and `last_alert_at`; a 409 does not change them; the heartbeat branch still stamps with `last_alert_at` untouched.
  - Health: `inventory_empty` with an empty `assets` table is `ok` when enrichment is off and not ok when it is on.
  - Gate: with the "unknown" context, a ① `false_positive` is forced to `needs_review` at step 4 (this documents the consequence in DEC-207 item 3; use the fake adapter).
  - Blind arm: with all flags off, `tier1/visibility.py` and the admin audit, usage and digest answers still hide the ① suggestion on a blind, undecided alert (reuse the existing P11 fixtures); the overview and the digest answer 200 and render with no auto-closed alert and no inventory.
- [ ] **Step 2:** Implement until green. Show each new guard red once on a scratch copy.
- [ ] **Step 3:** Docs: runbook, `.env.example`, limitations.
- [ ] **Step 4:** Suites: `make lint`, `make test`, `make test-db` (private scratch database), `make ui-test`. If you touched nothing under `frontend/`, say so and run `make ui-test` once to show it unchanged. `make ui-e2e` only if a page changed (it holds a per-user lock on ports 18000 and 18080).
- [ ] **Step 5:** Report `docs/plan/tasks/P12/P12-T01.report.md`: Built · Acceptance results · Deviations · Open questions · Reproduce. State the three new config keys and the 62 → 65 key count if the runbook table counts them.

**Do not:** read or write the live database; run anything with `docker`; edit `eval/`; change a migration; remove a module.

## P12-T02: Context from the SOAR payload (DEC-208)

**Starts after P12-T01 is merged** (both edit `_build_context`). Sample: `docs/plan/tasks/P12/soar-payload-sample-1.0.json`; copy it into `backend/tests/fixtures/` and derive the variants there.

**Files — modify:** `backend/app/soar/pipeline.py` (`_build_context` reads `enrichment` when `ENRICHMENT_ENABLED=false`; with enrichment on, the internal lookups stay), `backend/app/ingest/wazuh_parser.py` (user fallback), `backend/app/tier1/triage.py` and `backend/app/llm/triage.py` (the occurrence fact may be `None`), tests, `docs/limitations.md`.

**Rules (DEC-208 item 3–5):**
- `schema_version` must match `1.<n>`; else, or with no `enrichment`, the "unknown" context of P12-T01.
- Asset (DEC-208 amended 23/10): `asset_criticality` = `asset.criticality` (`high|medium|low|unknown`; absent → `unknown`); `asset_present` = `asset.in_inventory`; `asset.critical` is not read.
- `asset.user_is_admin`: bool → `identity_privileged`; `null`/absent → `None`, identity status `skipped`.
- IoC: worst of `ti[].verdict` and `ioc.verdict` (`malicious > suspicious > clean`); no block → `skipped`.
- Any value outside its vocabulary, or a wrong type → the whole context "unknown"; log the field name only.
- `occurrence_count` in the ① facts is `None` when the context comes from SOAR; the prompt renders it as "không rõ"; the risk occurrence addend is 0.
- Parser: no user found → `enrichment.asset.user` with the domain dropped (`FPT\hr01` → `hr01`, `hr01` unchanged).

**Tests (red first):** the sample, with `asset.criticality: medium` and `in_inventory: true` added, maps to `medium`, `False`, `skipped`; a sample without `asset.criticality` maps to `unknown`; the pfSense SC03 sample (`docs/plan/tasks/P12/soar-payload-sample-sc03-1.0.json`, checked 23/10 on the current parser: `category=recon` by MITRE T1046, `srcip`/`dstip`/ports parsed, `raw_log` = `full_log`) maps to `high`, identity `skipped`, IoC `clean`; each `ti` verdict and the C202 `ioc` block; two `ti` entries take the worst; a bad verdict, a string `critical`, a `2.0` schema and a missing block each give the whole "unknown" context; with `occurrence_count=None` none of the nine `occurrence_lt` rules matches and a ① `false_positive` is forced to `needs_review`; the parser fallback with and without a domain; no SQL reaches the inventory tables; the blind-arm pages still hide the suggestion. Suites as P12-T01.
