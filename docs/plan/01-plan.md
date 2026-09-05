# Delivery Plan — 9 phases, 14 days (04/09 → 18/09/2026)

Companion to `00-context-pack.md`. Each phase has one Planner prompt (`prompts/P*.md`) that turns it into task cards and coder prompts. Dates assume one developer working full time; cut order is in the context pack §10.

| Phase | Days | Objective | Exit gate (Director checks) |
|---|---|---|---|
| P0 Preparation | D0 04/09 (Fri) | Repo, environment, access, inventory files, canonical fixtures, coordination files | `make test` runs (even if 0 tests); indexer query returns documents; `.env.example` complete; `conf/*.yaml` present; `Final-Project` reuse decision recorded |
| P1 Smoke test + schema | D1 05/09 (Sat) → **slipped one day, DEC-030** | Prove the model works; land the v3 schema | `docs/smoke-test-D1.md` with numbers; migrations **013, 014, 016, 017** apply on a clean `soc_dev` with one command (`scripts/migrate.sh`) on any cluster whose migrator can create roles — 017 creates `app_rw` as NOLOGIN when absent and never stops for a missing role (DEC-024(a), which withdrew the earlier cluster-precondition qualifier). **015 (P1-T04) left this gate on 06/09 by Owner decision (DEC-029): not cut, card dispatch-ready, fills any idle coder slot, must merge before P4 (D5 09/09).** Granting `app_rw` LOGIN and a password is the one-off superuser step in HUONG-DAN §0 item 6 — done 05/09 on this host — needed only for the application to connect at P2, never for the migrations to apply (DEC-023, DEC-024); DB tests green |
| P2 Intake + pipeline | D2–D3 06–07/09 → **planning 06/09, coders from 07/09 (DEC-030, DEC-031)** | Alerts flow from indexer to `queued_tier1` without any LLM | G7 test green (< 30 s with LLM off); backfill lands in `alerts` from both sources (DEC-019): the indexer for 02/09 onward — all it holds (DEC-017) — and the manager archive for the pre-02/09 history as `source='replay'`; dedup, auto-close, simulate tests green; 18 transitions tested |
| P3 AI pipeline ① | D4 08/09 (Tue) | Proposer + gate + verifier on real replayed alerts | Linter rejects every legacy violation; gate tests green; ① runs live on ≥ 50 replayed alerts with `gate_result` written; cost recorded |
| P4 UI + auth + blind branch | D5 09/09 (Wed) | Two analysts can work Tier-1 in a browser; pilot starts | Login, queue, detail, decide/escalate/reopen work end-to-end; blind alerts return no suggestion at API level; pilot started |
| P5 Tier-2 + digest + ops | D6 10/09 (Thu) | Cases, ②, digest, health, backup | ② runs on a real case with evidence check; digest page reviews an auto-closed cluster and reopens it; health alarm fires when the indexer is unreachable; backup file produced |
| P6 Lab data + labeling | D7–D9 11–13/09 | Gold sets G1/G2/G3 built, labelled blind, frozen | `eval/gold_v1.csv` + sha256 committed; κ reported; ≥ 300 clusters; G2 ≥ 60 incl. ≥ 20 benign lab clusters; G3 = 40 |
| P7 Evaluation | D10 14/09 (Mon) | Ablation B0–B4, ASR, CIs, one prompt iteration | `eval_runs` rows for B0–B4 and G3; markdown tables generated; regression gate applied to prompt v1.1 |
| P8 Stabilise + report | D11–D13 15–17/09 | Pilot closed, restore drill, runbook, report material, demo, tag | Restore drill report; pilot stats exported; `docs/runbook.md`; git tag `v1.0`; demo script rehearsed |
| — | D14 18/09 (Fri) | Submission / defense | — |

---

## P0 · Preparation (D0)

**Objective.** Make the repo buildable and every later phase unblocked: environment, access, coordination files, canonical fixtures.

**Inputs.** Current repo (`backend/app/*/__init__.py` docstrings only; `llm/prompt_builder.py`; `docs/Schema/schema.sql`; `docs/*.md`); the sample alert; Owner's access to the Wazuh indexer and DeepSeek.

**Deliverables.**
- Git: all of `docs/`, `kb/`, `llm/`, `docs/Schema/` tracked; `.gitignore` covers `.env`, `backups/`, `eval/results/`.
- `backend/requirements.txt` (pinned), `backend/pyproject.toml` (ruff/black/pytest config), `Makefile` (`test`, `test-db`, `lint`, `migrate`, `run-app`, `run-worker`, `backup`), `docker-compose.yml` (app, worker, db), `.env.example` listing every config key in context pack §6.3.
- `backend/tests/fixtures/alert_40112.json` (sample alert) + 5 more real documents pulled from the indexer (different rules) saved as fixtures; `tests/conftest.py` with a DB fixture (schema from `docs/Schema/schema.sql`, later migrations).
- `conf/inventory.yaml`, `conf/identities.yaml`, `conf/iocs.csv` (human writes content; agent creates the format + loader stub + example).
- `eval/indexer_probe.py`: runs one `search_after` query against the indexer using `.env`, prints count per day since `PULL_START` and the earliest index date.
- Decision record: whether parser / category resolver / prompt_guard from `Final-Project` are reusable (Owner checks; Director records in `DECISIONS.md`).
- `docs/plan/STATE.md` initialised with P0–P8 rows.

**Human-only.** Indexer read-only user + certificate; DeepSeek key; inventory contents; `Final-Project` check.

**Exit gate.** See table. **Cut candidates:** none.

## P1 · Smoke test + schema (D1)

**Objective.** Retire the two biggest unknowns before writing product code: does the model behave, and does the v3 schema apply cleanly.

**Deliverables.**
- `eval/smoke_test.py`: sends a minimal ① prompt (typed builder not yet available — use a hand-built prompt that already follows the block rules) for 30 real alerts + 5 with ≥ 30 KB raw_log + 3 adversarial; records JSON-parse rate, schema-valid rate (against `triage_v2`), p50/p95 latency, tokens in/out, cost, and the raw responses. Writes `docs/smoke-test-D1.md`.
- Decision: model accepted / alternative model chosen (Director + Owner).
- Migrations `013_assets_enrichment.sql`, `014_intake_cursor_heartbeat.sql`, `015_labels_reviews_notes_eval_health.sql`, `016_alter_alerts_jobs_llm_runs_users.sql`, `017_append_only_and_roles.sql` flat in `docs/Schema/` next to `001`–`012` (DEC-005 — there is no `migrations/` subdirectory and no `backend/migrations/`), applied by `make migrate`; `docs/Schema/schema.sql` regenerated by the existing `build_schema.py`, whose `NNN_*.sql` glob picks them up unchanged.
- `tests/test_schema_v3.py`: tables/columns/CHECKs exist; `UPDATE audit_events` as `app_rw` raises; `intake` UNIQUE holds.

**Human-only.** Reading the smoke-test report and approving the model.

**Exit gate.** See table. **Cut candidates:** none.

## P2 · Intake + pipeline (D2–D3)

**Objective.** Deterministic core: indexer → intake → parse → dedup → enrich → auto-close → queue, fully tested, LLM-free.

**Deliverables (by package).**
- `infra/db.py` (connection, transaction helper, `SET LOCAL statement_timeout`), `infra/jobs.py` + `infra/worker.py` (claim with SKIP LOCKED, finish with backoff, reclaim stale locks, dispatch table), `infra/config.py`, `infra/errors.py`.
- `infra/puller.py` (`pull_once`, `backfill(since)`, cursor handling, overlap, idempotent insert, heartbeat detection), `infra/intake.py` (webhook path), `web` route `POST /webhook/alerts`.
- `ingest/wazuh_parser.py` (both envelope shapes; field mapping from context pack §8; time normalisation; `_safe_int`; `_is_private`; raw_log truncation at 1000 KB with flag; `rejected_alerts` on missing required fields), `ingest/category.py` (5-tier resolution with priority table; port from `Final-Project` if reusable), `ingest/dedup.py` (advisory lock on cluster key computed in SQL; `find_open_cluster` with 6 predicates; `bump_parent`).
- `domain/alert.py`, `domain/transitions.py` (8 public functions, `_apply`, guards, audit in same txn, fan-outs, two-statement escalate), `domain/correlation.py` (`summarize_for_prompt` returning structured rows + 5 samples; `correlated_cluster_ids`).
- `enrichment/inventory.py` (load YAML/CSV → upsert with `active` flag; reload endpoint), `enrichment/lookups.py` (asset by `agent_name` then `origin_host`; identity; ioc with three-state result).
- `ingest/autoclose.py` (hard blocks incl. asset-not-in-inventory; rule whitelist incl. internal fields; ordered match; `simulate`), `soar/risk.py`, `soar/pipeline.py` (one intake → one outcome; `jobs('triage')` enqueued in the same transaction as `queued_tier1` or `auto_closed`; `intake.processed_at`).
- Wazuh side (human): heartbeat wodle + local rule.
- Tests — DEC-014 adds the first: **dedup compression measured on the real 16/08 archive day (47,917 alerts, rule 40112) in place of a synthetic burst, reported as a ratio before any LLM-budget claim**; parser (7 blocks + fixture expectations), category permutations, dedup predicates + two concurrent sessions, 18 transitions × guard ok/fail, fan-outs, escalate race, autoclose hard blocks with a match-everything rule, simulate counts on replayed data, puller idempotency (double pull, cursor rewind), worker crash reclaim, **G7: LLM disabled → alert in `queued_tier1` < 30 s**.

**Exit gate.** See table. **Cut candidates:** `simulate` UI (keep API); correlation samples limit can drop to 3.

## P3 · AI pipeline ① (D4)

**Objective.** Proposer → gate → verifier, safe by construction, running live on replayed alerts.

**Deliverables.**
- Move legacy `llm/` into `backend/app/llm/` and `backend/app/security/`; delete top-level `llm/` at the end of the phase.
- `security/wrap.py` (nonce, NFKC, escape, nonce stripping, single truncation function with in-block marker), `security/linter.py`, `security/detector.py` (flag only), `security/gate.py` (steps 1–5 + 7 and the verifier call orchestration), `security/output_guard.py`.
- `llm/builder.py` (typed `fact`/`untrusted`/`Id`), `llm/adapter.py` (DeepSeek rules, cost, usage, retries, monthly cap), `llm/triage.py` (proposer prompt from the nine ① blocks; verifier prompt facts-only), `llm/templates/{triage_system.txt, verifier_system.txt, output_schemas.json}`.
- `kb/lookup.py` + `kb/decision_tables/*.yaml` (10 tables; content authored by Owner + advisor; agent provides format, loader, `apply_table`, and a consistency test) + `reviewed_by/at` gate.
- `tier1/triage.py` job: build → linter → adapter → gate → verifier → `llm_runs` ×2 → `triage_status`. Runs for auto-closed alerts too.
- `audit/llm_runs.py` writer with all v3 columns.
- Tests: linter catches each legacy violation (description outside block, context outside block, correlation outside block); builder cannot emit a free string outside a block; gate steps with crafted proposer outputs (basis mismatch, invalid quote, FP without structured evidence, verifier disagree); adapter parses `content` and ignores `reasoning_content`; cost cap; live run marked `@pytest.mark.live` on 50 replayed alerts writing `gate_result`.

**Exit gate.** See table. **Cut candidates:** detector heuristics beyond the 20 regex patterns.

## P4 · UI + auth + blind branch (D5)

**Objective.** Analysts can work Tier-1 in a browser; the blind branch is enforced at the API; the pilot starts.

**Deliverables.**
- `infra/auth.py` (argon2id, JWT 8 h, per-request DB check of `is_active`, `role`, `sessions_invalid_before`; lockout), CLI `seed_users`.
- `tier1/queue.py`, `tier1/decide.py` (acknowledge, decide with optimistic lock, escalate, reopen) + REST routes; suggestion stripping when blind.
- `web/`: login, queue, alert detail (raw_log, correlation ±2 h, targeted accounts, playbook, ① reasons with quotes and `gate_result`, decision buttons), HTMX partials.
- `suggestion_visible` assignment at alert creation (`hash(alert_id) % 2 == 0` when `EVAL_BLIND_FRACTION = 0.5`).
- Tests: auth flows; blind alert detail contains no suggestion key for any role until decided; decide fan-out via UI; escalate creates case.

**Human-only.** Start using the queue (pilot day 1).

**Exit gate.** See table. **Cut candidates:** filters on the queue; pagination beyond OFFSET.

## P5 · Tier-2 + digest + ops (D6)

**Objective.** Cases with ②, digest loop, health alarms, backup.

**Deliverables.**
- `tier2/dossier.py` (nine blocks, entity extraction with regex + lookups + 7-day history, deterministic), `llm/investigate.py` (single shot), `tier2/investigate.py` job (quota, one-running-per-case, nonce per attempt, evidence check), `tier2/conclude.py`, `case_notes`, REST + web screens (case list, case detail with ② result and `evidence_check`, notes, conclude).
- `tier1/digest.py` job + admin digest page (one-click verdict → `autoclose_reviews` + `triage_labels`; wrong → reopen A17), `rule.suspected_wrong` notification.
- Admin rules screen (create with simulate preview, toggle).
- `infra/health.py` job + `infra/notify.py` (Telegram or SMTP), `GET /health`, thresholds from context pack; `scripts/backup.sh` + **a systemd timer or user crontab** (never a compose cron — DEC-018/DEC-021, the daemon is unreachable and the backup would silently never run); `scripts/restore.sh`.
- Tests: dossier deterministic; evidence check; quota/409; digest review path; health thresholds simulated; backup produces a file.

**Exit gate.** See table. **Cut candidates (in order):** ② → digest UI → health job.

## P6 · Lab data + labeling (D7–D9)

**Objective.** Build and freeze the gold sets with bias controls.

**Deliverables.**
- `eval/build_gold.py`: stratified cluster selection (category × severity) from replayed + live alerts (G1) and lab alerts (G2, `source='lab'`); writes `eval/gold_candidates.csv`.
- Blind labeling page (`GET /api/admin/labels/next`, `POST /api/admin/labels`): shows cluster context (representative alert, raw_log, correlation, occurrence, category, playbook) and **never** any ① output; randomised order per labeler; progress counter.
- `eval/label_export.py`: two labelers → Cohen's κ → adjudication file → `eval/gold_v1.csv` + sha256 written to `eval/gold_v1.sha256` and committed.
- `eval/adversarial/`: 40 G3 alerts (5 vectors × 8 patterns) as fixtures + loader that injects them with `source='lab'` and tag `adversarial`.
- Lab runbook `docs/lab-scenarios.md`: per category, the attack and the benign scenario to run on the lab agent (Owner executes).

**Human-only.** Running scenarios on the lab; labeling (two people, two sessions); adjudication.

**Exit gate.** See table. **Cut candidates:** G2 category coverage below 8 (report what exists).

## P7 · Evaluation (D10)

**Objective.** Numbers with confidence intervals; one controlled prompt iteration.

**Deliverables.**
- `eval/run_configs.py`: runs B0–B4 over `gold_v1.csv` (B0/B1 offline, B2–B4 live calls with caching by prompt sha), ASR over G3 per configuration, bootstrap 1 000 CIs for macro-F1 / recall(escalate) / precision(false_positive), McNemar B4 vs B1, evidence-verified rate, cost and latency; writes `eval_runs` rows and `eval/results/*.json`.
- `eval/report.py`: markdown tables + PNG charts for the thesis.
- `eval/regression_gate.py`: compares two `eval_runs`; blocks activation if macro-F1 drops > 0.03, recall(escalate) drops, or ASR rises.
- Prompt v1.1 (one iteration, few-shot from `triage_labels` where `model_wrong`), gated.

**Human-only.** Reading results; choosing v1.0 vs v1.1.

**Exit gate.** See table. **Cut candidates:** McNemar; PNG charts.

## P8 · Stabilise + report (D11–D13)

**Objective.** Close the pilot, prove recoverability, hand the Owner everything the report needs.

**Deliverables.**
- Bug-fix pass on INBOX items; pilot export (`eval/pilot_export.py`: decisions by branch and by person, ack→decide medians, agreement on blind branch, gate-forced rate, digest error rate with Wilson CI, ② usefulness ratings).
- Restore drill: restore last backup into an empty DB, run `make test-db`, write `docs/restore-drill.md`.
- `docs/runbook.md` (2 pages: start/stop, env, backup/restore, alarms, common failures).
- Demo script (10 minutes) `docs/demo.md`; git tag `v1.0`; final `eval/report.py` run.

**Human-only.** Thesis writing; demo rehearsal.

**Exit gate.** See table. **Cut candidates:** demo script polish.

---

## Cross-phase rules

- Daily gate (Director, end of day): does the "exit gate" of the current phase advance? If a task is red for > 2 hours, apply the cut order rather than adding hours.
- Parallelism: at most 3 coder agents at once, on disjoint files; the Planner assigns files explicitly to avoid merge conflicts.
- Any contract change → `INBOX.md` Decision Request → Director → Owner if in scope of §10 of the context pack.
- The evaluation validity rules (blind labeling, freeze before eval, no ① output on the labeling page) are **never** relaxed for schedule reasons.
