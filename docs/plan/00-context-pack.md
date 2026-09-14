# Context Pack — AI Support SOC v3 (14-day build, 04/09 → 18/09/2026)

Read this first. Every prompt in `docs/plan/prompts/` assumes you have read it end to end. It is the single shared context for the Planner, Coder, Reviewer and Director agents. If anything here conflicts with older documents, **this file wins**.

## 0. Sources of truth (precedence order)

1. This file.
2. `docs/kien-truc-v3-14-ngay.html` — architecture v3 (open in a browser; §1 decisions, §2 overview, §3 components, §4 AI layer, §5 data/API/config, §6 evaluation, §7 sequences, §8 schedule, §9 risks, appendix package map).
3. `docs/chot-v3-14-ngay.md` — decisions D1–D20, cuts C1–C10, cut order, section F (adjustments after the sample alert).
4. `docs/Schema/schema.sql` — v1 schema (migrations 001–012, already applied in tests). v3 adds migrations 013+ (created in P1).
5. `docs/phase-1…7-*.md`, `docs/kien-truc-tong-quat-va-chi-tiet.md`, `docs/luong-du-lieu-theo-package.md` — v1 specs. Still authoritative for parser blocks, category resolution, dedup predicates, state-machine guards, correlation SQL. Where they conflict with (1)–(3), v3 wins.
6. `llm/prompt_builder.py`, `llm/templates/*` — legacy artifact (221 lines). It is **wrong** in the places listed in §7.4 and must be fixed, not copied blindly.

Vietnamese is the language of the design documents; code, identifiers, comments, commit messages and agent prompts are English. Existing Vietnamese identifiers in `llm/prompt_builder.py` (`boc`, `nonce_moi`, `chuan_hoa`, `dung_prompt_triage`) may be kept when ported; do not spend time renaming for style.

## 1. What we are building (one paragraph)

A triage and investigation layer between a single Wazuh manager and two analysts. **Volume, measured from the manager archive 08/08–05/09/2026 (DEC-014): 84,376 raw alerts over 29 days — median 592/day, mean 3,013/day, peak 47,917 on 16/08.** The "≈ 50 alerts/day" this line carried until 05/09 came from assumption S1 (`docs/phan-bien-kien-truc-v2-2026-09-04.md`) and is wrong by ~12× on the median and ~60× on the mean. Note the unit: that is *raw* alerts. ① runs per **cluster**, not per alert, so what reaches Tier-1 depends on the dedup ratio — **measured 06/09 on the full archive with the size/age/idle caps applied: 30.2 : 1, 2,778 clusters, ≈ 96 clusters/day (DEC-014 as amended by DEC-032)**. Alerts are pulled from the Wazuh indexer, deduplicated into clusters, enriched from a hand-maintained inventory, optionally auto-closed by explicit rules, and queued for a Tier-1 analyst. An LLM (DeepSeek, via OpenAI-compatible API) proposes a triage verdict (pipeline ①) that passes a 7-step gate and a facts-only verifier before it is shown; the analyst decides. Escalated alerts form a case; a second LLM pass (pipeline ②, single shot, no tools) writes an investigation dossier with quoted evidence; a Tier-2 analyst concludes. Every decision and every model call is recorded append-only. The thesis claim is proven offline on a labelled gold set with five ablation configurations, plus a 7-day blind online pilot. **No state transition ever depends on a model call succeeding.**

Owner: the thesis author (also Tier-1/Tier-2 analyst together with the advisor). Deadline: 18/09/2026. One developer. LLM data egress to DeepSeek is an accepted, documented assumption.

## 2. Non-negotiable invariants

| ID | Invariant | Enforced by |
|---|---|---|
| G1 | Tier packages (`ingest`, `soar`, `tier1`, `tier2`) never import each other; infrastructure packages never import tiers. Single exception: `soar/pipeline.py` may import `ingest/` (allowlisted). | `tests/test_import_rules.py` (AST scan) |
| G2 | Only `domain/` changes `alerts.status` / `cases.status`; every decision writes an audit event in the same transaction. | Single `_apply()` in `domain/transitions.py` + AST scan for `UPDATE … status` outside `domain/` |
| G6′ | Outside an `<untrusted_data nonce=…>` block, a prompt may contain only template constants and values from closed sets (DB-CHECKed enums, ints, ISO datetimes, regex-validated ids). Every free-text string is inside a block. | `security/linter.py` at test time and before every send |
| G7 | No state depends on a model call. With the LLM disabled, an alert reaches `queued_tier1` in < 30 s. | `tests/test_g7_llm_off.py` |
| G8′ | Never auto-close: `severity = critical`, agent in `NEVER_AUTOCLOSE_AGENTS`, `asset.criticality = high`, **asset not in inventory**, privileged identity, IoC malicious/suspicious. | Hard checks before any rule is evaluated + test with a rule that matches everything |
| G9 | `intake.raw_text` is the received document unchanged — the webhook body, the hit object's bytes sliced from the pull response, or the archive line (DEC-019) — as UTF-8 text; `intake.raw_payload` and `alerts.raw_payload` are derived from it and may be normalised. **Re-worded 05/09 (DEC-023):** byte identity cannot hold on `jsonb`, which reorders keys and collapses whitespace (measured). | byte-compare test: `raw_text.encode("utf-8") == bytes read`, on a fixture `jsonb` rewrites, plus the control `raw_payload::text != raw_text` |
| G11 | A `false_positive` verdict from ① exists only after all 7 gate steps pass. `gate_result` is written for every `llm_runs` row. | `security/gate.py` + DB CHECK on closed sets |
| G12 | Every `intake` row gets `processed_at` or `error` within 60 s while the worker is alive. | health job + kill-worker test |

## 3. Runtime shape

- **Local processes, no container runtime required (amended 05/09/2026, DEC-018).** `app` (FastAPI: intake webhook + REST API + HTMX UI) via `make run-app`, `worker` (all jobs: `pipeline`, `triage`, `investigate`, `digest`, `health`, `pull`) via `make run-worker`, and **PostgreSQL 16 native on `127.0.0.1:5432`** — `soc_dev` for the application, `soc_test` for the suite, both owned by the run-as account. One worker process; the `jobs` table uses `FOR UPDATE SKIP LOCKED` so a second worker can be started without code changes.
- `docker-compose.yml` is **retained but optional**: no `Makefile` target references it (`grep -cE 'COMPOSE|docker compose' Makefile` → `0`), and nothing in the build depends on a daemon. It exists for a host that has one. This line used to read "`docker compose`: app, worker, db" and was false on the only host this is built on, where the docker socket is unreachable to the run-as account.
- Python 3.12, FastAPI, psycopg 3, Jinja2 + HTMX (server-rendered, no build step), pytest, `openai` SDK pointed at DeepSeek `base_url`, PyYAML, argon2-cffi, PyJWT, httpx. Pin versions in `backend/requirements.txt` (P0).
- Secrets only via environment variables (`.env` is git-ignored). Never log secrets, never log full prompts to stdout (they go to `llm_runs`).

## 4. Package map (must match `backend/app/`)

| Package | Kind | May import | Contents (v3) |
|---|---|---|---|
| `ingest/` | tier | domain, infra, audit, enrichment | `wazuh_parser.py`, `category.py`, `dedup.py`, `autoclose.py` |
| `soar/` | tier | enrichment, domain, infra, audit, **ingest** (allowlisted exception) | `pipeline.py` (orchestrates one intake → alert), `risk.py` |
| `tier1/` | tier | domain, llm, kb, security, infra, audit | `queue.py`, `decide.py`, `triage.py` (job ①), `digest.py` |
| `tier2/` | tier | domain, llm, kb, security, infra, audit, enrichment | `dossier.py`, `investigate.py` (job ②), `conclude.py` |
| `domain/` | infra | infra, audit | `alert.py`, `transitions.py`, `correlation.py` |
| `infra/` | infra | — | `db.py`, `jobs.py`, `worker.py` (**the claim/lock/retry/reclaim loop only — it names no handler and imports no tier; DEC-037**), `auth.py`, `config.py`, `errors.py`, `puller.py`, `intake.py`, `health.py`, `notify.py` |
| `audit/` | infra | infra | `events.py`, `llm_runs.py` |
| `security/` | infra | infra | `wrap.py` (nonce, boc), `linter.py`, `gate.py`, `detector.py`, `output_guard.py` |
| `llm/` | infra | security, infra, kb | `adapter.py`, `builder.py` (typed), `triage.py` (proposer + verifier), `investigate.py`, `templates/` |
| `kb/` | infra | infra | `playbooks/*.md`, `decision_tables/*.yaml`, `lookup.py` |
| `enrichment/` | infra | infra | `inventory.py` (YAML/CSV loader), `lookups.py` |
| `web/` | composition root | everything | `main.py` (FastAPI app), **`worker.py` — the job worker entry point and the job-type → handler table (`make run-worker` runs `app.web.worker`); that table maps job types to tier code, so under G1 only a composition root may hold it (DEC-037)**, Jinja templates, HTMX routes |
| `eval/` | composition root | everything | `build_gold.py`, `label_export.py`, `run_configs.py`, `report.py`, `regression_gate.py`, `smoke_test.py` |

The legacy top-level `llm/` directory is moved into `backend/app/llm/` and `backend/app/security/` during P3; after that the top-level `llm/` is deleted.

## 5. Data flow and state machine

**Flow:** indexer `wazuh-alerts-*` → `puller` (every 60 s, `search_after`, persistent cursor, 60 s overlap) → `intake` (UNIQUE `manager_id + source_alert_id`) + `jobs('pipeline')` → job: parse → dedup (advisory lock on cluster key) → INSERT `alerts(received)` → internal enrichment (assets/identities/iocs from files) → auto-close (hard blocks, then rules) → `risk_score` → `queued_tier1` → `jobs('triage')` → job ①: typed builder → linter → proposer → gate steps 1–5 → verifier → gate step 7 → `llm_runs` ×2 + `triage_status`. Analyst decides (fan-out to duplicates) or escalates (case + `case_alerts`). `POST /analyze` → `jobs('investigate')` → dossier → ② → evidence check → `llm_runs`. Analyst concludes (fan-out). Daily `digest` job lists auto-closed clusters for human review. Webhook `POST /webhook/alerts` is a secondary intake path with identical downstream behaviour.

**Alert status set (CHECK):** `received, duplicate, auto_closed, enriching, queued_tier1, tier1_active, escalated_tier2, closed_fp, closed_benign, closed_confirmed`. **Second axis:** `triage_status ∈ pending, ready, unavailable`. **Case status:** `investigating, concluded_fp, concluded_policy_violation, confirmed_incident`.

**Transitions (18 edges, unchanged from v1 — see `docs/kien-truc-tong-quat-va-chi-tiet.md` §B3 and the architecture §3.5):** A1 `→received`, A2 `received→duplicate`, A3 `received→auto_closed`, A4 `received→enriching`, A5/A6 `enriching→queued_tier1`, A7 `queued_tier1→tier1_active`, A8/A9 `tier1_active→closed_fp|closed_benign`, A10 fan-out to duplicates, A11 `tier1_active→escalated_tier2`, A11b correlated `queued_tier1|tier1_active→escalated_tier2`, A12 duplicates receive `case_id` only, A13–A15 `escalated_tier2→closed_*`, A16 fan-out, A17 `auto_closed→queued_tier1` (reopen). Definitions: cluster = `duplicate_of IS NULL`; lifecycle ended = `closed_at IS NOT NULL`; cluster still absorbing = `closed_at IS NULL OR sealed_at IS NULL`.

**Cluster key:** `(rule_id, srcip, dstip, agent_name)`, compared with plain `=`; `srcip/dstip` are `NOT NULL DEFAULT ''`. Dedup predicates: still absorbing, not a duplicate itself, `IDLE_GAP 15 min`, `MAX_AGE 4 h` (30 min if auto-closed), `MAX_SIZE 1000`.

## 6. Frozen contracts

Changing any of these requires a Decision Request in `docs/plan/INBOX.md` and Director approval logged in `docs/plan/DECISIONS.md`. Coders never edit them on their own.

### 6.1 Schema (v1 + v3 additions; full DDL in migrations)

- v1 tables kept: `alerts` (≈ 40 cols), `cases`, `case_alerts` (UNIQUE alert_id), `jobs`, `audit_events`, `llm_runs`, `users`, `autoclose_rules`, `assets`, `identities`, `iocs`, `rejected_alerts`, `schema_migrations`.
- v3 new: `intake(intake_id, manager_id, source_alert_id, raw_text text, raw_payload jsonb GENERATED ALWAYS AS (raw_text::jsonb) STORED, sort_key bigint, via ∈ pull|webhook, received_at, processed_at, outcome ∈ alert|duplicate|auto_closed|heartbeat|rejected, error)` UNIQUE(manager_id, source_alert_id) — **annotated 05/09 (DEC-023): `raw_text text NOT NULL` holds the received bytes and `raw_payload` is generated from it, because G9 cannot hold on `jsonb`;** `source_cursor(manager_id PK, last_sort, last_pull_at, last_error)`; `source_heartbeat(manager_id PK, last_seen_at, last_alert_at)`; `triage_labels(alert_id, labeler_id, source ∈ gold_offline|digest|disagreement|lab, label ∈ false_positive|benign|escalate, confidence, note, created_at)` PK(alert_id, labeler_id, source); `autoclose_reviews(alert_id PK, reviewer_id, verdict ∈ correct|wrong|unsure, reviewed_at)`; `case_notes(note_id, case_id, author_id, body, created_at)`; `eval_runs(eval_run_id, prompt_version, model_id, gold_set, config ∈ B0..B4, metrics jsonb, created_at)`; `system_health(checked_at PK, checks jsonb, ok bool)`.
- v3 altered: `alerts` + `manager_id`, `origin_host`, `source ∈ wazuh|lab|replay`, `suggestion_visible bool NOT NULL DEFAULT true` (**`NOT NULL` annotated 05/09, DEC-023** — a tri-state flag on the blind branch is a defect magnet; 016 writes it so); drop `sampled_for_control` — **no-op, annotated 05/09 (DEC-022): no such column has ever existed.** Measured on the migrated `soc_dev`: `alerts` has 51 columns and none is named that; it appears only in `docs/phase-3-auto-close.md:166` as a key inside a `jsonb_build_object(...)` audit payload. The clause is **kept, not struck** — migration 016 satisfies it literally with `ALTER TABLE alerts DROP COLUMN IF EXISTS sampled_for_control`, verified a clean idempotent no-op (`NOTICE … skipping`, exit 0). Do not go looking for the column. `jobs.job_type ∈ pipeline|triage|investigate|digest|health|pull`. `llm_runs` + `role ∈ proposer|verifier|investigator`, `model_id`, `prompt_version` (git sha), `gate_result jsonb`, `verifier_result jsonb`, `evidence_check jsonb`, `cost_usd numeric(10,5)`, `stopped_by`. `users` + `sessions_invalid_before`, `failed_logins`, `locked_until`. `assets/identities/iocs` + `source`, `loaded_at`, `active`; `assets.criticality` CHECK becomes `high|medium|low|unknown` and `assets` gains `owner text NULL`, `role text NULL` (DEC-004 — the DB is moved onto §6.2's vocabulary so gate step 2 can compare field-by-field; `owner`/`role` are read only inside an `<untrusted_data>` block, §7.1). `audit_events.event_type` CHECK set = 21 v1 names + `autoclose.reviewed, rule.suspected_wrong, llm.gate_forced, llm.builder_violation, health.alarm, label.created`.
- Append-only enforcement — **amended 05/09 (DEC-023)**, two layers. Layer 1 (privileges): `REVOKE UPDATE, DELETE, TRUNCATE ON audit_events, llm_runs, intake FROM app_rw, PUBLIC`; then `GRANT UPDATE (processed_at, outcome, error) ON intake TO app_rw` — the single completion write G12 requires. Layer 2 (triggers, which also bind the owner): `BEFORE UPDATE OR DELETE … FOR EACH ROW` raising an exception on `audit_events` and `llm_runs`; on `intake` a `BEFORE UPDATE` row trigger that rejects any change to a column other than `processed_at`/`outcome`/`error` and any change to one of those three once it is non-null, plus `BEFORE DELETE`; and `BEFORE TRUNCATE … FOR EACH STATEMENT` on all three. The application connects as `app_rw` — a LOGIN role over TCP + scram-sha-256, made loginable once per cluster by a superuser (HUONG-DAN §0); migrations run as the owner role over the socket. Migration 017 **creates `app_rw` as `NOLOGIN`** when `pg_roles` shows it absent (amended 05/09, **DEC-024(a)**, superseding DEC-023 item 3: `user1` is now a superuser and `CREATE ROLE` succeeds — measured). It is created NOLOGIN deliberately: a passwordless LOGIN role cannot connect, and a password must never enter a migration on a public remote. Granting LOGIN and a SCRAM password stays a one-off out-of-band step per cluster (`HUONG-DAN` §0), needed for the application to connect, not for the migrations to apply. If the role is absent and creation is refused, 017 stops with `migration 017: role app_rw does not exist and this migrator cannot create it`.
- Dropped from v3: `enrich_cache`, `prompt_versions`.

### 6.2 LLM output schemas (`backend/app/llm/templates/output_schemas.json` is the only source; docs are generated from it)

```json
{"triage_v2": {"suggested_action": "false_positive|needs_review|escalate", "confidence": "low|medium|high",
  "structured_basis": {"severity": "critical|high|medium|low", "ioc_reputation": "malicious|suspicious|clean|not_found|skipped",
    "asset_criticality": "high|medium|low|unknown", "identity_privileged": "true|false|unknown",
    "occurrence_count": 0, "playbook_rule_applied": "string|null"},
  "reasons": [{"claim": "string", "quote": "verbatim substring of one block", "source": "wazuh_raw_log|rule_description|correlation_samples|kb_playbook|context"}],
  "playbook_used": "string|null"},
 "verifier_v1": {"agree": true, "structured_only_verdict": "false_positive|needs_review|escalate", "reason": "string"},
 "investigate_v2": {"summary": "string", "attack_narrative": "string",
  "suggested_conclusion": "false_positive|policy_violation|confirmed_incident|need_more_data", "confidence": "low|medium|high",
  "gia_thuyet": [{"noi_dung": "string", "evidence_for": ["string"], "evidence_against": ["string (minItems 1)"]}],
  "evidence": [{"alert_id": "string", "quote": "verbatim substring of that alert's raw_log or description", "why": "string"}],
  "next_steps": ["string"], "playbook_used": "string|null"}}
```

### 6.3 Config constants (`backend/app/infra/config.py`; all overridable by env)

```
DATABASE_URL(app runtime, role app_rw — a LOGIN role over TCP + scram-sha-256, DEC-023)  DATABASE_URL_OWNER(migrations and test setup, owner role)  TEST_DATABASE_URL(tests only; the database name must end in _test)
MAX_PAYLOAD_BYTES=2_097_152  RAW_LOG_MAX_BYTES=1_024_000  PROMPT_LOG_MAX_BYTES=32_768
DEDUP_IDLE_GAP_MINUTES=15  MAX_CLUSTER_AGE_HOURS=4  MAX_CLUSTER_AGE_AUTOCLOSED_MINUTES=30  MAX_CLUSTER_SIZE=1000
INDEXER_URL  INDEXER_USER  INDEXER_PASSWORD  INDEXER_CA(required: path to the indexer root CA, on this host conf/root-ca.pem; no insecure mode)  INDEXER_INDEX="wazuh-alerts-*"
PULL_INTERVAL_S=60  PULL_OVERLAP_S=60  PULL_PAGE=500  PULL_START="2026-08-01"
HEARTBEAT_RULE_ID="100999"  HEARTBEAT_MAX_AGE_MIN=30  SILENCE_WARN_HOURS=3
JOB_MAX_ATTEMPTS=3  JOB_BACKOFF=[10,60,300]  JOB_LOCK_TIMEOUT_S=300  N_WORKER=1
INVENTORY_PATHS=["conf/inventory.yaml","conf/identities.yaml","conf/iocs.csv"]
LLM_BASE_URL  LLM_API_KEY  LLM_MODEL_PROPOSER  LLM_MODEL_VERIFIER(default=proposer)  LLM_TIMEOUT_S=120(a wall-clock deadline per model call, enforced by the adapter — the SDK/httpx timeout it was mapped to bounds only the gap between received bytes; measured 05/09: 139.1 s completed under timeout=120; DEC-033, Owner)  LLM_RETRY=2  LLM_THINKING=disabled(enabled|disabled — DeepSeek `thinking.type`, sent as `extra_body`; **default flipped to `disabled` 06/09 by the Owner, DEC-042**, on P1-T08's measurement; enters the cache key of every measurement, P7's included; DEC-032, DEC-042)
LLM_MONTHLY_USD_CAP=30  LLM_PRICE_IN_PER_M  LLM_PRICE_OUT_PER_M
PROMPT_TOTAL_BUDGET_TOKENS=40_000  CASE_PROMPT_BUDGET_TOKENS=60_000  ANALYZE_QUOTA_PER_USER_DAY=30
NEVER_AUTOCLOSE_AGENTS=[]  AUTOCLOSE_RULE_WIDTH_PCT=30  REVIEW_DELTA_TOLERANCE=20  MAX_ALERTS_PER_CASE=200
JWT_SECRET  JWT_TTL_HOURS=8  LOGIN_MAX_FAILS=5  LOCKOUT_MINUTES=15  WEBHOOK_API_KEY(empty -> POST /webhook/alerts answers 503 webhook disabled; DEC-040, Owner)  WEBHOOK_IP_ALLOWLIST(JSON list of CIDRs, empty -> deny all; DEC-040, Owner)
RETENTION_DAYS=365  BACKUP_HOUR=2  EVAL_BLIND_FRACTION=0.5  DISPLAY_TZ="Asia/Ho_Chi_Minh"
NOTIFY_TELEGRAM_BOT_TOKEN  NOTIFY_TELEGRAM_CHAT_ID  (or NOTIFY_SMTP_*)
```

**Database connection keys — added 05/09/2026 (DEC-003).** §6.1 already fixes *which* role does what — the application connects as `app_rw`, migrations run as the owner role — so the three keys above only operationalise that rule and nothing more. `TEST_DATABASE_URL` is separate so a test run can never be pointed at the production database by accident; `backend/tests/conftest.py` refuses any DSN whose database name does not end in `_test`. The four Compose variables `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `DB_PORT` are **deliberately not part of this contract**: they exist only inside `docker-compose.yml` and `.env.example`, and `backend/app/infra/config.py` never reads them.

**Indexer environment on this host — verified 05/09/2026, differs from the generic Wazuh layout (DEC-001).** The alert store is a plain OpenSearch at `https://127.0.0.1:9400`; `wazuh-indexer.service` is `inactive` and `disabled` and must not be started. The manager writes `/var/ossec/logs/alerts/alerts.json`, which **Logstash** (`/etc/logstash/conf.d/wazuh-opensearch.conf`) ships into `wazuh-alerts-4.x-YYYY.MM.dd`, so `INDEXER_INDEX="wazuh-alerts-*"` is unchanged but end-to-end latency includes a Logstash flush. The root CA is `/etc/logstash/opensearch-certs/root-ca.pem` (world-readable, no sudo), copied to `conf/root-ca.pem`; it is OpenSearch's bundled demo CA (`CN = Example Com Inc. Root CA`, valid to 2034-02-17) — a limitation to record in P8. `alerts.json` is **not** readable without root, so the D3/F2 file fallback is unavailable **to the application**, which runs as `user1` — but not to the Owner, who has root (DEC-014, DEC-019). <!-- ANNOTATED, NOT STRUCK — DEC-060, 14/09. This sentence was true when written 05/09 and has since been falsified twice, in opposite directions, so all three states are dated here rather than the line being rewritten to whichever was last. (1) 08/09, measured with no sudo and no sg: `head -c 120 /var/ossec/logs/alerts/alerts.json` returned alert JSON — `user1` carried gid 124 (`wazuh`) as a supplementary group and the kernel applies it without `sg`. So the file WAS readable to the app's account, and the puller is the only path to history **by choice**, not by constraint: G9 requires a byte-identical `raw_payload` and G12 requires an `intake` receipt, both of which the puller produces and a file tail does not. The D3/F2 fallback stays closed on that reasoning (DEC-060 option A; option B, re-opening it, was refused). (2) 14/09, measured: `ls -ld /var/ossec` → No such file or directory; no wazuh packages, no unit files; `getent group 124` → no name; port 9400 not listening, `curl` exit 7. The path does not exist at all — DEC-061, escalated. (3) 14/09 22:15, measured (Support Agent, at the Owner's instruction) — the Owner reports the manager is back at a new location: `/data/wazuh/logs/alerts/alerts.json`, mode 777, uid/gid 999 with no local name, first line `rule 502 "Wazuh server started"` at 12:56:30Z, `manager.name` = `wazuh.manager`, readable by `user1`; the rotated dailies `/data/wazuh/logs/alerts/2026/` and `/data/wazuh/logs/archives/` are `drwxr-x---` gid 999 and NOT readable by `user1`; `/var/ossec` still absent, group `wazuh` gone. Port 9400 still dead; an OpenSearch answers on `https://127.0.0.1:9200` (401 unauthenticated; certificate `CN = 79.79.79.11` issued by `CN = Graylog CA`, NOT verifiable with `conf/root-ca.pem`; `soc_ro` rejected), and whether the new manager ships into it is unmeasured from `user1`. So `INDEXER_URL`, `INDEXER_CA` and the read-only account name nothing that exists until the Owner settles the indexer — INBOX 2026-09-14 · P2 / host (Owner's answer). The ruling itself is unchanged: the file fallback stays closed. Do not reach for the file fallback on the strength of (1) or (3). --> The puller is the only path to history *for the app*; pre-02/09 history reaches G1 through the Owner's root-side read of the manager archive, ingested as `source='replay'`. <!-- superseded-ok: DEC-001 names the service only to say it is inactive --> <!-- AMENDED 14/09 — DEC-065, the Owner's own §6.3 change; DEC-060's chain above is kept intact and nothing in it is struck. The alert store is now the Wazuh indexer running as container 005bea3363a9 on **https://127.0.0.1:19200** (certificate CN = wazuh.indexer, issuer OU = Wazuh; measured 14/09 23:42). The 9400 cluster is gone from the host (/usr/share/opensearch, /etc/opensearch, /var/lib/opensearch all absent) and 9400 does not listen. **:9200 is Graylog's store (CN = 79.79.79.11 / CN = Graylog CA) and must not be queried for alerts.** conf/root-ca.pem in the repo is still the OpenSearch demo CA (CN = Example Com Inc. Root CA, to 2034-02-17) and matches neither endpoint; the Owner copies the indexer's own CA out of the container and creates a read-only account there, then INDEXER_URL/INDEXER_CA/INDEXER_USER/INDEXER_PASSWORD are re-issued in .env (git-ignored) and .env.example regenerates from config.py. **Not yet proven, and the Owner set this condition themselves: `sudo docker exec 8e3772d039ed filebeat test output` plus _cat/indices/wazuh-alerts-* must be run and pasted before anything records the indexer path as reachable** — filebeat runs inside the manager container, and if it does not ship to 19200 nothing reaches any indexer. Host Logstash is still running on the old config and is broken at both ends: /etc/logstash/conf.d/wazuh-opensearch.conf:7 reads /var/ossec/logs/alerts/alerts.json (absent from the host) and :17 writes to 9400 (dead). -->

### 6.4 HTTP API (24 operations)

`POST /webhook/alerts` · `POST /api/auth/login` · `POST /api/auth/logout` · `GET /api/tier1/queue` · `GET /api/tier1/alerts/{id}` · `POST /api/tier1/alerts/{id}/acknowledge|decide|escalate|reopen` · `GET /api/tier2/cases` · `GET /api/tier2/cases/{id}` · `POST /api/tier2/cases/{id}/analyze` (202) · `GET /api/tier2/runs/{run_id}` · `POST /api/tier2/cases/{id}/notes` · `POST /api/tier2/cases/{id}/conclude` · `GET|POST|PATCH /api/admin/rules` · `POST /api/admin/rules/simulate` · `GET /api/admin/digest` · `POST /api/admin/digest/{alert_id}/review` · `GET /api/admin/labels/next` · `POST /api/admin/labels` · `POST /api/admin/jobs/{id}/retry` · `POST /api/admin/reload-inventory` · `GET /health`.

Roles: `tier1`, `tier2`, `admin`. The suggestion of ① is **removed from any response** (all roles) while `suggestion_visible = false` and the alert is not yet decided.

### 6.5 Job types and semantics

`pull` (every 60 s), `pipeline(intake_id)`, `triage(alert_id)` (also for auto-closed alerts), `investigate(case_id)` (one running per case; nonce regenerated per attempt), `digest` (daily 08:00), `health` (every 5 min). Retry: transient errors → `pending` with backoff `[10, 60, 300]`; permanent → `failed`. `locked_at` older than 300 s → reclaimable.

## 7. AI layer rules (summary; full detail in architecture §4)

### 7.1 Typed prompt builder
The builder exposes only `fact(name, value: Enum | int | datetime | Id)` for text outside blocks and `untrusted(text, source, **attrs)` for text inside `<untrusted_data nonce="…" source="…">…</untrusted_data nonce="…">` blocks. `Id` = string validated by regex: `alert_id ^\d+\.\d+$`, `rule_id ^\d+$`, MITRE `^T\d{4}(\.\d{3})?$`, `agent_id ^\d{3,}$`. There is no API to place a free string outside a block. One nonce per build (`secrets.token_hex(8)`), the nonce is stripped from content (`[nonce-removed]`), NFKC normalisation then HTML-escape inside blocks, truncation marker `[truncated]` placed **inside** the block by one shared function.

Always inside blocks: `rule.description`, `agent.name`, `predecoder.hostname`, `data.dstuser/srcuser`, `full_log`, inventory lookup values (owner, role text), correlation sample alerts, timeline lines, playbook text, analyst notes, previous ② result, MITRE technique/tactic names.

### 7.2 Linter
Parses the user message; every character outside a block must belong to: template constants (from the template file), field labels, enum values (from the DB CHECK sets), integers, ISO datetimes, regex-validated ids. Any violation → do not send, write `llm.builder_violation`, set `triage_status = unavailable`. Runs in tests over every template and at runtime before each send.

### 7.3 Gate (pipeline ①)
```
1 schema valid?            no → one repair attempt with the error message → still no → unavailable
2 structured_basis == DB facts on every field?  no → hallucination_flag, verdict := needs_review
3 every reasons[i].quote is a substring (NFKC, whitespace-collapsed) of the block named by source; drop invalid; 0 left → needs_review
4 verdict == false_positive kept only if: severity ≠ critical ∧ ioc ∉ {malicious, suspicious} ∧ asset ∉ {high, unknown}
  ∧ identity_privileged ≠ true ∧ playbook_rule_applied ∈ decision table ∧ that rule's condition holds on DB facts; else needs_review
5 detector (regex/heuristics) → injection_findings only; never changes the verdict
6 verifier: prompt = DB facts + playbook decision table + {verdict, reasons} wrapped as untrusted; agree=false or differing verdict → needs_review
7 output_guard: closed sets; write llm_runs (proposer + verifier) with gate_result, verifier_result, evidence_check; set triage_status
```
The verifier never sees raw_log, description, hostnames, usernames, lookup text, notes or previous results.

### 7.4 What is wrong in the legacy `llm/prompt_builder.py` (do not copy)
Line 134 injects `alert['description']` outside any block; lines 143–154 inject enrichment context and correlation lines outside blocks; lines 176–184 inject `tang1`/`tang3` outside blocks; `cat_theo_uu_tien` slices `raw_log` without the truncation marker; `dem_token` depends on `transformers`/gpt2 (remove). Keep: `nonce_moi`, `chuan_hoa`, `boc` (nonce stripping), the three mandatory sentences and their placement rule.

### 7.5 DeepSeek adapter
OpenAI SDK with `base_url`; `response_format={"type":"json_object"}`; the system prompt must contain the word "JSON"; validate against the schema, one repair round with the validation error; read only `choices[0].message.content` (ignore `reasoning_content`); record `usage`, `model`, latency; timeout `LLM_TIMEOUT_S` (120 s) as a **wall-clock deadline the adapter enforces** — the SDK/httpx timeout alone bounds only the gap between received bytes (DEC-033); 2 retries on network/5xx; every call is made from a job, never from a request handler; monthly cost cap enforced before each call. Token estimate before sending is character-based (calibrated from the smoke test); the authoritative count comes from `usage`.

### 7.6 Pipeline ② (single shot)
Dossier of nine blocks (case header as facts; every cluster with raw_log ≤ 8 KB; timeline ≤ 300 lines; extracted entities with inventory lookups and 7-day history; ±2 h correlation per alert; Tier-1 decisions; playbooks of all categories in the case; notes and previous ② result; an explicit out-of-block sentence listing what is NOT available). Evidence check: each `evidence[i].alert_id ∈ case ∪ duplicates` and `quote` is a substring of that alert's raw_log or description; zero valid evidence → `suggested_conclusion := need_more_data`. Budget 60 k tokens; truncation order raw_log 8 KB → 4 KB, representatives → 15, timeline.

## 8. Canonical fixture: the sample alert

Save as `backend/tests/fixtures/alert_40112.json` (indexer document shape with `_source`). Expected parse: `alert_id=1786903016.121311`, `manager_id=IA1803`, `alert_time=2026-08-16T17:56:56.130Z` (from `fields.timestamp[0]`), `event_time=NULL` (agent timezone unknown; raw `predecoder.timestamp` kept), `agent_name=user1-IA1803`, `origin_host=user1-IA1803`, `agent_id=001`, `agent_ip=79.79.79.12`, `srcip=127.0.0.1`, `dstip=''`, `src_port=48104`, `dst_port=0`, `alert_user=user1`, `rule_id=40112`, `rule_level=12`, `severity=critical`, `category=ssh_brute_force` (T1110 outranks T1078), `categories=[ssh_brute_force, suspicious_login]`, `decoder=sshd`, `raw_log=full_log`, `srcip_is_private=True`. Expected behaviour: never auto-closed; IoC lookup `skipped`; gate step 4 forbids `false_positive`; decision-table rule `sbf-3 (rule_level ≥ 12 → escalate)`.

```json
{"_index":"wazuh-alerts-4.x-2026.08.16","_id":"-pe4C6ABLQcppv5YO4pl","_source":{"predecoder":{"hostname":"user1-IA1803","program_name":"sshd","timestamp":"Aug 16 17:56:55"},"input":{"type":"log"},"agent":{"ip":"79.79.79.12","name":"user1-IA1803","id":"001"},"manager":{"name":"IA1803"},"data":{"srcip":"127.0.0.1","dstuser":"user1","srcport":"48104"},"rule":{"mail":true,"level":12,"description":"Multiple authentication failures followed by a success.","groups":["syslog","attacks"],"frequency":2,"firedtimes":1,"mitre":{"technique":["Valid Accounts","Brute Force"],"id":["T1078","T1110"],"tactic":["Defense Evasion","Persistence","Privilege Escalation","Initial Access","Credential Access"]},"id":"40112"},"location":"journald","decoder":{"parent":"sshd","name":"sshd"},"id":"1786903016.121311","full_log":"Aug 16 17:56:55 user1-IA1803 sshd[136570]: Accepted password for user1 from 127.0.0.1 port 48104 ssh2","timestamp":"2026-08-17T00:56:56.130+0700"},"fields":{"timestamp":["2026-08-16T17:56:56.130Z"]},"sort":[1786903016130]}
```

## 9. Engineering conventions

- **TDD.** Write the failing test first; the acceptance tests named in the task card must exist and pass. `make test` runs everything; `make test-db` reads `TEST_DATABASE_URL` and needs **no container runtime** (DEC-018, DEC-021 — no `Makefile` target requires docker). A worktree has no `.env`, so run it as `TEST_DATABASE_URL=postgresql:///soc_test make test-db`.
- **LLM is always stubbed in tests.** A fake adapter returns canned JSON. Live calls only in `eval/` and in tests marked `@pytest.mark.live` (skipped by default).
- **No network in unit tests** except a local PostgreSQL. The indexer is mocked with recorded fixtures.
- **Branch per task:** `task/<TASK_ID>`; small commits; final report as the task's PR description in `docs/plan/tasks/<PHASE>/<TASK_ID>.report.md`.
- **Contracts are frozen** (§6). If a task cannot be done without changing one, stop and file a Decision Request in `docs/plan/INBOX.md`.
- **Errors:** `infra/errors.py` classifies transient vs permanent; unclassified defaults to transient and increments a counter with prefix `UNCLASSIFIED:`.
- **Time:** control timestamps come from the DB (`now()`), never from Python or the SIEM. Display timezone is `Asia/Ho_Chi_Minh`; storage is UTC.
- **Logging:** structured JSON lines to stdout; never secrets, never full prompts.
- **Style:** black + ruff defaults; type hints on public functions; docstrings only where the why is non-obvious.

## 10. Cut list and cut order

Already out of scope (do not implement): ② tool loop, VirusTotal/MISP/n8n, shadow mode for rules, AD/CMDB sync job, prompt_versions UI, Prometheus, audit hash-chain, keyset pagination, enrich_cache, circuit breaker, rate limiting, `sealed_at` sweeper (the 30-min cap replaces it), MFA, SLA escalation, RAG, multi-tenant, ≥ 6-week online pilot.

If the schedule slips, cut in this order (Director decides, Owner approves): ② entirely (keep case + manual conclude) → digest UI (CSV instead) → health job (cron + grep) → login (basic auth) → auto-close rules (keep dedup). **Never cut:** intake/puller, ① + gate + verifier, blind labeling page, eval harness.

## 11. Human-only tasks (never assign to an agent)

Create a read-only indexer user, copy the indexer root CA file (on this host: `/etc/logstash/opensearch-certs/root-ca.pem`) into `conf/root-ca.pem` and share `INDEXER_*` env values; add the heartbeat wodle + local rule on the Wazuh manager; obtain the DeepSeek API key; write `conf/inventory.yaml` and `conf/identities.yaml` (must include `user1-IA1803` and `user1`); run attack and benign scenarios on the lab agent; label clusters (two people, blind, independent); review the daily digest; write and review playbook decision tables with the advisor; approve scope cuts and contract changes; run the backup restore drill sign-off; write the thesis report.

## 12. Definition of Done (global)

A task is done when: all acceptance tests in its card pass in a clean checkout; `make test` is green; `tests/test_import_rules.py` passes; the linter passes on every template touched; no frozen contract was changed; the task report exists; the Reviewer returned APPROVE **and the `.review.md` recording it is committed on the task branch** (DEC-028 — this clause used to outcome-test the Reviewer while artifact-testing the Coder one clause earlier; a verdict that exists only in chat is not one, and `backend/tests/test_review_artifacts.py` enforces it); the Director marked it done in `docs/plan/STATE.md`.

A phase is done when its exit gate in `docs/plan/01-plan.md` is satisfied and the Director has recorded it.

## 13. Glossary

① = pipeline "auto-triage" (proposer + gate + verifier) on one alert. ② = pipeline "investigate" on one case, single shot. Cluster = root alert (`duplicate_of IS NULL`) plus its duplicates. Gold set = labelled clusters (G1 history/live, G2 lab, G3 adversarial). B0–B4 = evaluation configurations (severity-only, decision-table-only, ① without context, ① without verifier, full). Severity = `rule.level` banded per phase-1 §Khối 4, `docs/phase-1-tiep-nhan-chuan-hoa.md:148` (≥ 12 critical, ≥ 8 high, ≥ 5 medium, else low) — one band for the parser, the gold-set strata, B0 and every per-severity result (DEC-053). Blind branch = alerts whose ① suggestion is hidden from analysts until decided. Digest = daily list of auto-closed clusters for human review. Decision table = machine-readable rules in `kb/decision_tables/*.yaml`, also baseline B1.
