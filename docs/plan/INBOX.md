# INBOX — decision requests and blockers for the Director

Anyone (Coder, Reviewer, Planner) appends here. The Director resolves each item, moves the outcome to `DECISIONS.md`, and marks it here as resolved. Never delete items.

Format:

```
## <date> · <TASK_ID or phase> · <type: DECISION_REQUEST | BLOCKER | QUESTION>
From: <role>
Summary: one sentence
Details: what is needed, why, what breaks otherwise
Options: A) … B) … (recommended: …)
Frozen contract affected: none | <name>
Resolved: <date> · <DECISIONS.md id> | open
```

---

## 2026-09-05 · P0 · QUESTION
From: Owner
Summary: `Final-Project` parser / `category_resolver` / `prompt_guard` all still run on the §8 sample alert, but only the category mapping table and the injection detector are reusable as-is; parser and wrapper must be rewritten for v3.
Details: Ran the three modules against the context-pack §8 document (`PYTHONPATH=~/Documents/Final-Project/backend`, Python 3.12, pydantic 2.13, no other deps, no DB).
  - `app/services/wazuh_ingest.parse_wazuh_alert` → runs, returns 12 of the 20 §8 fields. Missing: `manager_id`, `origin_host`, `agent_id`, `agent_ip`, `rule_level`, `categories`, `event_time`, `srcip_is_private`. Wrong: `alert_time` comes from `_source.timestamp` (`2026-08-17T00:56:56.130+0700`) instead of `fields.timestamp[0]` (`2026-08-16T17:56:56.130Z`).
  - `app/services/category_resolver` → runs; mapping tables (technique/group/decoder/port → category) are good and match the phase-1 5-layer scale, but resolution follows the order of `rule.mitre.id`, so the sample yields `primary_category = suspicious_login` while C5 requires `ssh_brute_force` (T1110 outranks T1078). The explicit priority table of phase-1 §Block 5 is missing.
  - `app/security/prompt_guard` → runs (stdlib only). `detect_injection` is directly reusable for gate step 5 / `security/detector.py`: detection-only, returns findings, never mutates. `wrap_untrusted` does not satisfy G6′: delimiter is `<<<UNTRUSTED_DATA[label:nonce]>>>` not `<untrusted_data nonce=… source=…>`, nonce is `token_hex(4)` not `(8)`, no NFKC, no HTML-escape, no nonce stripping inside content, no `[truncated]` marker, no typed builder.
Options: A) Port the category mapping tables + `detect_injection` into `ingest/category.py` and `security/detector.py` and write `ingest/wazuh_parser.py` + `security/wrap.py` fresh against §7.1/§8 (recommended). B) Port all three modules and patch them. C) Write everything from scratch, keep `Final-Project` as reference only.
Frozen contract affected: none
Resolved: open

## 2026-09-05 · P0 / P2 · BLOCKER
From: Owner (preparation session)
Summary: The read-only indexer user `soc_ro` cannot be created — no account with permission to write OpenSearch security config is available.
Details: Verified on IA1803 with root. The OpenSearch admin credential is stored in the Logstash keystore as `opensearch_username` / `opensearch_password`; the Logstash keystore CLI offers only `create/list/add/remove` and cannot read values back, so root does not recover it. It is not present in `/etc/default/logstash` or `/etc/logstash/startup.options`. `admin:admin` returns 401. What is already done: `conf/root-ca.pem` is copied and TLS verification against `https://127.0.0.1:9400` is clean (401 = CA correct, credential missing); `.env` carries the `INDEXER_*` block with `INDEXER_USER`/`INDEXER_PASSWORD` left empty.
Blocks: `eval/indexer_probe.py` being run for real (P0 exit gate), the retention check that sizes G1, and the whole P2 puller path from 06/09. P0 task authoring, P1-T01 smoke test, and Planner P0 are NOT blocked.
Options: A) Owner supplies the OpenSearch admin password (set at install, typically `OPENSEARCH_INITIAL_ADMIN_PASSWORD`) — no change to existing security config (recommended). B) Use the admin TLS certificate with `securityadmin.sh` — the supported route when the password is lost; requires locating `admin.pem`/`admin-key.pem`. C) Reset the admin password via a new bcrypt hash in `internal_users.yml` applied with `securityadmin.sh` — risks breaking the Logstash ingest account if Logstash authenticates as `admin`.
Frozen contract affected: none
Resolved: open

## 2026-09-05 · P0-T02 · DECISION_REQUEST
From: Planner (P0)
Summary: Context pack §6.3 lists 50 configuration keys and none of them says how to reach PostgreSQL; `.env.example`, `docker-compose.yml`, `scripts/migrate.sh` and `backend/tests/conftest.py` all need one.
Details: §6.3 is a frozen contract and `backend/app/infra/config.py` is to be generated from it, so adding a key is not a coder's call. The application connects as `app_rw` while migrations run as the owner role (§6.1), which is two DSNs, and the test database must be separable from the real one — the conftest drops and recreates it. Without a decision, P0-T02 either invents key names that P1/P2 then rename, or ships an `.env.example` that cannot start the stack.
Options: A) Add three keys — `DATABASE_URL` (app, role `app_rw`), `DATABASE_URL_OWNER` (migrations and test setup, owner role), `TEST_DATABASE_URL` (tests; the database name must end in `_test`, which the conftest enforces as a safety rail) — plus four compose-only keys `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `DB_PORT` (default 55432, because host port 5432 is already taken by the system PostgreSQL). Recommended. B) One `DATABASE_URL` plus a `DB_ROLE` switch — fewer keys, but the conftest then has no safe way to tell the test database from the real one. C) Keep §6.3 closed and hard-code the DSN in compose and the Makefile — no contract change, but the DSN is then duplicated in four files and cannot be overridden per host.
Frozen contract affected: §6.3 config constants
Resolved: open

## 2026-09-05 · P0-T05 / P1 · DECISION_REQUEST
From: Planner (P0)
Summary: The `assets` contract has two gaps that the inventory format must resolve before the Owner writes `conf/inventory.yaml`: the criticality vocabulary differs between the DB and the LLM schema, and the `owner` / `role` text named in §7.1 has no column.
Details:
  - `docs/Schema/schema.sql:42` — `assets.criticality` CHECK is `crown_jewel|high|normal|low`. Context pack §6.2 `structured_basis.asset_criticality` is `high|medium|low|unknown`, and G8′ blocks auto-close when "asset.criticality = high". Gate step 2 compares `structured_basis` against DB facts field by field, so P3 needs one written mapping, not two vocabularies.
  - §7.1 lists "inventory lookup values (owner, role text)" among the things that must be wrapped in an `<untrusted_data>` block, but §6.1 adds only `source`, `loaded_at`, `active` to `assets`. Either those texts are stored (a column is needed) or §7.1 refers to something that does not exist.
Options: A) Record the mapping `crown_jewel, high → high · normal → medium · low → low · host absent → unknown`, read G8′'s "high" as `{crown_jewel, high}`, and add `owner text`, `role text` to `assets` in a P1 migration. `conf/inventory.yaml.example` and `enrichment/inventory.py` already assume this reading. Recommended. B) Same mapping, but drop `owner` / `role` entirely and delete them from §7.1 — the model then never sees who owns a host. C) Change the DB CHECK to `high|medium|low` — a migration on a v1 table plus a rewrite of the risk-score formula that reads `crown_jewel`; most expensive, no gain.
Frozen contract affected: §6.1 schema (`assets`), §6.2 output schema wording, §2 G8′
Resolved: open

## 2026-09-05 · P0 / P1 · BLOCKER
From: Planner (P0)
Summary: No PostgreSQL is reachable by an agent on this host, so `make test-db` cannot be exercised and P1's exit gate ("migrations 013–016 apply on a clean DB, DB tests green") cannot be verified by a Coder or a Reviewer.
Details: Verified on IA1803 as `user1`. (a) Docker is installed (29.7.2, compose v5.4.0) and `user1` is in group `docker` (gid 984), but `/var/run/docker.sock` is owned by uid/gid 1001 and `sudo` requires a password, so `docker ps` fails with `permission denied`; `docker compose config` works (no daemon needed) and is used for acceptance instead. (b) The system PostgreSQL 16.15 on `127.0.0.1:5432` holds database `soc`, but `user1` has `rolcreatedb = false` and only CONNECT on `soc` — `createdb` and `CREATE SCHEMA` both fail with `permission denied`. The test fixture must drop and recreate its own database, so neither route is open today.
Blocks: `make test-db` on every task from P0-T03 onward; P1's migration verification; P2's dedup concurrency tests (two sessions, advisory locks) which cannot be faked. Does **not** block: P0-T01…T06 authoring and their acceptance, `make test`, P1-T01 smoke test.
Options: A) A PostgreSQL superuser grants the account database-creation rights — `sudo -u postgres psql -c 'ALTER ROLE user1 CREATEDB'` — after which `TEST_DATABASE_URL=postgresql://user1@127.0.0.1:5432/soc_test` works with no docker at all. One command, recommended. B) Fix docker access — `sudo chown root:docker /var/run/docker.sock` (or add the account to gid 1001) — which also unblocks `make run-app` / `run-worker` later, and keeps the test database inside the compose stack on port 55432 as `.env.example` assumes. C) The Owner runs `make test-db` by hand at each review point and pastes the output — no privilege change, but every Reviewer verdict then depends on a human step.
Frozen contract affected: none
Resolved: open
