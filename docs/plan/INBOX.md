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
Resolved: 2026-09-05 · DEC-002 · option A

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
Resolved: 2026-09-05 · DEC-003 · option A, split: the three `*DATABASE_URL*` keys enter §6.3; the four compose-only keys stay out of the contract

## 2026-09-05 · P0-T05 / P1 · DECISION_REQUEST
From: Planner (P0)
Summary: The `assets` contract has two gaps that the inventory format must resolve before the Owner writes `conf/inventory.yaml`: the criticality vocabulary differs between the DB and the LLM schema, and the `owner` / `role` text named in §7.1 has no column.
Details:
  - `docs/Schema/schema.sql:42` — `assets.criticality` CHECK is `crown_jewel|high|normal|low`. Current DDL, pasted verbatim 2026-09-05 before the decision, from `docs/Schema/schema.sql:42-48` (byte-identical to `docs/Schema/001_bang_nen.sql:23-29`, which is the migration that generates it):

    ```sql
    CREATE TABLE assets (
      hostname     text        PRIMARY KEY,
      criticality  text        NOT NULL,
      updated_at   timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT ck_assets_criticality
        CHECK (criticality IN ('crown_jewel','high','normal','low'))
    );
    ```

    Context pack §6.2 `structured_basis.asset_criticality` is `high|medium|low|unknown`, and G8′ blocks auto-close when "asset.criticality = high". Gate step 2 compares `structured_basis` against DB facts field by field, so P3 needs one written mapping, not two vocabularies.
  - §7.1 lists "inventory lookup values (owner, role text)" among the things that must be wrapped in an `<untrusted_data>` block, but §6.1 adds only `source`, `loaded_at`, `active` to `assets`. Either those texts are stored (a column is needed) or §7.1 refers to something that does not exist.
Options: A) Record the mapping `crown_jewel, high → high · normal → medium · low → low · host absent → unknown`, read G8′'s "high" as `{crown_jewel, high}`, and add `owner text`, `role text` to `assets` in a P1 migration. `conf/inventory.yaml.example` and `enrichment/inventory.py` already assume this reading. Recommended. B) Same mapping, but drop `owner` / `role` entirely and delete them from §7.1 — the model then never sees who owns a host. C) Change the DB CHECK to `high|medium|low` — a migration on a v1 table plus a rewrite of the risk-score formula that reads `crown_jewel`; most expensive, no gain.
Frozen contract affected: §6.1 schema (`assets`), §6.2 output schema wording, §2 G8′
Resolved: 2026-09-05 · DEC-004 · none of A/B/C as written — the DB is aligned to §6.2 instead (CHECK becomes `high|medium|low|unknown`; nullable `owner`, `role` added), so no mapping table is needed

## 2026-09-05 · P0 / P1 · BLOCKER
From: Planner (P0)
Summary: No PostgreSQL is reachable by an agent on this host, so `make test-db` cannot be exercised and P1's exit gate ("migrations 013–016 apply on a clean DB, DB tests green" — as filed; the gate reads 013–017 since DEC-004 renumbered the set on 05/09) cannot be verified by a Coder or a Reviewer.
Details: Verified on IA1803 as `user1`. (a) Docker is installed (29.7.2, compose v5.4.0) and `user1` is in group `docker` (gid 984), but `/var/run/docker.sock` is owned by uid/gid 1001 and `sudo` requires a password, so `docker ps` fails with `permission denied`; `docker compose config` works (no daemon needed) and is used for acceptance instead. (b) The system PostgreSQL 16.15 on `127.0.0.1:5432` holds database `soc`, but `user1` has `rolcreatedb = false` and only CONNECT on `soc` — `createdb` and `CREATE SCHEMA` both fail with `permission denied`. The test fixture must drop and recreate its own database, so neither route is open today.
Blocks: `make test-db` on every task from P0-T03 onward; P1's migration verification; P2's dedup concurrency tests (two sessions, advisory locks) which cannot be faked. Does **not** block: P0-T01…T06 authoring and their acceptance, `make test`, P1-T01 smoke test.
Options: A) A PostgreSQL superuser grants the account database-creation rights — `sudo -u postgres psql -c 'ALTER ROLE user1 CREATEDB'` — after which `TEST_DATABASE_URL=postgresql://user1@127.0.0.1:5432/soc_test` works with no docker at all. One command, recommended. B) Fix docker access — `sudo chown root:docker /var/run/docker.sock` (or add the account to gid 1001) — which also unblocks `make run-app` / `run-worker` later, and keeps the test database inside the compose stack on port 55432 as `.env.example` assumes. C) The Owner runs `make test-db` by hand at each review point and pastes the output — no privilege change, but every Reviewer verdict then depends on a human step.
Frozen contract affected: none
Resolved: 2026-09-05 · DEC-008 · option A. Verified independently: `rolcreatedb = t`, createdb/CREATE/INSERT/SELECT/dropdb all pass. **Correction to option A's DSN:** `postgresql://user1@127.0.0.1:5432/soc_test` fails with `fe_sendauth: no password supplied` — TCP needs a password here. The recorded value is `TEST_DATABASE_URL=postgresql:///soc_test` (socket, passwordless, no docker). Closing this immediately exposed a second defect that only a real database could reveal: `make migrate` exits 3 on a clean DB because migrations 008–012 never record themselves; the fix is specified and pre-verified in P0-T03 design note 7.

## 2026-09-05 · P0-T01 · QUESTION
From: Reviewer
Summary: Acceptance command 5 on the P0-T01 card cannot pass as literally written, on any git that rejects multiple pathnames with `-q` — this is blocking an otherwise-correct deliverable.
Details: `git check-ignore -q .env backups eval/results conf/inventory.yaml conf/root-ca.pem && echo IGNORED` (docs/plan/tasks/P0/P0-tasks.md and P0-T01.prompt.md, acceptance #5) fails with `fatal: --quiet is only valid with a single pathname` (exit 128) on git 2.43.0, independent of `.gitignore` content — `git-check-ignore(1)` has never accepted more than one pathname together with `-q`. Verified each of the 5 paths individually resolves to IGNORED (`git check-ignore -q <path>` run one at a time, all exit 0), so the P0-T01 `.gitignore` deliverable itself is correct; only the acceptance command's syntax is broken. Per the Reviewer's standing rule ("a single failing acceptance command is a CHANGES verdict"), this alone forces a CHANGES verdict on P0-T01 (full verdict: `docs/plan/tasks/P0/P0-T01.review.md`) even though no further code change is expected.
Options: A) Rewrite the command as a per-path loop: `for p in .env backups eval/results conf/inventory.yaml conf/root-ca.pem; do git check-ignore -q "$p" || echo "NOT IGNORED: $p"; done` — no output means pass. Recommended. B) Drop `-q` and grep the `-v` output for all 5 paths. C) Leave as written and have the Reviewer keep excusing this specific line — not recommended, contradicts the standing rule for every future task that reuses this pattern.
Frozen contract affected: none
Resolved: 2026-09-05 · DEC-006 · option A with a correction — the loop as filed still fails. Measured on a clean worktree at `1bb33ba`: bare `backups` and `eval/results` exit 1 (NOT IGNORED), because `.gitignore:28-29` are directory-only patterns and neither directory exists on disk. The committed form uses `backups/` and `eval/results/` with trailing slashes, which is the only variant that produces no output. Both cards updated.

## 2026-09-05 · P0-T02 · QUESTION
From: Reviewer
Summary: DEC-002, DEC-003 and DEC-004 are marked `Resolved` in this very file, but `docs/plan/DECISIONS.md` as committed on every P0 branch (checked on `task/P0-T01` @ 1bb33ba and `task/P0-T02` @ 4c837a3, both via an isolated `git worktree add --detach`) still contains only DEC-000 and DEC-001 — the resolutions exist solely as uncommitted edits in the shared working tree, alongside matching uncommitted edits to `00-context-pack.md`, `01-plan.md`, `STATE.md`, this file, and four task-card files.
Details: P0-T02's own `.env.example` and report correctly build against DEC-003 (three database keys enter §6.3) and reference DEC-004's migration renumbering ("P1 migration 017") — the content is right, and the coder had no scope to fix this (the card forbids touching `DECISIONS.md` / `00-context-pack.md`). But because none of it is committed, a fresh clone/checkout of any P0 branch today cannot find DEC-003 anywhere; `docs/plan/tasks/P0/P0-tasks.md` still reads "P1's `013`-`016`" and the committed `P0-T02.prompt.md` still describes the database keys as an open DECISION_REQUEST with the old 7-key `.env.example` layout, not the settled 3-in-§6.3-plus-4-compose-only layout that was actually built. Context pack §6 requires contract changes to be "Director approval logged in docs/plan/DECISIONS.md" — logged, not just live on disk. If this working tree is ever reset, or a P1 coder starts from a fresh clone instead of this shared directory, the authorization trail for §6.3's three database keys and for the `assets` table change disappears. (Full detail: `docs/plan/tasks/P0/P0-T02.review.md`, non-blocking note 1 — this did not block P0-T02's APPROVE, since the deliverable itself correctly implements what was actually decided.)
Options: A) Director commits the current working-tree state of `docs/plan/{DECISIONS.md, 00-context-pack.md, 01-plan.md, INBOX.md, STATE.md, prompts/P1.md, prompts/director.md, HUONG-DAN-VAN-HANH.md, tasks/P0/P0-tasks.md, tasks/P0/P0-T02.prompt.md, tasks/P0/P0-T05.prompt.md}` as one planning commit before P1 starts (recommended). B) Leave as is and rely on the shared working directory staying intact for the rest of the build. C) Have each Coder/Reviewer re-derive decisions from chat history instead of `DECISIONS.md` — defeats the point of the ADR log.
Frozen contract affected: §6.3 config constants (DEC-003), §6.1 schema / §6.2 wording / G8′ (DEC-004) — both already correctly implemented in code; only the git record is missing.
Resolved: 2026-09-05 · option A · committed to `main` as `202e9ca` "plan: log DEC-002…DEC-006 and the P0 review round" — 14 files, DEC-002 through DEC-006 plus the context pack, `01-plan.md`, this file, `STATE.md`, `prompts/P1.md`, `prompts/director.md`, `HUONG-DAN-VAN-HANH.md`, three P0 cards and both Reviewer verdicts. The diff was scanned for secrets before committing (the remote is public); the only hits were the two lines of `P0-T02.review.md` that quote the `.env.example` Compose placeholder. The two root-level page-save files stay untracked — they are ignored by P0-T01's `.gitignore`, which has not merged yet. Note for Coders: `task/P0-T01` and `task/P0-T02` are now behind `main`; rebase before reworking, or the old AC5/AC8 wording will still be in your card.
