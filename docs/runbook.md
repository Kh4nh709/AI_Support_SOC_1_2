# Runbook — AI Support SOC v3
This file is P8's deliverable (`docs/plan/prompts/P8.md`): P4-T07 created it with the `## Pilot` section only; P8-T03 extended it on 26/09/2026 with the five operating sections before `## Pilot` (start and stop, environment keys, backup and restore, what to watch, common failures).

Every command in those five sections runs **from the primary checkout**, in one shell that has sourced `.env` — never from an agent's worktree, which has no `.env` and whose `docker compose` addresses a different compose project: `cd /project/project/AI_Support_SOC_1_2 && set -a; . ./.env; set +a; echo "${DATABASE_URL:+env ok}"` → `env ok`. No value from `.env` is restated here (DEC-070). *(not run by the agent)* marks an expected output only the live stack can give; every other one was measured by P8-T03 on this host, on a private `soc_p8t03_*_test` database standing in for `soc_dev` (`docs/plan/tasks/P8/P8-T03.report.md`).

## Start and stop

`db` is PostgreSQL 16 on port `55432` (`DB_PORT`, volume `pgdata`), `app` is uvicorn on port `8000`, `worker` runs the `pull`, `pipeline` and `triage` jobs; the stack publishes both ports on every interface of the host (`docs/limitations.md` (xxxv)).

| action | command | expected |
|---|---|---|
| start everything | `make up` | `db`, `app`, `worker` up (`docker compose up -d`). **Only on an empty `pgdata` volume**, `db` first runs `db/init/01-roles.sh` (creates `app_rw`) and `02-restore.sh`, which restores `backups/latest.dump`: `docker compose logs db \| grep 'init:'` ends `init: restored — 17 migrations recorded, default privileges for app_rw set`. Later starts reuse the volume and never read the dump. Then `make migrate` → `migrate: 0 applied, 17 already present`. *(`make up`, `logs`: not run by the agent)* |
| stop everything | `make down` | the containers removed, the `pgdata` volume kept. **Never `docker compose down -v`**: it deletes the database, and the next `make up` restores `backups/latest.dump` in its place. *(not run by the agent)* |
| start one part | `make db-up` · `make run-app` · `make run-worker` | `up -d --wait`: returns once `db` is healthy · `db` and `app` are up · `db` and `worker` are up. *(not run by the agent)* |
| restart | after a merge under `backend/app`, or a hang: `docker compose restart worker` (or `app`) · after an `.env` edit: `docker compose up -d --force-recreate app worker` · after a `backend/requirements.txt` change: `docker compose build app worker && docker compose up -d app worker` | code, `conf/` and `kb/` are bind-mounted, so a merge needs a restart, not a build (DEC-099); `.env` is read when a container is created, so `restart` never sees an edit. *(not run by the agent)* |
| native fallback (`make help`: "the 05–20/09 way") | `docker compose stop app worker`; then `make run-app-native` and `make run-worker-native`, each in its own terminal, in a shell that has **not** sourced `.env` | the same two processes on the host, on the same database. They read `.env` themselves; sourcing strips the quotes inside `INVENTORY_PATHS=[…]`, and `config.load()` then refuses the value (measured on a scratch `.env`). Never a host worker beside a container worker: two pullers on one `source_cursor` (`docs/db-docker.md`). Back: `Ctrl-C` both, `make up`. *(not run by the agent)* |
| **up?** the containers | `docker compose ps` | `db`, `app`, `worker`, each `Up …`; `db` also `(healthy)` *(not run by the agent)* |
| **up?** `db` | `pg_isready -h 127.0.0.1 -p "${DB_PORT:-55432}"` | `127.0.0.1:55432 - accepting connections` |
| **up?** `app` | `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/login` | `200` *(not run by the agent)* |
| **up?** `worker` | `docker compose logs --tail=5 worker` | lines such as `{"job_id": …, "job_type": "pull", "outcome": "succeeded", "ms": …}`, a `pull` about once a minute; then **What to watch**, first row *(not run by the agent)* |

## Environment keys

The 62 keys of `.env.example`, one row each, no values. `.env.example` is generated from context pack §6.3 (`scripts/gen_env_example.py`, checked by `make lint`) and frozen: a new key is a decision (DEC-003), never an edit. **Who sets it:** *Owner* — a private or host-specific value, in `.env` only; *default* — `.env.example`'s value, changed only by a DEC. **Secret:** *yes* — `.env` only, never `.env.example`, a commit, a chat or a command line. *Compose* keys are read by `docker-compose.yml` and `db/init/*.sh` only, never by the application; *read by nothing* is a §6.3 key whose reader was cut or never built.

| key | what it controls | who sets it | secret |
|---|---|---|---|
| `DATABASE_URL` | the role the app and the worker use, `app_rw` (the containers get it with `db:5432` from `docker-compose.yml`) | Owner | yes |
| `DATABASE_URL_OWNER` | the owner role: `make migrate`, `backup.sh`, `restore.sh`, `make db-restore`, `make db-shell` | Owner | yes |
| `TEST_DATABASE_URL` | `make test-db`; the database name must end in `_test` | Owner | yes |
| `MAX_PAYLOAD_BYTES` | the largest intake body accepted, checked before parsing | default | no |
| `RAW_LOG_MAX_BYTES` | `raw_log` is truncated beyond this | default | no |
| `PROMPT_LOG_MAX_BYTES` | how much raw log a ① prompt carries | default | no |
| `DEDUP_IDLE_GAP_MINUTES` | dedup: the idle gap after which a cluster takes no more duplicates | default | no |
| `MAX_CLUSTER_AGE_HOURS` | dedup: the oldest a cluster may grow | default | no |
| `MAX_CLUSTER_AGE_AUTOCLOSED_MINUTES` | dedup: the same, for an auto-closed cluster | default | no |
| `MAX_CLUSTER_SIZE` | dedup: the most occurrences one cluster takes | default | no |
| `INDEXER_URL` | the indexer the puller reads; its host name must match the certificate | Owner | no |
| `INDEXER_USER` | the read-only indexer account | Owner | no |
| `INDEXER_PASSWORD` | that account's password | Owner | yes |
| `INDEXER_CA` | the CA every indexer connection is verified against (`conf/root-ca.pem`, mode 0400, git-ignored); there is no unverified mode | Owner | no |
| `INDEXER_INDEX` | the index pattern pulled | default | no |
| `PULL_INTERVAL_S` | seconds between two pulls | default | no |
| `PULL_OVERLAP_S` | each pull starts this far before the cursor; the overlap's duplicates are dropped | default | no |
| `PULL_PAGE` | hits per indexer page | default | no |
| `PULL_START` | where the first pull starts when `source_cursor` is empty | default | no |
| `HEARTBEAT_RULE_ID` | the manager heartbeat's rule: recorded in `intake`, never an alert | default | no |
| `HEARTBEAT_MAX_AGE_MIN` | read by nothing (the health job, P5-T11, was not built) | default | no |
| `SILENCE_WARN_HOURS` | read by nothing (P5-T11) | default | no |
| `JOB_MAX_ATTEMPTS` | attempts per job; then `failed` and a `job.exhausted` event | default | no |
| `JOB_BACKOFF` | seconds before each retry | default | no |
| `JOB_LOCK_TIMEOUT_S` | a `running` job locked longer than this is re-queued by the worker | default | no |
| `N_WORKER` | read by nothing; `docker-compose.yml` runs one worker | default | no |
| `INVENTORY_PATHS` | the inventory, identity and IOC files enrichment loads | default | no |
| `LLM_BASE_URL` | the model API endpoint | default | no |
| `LLM_API_KEY` | the model API key | Owner | yes |
| `LLM_MODEL_PROPOSER` | ①'s model; empty turns ① off (every alert `unavailable`) | default | no |
| `LLM_MODEL_VERIFIER` | the verifier's model; empty means the proposer's | default | no |
| `LLM_TIMEOUT_S` | the wall-clock deadline of one model call | default | no |
| `LLM_RETRY` | retries inside one call, on a network error or a 5xx | default | no |
| `LLM_THINKING` | the model's thinking mode, `disabled` \| `enabled` | default | no |
| `LLM_MONTHLY_USD_CAP` | the month's spend at which ① stops (`stopped_by='cap'`) | default | no |
| `LLM_PRICE_IN_PER_M` | USD per million input tokens (`llm_runs.cost_usd`) | default | no |
| `LLM_PRICE_OUT_PER_M` | USD per million output tokens | default | no |
| `PROMPT_TOTAL_BUDGET_TOKENS` | ①'s prompt budget | default | no |
| `CASE_PROMPT_BUDGET_TOKENS` | read by nothing (②, cut — DEC-097/111) | default | no |
| `ANALYZE_QUOTA_PER_USER_DAY` | read by nothing (②) | default | no |
| `NEVER_AUTOCLOSE_AGENTS` | agents whose alerts are never auto-closed | default | no |
| `AUTOCLOSE_RULE_WIDTH_PCT` | an auto-close rule that closes more than this share of a week's alerts is reported as too wide | default | no |
| `REVIEW_DELTA_TOLERANCE` | a decision is refused (409) when the alert grew by more occurrences than this since it was seen | default | no |
| `MAX_ALERTS_PER_CASE` | the most alerts one case or one correlation takes | default | no |
| `JWT_SECRET` | signs login sessions; empty → the login answers 503 | Owner | yes |
| `JWT_TTL_HOURS` | session lifetime | default | no |
| `LOGIN_MAX_FAILS` | failed logins before a lockout | default | no |
| `LOCKOUT_MINUTES` | the lockout's length | default | no |
| `WEBHOOK_API_KEY` | the webhook intake's key; empty → `503 webhook disabled` | Owner | yes |
| `WEBHOOK_IP_ALLOWLIST` | the addresses allowed to post to the webhook; empty → none | Owner | no |
| `RETENTION_DAYS` | read by nothing (data retention not built); the backup count is `BACKUP_KEEP` in `backup.sh` | default | no |
| `BACKUP_HOUR` | the nightly backup's hour, written into `conf/soc-backup.cron` as `0 2 * * *`; the key itself is read by nothing at run time | default | no |
| `EVAL_BLIND_FRACTION` | the share of alerts whose ① suggestion is hidden (the blind branch) | default | no |
| `DISPLAY_TZ` | the timezone of the times on the pages | default | no |
| `NOTIFY_TELEGRAM_BOT_TOKEN` | read by nothing (`infra/notify.py` was not built) | Owner | yes |
| `NOTIFY_TELEGRAM_CHAT_ID` | read by nothing (the same) | Owner | yes |
| `POSTGRES_USER` | Compose: the `db` superuser, owner of every object | default | no |
| `POSTGRES_PASSWORD` | Compose: its password; `docker compose` refuses to start without it | Owner | yes |
| `POSTGRES_DB` | Compose: the database name | default | no |
| `DB_PORT` | Compose: `db`'s port on the host | default | no |
| `APP_RW_PASSWORD` | Compose: `app_rw`'s password, set by `01-roles.sh` on a first start | Owner | yes |
| `INDEXER_HOST_IP` | Compose: the indexer's address as the containers see it; empty means `host-gateway`, this host | Owner | no |

## Backup and restore

**Nightly: armed on 26/09/2026 by the Owner.** The cron line's own command, run once that day, printed `backup: ok 2026-09-26T04:49:39Z backups/soc-20260926T044938Z.dump (380K), latest.dump refreshed, kept 1, pruned 0`; the first scheduled run is 27/09 02:00 +07. `conf/soc-backup.cron` is one user-crontab line: at `0 2 * * *` (`BACKUP_HOUR`, host time) it enters the primary checkout, sources `.env` and appends the one line of `scripts/backup.sh --quiet` to `~/soc-backup.log`. It was installed with `(crontab -l 2>/dev/null; cat conf/soc-backup.cron) | crontab -`; **do not run that again**, it appends a second line.

| check | command | expected |
|---|---|---|
| armed | `crontab -l \| grep -c backup.sh` | `1`. `0`: not armed, install as above. `2`: installed twice, `crontab -e` and delete one. |
| ran last night | `ls -t backups/soc-*.dump \| head -1` · `tail -1 ~/soc-backup.log` | a `soc-<yesterday>T19…Z.dump` (names are UTC; 02:00 +07 is 19:00Z) · `backup: ok <UTC> backups/soc-….dump (<size>), latest.dump refreshed, kept N, pruned M`. A failed night is one `backup: FAILED <UTC> at <stage> (exit N)` line: run the next row. |
| by hand | `bash scripts/backup.sh` (`make backup` runs the same) | `backup: wrote backups/soc-<UTC stamp>.dump (<size>, pg_dump (PostgreSQL) 16.…)` · `backup: refreshed backups/latest.dump` · `backup: kept N of at most 14 (BACKUP_KEEP), pruned M` |

`backup.sh` dumps `DATABASE_URL_OWNER` with the server's own major version (`/usr/lib/postgresql/16/bin`; PATH's `pg_dump` 18 writes archives a 16 `pg_restore` rejects), writes a hidden `.partial`, reads it back with `pg_restore --list` and only then renames it. It keeps the 14 newest `soc-*.dump` (`BACKUP_KEEP`), pruning only after a success, and copies the new dump over `backups/latest.dump`: the file a fresh `pgdata` volume restores, and the one file under `backups/` git tracks (commit it at milestones only; the remote is public — `docs/db-docker.md`).

**Restore: rehearse first, always, and never from `backups/latest.dump` as committed** — that copy was dumped on IA1803 and carries `DEFAULT ACL … FOR ROLE user1` entries that fail under `pg_restore --exit-on-error` (P5-T12); name a fresh `backups/soc-*.dump`. **Rehearsal, `scripts/restore.sh`:** restores into a separate, new or empty database and never touches the live one — use it before every real recovery (on the dump you will use), to read old data, and for the drill. **Real recovery, `make db-restore`:** **replaces the live database** — stops `app` and `worker`, drops and recreates the database `DATABASE_URL_OWNER` names, restores, starts them again — use it only when the live database is lost or corrupt, with a dump that has just rehearsed clean.

```bash
DUMP="$(ls -t backups/soc-*.dump | head -1)"
bash scripts/restore.sh "$DUMP" --into soc_restore_rehearsal; echo "exit=$?"
psql "$DATABASE_URL_OWNER" -c 'drop database soc_restore_rehearsal'    # once read
```

→ `restore: record — paste into the drill log`, then date, dump (size, sha256), source, target, `live … — not touched`, `pg_restore exit 0`, `schema_migrations 17` and five table counts; `restore: OK — soc_restore_rehearsal restored and verified`; `exit=0`; `DROP DATABASE`. **Its two refusals**, exit 2, nothing changed: the live name, `--into soc_dev` → `restore: REFUSED — soc_dev is the live database; …`; a target that is not empty → `restore: soc_restore_rehearsal is not empty (N objects) — refusing without --force …` (`--force` drops and recreates it, and only on a name ending in `_test`).

```bash
make db-restore FILE=backups/soc-<UTC stamp>.dump    # the dump that just rehearsed clean
```

→ `db-restore: server 16, /usr/lib/postgresql/16/bin/pg_restore`; compose stops `app` and `worker`; `db-restore: backups/soc-….dump → soc_dev (17 migrations)`; compose starts them *(not run by the agent)*. Before it stops anything it asks the server its major version and reads the dump with that version's `pg_restore` (P8-T07). **Exit 2** (`… nothing was stopped or dropped`): the server did not answer (`make db-up`), the only `pg_restore` is newer than the server, or it cannot read the dump. **`FAILED at drop` or `FAILED at restore`**: the target has already started `app` and `worker` again, on a missing or partial database. Run `docker compose stop app worker` **at once**; repair: rehearse the next-newest `soc-*.dump`, then `make db-restore FILE=<it>`; then `docker compose up -d app worker`.

The drill's record is `docs/restore-drill.md` (P8-T02: a `backup.sh` dump of `soc_dev` restored into `soc_restore_drill`, counts before ≤ restored ≤ after).

## What to watch (there is no alarm)

`infra/health.py` was not built (P5-T11 deprioritized, DEC-116): the file is a one-line skeleton, nothing checks the system and nothing sends an alarm. Run these by hand, each morning and after every change; the last column is the healthy answer.

| watch | command | healthy |
|---|---|---|
| the pull loop: a pull in the last 5 min, no error | `psql "$DATABASE_URL" -Atc "select now() - last_pull_at < interval '5 minutes', last_error is null from source_cursor"` | `t\|t` |
| pending jobs by type, not growing | `psql "$DATABASE_URL" -Atc "select job_type, status, count(*) from jobs where status in ('pending', 'running') group by 1, 2 order by 1, 2"`, twice, five minutes apart | a `pull\|pending\|1` (or `pull\|running\|1`) row both times; the `pipeline` and `triage` counts the same or lower the second time. **No `pull` row: pulling has stopped** (Common failures, first row). |
| failed jobs and `job.exhausted` events | `psql "$DATABASE_URL" -Atc "select (select count(*) from jobs where status = 'failed'), (select count(*) from audit_events where event_type = 'job.exhausted')"` | the same two numbers as last time. If either grew: `psql "$DATABASE_URL" -Atc "select job_type, left(last_error, 120) from jobs where status = 'failed' order by job_id desc limit 5"` |
| ① rows by `stopped_by`, today (+07) | `psql "$DATABASE_URL" -Atc "select coalesce(stopped_by, 'ok'), count(*) from llm_runs where role = 'proposer' and created_at >= date_trunc('day', now(), 'Asia/Ho_Chi_Minh') group by 1 order by 2 desc"` | `ok\|N` first; `schema` rare; no `cap`, `transient` or `linter` row (Common failures) |
| spend this month against `LLM_MONTHLY_USD_CAP` | `psql "$DATABASE_URL" -Atc "select round(coalesce(sum(cost_usd), 0), 2), ${LLM_MONTHLY_USD_CAP:-30} from llm_runs where created_at >= date_trunc('month', now())"` | the first number well below the second; the adapter sums the same rows (the UTC month) before every model call |
| disk use of `backups/` | `ls backups/soc-*.dump \| wc -l; du -sh backups; df -h --output=pcent . \| tail -1` | at most `14` dumps; the filesystem well below `90%` |
| another test run on the server | `pgrep -fc 'migrate.sh\|make test-db'` | `0` before a `make test-db`. Typed at a prompt or on a script line it never counts itself; inside a longer `bash -c "…; …"` (an agent's tool call) the calling shell's own command line matches and adds `1` — the bracketed `'[m]igrate.sh\|[m]ake test-db'` never matches itself. **Never `ps aux`**: `psql`, `migrate.sh` and `pg_restore` receive the DSN, password included, as an argument. |

## Common failures

Every `psql` check below ran on the stand-in; the failure answers `no response`, `000 exit=7`, `000 exit=60` and the two `pull_once` errors were measured on this host against a closed port and a throwaway TLS server. The `docker`, `.env` and live `curl` checks are *(not run by the agent)*.

| symptom | check | fix |
|---|---|---|
| **Indexer down, or its certificate rejected**: `last_pull_at` stale, no new alerts | `psql "$DATABASE_URL" -Atc "select status, left(last_error, 160) from jobs where job_type = 'pull' order by job_id desc limit 1"` → `pending\|` when well; `…\|pull_once: indexer request failed: [Errno 111] Connection refused` (down) or `…[SSL: CERTIFICATE_VERIFY_FAILED]…` (certificate) · `curl -s -o /dev/null -w '%{http_code}' --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" "$INDEXER_URL/_cluster/health"; echo " exit=$?"` → `200 exit=0` when well | `000 exit=7`, down: the Owner starts the Wazuh stack's indexer container (`docker ps -a --format '{{.Names}}' \| grep indexer`; `docs/wazuh-manager-changes.md` §0′). `000 exit=60`, certificate: the Owner copies that container's `/usr/share/wazuh-indexer/config/certs/root-ca.pem` to `conf/root-ca.pem`, mode 0400, and keeps `INDEXER_URL`'s host the certificate's name. `401 exit=0`: `INDEXER_USER` and `INDEXER_PASSWORD` in `.env`, then `docker compose up -d --force-recreate worker`. Then, if the `pull` job reads `failed`: `docker compose restart worker` — after `JOB_MAX_ATTEMPTS` failed pulls only a worker start queues a new one, which resumes from `source_cursor.last_sort`. |
| **Model API down**: ① rows `transient`, alerts `unavailable` | the ① row of **What to watch** · `psql "$DATABASE_URL" -Atc "select left(last_error, 120) from jobs where job_type = 'triage' and last_error is not null order by job_id desc limit 3"` | Nothing to restart. Each `triage` job is retried (up to `1 + LLM_RETRY` calls an attempt, `JOB_MAX_ATTEMPTS` attempts, `JOB_BACKOFF` apart); the last attempt writes `stopped_by='transient'`, `triage_status='unavailable'` and a `job.exhausted` event. An API that answers 5xx instead ends each job `failed`, with `job.exhausted`, no ① row and the alert left `pending`. Alerts that arrive once the API answers get ①; the others stay as they are, as no re-queue path exists: record the window in `docs/plan/STATE.md`. A `401` in `last_error` is the key, not an outage: `LLM_API_KEY` in `.env`, then `docker compose up -d --force-recreate worker`. |
| **Monthly cap reached**: ① rows `cap` | the spend row of **What to watch**: the first number ≥ the second | ① stays off until the month turns (UTC), or the Owner raises `LLM_MONTHLY_USD_CAP` in `.env` (a DEC) and runs `docker compose up -d --force-recreate worker`. Alerts already `unavailable` stay so. |
| **Worker stuck**: pending jobs growing, a `running` job older than `JOB_LOCK_TIMEOUT_S` | `psql "$DATABASE_URL" -Atc "select job_type, date_trunc('second', now() - locked_at) from jobs where status = 'running' order by locked_at limit 3"` → an age above `00:05:00` | `docker compose restart worker`: the loop re-queues every `running` job locked longer than `JOB_LOCK_TIMEOUT_S` (300 s) and runs the `pull` again; `docker compose logs --tail=5 worker` then shows `"outcome": "succeeded"`. |
| **Database container down**: pages fail, `psql` cannot connect | `docker compose ps db` · `pg_isready -h 127.0.0.1 -p "${DB_PORT:-55432}"` → `127.0.0.1:55432 - no response` | `make db-up` (it returns once `db` is healthy), then `docker compose restart app worker`. Never `docker compose down -v`. |
| **`JWT_SECRET` unset**: the login answers `503` | `grep -c '^JWT_SECRET=.\+' .env` → `0` · `curl -s -X POST http://127.0.0.1:8000/api/auth/login -H 'Content-Type: application/json' -d '{"username":"precheck-nobody","password":"x"}'` → `{"detail":"auth disabled: JWT_SECRET unset"}` | `.venv/bin/python -c "import secrets; print(secrets.token_hex(32))"` → paste as `JWT_SECRET=<value>` into `.env`, never into `.env.example`, a commit or a chat; then `docker compose up -d --force-recreate app`. The same `curl` → `{"detail":"invalid credentials"}`. |

## Pilot

> **26/09/2026 (P8-T03).** Not run. The Tier-1 console this procedure needs (P4-T03/T05/T06) was deprioritized and cut (DEC-116), so no human-decision pilot took place. The procedure is kept as designed. What ran instead is recorded in `docs/results/operations.md` (P8-T01/T06).

Addressed to the two people who run it — the Owner and the advisor (context pack §11: no agent starts the pilot, seeds an account, or tells the advisor the rule). Every command below is pasted **from the primary checkout** (`/project/project/AI_Support_SOC_1_2`, branch `main`, `.env` present); an agent's worktree has no `.env` and must never be the place these run. Commands, not prose: the seconds are the deliverable (`docs/lab-run-log.md`).

Open one shell for the checks and keep it for the whole pilot:

```bash
cd /project/project/AI_Support_SOC_1_2 && set -a; . ./.env; set +a; echo "${DATABASE_URL:+env ok}"
```

→ `env ok`. Every `psql "$DATABASE_URL"` and `curl … "$INDEXER_URL"` below reads that shell's variables; nothing here restates a value from `.env` (DEC-070). The app runs in its **own terminal** (`make run-app`, foreground). The worker runs the way the Owner Assist starts it — detached, log and pidfile under `/home/user1/soc-logs/` (`docs/plan/prompts/owner-assist-P6-run-2026-09-19.md` §0) — or, if you prefer, in its own terminal with `make run-worker`; row **d1** covers both.

### 0 · What this pilot is — and is not

Two analysts work the Tier-1 queue in a browser on `127.0.0.1:8000`: the Owner signed in as `tier1`, the advisor as `tier2`; each also holds an `admin` account, which is P6's labelling account and is not used to decide alerts. Half of the alerts (`EVAL_BLIND_FRACTION=0.5`, chosen per alert by `sha256(alert_id)` at intake, `soar/pipeline.py`) show **no** ① suggestion — the **blind branch** — and the suggestion is removed at the API, not in the page, so no role and no page can see it before the alert is decided; the report (P8) compares decisions **by branch and by person**. Nothing in this pilot is a controlled experiment — architecture §6: *"Thí điểm trực tuyến … là mô tả, không phải kiểm định"* — the numbers are descriptive, and the section that reports them says so in its first sentence.

**Dates.** The pilot runs from the day P4-T05 merges (23/09 evening at the earliest — `docs/plan/tasks/P4/P4-tasks.md` §10 item 5) until P8 closes it. The start day and time are written into `docs/plan/STATE.md` by the Owner (§2 below); no other date counts.

### 1 · Preconditions — each with the command that proves it

Run top to bottom; stop at the first row whose `expected` does not hold. The **in `main` before** column names the task whose merge the row waits for (`git log --oneline main | grep -c 'Merge branch .task/<id>'` → `1`).

| # | check | command | expected |
|---|---|---|---|
| a | `.env` carries a `JWT_SECRET` (in `main` before: P4-T01 ✓ 20/09) | `grep -c '^JWT_SECRET=.\+' .env` | `1`. If `0`: `python3 -c "import secrets; print(secrets.token_hex(32))"` → paste as `JWT_SECRET=<value>` into `.env` — never into `.env.example`, never into chat. Until it is set the login answers `503 auth disabled: JWT_SECRET unset`. Re-run the shell prelude after editing `.env`. |
| b | migrations current | `psql "$DATABASE_URL_OWNER" -Atc "select count(*) from schema_migrations"` | `17`. Less → `make migrate` from the primary checkout, then re-check. |
| c | inventory loaded (DEC-083) | `psql "$DATABASE_URL" -Atc "select (select count(*) from assets), (select count(*) from identities)"` | `4\|2` (`HR-computer`, `IA1803`, `user1-IA1803`, `wazuh.manager`; `root`, `user1`). If `0\|0`: `PYTHONPATH=backend python3 -c "from app.infra.db import connect; from app.enrichment.inventory import load; c = connect(); print(load(c)); c.commit()"` — or `POST /api/admin/reload-inventory` signed in as `admin`. |
| d1 | worker process alive | `pgrep -af 'python3 -m app.web.worker'` | one line ending `-m app.web.worker` (a `sh -c` wrapper may show as a second line — same worker). None → start it from the primary checkout, detached with a log outside the repo: `mkdir -p /home/user1/soc-logs && PYTHONUNBUFFERED=1 nohup setsid make run-worker > /home/user1/soc-logs/worker-$(date +%F).log 2>&1 & sleep 2; pgrep -f 'make run-worker' > /home/user1/soc-logs/worker.pid` (the pidfile is the process-group leader; stop with `kill -- -$(cat /home/user1/soc-logs/worker.pid)` — DEC-102) — or, simpler, `make run-worker` in its own terminal. Leave it running: the puller is the `pull` job the worker enqueues for itself every `PULL_INTERVAL_S=60`. Both were **down from the 16/09 reboot to 19/09** (DEC-089) — this row is not a formality. **Restart the worker after every merge that touches `backend/app/web/worker.py`, `soar/` or `infra/puller.py`** (P3-T10, P3-T11 do) — a running process never picks up a new handler. |
| d2 | puller pulling — cursor advances | `psql "$DATABASE_URL" -Atc "select last_sort, last_pull_at, last_error from source_cursor"` — run it, wait two minutes (`sleep 120`), run it again | `last_pull_at` later on the second run; `last_error` empty (a third field printed blank). A non-empty `last_error` names the indexer problem — fix that, not the worker. |
| d3 | live alerts arriving | `psql "$DATABASE_URL" -Atc "select count(*) from alerts where source='wazuh'"` | rising from **3,941** (the 19/09 figure, unchanged since 15/09). ≈ 3,400 live documents wait in the indexer, so the first minutes after `make run-worker` are catch-up — a jump of thousands is expected, not a fault. |
| d4 | intake drained | `psql "$DATABASE_URL" -Atc "select count(*) from intake where processed_at is null"` | falling to `0` and staying near it (G12: every intake row gets `processed_at` or `error` within 60 s while the worker is alive). |
| e | manager alive — through the indexer, **never the file** (DEC-091) | `curl -s --cacert "$INDEXER_CA" -u "$INDEXER_USER:$INDEXER_PASSWORD" "$INDEXER_URL/wazuh-alerts-*/_count" -H 'Content-Type: application/json' -d '{"query":{"term":{"rule.id":"100999"}}}'` | `{"count":N,…}` with `N` rising by **one every 10 minutes** (the heartbeat is a 600 s `full_command` stanza — DEC-068). Run it twice ten minutes apart if in doubt. An exit code `60` means `INDEXER_CA` does not match `INDEXER_URL`; `401` means the read-only account — both are `.env` facts, not pilot facts. |
| f | the seed CLI is in this checkout (in `main` before: P4-T01 ✓ 20/09), then **run block 1f below once** | `PYTHONPATH=backend python3 -m app.infra.auth seed-users --help >/dev/null && echo cli ok` | `cli ok`; then block **1f** prints four `created: <username> (<role>)` lines and exits `0`. |
| f′ | the `users` table shows the four accounts | `psql "$DATABASE_URL" -Atc "select username, role, is_active from users order by 1"` | four rows — one `tier1`, one `tier2`, two `admin` — each `\|t`. |
| g | ① is running (in `main` before: **P3-T10**, and the worker **restarted after that merge** — DEC-102 option A; live suggestions need **P3-T11**'s live run) | `psql "$DATABASE_URL" -Atc "select count(*) from llm_runs where role='proposer'"` | `> 0`, and rising as the worker's `triage` handler drains the pending `triage` jobs (≈ 500 at 20/09). `0` with P3-T10 in `main` → the worker predates the merge: stop it (`kill -- -$(cat /home/user1/soc-logs/worker.pid)`, or `Ctrl-C` in its terminal) and start it again as in row **d1**. **If `0` the pilot can still start** — every alert then reads *"Chưa có gợi ý ①"* and the blind branch measures nothing yet; say so in `STATE.md` beside the start time, and P8 dates the ① coverage from the first `llm_runs` row. |
| h | the app is up (in `main` before: P4-T04 for `/login`, **P4-T05** for `/queue` and `/alerts/{id}` — the pilot cannot start without T05) | in its **own terminal**, from the primary checkout: `make run-app 2>&1 \| tee -a ~/pilot-app.log` — then, in the checks shell: `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/login` | `200`. The `tee` keeps uvicorn's access log for §7 (the `409` count); `~/pilot-app.log` is outside the repository on purpose. |
| h′ | the app loaded `JWT_SECRET` | `curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8000/api/auth/login -H 'Content-Type: application/json' -d '{"username":"precheck-nobody","password":"x"}'` | `401` (invalid credentials for a user that does not exist — it counts against no account). `503` means the app was started before row **a** was done: restart it. |

**Block 1f — the seed command** (row **f**; once, from the primary checkout; `.env`'s `DATABASE_URL` is the `app_rw` DSN, and migration 017 lets it insert into `users`):

```bash
PYTHONPATH=backend python3 -m app.infra.auth seed-users --env-file .env \
  --user <OWNER_T1_USERNAME> tier1 "<Owner display name>" \
  --user <ADVISOR_T2_USERNAME> tier2 "<Advisor display name>" \
  --user <OWNER_ADMIN_USERNAME> admin "<Owner display name>" \
  --user <ADVISOR_ADMIN_USERNAME> admin "<Advisor display name>"
```

**Each password is typed at the `password for <username>:` prompt the CLI opens** (`getpass`) — never on the command line, and never as an inline `SEED_PASSWORD_<USERNAME>` assignment in front of the command: that lands in shell history (Director at E5, DEC-095; the env form exists for non-interactive tests only). A re-run prints `exists, skipped: <username>` four times and changes nothing (an existing hash is never overwritten). The four usernames must stay distinct after upper-casing with `-` → `_` — the CLI refuses a collision. The two `admin` accounts are P6's labelling accounts (26–27/09); write the four usernames into `STATE.md`'s "20/09 — KIỂM 2/2" line.

Rows **a–f′** can be done today; **g** waits for P3-T10; **h** waits for P4-T05 and is the last thing before §2.

### 2 · The start — one action

The Owner opens `http://127.0.0.1:8000/login`, signs in with the `tier1` account, opens the first alert in the queue, presses **"Tiếp nhận"**, and decides it (*"Dương tính giả"* / *"Lành tính"* with a reason, or escalates). **That first decision is the pilot start.** Write the date and time (`date '+%F %T'` in the checks shell) into `docs/plan/STATE.md` under the P4 phase row, commit from the primary checkout — nothing else counts as the start: not `make run-app`, not the login, not a decision by the advisor.

### 3 · The rule for the advisor — say it aloud, before the first alert

Vietnamese: **"Quyết trước; không bao giờ mở `llm_runs`, không hỏi ① đã nói gì, trước khi bấm quyết định. Khoảng một nửa alert không hiện gợi ý — đó là thiết kế, không phải lỗi."**

English: **"Decide first; never open `llm_runs` or ask what ① said before you press decide. About half the alerts show no suggestion — by design, not a bug."**

The same rule binds the Owner. The consequence (the Director's incident table, `docs/plan/prompts/director.md`): an alert whose ① output was seen before it was decided — in `llm_runs`, in a digest, in a chat — has its decision **discarded from the blind-branch analysis**, and the case is recorded in a DEC. Say when it happens; it is a recorded exclusion, not a fault.

### 4 · What day 1 looks like — and why nobody "fixes" it

- **(a) The queue opens with the 383 replayed heads** (`replay` 307 + `wazuh` 76 at 19/09). Every one was enriched **before** the inventory was loaded on 15/09, so all 383 carry `asset = unknown` / `lookup_status.asset = not_found`, and G8′'s asset block pinned every one of them to the queue (DEC-083 — enrichment is written at the A5/A6 edge and there is no `queued_tier1 → enriching` transition, so no supported path changes it). They are **real alerts with a known enrichment gap**: decide them normally, on what the raw log and the correlation say. **Do not re-enrich, do not delete, do not skip them.** P8 names them as a limitation and reports them in or out per its chapter (§6).
- **(b) New live alerts are enriched correctly** (the inventory has been loaded since 15/09) — and ≈ **79 %** of them come from one Windows endpoint, `HR-computer` (SCA / EventChannel noise; 79.4 % of the 14/09 sample — DEC-066). This is the estate, not a defect, and it is **not a reason to add a filter** (`docs/plan/prompts/planner-run-P4-2026-09-19.md` §2): a filtered pilot would measure the filter. Decide the noise as noise — that is what the false-positive half of the evaluation is for.
- **(c) The risk column is a band, never a number** — Thấp · Vừa · Cao · Rất cao (`docs/phase-4-enrichment.md:198-207`), shown with the alert's own severity. The score is not on the page by design.
- **(d) ⚑ beside a suggestion** means the gate forced the verdict (`gate.forced`; the detail page says which step, *"cổng đã ép: …"*). Expected on this corpus: the 383 heads all miss `asset_criticality`, so ① on them is forced to `needs_review` — the gate working, not ① failing.
- **(e) *"Gợi ý ① ẩn — nhánh mù"*** on a detail page is the blind branch: whatever ① said — or has not yet said — about that alert is hidden until it is decided, and so is whether ① ran at all (`triage_status` and `run_id` are stripped with the suggestion — DEC-101). *"Chưa có gợi ý ①"* appears only on the visible branch and means ① has not run on that alert yet (row **g**). In the queue the ① column shows `—` in both cases.

### 5 · Daily checks — two minutes, each morning

In the checks shell (prelude from the top of this section already run):

| check | command | expected | when it is off |
|---|---|---|---|
| ① ran in the last day | `psql "$DATABASE_URL" -Atc "select count(*) from llm_runs where created_at > now() - interval '1 day' and role='proposer'"` | `> 0` | flat at `0` → the worker's `triage` handler is not wired or the worker is down: `pgrep -af app.web.worker`; if alive, check P3-T10 is in `main` and restart the worker. |
| queue shape | `psql "$DATABASE_URL" -Atc "select triage_status, count(*) from alerts where status='queued_tier1' group by 1"` | mostly `ready`; `pending` shrinking | `pending` growing for a day → same as the row above. `unavailable` rows are alerts on which ① gave up (retries exhausted, budget cap, linter stop — P3-T10) — read why with `psql "$DATABASE_URL" -Atc "select stopped_by, count(*) from llm_runs where role='proposer' and result is null group by 1"` and `psql "$DATABASE_URL" -Atc "select last_error from jobs where job_type='triage' and status='failed' order by created_at desc limit 5"`; do not re-queue by hand. |
| decisions happened | `psql "$DATABASE_URL" -Atc "select count(*) from audit_events where event_type='tier1.decided' and created_at > now() - interval '1 day'"` | `> 0` on a pilot day | `0` → nobody decided yesterday; note the gap in `STATE.md`, do not backfill. |
| intake drained | `psql "$DATABASE_URL" -Atc "select count(*) from intake where processed_at is null"` | ≈ `0` | growing → worker down → `make run-worker` in its terminal (row **d1**); it catches up on its own. |
| manager heartbeat | the `_count` of row **e**; DB-side, `psql "$DATABASE_URL" -Atc "select now() - max(received_at) from intake where outcome='heartbeat'"` and `psql "$DATABASE_URL" -Atc "select now() - last_seen_at from source_heartbeat"` | `_count` rising by one every 10 minutes; the last heartbeat document ingested < `00:12:00` ago (600 s cadence + one pull); `last_seen_at` < `00:02:00` ago (the puller writes it after every successful pull, `PULL_INTERVAL_S=60`) | `last_seen_at` stale → the puller, not the manager: rows **d1**/**d2**. `_count` flat (or the ingested heartbeat old) with `last_seen_at` fresh → the manager or its `full_command` stanza stopped; a manager-side fact for the Owner (context pack §11), not a pilot fault. Decisions continue on what is queued. |
| puller errors | `psql "$DATABASE_URL" -Atc "select count(*) from source_cursor where last_error is not null"` | `0` | `1` → `psql "$DATABASE_URL" -Atc "select last_error from source_cursor"` names the indexer problem (certificate, credentials, index missing); fix `.env` or the indexer, restart the worker. |

### 6 · What P8 excludes from the pilot numbers — and why

P8's export (`eval/pilot_export.py`) excludes these **itself**; the Owner does not keep them out by hand, does not skip them, and does not decide them differently:

- **`source='lab'` rows** — the 22–24/09 lab scenarios on the same host, retagged after each run by `eval/lab_tag.py` from the seconds in `docs/lab-run-log.md` (DEC-085). They are G2's, not the pilot's. Decide them like any other alert if they reach the queue during the pilot; the tag separates them later.
- **Reopened alerts** — any alert with an `alert.reopened` audit event: the ① verdict was visible in the digest before the second decision, so it is blind no longer, and P8 drops it from the blind-branch agreement metric (P4 planning decision 7).
- **The 383 pre-inventory heads** (§4 a) — a named limitation; P8's chapter says whether they are in or out of each table, with the sentence attached.
- **Decisions on the visible branch** are reported as *"có thể thiên lệch"* (`docs/chot-v3-14-ngay.md` §A3; architecture §6): the analyst saw ① before deciding. They are counted, per person, and labelled — never pooled with the blind branch.

### 7 · Limitations of this pilot, stated

- **The session cookie is not `Secure`** — the app binds `127.0.0.1:8000` without TLS (`Makefile` `run-app`), so `soc_session` is `HttpOnly`, `SameSite=Lax`, `Secure` off; and there is no CSRF token beyond `SameSite=Lax`. Acceptable for two users on one host; stated for the record (P4 planning decision 8).
- **`REVIEW_DELTA_TOLERANCE=20`** and **`RETRIAGE_FACTOR=10` / `RETRIAGE_ABS_DELTA=200`** are unvalidated v1 constants. The pilot's evidence about them is the number of `409` conflicts on decide. They are **not audited** — `select count(*) from audit_events where event_type='authz.denied'` counts refused roles, not conflicts — so count them from the app log kept by row **h**: `grep -c ' 409 ' ~/pilot-app.log`. Note the number in `STATE.md` at the end of the pilot.
- **The two analysts are the author and the advisor** (`docs/chot-v3-14-ngay.md` §A3): the blind branch controls what they see, not who they are.
- The day-1 queue (§4 a) and the `HR-computer` share of the live stream (§4 b) are limitations of the same pilot and are listed with these in P8 (`P4-tasks.md` §11 item 4).

### 8 · Stop / rollback

- **Pause or stop the pilot:** `Ctrl-C` in the `make run-app` terminal stops the UI and nothing else. **Leave the worker running** — it keeps ingesting and ① keeps running, and both are wanted for the lab (22–24/09) and for P8's export. To resume, `make run-app` again (row **h**) — sessions survive a restart (they are tokens checked against `users`, not server memory).
- **Nothing in P4 needs a rollback of data.** Every decision is one `tier1.decided` audit row (append-only) plus a status the state machine owns; a wrong decision is corrected the way the design says — reopen when the state machine allows it, or a note in the DEC — never by an `UPDATE`.
- **Stop the worker only for the host, or to restart it after a merge** (row **d1**), never for the pilot: `kill -- -$(cat /home/user1/soc-logs/worker.pid)` for the detached form, `Ctrl-C` in its terminal for the foreground form; starting it again (row **d1**) resumes the puller from `source_cursor.last_sort` (row **d2**) and the pending `triage` jobs from where they were — nothing is lost, nothing is re-done.
