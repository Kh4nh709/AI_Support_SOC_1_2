# The database and the services in Docker — since 20/09/2026

Owner decision, 20/09/2026, ahead of moving the project to another server: PostgreSQL, the app and
the worker run under `docker compose`; the repository (plus two private files) is enough to bring
the whole thing back with one command. The native PostgreSQL 16 cluster that served 05–20/09 stays
on IA1803 untouched as a fallback until the submission (02/10).

## What runs where

| Service | Container | Host address | Notes |
|---|---|---|---|
| `db` | `soc-db` (postgres:16) | `127.0.0.1:55432` (`DB_PORT` in `.env`) | volume `pgdata`; first start restores `backups/latest.dump` |
| `app` | `soc-app` | `http://127.0.0.1:8000` | uvicorn `app.web.main:app` |
| `worker` | `soc-worker` | — | `app.web.worker`; pulls from the indexer, runs pipeline + triage jobs |

Inside the containers the repository layout is mirrored under `/srv` (`backend/app`, `conf/`, `kb/`,
`.env`) so every relative path behaves exactly as on the host. `backend/app`, `conf/` and `kb/` are
bind-mounted read-only: **a merge that touches worker code needs `docker compose restart worker`,
not a rebuild** (DEC-099's rule, new form). The indexer stays on the host; the containers reach it
as `wazuh.indexer` through `extra_hosts: host-gateway`.

## Credentials — all in `.env`, git-ignored

| Key | Used by | Value |
|---|---|---|
| `POSTGRES_USER` / `POSTGRES_PASSWORD` | container superuser (`soc`) — owner of every object, `make migrate`, tests | generated 20/09 |
| `APP_RW_PASSWORD` | the `app_rw` login role the application uses | the same password `app_rw` had on the native cluster |
| `DATABASE_URL` | app runtime | `postgresql://app_rw:<APP_RW_PASSWORD>@127.0.0.1:55432/soc_dev` |
| `DATABASE_URL_OWNER` | migrations, backup, seed CLI | `postgresql://soc:<POSTGRES_PASSWORD>@127.0.0.1:55432/soc_dev` |
| `TEST_DATABASE_URL` | `make test-db` | `postgresql://soc:<POSTGRES_PASSWORD>@127.0.0.1:55432/soc_test` |

`docker-compose.yml` overrides `DATABASE_URL` / `DATABASE_URL_OWNER` for the containers with the
in-network address `db:5432`; the `.env` values are what host processes (psql, tests, CLI) use.
`db/init/01-roles.sh` creates `app_rw` with `APP_RW_PASSWORD` before the dump is restored, so the
GRANTs in migration 017 have their grantee. `02-restore.sh` then re-issues 017's two
`ALTER DEFAULT PRIVILEGES` for the container owner (`soc`): the dump carries them for the host user
who ran the migration on the native cluster (`user1`), a role the container does not have.

The `app` and `worker` containers run as the host user (`HOST_UID`/`HOST_GID`, default 1000) so the
bind-mounted private files keep their strict modes — `conf/root-ca.pem` is 0400 and owned by the
Owner; the image's own `soc` user (uid 10001) cannot read it.

## Restore on a fresh machine

```bash
git clone <repo> /project/project/AI_Support_SOC_1_2 && cd /project/project/AI_Support_SOC_1_2
# the two private things, from the separate backup (~/soc-backup/<date>/secrets/):
cp <backup>/secrets/env .env; cp <backup>/secrets/root-ca.pem conf/root-ca.pem; chmod 400 conf/root-ca.pem
cp <backup>/conf/{inventory.yaml,identities.yaml,iocs.csv} conf/        # git-ignored estate files
# on a machine with no native cluster, set DB_PORT=5432 and the three DSNs to :5432 in .env
make up          # db restores backups/latest.dump on its first start, then app + worker come up
make migrate     # must print "0 applied, 17 already present"
make test && make test-db
```

Proof the worker is alive: `psql "$DATABASE_URL" -Atc "select last_pull_at, last_error from source_cursor"`
advancing every ~60 s with `last_error` empty, and `select count(*) from alerts where source='wazuh'`
rising while the estate produces alerts.

## Backup

`make backup` writes `backups/soc-<timestamp>.dump` (pg_dump custom format, `DATABASE_URL_OWNER`) and
refreshes `backups/latest.dump`. `latest.dump` is the **one tracked file** under `backups/`
(Owner decision 20/09 — the remote is public, the dump holds real alerts and argon2 password hashes;
commit it at milestones, not daily: each commit of a changed dump adds ~32 MB to the history).

Everything that is not the repository is backed up separately by `~/soc-backup/backup-full.sh`
(sessions of Claude Code, `.env`, CA, Wazuh config, host inventory) — see `~/soc-backup/<date>/MANIFEST.md`.

## Replacing the live database with a dump

```bash
make db-restore FILE=backups/soc-20260920T132511Z.dump   # stops app+worker, drops and recreates soc_dev, restores, starts them again
```

## Fallback to the native cluster (IA1803 only)

Put the socket DSNs back in `.env` (`postgresql:///soc_dev`, `postgresql:///soc_test`,
`postgresql://app_rw:<pw>@127.0.0.1:5432/soc_dev`), `make down`, then `make run-worker-native` /
`make run-app-native`. Never run the native worker and the container worker at the same time —
two pullers on one `source_cursor` corrupt it.

## Cutover record, 20/09/2026 (20:52–21:05 +07)

1. Native worker stopped at 20:52 (cursor `1789912039634`, last pull 20:51:44); dump
   `backups/soc-20260920T135203Z.dump` → `latest.dump` (32 MB); reference counts: alerts 98,972
   (replay 92,011 + wazuh 6,961), llm_runs 1,006, users 4, jobs 100,792, audit_events 100,706, 17 migrations.
2. `make db-up` → `01-roles.sh` → `02-restore.sh`: every count matched; 21 tables, 40 indexes,
   81 constraints, 7 triggers, 75 grants to `app_rw` — identical to the native cluster; the two
   default ACLs re-issued for `soc`.
3. `.env` DSNs switched to `127.0.0.1:55432`; `make migrate` → `0 applied, 17 already present`.
4. `make up`: the first worker start could not read the 0400 CA (image uid 10001) → containers now
   run as the host user; the next pull continued from the native cursor (`last_sort`
   `1789912039634` → `1789912812175`, 5 hits, 0 new, 5 duplicates — the 60 s overlap, no gap),
   `last_error` empty, heartbeat age 57 s; triage jobs and `llm_runs` kept growing from the container.
5. `POST /api/auth/login` with a wrong password → 401 (auth + JWT secret + DB reachable from `soc-app`).
6. `make lint` 0 · `make test` 1042 passed · `make test-db` **549 passed** on the container
   (the `createdb`-based scratch databases of test_auth/test_pipeline included).
