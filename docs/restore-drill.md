# Restore drill — P8-T02

- **Date.** 29/09/2026, 13:50 UTC (20:50 Asia/Ho_Chi_Minh).
- **Run by.** Director 1, at the Owner's word in chat on 29/09 ("Cho phép tự chạy").
- **Commit.** `b001af4` on `director/lab-rebuild-0925`. At the drill, `main` = `b001af4`, which is also the live code.
- **Card.** `docs/plan/tasks/P8/P8-T02.prompt.md`.
- **Outcome: PASS.** Every table satisfies before ≤ restored ≤ after, migrations = 17, and `app_rw` reads the copy.

## What was done

All commands ran in one shell that had sourced the primary checkout's `.env` (`set -a; . ./.env; set +a`). No DSN was printed; the drill script masks any password in its output. Counts were taken in read-only transactions (`default_transaction_read_only=on`).

| Step | Time (UTC) | Command | Decisive output |
|---|---|---|---|
| 1 · Before | T0 = 13:50:06 | Counts on `soc_dev` | See the criterion table |
| 2 · Backup | 13:50:06 → T1 = 13:50:07 | `bash scripts/backup.sh`, DSN = `DATABASE_URL_OWNER` | `wrote backups/soc-20260929T135006Z.dump (5.5M, pg_dump (PostgreSQL) 16.15)`, exit 0 |
| 3 · After | T2 = 13:50:07 | Counts on `soc_dev` | Equal to T0 on every table |
| 4 · Guard | 13:50:07 | `bash scripts/restore.sh <dump> --into soc_dev` | **exit 2**; see below |
| 5 · Restore | 13:50:07 → 13:50:10 | `bash scripts/restore.sh <dump> --into soc_restore_drill` | exit 0; see below |
| 7 · App role | 13:50:10 | `app_rw` (`DATABASE_URL` with only the database swapped): `select count(*) from alerts` | `alerts=9697`, the same as step 5; no `permission denied` |
| 8 · Code | 13:50:19 | `make test` at `b001af4` | 1586 passed, 0 failed, 2 skipped, 2 xfailed |

**Step 4, the live-name guard, run for real** (DEC-128 item 2):
```
restore: REFUSED — soc_dev is the live database; a rehearsal that can overwrite it is not a rehearsal
restore:   target (--into)            soc_dev
restore:   live   (DATABASE_URL)      soc_dev
restore:   live   (DATABASE_URL_OWNER) soc_dev
restore: nothing was restored; pick another --into name
```
- The guard exited 2 before connecting to anything.
- The counts on `soc_dev` taken right after the guard equal T0 on every table.

**Step 5, the restore:**
```
restore: record — paste into the drill log
  date               2026-09-29 13:50:10 UTC
  dump               …/drill/backups/soc-20260929T135006Z.dump (5.5M, sha256 5ded9e6e5b8e9de424819b6d8a77a7331d7aa48705ea23987691f3d060a3b3ca)
  source             soc_dev, archived 2026-09-29 20:50:06 +07 by pg_dump 16.15
  target             soc_restore_drill (created)
  live               soc_dev (DATABASE_URL) — not touched
  pg_restore         exit 0 — pg_restore 16.15 --no-owner --exit-on-error
  schema_migrations  17
  alerts             9697
  intake             10171
  llm_runs           1470
  jobs               16352
  audit_events       12379
  elapsed            3 s
restore: OK — soc_restore_drill restored and verified
```
- `pg_restore` printed **no error lines**.
- The dump's `GRANT … TO app_rw` lines met the role, because on this host roles are cluster-wide (one server, `127.0.0.1:55432`). The P8 brief expected this; the drill records it rather than assuming it.
- Step 7 is the proof that the grants survived.

## Criterion (step 6)

| Table | Before (T0) | Restored | After (T2) | Holds |
|---|---:|---:|---:|---|
| `schema_migrations` | 17 | 17 | 17 | yes (= 17) |
| `alerts` | 9,697 | 9,697 | 9,697 | yes |
| `intake` | 10,171 | 10,171 | 10,171 | yes |
| `llm_runs` | 1,470 | 1,470 | 1,470 | yes |
| `jobs` | 16,352 | 16,352 | 16,352 | yes |
| `audit_events` | 12,379 | 12,379 | 12,379 | yes |
| `triage_labels` | 112 | 112 | 112 | yes |
| `eval_runs` | 9 | 9 | 9 | yes |

The pipeline kept pulling during the drill. No new alert landed in the one second between T0 and T2, so before, restored and after are equal rather than merely ordered.

## Deviations from the card
1. **The dump went to a private scratch directory**, not the primary checkout's `backups/`: `backup.sh` was run from `~/.claude/jobs/…/tmp/drill/`, and it writes `backups/` relative to where it runs.
   - The effect is that the Owner's backup set, its retention count and the git-tracked `backups/latest.dump` are untouched.
   - The script, database and `pg_dump` binary are the same ones the nightly cron uses.
   - The dump is never committed. It will be deleted with the scratch directory.
2. **Step 8 did not show a failure.** The card expected `make test` to show exactly the DEC-113 host-fact failure (`test_backfill_cli.py:184`, as recorded on 25/09). At `b001af4`, `make test` has **0 failures**, so there was nothing to match.
   - `make test-db` needs a `_test` database, so it was not pointed at `soc_restore_drill`.
   - The drill's database proof is steps 5–7, and nothing more is claimed.

## What this drill does not prove
- **No restore onto a fresh cluster.** The copy was restored onto the same PostgreSQL server that holds `soc_dev`. A fresh cluster, as in `db/init/02-restore.sh` on a new volume, would need the `app_rw` role created before the grants apply.
- **No application run against the copy.** Neither the app nor the worker was started against `soc_restore_drill`. Step 7 shows only that the application role can read it.
- **The RPO is set by the schedule, not by this drill.** The nightly crontab is armed: dumps exist from 02:00 local on 27, 28 and 29/09. That gives an RPO of at most 24 h, with the 14 newest dumps kept. A loss between two nightly dumps is not covered.
- **No real recovery was timed.** The 3 s restore is for a 5.5 MB dump. It is not a recovery-time estimate for a larger database.

## Clean-up
`soc_restore_drill` stays in place until the Owner signs. After that, `dropdb soc_restore_drill` is run by the Owner, or by the Director at the Owner's word. This section will record which.

Signed: ________ (Owner) date ______
