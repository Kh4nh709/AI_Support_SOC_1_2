#!/usr/bin/env bash
# backup.sh — one custom-format dump into backups/ (git-ignored except latest.dump), keeping
# the BACKUP_KEEP newest. The restore side is scripts/restore.sh; the schedule is
# conf/soc-backup.cron (a user crontab line, 02:00 = BACKUP_HOUR).
#
# Usage: scripts/backup.sh [--quiet] [DSN]
#   DSN      defaults to ${DATABASE_URL_OWNER:-$DATABASE_URL}.
#   --quiet  one line per run instead of one per step: the cron path appends it to a log, so
#            the log shows every night the job ran and how it ended.
# backups/ is relative to the current directory: run it from the repository root (the cron
# line and `make backup` both do).
#
# Retention is a count, not an age: after a dump has succeeded — never otherwise — the
# BACKUP_KEEP newest soc-*.dump files by modification time are kept and the rest deleted.
# BACKUP_KEEP (default 14, prompts/P5.md "keep 14") is read by this script alone; it is not a
# context-pack §6.3 key, and the data-retention key there has nothing to do with backup files.
# backups/latest.dump does not match soc-*.dump: it is never counted and never pruned.
#
# pg_dump is the one of the server's own major version when the host has it installed
# (/usr/lib/postgresql/<major>/bin). Measured 26/09 on ATTT-M1, PATH's pg_dump is 18 and the
# server is 16: pg_dump 18 writes archive format 1.16, which pg_restore 16 — the one the db
# container runs on a fresh volume (db/init/02-restore.sh) — rejects as "unsupported version".
#
# A dump is written under a hidden .partial name, read back with pg_restore --list, and only
# then renamed: a half-written file never looks like a backup to the backup-age check or to the
# prune. Exit 0 ok · 1 a step failed · 2 bad arguments or settings (nothing dumped).
set -euo pipefail

QUIET=0
DSN_ARG=""
for arg in "$@"; do
  case "$arg" in
    --quiet) QUIET=1 ;;
    -*) echo "backup: unknown option $arg (usage: scripts/backup.sh [--quiet] [DSN])" >&2; exit 2 ;;
    *) DSN_ARG="$arg" ;;
  esac
done
say() { if [ "$QUIET" = 0 ]; then echo "backup: $*"; fi; }
utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }

STAGE=settings
TMP=""
LATEST_TMP=""
finish() {
  local rc=$?
  if [ -n "$TMP" ]; then rm -f -- "$TMP"; fi
  if [ -n "$LATEST_TMP" ]; then rm -f -- "$LATEST_TMP"; fi
  if [ "$rc" -ne 0 ]; then echo "backup: FAILED $(utc) at $STAGE (exit $rc)" >&2; fi
  exit "$rc"
}
trap finish EXIT

KEEP="${BACKUP_KEEP:-14}"
case "$KEEP" in
  *[!0-9]* | 0*)
    echo "backup: BACKUP_KEEP must be a whole number of dumps >= 1, got '$KEEP' — nothing dumped" >&2
    exit 2
    ;;
esac

DSN="${DSN_ARG:-${DATABASE_URL_OWNER:-${DATABASE_URL:-}}}"
if [ -z "$DSN" ]; then
  echo "backup: no DSN — pass one as argument 1 or set DATABASE_URL_OWNER (or DATABASE_URL)" >&2
  exit 2
fi

STAGE=connect
major="$(psql "$DSN" -XtAc "select current_setting('server_version_num')::int / 10000")"
case "$major" in
  '' | *[!0-9]*) echo "backup: unexpected server version answer: $major" >&2; exit 1 ;;
esac
if [ -x "/usr/lib/postgresql/$major/bin/pg_dump" ]; then
  PG_DUMP="/usr/lib/postgresql/$major/bin/pg_dump"
  PG_RESTORE="/usr/lib/postgresql/$major/bin/pg_restore"
else
  PG_DUMP="$(command -v pg_dump)"
  PG_RESTORE="$(command -v pg_restore)"
  echo "backup: warning — no pg_dump $major under /usr/lib/postgresql; using $PG_DUMP, whose archive a version-$major pg_restore may be unable to read" >&2
fi

STAGE=dump
mkdir -p backups
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="backups/soc-$STAMP.dump"
TMP="backups/.soc-$STAMP.dump.partial"
"$PG_DUMP" --format=custom --file="$TMP" "$DSN"
STAGE=verify
"$PG_RESTORE" --list "$TMP" >/dev/null
mv -f -- "$TMP" "$OUT"
TMP=""
SIZE="$(du -h "$OUT" | cut -f1)"
say "wrote $OUT ($SIZE, $("$PG_DUMP" --version))"

# backups/latest.dump is the copy docker-compose.yml restores on a fresh volume
# (db/init/02-restore.sh) and the one file under backups/ that git tracks
# (Owner decision 20/09/2026): commit it when a milestone is worth restoring to.
STAGE=latest
LATEST_TMP="backups/.latest.dump.partial"
cp -f -- "$OUT" "$LATEST_TMP"
mv -f -- "$LATEST_TMP" backups/latest.dump
LATEST_TMP=""
say "refreshed backups/latest.dump"

STAGE=prune
pruned=0
while IFS= read -r -d '' old; do
  rm -f -- "$old"
  pruned=$((pruned + 1))
  say "pruned $old"
done < <(find backups -maxdepth 1 -type f -name 'soc-*.dump' -printf '%T@ %p\0' \
  | sort -z -r -n | tail -z -n +"$((KEEP + 1))" | cut -z -d' ' -f2-)
kept="$(find backups -maxdepth 1 -type f -name 'soc-*.dump' | wc -l)"

STAGE=done
if [ "$QUIET" = 1 ]; then
  echo "backup: ok $(utc) $OUT ($SIZE), latest.dump refreshed, kept $kept, pruned $pruned"
else
  echo "backup: kept $kept of at most $KEEP (BACKUP_KEEP), pruned $pruned"
fi
