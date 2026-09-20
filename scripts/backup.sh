#!/usr/bin/env bash
# backup.sh — one custom-format dump into backups/ (git-ignored except latest.dump).
# P5 extends this script and adds scripts/restore.sh; the restore side is not here.
set -euo pipefail

DSN="${1:-${DATABASE_URL_OWNER:-${DATABASE_URL:-}}}"
if [ -z "$DSN" ]; then
  echo "backup: no DSN — pass one as argument 1 or set DATABASE_URL_OWNER (or DATABASE_URL)" >&2
  exit 2
fi

mkdir -p backups
OUT="backups/soc-$(date -u +%Y%m%dT%H%M%SZ).dump"

pg_dump --format=custom --file="$OUT" "$DSN"
echo "backup: wrote $OUT ($(du -h "$OUT" | cut -f1))"
# backups/latest.dump is the copy docker-compose.yml restores on a fresh volume
# (db/init/02-restore.sh) and the one file under backups/ that git tracks
# (Owner decision 20/09/2026): commit it when a milestone is worth restoring to.
cp -f "$OUT" backups/latest.dump
echo "backup: refreshed backups/latest.dump"

# Pruning is opt-in: only when RETENTION_DAYS is set in the environment.
if [ -n "${RETENTION_DAYS:-}" ]; then
  find backups -maxdepth 1 -type f -name 'soc-*.dump' -mtime "+$RETENTION_DAYS" -print -delete
  echo "backup: pruned dumps older than $RETENTION_DAYS days"
fi
