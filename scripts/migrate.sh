#!/usr/bin/env bash
# migrate.sh — apply the base schema once, then every migration not yet recorded.
#
# Migrations live flat in docs/Schema/ next to 001–012 (DEC-005); each one ends
# with `INSERT INTO schema_migrations (version) VALUES ('<file stem>');`, so the
# table is the only bookkeeping and P1's 013–017 are picked up with no edit here.
#
# Usage: scripts/migrate.sh [DSN]
#        DSN defaults to ${DATABASE_URL_OWNER:-$DATABASE_URL} — migrations run
#        as the owner role, never as app_rw (context pack §6.1).
set -euo pipefail

MIG_DIR="${MIGRATIONS_DIR:-docs/Schema}"
DSN="${1:-${DATABASE_URL_OWNER:-${DATABASE_URL:-}}}"

if [ -z "$DSN" ]; then
  echo "migrate: no DSN — pass one as argument 1 or set DATABASE_URL_OWNER (or DATABASE_URL)" >&2
  exit 2
fi
if [ ! -d "$MIG_DIR" ]; then
  echo "migrate: migrations directory not found: $MIG_DIR" >&2
  exit 2
fi

applied=0
present=0

# Empty result means the table is absent, so no migration has ever run here.
if [ -z "$(psql "$DSN" -tAc "SELECT to_regclass('public.schema_migrations')")" ]; then
  echo "migrate: schema_migrations absent — applying the base schema $MIG_DIR/schema.sql"
  psql "$DSN" -v ON_ERROR_STOP=1 -q -f "$MIG_DIR/schema.sql"
  echo "migrate: applied schema.sql (records 001_bang_nen … 012_hop_dong_job_llm itself)"
fi

for f in "$MIG_DIR"/[0-9][0-9][0-9]_*.sql; do
  [ -e "$f" ] || continue
  version="$(basename "$f" .sql)"
  if [ -n "$(psql "$DSN" -tAc \
      "SELECT 1 FROM schema_migrations WHERE version = '$version'")" ]; then
    present=$((present + 1))
    continue
  fi
  echo "migrate: applying $version"
  psql "$DSN" -v ON_ERROR_STOP=1 -q -f "$f"
  applied=$((applied + 1))
done

echo "migrate: $applied applied, $present already present"
