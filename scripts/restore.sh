#!/usr/bin/env bash
# restore.sh — restore a backup.sh dump into a NAMED database that is not the live one, and
# print a record of what came back. The tool of P8's restore drill.
#
# Usage: scripts/restore.sh <dump> --into <dbname> [--force]
#
# Deliberately not `make db-restore`: that target stops the app and the worker and replaces the
# LIVE database — the right tool for a real recovery, the wrong one for a rehearsal, where a
# failure would then be an outage. A rehearsal that can overwrite production is not a
# rehearsal, so this script refuses, before it connects to anything, when:
#   - DATABASE_URL is unset. It names the live database and is read from the environment only:
#     the caller sources .env (set -a; . ./.env; set +a); this script never reads that file.
#   - the target is the database DATABASE_URL (or DATABASE_URL_OWNER, when set) names — both
#     names are printed, exit 2;
#   - the target is postgres/template0/template1, or not a plain lower-case name;
#   - --force is given for a name that does not end in _test. --force drops and recreates an
#     existing target, so it carries the rail backend/tests/conftest.py puts on every database
#     it drops.
# An existing target must be empty (no relation, function or schema of its own) unless --force.
#
# It connects as DATABASE_URL_OWNER (else DATABASE_URL) with the database name swapped, creates
# the target if absent, runs pg_restore --no-owner --exit-on-error, and prints the record P8's
# drill log is made of: date, dump, target, pg_restore exit, schema_migrations (17 on this
# code) and the five counts the 22/09 migration proved itself on.
#
# pg_restore is the one of the server's own major version when installed
# (/usr/lib/postgresql/<major>/bin), else PATH's. Measured 26/09 on ATTT-M1 (PATH 18, server
# 16): pg_restore 18 sends `SET transaction_timeout = 0`, which a 16 server rejects, so with
# --exit-on-error nothing at all is restored.
#
# Exit: 0 restored and verified · 1 a step failed (connect, read, create, restore, verify) ·
#       2 refused — nothing was changed.
set -euo pipefail

TABLES=(schema_migrations alerts intake llm_runs jobs audit_events)
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() { echo "usage: scripts/restore.sh <dump> --into <dbname> [--force]" >&2; }
refuse() { echo "restore: $*" >&2; exit 2; }
fail() { echo "restore: FAILED — $*" >&2; exit 1; }

# The database a postgres:// URI names ('' if none); percent-escapes decoded.
dbname_of() {
  local rest="${1#*://}"
  case "$rest" in *@*) rest="${rest##*@}" ;; esac
  rest="${rest%%\?*}"
  case "$rest" in */*) rest="${rest#*/}" ;; *) rest="" ;; esac
  printf '%b' "${rest//%/\\x}"
}

# $1 with its database replaced by $2: same scheme, credentials, host and query string.
with_db() {
  local scheme="${1%%://*}" rest="${1#*://}" auth="" query=""
  case "$rest" in *@*) auth="${rest%@*}@"; rest="${rest##*@}" ;; esac
  case "$rest" in *\?*) query="?${rest#*\?}"; rest="${rest%%\?*}" ;; esac
  printf '%s://%s%s/%s%s' "$scheme" "$auth" "${rest%%/*}" "$2" "$query"
}

# --- arguments ------------------------------------------------------------------------------
DUMP=""
TARGET=""
FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --into)
      if [ $# -lt 2 ]; then usage; refuse "--into needs a database name"; fi
      TARGET="$2"
      shift 2
      ;;
    --into=*) TARGET="${1#--into=}"; shift ;;
    --force) FORCE=1; shift ;;
    -h | --help) usage; exit 0 ;;
    -*) usage; refuse "unknown option $1" ;;
    *)
      if [ -n "$DUMP" ]; then usage; refuse "one dump at a time (got $DUMP and $1)"; fi
      DUMP="$1"
      shift
      ;;
  esac
done
if [ -z "$DUMP" ]; then usage; refuse "no dump given"; fi
if [ -z "$TARGET" ]; then
  usage
  refuse "--into <dbname> is required: the database to restore into, never the live one"
fi

# --- refusals: nothing below this block runs unless all of them pass ---------------------------
if ! [[ "$TARGET" =~ ^[a-z_][a-z0-9_]{0,62}$ ]]; then
  refuse "--into '$TARGET' is not a plain database name ([a-z_][a-z0-9_]*, at most 63 characters)"
fi
case "$TARGET" in
  postgres | template0 | template1) refuse "$TARGET is a system database — pick another --into name" ;;
esac
if [ -z "${DATABASE_URL:-}" ]; then
  refuse "DATABASE_URL is unset — it names the live database, and without it the target cannot" \
    "be told apart from it. Source .env first: set -a; . ./.env; set +a"
fi
LIVE_VARS=(DATABASE_URL)
if [ -n "${DATABASE_URL_OWNER:-}" ]; then LIVE_VARS+=(DATABASE_URL_OWNER); fi
LIVE_NAMES=()
for var in "${LIVE_VARS[@]}"; do
  case "${!var}" in
    postgres://* | postgresql://*) ;;
    *) refuse "$var is not a postgresql:// URI — the live database's name cannot be read from it" ;;
  esac
  name="$(dbname_of "${!var}")"
  if [ -z "$name" ]; then refuse "$var names no database — the live one cannot be told apart"; fi
  LIVE_NAMES+=("$name")
done
for name in "${LIVE_NAMES[@]}"; do
  if [ "$name" = "$TARGET" ]; then
    {
      echo "restore: REFUSED — $TARGET is the live database; a rehearsal that can overwrite it" \
        "is not a rehearsal"
      printf 'restore:   %-26s %s\n' "target (--into)" "$TARGET"
      for i in "${!LIVE_VARS[@]}"; do
        printf 'restore:   %-26s %s\n' "live   (${LIVE_VARS[$i]})" "${LIVE_NAMES[$i]}"
      done
      echo "restore: nothing was restored; pick another --into name"
    } >&2
    exit 2
  fi
done
if [ "$FORCE" = 1 ] && [[ "$TARGET" != *_test ]]; then
  refuse "--force drops and recreates the target, so it is allowed only on a name ending in" \
    "_test (got $TARGET)"
fi
if [ ! -f "$DUMP" ]; then refuse "no such dump: $DUMP"; fi
if [ ! -s "$DUMP" ]; then refuse "empty dump: $DUMP"; fi

# --- connect ---------------------------------------------------------------------------------
if [ -n "${DATABASE_URL_OWNER:-}" ]; then BASE_VAR=DATABASE_URL_OWNER; else BASE_VAR=DATABASE_URL; fi
MAINT="$(with_db "${!BASE_VAR}" postgres)"
TARGET_DSN="$(with_db "${!BASE_VAR}" "$TARGET")"
started=$SECONDS

if ! major="$(psql "$MAINT" -XtAc "select current_setting('server_version_num')::int / 10000" 2>&1)"; then
  fail "cannot reach the server $BASE_VAR names: $major"
fi
case "$major" in '' | *[!0-9]*) fail "unexpected server version answer: $major" ;; esac
if [ -x "/usr/lib/postgresql/$major/bin/pg_restore" ]; then
  PG_RESTORE="/usr/lib/postgresql/$major/bin/pg_restore"
else
  PG_RESTORE="$(command -v pg_restore)" || fail "no pg_restore on PATH"
  echo "restore: warning — no pg_restore $major under /usr/lib/postgresql; using $PG_RESTORE" >&2
fi
if ! listing="$("$PG_RESTORE" --list "$DUMP")"; then
  fail "$PG_RESTORE cannot read $DUMP (an archive from a newer pg_dump? backup.sh uses the" \
    "server's own version)"
fi
# The archive's own header: which database it was taken from, when, and by which pg_dump.
src_db="$(sed -n 's/^;[[:space:]]*dbname: //p' <<<"$listing")"
src_at="$(sed -n 's/^;[[:space:]]*Archive created at //p' <<<"$listing")"
src_by="$(sed -n 's/^;[[:space:]]*Dumped by pg_dump version: \([^ ]*\).*/\1/p' <<<"$listing")"

# --- the target: absent → create; empty → use; not empty → refuse, or --force ------------------
if ! exists="$(psql "$MAINT" -XtAc "select count(*) from pg_database where datname = '$TARGET'" 2>&1)"; then
  fail "cannot list databases: $exists"
fi
if [ "$exists" = 1 ]; then
  objects_sql="select (select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace
                        where n.nspname !~ '^pg_' and n.nspname <> 'information_schema')
                    + (select count(*) from pg_proc p join pg_namespace n on n.oid = p.pronamespace
                        where n.nspname !~ '^pg_' and n.nspname <> 'information_schema')
                    + (select count(*) from pg_namespace
                        where nspname !~ '^pg_' and nspname not in ('public', 'information_schema'))"
  if ! objects="$(psql "$TARGET_DSN" -XtAc "$objects_sql" 2>&1)"; then
    fail "cannot inspect $TARGET: $objects"
  fi
  if [ "$objects" = 0 ]; then
    state="existed, empty"
  elif [ "$FORCE" = 1 ]; then
    dropdb --maintenance-db="$MAINT" "$TARGET" || fail "could not drop $TARGET"
    createdb --maintenance-db="$MAINT" "$TARGET" || fail "could not create $TARGET"
    state="dropped and recreated (--force; it held $objects objects)"
  else
    refuse "$TARGET is not empty ($objects objects) — refusing without --force, which drops and" \
      "recreates it; nothing was changed"
  fi
else
  createdb --maintenance-db="$MAINT" "$TARGET" || fail "could not create $TARGET"
  state="created"
fi

# --- restore and verify ------------------------------------------------------------------------
set +e
"$PG_RESTORE" --no-owner --exit-on-error --dbname="$TARGET_DSN" "$DUMP"
restore_rc=$?
set -e

verify_sql="select 0, 'date', to_char(now() at time zone 'UTC', 'YYYY-MM-DD HH24:MI:SS \"UTC\"')
union all
select i, t, case when to_regclass(format('public.%I', t)) is null then 'absent'
                  else (xpath('/row/n/text()', query_to_xml(
                          format('select count(*) as n from public.%I', t), false, true, '')))[1]::text
             end
from unnest(array['schema_migrations', 'alerts', 'intake', 'llm_runs', 'jobs', 'audit_events'])
     with ordinality as u(t, i)
order by 1"
if ! verified="$(psql "$TARGET_DSN" -XtA -F'|' -c "$verify_sql" 2>&1)"; then
  fail "pg_restore exit $restore_rc; the verification query failed: $verified"
fi
declare -A count=()
when=""
while IFS='|' read -r _ key value; do
  if [ "$key" = date ]; then when="$value"; else count[$key]="$value"; fi
done <<<"$verified"

expected="$(find "$ROOT/docs/Schema" -maxdepth 1 -name '[0-9][0-9][0-9]_*.sql' 2>/dev/null | wc -l)"
migrations="${count[schema_migrations]:-absent}"
if [ "$expected" -gt 0 ] && [ "$migrations" != "$expected" ]; then
  migrations="$migrations (this checkout has $expected migrations)"
fi
live="${LIVE_NAMES[0]} (DATABASE_URL)"
if [ "${#LIVE_NAMES[@]}" -gt 1 ] && [ "${LIVE_NAMES[1]}" != "${LIVE_NAMES[0]}" ]; then
  live="$live, ${LIVE_NAMES[1]} (DATABASE_URL_OWNER)"
fi

row() { printf '  %-18s %s\n' "$1" "$2"; }
echo "restore: record — paste into the drill log"
row date "$when"
row dump "$DUMP ($(du -h "$DUMP" | cut -f1), sha256 $(sha256sum "$DUMP" | cut -d' ' -f1))"
row source "${src_db:-?}, archived ${src_at:-?} by pg_dump ${src_by:-?}"
row target "$TARGET ($state)"
row live "$live — not touched"
row pg_restore "exit $restore_rc — pg_restore $("$PG_RESTORE" --version | awk '{print $3}') --no-owner --exit-on-error"
row schema_migrations "$migrations"
for t in "${TABLES[@]:1}"; do row "$t" "${count[$t]:-absent}"; done
row elapsed "$((SECONDS - started)) s"

if [ "$restore_rc" -ne 0 ]; then
  fail "pg_restore exit $restore_rc: $TARGET holds a partial restore — drop it, or re-run with" \
    "--force if its name ends in _test"
fi
case "${count[schema_migrations]:-}" in
  '' | absent | 0) fail "schema_migrations is ${count[schema_migrations]:-absent}: this is not a restored SOC database" ;;
esac
echo "restore: OK — $TARGET restored and verified"
