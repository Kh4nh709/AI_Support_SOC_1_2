#!/usr/bin/env bash
# First-start init: restore the tracked dump if it is there, otherwise leave the
# empty database for `make migrate` (which applies docs/Schema from the host).
# The dump is pg_dump --format=custom of soc_dev (scripts/backup.sh writes it and
# refreshes backups/latest.dump). --no-owner --role: every object ends up owned
# by the container's superuser ($POSTGRES_USER), not by the host user who made
# the dump; the GRANTs to app_rw inside the dump are applied as written.
#
# One class of entry cannot apply and is expected to fail: the dump's
# "ALTER DEFAULT PRIVILEGES FOR ROLE <host user> …" (migration 017, recorded
# for the role that ran it — user1 on IA1803). pg_restore reports it and goes
# on; the same default privileges are then granted below for $POSTGRES_USER,
# who owns everything here, so tables created by later migrations reach app_rw.
set -euo pipefail
DUMP=/backups/latest.dump
if [ ! -s "$DUMP" ]; then
  echo "init: no $DUMP — database $POSTGRES_DB is empty; run  make migrate  from the host"
  exit 0
fi
echo "init: restoring $DUMP into $POSTGRES_DB ($(du -h "$DUMP" | cut -f1))"
set +e
pg_restore --no-owner --role="$POSTGRES_USER" -U "$POSTGRES_USER" -d "$POSTGRES_DB" "$DUMP" 2> /tmp/restore.err
rc=$?
set -e
if [ $rc -ne 0 ]; then
  # tolerate only the default-ACL-for-a-foreign-role errors; anything else is fatal
  if grep -v 'role ".*" does not exist' /tmp/restore.err | grep -q 'pg_restore: error'; then
    cat /tmp/restore.err >&2; echo "init: pg_restore failed" >&2; exit 1
  fi
  echo "init: pg_restore finished with $(grep -c 'pg_restore: error' /tmp/restore.err) skipped default-ACL entries for the dump's host role (expected)"
fi
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" <<SQL
ALTER DEFAULT PRIVILEGES FOR ROLE "$POSTGRES_USER" IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_rw;
ALTER DEFAULT PRIVILEGES FOR ROLE "$POSTGRES_USER" IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO app_rw;
SQL
echo "init: restored — $(psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc 'select count(*) from schema_migrations') migrations recorded, default privileges for app_rw set"
