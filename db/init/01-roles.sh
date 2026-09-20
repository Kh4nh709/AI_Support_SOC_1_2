#!/usr/bin/env bash
# First-start init (docker-entrypoint-initdb.d runs only when pgdata is empty).
# Creates the application login role BEFORE 02-restore.sh, so the ACLs inside
# backups/latest.dump (GRANT ... TO app_rw, migration 017) have their grantee.
# The password comes from the Compose-only variable APP_RW_PASSWORD (DEC-003);
# migration 017 would otherwise create app_rw NOLOGIN and the app could not log in.
set -euo pipefail
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_rw') THEN
    CREATE ROLE app_rw LOGIN PASSWORD '${APP_RW_PASSWORD}';
  ELSE
    ALTER ROLE app_rw LOGIN PASSWORD '${APP_RW_PASSWORD}';
  END IF;
END
\$\$;
SQL
echo "init: role app_rw ready (LOGIN)"
