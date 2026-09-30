# Sourced by scripts/ui_e2e_stack.sh and scripts/ui_e2e_run.sh (P10-T12): which cluster the scratch database
# lives on. Needs ROOT, SCRIPT_DIR and PY from the caller.
#
# e2e_cluster_env exports PGHOST PGPORT PGUSER PGPASSWORD of the cluster TEST_DATABASE_URL names (the env, else
# the .env of this checkout, else the primary checkout's). The DSN is only ever held in a shell variable and
# handed to the one routine that reads a DSN (scripts/dsn_env.py) by the environment, never by argv, and it is
# never printed. The live DATABASE_URL is not read.

e2e_read_dsn() {
  [ -f "$1" ] || return 0
  sed -n 's/^[[:space:]]*TEST_DATABASE_URL[[:space:]]*=[[:space:]]*//p' "$1" \
    | sed 's/[[:space:]][[:space:]]*#.*$//' | tail -1 | sed -e "s/^\"\(.*\)\"\$/\1/" -e "s/^'\(.*\)'\$/\1/"
}

e2e_cluster_env() {
  local dsn="${TEST_DATABASE_URL:-}" common pg_exports
  if [ -z "$dsn" ]; then dsn="$(e2e_read_dsn "$ROOT/.env")"; fi
  if [ -z "$dsn" ]; then
    common="$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || true)"
    [ -n "$common" ] && dsn="$(e2e_read_dsn "$(dirname "$common")/.env")"
  fi
  if [ -z "$dsn" ]; then
    echo "ui_e2e: TEST_DATABASE_URL is unset and no .env carries one (the scratch database lives on that cluster)" >&2
    return 1
  fi
  pg_exports="$(E2E_SRC_DSN="$dsn" "$PY" -c '
import os, sys
sys.path.insert(0, sys.argv[1])
import dsn_env
raise SystemExit(dsn_env.main(["dsn_env.py", os.environ["E2E_SRC_DSN"]]))
' "$SCRIPT_DIR")" || return 1
  eval "$pg_exports"
  export PGHOST PGPORT PGUSER PGPASSWORD
}
