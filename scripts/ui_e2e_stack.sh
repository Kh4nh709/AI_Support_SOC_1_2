#!/usr/bin/env bash
# ui_e2e_stack.sh <scratch_db> — the whole stack the Playwright suite runs against (P10-T12).
#
# One scratch database, the API on 18000, the worker, an LLM stub on 18100 and `vite preview` of the
# production build on 18080 (proxying /api and the /api/ws upgrade to 18000). Every port is 127.0.0.1.
# The script stays in the foreground while the stack is up; Playwright starts it as `webServer` and
# stops it with SIGTERM, and an EXIT trap then stops every child, removes the state directory and
# drops the database. It also cleans up when a step fails.
#
# What it never does:
#   * connect to the live DATABASE_URL, or read it: the scratch database is made on the cluster of
#     TEST_DATABASE_URL (the env, else the .env of this checkout, else the primary checkout's) and its
#     name must match soc_ui_e2e*_test;
#   * print a DSN, a key or a password. The DSN never reaches an argument list (libpq reads PG*), and
#     the secrets of the run (JWT_SECRET, WEBHOOK_API_KEY, the seed passwords) are generated here and
#     handed to the children through their environment and to Playwright through a mode-600 file in
#     a mode-700 directory that the trap removes;
#   * let a provider key reach a child: every child runs under `env -i` with an explicit list, from a
#     neutral directory (so no .env is read either), and the LLM is the stub of scripts/e2e_llm_stub.py.
#
# Environment: PY (the interpreter with the backend's dependencies; default python3),
#              E2E_STATE_DIR (the directory to make for the run's secrets; required, must not exist,
#              its name must start with soc-ui-e2e-), TEST_DATABASE_URL (optional, see above),
#              E2E_BACKEND_DIR (optional: the backend directory to import; default is this checkout's).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

API_PORT=18000
WEB_PORT=18080
LLM_PORT=18100
HOST=127.0.0.1

die() { echo "ui_e2e_stack: $*" >&2; exit 2; }

DB="${1:-}"
[[ "$DB" =~ ^soc_ui_e2e[a-z0-9_]*_test$ ]] \
  || die "the scratch database name must match soc_ui_e2e*_test (got '${DB}')"

PY="${PY:-python3}"
if [[ "$PY" == */* ]]; then PY="$(cd "$(dirname "$PY")" && pwd)/$(basename "$PY")"; fi
command -v "$PY" >/dev/null 2>&1 || die "PY is not runnable: $PY"

# The backend the API and the worker import. It is this checkout's own; a red step of the suite points it at
# a scratch copy with one guard weakened, so the real security code is never edited.
BACKEND_DIR="${E2E_BACKEND_DIR:-$ROOT/backend}"
[ -f "$BACKEND_DIR/app/web/main.py" ] || die "E2E_BACKEND_DIR is not a backend: $BACKEND_DIR"

STATE_DIR="${E2E_STATE_DIR:-}"
[[ "$STATE_DIR" == /* && "$(basename "$STATE_DIR")" == soc-ui-e2e-* ]] \
  || die "E2E_STATE_DIR must be an absolute path whose name starts with soc-ui-e2e-"
[ ! -e "$STATE_DIR" ] || die "E2E_STATE_DIR already exists: refusing to reuse a state directory"

for port in "$API_PORT" "$WEB_PORT" "$LLM_PORT"; do
  if (exec 3<>"/dev/tcp/$HOST/$port") 2>/dev/null; then
    die "port $port is already in use on $HOST"
  fi
done

# ---------------------------------------------------------------- the cluster (never printed)
dsn="${TEST_DATABASE_URL:-}"
read_dsn() {
  [ -f "$1" ] || return 0
  sed -n 's/^[[:space:]]*TEST_DATABASE_URL[[:space:]]*=[[:space:]]*//p' "$1" \
    | sed 's/[[:space:]][[:space:]]*#.*$//' | tail -1 | sed -e "s/^\"\(.*\)\"\$/\1/" -e "s/^'\(.*\)'\$/\1/"
}
if [ -z "$dsn" ]; then dsn="$(read_dsn "$ROOT/.env")"; fi
if [ -z "$dsn" ]; then
  common="$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || true)"
  [ -n "$common" ] && dsn="$(read_dsn "$(dirname "$common")/.env")"
fi
[ -n "$dsn" ] || die "TEST_DATABASE_URL is unset and no .env carries one (the scratch database lives on that cluster)"

# PG* for libpq, through the one routine that reads a DSN (scripts/dsn_env.py); the DSN goes in by
# the environment, never by argv.
pg_exports="$(E2E_SRC_DSN="$dsn" "$PY" -c '
import os, sys
sys.path.insert(0, sys.argv[1])
import dsn_env
raise SystemExit(dsn_env.main(["dsn_env.py", os.environ["E2E_SRC_DSN"]]))
' "$SCRIPT_DIR")"
eval "$pg_exports"
unset pg_exports dsn
export PGHOST PGPORT PGUSER PGPASSWORD

# ---------------------------------------------------------------- the run's secrets
JWT_SECRET="$("$PY" -c 'import secrets; print(secrets.token_hex(32))')"
WEBHOOK_API_KEY="$("$PY" -c 'import secrets; print(secrets.token_hex(24))')"
T1_PASSWORD="$("$PY" -c 'import secrets; print(secrets.token_hex(16))')"
T2_PASSWORD="$("$PY" -c 'import secrets; print(secrets.token_hex(16))')"

pids=()
created_state=0
created_db=0

redact_stream() {
  # stdin -> stdout with every secret of the run masked (a log tail may show one in an error line)
  E2E_R1="$JWT_SECRET" E2E_R2="$WEBHOOK_API_KEY" E2E_R3="$T1_PASSWORD" E2E_R4="$T2_PASSWORD" \
    E2E_R5="${PGPASSWORD:-}" "$PY" -c '
import os, sys
secrets = [os.environ[k] for k in ("E2E_R1", "E2E_R2", "E2E_R3", "E2E_R4", "E2E_R5") if os.environ.get(k)]
for line in sys.stdin:
    for s in secrets:
        line = line.replace(s, "***")
    sys.stdout.write(line)
'
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  if [ "$status" -ne 0 ] && [ "$created_state" = 1 ]; then
    for log in "$STATE_DIR"/logs/*.log; do
      [ -s "$log" ] || continue
      echo "ui_e2e_stack: --- tail of $(basename "$log") ---" >&2
      tail -n 25 "$log" | redact_stream >&2
    done
  fi
  local pid
  for pid in "${pids[@]:-}"; do
    [ -n "$pid" ] && kill -TERM -- "-$pid" 2>/dev/null
    [ -n "$pid" ] && kill -TERM "$pid" 2>/dev/null
  done
  for pid in "${pids[@]:-}"; do
    [ -n "$pid" ] || continue
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.25
    done
    kill -KILL -- "-$pid" 2>/dev/null
    kill -KILL "$pid" 2>/dev/null
  done
  if [ "$created_db" = 1 ]; then
    psql -X -q -d postgres -v ON_ERROR_STOP=1 \
      -c "DROP DATABASE IF EXISTS \"$DB\" WITH (FORCE)" >/dev/null 2>&1 \
      || echo "ui_e2e_stack: could not drop the scratch database $DB" >&2
  fi
  if [ "$created_state" = 1 ]; then rm -rf -- "$STATE_DIR"; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 0' INT TERM

# ---------------------------------------------------------------- the state directory
mkdir -m 700 -- "$STATE_DIR"
created_state=1
mkdir -m 700 -- "$STATE_DIR/logs" "$STATE_DIR/home"

# ---------------------------------------------------------------- the scratch database
PGOPTIONS='-c client_min_messages=warning' \
  psql -X -q -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS \"$DB\" WITH (FORCE)" >/dev/null
psql -X -q -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE \"$DB\"" >/dev/null
created_db=1
MIGRATIONS_DIR="$ROOT/docs/Schema" bash "$ROOT/scripts/migrate.sh" "postgresql:///$DB" \
  >"$STATE_DIR/logs/migrate.log" 2>&1

# ---------------------------------------------------------------- the children's environment
# Nothing else is passed: no provider key, no proxy variable, no .env (children run in the state
# directory, and config.load reads .env from the working directory only).
child_env=(
  env -i
    PATH="$PATH" HOME="$STATE_DIR/home" LANG=C.UTF-8 TZ=UTC \
    PYTHONPATH="$BACKEND_DIR" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    PGHOST="${PGHOST:-}" PGPORT="${PGPORT:-}" PGUSER="${PGUSER:-}" PGPASSWORD="${PGPASSWORD:-}" \
    DATABASE_URL="postgresql:///$DB" DATABASE_URL_OWNER="postgresql:///$DB" \
    TEST_DATABASE_URL="postgresql:///$DB" \
    JWT_SECRET="$JWT_SECRET" WEBHOOK_API_KEY="$WEBHOOK_API_KEY" \
    WEBHOOK_IP_ALLOWLIST='["127.0.0.1"]' \
    LLM_BASE_URL="http://$HOST:$LLM_PORT/v1" LLM_API_KEY="e2e-stub-not-a-key" \
    LLM_MODEL_PROPOSER="e2e-stub-proposer" LLM_MODEL_VERIFIER="e2e-stub-verifier" \
    LLM_TIMEOUT_S=30 LLM_RETRY=1 \
    EVAL_BLIND_FRACTION=0.5 REVIEW_DELTA_TOLERANCE=20
)

start() {
  # start <name> <command...>: a child in its own session, from the state directory, logging there
  local name="$1"; shift
  (cd "$STATE_DIR" && exec setsid "$@" >"$STATE_DIR/logs/$name.log" 2>&1) &
  pids+=("$!")
}

wait_http() {
  # wait_http <name> <url> <pid>: up to 60 s for any HTTP answer, failing at once if the child died
  local name="$1" url="$2" pid="$3" i
  for i in $(seq 1 240); do
    if curl -s -o /dev/null --max-time 2 "$url"; then return 0; fi
    kill -0 "$pid" 2>/dev/null || die "$name exited before it was ready"
    sleep 0.25
  done
  die "$name was not ready in 60 s"
}

# users first: the seed CLI reads each password from SEED_PASSWORD_<USERNAME>, never from argv
(
  cd "$STATE_DIR"
  "${child_env[@]}" SEED_PASSWORD_E2E_T1="$T1_PASSWORD" SEED_PASSWORD_E2E_T2="$T2_PASSWORD" \
    "$PY" -m app.infra.auth seed-users --dsn "postgresql:///$DB" \
    --user e2e-t1 tier1 "E2E Tier 1" --user e2e-t2 tier2 "E2E Tier 2"
) >"$STATE_DIR/logs/seed.log" 2>&1

# the secrets file Playwright's fixtures read (mode 600, in the mode-700 directory)
(
  umask 077
  E2E_WH="$WEBHOOK_API_KEY" E2E_P1="$T1_PASSWORD" E2E_P2="$T2_PASSWORD" \
    E2E_PGH="${PGHOST:-}" E2E_PGP="${PGPORT:-}" E2E_PGU="${PGUSER:-}" E2E_PGW="${PGPASSWORD:-}" \
    E2E_DB="$DB" "$PY" -c '
import json, os, sys
e = os.environ
with open(sys.argv[1], "w") as f:
    json.dump({
        "webhook_key": e["E2E_WH"],
        "t1_password": e["E2E_P1"],
        "t2_password": e["E2E_P2"],
        "pg": {"PGHOST": e["E2E_PGH"], "PGPORT": e["E2E_PGP"], "PGUSER": e["E2E_PGU"],
               "PGPASSWORD": e["E2E_PGW"], "PGDATABASE": e["E2E_DB"]},
    }, f)
' "$STATE_DIR/secrets.json"
)

# ---------------------------------------------------------------- the processes
start llm "${child_env[@]}" "$PY" "$ROOT/scripts/e2e_llm_stub.py" "$LLM_PORT"
wait_http "the LLM stub" "http://$HOST:$LLM_PORT/health" "${pids[-1]}"

start api "${child_env[@]}" "$PY" -m uvicorn app.web.main:app --host "$HOST" --port "$API_PORT" --ws-max-size 65536
wait_http "the API" "http://$HOST:$API_PORT/openapi.json" "${pids[-1]}"

start worker "${child_env[@]}" "$PY" -m app.web.worker

# the production build, served by vite preview with /api (and the ws upgrade) proxied to the API
(cd "$ROOT/frontend" && npm run build >"$STATE_DIR/logs/build.log" 2>&1)
start web env -i PATH="$PATH" HOME="$HOME" LANG=C.UTF-8 \
  bash -c 'cd "$1" && exec node_modules/.bin/vite preview --config e2e/vite.preview.config.ts' _ "$ROOT/frontend"
web_pid="${pids[-1]}"
wait_http "vite preview" "http://$HOST:$WEB_PORT/" "$web_pid"

echo "ui_e2e_stack: ready on http://$HOST:$WEB_PORT (api $API_PORT, llm stub $LLM_PORT, database $DB)"

# stay up until Playwright stops us (SIGTERM) or a child dies
while true; do
  for pid in "${pids[@]}"; do
    kill -0 "$pid" 2>/dev/null || die "a child of the stack exited (pid $pid)"
  done
  sleep 1
done
