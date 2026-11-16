#!/usr/bin/env bash
# ui_e2e_stack.sh soc_ui_e2e_test — the whole stack the Playwright suite runs against (P10-T12).
#
# One scratch database, the API on 18000, the worker, an LLM stub on 18100, a stand-in for n8n's
# `soar-approval` webhook on 18200 (scripts/ui_e2e_n8n.py: the stand-in of scripts/mock_n8n_approval.py, its mode
# read from a file of the state directory at each request, so a spec can make a press fail) and `vite preview` of the
# production build on 18080 (proxying /api and the /api/ws upgrade to 18000). Every port is 127.0.0.1.
# The script stays in the foreground while the stack is up; Playwright starts it as `webServer` and
# stops it with SIGTERM, and an EXIT trap then stops every child, removes the state directory and
# drops the database. It also cleans up when a step fails, and when whoever started it is gone (a runner
# killed with SIGKILL never sends the SIGTERM): the wait loop watches its stdin pipe and its parent.
#
# What it never does:
#   * connect to the live DATABASE_URL, or read it: the scratch database is made on the cluster of
#     TEST_DATABASE_URL (the env, else the .env of this checkout, else the primary checkout's, see
#     scripts/ui_e2e_cluster.sh) and its name is exactly soc_ui_e2e_test;
#   * print a DSN, a key or a password, or put one in an argument list (/proc/<pid>/cmdline is world
#     readable). The DSN never reaches an argument list (libpq reads PG*); the secrets of the run
#     (JWT_SECRET, WEBHOOK_API_KEY, the seed passwords) reach the children through a mode-600 env file in
#     the mode-700 state directory that each child reads under `env -i`, and reach Playwright through a
#     mode-600 file in the same directory. The trap removes the directory;
#   * let a provider key reach a child: every child runs under `env -i` with the file's list only, from a
#     neutral directory (so no .env is read either), and the LLM is the stub of scripts/e2e_llm_stub.py.
#
# The scratch repository (P11-T18). The API and the worker do not import the checkout's backend/ itself but a
# copy of its app/ made in the state directory (repo/backend/app, with a copy of kb/ and an empty repo/eval/
# beside it). The blind labelling page reads its candidates file and the gold set's freeze marker from the eval/
# of the repository its code sits in (tier1/labels.py: parents[3]), so the copy reads the scratch eval/, never
# the real one: the suite can write a candidates file and a freeze marker there and the real gold set is
# neither read nor written. The trap removes the directory with the rest of the state.
#
# One run at a time: an exclusive flock on /tmp/ui-e2e-stack-<uid>.lock is held for the whole run (a second
# run fails at once instead of dropping the first run's database).
#
# Environment: PY (the interpreter with the backend's dependencies; default python3),
#              E2E_STATE_DIR (the directory to make for the run's secrets; required, must not exist,
#              its name must start with soc-ui-e2e-), TEST_DATABASE_URL (optional, see above),
#              E2E_JWT_SECRET, E2E_WEBHOOK_API_KEY, E2E_T1_PASSWORD, E2E_T2_PASSWORD, E2E_T2B_PASSWORD,
#              E2E_ADMIN_PASSWORD, E2E_ADMIN2_PASSWORD (the two seeded admins), E2E_NEWUSER_PASSWORD (the
#              password the admin suite types for the account it creates), E2E_SOAR_NOTICE_API_KEY (the key of
#              `POST /webhook/soar-notices`) and E2E_N8N_APPROVAL_SECRET (the secret the web sends to the stand-in of n8n)
#              (optional, at least 16 characters: scripts/ui_e2e_run.sh generates them so that it can scan the
#              run's output for them; generated here when unset),
#              E2E_BACKEND_DIR (optional: the backend directory whose app/ is copied into the scratch repository
#              and imported; default is this checkout's; a red step of the suite points it at a scratch copy).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

API_PORT=18000
WEB_PORT=18080
LLM_PORT=18100
N8N_PORT=18200
HOST=127.0.0.1
LOCK_FILE="/tmp/ui-e2e-stack-$(id -u).lock"

die() { echo "ui_e2e_stack: $*" >&2; exit 2; }

DB="${1:-}"
[ "$DB" = soc_ui_e2e_test ] || die "the scratch database name must be exactly soc_ui_e2e_test (got '${DB}')"

PY="${PY:-python3}"
if [[ "$PY" == */* ]]; then PY="$(cd "$(dirname "$PY")" && pwd)/$(basename "$PY")"; fi
command -v "$PY" >/dev/null 2>&1 || die "PY is not runnable: $PY"

# The backend whose app/ the API and the worker run. It is this checkout's own; a red step of the suite points it
# at a scratch copy with one guard weakened, so the real security code is never edited. What runs is always a copy
# of its app/ in the state directory (see the scratch repository above), made once the state directory exists.
BACKEND_SRC="${E2E_BACKEND_DIR:-$ROOT/backend}"
[ -f "$BACKEND_SRC/app/web/main.py" ] || die "E2E_BACKEND_DIR is not a backend: $BACKEND_SRC"
BACKEND_SRC="$(cd "$BACKEND_SRC" && pwd -P)"
if [ "$BACKEND_SRC" != "$(cd "$ROOT/backend" && pwd -P)" ]; then
  echo "ui_e2e_stack: WARNING: the API and the worker run a copy of $BACKEND_SRC/app, not of this checkout's backend/app" >&2
fi

STATE_DIR="${E2E_STATE_DIR:-}"
[[ "$STATE_DIR" == /* && "$(basename "$STATE_DIR")" == soc-ui-e2e-* ]] \
  || die "E2E_STATE_DIR must be an absolute path whose name starts with soc-ui-e2e-"
[ ! -e "$STATE_DIR" ] || die "E2E_STATE_DIR already exists: refusing to reuse a state directory"

# One run at a time. The lock lives as long as this shell does (and as long as any child that inherited the
# descriptor: an orphaned stack keeps a second run out until it is gone). Appending never truncates a file
# a symlink in /tmp might point at.
command -v flock >/dev/null 2>&1 || die "flock (util-linux) is required"
exec 9>>"$LOCK_FILE"
flock -n 9 || die "another ui-e2e run holds $LOCK_FILE: wait for it to finish (nothing was touched)"

for port in "$API_PORT" "$WEB_PORT" "$LLM_PORT" "$N8N_PORT"; do
  if (exec 3<>"/dev/tcp/$HOST/$port") 2>/dev/null; then
    die "port $port is already in use on $HOST"
  fi
done

# ---------------------------------------------------------------- the cluster (never printed)
# shellcheck source=scripts/ui_e2e_cluster.sh
. "$SCRIPT_DIR/ui_e2e_cluster.sh"
e2e_cluster_env || exit 2

# ---------------------------------------------------------------- the run's secrets
gen() { "$PY" -c 'import secrets, sys; print(secrets.token_hex(int(sys.argv[1])))' "$1"; }
given_or_generated() {
  # given_or_generated <value from the environment> <bytes>: a value the caller made must be long enough
  if [ -z "$1" ]; then gen "$2"; return; fi
  [ "${#1}" -ge 16 ] || die "a secret given in the environment is shorter than 16 characters"
  printf '%s\n' "$1"
}
JWT_SECRET="$(given_or_generated "${E2E_JWT_SECRET:-}" 32)"
WEBHOOK_API_KEY="$(given_or_generated "${E2E_WEBHOOK_API_KEY:-}" 24)"
T1_PASSWORD="$(given_or_generated "${E2E_T1_PASSWORD:-}" 16)"
T2_PASSWORD="$(given_or_generated "${E2E_T2_PASSWORD:-}" 16)"
T2B_PASSWORD="$(given_or_generated "${E2E_T2B_PASSWORD:-}" 16)"
ADMIN_PASSWORD="$(given_or_generated "${E2E_ADMIN_PASSWORD:-}" 16)"
ADMIN2_PASSWORD="$(given_or_generated "${E2E_ADMIN2_PASSWORD:-}" 16)"
NEWUSER_PASSWORD="$(given_or_generated "${E2E_NEWUSER_PASSWORD:-}" 16)"
SOAR_NOTICE_API_KEY="$(given_or_generated "${E2E_SOAR_NOTICE_API_KEY:-}" 24)"
N8N_APPROVAL_SECRET="$(given_or_generated "${E2E_N8N_APPROVAL_SECRET:-}" 24)"

pids=()
created_state=0
created_db=0

redact_stream() {
  # stdin -> stdout with every secret of the run masked (a log tail may show one in an error line)
  E2E_R1="$JWT_SECRET" E2E_R2="$WEBHOOK_API_KEY" E2E_R3="$T1_PASSWORD" E2E_R4="$T2_PASSWORD" \
    E2E_R5="${PGPASSWORD:-}" E2E_R6="$T2B_PASSWORD" E2E_R7="$ADMIN_PASSWORD" E2E_R8="$ADMIN2_PASSWORD" \
    E2E_R9="$NEWUSER_PASSWORD" E2E_R10="$SOAR_NOTICE_API_KEY" E2E_R11="$N8N_APPROVAL_SECRET" "$PY" -c '
import os, sys
secrets = [os.environ[k] for k in ("E2E_R1", "E2E_R2", "E2E_R3", "E2E_R4", "E2E_R5", "E2E_R6", "E2E_R7", "E2E_R8", "E2E_R9", "E2E_R10", "E2E_R11") if os.environ.get(k)]
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
      sleep 0.1
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

# ---------------------------------------------------------------- the watchdog
# Playwright stops the stack with SIGTERM, but a runner that dies otherwise (SIGKILL, the OOM killer) sends
# nothing, and the children are in sessions of their own. So every wait of this script goes through `tick`,
# which ends the run (the EXIT trap then does the whole cleanup) when
#   * stdin is a pipe or a socket (Node hands a child a socket for stdio "pipe") and it reaches end of file:
#     the runner, the only writer, has exited; or
#   * the parent process is no longer the one that started this script.
# A stdin that is neither (a terminal, /dev/null) is not watched: only the parent is.
STDIN_IS_PIPE=0
if [ -p /dev/stdin ] || [ -S /dev/stdin ]; then STDIN_IS_PIPE=1; fi
ppid_now() { awk '/^PPid:/ { print $2 }' "/proc/$$/status"; }
ORIG_PPID="$(ppid_now)"

tick() {
  # tick <seconds>: waits up to that long, or ends the run at once when the runner is gone
  local rc=0
  if [ "$STDIN_IS_PIPE" = 1 ]; then
    IFS= read -r -t "$1" _ || rc=$?
    if [ "$rc" -eq 1 ]; then
      echo "ui_e2e_stack: stdin was closed, the runner is gone: cleaning up" >&2
      exit 0
    fi
  else
    sleep "$1"
  fi
  if [ "$(ppid_now)" != "$ORIG_PPID" ]; then
    echo "ui_e2e_stack: the parent process is gone: cleaning up" >&2
    exit 0
  fi
}

# ---------------------------------------------------------------- the state directory
mkdir -m 700 -- "$STATE_DIR"
created_state=1
mkdir -m 700 -- "$STATE_DIR/logs" "$STATE_DIR/home"

# The scratch repository: a copy of the backend's app/ and of kb/, and an empty eval/ (see the header).
REPO_DIR="$STATE_DIR/repo"
mkdir -m 700 -- "$REPO_DIR" "$REPO_DIR/backend" "$REPO_DIR/eval"
cp -R -- "$BACKEND_SRC/app" "$REPO_DIR/backend/app"
find "$REPO_DIR/backend/app" -type d -name __pycache__ -prune -exec rm -rf -- {} +
# What runs must be what was asked for: a copy that differs from its source (a file the copy missed, a symlink it
# followed) would make every green of the suite a statement about some other code.
diff -rq -x __pycache__ "$BACKEND_SRC/app" "$REPO_DIR/backend/app" >/dev/null \
  || die "the scratch copy of app/ is not the same as $BACKEND_SRC/app: refusing to start the stack"
cp -R -- "$ROOT/kb" "$REPO_DIR/kb"
BACKEND_DIR="$REPO_DIR/backend"

# ---------------------------------------------------------------- the scratch database
PGOPTIONS='-c client_min_messages=warning' \
  psql -X -q -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS \"$DB\" WITH (FORCE)" >/dev/null
psql -X -q -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE \"$DB\"" >/dev/null
created_db=1
MIGRATIONS_DIR="$ROOT/docs/Schema" bash "$ROOT/scripts/migrate.sh" "postgresql:///$DB" \
  >"$STATE_DIR/logs/migrate.log" 2>&1

# ---------------------------------------------------------------- the children's environment
# A child's environment is read from a mode-600 file in the state directory, under `env -i`, so no secret is
# ever in an argument list. write_env_file is all shell builtins: a value is never in one either. Nothing
# else is passed: no provider key, no proxy variable, no .env (children run in the state directory, and
# config.load reads .env from the working directory only).
write_env_file() {
  # write_env_file <file> NAME=value...: appends `export NAME=value` lines, quoted for the shell
  local file="$1" pair
  shift
  (
    umask 077
    for pair in "$@"; do printf 'export %s=%q\n' "${pair%%=*}" "${pair#*=}" >>"$file"; done
  )
}

write_env_file "$STATE_DIR/child.env" \
  PATH="$PATH" HOME="$STATE_DIR/home" LANG=C.UTF-8 TZ=UTC \
  PYTHONPATH="$BACKEND_DIR" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
  PGHOST="${PGHOST:-}" PGPORT="${PGPORT:-}" PGUSER="${PGUSER:-}" PGPASSWORD="${PGPASSWORD:-}" \
  DATABASE_URL="postgresql:///$DB" DATABASE_URL_OWNER="postgresql:///$DB" \
  TEST_DATABASE_URL="postgresql:///$DB" \
  JWT_SECRET="$JWT_SECRET" WEBHOOK_API_KEY="$WEBHOOK_API_KEY" \
  WEBHOOK_IP_ALLOWLIST='["127.0.0.1"]' \
  SOAR_NOTICE_API_KEY="$SOAR_NOTICE_API_KEY" SOAR_NOTICE_IP_ALLOWLIST='["127.0.0.1"]' \
  N8N_APPROVAL_SECRET="$N8N_APPROVAL_SECRET" \
  N8N_APPROVAL_URL="http://$HOST:$N8N_PORT/webhook/soar-approval" N8N_APPROVAL_TIMEOUT_SECONDS=10 \
  LLM_BASE_URL="http://$HOST:$LLM_PORT/v1" LLM_API_KEY="e2e-stub-not-a-key" \
  LLM_MODEL_PROPOSER="e2e-stub-proposer" LLM_MODEL_VERIFIER="e2e-stub-verifier" \
  LLM_TIMEOUT_S=30 LLM_RETRY=1 \
  EVAL_BLIND_FRACTION=0.5 REVIEW_DELTA_TOLERANCE=20
# the seed CLI reads each password from SEED_PASSWORD_<USERNAME> (- as _), never from argv
(umask 077 && cp -- "$STATE_DIR/child.env" "$STATE_DIR/seed.env")
write_env_file "$STATE_DIR/seed.env" \
  SEED_PASSWORD_E2E_T1="$T1_PASSWORD" SEED_PASSWORD_E2E_T2="$T2_PASSWORD" \
  SEED_PASSWORD_E2E_T2B="$T2B_PASSWORD" SEED_PASSWORD_E2E_ADMIN="$ADMIN_PASSWORD" \
  SEED_PASSWORD_E2E_ADMIN2="$ADMIN2_PASSWORD"
# vite preview needs no secret and no database
write_env_file "$STATE_DIR/web.env" PATH="$PATH" HOME="$HOME" LANG=C.UTF-8
# The stand-in of n8n: the secret the web must send, and the file its mode is read from (a spec writes `ok`, `fail` or
# `conflict` into it; the stand-in reads it at every request). It starts as `ok`.
(umask 077 && printf 'ok\n' >"$STATE_DIR/n8n.mode")
write_env_file "$STATE_DIR/n8n.env" PATH="$PATH" HOME="$STATE_DIR/home" LANG=C.UTF-8 PYTHONUNBUFFERED=1 \
  N8N_APPROVAL_SECRET="$N8N_APPROVAL_SECRET" E2E_N8N_MODE_FILE="$STATE_DIR/n8n.mode"

CLEAN_SHELL='. "$1"; shift; exec "$@"'

start() {
  # start <name> <envfile> <command...>: a child in its own session, from the state directory, under
  # `env -i` with the file's environment, logging there. stdin is /dev/null: a child never reads the pipe
  # the watchdog reads.
  local name="$1" envfile="$2"
  shift 2
  (cd "$STATE_DIR" && exec setsid env -i "$BASH" -c "$CLEAN_SHELL" _ "$envfile" "$@" \
    </dev/null >"$STATE_DIR/logs/$name.log" 2>&1) &
  pids+=("$!")
}

wait_http() {
  # wait_http <name> <url> <pid>: up to 60 s for any HTTP answer, failing at once if the child died
  local name="$1" url="$2" pid="$3" i
  for i in $(seq 1 240); do
    if curl -s -o /dev/null --max-time 2 "$url"; then return 0; fi
    kill -0 "$pid" 2>/dev/null || die "$name exited before it was ready"
    tick 0.25
  done
  die "$name was not ready in 60 s"
}

# users first
(
  cd "$STATE_DIR"
  env -i "$BASH" -c "$CLEAN_SHELL" _ "$STATE_DIR/seed.env" \
    "$PY" -m app.infra.auth seed-users --dsn "postgresql:///$DB" \
    --user e2e-t1 tier1 "E2E Tier 1" --user e2e-t2 tier2 "E2E Tier 2" \
    --user e2e-t2b tier2 "E2E Tier 2 B" \
    --user e2e-admin admin "E2E Admin" --user e2e-admin2 admin "E2E Admin 2"
) >"$STATE_DIR/logs/seed.log" 2>&1
rm -f -- "$STATE_DIR/seed.env"

# the secrets file Playwright's fixtures read (mode 600, in the mode-700 directory)
(
  umask 077
  E2E_WH="$WEBHOOK_API_KEY" E2E_SN="$SOAR_NOTICE_API_KEY" E2E_P1="$T1_PASSWORD" E2E_P2="$T2_PASSWORD" E2E_P3="$T2B_PASSWORD" \
    E2E_P4="$ADMIN_PASSWORD" E2E_P5="$ADMIN2_PASSWORD" E2E_P6="$NEWUSER_PASSWORD" \
    E2E_PGH="${PGHOST:-}" E2E_PGP="${PGPORT:-}" E2E_PGU="${PGUSER:-}" E2E_PGW="${PGPASSWORD:-}" \
    E2E_DB="$DB" "$PY" -c '
import json, os, sys
e = os.environ
with open(sys.argv[1], "w") as f:
    json.dump({
        "webhook_key": e["E2E_WH"],
        "soar_notice_key": e["E2E_SN"],
        "t1_password": e["E2E_P1"],
        "t2_password": e["E2E_P2"],
        "t2b_password": e["E2E_P3"],
        "admin_password": e["E2E_P4"],
        "admin2_password": e["E2E_P5"],
        "new_password": e["E2E_P6"],
        "pg": {"PGHOST": e["E2E_PGH"], "PGPORT": e["E2E_PGP"], "PGUSER": e["E2E_PGU"],
               "PGPASSWORD": e["E2E_PGW"], "PGDATABASE": e["E2E_DB"]},
    }, f)
' "$STATE_DIR/secrets.json"
)

# ---------------------------------------------------------------- the processes
start llm "$STATE_DIR/child.env" "$PY" "$ROOT/scripts/e2e_llm_stub.py" "$LLM_PORT"
wait_http "the LLM stub" "http://$HOST:$LLM_PORT/health" "${pids[-1]}"

start n8n "$STATE_DIR/n8n.env" "$PY" "$ROOT/scripts/ui_e2e_n8n.py" "$N8N_PORT"
wait_http "the n8n stand-in" "http://$HOST:$N8N_PORT/" "${pids[-1]}"

start api "$STATE_DIR/child.env" "$PY" -m uvicorn app.web.main:app --host "$HOST" --port "$API_PORT" --ws-max-size 65536
wait_http "the API" "http://$HOST:$API_PORT/openapi.json" "${pids[-1]}"

start worker "$STATE_DIR/child.env" "$PY" -m app.web.worker

# the production build, served by vite preview with /api (and the ws upgrade) proxied to the API. The build
# runs in the background so that the watchdog is not blind for its length.
(cd "$ROOT/frontend" && exec setsid npm run build </dev/null >"$STATE_DIR/logs/build.log" 2>&1) &
build_pid=$!
pids+=("$build_pid")
while kill -0 "$build_pid" 2>/dev/null; do tick 0.5; done
wait "$build_pid" || die "the UI build failed"
unset 'pids[-1]'

start web "$STATE_DIR/web.env" \
  bash -c 'cd "$1" && exec node_modules/.bin/vite preview --config e2e/vite.preview.config.ts' _ "$ROOT/frontend"
web_pid="${pids[-1]}"
wait_http "vite preview" "http://$HOST:$WEB_PORT/" "$web_pid"

echo "ui_e2e_stack: ready on http://$HOST:$WEB_PORT (api $API_PORT, llm stub $LLM_PORT, n8n stand-in $N8N_PORT, backend $BACKEND_SRC, database $DB)"

# stay up until Playwright stops us (SIGTERM), the runner is gone, or a child dies
while true; do
  for pid in "${pids[@]}"; do
    kill -0 "$pid" 2>/dev/null || die "a child of the stack exited (pid $pid)"
  done
  tick 0.5
done
