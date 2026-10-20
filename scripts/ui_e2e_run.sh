#!/usr/bin/env bash
# ui_e2e_run.sh [playwright args...] — what `make ui-e2e` runs (P10-T12): the Playwright suite on the scratch
# stack, then a scan of everything the run left behind for the run's own secrets.
#
# The run's secrets (the signing key, the webhook key, the passwords of the seeded users, the two seeded admins
# and the account the admin suite creates) are made here and
# handed to the stack and to the fixtures by the environment, so that this script can search for them
# afterwards: in frontend/test-results, in frontend/playwright-report and in the run's own output (captured
# with tee into a private directory that is removed on exit). A DSN, a session token or a Bearer header found
# there fails the target too. The scan (scripts/ui_e2e_scan.py) prints file names only, never a match.
#
# Environment: PY (the interpreter with the backend's dependencies; default python3), E2E_BACKEND_DIR
# (optional, see scripts/ui_e2e_stack.sh; the Makefile passes it only when it was given on the make command line).
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOCK_FILE="/tmp/ui-e2e-stack-$(id -u).lock"

die() { echo "ui_e2e_run: $*" >&2; exit 2; }

PY="${PY:-python3}"
if [[ "$PY" == */* ]]; then PY="$(cd "$(dirname "$PY")" && pwd)/$(basename "$PY")"; fi
command -v "$PY" >/dev/null 2>&1 || die "PY is not runnable: $PY"
export PY

# A second run at the same time would be refused by the stack script's lock, after Playwright has tried to
# start it; ask first, so the message is the first thing on the screen. (The stack script's own flock is the
# authoritative one; this check holds nothing.)
if command -v flock >/dev/null 2>&1; then
  if ! (exec 9>>"$LOCK_FILE" && flock -n 9) 2>/dev/null; then
    die "another ui-e2e run holds $LOCK_FILE: wait for it to finish (nothing was touched)"
  fi
fi

gen() { "$PY" -c 'import secrets, sys; print(secrets.token_hex(int(sys.argv[1])))' "$1"; }
E2E_JWT_SECRET="$(gen 32)"
E2E_WEBHOOK_API_KEY="$(gen 24)"
E2E_T1_PASSWORD="$(gen 16)"
E2E_T2_PASSWORD="$(gen 16)"
E2E_T2B_PASSWORD="$(gen 16)"
E2E_ADMIN_PASSWORD="$(gen 16)"
E2E_ADMIN2_PASSWORD="$(gen 16)"
E2E_NEWUSER_PASSWORD="$(gen 16)"
export E2E_JWT_SECRET E2E_WEBHOOK_API_KEY E2E_T1_PASSWORD E2E_T2_PASSWORD E2E_T2B_PASSWORD \
  E2E_ADMIN_PASSWORD E2E_ADMIN2_PASSWORD E2E_NEWUSER_PASSWORD

# The password of the test cluster, for the scan only (never exported to the run): it is in the stack's
# environment and in a mode-600 file of the run, and a failing helper could print it.
# shellcheck source=scripts/ui_e2e_cluster.sh
. "$SCRIPT_DIR/ui_e2e_cluster.sh"
SCAN_PGPASSWORD="$( (e2e_cluster_env >/dev/null 2>&1 && printf '%s' "${PGPASSWORD:-}") || true)"

OUT="$(mktemp -d "${TMPDIR:-/tmp}/ui-e2e-out.XXXXXX")" || die "could not make a private directory for the run's output"
trap 'rm -rf -- "$OUT"' EXIT

(cd "$ROOT/frontend" && npm run e2e -- "$@") 2>&1 | tee "$OUT/run.log"
status="${PIPESTATUS[0]}"

E2E_SCAN_PGPASSWORD="$SCAN_PGPASSWORD" "$PY" "$SCRIPT_DIR/ui_e2e_scan.py" \
  "$ROOT/frontend/test-results" "$ROOT/frontend/playwright-report" "$OUT/run.log"
scan="$?"
if [ "$scan" -ne 0 ]; then
  echo "ui_e2e_run: the run left a secret behind: the target fails (see the files above)" >&2
  [ "$status" -ne 0 ] || status=1
fi
exit "$status"
