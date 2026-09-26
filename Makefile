# AI Support SOC — developer entry points.
#
# Every tool runs from the repository root with an explicit config file
# (DEC-005): pytest, ruff and black all read backend/pyproject.toml, which is
# what makes backend/ the rootdir and `app.*` importable.
#
# SINCE 20/09/2026 THE DATABASE IS THE `db` COMPOSE SERVICE (Owner decision):
# docker-compose.yml runs PostgreSQL 16 on 127.0.0.1:${DB_PORT:-55432} and the
# `app` / `worker` services; `run-app` / `run-worker` start those containers.
# The pure-Python targets (test, lint) still need no daemon; `test-db`,
# `migrate` and `backup` talk to whatever DSN .env names — the container since
# the cutover. The native cluster that served 05–20/09 stays on IA1803 as a
# fallback only (`run-app-native` / `run-worker-native`).

# `python3` on ATTT-M1 is 3.14 with no pytest/ruff (DEC-106); this project's toolchain is the
# .venv of the primary checkout. Resolve it here so every target works unchanged from the
# primary checkout AND from a task worktree (which has no .venv of its own), while still
# falling back to python3 on a host where python3 IS the toolchain. `make <t> PY=...` still wins.
PY             ?= $(firstword $(wildcard .venv/bin/python ../AI_Support_SOC_1_2/.venv/bin/python) python3)
PYTEST         ?= $(PY) -m pytest -c backend/pyproject.toml
TESTS          ?= backend/tests
MIGRATIONS_DIR ?= docs/Schema
APP_HOST       ?= 127.0.0.1
APP_PORT       ?= 8000

# eval/ arrives with P0-T04/P0-T06; lint only what is on disk.
LINT_PATHS := $(wildcard backend eval)

.DEFAULT_GOAL := help
.PHONY: help test test-db lint migrate run-app run-worker run-app-native run-worker-native backup up down db-up db-shell db-restore logs

help:
	@echo "AI Support SOC — make targets"
	@echo "  test        run the unit tests (excludes db and live markers)"
	@echo "  test-db     run the db-marked tests against TEST_DATABASE_URL (TESTS=<path> narrows the run)"
	@echo "  lint        ruff check + black --check over $(LINT_PATHS)"
	@echo "  migrate     apply docs/Schema migrations to DATABASE_URL_OWNER"
	@echo "  up          docker compose up -d (db, app, worker); first db start restores backups/latest.dump"
	@echo "  down        docker compose down (the pgdata volume is kept)"
	@echo "  db-up       start only the db container and wait until it is healthy"
	@echo "  db-shell    psql on DATABASE_URL_OWNER from .env"
	@echo "  db-restore  FILE=backups/x.dump — replace the live database with a dump (stops app+worker)"
	@echo "  logs        docker compose logs -f --tail=100"
	@echo "  run-app     the app container on :$(APP_PORT) (docker compose up -d db app)"
	@echo "  run-worker  the worker container (docker compose up -d db worker)"
	@echo "  run-app-native / run-worker-native   the 05–20/09 way: plain processes on the host"
	@echo "  backup      pg_dump --format=custom into backups/ and refresh backups/latest.dump"

# pytest exits 5 when it collects nothing. backend/tests/ is empty until
# P0-T03 merges, so 5 is translated into success here and nowhere else.
test:
	@$(PYTEST) -m "not db and not live" backend/tests; rc=$$?; \
	if [ $$rc -eq 5 ]; then echo "no tests collected — ok"; exit 0; fi; exit $$rc

# TEST_DATABASE_URL wins from the environment; otherwise the last assignment in
# .env is used. A trailing comment is only stripped when whitespace precedes the
# `#`, so a `#` inside a DSN password survives. The DSN is only ever shown through
# `scripts/dsn_env.py --redact`, the routine conftest.py redacts with: the whole
# password becomes ***, whatever it holds (the sed before it stopped at the first
# `@` and printed the rest — DEC-123). Reachability is checked on the
# server's `postgres` maintenance database: the test database itself is dropped
# and recreated by backend/tests/conftest.py, so it need not exist beforehand.
test-db:
	@dsn="$${TEST_DATABASE_URL:-$$(sed -n 's/^[[:space:]]*TEST_DATABASE_URL[[:space:]]*=[[:space:]]*//p' .env 2>/dev/null | sed 's/[[:space:]][[:space:]]*#.*$$//' | tail -1)}"; \
	if [ -z "$$dsn" ]; then \
	  echo "test-db: TEST_DATABASE_URL is unset and .env carries no value for it." >&2; \
	  echo "test-db: PostgreSQL is native on this host — use TEST_DATABASE_URL=postgresql:///soc_test" >&2; \
	  exit 1; \
	fi; \
	shown="$$($(PY) scripts/dsn_env.py --redact "$$dsn")" || shown="(hidden: dsn_env.py --redact failed)"; \
	if ! psql "$${dsn%/*}/postgres" -tAc 'select 1' >/dev/null 2>&1; then \
	  echo "test-db: TEST_DATABASE_URL is set but its server is unreachable: $$shown" >&2; \
	  echo "test-db: the database itself is (re)created by the tests; the server must be up — make db-up" >&2; \
	  exit 1; \
	fi; \
	echo "test-db: using $$shown"; \
	eval "$$($(PY) scripts/dsn_env.py "$$dsn")"; \
	TEST_DATABASE_URL="$$dsn" $(PYTEST) -m "db and not live" -rs $(TESTS)

# Guarded at parse time, not inside the recipe: an `exit 0` in a recipe line
# only ends that line's shell, it does not stop the target.
ifeq ($(strip $(LINT_PATHS)),)
lint:
	@echo "lint: no path to check"
else
lint:
	$(PY) scripts/gen_env_example.py --check
	$(PY) docs/Schema/build_schema.py --check
	$(PY) scripts/check_output_schemas.py --check
	$(PY) -m ruff check --config backend/pyproject.toml $(LINT_PATHS)
	$(PY) -m black --check --config backend/pyproject.toml $(LINT_PATHS)
endif

migrate:
	MIGRATIONS_DIR=$(MIGRATIONS_DIR) bash scripts/migrate.sh

# The tests that build scratch databases with a bare `createdb` / postgresql:///
# DSN follow PGHOST/PGPORT/PGUSER/PGPASSWORD — exported above from the DSN, so
# they land on the same cluster as TEST_DATABASE_URL (scripts/dsn_env.py).

# --- docker compose --------------------------------------------------------
COMPOSE ?= docker compose

up:
	$(COMPOSE) up -d

down:
	$(COMPOSE) down

db-up:
	$(COMPOSE) up -d --wait db

db-shell:
	@dsn="$$(sed -n 's/^[[:space:]]*DATABASE_URL_OWNER[[:space:]]*=[[:space:]]*//p' .env | sed 's/[[:space:]][[:space:]]*#.*$$//' | tail -1)"; \
	psql "$$dsn"

# Replace the live database with a dump: FILE=backups/soc-<ts>.dump (default latest).
# The real-recovery tool (a rehearsal is scripts/restore.sh): it stops app and worker
# so no connection holds the database open, drops and recreates the database that
# .env's DATABASE_URL_OWNER names, restores the dump into it and restarts them.
# Nothing is stopped or dropped before the dump has been read (pg_restore --list)
# with the pg_restore of the SERVER's major version — PG_LIB/<major>/bin, as
# backup.sh and restore.sh pick it, else PATH's with a warning. On ATTT-M1 PATH has
# PostgreSQL 18 and the server is 16: pg_dump 18's archive is unreadable by
# pg_restore 16, and pg_restore 18 into 16 fails on `SET transaction_timeout`, so
# PATH's binary dropped the live database and restored nothing (P5-T12, DEC-130).
# A pg_restore newer than the server passes --list and still fails there, so it is
# refused too. Exit 2 — a server it cannot ask, a pg_restore newer than the server,
# a dump that binary cannot read — means nothing was stopped or dropped.
db-restore: PG_LIB ?= /usr/lib/postgresql
db-restore:
	@f="$${FILE:-backups/latest.dump}"; [ -s "$$f" ] || { echo "db-restore: no such dump: $$f" >&2; exit 2; }; \
	dsn="$$(sed -n 's/^[[:space:]]*DATABASE_URL_OWNER[[:space:]]*=[[:space:]]*//p' .env | sed 's/[[:space:]][[:space:]]*#.*$$//' | tail -1)"; \
	[ -n "$$dsn" ] || { echo "db-restore: .env names no DATABASE_URL_OWNER — nothing was stopped or dropped" >&2; exit 2; }; \
	db="$${dsn##*/}"; maint="$${dsn%/*}/postgres"; \
	major="$$(psql "$$maint" -XtAc "select current_setting('server_version_num')::int / 10000" 2>/dev/null)"; \
	case "$$major" in ''|*[!0-9]*) echo "db-restore: cannot ask the server DATABASE_URL_OWNER names for its version (is db up?) — nothing was stopped or dropped" >&2; exit 2;; esac; \
	if [ -x "$(PG_LIB)/$$major/bin/pg_restore" ] && [ -x "$(PG_LIB)/$$major/bin/psql" ]; then \
	  pg_restore="$(PG_LIB)/$$major/bin/pg_restore"; psql="$(PG_LIB)/$$major/bin/psql"; \
	else \
	  pg_restore="$$(command -v pg_restore)"; psql="$$(command -v psql)"; \
	  echo "db-restore: warning — no PostgreSQL $$major client under $(PG_LIB); using $$pg_restore, which may be unable to restore into a $$major server" >&2; \
	fi; \
	echo "db-restore: server $$major, $$pg_restore"; \
	have="$$("$$pg_restore" --version 2>/dev/null | sed -nE 's/^pg_restore \(PostgreSQL\) ([0-9]+).*/\1/p')"; \
	if [ -n "$$have" ] && [ "$$have" -gt "$$major" ]; then \
	  echo "db-restore: REFUSED — $$pg_restore is PostgreSQL $$have, the server $$major: a newer pg_restore fails into an older server (SET transaction_timeout, P5-T12); install the $$major client — nothing was stopped or dropped" >&2; exit 2; \
	fi; \
	if ! "$$pg_restore" --list "$$f" >/dev/null; then \
	  echo "db-restore: REFUSED — $$pg_restore cannot read $$f; nothing was stopped or dropped" >&2; exit 2; \
	fi; \
	role="$$(echo "$$dsn" | sed -E 's#^[a-z]+://([^:/@]+).*#\1#')"; \
	stage=stop; $(COMPOSE) stop app worker \
	  && stage=drop && "$$psql" "$$maint" -X -v ON_ERROR_STOP=1 -c "drop database if exists \"$$db\"" -c "create database \"$$db\"" \
	  && stage=restore && "$$pg_restore" --no-owner --role="$$role" --exit-on-error -d "$$dsn" "$$f"; \
	rc=$$?; \
	if [ $$rc -eq 0 ]; then \
	  echo "db-restore: $$f → $$db ($$("$$psql" "$$dsn" -XtAc 'select count(*) from schema_migrations') migrations)"; \
	elif [ "$$stage" = stop ]; then \
	  echo "db-restore: FAILED stopping app and worker (exit $$rc) — nothing was dropped" >&2; \
	else \
	  echo "db-restore: FAILED at $$stage (exit $$rc) — $$db may be missing or partial: read the error above" >&2; \
	fi; \
	$(COMPOSE) up -d app worker || { echo "db-restore: FAILED restarting app and worker" >&2; [ $$rc -ne 0 ] || rc=1; }; \
	exit $$rc

logs:
	$(COMPOSE) logs -f --tail=100

run-app:
	$(COMPOSE) up -d --wait db app

run-worker:
	$(COMPOSE) up -d --wait db worker

# The 05–20/09 way, kept for the fallback cluster: plain processes on the host.
run-app-native:
	PYTHONPATH=backend $(PY) -m uvicorn app.web.main:app --host $(APP_HOST) --port $(APP_PORT)

run-worker-native:
	PYTHONPATH=backend $(PY) -m app.web.worker

backup:
	bash scripts/backup.sh
