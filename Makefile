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
# `#`, so a `#` inside a DSN password survives. Reachability is checked on the
# server's `postgres` maintenance database: the test database itself is dropped
# and recreated by backend/tests/conftest.py, so it need not exist beforehand.
test-db:
	@dsn="$${TEST_DATABASE_URL:-$$(sed -n 's/^[[:space:]]*TEST_DATABASE_URL[[:space:]]*=[[:space:]]*//p' .env 2>/dev/null | sed 's/[[:space:]][[:space:]]*#.*$$//' | tail -1)}"; \
	if [ -z "$$dsn" ]; then \
	  echo "test-db: TEST_DATABASE_URL is unset and .env carries no value for it." >&2; \
	  echo "test-db: PostgreSQL is native on this host — use TEST_DATABASE_URL=postgresql:///soc_test" >&2; \
	  exit 1; \
	fi; \
	shown="$$(printf '%s' "$$dsn" | sed -E 's#://([^:/@]+):[^@]*@#://\1:***@#')"; \
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
# Stops app and worker first so no connection holds the database open.
db-restore:
	@f="$${FILE:-backups/latest.dump}"; [ -s "$$f" ] || { echo "db-restore: no such dump: $$f" >&2; exit 2; }; \
	dsn="$$(sed -n 's/^[[:space:]]*DATABASE_URL_OWNER[[:space:]]*=[[:space:]]*//p' .env | sed 's/[[:space:]][[:space:]]*#.*$$//' | tail -1)"; \
	db="$${dsn##*/}"; maint="$${dsn%/*}/postgres"; \
	$(COMPOSE) stop app worker; \
	psql "$$maint" -v ON_ERROR_STOP=1 -c "drop database if exists \"$$db\"" -c "create database \"$$db\""; \
	pg_restore --no-owner --role="$$(echo "$$dsn" | sed -E 's#^[a-z]+://([^:/@]+).*#\1#')" --exit-on-error -d "$$dsn" "$$f"; \
	echo "db-restore: $$f → $$db ($$(psql "$$dsn" -tAc 'select count(*) from schema_migrations') migrations)"; \
	$(COMPOSE) up -d app worker

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
