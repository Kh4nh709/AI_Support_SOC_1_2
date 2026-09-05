# AI Support SOC — developer entry points.
#
# Every tool runs from the repository root with an explicit config file
# (DEC-005): pytest, ruff and black all read backend/pyproject.toml, which is
# what makes backend/ the rootdir and `app.*` importable.
#
# NO TARGET REQUIRES DOCKER. PostgreSQL runs natively on this host and the
# application and worker run as ordinary processes. docker-compose.yml is kept
# as a portable alternative for a machine that has a working daemon; nothing in
# this file depends on it. Owner decision, 05/09/2026.

PY             ?= python3
PYTEST         ?= $(PY) -m pytest -c backend/pyproject.toml
TESTS          ?= backend/tests
MIGRATIONS_DIR ?= docs/Schema
APP_HOST       ?= 127.0.0.1
APP_PORT       ?= 8000

# eval/ arrives with P0-T04/P0-T06; lint only what is on disk.
LINT_PATHS := $(wildcard backend eval)

.DEFAULT_GOAL := help
.PHONY: help test test-db lint migrate run-app run-worker backup

help:
	@echo "AI Support SOC — make targets"
	@echo "  test        run the unit tests (excludes db and live markers)"
	@echo "  test-db     run the db-marked tests against TEST_DATABASE_URL (TESTS=<path> narrows the run)"
	@echo "  lint        ruff check + black --check over $(LINT_PATHS)"
	@echo "  migrate     apply docs/Schema migrations to DATABASE_URL_OWNER"
	@echo "  run-app     uvicorn on $(APP_HOST):$(APP_PORT)"
	@echo "  run-worker  the job worker as a local process"
	@echo "  backup      pg_dump --format=custom into backups/"

# pytest exits 5 when it collects nothing. backend/tests/ is empty until
# P0-T03 merges, so 5 is translated into success here and nowhere else.
test:
	@$(PYTEST) -m "not db and not live" backend/tests; rc=$$?; \
	if [ $$rc -eq 5 ]; then echo "no tests collected — ok"; exit 0; fi; exit $$rc

# TEST_DATABASE_URL wins from the environment; otherwise the last assignment in
# .env is used. A trailing comment is only stripped when whitespace precedes the
# `#`, so a `#` inside a DSN password survives.
test-db:
	@dsn="$${TEST_DATABASE_URL:-$$(sed -n 's/^[[:space:]]*TEST_DATABASE_URL[[:space:]]*=[[:space:]]*//p' .env 2>/dev/null | sed 's/[[:space:]][[:space:]]*#.*$$//' | tail -1)}"; \
	if [ -z "$$dsn" ]; then \
	  echo "test-db: TEST_DATABASE_URL is unset and .env carries no value for it." >&2; \
	  echo "test-db: PostgreSQL is native on this host — use TEST_DATABASE_URL=postgresql:///soc_test" >&2; \
	  exit 1; \
	fi; \
	if ! psql "$$dsn" -tAc 'select 1' >/dev/null 2>&1; then \
	  echo "test-db: TEST_DATABASE_URL is set but unreachable: $$dsn" >&2; \
	  echo "test-db: create it with  createdb $${dsn##*/}" >&2; \
	  exit 1; \
	fi; \
	echo "test-db: using $$dsn"; \
	TEST_DATABASE_URL="$$dsn" $(PYTEST) -m "db and not live" -rs $(TESTS)

# Guarded at parse time, not inside the recipe: an `exit 0` in a recipe line
# only ends that line's shell, it does not stop the target.
ifeq ($(strip $(LINT_PATHS)),)
lint:
	@echo "lint: no path to check"
else
lint:
	$(PY) -m ruff check --config backend/pyproject.toml $(LINT_PATHS)
	$(PY) -m black --check --config backend/pyproject.toml $(LINT_PATHS)
endif

migrate:
	MIGRATIONS_DIR=$(MIGRATIONS_DIR) bash scripts/migrate.sh

run-app:
	PYTHONPATH=backend $(PY) -m uvicorn app.web.main:app --host $(APP_HOST) --port $(APP_PORT)

run-worker:
	PYTHONPATH=backend $(PY) -m app.infra.worker

backup:
	bash scripts/backup.sh
