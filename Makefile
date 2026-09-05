# AI Support SOC — developer entry points.
#
# Every tool runs from the repository root with an explicit config file
# (DEC-005): pytest, ruff and black all read backend/pyproject.toml, which is
# what makes backend/ the rootdir and `app.*` importable.
#
# `test-db`, `run-app` and `run-worker` need the docker daemon; on this host an
# agent account cannot reach /var/run/docker.sock — see docs/plan/INBOX.md
# (2026-09-05 · P0 / P1 · BLOCKER). No other target depends on the daemon.

PY             ?= python3
PYTEST         ?= $(PY) -m pytest -c backend/pyproject.toml
COMPOSE        ?= docker compose
MIGRATIONS_DIR ?= docs/Schema

# eval/ arrives with P0-T04/P0-T06; lint only what is on disk.
LINT_PATHS := $(wildcard backend eval)

.DEFAULT_GOAL := help
.PHONY: help test test-db lint migrate run-app run-worker backup

help:
	@echo "AI Support SOC — make targets"
	@echo "  test        run the unit tests (excludes db and live markers)"
	@echo "  test-db     start the compose db service and run the db-marked tests"
	@echo "  lint        ruff check + black --check over $(LINT_PATHS)"
	@echo "  migrate     apply docs/Schema migrations to DATABASE_URL_OWNER"
	@echo "  run-app     docker compose up app (FastAPI on :8000)"
	@echo "  run-worker  docker compose up worker (jobs)"
	@echo "  backup      pg_dump --format=custom into backups/"

# pytest exits 5 when it collects nothing. backend/tests/ is empty until
# P0-T03 merges, so 5 is translated into success here and nowhere else.
test:
	@$(PYTEST) -m "not db and not live" backend/tests; rc=$$?; \
	if [ $$rc -eq 5 ]; then echo "no tests collected — ok"; exit 0; fi; exit $$rc

test-db:
	@if ! $(COMPOSE) ps >/dev/null 2>&1; then \
	  echo "test-db: the docker daemon is unreachable — see docs/plan/INBOX.md (2026-09-05 · P0 / P1 · BLOCKER)" >&2; \
	  exit 1; \
	fi
	$(COMPOSE) up -d db
	@cid=$$($(COMPOSE) ps -q db); \
	echo "test-db: waiting up to 60 s for the db healthcheck"; \
	i=0; \
	while [ $$i -lt 60 ]; do \
	  state=$$(docker inspect -f '{{.State.Health.Status}}' "$$cid" 2>/dev/null || echo unknown); \
	  if [ "$$state" = "healthy" ]; then echo "test-db: db healthy after $$i s"; break; fi; \
	  i=$$((i + 1)); sleep 1; \
	done; \
	if [ "$$state" != "healthy" ]; then \
	  echo "test-db: db did not become healthy within 60 s (last state: $$state)" >&2; \
	  exit 1; \
	fi
	$(PYTEST) -m "db and not live" backend/tests

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
	$(COMPOSE) up app

run-worker:
	$(COMPOSE) up worker

backup:
	bash scripts/backup.sh
