"""INT-T03 fix round 1 / DEC-212 - the runbook's "Archiving the old queue" section, step 1.

The section says a queued `triage`, `rag_lookup` or `investigate` job for an archived subject "is skipped
when it runs". That is only true of a process that loads the new code, and `rag/lookup.py` runs in
`rag-worker` when the second compose file is in use (DEC-210), so step 1 must restart it too. Migration 021
takes an exclusive lock on `alerts`, so the workers are stopped while `make migrate` runs: a worker
transaction left open across a model call would make it wait.
"""

from __future__ import annotations

from tests import conftest

SECTION = "## Archiving the old queue (DEC-212)"


def _step_1() -> str:
    text = (conftest.REPO_ROOT / "docs" / "runbook.md").read_text(encoding="utf-8")
    section = text.split(SECTION, 1)[1].split("\n## ", 1)[0]
    row = next(line for line in section.splitlines() if line.startswith("| 1 · migrate |"))
    return " ".join(row.replace("`", "").split())


def test_step_1_stops_both_workers_before_the_migration_and_says_why():
    row = _step_1()
    migrate = row.index("make migrate")
    stop_worker = row.index("docker compose stop worker")
    stop_rag = row.index("docker compose stop rag-worker")
    assert stop_worker < migrate and stop_rag < migrate
    assert "exclusive lock on alerts" in row


def test_step_1_restarts_rag_worker_as_well_as_app_and_worker_after_the_migration():
    row = _step_1()
    migrate = row.index("make migrate")
    restart_app_worker = row.index("docker compose restart app worker")
    restart_rag = row.index("docker compose restart rag-worker")
    assert migrate < restart_app_worker and migrate < restart_rag


def test_step_1_names_the_second_compose_file_for_rag_worker_only():
    """`rag-worker` is no service without the override: its stop and its restart are conditional."""
    row = _step_1()
    for command in ("docker compose stop rag-worker", "docker compose restart rag-worker"):
        around = row[max(0, row.index(command) - 120) : row.index(command) + len(command) + 120]
        assert "second compose file" in around, command
