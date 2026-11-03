"""Rows the lab tests share (P14-T09): runs written straight into `lab_runs`, so a test of the labels
does not stand on `lab.runs.create_run`, and the clock the windows are laid on."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import psycopg

#: Hour zero of every window the lab tests build; `at(2)` is two hours later.
T0 = datetime(2026, 11, 5, 9, 0, tzinfo=UTC)


def at(hours: float) -> datetime:
    return T0 + timedelta(hours=hours)


def insert_run(
    conn: psycopg.Connection,
    created_by: str,
    *,
    start: float = 0,
    end: float = 4,
    purpose: str = "test",
    name: str | None = None,
) -> str:
    """One `lab_runs` row on `conn` (the caller commits or rolls back); its `run_id`."""
    run_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO lab_runs (run_id, name, purpose, starts_at, ends_at, created_by) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (run_id, name or f"run-{uuid.uuid4().hex[:10]}", purpose, at(start), at(end), created_by),
    )
    return run_id
