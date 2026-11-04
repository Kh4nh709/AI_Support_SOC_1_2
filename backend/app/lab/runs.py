"""The lab runs (P14-T09, DEC-213, spec §6): an attack run of the lab, as the admin records it.

A run is a name, a purpose and a window. The purpose says what the run is for: `kb` builds the knowledge
base, `test` is scored. The window is half-open, `[starts_at, ends_at)`: an alert belongs to the run whose
window holds its `received_at` (`run_of`), so a run may start where another ends and an alert received at
that instant is in the later one only. The database refuses two overlapping windows and a window of no
time (`ex_lab_runs_no_overlap`, `ck_lab_runs_ends_after_starts`); this module checks the same things first
so the admin gets the field and the reason, and maps what the database still refuses.

Every function runs in the caller's transaction: it commits nothing. `create_run` takes a savepoint around
its INSERT and the event, so a refusal leaves the caller's transaction usable, and writes `lab.run_created`
`{run_id, name, purpose}` for the admin after the row is in, in the same savepoint: both land or neither.
"""

from __future__ import annotations

import unicodedata
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import psycopg
from psycopg import errors

from app.audit.events import write_event

#: What a run is for: `kb` builds the knowledge base, `test` is scored.
PURPOSES: tuple[str, ...] = ("kb", "test")
NAME_MAX_CHARS = 80

#: The years an instant of a run may have, in UTC, both ends included. A lab run is a few hours of this
#: decade; the bound is not about meaning but about the driver: an instant valid in UTC near year 1 or 9999 was
#: stored, and then could not be read in a session whose zone moved it out of those years (`DataError`, and so a
#: 500 for the list, for good). No zone moves a time inside 2000..2099 out of the driver's range.
YEAR_MIN = 2000
YEAR_MAX = 2099

#: A name may not hold a control character (`Cc`), a lone surrogate (`Cs`: legal in a Python string,
#: not in UTF-8), or an invisible one that lets one name pass for another in the list and the audit page
#: (`Cf` format characters such as a bidi override, `Zl`, `Zp`). The rule `admin_users` holds a display
#: name to.
_REFUSED_NAME_CATEGORIES = frozenset({"Cc", "Cs", "Cf", "Zl", "Zp"})

_RUN_COLUMNS = "run_id::text, name, purpose, starts_at, ends_at"


class LabError(Exception):
    """Base of every refusal this package raises; `web` maps each to a status."""


class RunOverlap(LabError):
    """The window shares time with another run's (409 `overlap`)."""


class UnknownRun(LabError):
    """No run has this id (404)."""


class InvalidRun(LabError):
    """The input is not a run (422). `field` is the input that is wrong and `reason` why, in the words the
    admin API answers with: `empty`, `too_long`, `invalid`, `taken`, `not_after_starts`."""

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"{field}: {reason}")
        self.field = field
        self.reason = reason


@dataclass(frozen=True)
class LabRun:
    run_id: str
    name: str
    purpose: str
    starts_at: datetime
    ends_at: datetime


@dataclass(frozen=True)
class RunCounts:
    """What a run's list row shows: the queue heads received in its window, and how many of them carry a
    label."""

    total: int
    labelled: int


def _run(row: tuple[Any, ...]) -> LabRun:
    return LabRun(*row)


def _clean_name(value: Any) -> str:
    if not isinstance(value, str):
        raise InvalidRun("name", "invalid")
    name = value.strip()
    if not name:
        raise InvalidRun("name", "empty")
    if len(name) > NAME_MAX_CHARS:
        raise InvalidRun("name", "too_long")
    if any(unicodedata.category(char) in _REFUSED_NAME_CATEGORIES for char in name):
        raise InvalidRun("name", "invalid")
    return name


def utc_instant(field: str, value: Any) -> datetime:
    """A moment is a datetime that says its zone: a naive one would be read in the session's, which is not
    what the admin meant. It is returned in UTC. `InvalidRun(field, "invalid")` for a value that is not a
    zone-aware datetime, for one that has no UTC form (year 0001 at +14:00, year 9999 at -14:00: an overflow
    the driver would turn into a 500), and for one whose UTC year is outside `YEAR_MIN..YEAR_MAX`.
    """
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise InvalidRun(field, "invalid")
    try:
        moment = value.astimezone(UTC)
    except (OverflowError, ValueError):  # an offset that takes it before year 1 or past year 9999
        raise InvalidRun(field, "invalid") from None
    if not YEAR_MIN <= moment.year <= YEAR_MAX:
        raise InvalidRun(field, "invalid")
    return moment


def create_run(
    conn: psycopg.Connection,
    *,
    name: str,
    purpose: str,
    starts_at: datetime,
    ends_at: datetime,
    admin_id: str,
) -> LabRun:
    """Record a run and its `lab.run_created` event. `InvalidRun` for input that is not a run,
    `RunOverlap` when the window shares time with another run's."""
    name = _clean_name(name)
    if not isinstance(purpose, str) or purpose not in PURPOSES:
        raise InvalidRun("purpose", "invalid")
    starts_at = utc_instant("starts_at", starts_at)
    ends_at = utc_instant("ends_at", ends_at)
    if ends_at <= starts_at:
        raise InvalidRun("ends_at", "not_after_starts")

    try:
        # A savepoint: a refusal leaves the caller's transaction usable. The event is written INSIDE it, so the
        # run and its event land together or not at all; on an idle connection this block is the outermost
        # transaction, and an event written after it would find the run already committed.
        with conn.transaction():
            row = conn.execute(
                f"INSERT INTO lab_runs (name, purpose, starts_at, ends_at, created_by) "
                f"VALUES (%s, %s, %s, %s, %s) RETURNING {_RUN_COLUMNS}",
                (name, purpose, starts_at, ends_at, admin_id),
            ).fetchone()
            run = _run(row)
            write_event(
                conn,
                "lab.run_created",
                run.run_id,
                "admin",
                actor_id=admin_id,
                payload={"run_id": run.run_id, "name": run.name, "purpose": run.purpose},
            )
    except errors.ExclusionViolation as exc:
        raise RunOverlap(name) from exc
    except errors.UniqueViolation as exc:
        if exc.diag.constraint_name != "lab_runs_name_key":
            raise
        raise InvalidRun("name", "taken") from exc
    return run


def list_runs(conn: psycopg.Connection) -> list[LabRun]:
    """Every run, the latest window first."""
    rows = conn.execute(
        f"SELECT {_RUN_COLUMNS} FROM lab_runs ORDER BY starts_at DESC, run_id"
    ).fetchall()
    return [_run(row) for row in rows]


def get_run(conn: psycopg.Connection, run_id: str | uuid.UUID) -> LabRun | None:
    """The run with this id, or None (also for text that is no uuid)."""
    try:
        wanted = str(uuid.UUID(str(run_id)))
    except ValueError:
        return None
    row = conn.execute(
        f"SELECT {_RUN_COLUMNS} FROM lab_runs WHERE run_id = %s", (wanted,)
    ).fetchone()
    return None if row is None else _run(row)


def run_of(conn: psycopg.Connection, received_at: datetime) -> LabRun | None:
    """The run whose window `[starts_at, ends_at)` holds `received_at`, or None. At most one run can: the
    windows never overlap."""
    row = conn.execute(
        f"SELECT {_RUN_COLUMNS} FROM lab_runs WHERE starts_at <= %s AND %s < ends_at LIMIT 1",
        (received_at, received_at),
    ).fetchone()
    return None if row is None else _run(row)


def run_counts(conn: psycopg.Connection, run: LabRun) -> RunCounts:
    """The queue heads (`duplicate_of IS NULL`) received in the run's window, and how many carry a label.
    Only heads are counted on both sides: the page lists only heads, so `labelled` never exceeds
    `total`."""
    total, labelled = conn.execute(
        "SELECT"
        " (SELECT count(*) FROM alerts a"
        "   WHERE a.received_at >= %(starts)s AND a.received_at < %(ends)s"
        "     AND a.duplicate_of IS NULL),"
        " (SELECT count(*) FROM lab_labels l JOIN alerts a ON a.alert_id = l.alert_id"
        "   WHERE l.run_id = %(run)s AND a.duplicate_of IS NULL)",
        {"starts": run.starts_at, "ends": run.ends_at, "run": run.run_id},
    ).fetchone()
    return RunCounts(total=total, labelled=labelled)
