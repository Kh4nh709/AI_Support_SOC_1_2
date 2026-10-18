"""tier2/conclude.py — the guarded layer over `domain.transitions.conclude_case`
(P5-T06 card), plus `case_notes` (`add_note`, `list_notes`).

`submit()` is a guard, a call and a translation — not a second implementation
(design note 1): it validates `conclusion` and `reason` before any SQL, sets
the 5 s statement timeout `docs/phase-7-tier2.md` §Kết luận detail 3 asks for
(longer than Tier-1's 3 s, because this `UPDATE` touches every alert in the
case — heads and duplicates both), then calls `domain.transitions.conclude_case`
and translates its `StaleState` into `ConcludeConflict`, reading the case's
current status — and, when it is already concluded, who and when — *inside*
the still-open transaction before raising (the read tier1/decide.py's
`DecisionConflict` is described as doing; nothing here was meant to persist,
so the rollback that follows it is correct). `transitions.IllegalTransition`
and a statement-timeout `psycopg.errors.QueryCanceled` are left to propagate
unmodified — `web/routers/tier2.py` maps every one of the three directly
(409/500/503). G2 holds throughout: this module issues no
`UPDATE (alerts|cases) SET`.

Notes are not decisions: `add_note`/`list_notes` read and write `case_notes`
directly and write no audit event — a "note added" name is not one of the 27
`ck_audit_event_type` fixes, and adding one would be a frozen-contract change
(design note 2; P5-tasks.md planning decision 4's sibling). The note itself
is the record, in an append-only-by-convention table.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime
from typing import Any

import psycopg
from psycopg import sql

from app.domain import transitions

#: `docs/phase-7-tier2.md` §Kết luận detail 3 — longer than Tier-1's 3 s
#: because this `UPDATE` touches every alert in the case, heads and
#: duplicates both.
STATEMENT_TIMEOUT = "5s"

#: The only three conclusions `domain.transitions.conclude_case` accepts.
#: Not imported from there — `_CONCLUSION_TO_ALERT_STATUS` is private to
#: `domain/transitions.py`, a file this card does not open (scope out).
CONCLUSIONS = frozenset({"concluded_fp", "concluded_policy_violation", "confirmed_incident"})

#: A note is a short analyst comment, not a second dossier — capped so one
#: field cannot grow into the free-text block the ② dossier (P5-T03) later
#: wraps whole. Not a §6.3 key: this is an application-level guard on a
#: column the schema leaves `text` with no length CHECK.
NOTE_BODY_MAX_BYTES = 4000

#: The conclusion's reason, stripped, is 1-500 characters: the bound Tier-1's decision reason
#: has (`tier1/decide.py`, `decide`/`reopen`) and the same message, so the route's 422 is the
#: one the Tier-1 routes give (a string `detail`). The column is `text` with no CHECK, and the
#: reason is also copied into the `tier2.concluded` event's payload (P11-T20 row 12).
REASON_MAX_CHARS = 500


class ConcludeConflict(Exception):
    """The case exists but is not `investigating` — already concluded
    (`domain.transitions.StaleState`, translated with the extra read design
    note 1 asks for). `web/routers/tier2.py` maps this to 409. `status` is
    always the case's real, current status; `concluded_by`/`concluded_at`
    are set because a case this exception fires for is always concluded (the
    only other way to leave `investigating` in the three-state
    `ck_cases_status` CHECK). A `case_id` that names no row at all is
    `UnknownCase`, not this — see below."""

    def __init__(
        self,
        case_id: str,
        status: str,
        *,
        concluded_by: Any = None,
        concluded_at: datetime | None = None,
    ) -> None:
        super().__init__(f"case_id={case_id!r} is not investigating (status={status!r})")
        self.case_id = case_id
        self.status = status
        self.concluded_by = concluded_by
        self.concluded_at = concluded_at


class UnknownCase(Exception):
    """`case_id` matches no row in `cases`. Raised by `submit` (the case
    re-read after `StaleState` comes back empty) and by `add_note` (the
    `fk_case_notes_case` foreign key firing on the `INSERT`, translated
    rather than left as a raw `IntegrityError`). Maps to 404."""

    def __init__(self, case_id: str) -> None:
        super().__init__(f"case_id={case_id!r} does not exist")
        self.case_id = case_id


def submit(
    conn: psycopg.Connection,
    case_id: str,
    actor_id: str,
    *,
    conclusion: str,
    reason: str,
) -> None:
    """Validate, set the timeout, call `domain.conclude_case`, translate
    `StaleState`. `IllegalTransition` (unreachable through this function's own
    guard below, since `conclusion` is already checked — but domain's to
    raise, not this module's to re-derive) and a statement-timeout
    `psycopg.errors.QueryCanceled` are left to propagate; the router maps
    both directly (design note 1: 500 and 503)."""
    if conclusion not in CONCLUSIONS:
        raise ValueError(f"conclusion: no such value {conclusion!r}")
    if not reason or not reason.strip():
        raise ValueError("reason: must not be empty")
    if "\x00" in reason:
        raise ValueError("reason: must not contain a NUL byte")
    reason = reason.strip()  # as Tier-1's `decide` does: the stored reason is the bounded one
    if len(reason) > REASON_MAX_CHARS:
        raise ValueError(f"reason: must be 1-{REASON_MAX_CHARS} characters")

    conn.execute(sql.SQL("SET LOCAL statement_timeout = {}").format(sql.Literal(STATEMENT_TIMEOUT)))
    try:
        transitions.conclude_case(conn, case_id, actor_id, conclusion=conclusion, reason=reason)
    except transitions.StaleState as exc:
        row = conn.execute(
            "SELECT status, concluded_by, concluded_at FROM cases WHERE case_id = %s",
            (case_id,),
        ).fetchone()
        if row is None:
            raise UnknownCase(case_id) from exc
        status, concluded_by, concluded_at = row
        raise ConcludeConflict(
            case_id, status, concluded_by=concluded_by, concluded_at=concluded_at
        ) from exc


@dataclasses.dataclass(frozen=True)
class Note:
    note_id: int
    case_id: Any
    author_id: Any
    body: str
    created_at: datetime


def add_note(conn: psycopg.Connection, case_id: str, author_id: str, body: str) -> int:
    """`INSERT INTO case_notes`; `note_id` comes from the IDENTITY column —
    never supplied on the `INSERT` (migration 015 note (4): `app_rw` can
    `INSERT` into an IDENTITY table and cannot into the older auto-increment
    type). No audit event — see the module docstring."""
    if not body or not body.strip():
        raise ValueError("body: must not be empty")
    if "\x00" in body:
        raise ValueError("body: must not contain a NUL byte")
    encoded = body.encode("utf-8")
    if len(encoded) > NOTE_BODY_MAX_BYTES:
        raise ValueError(f"body: exceeds {NOTE_BODY_MAX_BYTES} bytes ({len(encoded)})")
    try:
        row = conn.execute(
            "INSERT INTO case_notes (case_id, author_id, body) VALUES (%s, %s, %s) "
            "RETURNING note_id",
            (case_id, author_id, body),
        ).fetchone()
    except psycopg.errors.ForeignKeyViolation as exc:
        if exc.diag.constraint_name == "fk_case_notes_case":
            raise UnknownCase(case_id) from exc
        raise
    assert row is not None
    return row[0]


def list_notes(conn: psycopg.Connection, case_id: str) -> list[Note]:
    """Ordered `created_at, note_id` — the second key makes the order total,
    which is what P5-T03's dossier build depends on when it reads notes into
    block 8 (design note 2)."""
    rows = conn.execute(
        "SELECT note_id, case_id, author_id, body, created_at FROM case_notes "
        "WHERE case_id = %s ORDER BY created_at, note_id",
        (case_id,),
    ).fetchall()
    return [Note(*row) for row in rows]
