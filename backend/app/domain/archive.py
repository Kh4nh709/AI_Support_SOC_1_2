"""`python -m app.domain.archive` - archive the old queue (INT-T03, DEC-212).

    docker compose exec app python -m app.domain.archive \\
        --before 2026-10-30T20:15:00+07:00 --reason "DEC-212: fresh start" [--apply]

Every alert and case that arrived before `--before` is closed out without review, as `archived`
(`domain.transitions.archive_before`, which has the rules: what is archived, what is left alone,
the audit events, the locking). This module is only the command around it.

Without `--apply` it is a DRY RUN: `archive_before` runs in a transaction that is rolled back, and
the counts are printed. With `--apply` the same transaction is committed and the same counts are
printed. Run the dry run first and read the numbers; there is no reopen, the way back is the backup
taken before `--apply` (runbook, "Archiving the old queue (DEC-212)").

`--before` must carry a UTC offset (`+07:00`, `Z`): an ISO-8601 time without one is refused before the
database is touched, because it would be read in the server's time zone. It must not be later than the
database's own `now()` either: a typo such as next month would archive the live queue that arrived
after the real cutoff, so such a `--before` exits 2 with a plain message and writes nothing, in a dry
run and with `--apply` alike. The DSN is read the way the other `python -m app...` commands read it
(`infra.config.load`: `DATABASE_URL` from the environment, else `.env`) and is never printed. Neither is
the text of a connection error or of a failed rollback, whatever `psycopg.Error` it is (one generic
line, exit 1); a query error's first line is shown.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime

import psycopg

from app.domain import transitions
from app.infra import config, db
from app.infra.errors import ConfigError

REASON_MAX = 500


def parse_before(text: str) -> datetime:
    """An ISO-8601 time WITH a UTC offset, as the `--before` argument. `argparse` turns the error
    into its usual usage message and exit code 2."""
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"{text!r} is not an ISO-8601 time (e.g. 2026-10-30T20:15:00+07:00)"
        ) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise argparse.ArgumentTypeError(
            f"{text!r} has no UTC offset: write one, e.g. 2026-10-30T20:15:00+07:00"
        )
    return parsed


def _reason(text: str) -> str:
    stripped = text.strip()
    if not 1 <= len(stripped) <= REASON_MAX:
        raise argparse.ArgumentTypeError(f"must be 1-{REASON_MAX} characters")
    return stripped


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.domain.archive",
        description=(
            "Archive the old queue (DEC-212): every alert and case that arrived before --before is "
            "closed out without review, as 'archived' (not a decision). A dry run unless --apply."
        ),
    )
    parser.add_argument(
        "--before",
        required=True,
        type=parse_before,
        metavar="ISO-8601",
        help="the cutoff, with a UTC offset, e.g. 2026-10-30T20:15:00+07:00",
    )
    parser.add_argument(
        "--reason",
        required=True,
        type=_reason,
        help="why, 1-500 characters; written to every archived row and audit event",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="commit. Without it the run is rolled back and only the counts are printed",
    )
    parser.add_argument("--env-file", default=".env")
    return parser


def _report(
    counts: transitions.ArchiveCounts, *, before: datetime, reason: str, apply: bool
) -> str:
    per_status = ", ".join(f"{status}={n}" for status, n in counts.by_status.items())
    first = "none" if counts.oldest_received_at is None else counts.oldest_received_at.isoformat()
    last = "none" if counts.newest_received_at is None else counts.newest_received_at.isoformat()
    lines = [
        (
            "archive: APPLIED - committed"
            if apply
            else "archive: DRY RUN - rolled back, nothing changed"
        ),
        f"before: {before.isoformat()}",
        f"reason: {reason}",
        f"alerts: {counts.alerts} ({per_status})",
        f"cases: {counts.cases}",
        f"oldest received_at: {first}",
        f"newest received_at: {last}",
    ]
    if not apply:
        lines.append("archive: to do it for real, run the same command with --apply")
    return "\n".join(lines)


def _rollback(conn: psycopg.Connection) -> bool:
    """Roll back; False when the rollback itself failed (a connection the server dropped). Nothing
    is lost then: the server discards a transaction whose connection ends without a commit."""
    try:
        conn.rollback()
    except psycopg.Error:
        return False
    return True


def _rollback_failed() -> int:
    # libpq's text can quote the host and the user, so it is not shown; the operator has the DSN.
    print(
        "archive: the rollback failed and the connection was closed; the server discards a "
        "transaction that was not committed. Run the dry run to see what the database holds",
        file=sys.stderr,
    )
    return 1


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)

    try:
        cfg = config.load(env_file=args.env_file)
        conn = db.connect(cfg.DATABASE_URL)
    except ConfigError as exc:
        print(f"archive: {exc}", file=sys.stderr)
        return 2
    except psycopg.Error:
        # Not only `OperationalError`: a DSN libpq cannot parse is a `ProgrammingError`, and its text
        # quotes the DSN, password included. The operator has the DSN, the log need not.
        print("archive: cannot connect to the database named by DATABASE_URL", file=sys.stderr)
        return 1

    try:
        # The database's own clock, read in the transaction `archive_before` then runs in, so it is
        # the `now()` that stamps every archived row.
        clock = conn.execute("SELECT now()").fetchone()[0]
        if args.before > clock:
            # A typo such as next month would also archive the live queue that arrived after the
            # cutoff, and only the backup brings it back. Nothing was written: it is a SELECT.
            if not _rollback(conn):
                return _rollback_failed()
            print(
                f"archive: --before {args.before.isoformat()} is later than the database's clock "
                f"({clock.isoformat()}): everything that arrived up to now would be archived. "
                "Check the cutoff; nothing was changed",
                file=sys.stderr,
            )
            return 2
        counts = transitions.archive_before(conn, before=args.before, reason=args.reason)
        if args.apply:
            conn.commit()
        elif not _rollback(conn):
            return _rollback_failed()
    except psycopg.Error as exc:
        if not _rollback(conn):
            return _rollback_failed()
        # a query error names no DSN: its first line (a lock, a deadlock, a right) is what the operator needs
        reason = str(exc).splitlines()[0] if str(exc) else ""
        print(f"archive: failed, nothing changed ({type(exc).__name__}: {reason})", file=sys.stderr)
        return 1
    finally:
        conn.close()

    print(_report(counts, before=args.before, reason=args.reason, apply=args.apply))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
