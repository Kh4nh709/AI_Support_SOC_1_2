#!/usr/bin/env python3
"""Import one day's abuse.ch IOC file into the Threat Intel tables (DEC-224).

    ti_import.py [FILE] --env-file PATH [--dir DIR]

FILE is the CSV to import, whatever its name or date (running an old file again by hand is a normal thing to do).
Without it the file is TODAY's, `ioc_YYYY-MM-DD.csv` in DIR (default `/var/lib/abusech/daily`) by the host's local
date, which is how the fetch script names it at 07:00; if it is not there the run is `failed` (`no_file`, exit 1,
a log row), and no older file is taken in its place (an old day imported as `ok` would hide a broken fetch from the
page's stale check). The database is the one `DATABASE_URL` names in the file at PATH: that one key is read from the
file here and from nowhere else (not from the arguments, not from the process environment), and it is never
printed; a failure prints the exception's class name and nothing of its text, because a driver's error can quote the
connection string.

The work is `backend/app/ti/importer.py`; this file only finds the CSV, opens the connection and prints. It puts the
repository's `backend/` on `sys.path` itself, so it runs by a plain path from any directory with the project's
interpreter, as any user who can read the checkout. Root is not needed and not wanted: root's cron line starts it
through `runuser` as the checkout's owner, with `-B` so that no bytecode is written into the checkout:

    ... abusech_daily100.py && runuser -u <owner> -- <venv>/bin/python -B <checkout>/scripts/ti_import.py \\
        --env-file <checkout>/.env

Output: one line per bad record on stderr (`ti_import: line 17: value_too_long`, or `lines 17-60: row_malformed` for
a record that swallowed lines; the first 100, then a count), and ONE summary line on stdout (`ti_import: status=ok
file=... total=... new=... updated=... errors=... repeated=...`), counts and closed words only. Exit code: 0 for `ok`
or `partial`; 1 for `failed` (no file, a header with a missing column, an unreadable or too large file, no good row,
a database that cannot be reached or refuses the file, a missing or empty `DATABASE_URL`); 2 for a usage error.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import UTC, date, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

import psycopg  # noqa: E402
from app.infra import db  # noqa: E402
from app.ti import importer  # noqa: E402

DEFAULT_DIR = "/var/lib/abusech/daily"
#: The names the fetch script gives its files; only today's, built from the date, is ever looked for.
DAILY_NAME = re.compile(r"ioc_\d{4}-\d{2}-\d{2}\.csv")
#: Bad rows listed on stderr; the rest are counted in one line (a corrupt file must not fill the cron's log).
MAX_ERROR_LINES = 100
CONNECT_TIMEOUT_S = 10

_TRAILING_COMMENT = re.compile(r"\s+#.*$")


def read_env_value(path: str | Path, key: str) -> str | None:
    """The value of `key` in a `KEY=value` file, or None. Blank lines and `#` lines are skipped, an `export ` prefix
    is ignored, a value may be in single or double quotes (nothing is unescaped), an unquoted value ends at a ` #`
    (whitespace first, so a `#` inside a password stays), and the last assignment wins. Only the one key is looked
    at; the other lines are never kept."""
    found: str | None = None
    for raw in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        name, separator, rest = line.partition("=")
        if not separator or name.strip() != key:
            continue
        rest = rest.strip()
        if rest[:1] in ("'", '"') and rest.find(rest[0], 1) != -1:
            found = rest[1 : rest.find(rest[0], 1)]
        else:
            found = _TRAILING_COMMENT.sub("", rest).strip()
    return found


def daily_name(day: date) -> str:
    """The file the fetch script writes on `day`."""
    return f"ioc_{day.isoformat()}.csv"


def todays_file(directory: str | Path, today: date) -> Path | None:
    """`ioc_<today>.csv` of the directory when it is a regular file there, else None. Only a name of the fetch
    script's shape (`DAILY_NAME`) is ever considered, and only the one of `today`: an older day's file is never
    taken in its place."""
    name = daily_name(today)
    if not DAILY_NAME.fullmatch(name):
        return None
    path = Path(directory) / name
    try:
        return path if path.is_file() else None
    except OSError:
        return None


def _report(result: importer.Result) -> int:
    spans = dict(result.error_spans)
    for number, reason in result.error_rows[:MAX_ERROR_LINES]:
        print(importer.format_error_line(number, reason, spans.get(number, 1)), file=sys.stderr)
    left = len(result.error_rows) - MAX_ERROR_LINES
    if left > 0:
        print(f"ti_import: {left} more bad rows not listed", file=sys.stderr)
    print(importer.format_summary(result))
    sys.stdout.flush()
    return 1 if result.status == "failed" else 0


def _fail(message: str) -> int:
    """A failure before any file was read, with no run to log (no usable DSN, no connection)."""
    return _report(
        importer.Result(
            file="-", total=0, new=0, updated=0, errors=0, status="failed", message=message
        )
    )


def main(argv: list[str] | None = None, *, today: date | None = None) -> int:
    """The command. `today` (default: the host's local date) is the day whose file is taken when no FILE is given."""
    parser = argparse.ArgumentParser(
        prog="ti_import.py",
        description="Import one day's abuse.ch IOC CSV into the Threat Intel tables.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="the CSV to import, any name (default: today's ioc_YYYY-MM-DD.csv of --dir)",
    )
    parser.add_argument(
        "--env-file",
        required=True,
        metavar="PATH",
        help="the file whose DATABASE_URL line names the database",
    )
    parser.add_argument(
        "--dir",
        default=DEFAULT_DIR,
        help=f"where to look for today's file (default {DEFAULT_DIR})",
    )
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse's own exit: 2 for a usage error, 0 for --help
        return exc.code if isinstance(exc.code, int) else 2

    try:
        dsn = read_env_value(args.env_file, "DATABASE_URL")
    except OSError:
        return _fail("env_file_unreadable")
    if not dsn:
        return _fail("dsn_missing")

    try:
        conn = db.connect(dsn, connect_timeout=CONNECT_TIMEOUT_S)
    except Exception as exc:
        # The class name only: the text of a connection error can quote the DSN.
        return _fail(f"database_unreachable: {type(exc).__name__}")
    try:
        now = datetime.now(UTC)
        if args.file:  # an explicit file is imported whatever its name or date
            result = importer.import_file(conn, Path(args.file), now=now)
        else:
            day = (
                date.today() if today is None else today
            )  # noqa: DTZ011 - the host's LOCAL date, as the fetch names it
            path = todays_file(args.dir, day)
            if path is None:
                result = importer.record_failure(conn, daily_name(day), "no_file", now=now)
            else:
                result = importer.import_file(conn, path, now=now)
    except Exception as exc:  # only reached when even the log row could not be written
        kind = "database_error" if isinstance(exc, psycopg.Error) else "internal_error"
        return _fail(f"{kind}: {type(exc).__name__}")
    finally:
        conn.close()
    return _report(result)


if __name__ == "__main__":
    sys.exit(main())
