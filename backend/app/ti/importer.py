"""The Threat Intel importer (DEC-224, spec 2026-11-17 §6): one day's abuse.ch CSV into `ti_ioc`.

The host's cron writes `/var/lib/abusech/daily/ioc_YYYY-MM-DD.csv` (header `source,first_seen,type,value,threat,
malware,confidence,tags,reference`); `scripts/ti_import.py` runs this module over it. Three steps, each apart from
the others so each can be tested alone:

1. **`parse_row`** turns one record into an `Ioc`, or raises `RowError` with ONE reason of the closed list `REASONS`.
   A reason names a rule, never the row's text. The bounds count UTF-8 BYTES (`value` 2 048, `type` 64, `malware`
   256, `threat` 256, `reference` 2 048, at most 32 tags of at most 64 bytes), on the value AS STORED (after
   `normalise_value`, which can lengthen a string: `lower()` turns the 2-byte U+0130 into 3 bytes), so a long
   field is a bad row with its reason and never a database error. A control character (C0, DEL, C1, U+2028/9) in
   any text field is a bad row too; it would otherwise reach the database (a NUL is a `DataError` that fails the
   whole file) or a log line. A `first_seen` more than a day ahead of the run is invalid (a date in year 9999 would
   head the list for ever).
2. **`read_file`** reads the CSV with the csv module, maps the header by name (order free, extra columns ignored, a
   missing column is a `HeaderError`) and returns the good rows, the bad ones as `(line, reason)` and the count of
   rows. `line` is the physical line the record STARTS on (the header is line 1). The file is decoded with
   `surrogateescape`, so a byte that is not UTF-8 is a bad row (`invalid_utf8`) and not an exception.
   **No legitimate record spans lines** (every field refuses a newline), so a record that does is ONE bad row,
   `row_malformed`, whatever its fields say, and its span is kept in `Parsed.spans` (`line -> physical lines`). It
   counts as the physical lines it swallows, in `total` and in the error count alike (an unclosed quote that eats
   the rest of the file is as many lost rows as lines), so `total = good rows + error_count` always holds.
   **The csv module is never left to stop mid-field.** Its `field_size_limit` (131 072 characters, process-wide)
   is raised above any field a file within `MAX_FILE_BYTES` (20 MB) can hold for the length of the read and put
   back after it; a field larger than the limit would otherwise raise in the middle of a quoted field, and the
   reader would go on at the next line and read the rest of the field as records (a forged record with a chosen
   source and confidence). A file over the cap, or one that is not a regular file, is a `FileError` before any
   row is read; a `csv.Error` after all that, whose reader state cannot be trusted, is a `FileError` too.
3. **`import_file`** loads the good rows in ONE transaction with `INSERT ... ON CONFLICT ON CONSTRAINT uq_ti_ioc_key
   DO UPDATE ... RETURNING (xmax = 0)`, which tells a new row from an updated one in the same statement, and writes
   one `ti_import_log` row. The transaction starts with `SET LOCAL lock_timeout` and `SET LOCAL statement_timeout`
   (`LOCK_TIMEOUT` 5 s, `STATEMENT_TIMEOUT` 10 s: a batch job, so more headroom than the web's 3 s, yet bounded:
   a one-row upsert takes a millisecond, a stuck lock ends as `database_error: LockNotAvailable`). On success the
   log row is part of that transaction (the data and its log commit together); on a database error the
   transaction is rolled back (nothing is loaded) and the failed run is logged in a transaction of its own, under the same
   timeouts. A header error, an unreadable or too large file and a file with no good row are logged the same way.

**The upsert** (spec §6): a new IOC gets `imported_at = last_seen = now`; an existing one gets `last_seen = now`, its
descriptive fields (malware, threat, confidence, tags, reference) replaced by what the feed says now, and
`first_seen = LEAST(old, new)`; `imported_at`, `hit_count` and `last_hit` are never touched. `expires_at =
last_seen + 30 days` both ways. A key (`source`, `type`, normalised `value`) repeated inside one file counts ONCE: the
first occurrence is loaded (its descriptive fields), with the EARLIEST `first_seen` of all its occurrences, and the
later ones are only counted (`Result.repeated`), so `total = new + updated + errors + repeated`.

**The log row.** `started_at` is the `now` the run was given; `finished_at` is `max(now, clock())`, both from the
caller's clock, never the database's: a finish before its start is refused by `ck_ti_import_log_finished_after_started`
and the row of a FAILED run must still be written. `status` is `ok` (no bad row), `partial` (some, the good ones
loaded) or `failed` (nothing loaded: a header error, an unreadable file, no record, no good record, a database
error). `message` is a closed vocabulary and never a row's text: NULL for `ok`; `skipped: <reason>=<n> ...` for
`partial`; `header_missing: <column names of COLUMNS>`, `file_unreadable`, `file_too_large`, `no_file`, `no_rows`,
`no_valid_rows; skipped: ...` or `database_error: <exception class name>` for `failed`.

The module imports nothing of the app: it is handed a connection, and the command (`scripts/ti_import.py`) opens it.
"""

from __future__ import annotations

import csv
import os
import re
import stat
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg
from psycopg import sql

COLUMNS = (
    "source",
    "first_seen",
    "type",
    "value",
    "threat",
    "malware",
    "confidence",
    "tags",
    "reference",
)
SOURCES = ("threatfox", "urlhaus", "malwarebazaar")
STATUSES = ("ok", "partial", "failed")
EXPIRES_AFTER = timedelta(days=30)

# The byte bounds. `value`, `type` and `malware` mirror the CHECKs of migration 026 (`ck_ti_ioc_*_bytes`); the other
# three have no CHECK and are the importer's own. Read at call time (a test moves one to show the database's own
# CHECK refuse what the importer let through).
VALUE_MAX_BYTES = 2048
TYPE_MAX_BYTES = 64
MALWARE_MAX_BYTES = 256
THREAT_MAX_BYTES = 256
REFERENCE_MAX_BYTES = 2048
TAGS_MAX = 32
TAG_MAX_BYTES = 64
FILE_NAME_MAX = 255

#: The largest file read. The csv module's field limit is raised above it for the read, so no field of a file within
#: the cap can trip the limit and leave the reader in the middle of a quoted field.
MAX_FILE_BYTES = 20 * 1024 * 1024
#: A `first_seen` later than the run's `now` plus this is invalid: the feed's dates are the past (or this host's
#: clock being a little behind the feed's).
FIRST_SEEN_MAX_AHEAD = timedelta(days=1)
#: Per statement, inside the import transaction (`SET LOCAL`). A batch job: more than the web's 3 s, still bounded.
STATEMENT_TIMEOUT = "10s"
LOCK_TIMEOUT = "5s"

#: The closed list of reasons a record is skipped, in the order the fields are checked. Nothing else is ever
#: reported for a row (`RowError` refuses a reason that is not here).
REASONS = (
    "row_malformed",  # a record that spans lines, or has more or fewer fields than the header
    "invalid_utf8",  # a byte that is not UTF-8 (a lone surrogate once decoded with surrogateescape)
    "source_invalid",  # not threatfox, urlhaus or malwarebazaar
    "first_seen_missing",
    "first_seen_invalid",  # not `YYYY-MM-DD HH:MM:SS[ UTC]` nor ISO-8601
    "type_invalid",  # empty, or not a lower-case token of [a-z0-9_:.-]
    "type_too_long",
    "value_empty",
    "value_control_char",
    "value_too_long",
    "threat_too_long",
    "malware_too_long",
    "confidence_not_integer",
    "confidence_out_of_range",
    "tags_too_many",
    "tag_too_long",
    "reference_too_long",
    "text_control_char",  # a control character in threat, malware, a tag or reference
)

#: C0, DEL, C1 and the two Unicode line separators: what a person reads as a line break or an escape.
_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029]")
_SURROGATE = re.compile("[\ud800-\udfff]")
_TYPE_TOKEN = re.compile(r"[a-z0-9_:.\-]+")
_INTEGER = re.compile(r"-?[0-9]+")
_UTC_SUFFIX = re.compile(r"\s+UTC$", re.IGNORECASE)


class RowError(Exception):
    """One record is not loadable. `reason` is one of `REASONS`."""

    def __init__(self, reason: str):
        if reason not in REASONS:
            raise ValueError("a row error needs a reason of the closed list REASONS")
        super().__init__(reason)
        self.reason = reason


class HeaderError(Exception):
    """The file's header lacks columns of `COLUMNS`. `missing` names them, in the order of `COLUMNS`."""

    def __init__(self, missing: Iterable[str]):
        self.missing = tuple(missing)
        super().__init__("missing columns: " + ",".join(self.missing))


class FileError(Exception):
    """The file cannot be read as a feed file. `message` is the log row's closed word: `file_unreadable` (not a
    regular file, or one the csv module cannot read) or `file_too_large` (over `MAX_FILE_BYTES`)."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class UpsertError(Exception):
    """The upsert statement returned no row, which `ON CONFLICT ... DO UPDATE ... RETURNING` never does; counting the
    row as an update would be a guess, so the run fails."""


@dataclass(frozen=True)
class Ioc:
    """One indicator, the nine fields normalised. `first_seen` is aware (UTC); an empty text field is None."""

    source: str
    first_seen: datetime
    type: str
    value: str
    threat: str | None
    malware: str | None
    confidence: int | None
    tags: tuple[str, ...]
    reference: str | None

    @property
    def key(self) -> tuple[str, str, str]:
        """The upsert's key, `uq_ti_ioc_key`."""
        return (self.source, self.type, self.value)


@dataclass
class Parsed:
    """What `read_file` found: the good rows, the bad records as `(line, reason)` (one entry per record), the rows
    read, and `spans`, `{line: physical lines}` for each bad record that spans more than one. A record that spans N
    lines counts as N rows in `total` and in `error_count`: the rows lost, one per physical line."""

    iocs: list[Ioc]
    errors: list[tuple[int, str]]
    total: int
    spans: dict[int, int] = field(default_factory=dict)

    @property
    def error_count(self) -> int:
        """The rows lost: one per bad record, plus the extra physical lines of each record that spans lines."""
        return len(self.errors) + sum(span - 1 for span in self.spans.values())


@dataclass(frozen=True)
class Result:
    """One run. `errors` is the count of rows lost (`Parsed.error_count`: a record that spans N lines is N), and
    `error_rows` the bad records as `(line, reason)`, with `error_spans` the `(line, physical lines)` of those that
    span more than one; `repeated` counts the later occurrences of a key already seen in the file, so `total = new +
    updated + errors + repeated` for a run that loaded. `message` is the closed vocabulary of the module docstring
    and never a row's text. `status` is one of `STATUSES`.
    """

    file: str
    total: int
    new: int
    updated: int
    errors: int
    status: str
    message: str | None
    repeated: int = 0
    error_rows: tuple[tuple[int, str], ...] = ()
    error_spans: tuple[tuple[int, int], ...] = ()

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError("a result's status is one of STATUSES")


# ═════════════════════════════ one record ═════════════════════════════════════════════════════════════════════


def normalise_value(type: str, value: str) -> str:
    """`value` trimmed; lower-cased for `domain` and every `*_hash` type, case kept for a URL or an `ip:port`.
    The one place the rule lives: the importer stores what it returns, and the lookup of the API compares with it.
    `type` may be spelled as the caller has it (case and spaces are not significant here)."""
    value = value.strip()
    kind = type.strip().lower()
    if kind == "domain" or kind.endswith("_hash"):
        value = value.lower()
    return value


def _parse_first_seen(raw: str, now: datetime) -> datetime:
    text = raw.strip()
    if not text:
        raise RowError("first_seen_missing")
    text = _UTC_SUFFIX.sub("", text)
    try:
        parsed = datetime.fromisoformat(text)
        moment = parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    except (ValueError, OverflowError):
        raise RowError("first_seen_invalid") from None
    if moment > now + FIRST_SEEN_MAX_AHEAD:
        raise RowError("first_seen_invalid")
    return moment


def _parse_type(raw: str) -> str:
    kind = raw.strip().lower()
    if not _TYPE_TOKEN.fullmatch(kind):
        raise RowError("type_invalid")
    # The token is ASCII, so its characters are its bytes.
    if len(kind) > TYPE_MAX_BYTES:
        raise RowError("type_too_long")
    return kind


def _parse_value(type_: str, raw: str) -> str:
    value = normalise_value(type_, raw)
    if not value:
        raise RowError("value_empty")
    if _CONTROL.search(value):
        raise RowError("value_control_char")
    if len(value.encode("utf-8")) > VALUE_MAX_BYTES:
        raise RowError("value_too_long")
    return value


def _parse_text(raw: str, limit: int, too_long: str) -> str | None:
    """A descriptive field: trimmed, None when empty, no control character, at most `limit` bytes."""
    text = raw.strip()
    if not text:
        return None
    if _CONTROL.search(text):
        raise RowError("text_control_char")
    if len(text.encode("utf-8")) > limit:
        raise RowError(too_long)
    return text


def _parse_confidence(raw: str) -> int | None:
    text = raw.strip()
    if not text:
        return None
    if not _INTEGER.fullmatch(text):
        raise RowError("confidence_not_integer")
    # An integer however long: far outside 0..100, and int() refuses more than 4 300 digits.
    if len(text.lstrip("-")) > 6:
        raise RowError("confidence_out_of_range")
    number = int(text)
    if not 0 <= number <= 100:
        raise RowError("confidence_out_of_range")
    return number


def _parse_tags(raw: str) -> tuple[str, ...]:
    text = raw.strip()
    if _CONTROL.search(text):
        raise RowError("text_control_char")
    tags = tuple(tag for tag in (part.strip() for part in text.split(",")) if tag)
    if len(tags) > TAGS_MAX:
        raise RowError("tags_too_many")
    if any(len(tag.encode("utf-8")) > TAG_MAX_BYTES for tag in tags):
        raise RowError("tag_too_long")
    return tags


def parse_row(row: Mapping[str, str | None], *, now: datetime | None = None) -> Ioc:
    """The `Ioc` of one record, or `RowError` with the reason of the FIRST problem, fields taken in the order of
    `COLUMNS`. A key the mapping lacks, or a None, reads as an empty field. `now` (default: the wall clock) is what
    `first_seen` is judged against: later than `now` plus `FIRST_SEEN_MAX_AHEAD` is invalid."""
    now = _utcnow() if now is None else _utc(now)
    fields = {name: row.get(name) or "" for name in COLUMNS}
    if any(_SURROGATE.search(text) for text in fields.values()):
        raise RowError("invalid_utf8")  # before any `.encode()`: a lone surrogate cannot be encoded
    source = fields["source"].strip().lower()
    if source not in SOURCES:
        raise RowError("source_invalid")
    first_seen = _parse_first_seen(fields["first_seen"], now)
    type_ = _parse_type(fields["type"])
    value = _parse_value(type_, fields["value"])
    threat = _parse_text(fields["threat"], THREAT_MAX_BYTES, "threat_too_long")
    malware = _parse_text(fields["malware"], MALWARE_MAX_BYTES, "malware_too_long")
    confidence = _parse_confidence(fields["confidence"])
    tags = _parse_tags(fields["tags"])
    reference = _parse_text(fields["reference"], REFERENCE_MAX_BYTES, "reference_too_long")
    return Ioc(source, first_seen, type_, value, threat, malware, confidence, tags, reference)


# ═════════════════════════════ one file ═══════════════════════════════════════════════════════════════════════


def read_file(path: str | Path, *, now: datetime | None = None) -> Parsed:
    """Every record of the file: `Parsed(iocs, errors, total, spans)`. `HeaderError` when a column of `COLUMNS` is
    not in the header (an empty file lacks all nine); `FileError` when the file is over `MAX_FILE_BYTES`, is not a
    regular file or cannot be read as CSV; `OSError` when it cannot be opened or read. `now` (default: the wall
    clock) is what each `first_seen` is judged against.

    The csv module's field limit is process-wide: this function raises it for the duration of the read and puts it
    back, so it is for single-threaded callers (the command is one); two threads reading at once could restore it
    in the wrong order."""
    moment = _utcnow() if now is None else _utc(now)
    with open(path, encoding="utf-8-sig", errors="surrogateescape", newline="") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise FileError("file_unreadable")
        if info.st_size > MAX_FILE_BYTES:
            raise FileError("file_too_large")
        # Process-wide, so put back whatever happens. Above any field of a file within the cap: the csv module
        # never raises mid-field, and so never resumes in the middle of a quoted field.
        previous = csv.field_size_limit(MAX_FILE_BYTES + 1)
        try:
            return _read_records(handle, moment)
        finally:
            csv.field_size_limit(previous)


def _read_records(handle: Iterable[str], now: datetime) -> Parsed:
    reader = csv.reader(handle)
    try:
        header = next(reader)
    except (StopIteration, csv.Error):
        raise HeaderError(COLUMNS) from None
    names = [name.strip() for name in header]
    missing = tuple(column for column in COLUMNS if column not in names)
    if missing:
        raise HeaderError(missing)
    position: dict[str, int] = {}
    for index, name in enumerate(names):
        position.setdefault(name, index)

    iocs: list[Ioc] = []
    errors: list[tuple[int, str]] = []
    spans: dict[int, int] = {}
    total = 0
    while True:
        # The line this record starts on; `reader.line_num` is the last line read, so after the record it is the
        # last line the record takes.
        start = reader.line_num + 1
        try:
            record = next(reader)
        except StopIteration:
            break
        except csv.Error:
            # With the field limit raised this cannot be a long field; whatever it is, the reader's state after
            # it cannot be trusted, and a guess at where the next record starts could load a forged one.
            raise FileError("file_unreadable") from None
        span = reader.line_num - start + 1
        if not record:  # a blank line
            continue
        # No legitimate record spans lines: one bad record, counted as the lines it swallows.
        if span > 1:
            total += span
            errors.append((start, "row_malformed"))
            spans[start] = span
            continue
        total += 1
        if len(record) != len(names):
            errors.append((start, "row_malformed"))
            continue
        try:
            iocs.append(
                parse_row({column: record[position[column]] for column in COLUMNS}, now=now)
            )
        except RowError as exc:
            errors.append((start, exc.reason))
    return Parsed(iocs, errors, total, spans)


# ═════════════════════════════ one run ════════════════════════════════════════════════════════════════════════

_UPSERT = """
INSERT INTO ti_ioc (source, type, value, malware, threat, confidence, tags, reference,
                    first_seen, last_seen, imported_at, expires_at)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT ON CONSTRAINT uq_ti_ioc_key DO UPDATE SET
    malware    = EXCLUDED.malware,
    threat     = EXCLUDED.threat,
    confidence = EXCLUDED.confidence,
    tags       = EXCLUDED.tags,
    reference  = EXCLUDED.reference,
    first_seen = LEAST(ti_ioc.first_seen, EXCLUDED.first_seen),
    last_seen  = EXCLUDED.last_seen,
    expires_at = EXCLUDED.expires_at
RETURNING (xmax = 0) AS inserted
"""

_LOG = """
INSERT INTO ti_import_log (file, started_at, finished_at, rows_total, rows_new, rows_updated, rows_error,
                           status, message)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
"""


def _utcnow() -> datetime:
    return datetime.now(UTC)


def safe_name(name: str) -> str:
    """A file name as the log row and the summary line carry it: white space becomes `_` (so the `key=value` words
    of the summary line stay one word each, and a newline cannot split the line), any other character that is not
    printable becomes `?`, at most 255 characters. The directory is never part of it."""
    return "".join("_" if ch.isspace() else ch if ch.isprintable() else "?" for ch in name)[
        :FILE_NAME_MAX
    ]


def format_summary(result: Result) -> str:
    """The one line a run prints on stdout, counts and closed words only (it lands in the cron's log)."""
    line = (
        f"ti_import: status={result.status} file={result.file} total={result.total} new={result.new}"
        f" updated={result.updated} errors={result.errors} repeated={result.repeated}"
    )
    return f"{line} message={result.message}" if result.message else line


def format_error_line(line: int, reason: str, span: int = 1) -> str:
    """The line printed for one bad record: its line number (`lines A-B` for a record that spans lines) and its
    closed reason, never the row's text."""
    where = f"line {line}" if span <= 1 else f"lines {line}-{line + span - 1}"
    return f"ti_import: {where}: {reason}"


def _skipped(errors: tuple[tuple[int, str], ...], spans: Mapping[int, int]) -> str:
    """`skipped: <reason>=<rows> ...`, reasons sorted; a record that spans lines counts as the lines it takes."""
    counts: Counter[str] = Counter()
    for line, reason in errors:
        counts[reason] += spans.get(line, 1)
    if not counts:
        return ""
    return "skipped: " + " ".join(f"{reason}={counts[reason]}" for reason in sorted(counts))


def _first_occurrences(iocs: list[Ioc]) -> tuple[list[Ioc], int]:
    """One row per key, in the order of the keys' first occurrences, and how many later occurrences were dropped.
    The first occurrence supplies the descriptive fields; its `first_seen` is the earliest of all its occurrences.
    """
    kept: dict[tuple[str, str, str], Ioc] = {}
    repeated = 0
    for ioc in iocs:
        first = kept.get(ioc.key)
        if first is None:
            kept[ioc.key] = ioc
            continue
        repeated += 1
        if ioc.first_seen < first.first_seen:
            kept[ioc.key] = replace(first, first_seen=ioc.first_seen)
    return list(kept.values()), repeated


def _utc(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        raise ValueError("now must carry a time zone")
    return moment.astimezone(UTC)


def _finish(now: datetime, clock: Callable[[], datetime]) -> datetime:
    """When the run ended: never before it started, whatever `clock` says (the CHECK refuses a finish before the
    start, and the row of a failed run must still be written)."""
    return max(now, _utc(clock()))


def _write_log(
    conn: psycopg.Connection, result: Result, started: datetime, finished: datetime
) -> None:
    conn.execute(
        _LOG,
        (
            result.file,
            started,
            finished,
            result.total,
            result.new,
            result.updated,
            result.errors,
            result.status,
            result.message,
        ),
    )


def _log_alone(
    conn: psycopg.Connection, result: Result, now: datetime, clock: Callable[[], datetime]
) -> Result:
    """The log row of a run that loaded nothing, in a transaction of its own and under the same lock and statement
    timeouts as the import: a lock held on `ti_import_log` ends the run in the timeout (the driver's error leaves
    this function, and the command prints its class), it does not hang it."""
    with conn.transaction():
        _bound_waits(conn)
        _write_log(conn, result, now, _finish(now, clock))
    return result


def _bound_waits(conn: psycopg.Connection) -> None:
    """The first statements of the import transaction: `SET LOCAL` dies with it, and takes no bind parameter, hence
    `sql.Literal` (as `infra/db.py`'s `transaction()` does). Inside a transaction the caller already holds, they
    last until the caller's transaction ends."""
    conn.execute(sql.SQL("SET LOCAL lock_timeout = {}").format(sql.Literal(LOCK_TIMEOUT)))
    conn.execute(sql.SQL("SET LOCAL statement_timeout = {}").format(sql.Literal(STATEMENT_TIMEOUT)))


def _upsert(conn: psycopg.Connection, iocs: list[Ioc], now: datetime) -> tuple[int, int]:
    """The rows into `ti_ioc`, one statement each; `(new, updated)`."""
    new = updated = 0
    expires = now + EXPIRES_AFTER
    with conn.cursor() as cur:
        for ioc in iocs:
            params: tuple[Any, ...] = (
                ioc.source,
                ioc.type,
                ioc.value,
                ioc.malware,
                ioc.threat,
                ioc.confidence,
                list(ioc.tags),
                ioc.reference,
                ioc.first_seen,
                now,
                now,
                expires,
            )
            row = cur.execute(_UPSERT, params).fetchone()
            if row is None:  # never, for DO UPDATE ... RETURNING: not a row to guess about
                raise UpsertError("the upsert returned no row")
            if row[0]:
                new += 1
            else:
                updated += 1
    return new, updated


def record_failure(
    conn: psycopg.Connection,
    file: str,
    message: str,
    *,
    now: datetime,
    clock: Callable[[], datetime] | None = None,
) -> Result:
    """A failed run that never reached a file (the command found none to import): one `failed` log row, counts 0."""
    result = Result(safe_name(file), 0, 0, 0, 0, "failed", message)
    return _log_alone(conn, result, _utc(now), clock or _utcnow)


def import_file(
    conn: psycopg.Connection,
    path: str | Path,
    *,
    now: datetime,
    clock: Callable[[], datetime] | None = None,
) -> Result:
    """Import one file as the module docstring says. `now` (timezone-aware) is the run's instant: `started_at`,
    every row's `last_seen` and, plus 30 days, `expires_at`; `clock` (default: the wall clock) is read once more
    for `finished_at`. A run that cannot load is still logged and returned as `failed`; the only exceptions that
    leave this function are a database error while writing that log row and a `now` without a zone.
    """
    now = _utc(now)
    clock = clock or _utcnow
    path = Path(path)
    name = safe_name(path.name)

    try:
        parsed = read_file(path, now=now)
    except HeaderError as exc:
        failed = Result(name, 0, 0, 0, 0, "failed", "header_missing: " + ",".join(exc.missing))
        return _log_alone(conn, failed, now, clock)
    except FileError as exc:
        return _log_alone(conn, Result(name, 0, 0, 0, 0, "failed", exc.message), now, clock)
    except OSError:
        return _log_alone(conn, Result(name, 0, 0, 0, 0, "failed", "file_unreadable"), now, clock)

    bad = tuple(parsed.errors)
    unique, repeated = _first_occurrences(parsed.iocs)
    skipped = _skipped(bad, parsed.spans)
    counted = {
        "file": name,
        "total": parsed.total,
        "errors": parsed.error_count,
        "repeated": repeated,
        "error_rows": bad,
        "error_spans": tuple(sorted(parsed.spans.items())),
    }
    if parsed.total == 0:
        return _log_alone(
            conn,
            Result(**counted, new=0, updated=0, status="failed", message="no_rows"),
            now,
            clock,
        )
    if not unique:
        message = "no_valid_rows; " + skipped
        return _log_alone(
            conn, Result(**counted, new=0, updated=0, status="failed", message=message), now, clock
        )

    try:
        with conn.transaction():
            _bound_waits(conn)
            new, updated = _upsert(conn, unique, now)
            result = Result(
                **counted,
                new=new,
                updated=updated,
                status="partial" if bad else "ok",
                message=skipped or None,
            )
            _write_log(conn, result, now, _finish(now, clock))
    except (psycopg.Error, UpsertError) as exc:
        # The transaction is rolled back: nothing of this file is in `ti_ioc`. The type names the error (a timeout
        # is `LockNotAvailable` or `QueryCanceled`); its text can quote the offending row, so it is never kept.
        message = f"database_error: {type(exc).__name__}"
        failed = Result(**counted, new=0, updated=0, status="failed", message=message)
        return _log_alone(conn, failed, now, clock)
    return result
