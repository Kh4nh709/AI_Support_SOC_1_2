"""The Threat Intel read side (DEC-224, spec 2026-11-17 §7): the SQL behind `GET /api/ti/*`, and the two export formats.

The module holds no FastAPI: `web/routers/ti.py` reads the request, checks the role and calls these functions with a connection
and a clock (`now`, always handed in: the tests move it). The layering rule (`test_import_rules.py`) lets `ti` import `infra` and
nothing else, and only `web` import `ti`. Nothing here opens a socket, resolves a name or fetches anything: an IOC value is
DATA, and every function returns it as it is stored.

**Safe by construction.** Every statement is a fixed text with `%(name)s` parameters: the `WHERE` of the list is built from
fixed fragments (`_where`), a value only ever goes in as a parameter, the sort is the constant `_ORDER` and never comes from the
request. The text of a search (`q`) is escaped for `LIKE` (`like_contains`: `%`, `_` and `\\` are literal) and always used with
an explicit `ESCAPE '\\'`.

**The list's rules.** The order is `first_seen DESC, id DESC` (the index `ix_ti_ioc_first_seen`; the id is the tie-break, so a
page never overlaps or skips). A row is EXPIRED when `expires_at <= now`; the list, the stats and the exports leave expired rows
out unless the filter says `include_expired`; the lookup includes them (each row carries `expired`). `min_confidence` is
`confidence >= n`: a row whose confidence is NULL (every MalwareBazaar row) is left out, even for 0. `type` is read the way the
importer stores it (trimmed, lower-case) and compared for equality; `malware` is an equality on the trimmed name (the index
`ix_ti_ioc_malware` serves it); `q` is a case-insensitive substring of `value`, `malware`, `threat` or one tag.

**Time.** Everything is served as ISO 8601 in UTC (`2026-11-17T06:12:44+00:00`). The page's zone is GMT+7
(`Asia/Ho_Chi_Minh`): a day, for the stats and for a `from` / `to` that is a date, is a day of GMT+7 (`parse_bound`).

**The stats** count the rows that are not expired, as the list does by default, so a figure here is the `total` the list gives
for the same question: `high_confidence` is the total of `min_confidence=75`, a `top_malware` count is the total of that
`malware`. `days` only sets the length of the per-day series, which is dense: every day of the window is there, as zeros when no
IOC has it, oldest first, today last. The other figures are not windowed.

**The lookup** compares the input, trimmed, the way the importer stored each row: a `domain` and every `*_hash` row is stored
lower-case, so it is compared with the lower-cased input; every other type keeps its case. An IPv4 input also finds the `ip:port`
rows of that address (`value LIKE '1.2.3.4:%'`, the address validated by `ipaddress`).

**Exports.** `csv_cell` puts a `'` before a cell a spreadsheet would run as a formula; `export_csv` is RFC 4180 text with every
cell guarded; `blocklist_text` is one domain or address per line, built only from values that are made of the characters of a
hostname or an address (so a line break in a stored value can never make a second line). `export_iocs` reads at most
`EXPORT_MAX_ROWS` rows and RAISES `TooManyRows` beyond it: an export is never silently cut.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo

import psycopg
from psycopg.rows import dict_row

from app.ti.importer import (
    MALWARE_MAX_BYTES,
    SOURCES,
    TYPE_MAX_BYTES,
    VALUE_MAX_BYTES,
    normalise_value,
)

#: The page's zone (spec §8) and the one the stats count their days in.
DISPLAY_TZ = "Asia/Ho_Chi_Minh"
GMT7 = ZoneInfo(DISPLAY_TZ)

PAGE_SIZE_DEFAULT = 50
PAGE_SIZE_MAX = 200
#: A page number past this is not a page; the offset stays a small integer.
PAGE_MAX = 1_000_000
DAYS_DEFAULT = 30
DAYS_MAX = 90
#: The ceilings of the text inputs: the importer's own bounds (a value that is longer than the importer allows names nothing).
VALUE_MAX = VALUE_MAX_BYTES
MALWARE_MAX = MALWARE_MAX_BYTES
TYPE_MAX = TYPE_MAX_BYTES
#: A lookup serves at most this many rows (an IPv4 address with a port per row); `total` says how many there are.
LOOKUP_MAX_ROWS = 200
#: An export holds at most this many rows, read at call time. 30 days of three sources of 100 rows a day leave 9 000 rows
#: unexpired; the cap is above that, and a filter that gives more is REFUSED (`TooManyRows`), never cut.
EXPORT_MAX_ROWS = 20_000
#: `status`: no successful import finished within this long before `now` is `stale`.
STALE_AFTER = timedelta(hours=26)
#: The import-log statuses that count as a success for `status`.
SUCCESS_STATUSES = ("ok", "partial")
HIGH_CONFIDENCE = 75
TOP_MALWARE = 10
NEWEST_MALWARE = 3

#: The served keys of one IOC, in order: also the columns of the CSV export.
IOC_KEYS = (
    "id",
    "source",
    "type",
    "value",
    "malware",
    "threat",
    "confidence",
    "tags",
    "reference",
    "first_seen",
    "last_seen",
    "imported_at",
    "expires_at",
    "expired",
    "hit_count",
    "last_hit",
)
_IOC_COLUMNS = (
    "id, source, type, value, malware, threat, confidence, tags, reference, first_seen, last_seen, "
    "imported_at, expires_at, hit_count, last_hit"
)
_LOG_COLUMNS = "id, file, started_at, finished_at, rows_total, rows_new, rows_updated, rows_error, status, message"
#: The one order of every list. Never built from a request.
_ORDER = "ORDER BY first_seen DESC, id DESC"


class TooManyRows(Exception):
    """An export would hold more than `limit` rows."""

    def __init__(self, limit: int):
        self.limit = limit
        super().__init__(f"more than {limit} rows")


# ═════════════════════════════ what a request asks ════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class Filters:
    """The filters of the list and of the exports, all optional and ANDed. `first_seen_from` is inclusive and
    `first_seen_before` exclusive (`parse_bound` makes both). `type`, `malware` and `q` are trimmed here, and a blank one is
    no filter; `type` is lower-cased, as the importer stores it."""

    source: str | None = None
    type: str | None = None
    malware: str | None = None
    first_seen_from: datetime | None = None
    first_seen_before: datetime | None = None
    min_confidence: int | None = None
    q: str | None = None
    include_expired: bool = False


_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_DATETIME = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}(:[0-9]{2}(\.[0-9]{1,6})?)?(Z|[+-][0-9]{2}:[0-9]{2})?"
)


def parse_bound(text: str, *, upper: bool) -> datetime:
    """A `from` (`upper=False`) or a `to` (`upper=True`) as an aware UTC instant, or `ValueError`.

    The text is `YYYY-MM-DD` or `YYYY-MM-DD[T ]HH:MM[:SS[.ffffff]]` with an optional `Z` or `+HH:MM`; nothing else (no week date,
    no compact `20261117`, no offset without its colon). A date, and a time with no offset, are read in GMT+7. `from` is
    inclusive; `to` is inclusive too, so as an upper bound it is returned as the EXCLUSIVE end: the first instant of the next
    day for a date (the whole day is in), a microsecond after a time. A bound that has no UTC form is a `ValueError` as well.
    """
    try:
        if _DATE.fullmatch(text):
            moment = datetime.combine(date.fromisoformat(text), time.min, tzinfo=GMT7)
            if upper:
                moment += timedelta(days=1)
        elif _DATETIME.fullmatch(text):
            moment = datetime.fromisoformat(text)
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=GMT7)
            if upper:
                moment += timedelta(microseconds=1)
        else:
            raise ValueError
        return moment.astimezone(UTC)
    except (ValueError, OverflowError):
        raise ValueError(
            "must be a date or an ISO 8601 time (YYYY-MM-DD[THH:MM[:SS]][Z|+HH:MM])"
        ) from None


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def like_contains(text: str) -> str:
    r"""`text` as the middle of a `LIKE` pattern that matches it literally: `\`, `%` and `_` are escaped, for use with
    `ESCAPE '\'`. Every backslash is doubled, so the pattern never ends in a lone escape character (a database error).
    """
    return "%" + _escape_like(text) + "%"


def _where(filters: Filters, now: datetime) -> tuple[str, dict[str, Any]]:
    """The `WHERE` of the list and of the exports: fixed fragments, every value a bound parameter."""
    clauses: list[str] = []
    params: dict[str, Any] = {"now": now}
    if not filters.include_expired:
        clauses.append("expires_at > %(now)s")
    if filters.source is not None:
        clauses.append("source = %(source)s")
        params["source"] = filters.source
    kind = (filters.type or "").strip().lower()
    if kind:
        clauses.append("type = %(type)s")
        params["type"] = kind
    malware = (filters.malware or "").strip()
    if malware:
        clauses.append("malware = %(malware)s")
        params["malware"] = malware
    if filters.first_seen_from is not None:
        clauses.append("first_seen >= %(first_seen_from)s")
        params["first_seen_from"] = filters.first_seen_from
    if filters.first_seen_before is not None:
        clauses.append("first_seen < %(first_seen_before)s")
        params["first_seen_before"] = filters.first_seen_before
    if filters.min_confidence is not None:
        clauses.append("confidence >= %(min_confidence)s")
        params["min_confidence"] = filters.min_confidence
    q = (filters.q or "").strip()
    if q:
        clauses.append(
            "(value ILIKE %(q_like)s ESCAPE '\\' OR malware ILIKE %(q_like)s ESCAPE '\\' "
            "OR threat ILIKE %(q_like)s ESCAPE '\\' "
            "OR EXISTS (SELECT 1 FROM unnest(tags) AS t(tag) WHERE t.tag ILIKE %(q_like)s ESCAPE '\\'))"
        )
        params["q_like"] = like_contains(q)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


# ═════════════════════════════ what is served ═════════════════════════════════════════════════════════════════


def _iso(moment: datetime | None) -> str | None:
    return None if moment is None else moment.astimezone(UTC).isoformat()


def serve_ioc(record: Mapping[str, Any], now: datetime) -> dict[str, Any]:
    """One `ti_ioc` row as the API serves it: the keys of `IOC_KEYS`, timestamps in UTC, `expired` as of `now`."""
    return {
        "id": record["id"],
        "source": record["source"],
        "type": record["type"],
        "value": record["value"],
        "malware": record["malware"],
        "threat": record["threat"],
        "confidence": record["confidence"],
        "tags": list(record["tags"]),
        "reference": record["reference"],
        "first_seen": _iso(record["first_seen"]),
        "last_seen": _iso(record["last_seen"]),
        "imported_at": _iso(record["imported_at"]),
        "expires_at": _iso(record["expires_at"]),
        "expired": record["expires_at"] <= now,
        "hit_count": record["hit_count"],
        "last_hit": _iso(record["last_hit"]),
    }


def _serve_log(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": record["id"],
        "file": record["file"],
        "started_at": _iso(record["started_at"]),
        "finished_at": _iso(record["finished_at"]),
        "rows_total": record["rows_total"],
        "rows_new": record["rows_new"],
        "rows_updated": record["rows_updated"],
        "rows_error": record["rows_error"],
        "status": record["status"],
        "message": record["message"],
    }


# ═════════════════════════════ the list ═══════════════════════════════════════════════════════════════════════


def list_iocs(
    conn: psycopg.Connection, filters: Filters, *, page: int, page_size: int, now: datetime
) -> tuple[list[dict[str, Any]], int]:
    """`(rows, total)`: one page of the IOCs the filters keep, newest `first_seen` first and the highest `id` first among equals.
    `total` counts all the rows the filters keep, so a page past the end is an empty list with the right total.
    """
    page_size = min(page_size, PAGE_SIZE_MAX)
    where, params = _where(filters, now)
    records = (
        conn.cursor(row_factory=dict_row)
        .execute(
            f"SELECT {_IOC_COLUMNS} FROM ti_ioc{where} {_ORDER} LIMIT %(limit)s OFFSET %(offset)s",
            {**params, "limit": page_size, "offset": (page - 1) * page_size},
        )
        .fetchall()
    )
    (total,) = conn.execute(f"SELECT count(*) FROM ti_ioc{where}", params).fetchone()
    return [serve_ioc(record, now) for record in records], total


def export_iocs(
    conn: psycopg.Connection, filters: Filters, *, now: datetime, limit: int
) -> list[dict[str, Any]]:
    """Every IOC the filters keep, in the list's order, or `TooManyRows` when they keep more than `limit`. It reads `limit + 1`
    rows to know, so an export is whole or refused and never silently cut."""
    where, params = _where(filters, now)
    records = (
        conn.cursor(row_factory=dict_row)
        .execute(
            f"SELECT {_IOC_COLUMNS} FROM ti_ioc{where} {_ORDER} LIMIT %(limit)s",
            {**params, "limit": limit + 1},
        )
        .fetchall()
    )
    if len(records) > limit:
        raise TooManyRows(limit)
    return [serve_ioc(record, now) for record in records]


# ═════════════════════════════ the stats ══════════════════════════════════════════════════════════════════════

_LIVE = "expires_at > %(now)s"
_NAMED = "malware IS NOT NULL AND malware <> ''"


def stats(conn: psycopg.Connection, *, days: int, now: datetime) -> dict[str, Any]:
    """The figures of the page's cards and charts over the rows that are not expired (see the module docstring)."""
    today = now.astimezone(GMT7).date()
    first_day = today - timedelta(days=days - 1)
    day_start = datetime.combine(first_day, time.min, tzinfo=GMT7)
    day_end = datetime.combine(today + timedelta(days=1), time.min, tzinfo=GMT7)
    today_start = datetime.combine(today, time.min, tzinfo=GMT7)
    params: dict[str, Any] = {
        "now": now,
        "tz": DISPLAY_TZ,
        "series_start": day_start,
        "series_end": day_end,
        "today_start": today_start,
        "today_end": day_end,
        "high": HIGH_CONFIDENCE,
        "top": TOP_MALWARE,
        "newest": NEWEST_MALWARE,
    }
    per_day = {
        (day, source): count
        for day, source, count in conn.execute(
            "SELECT (first_seen AT TIME ZONE %(tz)s)::date AS day, source, count(*) FROM ti_ioc "
            f"WHERE {_LIVE} AND first_seen >= %(series_start)s AND first_seen < %(series_end)s "
            "GROUP BY 1, 2",
            params,
        ).fetchall()
    }
    by_day = []
    for offset in range(days):
        day = first_day + timedelta(days=offset)
        counts = {source: per_day.get((day, source), 0) for source in SOURCES}
        by_day.append({"day": day.isoformat(), **counts, "total": sum(counts.values())})
    top_malware = [
        {"malware": name, "count": count}
        for name, count in conn.execute(
            f"SELECT malware, count(*) AS n FROM ti_ioc WHERE {_LIVE} AND {_NAMED} "
            "GROUP BY malware ORDER BY n DESC, malware ASC LIMIT %(top)s",
            params,
        ).fetchall()
    ]
    high, matched, imported_today = conn.execute(
        "SELECT count(*) FILTER (WHERE confidence >= %(high)s), "
        "count(*) FILTER (WHERE hit_count > 0), "
        "count(*) FILTER (WHERE imported_at >= %(today_start)s AND imported_at < %(today_end)s) "
        f"FROM ti_ioc WHERE {_LIVE}",
        params,
    ).fetchone()
    newest = [
        name
        for (name,) in conn.execute(
            f"SELECT malware FROM ti_ioc WHERE {_LIVE} AND {_NAMED} "
            "GROUP BY malware ORDER BY max(first_seen) DESC, malware ASC LIMIT %(newest)s",
            params,
        ).fetchall()
    ]
    return {
        "days": days,
        "today": today.isoformat(),
        "sources": list(SOURCES),
        "by_day": by_day,
        "top_malware": top_malware,
        "high_confidence": high,
        "matched_in_logs": matched,
        "imported_today": imported_today,
        "newest_malware": newest,
    }


# ═════════════════════════════ the lookup ═════════════════════════════════════════════════════════════════════

# A `domain` and every `*_hash` row is stored lower-case (`importer.normalise_value`); this is that rule's own test on a row's
# type, and a database test pins the two together over several types. A row matches when its value is exactly what the importer
# would have stored for the input under the row's type, so a lower-cased type is compared with the lower-cased input and any
# other with the input as it is.
_LOWERED_TYPE = "(type = 'domain' OR right(type, 5) = '_hash')"


def lookup(
    conn: psycopg.Connection, value: str, *, now: datetime
) -> tuple[str, list[dict[str, Any]], int]:
    """`(needle, rows, total)`: the rows whose value equals `value` after the importer's normalisation, newest first, at most
    `LOOKUP_MAX_ROWS` of them (`total` is how many there are). The caller gives no type, so a row is judged by its own: its
    value must equal `normalise_value(row.type, value)`. `needle` is the input trimmed, in the case it came. An IPv4 input also
    finds the `ip:port` rows of that address; the address is validated by `ipaddress` and the prefix escaped, so what reaches
    `LIKE` is digits, dots and a colon."""
    needle = normalise_value(
        "url", value
    )  # trimmed, case kept: the rule of every type that is not a domain or a hash
    lowered = normalise_value("domain", value)  # the rule of a domain and of every *_hash
    params: dict[str, Any] = {"raw": needle, "lowered": lowered, "limit": LOOKUP_MAX_ROWS}
    if needle == lowered:
        exact = "value = %(raw)s"
    else:
        exact = f"(({_LOWERED_TYPE} AND value = %(lowered)s) OR (NOT {_LOWERED_TYPE} AND value = %(raw)s))"
    branches = [f"SELECT {_IOC_COLUMNS} FROM ti_ioc WHERE {exact}"]
    if _is_ipv4(needle):
        params["prefix"] = _escape_like(needle + ":") + "%"
        branches.append(
            f"SELECT {_IOC_COLUMNS} FROM ti_ioc WHERE type = 'ip:port' AND value LIKE %(prefix)s ESCAPE '\\'"
        )
    records = (
        conn.cursor(row_factory=dict_row)
        .execute(
            f"SELECT {_IOC_COLUMNS}, count(*) OVER () AS total_rows FROM ({' UNION ALL '.join(branches)}) AS found "
            f"{_ORDER} LIMIT %(limit)s",
            params,
        )
        .fetchall()
    )
    total = records[0]["total_rows"] if records else 0
    return needle, [serve_ioc(record, now) for record in records], total


def _is_ipv4(text: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(text), ipaddress.IPv4Address)
    except ValueError:
        return False


# ═════════════════════════════ the status ═════════════════════════════════════════════════════════════════════


def _newest_log(conn: psycopg.Connection, *, only: tuple[str, ...] | None) -> dict[str, Any] | None:
    where = " WHERE status = ANY(%(only)s)" if only is not None else ""
    return (
        conn.cursor(row_factory=dict_row)
        .execute(
            f"SELECT {_LOG_COLUMNS} FROM ti_import_log{where} ORDER BY finished_at DESC, id DESC LIMIT 1",
            {"only": list(only) if only is not None else None},
        )
        .fetchone()
    )


def status(conn: psycopg.Connection, *, now: datetime) -> dict[str, Any]:
    """The newest import-log row, the newest successful one (`ok` or `partial`), and `stale`: no successful import FINISHED
    within the `STALE_AFTER` before `now` (an import that finished exactly that long ago is still fresh), or none at all.
    Newest is the last to FINISH (the id breaks a tie)."""
    latest = _newest_log(conn, only=None)
    success = _newest_log(conn, only=SUCCESS_STATUSES)
    stale = success is None or now - success["finished_at"] > STALE_AFTER
    return {
        "latest": None if latest is None else _serve_log(latest),
        "latest_success": None if success is None else _serve_log(success),
        "stale": stale,
        "stale_after_hours": int(STALE_AFTER.total_seconds() // 3600),
    }


# ═════════════════════════════ the exports ════════════════════════════════════════════════════════════════════

#: A cell that begins with one of these is run as a formula by a spreadsheet (OWASP "CSV injection").
_FORMULA_STARTS = ("=", "+", "-", "@", "\t", "\r")


def csv_cell(value: str) -> str:
    """`value` with a `'` in front when it begins with `=`, `+`, `-`, `@`, a tab or a carriage return: the spreadsheet then reads
    the cell as text. Any other text is returned as it is."""
    return "'" + value if value.startswith(_FORMULA_STARTS) else value


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list | tuple):
        return ",".join(str(item) for item in value)
    return str(value)


def export_csv(rows: Iterable[Mapping[str, Any]]) -> str:
    """The rows (as `serve_ioc` serves them) as RFC 4180 CSV: the header of `IOC_KEYS`, then a record per row with every cell
    through `csv_cell`; a cell that holds a comma, a quote or a line break is quoted by the csv module, so one row is one
    record whatever its cells hold. Tags are joined by commas into one cell; a null is an empty cell.
    """
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(IOC_KEYS)
    for row in rows:
        writer.writerow([csv_cell(_text(row[key])) for key in IOC_KEYS])
    return out.getvalue()


# A hostname: labels of ASCII letters, digits, `-` and `_` (1..63, not beginning or ending with `-`), joined by single dots, at
# most 253 characters. `fullmatch` and no `$`: a trailing line break is not a match.
_LABEL = r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
_HOSTNAME = re.compile(rf"(?=.{{1,253}}\Z){_LABEL}(?:\.{_LABEL})*", re.ASCII)
_ADDRESS_CHARS = re.compile(r"[0-9A-Fa-f:.]+")
_BRACKETED = re.compile(r"\[([0-9A-Fa-f:.]+)\]:([0-9]{1,5})")
_PORT = re.compile(r"[0-9]{1,5}")


def _port_ok(text: str) -> bool:
    return _PORT.fullmatch(text) is not None and 1 <= int(text) <= 65535


def _address(text: str) -> str | None:
    """`text` as the canonical form of the IPv4 or IPv6 address it is, or None (a scope id, a space, any other character)."""
    if not _ADDRESS_CHARS.fullmatch(text):
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _ip_without_port(value: str) -> str | None:
    """The address of an `ip:port` value: `1.2.3.4:443`, `[2001:db8::1]:443`, or an address with no port; None for anything
    else (a port that is not 1..65535, a name where the address should be, a bracket round an IPv4 address).
    """
    bare = _address(value)
    if bare is not None:
        return bare
    bracketed = _BRACKETED.fullmatch(value)
    if bracketed is not None:
        address = _address(bracketed[1])
        return (
            address if address is not None and ":" in address and _port_ok(bracketed[2]) else None
        )
    host, colon, port = value.rpartition(":")
    if colon and ":" not in host and _port_ok(port):
        address = _address(host)
        return address if address is not None and "." in address else None
    return None


def blocklist_entry(kind: str, value: str) -> str | None:
    """The line one IOC gives a blocklist, or None when it gives none. Only a `domain` (a hostname, lower-cased) and an
    `ip:port` (the address, its port dropped; IPv6 in its canonical form) give a line; a URL, a hash, an unknown type, and a value
    with anything but the characters of a hostname or an address in it give none."""
    if kind == "domain":
        return value.lower() if _HOSTNAME.fullmatch(value) else None
    if kind == "ip:port":
        return _ip_without_port(value)
    return None


def blocklist_text(rows: Iterable[Mapping[str, Any]]) -> str:
    """One value per line, each followed by a line feed, de-duplicated (the first occurrence keeps its place, so the order is the
    list's): domains and addresses only, see `blocklist_entry`. An empty text when no row gives a line.
    """
    seen: set[str] = set()
    lines: list[str] = []
    for row in rows:
        entry = blocklist_entry(row["type"], row["value"])
        if entry is not None and entry not in seen:
            seen.add(entry)
            lines.append(entry)
    return "".join(f"{line}\n" for line in lines)
