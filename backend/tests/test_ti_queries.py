"""DEC-224 T3 — the pure half of the Threat Intel read side (`app.ti.queries`): the functions that touch no database.

* **`csv_cell`**, the CSV-injection guard: a `'` before any cell that begins with `=`, `+`, `-`, `@`, a tab or a carriage
  return, and nothing else changed;
* **`export_csv`**, the CSV text: the header, the guard on EVERY cell (the tags too), RFC 4180 quoting, one record per row
  whatever a cell holds;
* **`blocklist_entry` / `blocklist_text`**, the plain-text blocklist: domains and IP addresses only, the port of an `ip:port`
  dropped, an IPv6 `[addr]:port` handled, a value with anything but the characters of a hostname or an address left out
  (so a line break in a value can never make two lines), de-duplicated;
* **`like_contains`**: `%`, `_` and `\\` in the text of a search are literal;
* **`parse_bound`**: the `from` / `to` of the list, a date or an ISO time, a time with no zone read as GMT+7.

The database half (the SQL, the routes, the roles) is `test_ti_api.py`, which needs a database; nothing here does.
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime, timedelta

import pytest
from app.ti import queries

# ── csv_cell ────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("lead", ["=", "+", "-", "@", "\t", "\r"])
def test_a_cell_that_begins_with_a_formula_character_gets_an_apostrophe(lead):
    assert queries.csv_cell(f"{lead}cmd") == f"'{lead}cmd"


def test_the_classic_payloads_are_neutralised():
    assert queries.csv_cell("=cmd|' /C calc'!A0") == "'=cmd|' /C calc'!A0"
    assert queries.csv_cell('=HYPERLINK("http://x","y")') == "'" + '=HYPERLINK("http://x","y")'
    assert queries.csv_cell("@SUM(1+1)*cmd|' /C calc'!A0") == "'@SUM(1+1)*cmd|' /C calc'!A0"
    assert queries.csv_cell("-2+3+cmd|' /C calc'!A0") == "'-2+3+cmd|' /C calc'!A0"
    assert queries.csv_cell("+1+1") == "'+1+1"


@pytest.mark.parametrize(
    "text",
    ["", "abc", "a=b", "a+b", "x-y", "user@example.com", " =x", "'=x", "1.2.3.4", "0", "é=", "\nx"],
)
def test_any_other_cell_is_returned_unchanged(text):
    assert queries.csv_cell(text) == text


# ── export_csv ──────────────────────────────────────────────────────────────────────────────


def row(**over):
    base = {key: None for key in queries.IOC_KEYS}
    base.update(
        id=1,
        source="threatfox",
        type="domain",
        value="c2.example.com",
        tags=[],
        expired=False,
        hit_count=0,
    )
    base.update(over)
    return base


def read_back(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text, newline="")))


def test_the_header_is_the_lists_columns_in_the_lists_order():
    (header,) = read_back(queries.export_csv([]))
    assert header == list(queries.IOC_KEYS)


def test_a_row_is_written_with_every_column_and_none_is_empty():
    text = queries.export_csv(
        [
            row(
                id=7,
                confidence=75,
                tags=["a", "b"],
                first_seen="2026-11-17T06:12:44+00:00",
                expired=True,
            )
        ]
    )
    header, record = read_back(text)
    cells = dict(zip(header, record, strict=True))
    assert cells["id"] == "7"
    assert cells["confidence"] == "75"
    assert cells["tags"] == "a,b"
    assert cells["first_seen"] == "2026-11-17T06:12:44+00:00"
    assert cells["expired"] == "true"
    assert cells["malware"] == "" and cells["last_hit"] == ""
    assert cells["hit_count"] == "0"


def test_every_cell_is_guarded_the_tags_too():
    text = queries.export_csv(
        [
            row(
                value="=cmd|' /C calc'!A0",
                malware="+SUM(1)",
                threat="-2+3",
                reference="@SUM(A1)",
                tags=["=x", "ok"],
            ),
            row(id=2, value="\t=tab", malware="\r=cr", threat="plain"),
        ]
    )
    header, first, second = read_back(text)
    one = dict(zip(header, first, strict=True))
    two = dict(zip(header, second, strict=True))
    assert one["value"] == "'=cmd|' /C calc'!A0"
    assert one["malware"] == "'+SUM(1)"
    assert one["threat"] == "'-2+3"
    assert one["reference"] == "'@SUM(A1)"
    assert one["tags"] == "'=x,ok"
    assert two["value"] == "'\t=tab"
    assert two["malware"] == "'\r=cr"
    assert two["threat"] == "plain"
    for record in (first, second):  # nothing a spreadsheet would run, anywhere in a data row
        assert not [cell for cell in record if cell.startswith(("=", "+", "-", "@", "\t", "\r"))]


def test_a_cell_with_a_comma_a_quote_or_a_line_break_is_quoted_and_stays_one_record():
    text = queries.export_csv(
        [
            row(value='say "hi", then\nleave', malware="a\r\nb", threat="x,y"),
            row(id=2, value="second"),
        ]
    )
    records = read_back(text)
    assert len(records) == 3  # the header and the two rows, whatever the cells hold
    header = records[0]
    first = dict(zip(header, records[1], strict=True))
    assert first["value"] == 'say "hi", then\nleave'
    assert first["malware"] == "a\r\nb"
    assert first["threat"] == "x,y"
    assert records[2][header.index("value")] == "second"


def test_the_records_end_with_crlf_as_rfc_4180_says():
    text = queries.export_csv([row()])
    assert text.endswith("\r\n")
    assert text.count("\r\n") == 2


# ── blocklist ───────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("kind", "value", "expected"),
    [
        ("domain", "c2.example.com", "c2.example.com"),
        ("domain", "C2.Example.COM", "c2.example.com"),
        ("domain", "example.com", "example.com"),
        ("domain", "localhost", "localhost"),
        ("domain", "xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("domain", "a-b.c_d.example.net", "a-b.c_d.example.net"),
        ("ip:port", "192.0.2.10:443", "192.0.2.10"),
        ("ip:port", "198.51.100.24:8080", "198.51.100.24"),
        ("ip:port", "203.0.113.5:1", "203.0.113.5"),
        ("ip:port", "203.0.113.5:65535", "203.0.113.5"),
        ("ip:port", "192.0.2.10", "192.0.2.10"),
        ("ip:port", "[2001:db8::1]:443", "2001:db8::1"),
        ("ip:port", "[2001:0DB8:0000:0000:0000:0000:0000:0001]:8080", "2001:db8::1"),
        ("ip:port", "2001:db8::1", "2001:db8::1"),
    ],
)
def test_a_domain_or_an_address_gives_its_line(kind, value, expected):
    assert queries.blocklist_entry(kind, value) == expected


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("url", "http://c2.example.com/a"),
        ("url", "c2.example.com"),
        ("sha256_hash", "a" * 64),
        ("md5_hash", "d41d8cd98f00b204e9800998ecf8427e"),
        ("", "c2.example.com"),
        ("something_new", "c2.example.com"),
        # a line break in a value must never become a second line, a separator never part of a name
        ("domain", "c2.example.com\nevil.example.net"),
        ("domain", "c2.example.com\r\nevil.example.net"),
        ("domain", "c2.example.com\n"),
        ("domain", "\nc2.example.com"),
        ("domain", "c2.example.com\x00"),
        ("domain", "c2.example.com\u2028evil.example.net"),
        ("domain", "c2.example.com evil.example.net"),
        ("domain", " c2.example.com"),
        ("domain", "c2.example.com "),
        ("domain", "c2.example.com;rm -rf"),
        ("domain", "c2.example.com|calc"),
        ("domain", "<script>.example.com"),
        ("domain", "c2.example.com/path"),
        ("domain", "c2.example.com:443"),
        ("domain", "user@c2.example.com"),
        ("domain", "=cmd.example.com"),
        ("domain", "*.example.com"),
        ("domain", "bücher.example"),
        ("domain", "c2.example.com."),
        ("domain", ".example.com"),
        ("domain", "a..example.com"),
        ("domain", "-a.example.com"),
        ("domain", "a-.example.com"),
        ("domain", "a" * 64 + ".example.com"),
        ("domain", ("a" * 60 + ".") * 5 + "com"),
        ("domain", ""),
        ("ip:port", "192.0.2.10:443\n198.51.100.1:80"),
        ("ip:port", "192.0.2.10:443 "),
        ("ip:port", "192.0.2.10:"),
        ("ip:port", "192.0.2.10:0x1bb"),
        ("ip:port", "192.0.2.10:65536"),
        ("ip:port", "192.0.2.10:-1"),
        ("ip:port", "192.0.2.10:443:80"),
        ("ip:port", "192.0.2.256:443"),
        ("ip:port", "192.0.2:443"),
        ("ip:port", "192.0.02.1:443"),  # a leading zero is not an address
        ("ip:port", "c2.example.com:443"),
        ("ip:port", "[2001:db8::1]"),
        ("ip:port", "[2001:db8::1]:"),
        ("ip:port", "[2001:db8::1]:99999"),
        ("ip:port", "[2001:db8::1%eth0]:443"),
        ("ip:port", "[192.0.2.1]:443"),
        ("ip:port", "[2001:db8::1]:443\n"),
        ("ip:port", "fe80::1%eth0"),
        ("ip:port", ":443"),
        ("ip:port", ""),
    ],
)
def test_anything_that_is_not_a_domain_or_an_address_is_left_out(kind, value):
    assert queries.blocklist_entry(kind, value) is None


def test_the_blocklist_is_one_value_per_line_and_de_duplicated_in_the_order_met():
    rows = [
        row(type="ip:port", value="192.0.2.10:443"),
        row(type="domain", value="c2.example.com"),
        row(type="ip:port", value="192.0.2.10:8080"),  # the same address, another port
        row(type="domain", value="C2.EXAMPLE.COM"),  # the same name, spelt another way
        row(type="url", value="http://c2.example.com/x"),
        row(type="sha256_hash", value="b" * 64),
        row(type="domain", value="evil.example.net\nc2.example.com"),
        row(type="ip:port", value="[2001:db8::1]:443"),
        row(type="ip:port", value="2001:0db8::1"),  # the same IPv6 address, spelt another way
        row(type="domain", value="payload.example.net"),
    ]
    text = queries.blocklist_text(rows)
    assert text == "192.0.2.10\nc2.example.com\n2001:db8::1\npayload.example.net\n"
    assert text.splitlines() == text.rstrip("\n").split("\n")  # no line holds a line break


def test_an_empty_blocklist_is_an_empty_text():
    assert queries.blocklist_text([]) == ""
    assert queries.blocklist_text([row(type="url", value="http://x.example.com/")]) == ""


# ── like_contains ───────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("text", "pattern"),
    [
        ("abc", "%abc%"),
        ("100%", "%100\\%%"),
        ("a_b", "%a\\_b%"),
        ("back\\slash", "%back\\\\slash%"),
        ("%_\\", "%\\%\\_\\\\%"),
        ("'; drop table ti_ioc; --", "%'; drop table ti\\_ioc; --%"),
        ("%s %(x)s", "%\\%s \\%(x)s%"),
    ],
)
def test_percent_underscore_and_backslash_are_literal_in_a_search(text, pattern):
    assert queries.like_contains(text) == pattern


def test_the_escaped_text_never_ends_in_a_lone_escape_character():
    # `LIKE '...\\'` is a database error ("must not end with escape character"): every backslash is doubled.
    pattern = queries.like_contains("ends with a backslash\\")
    assert pattern.endswith("\\\\%")


# ── parse_bound ─────────────────────────────────────────────────────────────────────────────

GMT7 = timedelta(hours=7)


def utc(*args: int) -> datetime:
    return datetime(*args, tzinfo=UTC)


def test_a_date_is_the_whole_day_in_gmt_plus_7():
    assert queries.parse_bound("2026-11-17", upper=False) == utc(2026, 11, 16, 17, 0, 0)
    # the upper bound is exclusive: the first instant of the NEXT day, so the day itself is all in
    assert queries.parse_bound("2026-11-17", upper=True) == utc(2026, 11, 17, 17, 0, 0)


@pytest.mark.parametrize(
    "text", ["2026-11-17T08:30:00", "2026-11-17 08:30:00", "2026-11-17T08:30", "2026-11-17 08:30"]
)
def test_a_time_with_no_zone_is_read_as_gmt_plus_7(text):
    assert queries.parse_bound(text, upper=False) == utc(2026, 11, 17, 1, 30, 0)


def test_a_time_with_a_zone_is_the_instant_it_names():
    assert queries.parse_bound("2026-11-17T08:30:00+00:00", upper=False) == utc(2026, 11, 17, 8, 30)
    assert queries.parse_bound("2026-11-17T08:30:00Z", upper=False) == utc(2026, 11, 17, 8, 30)
    assert queries.parse_bound("2026-11-17T08:30:00+07:00", upper=False) == utc(2026, 11, 17, 1, 30)
    assert queries.parse_bound("2026-11-17T08:30:00-05:00", upper=False) == utc(
        2026, 11, 17, 13, 30
    )
    assert queries.parse_bound("2026-11-17T08:30:00.250000Z", upper=False) == utc(
        2026, 11, 17, 8, 30, 0, 250000
    )


def test_a_time_as_an_upper_bound_is_inclusive_and_so_exclusive_a_microsecond_later():
    assert queries.parse_bound("2026-11-17T08:30:00Z", upper=True) == utc(2026, 11, 17, 8, 30, 0, 1)


@pytest.mark.parametrize(
    "text",
    [
        "",
        " ",
        "yesterday",
        "now",
        "1e3",
        "1763370000",
        "2026-13-01",
        "2026-02-30",
        "2026-11-17T25:00:00",
        "2026-11-17T08:30:00+25:00",
        "2026-11-17T08:30:00+0700",
        "20261117",
        "2026-W46-1",
        "17/11/2026",
        "2026-11-17T",
        "2026-11-17T08:30:00 +07:00",
        "2026-11-17\n",
        "2026-11-17T08:30:00Z\n",
        "２０２６-11-17",
        "2026-11-17; drop table ti_ioc",
        "9999-12-31",  # the day after it is not a date
        "0001-01-01T00:00:00+14:00",  # no UTC form
    ],
)
def test_anything_else_is_refused(text):
    with pytest.raises(ValueError):
        queries.parse_bound(text, upper=text in {"9999-12-31"})
    with pytest.raises(ValueError):
        queries.parse_bound(text, upper=True)


# ── the shape of the module ─────────────────────────────────────────────────────────────────


def test_the_cap_of_an_export_is_above_what_30_days_of_the_feed_leave_unexpired():
    # three sources of 100 rows a day for 30 days: 9 000 rows; the cap leaves room above that
    assert queries.EXPORT_MAX_ROWS >= 10_000


def test_the_bounds_of_the_routes_are_the_importers_own_ceilings():
    from app.ti import importer

    assert queries.VALUE_MAX == importer.VALUE_MAX_BYTES
    assert queries.MALWARE_MAX == importer.MALWARE_MAX_BYTES
    assert queries.TYPE_MAX == importer.TYPE_MAX_BYTES


def test_the_read_side_imports_nothing_that_can_open_a_connection():
    """A value is data: nothing in the read side resolves, fetches or previews it (the brief's A2/A3). The two modules import no
    networking, no subprocess and no HTTP client, so no route of this module can make an outbound call.
    """
    import ast
    from pathlib import Path

    banned = {
        "socket", "ssl", "urllib", "http", "httpx", "requests", "aiohttp", "subprocess", "ftplib", "smtplib",
        "telnetlib", "asyncio", "dns", "webbrowser", "os",
    }  # fmt: skip
    root = Path(queries.__file__).resolve().parents[1]
    for path in (root / "ti" / "queries.py", root / "web" / "routers" / "ti.py"):
        tree = ast.parse(path.read_text())
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names.add((node.module or "").split(".")[0])
        assert not names & banned, (path.name, names & banned)
