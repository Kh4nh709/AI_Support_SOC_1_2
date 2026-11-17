"""DEC-224 T2 — the Threat Intel importer (`app.ti.importer`) and its command (`scripts/ti_import.py`).

The importer turns one day's abuse.ch CSV into rows of `ti_ioc` (migration 026) and writes one `ti_import_log` row
per run, a failed run included. Three layers, three kinds of test:

* **parsing, no database** (`parse_row`, `normalise_value`, `read_file`): every field's rule, in BYTES where the
  spec says bytes, every reason of the closed list `REASONS` produced by a test of its own, the CSV
  mechanics (quoted comma, quoted newline, BOM, CRLF, a bad byte, a NUL, a field over the csv module's limit) and
  the line number of the record's FIRST line;
* **loading, a scratch database** (`import_file`, marked `db`): the upsert (the same file twice, two days sharing
  an IOC, a key repeated inside one file), the log row of each outcome, `finished_at` never before `started_at`,
  one transaction (a database error loads nothing and is still logged), and the same under the app's role
  `app_rw`, which has no DELETE;
* **the command** (`main` of `scripts/ti_import.py`, in this process and as a plain-path subprocess started from
  another directory): arguments, exit codes, the DSN read from the env file only and never printed, a database
  that is down.

The scratch database is built once for the module (`scratch_database`); each test empties the two tables first.
No test prints a DSN, and the sample file `fixtures/ti/ioc_sample.csv` holds made-up values only.
"""

from __future__ import annotations

import csv
import importlib.util
import io
import os
import subprocess
import sys
import time
import urllib.parse
from datetime import UTC, date, datetime, timedelta, timezone
from pathlib import Path

import psycopg
import pytest
from app.ti import importer
from app.ti.importer import (
    COLUMNS,
    EXPIRES_AFTER,
    REASONS,
    HeaderError,
    Ioc,
    RowError,
    import_file,
    normalise_value,
    parse_row,
    read_file,
)
from psycopg.rows import dict_row

from tests import conftest
from tests.scratch_db import scratch_database

needs_db = pytest.mark.db

SAMPLE = Path(__file__).resolve().parent / "fixtures" / "ti" / "ioc_sample.csv"
SCRIPT = conftest.REPO_ROOT / "scripts" / "ti_import.py"

NOW = datetime(2026, 11, 17, 7, 5, 0, tzinfo=UTC)
LATER = NOW + timedelta(days=1)
#: What the importer's clock says after the run, so `finished_at` is exact in the tests that read it.
FINISH = NOW + timedelta(seconds=3)
SENTINEL = "SENTINEL-ROW-TEXT-7f3a"


def _clock(at: datetime = FINISH):
    return lambda: at


def good(**over: str) -> dict[str, str]:
    """One valid ThreatFox row (documentation address range, example name), fields overridden by name."""
    row = {
        "source": "threatfox",
        "first_seen": "2026-11-17 08:30:15 UTC",
        "type": "ip:port",
        "value": "192.0.2.10:443",
        "threat": "botnet_cc",
        "malware": "win.example_rat",
        "confidence": "75",
        "tags": "example_rat,c2",
        "reference": "https://threatfox.abuse.ch/ioc/90000001/",
    }
    row.update(over)
    return row


def write_csv(path: Path, rows, header=COLUMNS) -> Path:
    """`rows` are dicts (written in `header`'s order) or plain lists; the csv module does the quoting."""
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(header)
        for row in rows:
            writer.writerow([row[name] for name in header] if isinstance(row, dict) else row)
    return path


def write_raw(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def line(row: dict[str, str]) -> str:
    """One record as the csv module writes it (quoted where it must be), no line end."""
    out = io.StringIO()
    csv.writer(out, lineterminator="").writerow([row[name] for name in COLUMNS])
    return out.getvalue()


HEAD = ",".join(COLUMNS)


def reason_of(row: dict[str, str]) -> str:
    with pytest.raises(RowError) as caught:
        parse_row(row)
    return caught.value.reason


# ═════════════════════════════ the vocabulary ═════════════════════════════════════════════════════════════════


def test_the_names_the_other_tasks_use():
    assert COLUMNS == (
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
    assert EXPIRES_AFTER == timedelta(days=30)
    assert importer.SOURCES == ("threatfox", "urlhaus", "malwarebazaar")
    assert len(set(REASONS)) == len(REASONS)


def test_a_row_error_names_a_reason_of_the_closed_list_only():
    assert RowError("value_empty").reason == "value_empty"
    with pytest.raises(ValueError):
        RowError("some reason of my own")


# ═════════════════════════════ parse_row: the good row ════════════════════════════════════════════════════════


def test_a_valid_row_is_normalised_into_an_ioc():
    ioc = parse_row(good())
    assert ioc == Ioc(
        source="threatfox",
        first_seen=datetime(2026, 11, 17, 8, 30, 15, tzinfo=UTC),
        type="ip:port",
        value="192.0.2.10:443",
        threat="botnet_cc",
        malware="win.example_rat",
        confidence=75,
        tags=("example_rat", "c2"),
        reference="https://threatfox.abuse.ch/ioc/90000001/",
    )
    assert ioc.key == ("threatfox", "ip:port", "192.0.2.10:443")


@pytest.mark.parametrize(
    "text",
    [
        "2026-11-17 08:30:15",
        "2026-11-17 08:30:15 UTC",
        "  2026-11-17 08:30:15 UTC  ",
        "2026-11-17T08:30:15",
        "2026-11-17T08:30:15Z",
        "2026-11-17T08:30:15+00:00",
        "2026-11-17T15:30:15+07:00",
        "2026-11-17 15:30:15+07:00",
    ],
)
def test_first_seen_in_both_feed_shapes_and_iso_8601_is_read_as_utc(text):
    got = parse_row(good(first_seen=text)).first_seen
    assert got == datetime(2026, 11, 17, 8, 30, 15, tzinfo=UTC)
    assert got.utcoffset() == timedelta(0)


def test_an_empty_confidence_is_none_and_the_bounds_are_zero_and_one_hundred():
    assert parse_row(good(confidence="")).confidence is None
    assert parse_row(good(confidence="   ")).confidence is None
    assert parse_row(good(confidence="0")).confidence == 0
    assert parse_row(good(confidence="100")).confidence == 100
    assert parse_row(good(confidence=" 75 ")).confidence == 75


def test_the_type_is_lower_cased_and_a_new_type_is_not_refused():
    assert parse_row(good(type=" IP:Port ")).type == "ip:port"
    assert parse_row(good(type="sha3-384_hash", value="ab" * 48)).type == "sha3-384_hash"
    assert parse_row(good(type="Some.New_type:v2")).type == "some.new_type:v2"


@pytest.mark.parametrize(
    ("type_", "value", "expected"),
    [
        ("domain", "C2.Example.COM", "c2.example.com"),
        ("DOMAIN", " Example.NET ", "example.net"),
        ("sha256_hash", "ABCDEF" + "0" * 58, "abcdef" + "0" * 58),
        ("md5_hash", "0123456789ABCDEF0123456789ABCDEF", "0123456789abcdef0123456789abcdef"),
        (
            "sha1_hash",
            "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
            "abcdef0123456789abcdef0123456789abcdef01",
        ),
        ("url", "http://Example.COM/Path/File.EXE?Q=A", "http://Example.COM/Path/File.EXE?Q=A"),
        ("ip:port", "192.0.2.10:443", "192.0.2.10:443"),
        ("url", "  http://example.com/x  ", "http://example.com/x"),
    ],
)
def test_domain_and_every_hash_are_lower_cased_a_url_keeps_its_case(type_, value, expected):
    assert normalise_value(type_, value) == expected
    assert parse_row(good(type=type_, value=value)).value == expected


def test_normalise_value_is_the_one_function_a_lookup_can_reuse():
    # The spelling of the type does not matter to it: the lookup passes what the page sends.
    assert normalise_value(" Domain ", " EXAMPLE.com ") == "example.com"
    assert normalise_value("SHA256_HASH", "AB") == "ab"
    assert normalise_value("URL", "HTTP://X.example.com/A") == "HTTP://X.example.com/A"


def test_the_source_is_trimmed_and_lower_cased():
    assert parse_row(good(source=" ThreatFox ")).source == "threatfox"
    assert parse_row(good(source="URLHAUS")).source == "urlhaus"
    assert parse_row(good(source="malwarebazaar")).source == "malwarebazaar"


def test_the_descriptive_fields_are_trimmed_and_empty_ones_are_none():
    ioc = parse_row(good(threat="  ", malware=" win.x ", reference=""))
    assert (ioc.threat, ioc.malware, ioc.reference) == (None, "win.x", None)


def test_tags_are_split_on_commas_trimmed_and_empties_dropped():
    assert parse_row(good(tags="a, b ,,c,")).tags == ("a", "b", "c")
    assert parse_row(good(tags="")).tags == ()
    assert parse_row(good(tags=" , ,")).tags == ()
    assert parse_row(good(tags="one")).tags == ("one",)


def test_a_value_is_trimmed_and_a_comma_or_quote_inside_it_is_data():
    assert parse_row(good(type="url", value=" \tx.example.com\n")).value == "x.example.com"
    value = 'http://example.com/a,b?q="c"'
    assert parse_row(good(type="url", value=value)).value == value


def test_a_row_with_missing_keys_or_none_values_is_a_bad_row_not_a_crash():
    assert reason_of({}) == "source_invalid"
    assert reason_of({**good(), "value": None}) == "value_empty"


# ═════════════════════════════ parse_row: every bad row, one reason each ══════════════════════════════════════
#
# (the fields to override, the reason). The list is the closed set REASONS, less `row_malformed`, which is a
# record shape and is produced by `read_file` (tested below); `test_every_reason_has_a_test` holds the two together.

THREE_BYTE = "€"  # U+20AC, three bytes in UTF-8
TWO_BYTE = "é"
BAD_ROWS = [
    # source
    ({"source": "virustotal"}, "source_invalid"),
    ({"source": ""}, "source_invalid"),
    # first_seen
    ({"first_seen": ""}, "first_seen_missing"),
    ({"first_seen": "   "}, "first_seen_missing"),
    ({"first_seen": "yesterday"}, "first_seen_invalid"),
    ({"first_seen": "2026-13-45 99:00:00"}, "first_seen_invalid"),
    ({"first_seen": "2026-11-17 08:30:15 PST"}, "first_seen_invalid"),
    ({"first_seen": "0001-01-01T00:00:00+14:00"}, "first_seen_invalid"),  # before the epoch of UTC
    ({"first_seen": "9999-12-31 23:59:59"}, "first_seen_invalid"),  # ahead of the clock by years
    # type
    ({"type": ""}, "type_invalid"),
    ({"type": "ip port"}, "type_invalid"),
    ({"type": "tyé"}, "type_invalid"),
    ({"type": "a" * 65}, "type_too_long"),
    # value
    ({"value": ""}, "value_empty"),
    ({"value": "  \t "}, "value_empty"),
    ({"type": "url", "value": "a" * 2049}, "value_too_long"),
    ({"type": "url", "value": "a" * 5000}, "value_too_long"),
    ({"type": "url", "value": THREE_BYTE * 683}, "value_too_long"),  # 683 characters, 2 049 bytes
    ({"type": "url", "value": "a" + THREE_BYTE * 683}, "value_too_long"),
    # the bound counts the NORMALISED value: 1 024 of U+0130 are 2 048 bytes, and lower-case to 3 072
    ({"type": "domain", "value": "İ" * 1024}, "value_too_long"),
    ({"value": "1.2.3.4\x00:80"}, "value_control_char"),
    ({"value": "1.2.3.4\n:80"}, "value_control_char"),
    ({"value": "1.2.3.4\r:80"}, "value_control_char"),
    ({"value": "1.2.3.4\t:80"}, "value_control_char"),
    ({"value": "1.2.3.4\x1b[31m:80"}, "value_control_char"),
    ({"value": "1.2.3.4\x7f:80"}, "value_control_char"),
    ({"value": "1.2.3.4\x85:80"}, "value_control_char"),
    ({"value": "1.2.3.4\u2028:80"}, "value_control_char"),
    ({"value": "1.2.3.4\u2029:80"}, "value_control_char"),
    # threat, malware
    ({"threat": "t" * 257}, "threat_too_long"),
    ({"threat": THREE_BYTE * 86}, "threat_too_long"),  # 86 characters, 258 bytes
    ({"malware": "m" * 257}, "malware_too_long"),
    ({"malware": TWO_BYTE * 129}, "malware_too_long"),  # 129 characters, 258 bytes
    # confidence
    ({"confidence": "abc"}, "confidence_not_integer"),
    ({"confidence": "7.5"}, "confidence_not_integer"),
    ({"confidence": "1e2"}, "confidence_not_integer"),
    ({"confidence": "+5"}, "confidence_not_integer"),
    ({"confidence": "٣"}, "confidence_not_integer"),  # an Arabic-Indic digit is not a digit here
    ({"confidence": "101"}, "confidence_out_of_range"),
    ({"confidence": "-1"}, "confidence_out_of_range"),
    ({"confidence": "9" * 5000}, "confidence_out_of_range"),
    # tags
    ({"tags": ",".join(f"t{i}" for i in range(33))}, "tags_too_many"),
    ({"tags": "t" * 65}, "tag_too_long"),
    ({"tags": "ok," + THREE_BYTE * 22}, "tag_too_long"),  # 22 characters, 66 bytes
    # reference
    ({"reference": "https://threatfox.abuse.ch/" + "r" * 2048}, "reference_too_long"),
    ({"reference": THREE_BYTE * 683}, "reference_too_long"),
    # a control character in any descriptive field
    ({"threat": "a\x00b"}, "text_control_char"),
    ({"malware": "a\nb"}, "text_control_char"),
    ({"tags": "a,b\tc"}, "text_control_char"),
    ({"reference": "https://threatfox.abuse.ch/\x00"}, "text_control_char"),
    ({"reference": "https://threatfox.abuse.ch/\r\nX: y"}, "text_control_char"),
    # a byte that was not UTF-8 arrives as a lone surrogate (read_file decodes with surrogateescape)
    ({"malware": "win.\udcff"}, "invalid_utf8"),
    ({"value": "1.2.3.4\udc80:80"}, "invalid_utf8"),
]


@pytest.mark.parametrize(("over", "reason"), BAD_ROWS)
def test_a_bad_row_raises_its_reason(over, reason):
    assert reason_of(good(**over)) == reason


def test_every_reason_has_a_test():
    tested = {reason for _, reason in BAD_ROWS} | {"row_malformed"}
    assert tested == set(REASONS)


def test_a_first_seen_more_than_a_day_ahead_of_the_run_is_invalid_and_exactly_a_day_is_not():
    day = timedelta(days=1)
    edge = (NOW + day).strftime("%Y-%m-%d %H:%M:%S")
    beyond = (NOW + day + timedelta(seconds=1)).strftime("%Y-%m-%d %H:%M:%S")
    assert parse_row(good(first_seen=edge), now=NOW).first_seen == NOW + day
    with pytest.raises(RowError) as caught:
        parse_row(good(first_seen=beyond), now=NOW)
    assert caught.value.reason == "first_seen_invalid"
    assert parse_row(good(first_seen="2020-01-01 00:00:00"), now=NOW).first_seen.year == 2020


def test_read_file_judges_first_seen_against_the_now_it_is_given(tmp_path):
    path = write_csv(tmp_path / "f.csv", [good(first_seen="2026-11-17 08:30:15")])
    assert read_file(path, now=NOW).errors == []
    assert read_file(path, now=NOW - timedelta(days=3)).errors == [(2, "first_seen_invalid")]


def test_the_bounds_are_in_bytes_and_a_row_at_the_bound_is_accepted():
    ok = parse_row(
        good(
            type="url",
            value="a" * 2048,
            threat="t" * 256,
            malware=TWO_BYTE * 128,
            reference="r" * 2048,
            tags=",".join(["t" * 64] * 32),
        )
    )
    assert len(ok.value) == 2048 and len(ok.tags) == 32
    assert len(parse_row(good(type="url", value=THREE_BYTE * 682 + "ab")).value.encode()) == 2048
    assert len(parse_row(good(type="a" * 64)).type) == 64
    assert parse_row(good(threat=THREE_BYTE * 85)).threat == THREE_BYTE * 85  # 255 bytes
    assert parse_row(good(tags=THREE_BYTE * 21)).tags == (THREE_BYTE * 21,)  # 63 bytes
    # trailing empties do not count toward the 32
    assert len(parse_row(good(tags=",".join(f"t{i}" for i in range(32)) + ",,")).tags) == 32


def test_the_first_problem_in_column_order_names_the_reason():
    assert reason_of(good(source="x", first_seen="", value="")) == "source_invalid"
    assert reason_of(good(first_seen="", value="")) == "first_seen_missing"
    assert reason_of(good(value="", confidence="abc")) == "value_empty"


# ═════════════════════════════ read_file: the CSV mechanics ═══════════════════════════════════════════════════


def test_the_sample_file_reads_whole_in_both_date_shapes_with_every_feed_type():
    parsed = read_file(SAMPLE)
    assert parsed.errors == []
    assert parsed.total == 12 == len(parsed.iocs)
    assert {i.source for i in parsed.iocs} == {"threatfox", "urlhaus", "malwarebazaar"}
    assert {i.type for i in parsed.iocs} == {"ip:port", "domain", "url", "sha256_hash"}
    assert all(i.first_seen.tzinfo is not None for i in parsed.iocs)
    assert [i.confidence for i in parsed.iocs if i.source == "malwarebazaar"] == [None] * 4
    domains = [i.value for i in parsed.iocs if i.type == "domain"]
    assert domains == ["c2.example.com", "payload.example.net"]
    urls = {i.value for i in parsed.iocs if i.type == "url"}
    assert "https://download.example.net/Setup.EXE" in urls  # a URL keeps its case
    assert all(i.value == i.value.lower() for i in parsed.iocs if i.type == "sha256_hash")


def test_a_file_missing_a_column_is_a_header_error_naming_the_columns(tmp_path):
    header = [c for c in COLUMNS if c not in ("reference", "malware")]
    path = write_csv(tmp_path / "f.csv", [{c: good()[c] for c in header}], header=header)
    with pytest.raises(HeaderError) as caught:
        read_file(path)
    assert caught.value.missing == ("malware", "reference")  # in COLUMNS' order


def test_an_empty_file_is_a_header_error_with_every_column_missing(tmp_path):
    with pytest.raises(HeaderError) as caught:
        read_file(write_raw(tmp_path / "f.csv", b""))
    assert caught.value.missing == COLUMNS


def test_a_file_that_is_not_csv_at_all_is_a_header_error(tmp_path):
    with pytest.raises(HeaderError):
        read_file(write_raw(tmp_path / "f.csv", b"\x00\x01\xff\xfe garbage\n1,2,3\n"))


def test_a_header_only_file_has_no_rows(tmp_path):
    parsed = read_file(write_csv(tmp_path / "f.csv", []))
    assert (parsed.iocs, parsed.errors, parsed.total) == ([], [], 0)


def test_the_column_order_is_free_and_extra_columns_are_ignored(tmp_path):
    header = ["extra", *reversed(COLUMNS), "another extra"]
    rows = [{**good(), "extra": "x", "another extra": "y"}]
    parsed = read_file(write_csv(tmp_path / "f.csv", rows, header=header))
    assert parsed.errors == [] and parsed.iocs[0].value == "192.0.2.10:443"
    assert parsed.iocs[0].threat == "botnet_cc"


def test_the_header_names_are_trimmed(tmp_path):
    header = [f" {c} " for c in COLUMNS]
    row = [good()[c] for c in COLUMNS]
    parsed = read_file(write_csv(tmp_path / "f.csv", [row], header=header))
    assert parsed.errors == [] and len(parsed.iocs) == 1


def test_a_byte_order_mark_and_crlf_line_ends_are_read(tmp_path):
    text = HEAD + "\r\n" + line(good()) + "\r\n"
    path = write_raw(tmp_path / "f.csv", b"\xef\xbb\xbf" + text.encode())
    parsed = read_file(path)
    assert parsed.errors == [] and parsed.iocs[0].source == "threatfox"


def test_a_quoted_comma_stays_in_its_field(tmp_path):
    row = good(type="url", value="http://example.com/a,b,c", malware="win.x,y", tags="a,b,c")
    parsed = read_file(write_csv(tmp_path / "f.csv", [row]))
    assert parsed.errors == []
    assert parsed.iocs[0].value == "http://example.com/a,b,c"
    assert parsed.iocs[0].malware == "win.x,y"
    assert parsed.iocs[0].tags == (
        "a",
        "b",
        "c",
    )  # the quoted field is one CSV field; the tags split on commas


def test_a_record_that_spans_lines_is_one_bad_row_counted_as_the_lines_it_swallows(tmp_path):
    """No legitimate record spans lines (every field refuses a newline), so a quoted newline makes the whole record
    ONE bad row `row_malformed`, whatever field it is in; it counts as the physical lines it takes, so the totals
    reflect the lines lost: `total = good + error_count`."""
    rows = [
        good(value="192.0.2.1:1"),  # line 2
        good(value="192.0.2.2\n:2"),  # lines 3-4: a newline in a value
        good(value="192.0.2.3:3"),  # line 5
        good(threat="a\nb\nc", value="192.0.2.4:4"),  # lines 6-8
        good(value="192.0.2.5:5", first_seen="never"),  # line 9
    ]
    parsed = read_file(write_csv(tmp_path / "f.csv", rows))
    assert [i.value for i in parsed.iocs] == ["192.0.2.1:1", "192.0.2.3:3"]
    assert parsed.errors == [
        (3, "row_malformed"),
        (6, "row_malformed"),
        (9, "first_seen_invalid"),
    ]
    assert parsed.spans == {3: 2, 6: 3}
    assert parsed.error_count == 2 + 3 + 1
    assert parsed.total == 8 == len(parsed.iocs) + parsed.error_count


def test_blank_lines_are_skipped_and_not_counted(tmp_path):
    one, bad = line(good(value="192.0.2.1:1")), line(good(value=""))
    path = write_raw(tmp_path / "f.csv", f"{HEAD}\n\n{one}\n\n\n{bad}\n\n".encode())
    parsed = read_file(path)
    assert parsed.total == 2 and len(parsed.iocs) == 1
    assert parsed.errors == [(6, "value_empty")]


def test_a_record_with_too_few_or_too_many_fields_is_row_malformed(tmp_path):
    ok = [good()[c] for c in COLUMNS]
    rows = [ok[:-1], ok + ["extra"], ok, ["only one"]]
    parsed = read_file(write_csv(tmp_path / "f.csv", rows))
    assert parsed.errors == [(2, "row_malformed"), (3, "row_malformed"), (5, "row_malformed")]
    assert len(parsed.iocs) == 1 and parsed.total == 4


def test_a_byte_that_is_not_utf8_makes_that_row_bad_and_no_other(tmp_path):
    one = line(good(value="192.0.2.1:1")).encode()
    broken = line(good(value="192.0.2.2:2", malware="win.XX")).encode().replace(b"XX", b"\xff\xfe")
    path = write_raw(tmp_path / "f.csv", HEAD.encode() + b"\n" + broken + b"\n" + one + b"\n")
    parsed = read_file(path)
    assert [i.value for i in parsed.iocs] == ["192.0.2.1:1"]
    assert parsed.errors == [(2, "invalid_utf8")]


def test_a_nul_byte_in_the_file_makes_that_row_bad_and_no_other(tmp_path):
    one = line(good(value="192.0.2.1:1")).encode()
    nul = line(good(value="192.0.2.2:2")).encode().replace(b"192.0.2.2", b"192.0\x002.2")
    parsed = read_file(
        write_raw(tmp_path / "f.csv", HEAD.encode() + b"\n" + nul + b"\n" + one + b"\n")
    )
    assert [i.value for i in parsed.iocs] == ["192.0.2.1:1"]
    assert parsed.errors == [(2, "value_control_char")]


def test_a_field_of_five_thousand_characters_is_one_bad_row(tmp_path):
    rows = [good(type="url", value="http://example.com/" + "a" * 5000), good(value="192.0.2.9:9")]
    parsed = read_file(write_csv(tmp_path / "f.csv", rows))
    assert parsed.errors == [(2, "value_too_long")]
    assert [i.value for i in parsed.iocs] == ["192.0.2.9:9"]


def test_a_field_over_the_csv_modules_default_limit_is_read_as_an_ordinary_too_long_field(tmp_path):
    rows = [good(value="192.0.2.1:1"), good(threat="x" * 200_000), good(value="192.0.2.3:3")]
    parsed = read_file(write_csv(tmp_path / "f.csv", rows))
    assert [i.value for i in parsed.iocs] == ["192.0.2.1:1", "192.0.2.3:3"]
    assert parsed.errors == [(3, "threat_too_long")]
    assert parsed.total == 3 and parsed.spans == {}


FORGED = (
    "threatfox,2026-11-17 09:00:00,ip:port,192.0.2.66:66,botnet_cc,forged,100,,"
    "https://threatfox.abuse.ch/ioc/90000066/"
)


def _forging_file(tmp_path: Path) -> Path:
    """Three records; the middle one is ONE quoted field that runs past the csv module's default limit of 131 072
    characters on its first line (the limit trips there) and then holds a complete record line of its own, on a
    line of its own."""
    hidden = "x" * 140_000 + "\n" + FORGED + "\n" + "y" * 10
    rows = [
        good(value="192.0.2.1:1"),  # line 2
        good(threat=hidden, value="192.0.2.2:2"),  # lines 3-5
        good(value="192.0.2.3:3"),  # line 6
    ]
    return write_csv(tmp_path / "f.csv", rows)


def test_an_over_limit_quoted_multi_line_field_is_one_bad_row_and_forges_no_record(tmp_path):
    parsed = read_file(_forging_file(tmp_path))
    assert [i.value for i in parsed.iocs] == [
        "192.0.2.1:1",
        "192.0.2.3:3",
    ]  # the forged line is not a record
    assert parsed.errors == [(3, "row_malformed")]
    assert parsed.spans == {3: 3}
    assert parsed.total == 5 and parsed.error_count == 3


def test_an_unclosed_quote_swallows_the_rest_of_the_file_and_the_lines_lost_are_counted(tmp_path):
    ok = line(good(value="192.0.2.1:1"))
    opened = line(good(value="192.0.2.2:2", tags="")).replace(",192.0.2.2:2,", ',"192.0.2.2:2,')
    # no tags: a tags field with a comma is quoted, and its quote would close the open one
    rest = [line(good(value=f"192.0.2.{n}:{n}", tags="")) for n in (3, 4, 5)]
    path = write_raw(tmp_path / "f.csv", "\n".join([HEAD, ok, opened, *rest, ""]).encode())
    parsed = read_file(path)
    assert [i.value for i in parsed.iocs] == ["192.0.2.1:1"]
    assert parsed.errors == [(3, "row_malformed")]
    assert parsed.spans == {3: 4}  # lines 3 to 6: the opened record and the three after it
    assert parsed.total == 1 + 4 and parsed.error_count == 4


def test_the_csv_field_limit_is_raised_for_the_read_and_put_back(tmp_path, monkeypatch):
    before = csv.field_size_limit()
    read_file(SAMPLE)
    assert csv.field_size_limit() == before
    with pytest.raises(HeaderError):
        read_file(write_raw(tmp_path / "e.csv", b""))
    assert csv.field_size_limit() == before
    monkeypatch.setattr(importer, "MAX_FILE_BYTES", 10)
    with pytest.raises(importer.FileError):
        read_file(SAMPLE)
    assert csv.field_size_limit() == before
    seen = []
    real = importer.csv.reader

    def watching(*args, **kwargs):
        seen.append(csv.field_size_limit())
        return real(*args, **kwargs)

    monkeypatch.setattr(importer, "MAX_FILE_BYTES", 20 * 1024 * 1024)
    monkeypatch.setattr(importer.csv, "reader", watching)
    read_file(SAMPLE)
    assert seen and seen[0] > 20 * 1024 * 1024  # above any field a file within the cap can hold


def test_the_file_size_cap_is_twenty_megabytes():
    assert importer.MAX_FILE_BYTES == 20 * 1024 * 1024


def test_a_file_over_the_size_cap_is_refused_before_a_row_is_read_and_one_at_the_cap_is_read(
    tmp_path, monkeypatch
):
    path = write_csv(tmp_path / "f.csv", [good(value=f"192.0.2.{n}:1") for n in range(20)])
    size = path.stat().st_size
    monkeypatch.setattr(importer, "MAX_FILE_BYTES", size - 1)
    with pytest.raises(importer.FileError) as caught:
        read_file(path)
    assert caught.value.message == "file_too_large"
    monkeypatch.setattr(importer, "MAX_FILE_BYTES", size)
    assert read_file(path).total == 20


def test_something_that_is_not_a_regular_file_is_not_read():
    with pytest.raises(importer.FileError) as caught:
        read_file("/dev/null")
    assert caught.value.message == "file_unreadable"


def test_a_file_that_is_not_there_raises_oserror(tmp_path):
    with pytest.raises(OSError):
        read_file(tmp_path / "missing.csv")


# ═════════════════════════════ the loading: a scratch database ════════════════════════════════════════════════


@pytest.fixture(scope="module")
def ti_dsn():
    with scratch_database("ti") as dsn:
        yield dsn


@pytest.fixture
def ti_conn(ti_dsn):
    """A connection as the database owner, both tables empty. The importer commits, so a test cannot lean on a
    rollback: the tables are emptied here instead."""
    conn = psycopg.connect(ti_dsn)
    conn.execute("TRUNCATE ti_ioc, ti_import_log RESTART IDENTITY")
    conn.commit()
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


def iocs(conn) -> list[dict]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM ti_ioc ORDER BY id")
        rows = cur.fetchall()
    conn.commit()  # a reader leaves the connection idle, as the command's own connection is when it starts
    return rows


def logs(conn) -> list[dict]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM ti_import_log ORDER BY id")
        rows = cur.fetchall()
    conn.commit()
    return rows


def by_value(conn) -> dict[str, dict]:
    return {r["value"]: r for r in iocs(conn)}


@needs_db
def test_a_valid_file_is_loaded_and_logged_ok(ti_conn):
    result = import_file(ti_conn, SAMPLE, now=NOW, clock=_clock())
    assert (result.file, result.total, result.new, result.updated, result.errors) == (
        "ioc_sample.csv",
        12,
        12,
        0,
        0,
    )
    assert (result.status, result.message, result.repeated, result.error_rows) == (
        "ok",
        None,
        0,
        (),
    )
    rows = by_value(ti_conn)
    assert len(rows) == 12

    rat = rows["192.0.2.10:443"]
    assert (rat["source"], rat["type"], rat["malware"], rat["threat"]) == (
        "threatfox",
        "ip:port",
        "win.example_rat",
        "botnet_cc",
    )
    assert (rat["confidence"], rat["tags"]) == (75, ["example_rat", "c2"])
    assert rat["first_seen"] == datetime(2026, 11, 17, 6, 12, 44, tzinfo=UTC)
    assert rat["last_seen"] == rat["imported_at"] == NOW
    assert rat["expires_at"] == NOW + timedelta(days=30)
    assert (rat["hit_count"], rat["last_hit"]) == (0, None)
    assert rat["reference"] == "https://threatfox.abuse.ch/ioc/90000001/"

    assert "c2.example.com" in rows and "c2.Example.COM" not in rows  # a domain is lower-cased
    assert "https://download.example.net/Setup.EXE" in rows  # a URL keeps its case
    assert "http://malware.example.com/a/b.php?id=1,2" in rows  # a comma inside a quoted value
    bazaar = [r for r in rows.values() if r["source"] == "malwarebazaar"]
    assert len(bazaar) == 4 and all(r["confidence"] is None for r in bazaar)
    empty = [r for r in bazaar if r["malware"] is None]
    assert len(empty) == 1 and empty[0]["tags"] == [] and empty[0]["threat"] is None
    hashes = [r["value"] for r in rows.values() if r["type"] == "sha256_hash"]
    assert all(v == v.lower() and len(v) == 64 for v in hashes)

    (log,) = logs(ti_conn)
    assert (log["file"], log["status"], log["message"]) == ("ioc_sample.csv", "ok", None)
    assert (log["rows_total"], log["rows_new"], log["rows_updated"], log["rows_error"]) == (
        12,
        12,
        0,
        0,
    )
    assert (log["started_at"], log["finished_at"]) == (NOW, FINISH)


@needs_db
def test_a_file_missing_a_column_loads_nothing_and_logs_a_failed_run(ti_conn, tmp_path):
    header = [c for c in COLUMNS if c != "value"]
    path = write_csv(
        tmp_path / "ioc_2026-11-17.csv", [{c: good()[c] for c in header}], header=header
    )
    result = import_file(ti_conn, path, now=NOW, clock=_clock())
    assert (result.status, result.total, result.new, result.updated, result.errors) == (
        "failed",
        0,
        0,
        0,
        0,
    )
    assert result.message == "header_missing: value"
    assert iocs(ti_conn) == []
    (log,) = logs(ti_conn)
    assert (log["file"], log["status"], log["message"]) == (
        "ioc_2026-11-17.csv",
        "failed",
        "header_missing: value",
    )
    assert (log["rows_total"], log["rows_new"], log["rows_updated"], log["rows_error"]) == (
        0,
        0,
        0,
        0,
    )
    assert (log["started_at"], log["finished_at"]) == (NOW, FINISH)


@needs_db
def test_a_file_with_a_header_and_no_row_is_a_failed_run(ti_conn, tmp_path):
    result = import_file(ti_conn, write_csv(tmp_path / "e.csv", []), now=NOW, clock=_clock())
    assert (result.status, result.total, result.message) == ("failed", 0, "no_rows")
    assert iocs(ti_conn) == [] and [r["status"] for r in logs(ti_conn)] == ["failed"]


@needs_db
def test_an_unreadable_file_is_a_failed_run_with_the_file_name_and_never_its_directory(
    ti_conn, tmp_path
):
    missing = tmp_path / "ioc_2026-11-18.csv"
    result = import_file(ti_conn, missing, now=NOW, clock=_clock())
    assert (result.status, result.message, result.file) == (
        "failed",
        "file_unreadable",
        "ioc_2026-11-18.csv",
    )
    result = import_file(ti_conn, tmp_path, now=NOW, clock=_clock())  # a directory
    assert (result.status, result.message) == ("failed", "file_unreadable")
    first = logs(ti_conn)[0]
    assert (first["file"], first["status"]) == ("ioc_2026-11-18.csv", "failed")
    assert all(str(tmp_path) not in r["file"] for r in logs(ti_conn))
    assert iocs(ti_conn) == []


@needs_db
def test_bad_rows_are_skipped_with_line_and_reason_and_the_rest_is_loaded(ti_conn, tmp_path):
    rows = [
        good(value="192.0.2.1:1"),  # 2 good
        good(source="virustotal", value="192.0.2.2:2"),  # 3
        good(value="", type="url"),  # 4
        good(value="192.0.2.4\x00:4"),  # 5
        good(type="url", value="http://example.com/" + "a" * 2048),  # 6
        good(type="url", value=THREE_BYTE * 683),  # 7
        good(type="a" * 65, value="192.0.2.7"),  # 8
        good(malware="m" * 257, value="192.0.2.8:8"),  # 9
        good(threat="t" * 257, value="192.0.2.9:9"),  # 10
        good(reference="r" * 2049, value="192.0.2.10:10"),  # 11
        good(tags=",".join(["t"] * 33), value="192.0.2.11:11"),  # 12
        good(tags="t" * 65, value="192.0.2.12:12"),  # 13
        good(confidence="abc", value="192.0.2.13:13"),  # 14
        good(confidence="101", value="192.0.2.14:14"),  # 15
        good(first_seen="", value="192.0.2.15:15"),  # 16
        good(first_seen="not a date", value="192.0.2.16:16"),  # 17
        good(value="192.0.2.17:17"),  # 18 good
    ]
    path = write_csv(tmp_path / "ioc_2026-11-17.csv", rows)
    result = import_file(ti_conn, path, now=NOW, clock=_clock())
    assert result.error_rows == (
        (3, "source_invalid"),
        (4, "value_empty"),
        (5, "value_control_char"),
        (6, "value_too_long"),
        (7, "value_too_long"),
        (8, "type_too_long"),
        (9, "malware_too_long"),
        (10, "threat_too_long"),
        (11, "reference_too_long"),
        (12, "tags_too_many"),
        (13, "tag_too_long"),
        (14, "confidence_not_integer"),
        (15, "confidence_out_of_range"),
        (16, "first_seen_missing"),
        (17, "first_seen_invalid"),
    )
    assert (result.status, result.total, result.new, result.updated, result.errors) == (
        "partial",
        17,
        2,
        0,
        15,
    )
    assert set(by_value(ti_conn)) == {"192.0.2.1:1", "192.0.2.17:17"}
    assert result.message == (
        "skipped: confidence_not_integer=1 confidence_out_of_range=1 first_seen_invalid=1 first_seen_missing=1"
        " malware_too_long=1 reference_too_long=1 source_invalid=1 tag_too_long=1 tags_too_many=1"
        " threat_too_long=1 type_too_long=1 value_control_char=1 value_empty=1 value_too_long=2"
    )
    (log,) = logs(ti_conn)
    assert (log["status"], log["message"]) == ("partial", result.message)
    assert (log["rows_total"], log["rows_new"], log["rows_updated"], log["rows_error"]) == (
        17,
        2,
        0,
        15,
    )


@needs_db
def test_a_file_whose_every_row_is_bad_is_a_failed_run_with_nothing_loaded(ti_conn, tmp_path):
    rows = [good(value=""), good(source="x"), good(value="")]
    result = import_file(ti_conn, write_csv(tmp_path / "f.csv", rows), now=NOW, clock=_clock())
    assert (result.status, result.total, result.new, result.errors) == ("failed", 3, 0, 3)
    assert result.message == "no_valid_rows; skipped: source_invalid=1 value_empty=2"
    assert iocs(ti_conn) == []
    assert [(r["status"], r["rows_total"], r["rows_error"]) for r in logs(ti_conn)] == [
        ("failed", 3, 3)
    ]


@needs_db
def test_the_same_file_twice_gives_the_same_rows_and_moves_last_seen_and_expiry(ti_conn):
    first = import_file(ti_conn, SAMPLE, now=NOW, clock=_clock())
    before = {r["id"]: r for r in iocs(ti_conn)}
    second = import_file(ti_conn, SAMPLE, now=LATER, clock=_clock(LATER + timedelta(seconds=3)))
    after = {r["id"]: r for r in iocs(ti_conn)}

    assert (first.new, first.updated) == (12, 0)
    assert (second.new, second.updated, second.total, second.status) == (0, 12, 12, "ok")
    assert after.keys() == before.keys() and len(after) == 12  # no second row for any IOC
    for key, row in after.items():
        old = before[key]
        assert row["first_seen"] == old["first_seen"]
        assert row["imported_at"] == NOW  # the first import's instant stays
        assert row["last_seen"] == LATER
        assert row["expires_at"] == LATER + timedelta(days=30)
        assert {k: v for k, v in row.items() if k not in ("last_seen", "expires_at")} == {
            k: v for k, v in old.items() if k not in ("last_seen", "expires_at")
        }
    first_log, second_log = logs(ti_conn)
    assert (second_log["rows_new"], second_log["rows_updated"]) == (0, 12)
    assert (first_log["rows_new"], first_log["rows_updated"]) == (12, 0)


def _one_row_file(tmp_path: Path, name: str, **over: str) -> Path:
    return write_csv(tmp_path / name, [good(**over)])


@needs_db
def test_two_days_sharing_an_ioc_keep_the_earlier_first_seen_and_the_later_last_seen(
    ti_conn, tmp_path
):
    day1 = _one_row_file(tmp_path, "ioc_2026-11-17.csv", first_seen="2026-11-17 06:00:00 UTC")
    # day 2 sees the same IOC with a LATER first_seen (the feed re-dates it): the earlier one stays
    day2 = _one_row_file(tmp_path, "ioc_2026-11-18.csv", first_seen="2026-11-18 06:00:00 UTC")
    # day 3 sees it with an EARLIER first_seen (an older sighting turns up): the earlier one wins
    day3 = _one_row_file(tmp_path, "ioc_2026-11-19.csv", first_seen="2026-11-10 12:00:00 UTC")
    d2, d3 = NOW + timedelta(days=1), NOW + timedelta(days=2)

    import_file(ti_conn, day1, now=NOW)
    (row,) = iocs(ti_conn)
    assert row["first_seen"] == datetime(2026, 11, 17, 6, 0, tzinfo=UTC)

    result = import_file(ti_conn, day2, now=d2)
    (row,) = iocs(ti_conn)
    assert (result.new, result.updated) == (0, 1)
    assert row["first_seen"] == datetime(2026, 11, 17, 6, 0, tzinfo=UTC)
    assert row["last_seen"] == d2 and row["imported_at"] == NOW

    import_file(ti_conn, day3, now=d3)
    (row,) = iocs(ti_conn)
    assert row["first_seen"] == datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
    assert row["last_seen"] == d3 and row["expires_at"] == d3 + timedelta(days=30)


@needs_db
def test_an_update_refreshes_the_descriptive_fields_and_leaves_the_hit_columns_alone(
    ti_conn, tmp_path
):
    import_file(ti_conn, _one_row_file(tmp_path, "a.csv"), now=NOW)
    ti_conn.execute("UPDATE ti_ioc SET hit_count = 5, last_hit = %s", (NOW,))
    ti_conn.commit()
    changed = _one_row_file(
        tmp_path,
        "b.csv",
        malware="win.other",
        threat="payload",
        confidence="40",
        tags="x,y,z",
        reference="https://threatfox.abuse.ch/ioc/90000099/",
    )
    result = import_file(ti_conn, changed, now=LATER)
    (row,) = iocs(ti_conn)
    assert (result.new, result.updated) == (0, 1)
    assert (row["malware"], row["threat"], row["confidence"]) == ("win.other", "payload", 40)
    assert (row["tags"], row["reference"]) == (
        ["x", "y", "z"],
        "https://threatfox.abuse.ch/ioc/90000099/",
    )
    assert (row["hit_count"], row["last_hit"]) == (5, NOW)

    emptied = _one_row_file(
        tmp_path, "c.csv", malware="", threat="", confidence="", tags="", reference=""
    )
    import_file(ti_conn, emptied, now=LATER + timedelta(days=1))
    (row,) = iocs(ti_conn)  # what the feed says now replaces what it said before, empty included
    assert (row["malware"], row["threat"], row["confidence"], row["tags"], row["reference"]) == (
        None,
        None,
        None,
        [],
        None,
    )


@needs_db
def test_the_same_value_under_another_source_or_type_is_another_row(ti_conn, tmp_path):
    rows = [
        good(source="threatfox", type="url", value="http://example.com/x"),
        good(source="urlhaus", type="url", value="http://example.com/x"),
        good(source="threatfox", type="domain", value="example.com"),
        good(source="threatfox", type="ip:port", value="example.com"),
    ]
    result = import_file(ti_conn, write_csv(tmp_path / "f.csv", rows), now=NOW)
    assert (result.new, result.updated, result.repeated) == (4, 0, 0)
    assert len(iocs(ti_conn)) == 4


@needs_db
def test_a_key_repeated_in_one_file_counts_once_and_the_first_occurrence_wins(ti_conn, tmp_path):
    rows = [
        good(value="192.0.2.1:1", malware="first", confidence="10"),  # line 2
        good(value="192.0.2.2:2"),  # 3
        good(value="192.0.2.1:1", malware="second", confidence="99"),  # 4: the same key
        good(type="domain", value="Dup.Example.com", malware="d1"),  # 5
        good(
            type="domain", value="dup.example.COM", malware="d2"
        ),  # 6: the same key after lower-casing
        good(value="192.0.2.1:1", malware="third"),  # 7
        good(value="", malware="bad"),  # 8: a bad row
    ]
    result = import_file(ti_conn, write_csv(tmp_path / "f.csv", rows), now=NOW)
    assert (result.total, result.new, result.updated, result.errors, result.repeated) == (
        7,
        3,
        0,
        1,
        3,
    )
    assert result.total == result.new + result.updated + result.errors + result.repeated
    assert result.status == "partial"
    values = by_value(ti_conn)
    assert sorted(values) == ["192.0.2.1:1", "192.0.2.2:2", "dup.example.com"]
    assert (values["192.0.2.1:1"]["malware"], values["192.0.2.1:1"]["confidence"]) == ("first", 10)
    assert values["dup.example.com"]["malware"] == "d1"
    (log,) = logs(ti_conn)
    assert (log["rows_total"], log["rows_new"], log["rows_error"]) == (7, 3, 1)


@needs_db
def test_a_second_run_over_a_file_with_a_repeated_key_still_counts_it_once(ti_conn, tmp_path):
    rows = [good(value="192.0.2.1:1"), good(value="192.0.2.1:1")]
    path = write_csv(tmp_path / "f.csv", rows)
    import_file(ti_conn, path, now=NOW)
    second = import_file(ti_conn, path, now=LATER)
    assert (second.new, second.updated, second.repeated) == (0, 1, 1)
    assert len(iocs(ti_conn)) == 1


@needs_db
def test_a_nul_or_control_character_never_reaches_the_database_the_row_is_skipped(
    ti_conn, tmp_path
):
    rows = [
        good(value="192.0.2.1:1"),
        good(value="192.0.2.2\x00:2"),
        good(value="192.0.2.3:3", malware="a\x00b"),
        good(value="192.0.2.4:4", threat="a\x00b"),
        good(value="192.0.2.5:5", reference="http://x\x00"),
        good(value="192.0.2.6:6", tags="a,b\x00"),
        good(value="192.0.2.7:7", malware="a\x1bb"),
        good(value="192.0.2.8:8"),
    ]
    result = import_file(ti_conn, write_csv(tmp_path / "f.csv", rows), now=NOW)
    assert (result.status, result.new, result.errors) == ("partial", 2, 6)
    assert sorted(by_value(ti_conn)) == ["192.0.2.1:1", "192.0.2.8:8"]


@needs_db
def test_a_formula_markup_or_sql_in_a_field_is_stored_as_the_text_it_is(ti_conn, tmp_path):
    """Review focus: the importer neither interprets nor rewrites what a field says. A spreadsheet formula, markup,
    a `javascript:` URL and SQL are data (every statement is parameterised); guarding them is for the export and the
    page, which read these bytes back as they were."""
    formula = "=cmd|' /C calc'!A0"
    markup = "<img src=x onerror=alert(1)>"
    script_url = "javascript:alert(document.cookie)"
    sql_text = "x'; DROP TABLE ti_ioc; --"
    rows = [
        good(
            type="url",
            value=formula,
            malware="@SUM(1+1)",
            threat="+1+1",
            tags="-2+3,=1",
            reference=markup,
        ),
        good(type="url", value=markup, malware=sql_text, reference=script_url),
        good(type="url", value=script_url, threat=sql_text),
        good(type="url", value=sql_text, malware="%", threat="_"),
    ]
    result = import_file(ti_conn, write_csv(tmp_path / "f.csv", rows), now=NOW)
    assert (result.status, result.new) == ("ok", 4)
    stored = by_value(ti_conn)
    assert set(stored) == {formula, markup, script_url, sql_text}
    row = stored[formula]
    assert (row["malware"], row["threat"], row["tags"], row["reference"]) == (
        "@SUM(1+1)",
        "+1+1",
        ["-2+3", "=1"],
        markup,
    )
    assert (stored[markup]["malware"], stored[markup]["reference"]) == (sql_text, script_url)
    assert (stored[sql_text]["malware"], stored[sql_text]["threat"]) == ("%", "_")
    assert ti_conn.execute("SELECT count(*) FROM ti_ioc").fetchone() == (
        4,
    )  # the table is still there


@needs_db
def test_a_row_at_every_bound_loads_so_the_importers_bounds_sit_inside_the_databases(
    ti_conn, tmp_path
):
    at_bound = good(
        type="url",
        value="u" + THREE_BYTE * 682 + "v",  # 2 048 bytes
        malware=TWO_BYTE * 128,  # 256 bytes
        threat=TWO_BYTE * 128,
        reference=THREE_BYTE * 682 + "rr",  # 2 048 bytes
        tags=",".join([THREE_BYTE * 21 + "x"] * 32),  # 32 tags of 64 bytes
    )
    long_type = good(type="t" * 64, value="192.0.2.50")
    result = import_file(ti_conn, write_csv(tmp_path / "f.csv", [at_bound, long_type]), now=NOW)
    assert (result.status, result.new, result.errors) == ("ok", 2, 0)
    (row,) = [r for r in iocs(ti_conn) if r["type"] == "url"]
    assert len(row["value"].encode()) == 2048 and len(row["tags"]) == 32
    assert any(r["type"] == "t" * 64 for r in iocs(ti_conn))


@needs_db
def test_a_database_error_loads_nothing_and_the_failed_run_is_still_logged(
    ti_conn, tmp_path, monkeypatch
):
    """The importer's bound drifts above the database's CHECK (here by monkeypatch): the third row, which the
    importer lets through, is refused by `ck_ti_ioc_value_bytes`. The whole file is one transaction, so the two
    rows before it are rolled back, a row loaded by an earlier run is untouched, and the log row still lands.
    """
    import_file(ti_conn, _one_row_file(tmp_path, "old.csv", value="198.51.100.1:1"), now=NOW)
    old = iocs(ti_conn)
    rows = [
        good(value="198.51.100.1:1", malware="changed"),  # would be an update of the old row
        good(value="192.0.2.2:2"),
        good(
            type="url", value="http://example.com/" + SENTINEL + "a" * 2500
        ),  # the one the database refuses
        good(value="192.0.2.4:4"),
    ]
    path = write_csv(tmp_path / "ioc_2026-11-18.csv", rows)
    monkeypatch.setattr(importer, "VALUE_MAX_BYTES", 5000)

    result = import_file(ti_conn, path, now=LATER, clock=_clock(LATER + timedelta(seconds=9)))

    assert (result.status, result.new, result.updated, result.total) == ("failed", 0, 0, 4)
    assert result.message == "database_error: CheckViolation"
    assert SENTINEL not in repr(result)
    assert iocs(ti_conn) == old  # nothing loaded, nothing updated
    old_log, new_log = logs(ti_conn)
    assert old_log["status"] == "ok"
    assert (new_log["status"], new_log["message"]) == ("failed", "database_error: CheckViolation")
    assert (new_log["rows_total"], new_log["rows_new"], new_log["rows_updated"]) == (4, 0, 0)
    assert (new_log["started_at"], new_log["finished_at"]) == (LATER, LATER + timedelta(seconds=9))
    assert SENTINEL not in (new_log["message"] or "")


@needs_db
def test_a_database_error_does_not_swallow_the_connection_the_next_run_works(
    ti_conn, tmp_path, monkeypatch
):
    path = write_csv(tmp_path / "f.csv", [good(type="url", value="u" * 3000)])
    with monkeypatch.context() as patched:
        patched.setattr(importer, "VALUE_MAX_BYTES", 5000)
        assert import_file(ti_conn, path, now=NOW).status == "failed"
    assert import_file(ti_conn, SAMPLE, now=LATER).status == "ok"
    assert len(iocs(ti_conn)) == 12


@needs_db
def test_finished_at_is_never_before_started_at_even_when_the_clock_says_so(ti_conn, tmp_path):
    early = _clock(NOW - timedelta(hours=1))
    ok = import_file(ti_conn, SAMPLE, now=NOW, clock=early)
    bad = import_file(ti_conn, write_csv(tmp_path / "e.csv", []), now=NOW, clock=early)
    assert (ok.status, bad.status) == ("ok", "failed")
    for log in logs(ti_conn):
        assert (
            log["started_at"] == NOW and log["finished_at"] == NOW
        )  # raised to the start, not refused


@needs_db
def test_the_default_clock_gives_a_finish_at_or_after_the_start(ti_conn):
    start = datetime.now(UTC)
    import_file(ti_conn, SAMPLE, now=start)
    (log,) = logs(ti_conn)
    assert log["started_at"] == start
    assert log["finished_at"] >= start
    assert log["finished_at"] <= datetime.now(UTC)


def test_a_now_without_a_time_zone_is_refused_before_anything_is_read(tmp_path):
    class NoConnection:
        def __getattr__(self, name):
            raise AssertionError("the connection was used")

    with pytest.raises(ValueError):
        import_file(NoConnection(), SAMPLE, now=datetime(2026, 11, 17, 7, 5))  # noqa: DTZ001


@needs_db
def test_a_now_in_another_zone_is_stored_as_the_same_instant(ti_conn):
    plus7 = NOW.astimezone(timezone(timedelta(hours=7)))
    import_file(ti_conn, SAMPLE, now=plus7, clock=_clock())
    assert {r["last_seen"] for r in iocs(ti_conn)} == {NOW}
    assert logs(ti_conn)[0]["started_at"] == NOW


@needs_db
def test_the_importer_works_with_the_rights_of_app_rw_which_has_no_delete(ti_conn):
    ti_conn.execute("SET ROLE app_rw")
    ti_conn.commit()  # the role is the session's, so the importer below is the outermost transaction
    try:
        first = import_file(ti_conn, SAMPLE, now=NOW, clock=_clock())
        second = import_file(ti_conn, SAMPLE, now=LATER, clock=_clock(LATER))
        bad = import_file(ti_conn, SAMPLE.with_name("missing.csv"), now=LATER, clock=_clock(LATER))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            ti_conn.execute("DELETE FROM ti_ioc")
        ti_conn.rollback()
    finally:
        ti_conn.execute("RESET ROLE")
        ti_conn.commit()
    assert (first.status, first.new, second.status, second.updated, bad.status) == (
        "ok",
        12,
        "ok",
        12,
        "failed",
    )
    assert len(logs(ti_conn)) == 3


@needs_db
def test_a_caller_with_a_transaction_open_keeps_control_of_it(ti_conn, tmp_path):
    """Run inside the caller's transaction, the importer's own block is a savepoint: the caller can roll back."""
    ti_conn.execute("SELECT 1")  # a transaction is now open
    result = import_file(ti_conn, SAMPLE, now=NOW, clock=_clock())
    assert result.status == "ok"
    ti_conn.rollback()
    assert iocs(ti_conn) == [] and logs(ti_conn) == []


@needs_db
def test_a_forged_record_inside_an_over_limit_field_is_not_loaded(ti_conn, tmp_path):
    result = import_file(ti_conn, _forging_file(tmp_path), now=NOW, clock=_clock())
    assert (result.status, result.total, result.new, result.updated, result.errors) == (
        "partial",
        5,
        2,
        0,
        3,
    )
    assert (result.error_rows, result.error_spans) == (((3, "row_malformed"),), ((3, 3),))
    assert result.message == "skipped: row_malformed=3"
    assert set(by_value(ti_conn)) == {"192.0.2.1:1", "192.0.2.3:3"}
    assert not [r for r in iocs(ti_conn) if r["malware"] == "forged" or r["confidence"] == 100]
    (log,) = logs(ti_conn)
    assert (log["rows_total"], log["rows_new"], log["rows_error"], log["status"]) == (
        5,
        2,
        3,
        "partial",
    )


@needs_db
def test_an_unclosed_quote_is_logged_with_the_lines_it_swallowed(ti_conn, tmp_path):
    ok = line(good(value="192.0.2.1:1"))
    opened = line(good(value="192.0.2.2:2", tags="")).replace(",192.0.2.2:2,", ',"192.0.2.2:2,')
    # no tags: a tags field with a comma is quoted, and its quote would close the open one
    rest = [line(good(value=f"192.0.2.{n}:{n}", tags="")) for n in (3, 4, 5)]
    path = write_raw(tmp_path / "f.csv", "\n".join([HEAD, ok, opened, *rest, ""]).encode())
    result = import_file(ti_conn, path, now=NOW, clock=_clock())
    assert (result.status, result.total, result.new, result.errors) == ("partial", 5, 1, 4)
    assert result.total == result.new + result.updated + result.errors + result.repeated
    assert result.error_rows == ((3, "row_malformed"),) and result.error_spans == ((3, 4),)
    (log,) = logs(ti_conn)
    assert (log["rows_total"], log["rows_new"], log["rows_error"]) == (5, 1, 4)
    assert (
        importer.format_error_line(3, "row_malformed", span=4)
        == "ti_import: lines 3-6: row_malformed"
    )


@needs_db
def test_a_file_over_the_size_cap_is_a_failed_run_with_nothing_loaded(
    ti_conn, tmp_path, monkeypatch
):
    path = write_csv(
        tmp_path / "ioc_2026-11-17.csv", [good(value=f"192.0.2.{n}:1") for n in range(20)]
    )
    monkeypatch.setattr(importer, "MAX_FILE_BYTES", path.stat().st_size - 1)
    result = import_file(ti_conn, path, now=NOW, clock=_clock())
    assert (result.status, result.message, result.total, result.new) == (
        "failed",
        "file_too_large",
        0,
        0,
    )
    assert iocs(ti_conn) == []
    (log,) = logs(ti_conn)
    assert (log["file"], log["status"], log["message"]) == (
        "ioc_2026-11-17.csv",
        "failed",
        "file_too_large",
    )


@needs_db
def test_a_repeated_key_keeps_the_first_occurrence_but_the_earliest_first_seen(ti_conn, tmp_path):
    rows = [
        good(value="192.0.2.1:1", malware="first", first_seen="2026-11-17 06:00:00"),
        good(
            value="192.0.2.1:1", malware="second", first_seen="2026-11-16 05:00:00"
        ),  # the earliest
        good(value="192.0.2.1:1", malware="third", first_seen="2026-11-17 08:00:00"),
        good(value="192.0.2.2:2", malware="solo", first_seen="2026-11-17 07:00:00"),
    ]
    result = import_file(ti_conn, write_csv(tmp_path / "f.csv", rows), now=NOW)
    assert (result.new, result.repeated, result.total) == (2, 2, 4)
    row = by_value(ti_conn)["192.0.2.1:1"]
    assert row["malware"] == "first"  # the first occurrence's descriptive fields
    assert row["first_seen"] == datetime(
        2026, 11, 16, 5, 0, tzinfo=UTC
    )  # the earliest first_seen of the repeats
    assert by_value(ti_conn)["192.0.2.2:2"]["first_seen"] == datetime(
        2026, 11, 17, 7, 0, tzinfo=UTC
    )


@needs_db
def test_a_lock_wait_is_bounded_and_the_failed_run_is_logged(ti_dsn, ti_conn, monkeypatch):
    import_file(ti_conn, SAMPLE, now=NOW)
    blocker = psycopg.connect(ti_dsn)
    try:
        blocker.execute("LOCK TABLE ti_ioc IN ACCESS EXCLUSIVE MODE")
        monkeypatch.setattr(importer, "LOCK_TIMEOUT", "300ms")
        started = time.monotonic()
        result = import_file(ti_conn, SAMPLE, now=LATER, clock=_clock(LATER))
        waited = time.monotonic() - started
    finally:
        blocker.rollback()
        blocker.close()
    assert (result.status, result.message) == ("failed", "database_error: LockNotAvailable")
    assert waited < 5
    assert (result.new, result.updated) == (0, 0)
    assert [r["status"] for r in logs(ti_conn)] == ["ok", "failed"]
    assert logs(ti_conn)[1]["message"] == "database_error: LockNotAvailable"
    assert {r["last_seen"] for r in iocs(ti_conn)} == {NOW}  # the first run's rows, untouched


@needs_db
def test_a_statement_that_runs_too_long_is_cancelled_and_the_failed_run_is_logged(
    ti_dsn, ti_conn, monkeypatch
):
    blocker = psycopg.connect(ti_dsn)
    try:
        blocker.execute("LOCK TABLE ti_ioc IN ACCESS EXCLUSIVE MODE")
        monkeypatch.setattr(importer, "LOCK_TIMEOUT", "10s")
        monkeypatch.setattr(importer, "STATEMENT_TIMEOUT", "300ms")
        started = time.monotonic()
        result = import_file(ti_conn, SAMPLE, now=NOW, clock=_clock())
        waited = time.monotonic() - started
    finally:
        blocker.rollback()
        blocker.close()
    assert (result.status, result.message) == ("failed", "database_error: QueryCanceled")
    assert waited < 5
    assert iocs(ti_conn) == [] and [r["status"] for r in logs(ti_conn)] == ["failed"]


@needs_db
def test_the_timeouts_end_with_the_import_transaction(ti_conn):
    assert import_file(ti_conn, SAMPLE, now=NOW).status == "ok"
    for name in ("lock_timeout", "statement_timeout"):
        assert ti_conn.execute(f"SHOW {name}").fetchone() == ("0",)
    ti_conn.rollback()
    assert (importer.LOCK_TIMEOUT, importer.STATEMENT_TIMEOUT) == ("5s", "10s")


DO_NOTHING = """
INSERT INTO ti_ioc (source, type, value, malware, threat, confidence, tags, reference,
                    first_seen, last_seen, imported_at, expires_at)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT ON CONSTRAINT uq_ti_ioc_key DO NOTHING
RETURNING (xmax = 0) AS inserted
"""


@needs_db
def test_an_upsert_that_returns_no_row_is_an_error_and_not_counted_as_an_update(
    ti_conn, tmp_path, monkeypatch
):
    path = _one_row_file(tmp_path, "a.csv")
    import_file(ti_conn, path, now=NOW)
    before = iocs(ti_conn)
    monkeypatch.setattr(importer, "_UPSERT", DO_NOTHING)  # a conflict then returns no row
    result = import_file(ti_conn, path, now=LATER)
    assert (result.status, result.new, result.updated) == ("failed", 0, 0)
    assert result.message == "database_error: UpsertError"
    assert iocs(ti_conn) == before
    assert [r["status"] for r in logs(ti_conn)] == ["ok", "failed"]


# ═════════════════════════════ what is printed or stored never holds a row's text ═════════════════════════════


def _hostile_rows() -> list[dict[str, str]]:
    return [
        good(value=f"192.0.2.1:{SENTINEL}"),  # source ok, value ok (a sentinel in a good row)
        good(source=f"{SENTINEL}", value="192.0.2.2:2"),
        good(value=f"{SENTINEL}\x00"),
        good(type="url", value=f"http://{SENTINEL}/" + "a" * 3000),
        good(first_seen=SENTINEL),
        good(confidence=SENTINEL),
        good(threat=SENTINEL * 40),
        good(malware=SENTINEL * 40),
        good(reference=SENTINEL * 200),
        good(tags=SENTINEL + ",".join(["t"] * 40)),
        good(type=f"{SENTINEL} x"),
    ]


@needs_db
def test_the_summary_line_the_error_lines_and_the_log_row_carry_no_row_text(ti_conn, tmp_path):
    path = write_csv(tmp_path / "ioc_2026-11-17.csv", _hostile_rows())
    result = import_file(ti_conn, path, now=NOW, clock=_clock())
    assert result.errors == 10 and result.new == 1
    lines = [importer.format_summary(result)] + [
        importer.format_error_line(n, r) for n, r in result.error_rows
    ]
    stored = [str(v) for log in logs(ti_conn) for v in log.values()]
    for text in [*lines, *stored, repr(result)]:
        assert SENTINEL not in text
        assert str(tmp_path) not in text
    assert all("\n" not in line for line in lines)


def test_the_summary_line_has_one_fixed_shape():
    ok = importer.Result(
        file="ioc_2026-11-17.csv",
        total=200,
        new=198,
        updated=0,
        errors=0,
        status="ok",
        message=None,
        repeated=2,
    )
    assert importer.format_summary(ok) == (
        "ti_import: status=ok file=ioc_2026-11-17.csv total=200 new=198 updated=0 errors=0 repeated=2"
    )
    failed = importer.Result(
        file="f.csv",
        total=3,
        new=0,
        updated=0,
        errors=3,
        status="failed",
        message="no_valid_rows; skipped: value_empty=3",
    )
    assert importer.format_summary(failed) == (
        "ti_import: status=failed file=f.csv total=3 new=0 updated=0 errors=3 repeated=0"
        " message=no_valid_rows; skipped: value_empty=3"
    )
    assert importer.format_error_line(17, "value_too_long") == "ti_import: line 17: value_too_long"


def test_a_file_name_with_a_control_character_is_made_printable_in_the_line_and_the_log():
    assert importer.safe_name("ioc_2026-11-17.csv") == "ioc_2026-11-17.csv"
    assert importer.safe_name("a\x00c\x1b[31m.csv") == "a?c?[31m.csv"
    assert len(importer.safe_name("x" * 1000)) == 255


def test_white_space_in_a_file_name_becomes_an_underscore_so_the_summary_line_stays_unambiguous():
    assert importer.safe_name("my file\tname\n.csv") == "my_file_name_.csv"
    assert importer.safe_name("a\u00a0b\u2028c") == "a_b_c"
    result = importer.Result(
        file=importer.safe_name("a b.csv"),
        total=1,
        new=1,
        updated=0,
        errors=0,
        status="ok",
        message=None,
    )
    assert (
        len(importer.format_summary(result).split(" ")) == 8
    )  # ti_import: + seven key=value words


def test_a_result_refuses_a_status_that_is_not_one_of_the_three():
    assert importer.STATUSES == ("ok", "partial", "failed")
    for status in importer.STATUSES:
        importer.Result(file="f", total=0, new=0, updated=0, errors=0, status=status, message=None)
    with pytest.raises(ValueError):
        importer.Result(file="f", total=0, new=0, updated=0, errors=0, status="done", message=None)


def test_the_error_line_of_a_record_that_spans_lines_names_the_span():
    assert (
        importer.format_error_line(3, "row_malformed", span=4)
        == "ti_import: lines 3-6: row_malformed"
    )
    assert (
        importer.format_error_line(3, "row_malformed", span=1) == "ti_import: line 3: row_malformed"
    )


# ═════════════════════════════ the command: scripts/ti_import.py ══════════════════════════════════════════════


def _load_script():
    spec = importlib.util.spec_from_file_location("_ti_import_script", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def env_file(tmp_path: Path, dsn: str | None, extra: str = "") -> Path:
    path = tmp_path / ".env"
    lines = [extra] if extra else []
    if dsn is not None:
        lines.append(f"DATABASE_URL={dsn}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def closed_port_dsn(password: str = "PWSENTINEL-9c1e") -> str:
    return f"postgresql://app_rw:{password}@127.0.0.1:1/soc_trial"


def test_the_env_file_parser_reads_the_one_key_and_nothing_else(tmp_path):
    script = _load_script()
    text = (
        "# a comment\n"
        "\n"
        "TEST_DATABASE_URL=postgresql://wrong/one\n"
        "DATABASE_URL_OWNER=postgresql://wrong/two\n"
        "NOT_DATABASE_URL=postgresql://wrong/three\n"
        "DATABASE_URL=postgresql://u:p#w@h:1/d   # a trailing comment\n"
        "OTHER=x\n"
    )
    path = tmp_path / ".env"
    path.write_text(text, encoding="utf-8")
    assert script.read_env_value(path, "DATABASE_URL") == "postgresql://u:p#w@h:1/d"
    assert script.read_env_value(path, "MISSING") is None


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("DATABASE_URL=postgresql://a/b", "postgresql://a/b"),
        ('DATABASE_URL="postgresql://a/b"', "postgresql://a/b"),
        ("DATABASE_URL='postgresql://a/b'", "postgresql://a/b"),
        ("export DATABASE_URL=postgresql://a/b", "postgresql://a/b"),
        ("  DATABASE_URL = postgresql://a/b  ", "postgresql://a/b"),
        ('DATABASE_URL="postgresql://a/b" # note', "postgresql://a/b"),
        ("DATABASE_URL='post gres'#x", "post gres"),
        ("DATABASE_URL=", ""),
    ],
)
def test_the_env_file_parser_handles_quotes_export_and_comments(tmp_path, line, expected):
    path = tmp_path / ".env"
    path.write_text(f"{line}\n", encoding="utf-8")
    assert _load_script().read_env_value(path, "DATABASE_URL") == expected


def test_the_env_file_parser_takes_the_last_assignment(tmp_path):
    path = tmp_path / ".env"
    path.write_text(
        "DATABASE_URL=postgresql://first/x\nDATABASE_URL=postgresql://last/x\n", encoding="utf-8"
    )
    assert _load_script().read_env_value(path, "DATABASE_URL") == "postgresql://last/x"


def _never_connect(monkeypatch, script) -> None:
    def refuse(*args, **kwargs):
        raise AssertionError("the command touched the database")

    monkeypatch.setattr(script.db, "connect", refuse)


def test_no_env_file_argument_is_a_usage_error_exit_2(monkeypatch, capsys):
    script = _load_script()
    _never_connect(monkeypatch, script)
    assert script.main([str(SAMPLE)]) == 2
    assert "--env-file" in capsys.readouterr().err


def test_an_unknown_option_is_a_usage_error_exit_2(monkeypatch, capsys, tmp_path):
    script = _load_script()
    _never_connect(monkeypatch, script)
    assert script.main(["--env-file", str(env_file(tmp_path, "x")), "--bogus"]) == 2
    capsys.readouterr()


def test_a_missing_env_file_or_a_missing_key_is_exit_1_and_never_the_process_environment(
    monkeypatch, capsys, tmp_path
):
    script = _load_script()
    _never_connect(monkeypatch, script)
    monkeypatch.setenv("DATABASE_URL", closed_port_dsn("ENVSENTINEL-5d2b"))
    assert script.main([str(SAMPLE), "--env-file", str(tmp_path / "nope.env")]) == 1
    assert script.main([str(SAMPLE), "--env-file", str(env_file(tmp_path, None, "OTHER=1"))]) == 1
    assert script.main([str(SAMPLE), "--env-file", str(env_file(tmp_path, ""))]) == 1
    out = capsys.readouterr()
    assert "status=failed" in out.out and "ENVSENTINEL" not in out.out + out.err


def test_a_database_that_is_down_is_exit_1_and_only_the_exception_type_is_printed(
    monkeypatch, capsys, tmp_path
):
    script = _load_script()
    code = script.main([str(SAMPLE), "--env-file", str(env_file(tmp_path, closed_port_dsn()))])
    out = capsys.readouterr()
    assert code == 1
    assert (
        "status=failed" in out.out and "message=database_unreachable: OperationalError" in out.out
    )
    for forbidden in ("PWSENTINEL", "app_rw", "127.0.0.1", "soc_trial", "postgresql://"):
        assert forbidden not in out.out + out.err


@needs_db
def test_main_imports_the_file_prints_one_summary_line_and_exits_0(
    ti_dsn, ti_conn, tmp_path, capsys
):
    script = _load_script()
    code = script.main([str(SAMPLE), "--env-file", str(env_file(tmp_path, str(ti_dsn)))])
    out = capsys.readouterr()
    assert code == 0
    assert out.out == (
        "ti_import: status=ok file=ioc_sample.csv total=12 new=12 updated=0 errors=0 repeated=0\n"
    )
    assert out.err == ""
    assert str(ti_dsn) not in out.out + out.err
    ti_conn.rollback()
    assert len(iocs(ti_conn)) == 12 and [r["status"] for r in logs(ti_conn)] == ["ok"]


@needs_db
def test_main_with_bad_rows_is_partial_exit_0_and_names_each_line_and_reason_on_stderr(
    ti_dsn, ti_conn, tmp_path, capsys
):
    path = write_csv(
        tmp_path / "ioc_2026-11-17.csv",
        [good(value="192.0.2.1:1"), good(value=""), good(source="x")],
    )
    code = _load_script().main([str(path), "--env-file", str(env_file(tmp_path, str(ti_dsn)))])
    out = capsys.readouterr()
    assert code == 0
    assert out.err == "ti_import: line 3: value_empty\nti_import: line 4: source_invalid\n"
    assert out.out.startswith(
        "ti_import: status=partial file=ioc_2026-11-17.csv total=3 new=1 updated=0 errors=2"
    )
    assert out.out.count("\n") == 1


@needs_db
def test_main_lists_at_most_a_hundred_bad_rows_then_says_how_many_it_left_out(
    ti_dsn, ti_conn, tmp_path, capsys
):
    rows = [good(value="192.0.2.1:1")] + [good(value="") for _ in range(130)]
    path = write_csv(tmp_path / "f.csv", rows)
    code = _load_script().main([str(path), "--env-file", str(env_file(tmp_path, str(ti_dsn)))])
    out = capsys.readouterr()
    assert code == 0
    lines = out.err.splitlines()
    assert len(lines) == 101 and lines[0] == "ti_import: line 3: value_empty"
    assert lines[-1] == "ti_import: 30 more bad rows not listed"
    assert "errors=130" in out.out


@needs_db
def test_main_with_a_missing_column_is_exit_1_and_a_failed_log_row(
    ti_dsn, ti_conn, tmp_path, capsys
):
    header = [c for c in COLUMNS if c != "first_seen"]
    path = write_csv(
        tmp_path / "ioc_2026-11-17.csv", [{c: good()[c] for c in header}], header=header
    )
    code = _load_script().main([str(path), "--env-file", str(env_file(tmp_path, str(ti_dsn)))])
    out = capsys.readouterr()
    assert code == 1
    assert out.out == (
        "ti_import: status=failed file=ioc_2026-11-17.csv total=0 new=0 updated=0 errors=0 repeated=0"
        " message=header_missing: first_seen\n"
    )
    ti_conn.rollback()
    assert iocs(ti_conn) == [] and [(r["status"], r["message"]) for r in logs(ti_conn)] == [
        ("failed", "header_missing: first_seen")
    ]


def _daily(tmp_path: Path) -> Path:
    """A directory like the host's: three days, a stray csv, a temp file, a directory with a feed name."""
    daily = tmp_path / "daily"
    daily.mkdir()
    write_csv(daily / "ioc_2026-11-15.csv", [good(value="192.0.2.15:15")])
    write_csv(daily / "ioc_2026-11-17.csv", [good(value="192.0.2.17:17")])
    write_csv(daily / "ioc_2026-11-16.csv", [good(value="192.0.2.16:16")])
    write_csv(daily / "ioc_test.csv", [good(value="192.0.2.98:98")])
    write_csv(daily / "notes.csv", [good(value="192.0.2.99:99")])
    write_csv(
        daily / "ioc_2026-11-18.csv", [good(value="192.0.2.18:18")]
    )  # tomorrow's: not today's
    (daily / "ioc_2026-11-17.csv.tmp").write_text("not a feed file")
    (daily / "ioc_2026-11-19.csv").mkdir()  # a directory with a feed name is not a file
    return daily


def test_todays_file_is_the_one_named_for_the_hosts_date_and_no_other(tmp_path):
    script = _load_script()
    daily = _daily(tmp_path)
    assert script.todays_file(daily, date(2026, 11, 17)) == daily / "ioc_2026-11-17.csv"
    assert script.todays_file(daily, date(2026, 11, 16)) == daily / "ioc_2026-11-16.csv"
    assert (
        script.todays_file(daily, date(2026, 11, 20)) is None
    )  # an older file is not picked in its place
    assert script.todays_file(daily, date(2026, 11, 19)) is None  # a directory is not a file
    assert script.todays_file(tmp_path / "gone", date(2026, 11, 17)) is None
    assert script.DAILY_NAME.fullmatch("ioc_2026-11-17.csv")
    for name in (
        "ioc_test.csv",
        "ioc_2026-11-17.csv.tmp",
        "ioc_20261117.csv",
        "xioc_2026-11-17.csv",
        "notes.csv",
    ):
        assert not script.DAILY_NAME.fullmatch(name)


@needs_db
def test_main_without_a_file_imports_todays_file_of_the_directory(
    ti_dsn, ti_conn, tmp_path, capsys
):
    daily = _daily(tmp_path)
    code = _load_script().main(
        ["--dir", str(daily), "--env-file", str(env_file(tmp_path, str(ti_dsn)))],
        today=date(2026, 11, 17),
    )
    out = capsys.readouterr()
    assert code == 0 and "file=ioc_2026-11-17.csv" in out.out
    ti_conn.rollback()
    assert list(by_value(ti_conn)) == ["192.0.2.17:17"]


@needs_db
def test_main_without_a_file_and_without_a_today_uses_the_hosts_local_date(
    ti_dsn, ti_conn, tmp_path, capsys
):
    daily = tmp_path / "daily"
    daily.mkdir()
    local_today = date.today()  # noqa: DTZ011 - the host's LOCAL date is the point
    write_csv(daily / f"ioc_{local_today.isoformat()}.csv", [good(value="192.0.2.17:17")])
    write_csv(daily / "ioc_2020-01-01.csv", [good(value="192.0.2.20:20")])
    code = _load_script().main(
        ["--dir", str(daily), "--env-file", str(env_file(tmp_path, str(ti_dsn)))]
    )
    capsys.readouterr()
    assert code == 0
    ti_conn.rollback()
    assert list(by_value(ti_conn)) == ["192.0.2.17:17"]


@needs_db
def test_main_when_todays_file_is_missing_is_no_file_exit_1_a_log_row_and_no_older_file_is_taken(
    ti_dsn, ti_conn, tmp_path, capsys
):
    daily = _daily(tmp_path)
    args = ["--dir", str(daily), "--env-file", str(env_file(tmp_path, str(ti_dsn)))]
    code = _load_script().main(args, today=date(2026, 11, 20))
    out = capsys.readouterr()
    assert code == 1
    assert out.out == (
        "ti_import: status=failed file=ioc_2026-11-20.csv total=0 new=0 updated=0 errors=0 repeated=0"
        " message=no_file\n"
    )
    gone = _load_script().main(
        ["--dir", str(tmp_path / "gone"), "--env-file", str(env_file(tmp_path, str(ti_dsn)))],
        today=date(2026, 11, 20),
    )
    capsys.readouterr()
    assert gone == 1
    ti_conn.rollback()
    assert iocs(ti_conn) == []  # nothing of an older day was imported in its place
    assert [(r["file"], r["status"], r["message"]) for r in logs(ti_conn)] == [
        ("ioc_2026-11-20.csv", "failed", "no_file")
    ] * 2
    assert all(str(tmp_path) not in r["file"] for r in logs(ti_conn))


@needs_db
def test_an_explicit_file_is_always_imported_whatever_its_name_or_date(
    ti_dsn, ti_conn, tmp_path, capsys
):
    script = _load_script()
    env = env_file(tmp_path, str(ti_dsn))
    for name, value in (
        ("ioc_2026-11-10.csv", "192.0.2.10:10"),
        ("rerun of monday.csv", "192.0.2.11:11"),
    ):
        path = write_csv(tmp_path / name, [good(value=value)])
        assert script.main([str(path), "--env-file", str(env)], today=date(2030, 1, 1)) == 0
    out = capsys.readouterr().out
    assert "file=ioc_2026-11-10.csv" in out and "file=rerun_of_monday.csv" in out
    ti_conn.rollback()
    assert set(by_value(ti_conn)) == {"192.0.2.10:10", "192.0.2.11:11"}


@needs_db
def test_main_names_the_span_of_a_record_that_swallowed_lines(ti_dsn, ti_conn, tmp_path, capsys):
    code = _load_script().main(
        [str(_forging_file(tmp_path)), "--env-file", str(env_file(tmp_path, str(ti_dsn)))]
    )
    out = capsys.readouterr()
    assert code == 0
    assert out.err == "ti_import: lines 3-5: row_malformed\n"
    assert "total=5 new=2 updated=0 errors=3 repeated=0" in out.out


@needs_db
def test_main_with_a_file_that_is_not_there_is_exit_1_and_a_failed_log_row(
    ti_dsn, ti_conn, tmp_path, capsys
):
    code = _load_script().main(
        [str(tmp_path / "ioc_x.csv"), "--env-file", str(env_file(tmp_path, str(ti_dsn)))]
    )
    out = capsys.readouterr()
    assert code == 1 and "message=file_unreadable" in out.out and str(tmp_path) not in out.out
    ti_conn.rollback()
    assert [(r["file"], r["status"]) for r in logs(ti_conn)] == [("ioc_x.csv", "failed")]


@needs_db
def test_the_command_runs_by_a_plain_path_from_any_directory_and_reads_the_file_not_the_environment(
    ti_dsn, ti_conn, tmp_path
):
    """The cron line starts it as `<venv python> <checkout>/scripts/ti_import.py --env-file <checkout>/.env`, from
    root's home. It must find `backend/` on its own, take the DSN from the file, and ignore a `DATABASE_URL` in the
    environment (here a decoy that points nowhere)."""
    elsewhere = tmp_path / "somewhere" / "else"
    elsewhere.mkdir(parents=True)
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "DATABASE_URL")}
    env["DATABASE_URL"] = closed_port_dsn("ENVSENTINEL-5d2b")
    done = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            str(SAMPLE),
            "--env-file",
            str(env_file(tmp_path, str(ti_dsn))),
        ],
        cwd=elsewhere,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert (
        done.stdout
        == "ti_import: status=ok file=ioc_sample.csv total=12 new=12 updated=0 errors=0 repeated=0\n"
    )
    assert done.stderr == ""
    assert "ENVSENTINEL" not in done.stdout + done.stderr
    assert str(ti_dsn) not in done.stdout + done.stderr
    password = urllib.parse.urlsplit(str(ti_dsn)).password
    if password:
        assert password not in done.stdout + done.stderr
    ti_conn.rollback()
    assert len(iocs(ti_conn)) == 12


@needs_db
def test_the_command_works_with_an_empty_environment(ti_dsn, ti_conn, tmp_path):
    """So `env -i` before the interpreter (the runbook's optional hardening) costs it nothing."""
    done = subprocess.run(
        [
            sys.executable,
            "-B",
            str(SCRIPT),
            str(SAMPLE),
            "--env-file",
            str(env_file(tmp_path, str(ti_dsn))),
        ],
        cwd=tmp_path,
        env={},
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.startswith("ti_import: status=ok file=ioc_sample.csv total=12 new=12")
    ti_conn.rollback()
    assert len(iocs(ti_conn)) == 12


def test_the_runbooks_cron_line_runs_the_importer_as_the_checkouts_owner_without_bytecode():
    text = (conftest.REPO_ROOT / "docs" / "runbook.md").read_text(encoding="utf-8")
    section = text.split("## Threat Intel importer (DEC-224)", 1)[1].split("\n## ", 1)[0]
    cron = [ln.strip() for ln in section.splitlines() if ln.strip().startswith("0 7 * * *")]
    assert len(cron) == 1
    after_fetch = cron[0].split("abusech_daily100.py", 1)[1]
    assert " && runuser -u user1 -- " in after_fetch
    runuser = after_fetch.split(" && runuser -u user1 -- ", 1)[1]
    assert runuser.split(" ")[0].endswith("/.venv/bin/python") and runuser.split(" ")[1] == "-B"
    assert "scripts/ti_import.py --env-file " in runuser and runuser.endswith("2>&1")
    assert "as root" not in section.lower()


def test_the_command_as_a_subprocess_with_the_database_down_prints_the_type_only(tmp_path):
    done = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            str(SAMPLE),
            "--env-file",
            str(env_file(tmp_path, closed_port_dsn())),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 1
    assert "database_unreachable: OperationalError" in done.stdout
    for forbidden in ("PWSENTINEL", "app_rw", "127.0.0.1", "Traceback"):
        assert forbidden not in done.stdout + done.stderr
