"""DEC-224 T3 — the pure half of the Threat Intel read side (`app.ti.queries`): the functions that touch no database.

* **`csv_cell`**, the CSV-injection guard: a `'` before any cell that begins with `=`, `+`, `-`, `@`, a tab or a carriage
  return, or with one of `= + - @` after leading white space (a space, a no-break space, any Unicode space), the original
  cell kept behind the `'`; nothing else changed;
* **`export_csv`**, the CSV text: a UTF-8 byte order mark, the header, the guard on EVERY cell (the tags too), RFC 4180
  quoting, one record per row whatever a cell holds;
* **`blocklist_entry` / `blocklist_text`**, the plain-text blocklist: domains and IP addresses only, the port of an `ip:port`
  dropped, an IPv6 only in brackets, a value with anything but the characters of a hostname or an address left out (so a
  line break in a value can never make two lines), de-duplicated, and NEVER an address or a name a firewall or a DNS
  sinkhole must not block (`NEVER_BLOCK_V4`, `GLOBAL_UNICAST_V6`, `NEVER_BLOCK_NAME_ENDINGS`: each case below);
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
    [
        "", "abc", "a=b", "a+b", "x-y", "user@example.com", "'=x", "1.2.3.4", "0", "é=", "\nx",
        " ", "   ", " x=1", " a+b", "\u00a0abc", "\u2003x@y", " 'x", "\n\n", " \n ",
    ],
)  # fmt: skip
def test_any_other_cell_is_returned_unchanged(text):
    assert queries.csv_cell(text) == text


@pytest.mark.parametrize(
    "space",
    [
        " ",
        "  ",
        "\u00a0",
        "\u2003",
        "\u3000",
        "\u202f",
        "\u1680",
        "\u2009",
        "\n",
        "\x0b",
        "\x0c",
        " \u00a0 ",
    ],
)
@pytest.mark.parametrize("lead", ["=", "+", "-", "@"])
def test_a_formula_character_after_white_space_is_guarded_and_the_original_cell_is_kept(
    space, lead
):
    cell = f"{space}{lead}1+1"
    assert queries.csv_cell(cell) == "'" + cell


@pytest.mark.parametrize(
    ("cell", "guarded"),
    [
        ("\t", True), ("\r", True), ("\t\t", True), ("\tabc", True), ("\rabc", True),
        ("\t =x", True), ("\r =x", True), (" \t=x", True), ("\u00a0\t=x", True),
        (" \tabc", False), (" \r", False), ("\u00a0\rabc", False),
    ],
)  # fmt: skip
def test_a_tab_or_a_carriage_return_at_the_start_is_guarded_whatever_follows(cell, guarded):
    """The first character decides for a tab or a CR (white space itself, so the rule after white space must not skip it);
    after any other white space only a formula character counts."""
    assert queries.csv_cell(cell) == ("'" + cell if guarded else cell)


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
    """The records of an export; the byte order mark every export starts with is not part of the first cell."""
    return list(csv.reader(io.StringIO(text.removeprefix("\ufeff"), newline="")))


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


def test_the_csv_starts_with_a_utf_8_byte_order_mark_and_the_first_header_cell_is_still_id():
    text = queries.export_csv([row(value="bücher.example.com")])
    assert text.startswith("\ufeffid,source,")
    assert text.encode("utf-8").startswith(b"\xef\xbb\xbf")
    # a reader that drops the mark (Excel, `utf-8-sig`) sees `id`; the mark appears once and nowhere else
    header = next(csv.reader(io.StringIO(text.encode("utf-8").decode("utf-8-sig"), newline="")))
    assert header[0] == "id" and text.count("\ufeff") == 1
    assert queries.export_csv([]).startswith("\ufeffid,")


# ── blocklist ───────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("kind", "value", "expected"),
    [
        ("domain", "c2.example.com", "c2.example.com"),
        ("domain", "C2.Example.COM", "c2.example.com"),
        ("domain", "example.com", "example.com"),
        ("domain", "xn--bcher-kva.example.com", "xn--bcher-kva.example.com"),
        ("domain", "a-b.c_d.example.net", "a-b.c_d.example.net"),
        ("domain", "1.example.com", "1.example.com"),  # an all-digit label is fine; the LAST one decides
        ("domain", "127.0.0.1.example.com", "127.0.0.1.example.com"),
        ("domain", "local.example.com", "local.example.com"),  # a never-block word is judged as the LAST label only
        ("domain", "home.example.net", "home.example.net"),
        ("domain", "corp.example.com", "corp.example.com"),
        ("domain", "notlocal.com", "notlocal.com"),
        ("domain", "x.localdomain.com", "x.localdomain.com"),
        ("ip:port", "192.0.2.10:443", "192.0.2.10"),
        ("ip:port", "198.51.100.24:8080", "198.51.100.24"),
        ("ip:port", "203.0.113.5:1", "203.0.113.5"),
        ("ip:port", "203.0.113.5:65535", "203.0.113.5"),
        ("ip:port", "192.0.2.10", "192.0.2.10"),
        ("ip:port", "[2001:db8::1]:443", "2001:db8::1"),
        ("ip:port", "[2001:0DB8:0000:0000:0000:0000:0000:0001]:8080", "2001:db8::1"),
        ("ip:port", "[2000::1]:80", "2000::1"),
        ("ip:port", "[3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:80", "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        # an IPv4-mapped IPv6 is the IPv4 address it wraps, judged and written as that
        ("ip:port", "[::ffff:192.0.2.1]:443", "192.0.2.1"),
        ("ip:port", "[::ffff:c000:201]:443", "192.0.2.1"),
        ("ip:port", "[::FFFF:203.0.113.9]:1", "203.0.113.9"),
    ],
)  # fmt: skip
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
        ("domain", "bücher.example.com"),
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
        # an IPv6 address is accepted only in brackets: `2001:db8::1:443` would be another host, not a port
        ("ip:port", "2001:db8::1:443"),
        ("ip:port", "2001:db8::1"),
        ("ip:port", "2001:db8::"),
        ("ip:port", "2001:0db8:0000:0000:0000:0000:0000:0001"),
        ("ip:port", "::ffff:192.0.2.1"),
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
        row(type="ip:port", value="[::ffff:192.0.2.10]:80"),  # the same address, wrapped in IPv6
        row(type="domain", value="C2.EXAMPLE.COM"),  # the same name, spelt another way
        row(type="url", value="http://c2.example.com/x"),
        row(type="sha256_hash", value="b" * 64),
        row(type="domain", value="evil.example.net\nc2.example.com"),
        row(type="ip:port", value="[2001:db8::1]:443"),
        row(type="ip:port", value="[2001:0db8::1]:80"),  # the same IPv6 address, spelt another way
        row(type="domain", value="payload.example.net"),
    ]
    text = queries.blocklist_text(rows)
    assert text == "192.0.2.10\nc2.example.com\n2001:db8::1\npayload.example.net\n"
    assert text.splitlines() == text.rstrip("\n").split("\n")  # no line holds a line break


def test_an_empty_blocklist_is_an_empty_text():
    assert queries.blocklist_text([]) == ""
    assert queries.blocklist_text([row(type="url", value="http://x.example.com/")]) == ""


# ── what a blocklist must never carry (Rulings TI9 and TI10, I1) ──────────────────────────

#: Every address a firewall or a DNS sinkhole must never block, by kind; each is tried as `ip:port`, bare (IPv4) and in brackets
#: (IPv6), and each is also tried wrapped in an IPv4-mapped IPv6 address. The kind is in the id of the case.
NEVER_V4 = {
    "unspecified": ["0.0.0.0", "0.0.0.1", "0.1.2.3", "0.255.255.255"],
    "rfc1918 10/8": ["10.0.0.0", "10.0.0.1", "10.1.2.3", "10.255.255.255"],
    "rfc1918 172.16/12": ["172.16.0.0", "172.16.0.1", "172.20.5.5", "172.31.255.255"],
    "rfc1918 192.168/16": ["192.168.0.0", "192.168.1.1", "192.168.255.255"],
    "ietf protocol 192.0.0.0/24": [
        "192.0.0.0",
        "192.0.0.1",
        "192.0.0.8",
        "192.0.0.170",
        "192.0.0.255",
    ],
    "benchmarking and fake-ip 198.18/15": [
        "198.18.0.0",
        "198.18.0.1",
        "198.19.0.1",
        "198.19.255.255",
    ],
    "cgnat 100.64/10": ["100.64.0.0", "100.64.0.1", "100.100.100.100", "100.127.255.255"],
    "loopback": ["127.0.0.1", "127.0.0.2", "127.1.2.3", "127.255.255.255"],
    "link-local": ["169.254.0.0", "169.254.1.1", "169.254.169.254", "169.254.255.255"],
    "multicast": ["224.0.0.0", "224.0.0.1", "232.1.1.1", "239.255.255.255"],
    "reserved and broadcast": [
        "240.0.0.0",
        "240.0.0.1",
        "250.1.1.1",
        "255.255.255.254",
        "255.255.255.255",
    ],
}
NEVER_V6 = {
    "unspecified": ["::"],
    "loopback": ["::1"],
    "link-local fe80::/10": ["fe80::", "fe80::1", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
    "site-local fec0::/10": ["fec0::1", "feff::1"],
    "unique local fc00::/7": ["fc00::1", "fd12:3456:789a::1", "fdff:ffff::1"],
    "multicast": ["ff00::", "ff02::1", "ff05::2"],
    "ipv4-compatible and other reserved space": [
        "::192.0.2.1", "::2", "64:ff9b::c000:201", "100::1", "1fff:ffff::1", "4000::1", "8000::1", "fe00::1",
    ],
    "ipv4-mapped, wrapping a private address": [
        "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:192.168.1.1", "::ffff:0.0.0.0", "::ffff:255.255.255.255",
        "::ffff:7f00:1", "::ffff:a00:1", "::ffff:192.0.0.1", "::ffff:c000:1", "::ffff:198.18.0.1", "::ffff:c612:1",
    ],
    "benchmarking 2001:2::/48, inside the global block": [
        "2001:2::", "2001:2::1", "2001:2:0:1::1", "2001:2:0:ffff:ffff:ffff:ffff:ffff",
    ],
}  # fmt: skip
#: Addresses just outside each never-block range, and the documentation ranges the committed test data lives in: all stay.
STAY_V4 = [
    "1.0.0.1", "9.255.255.255", "11.0.0.1", "100.63.255.255", "100.128.0.0", "126.255.255.255", "128.0.0.1",
    "169.253.255.255", "169.255.0.1", "172.15.255.255", "172.32.0.0", "192.167.255.255", "192.169.0.1",
    "223.255.255.254", "192.0.2.0", "192.0.2.1", "192.0.2.255", "198.51.100.1", "203.0.113.254",
    "191.255.255.255", "192.0.1.0", "192.0.1.255", "198.17.255.255", "198.20.0.0", "198.20.0.1",
]  # fmt: skip
STAY_V6 = [
    "2000::1",
    "2001:db8::1",
    "2001:db8:ffff::1",
    "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
    "3fff:ffff::1",
    # just outside 2001:2::/48, and the neighbours of the global block's special ranges
    "2001:2:1::1",
    "2001:3::1",
    "2001:1:ffff:ffff::1",
    "2001::1",
]


def _forms(address: str) -> list[str]:
    """The `ip:port` spellings of one address: with and without a port for IPv4, bracketed for IPv6."""
    if ":" in address:
        return [f"[{address}]:443", f"[{address}]:1", f"[{address.upper()}]:65535"]
    return [address, f"{address}:443", f"{address}:1", f"{address}:65535"]


NEVER = [
    (f"{family} {kind}", address)
    for family, groups in (("v4", NEVER_V4), ("v6", NEVER_V6))
    for kind, group in groups.items()
    for address in group
]


@pytest.mark.parametrize(("kind", "address"), NEVER, ids=[f"{k}-{a}" for k, a in NEVER])
def test_an_address_a_firewall_must_never_block_gives_no_line(kind, address):
    for value in _forms(address):
        assert queries.blocklist_entry("ip:port", value) is None, (kind, value)
    if ":" not in address:  # an IPv4 address wrapped in IPv6 is judged as the IPv4 address it is
        for value in (f"[::ffff:{address}]:443", f"[::FFFF:{address}]:1"):
            assert queries.blocklist_entry("ip:port", value) is None, (kind, value)


@pytest.mark.parametrize(
    "address", NEVER_V4["loopback"] + NEVER_V4["rfc1918 10/8"] + ["0.0.0.0", "192.0.2.1"]
)
def test_an_ip_literal_written_as_a_domain_is_left_out_and_does_not_become_an_address_line(address):
    assert queries.blocklist_entry("domain", address) is None


@pytest.mark.parametrize("address", STAY_V4)
def test_an_address_just_outside_a_never_block_range_or_in_a_documentation_range_stays(address):
    for value in _forms(address):
        assert queries.blocklist_entry("ip:port", value) == address, value
    assert queries.blocklist_entry("ip:port", f"[::ffff:{address}]:443") == address


@pytest.mark.parametrize("address", STAY_V6)
def test_an_ipv6_address_in_global_unicast_space_or_the_documentation_range_stays(address):
    import ipaddress

    canonical = str(ipaddress.ip_address(address))
    for value in _forms(address):
        assert queries.blocklist_entry("ip:port", value) == canonical, value


@pytest.mark.parametrize(
    "name",
    [
        # fewer than two labels
        "com", "net", "localhost", "lan", "localdomain", "internal", "example", "x", "a" * 63, "LOCALHOST",
        # the last label is a word a resolver answers for itself, or that is no name on the internet
        "x.local", "x.localhost", "x.localdomain", "printer.lan", "nas.home", "db.internal", "wiki.intranet",
        "dc.corp", "1.0.0.127.in-addr.arpa", "x.arpa", "a.b.ip6.arpa", "a.test", "a.invalid", "foo.example",
        "abcdefghijklmnop.onion", "X.LOCAL", "C2.Example.INTERNAL", "a.b.c.corp", "a-b.home",
        # an IP literal written as a domain: the last label is all digits
        "127.0.0.1", "0.0.0.0", "10.1.2.3", "192.168.1.1", "169.254.1.1", "100.64.0.1", "224.0.0.1",
        "255.255.255.255", "192.0.2.1", "203.0.113.9", "8.8.8.8", "1.2", "x.123", "0x7f.0.0.1", "a.b.1",
        # the same literals spelt in hex, octal or as one number: getaddrinfo reads them as an address with no DNS query
        "127.0.0.0x1", "0x7f.0x0.0x0.0x1", "0xa.0x1", "192.168.1.0x1", "169.254.169.0xfe", "0.0.0.0x0",
        "2130706433", "0177.0.0.1", "127.1", "0x7f000001", "0X7F.0.0.1", "10.0.0.0X1", "0300.0250.0.1",
        "a.0xff", "x.0x7f", "1.2.3.0x4", "example.0x1",
        # a last label that is not a real top-level label: one letter, a digit in it, a hyphen at an end, too long
        "a.b", "example.c", "x.y.z", "example.c0m", "example.co1", "example.1com", "example.com1", "example.c-m",
        "example.xn--", "example.xn", "example.x_y", "a." + "b" * 64,
    ],
)  # fmt: skip
def test_a_name_that_is_no_host_to_block_gives_no_line(name):
    assert queries.blocklist_entry("domain", name) is None


@pytest.mark.parametrize(
    ("name", "line"),
    [
        ("example.com", "example.com"),
        ("c2.example.com", "c2.example.com"),
        ("example.net", "example.net"),
        ("example.co", "example.co"),
        ("a.ab", "a.ab"),
        ("EXAMPLE.COM", "example.com"),
        ("example.xn--p1ai", "example.xn--p1ai"),
        ("EXAMPLE.XN--P1AI", "example.xn--p1ai"),
        ("example.xn--80asehdb", "example.xn--80asehdb"),
        ("xn--bcher-kva.xn--p1ai", "xn--bcher-kva.xn--p1ai"),
        ("example.museum", "example.museum"),
        ("a." + "b" * 63, "a." + "b" * 63),
        ("127.0.0.1.example.com", "127.0.0.1.example.com"),
        ("0x7f.example.com", "0x7f.example.com"),
        ("1.0xa.example.org", "1.0xa.example.org"),
    ],
)
def test_a_real_top_level_label_is_two_to_63_letters_or_punycode(name, line):
    assert queries.blocklist_entry("domain", name) == line


def test_the_never_block_constants_are_these_and_no_others():
    """The closed sets, written out: a test that would not notice one of them changing is no test of the rule."""
    assert queries.NEVER_BLOCK_V4 == (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
        "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
    )  # fmt: skip
    assert queries.GLOBAL_UNICAST_V6 == "2000::/3"
    assert queries.NEVER_BLOCK_V6_WITHIN_GLOBAL == ("2001:2::/48",)
    assert queries.NEVER_BLOCK_NAME_ENDINGS == frozenset(
        {"local", "localhost", "localdomain", "lan", "home", "internal", "intranet", "corp", "arpa", "test", "invalid", "example", "onion"}
    )  # fmt: skip


def test_the_documentation_names_and_ranges_of_the_test_data_are_not_in_the_never_block_sets():
    import ipaddress

    nets = [ipaddress.ip_network(n) for n in queries.NEVER_BLOCK_V4]
    for doc in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"):
        assert not any(ipaddress.ip_network(doc).overlaps(net) for net in nets), doc
    assert ipaddress.ip_network("2001:db8::/32").subnet_of(
        ipaddress.ip_network(queries.GLOBAL_UNICAST_V6)
    )
    # the exclusions inside the global block are inside it, and the documentation range is not touched by them
    inside = [ipaddress.ip_network(n) for n in queries.NEVER_BLOCK_V6_WITHIN_GLOBAL]
    assert all(net.subnet_of(ipaddress.ip_network(queries.GLOBAL_UNICAST_V6)) for net in inside)
    assert not any(ipaddress.ip_network("2001:db8::/32").overlaps(net) for net in inside)
    assert not {"com", "net", "org"} & queries.NEVER_BLOCK_NAME_ENDINGS


def test_a_blocklist_of_rows_leaves_out_what_must_never_be_blocked_and_keeps_the_rest():
    rows = [
        row(type="ip:port", value="127.0.0.1:80"),
        row(type="ip:port", value="10.0.0.1:80"),
        row(type="ip:port", value="[::1]:80"),
        row(type="ip:port", value="[fe80::1]:80"),
        row(type="ip:port", value="[::ffff:192.168.1.1]:80"),
        row(type="ip:port", value="192.0.2.1:80"),
        row(type="domain", value="localhost"),
        row(type="domain", value="127.0.0.1"),
        row(type="domain", value="x.local"),
        row(type="domain", value="127.0.0.0x1"),
        row(type="domain", value="0xa.0x1"),
        row(type="ip:port", value="192.0.0.1:80"),
        row(type="ip:port", value="[::ffff:198.18.0.1]:80"),
        row(type="ip:port", value="[2001:2::1]:80"),
        row(type="domain", value="c2.example.com"),
        row(type="ip:port", value="255.255.255.255:80"),
    ]
    assert queries.blocklist_text(rows) == "192.0.2.1\nc2.example.com\n"


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


# ── the byte order mark in the source (Ruling TI10) ─────────────────────────────────────────


def test_the_byte_order_mark_is_written_in_the_source_as_an_escape_not_as_an_invisible_character():
    from pathlib import Path

    source = Path(queries.__file__).read_text(encoding="utf-8")
    lines = [line for line in source.splitlines() if line.startswith("CSV_BOM = ")]
    assert lines == ['CSV_BOM = "\\ufeff"']  # the six characters backslash, u, f, e, f, f
    assert queries.CSV_BOM == "\ufeff" and len(queries.CSV_BOM) == 1


def test_no_source_file_of_the_read_side_holds_an_invisible_format_or_separator_character():
    import unicodedata
    from pathlib import Path

    root = Path(queries.__file__).resolve().parents[1]
    for path in (root / "ti" / "queries.py", root / "web" / "routers" / "ti.py"):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for char in line:
                assert unicodedata.category(char) not in {"Cf", "Zl", "Zp", "Cc"} or char == "\t", (
                    path.name,
                    number,
                    hex(ord(char)),
                )


# ── the shape of the module ─────────────────────────────────────────────────────────────────


def test_the_cap_of_an_export_is_above_what_30_days_of_the_feed_leave_unexpired():
    # three sources of 100 rows a day for 30 days: 9 000 rows; the cap leaves room above that
    assert queries.EXPORT_MAX_ROWS >= 10_000


def test_the_bounds_of_the_routes_are_the_importers_own_ceilings():
    from app.ti import importer

    assert queries.VALUE_MAX == importer.VALUE_MAX_BYTES
    assert queries.MALWARE_MAX == importer.MALWARE_MAX_BYTES
    assert queries.TYPE_MAX == importer.TYPE_MAX_BYTES


def test_q_is_capped_at_128_characters_and_a_lookup_keeps_the_importers_2048():
    # a whole URL belongs to the lookup, not to a four-column substring search (Ruling TI9, I2)
    assert queries.Q_MAX == 128
    assert queries.VALUE_MAX == 2048


def test_every_read_has_a_statement_timeout_of_five_seconds_by_default():
    assert queries.STATEMENT_TIMEOUT == "5s"


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
