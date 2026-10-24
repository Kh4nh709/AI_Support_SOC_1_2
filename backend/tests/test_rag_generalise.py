"""P13-T02 / DEC-210, spec §7.4 — `rag.generalise`: the placeholders and the V3 fault names.

`placeholderise` turns the values that identify one event (an address, an account, a host, an id, a
hash, a number) into the placeholder of their kind, so that the fingerprint of one scan matches the
fingerprint of the next. `literal_findings` is its inverse as a check: the NAMES of the kinds of
literal still in a text, never the values (V3 puts them in a message an admin reads, and a value
would put an address into a log line).

The values are the ones in the two real samples the SOAR team sent (`fixtures/soar_payload_sample_*`,
copies of `docs/plan/tasks/P12/`); every expected string is written out, not computed by the code
under test. Pure: no database.
"""

from __future__ import annotations

import time

import pytest
from app.rag.generalise import literal_findings, placeholderise

from tests.soar_payloads import mw03, sc03

HOSTS = ["Windows_Endpoint", "HR-computer.fpt.com", "HR-computer", "pfSense.home.arpa"]

SC03_LINE = (
    "<134>Oct 16 21:19:30 filterlog[21588]: 1,6,,1000000103,em1,match,block,in,4,0x0,,48,23087,0,"
    "none,6,tcp,44,79.79.78.202,79.79.78.75,48509,993,0,S,91263131,,1024,,mss"
)
SC03_TEMPLATE = (
    "<<N>>Oct <N> <N>:<N>:<N> filterlog[<N>]: <N>,<N>,,<N>,em<N>,match,block,in,<N>,<N>x<N>,,<N>,<N>,"
    "<N>,none,<N>,tcp,<N>,<IP_NGOAI>,<IP_NGOAI>,<N>,<N>,<N>,S,<N>,,<N>,,mss"
)


# ── each placeholder, with the values of the two samples ──────────────────────────────────────


def test_the_external_address_of_the_port_scan_sample_is_ip_ngoai() -> None:
    assert sc03()["data"]["srcip"] == "79.79.78.202"
    assert placeholderise("79.79.78.202", []) == "<IP_NGOAI>"
    assert placeholderise("from 79.79.78.202 to 79.79.78.75.", []) == (
        "from <IP_NGOAI> to <IP_NGOAI>."
    )


@pytest.mark.parametrize("address", ["192.168.102.20", "10.0.0.7", "172.16.4.9", "127.0.0.1"])
def test_a_private_address_is_ip_noi_bo(address: str) -> None:
    assert mw03()["agent"]["ip"] == "192.168.102.20"
    assert placeholderise(f"agent {address} up", []) == "agent <IP_NOI_BO> up"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("peer 2606:4700:4700::1111 sent", "peer <IP_NGOAI> sent"),
        ("peer [2606:4700:4700::1111]:443 sent", "peer [<IP_NGOAI>]:<N> sent"),
        ("link fe80::1 up", "link <IP_NOI_BO> up"),
        ("loopback ::1 up", "loopback <IP_NOI_BO> up"),
        ("fd00:1234:5678::9 internal", "<IP_NOI_BO> internal"),
        ("mapped ::ffff:192.168.1.5 seen", "mapped <IP_NOI_BO> seen"),
        ("full 2001:4860:4860:0:0:0:0:8888 end", "full <IP_NGOAI> end"),
    ],
)
def test_ipv6_is_replaced_by_its_range(text: str, expected: str) -> None:
    assert placeholderise(text, []) == expected


def test_a_time_a_mac_a_version_and_a_scope_operator_are_not_addresses() -> None:
    text = "at 21:19:30 mac aa:bb:cc:dd:ee:ff build 10.0.19041.1234 call Foo::Bar now"
    out = placeholderise(text, [])
    assert "<IP_NGOAI>" not in out and "<IP_NOI_BO>" not in out
    assert out == ("at <N>:<N>:<N> mac aa:bb:cc:dd:ee:ff build <N>.<N>.<N>.<N> call Foo::Bar now")


def test_a_bare_double_colon_and_an_octet_over_255_are_not_addresses() -> None:
    assert placeholderise("a :: b", []) == "a :: b"
    assert placeholderise("v 999.1.1.1 x", []) == "v <N>.<N>.<N>.<N> x"


def test_an_address_with_leading_zeros_is_still_an_address() -> None:
    assert placeholderise("from 010.000.000.001 x", []) == "from <IP_NOI_BO> x"


def test_an_email_address_is_email() -> None:
    assert placeholderise("mail soc.admin+x@fpt.com.vn sent", []) == "mail <EMAIL> sent"
    assert placeholderise("hr01@HR-computer.fpt.com", ["HR-computer.fpt.com"]) == "<EMAIL>"


def test_the_domain_account_of_the_defender_sample_is_user() -> None:
    assert mw03()["data"]["win"]["eventdata"]["detectionUser"] == "FPT\\hr01"
    assert placeholderise("detected for FPT\\hr01 today", []) == "detected for <USER> today"
    assert placeholderise("run as NT AUTHORITY\\SYSTEM", []) == "run as NT <USER>"


def test_a_path_is_not_an_account_but_a_given_user_is_replaced_inside_it() -> None:
    path = "file:_C:\\Users\\hr01\\Documents\\eicar.com by C:\\Windows\\System32\\notepad.exe"
    assert placeholderise(path, [], users=["hr01"]) == (
        "file:_C:\\Users\\<USER>\\Documents\\eicar.com by C:\\Windows\\System<N>\\notepad.exe"
    )
    # without the user, only the digit rule touches the path: no `Users\hr01` account is invented
    assert "<USER>" not in placeholderise(path, [])


def test_the_given_hostnames_are_host_longest_first_and_case_insensitive() -> None:
    assert mw03()["agent"]["name"] == "Windows_Endpoint"
    assert placeholderise("Windows_Endpoint scanned", HOSTS) == "<HOST> scanned"
    assert placeholderise("windows_endpoint scanned", HOSTS) == "<HOST> scanned"
    # the FQDN goes whole, not as `<HOST>.fpt.com`
    assert placeholderise("HR-computer.fpt.com and HR-computer", HOSTS) == "<HOST> and <HOST>"


def test_a_hostname_is_replaced_only_as_a_whole_word() -> None:
    out = placeholderise("Windows_Endpoint2 and xWindows_Endpoint and Windows_Endpoint", HOSTS)
    assert out == "Windows_Endpoint<N> and xWindows_Endpoint and <HOST>"


def test_a_hostname_that_is_not_given_stays() -> None:
    assert placeholderise("Windows_Endpoint scanned", []) == "Windows_Endpoint scanned"


def test_a_hostname_cannot_eat_a_placeholder() -> None:
    # a hostname that equals a placeholder's letters must not change the placeholders around it
    out = placeholderise("a 79.79.78.202 b 12 c", ["N", "IP_NGOAI", "HOST"])
    assert out == "a <IP_NGOAI> b <N> c"


def test_a_hostname_in_angle_brackets_is_still_found_but_a_placeholder_is_not_a_hostname() -> None:
    assert placeholderise("log <srv-01> up", ["srv-01"]) == "log <<HOST>> up"
    assert literal_findings("log <srv-01> up", ["srv-01"]) == ["hostname"]
    assert literal_findings("<HOST> and <IP_NGOAI>", ["HOST", "IP_NGOAI"]) == []


def test_a_blank_or_one_letter_hostname_is_ignored() -> None:
    assert placeholderise("a b c", ["", " ", "a"]) == "a b c"


def test_the_graylog_id_and_the_wazuh_id_are_alert_id() -> None:
    gl = sc03()["id"]
    assert gl.startswith("gl-01M539BAX06VRSYZQ35BR1XJ1D-")
    assert placeholderise(f"event {gl} fired", []) == "event <ALERT_ID> fired"
    assert placeholderise("alert 1789200000.300001 fired", []) == "alert <ALERT_ID> fired"


def test_a_short_decimal_is_not_an_alert_id() -> None:
    assert placeholderise("ratio 3.14 of 12.5", []) == "ratio <N>.<N> of <N>.<N>"


@pytest.mark.parametrize(
    "digest",
    [
        "d41d8cd98f00b204e9800998ecf8427e",  # md5, 32
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # sha1, 40
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # sha256, 64
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",  # upper case
    ],
)
def test_a_hex_hash_of_32_characters_or_more_is_hash(digest: str) -> None:
    assert placeholderise(f"sha {digest} seen", []) == "sha <HASH> seen"


def test_a_hex_string_of_31_characters_is_not_a_hash() -> None:
    out = placeholderise("x d41d8cd98f00b204e9800998ecf8427 y", [])
    assert "<HASH>" not in out


def test_every_digit_run_is_n() -> None:
    assert placeholderise("port 48509 and 993, em1", []) == "port <N> and <N>, em<N>"


def test_the_longest_patterns_go_first_so_an_id_or_hash_is_not_split_into_numbers() -> None:
    out = placeholderise(
        "1789200000.300001 d41d8cd98f00b204e9800998ecf8427e 79.79.78.202 gl-"
        "01M539BAX06VRSYZQ35BR1XJ1D-46b75f26-c9a7-11f1-ae13-9a661b530912",
        [],
    )
    assert out == "<ALERT_ID> <HASH> <IP_NGOAI> <ALERT_ID>"


# ── the real log lines ────────────────────────────────────────────────────────────────────────


def test_the_port_scan_log_line_becomes_its_template() -> None:
    assert sc03()["full_log"].startswith(SC03_LINE)
    assert placeholderise(SC03_LINE, ["pfSense.home.arpa"]) == SC03_TEMPLATE


def test_two_scans_from_other_addresses_share_one_template() -> None:
    other = SC03_LINE.replace("79.79.78.202", "45.33.32.156").replace("48509", "51234")
    other = other.replace("23087", "9").replace("21588", "777")
    assert placeholderise(other, []) == SC03_TEMPLATE


def test_the_defender_sample_keeps_the_threat_name_and_loses_the_account() -> None:
    event = mw03()["data"]["win"]["eventdata"]
    text = f"{event['threatName']} user {event['detectionUser']} path {event['path']}"
    out = placeholderise(text, ["Windows_Endpoint"], users=["hr01"])
    assert out == (
        "Virus:DOS/EICAR_Test_File user <USER> path file:_C:\\Users\\<USER>\\Documents\\eicar.com"
    )


def test_placeholderise_is_idempotent() -> None:
    once = placeholderise(SC03_LINE, ["pfSense.home.arpa"])
    assert placeholderise(once, ["pfSense.home.arpa"]) == once


def test_a_generator_of_hostnames_is_read_once_and_used_everywhere() -> None:
    hosts = (h for h in ["alpha-1", "beta-2"])
    assert placeholderise("alpha-1 beta-2 alpha-1", hosts) == "<HOST> <HOST> <HOST>"


def test_an_empty_text_is_empty() -> None:
    assert placeholderise("", HOSTS) == ""


# ── literal_findings ──────────────────────────────────────────────────────────────────────────


def test_literal_findings_names_every_kind_of_literal() -> None:
    gl = sc03()["id"]
    text = (
        f"from 79.79.78.202 account FPT\\hr01 on Windows_Endpoint, event {gl}, "
        "hash d41d8cd98f00b204e9800998ecf8427e"
    )
    assert literal_findings(text, HOSTS) == ["ipv4", "account", "hostname", "alert_id", "hash"]


def test_literal_findings_has_a_name_for_ipv6_and_for_an_email() -> None:
    assert literal_findings("peer 2606:4700:4700::1111", []) == ["ipv6"]
    assert literal_findings("mail soc.admin@fpt.com.vn", []) == ["email"]


@pytest.mark.parametrize(
    ("text", "name"),
    [
        ("from 79.79.78.202", "ipv4"),
        ("from 192.168.102.20", "ipv4"),  # a private address is still a literal address
        ("FPT\\hr01", "account"),
        ("Windows_Endpoint", "hostname"),
        ("windows_endpoint", "hostname"),
        ("alert 1789200000.300001", "alert_id"),
        ("d41d8cd98f00b204e9800998ecf8427e", "hash"),
    ],
)
def test_each_fault_is_found_alone(text: str, name: str) -> None:
    assert literal_findings(text, HOSTS) == [name]


def test_literal_findings_never_echoes_a_value() -> None:
    gl = sc03()["id"]
    text = f"79.79.78.202 FPT\\hr01 Windows_Endpoint {gl} d41d8cd98f00b204e9800998ecf8427e a@b.vn"
    joined = " ".join(literal_findings(text, HOSTS))
    for value in ("79.79", "FPT", "hr01", "Windows", "Endpoint", "gl-01M", "d41d8cd", "a@b.vn"):
        assert value not in joined
    assert set(literal_findings(text, HOSTS)) == {
        "ipv4",
        "email",
        "account",
        "hostname",
        "alert_id",
        "hash",
    }


def test_text_written_with_placeholders_has_no_finding() -> None:
    text = "Quét cổng từ <IP_NGOAI> vào <HOST>; tài khoản <USER>; mã <ALERT_ID> <HASH> <N> lần."
    assert literal_findings(text, HOSTS) == []


def test_a_plain_vietnamese_sentence_has_no_finding() -> None:
    assert (
        literal_findings("Máy chủ quét cổng bị chặn bởi tường lửa, không có thiệt hại.", HOSTS)
        == []
    )


def test_a_one_letter_hostname_is_not_a_finding() -> None:
    assert literal_findings("a b c", ["a", ""]) == []


def test_what_placeholderise_removes_literal_findings_no_longer_reports() -> None:
    for line in (SC03_LINE, mw03()["data"]["win"]["eventdata"]["path"], sc03()["id"]):
        assert literal_findings(placeholderise(line, HOSTS), HOSTS) == []


# ── a hostile log line costs time in proportion to its length ─────────────────────────────────


@pytest.mark.parametrize(
    "unit",
    ["a", "a.", "aa:", "0", "1.", "ab-", "A\\", "gl-", "\u00e9", "f", "1:", "::"],
)
def test_a_long_repetitive_log_is_processed_in_linear_time(unit: str) -> None:
    """Each pattern starts only at the start of a run of its characters. Without that, a long
    run of letters is read again from every letter on, which is quadratic: 100,000 characters
    take minutes."""
    text = unit * (100_000 // len(unit))
    started = time.perf_counter()
    placeholderise(text, ["srv-01"], users=["hr01"])
    literal_findings(text, ["srv-01"])
    assert time.perf_counter() - started < 5.0


def test_a_long_hex_run_that_is_not_a_hash_is_processed_in_linear_time() -> None:
    text = "f" * 100_000 + "g"
    started = time.perf_counter()
    out = placeholderise(text, [])
    literal_findings(text, [])
    assert time.perf_counter() - started < 5.0
    assert "<HASH>" not in out
