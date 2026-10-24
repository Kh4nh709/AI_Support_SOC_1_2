"""Generalisation: placeholders for what identifies one event, and the check that none is left
(P13-T02, DEC-210, spec §7.4 V3).

`placeholderise` replaces, longest pattern first (so an id or a hash is not cut into digit runs):

    Graylog id `gl-…`                              <ALERT_ID>
    e-mail address                                 <EMAIL>
    `DOMAIN\\user`                                 <USER>
    IPv6, then IPv4 address                        <IP_NOI_BO> if `ipaddress.is_private`, else <IP_NGOAI>
    hex hash of 32 characters or more              <HASH>
    Wazuh id `<epoch>.<n>`                         <ALERT_ID>
    the given hostnames                            <HOST>
    the given user names (keyword `users`)         <USER>
    any other run of digits                        <N>

so the log of one port scan and the log of the next give the same template. The given names are
matched whole-word and case-insensitively, longest first, and never inside a placeholder.

`literal_findings` is the V3 check: it names the KINDS of literal still in a text (`ipv4`, `ipv6`,
`email`, `account`, `hostname`, `alert_id`, `hash`), in that order, and never returns a matched
value: the names go into messages an admin reads and into logs, and a value would put an address or
an account there. It uses the very patterns `placeholderise` replaces, so whatever `placeholderise`
removes is no longer a finding.

Pure: no I/O, no clock. Every pattern is anchored so that it starts only at the start of a run of
its characters, which keeps a long log line linear.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

IP_EXTERNAL = "<IP_NGOAI>"
IP_INTERNAL = "<IP_NOI_BO>"
EMAIL = "<EMAIL>"
USER = "<USER>"
HOST = "<HOST>"
ALERT_ID = "<ALERT_ID>"
HASH = "<HASH>"
NUMBER = "<N>"

#: The fault names `literal_findings` returns, in the order it returns them.
FINDING_NAMES = ("ipv4", "ipv6", "email", "account", "hostname", "alert_id", "hash")

_MIN_NAME = 2  # a one-letter "hostname" would match every word of that letter

# `gl-<ULID>-<uuid>`: a lenient shape (a long first segment, more hyphenated segments) so a variant
# of the Graylog id is still caught; the exact shape is `llm.builder.ID_PATTERNS["alert_id"]`.
_GL_ID = re.compile(r"(?<![\w-])gl-[0-9A-Za-z]{20,}(?:-[0-9A-Za-z]+)*(?![\w-])")
# `<epoch>.<n>`: nine or more digits before the point, so a decimal like 3.14 is not an id.
_WAZUH_ID = re.compile(r"(?<![\w.])\d{9,11}\.\d{1,9}(?!\w)")
_EMAIL = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
# `DOMAIN\user`. Not after a backslash, a colon, a slash or a dot, so `C:\Users\hr01` and
# `C:\Windows\System32` (a path, where each part follows a backslash) are not accounts.
_ACCOUNT = re.compile(
    r"(?<![\w\\:/.$-])[A-Za-z][A-Za-z0-9_.-]{0,62}\\[A-Za-z0-9][A-Za-z0-9._$-]{0,62}(?<![.-])"
)
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\d|\.\d)")
# A candidate IPv6 address; `ipaddress` decides whether it is one (a time, a MAC address and
# `Foo::Bar` look like candidates and are not).
_IPV6 = re.compile(
    r"(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{0,4}:){2,7}"
    r"(?:[0-9A-Fa-f]{0,4}|(?:\d{1,3}\.){3}\d{1,3})(?![0-9A-Za-z:]|\.\d)"
)
_HASH = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{32,}(?![0-9A-Za-z])")
_DIGITS = re.compile(r"\d+")
_HEX_DIGIT = re.compile(r"[0-9A-Fa-f]")
_PLACEHOLDER = r"<(?:IP_NGOAI|IP_NOI_BO|EMAIL|USER|HOST|ALERT_ID|HASH|N)>"


def _ipv4_placeholder(match: re.Match[str]) -> str:
    octets = [int(group) for group in match.groups()]
    if any(octet > 255 for octet in octets):
        return match.group(0)  # not an address: a version, a build number
    address = ipaddress.IPv4Address(".".join(str(octet) for octet in octets))
    return IP_INTERNAL if address.is_private else IP_EXTERNAL


def _ipv6_address(candidate: str) -> ipaddress.IPv6Address | None:
    if not _HEX_DIGIT.search(candidate):  # a bare `::`
        return None
    try:
        return ipaddress.IPv6Address(candidate)
    except ValueError:
        return None


def _ipv6_placeholder(match: re.Match[str]) -> str:
    address = _ipv6_address(match.group(0))
    if address is None:
        return match.group(0)
    mapped = address.ipv4_mapped
    private = mapped.is_private if mapped is not None else address.is_private
    return IP_INTERNAL if private else IP_EXTERNAL


def _name_pattern(names: Iterable[str]) -> re.Pattern[str] | None:
    """Whole-word, case-insensitive, longest first; placeholders are matched first and kept."""
    usable = {name.strip() for name in names if isinstance(name, str)}
    usable = {name for name in usable if len(name) >= _MIN_NAME}
    if not usable:
        return None
    ordered = sorted(usable, key=lambda name: (-len(name), name.lower()))
    alternation = "|".join(re.escape(name) for name in ordered)
    return re.compile(rf"({_PLACEHOLDER})|(?<![\w-])(?:{alternation})(?![\w-])", re.IGNORECASE)


def _replace_names(text: str, pattern: re.Pattern[str] | None, placeholder: str) -> str:
    if pattern is None:
        return text
    return pattern.sub(lambda m: m.group(1) or placeholder, text)


def placeholderise(text: str, hostnames: Iterable[str], *, users: Iterable[str] = ()) -> str:
    """`text` with every identifying value replaced by the placeholder of its kind (module doc).

    `users` are bare user names (the fingerprint passes the alert's own); `hostnames` are the hosts
    of the record and of the inventory. Both are matched whole-word, case-insensitively."""
    hosts = _name_pattern(list(hostnames))
    people = _name_pattern(list(users))
    out = _GL_ID.sub(ALERT_ID, text)
    out = _EMAIL.sub(EMAIL, out)
    out = _ACCOUNT.sub(USER, out)
    out = _IPV6.sub(_ipv6_placeholder, out)
    out = _IPV4.sub(_ipv4_placeholder, out)
    out = _HASH.sub(HASH, out)
    out = _WAZUH_ID.sub(ALERT_ID, out)
    out = _replace_names(out, hosts, HOST)
    out = _replace_names(out, people, USER)
    return _DIGITS.sub(NUMBER, out)


def _has_ipv4(text: str) -> bool:
    return any(all(int(group) <= 255 for group in match.groups()) for match in _IPV4.finditer(text))


def _has_ipv6(text: str) -> bool:
    return any(_ipv6_address(match.group(0)) is not None for match in _IPV6.finditer(text))


def _has_name(text: str, pattern: re.Pattern[str] | None) -> bool:
    return pattern is not None and any(m.group(1) is None for m in pattern.finditer(text))


def literal_findings(text: str, hostnames: Iterable[str]) -> list[str]:
    """The V3 fault names present in `text`, in `FINDING_NAMES` order. Never a matched value."""
    hosts = _name_pattern(list(hostnames))
    present = {
        "ipv4": _has_ipv4(text),
        "ipv6": _has_ipv6(text),
        "email": _EMAIL.search(text) is not None,
        "account": _ACCOUNT.search(text) is not None,
        "hostname": _has_name(text, hosts),
        "alert_id": _GL_ID.search(text) is not None or _WAZUH_ID.search(text) is not None,
        "hash": _HASH.search(text) is not None,
    }
    return [name for name in FINDING_NAMES if present[name]]
