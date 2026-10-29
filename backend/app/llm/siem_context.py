"""The text of the `siem_context` block: SOAR's `enrichment` object as lines a model can read and cite (S2).

SOAR sends each alert with an `enrichment` object — the scenario it matched, the signal in words, TI verdicts,
the action it plans, how often the rule fired before, a summary of a scan, the logs around the alert. All of it
is SIEM text and therefore UNTRUSTED: `llm/triage.py` puts what this module renders into ONE nonce-wrapped
block (`pb.block(text, "siem_context")`), as it does for the playbook and the correlation samples, and into
nothing else. This module only decides the words inside that block; it cannot reach the outside of one.

What it renders, in this order, present fields only (a `None` or an empty value is no field, `0` and `false`
are):

    scenario: id=… name=…
    signal_text: …                                  (the SIEM's sentence about the alert)
    signal_codes: …, …
    ti: type=… value=… verdict=…                    (one line per entry)
    ioc: …                                          (no example carries it yet: its scalar fields)
    geo: country=… country_simulated=… src_ip_type=… first_seen_country_30d=… seen_count_30d=…
         prior_failures_30m=… impossible_travel=… off_hours=…
    soar.planned_action: type=… target=… tier=… mode=…
    history: rule_7d_total=… rule_7d_host=… rule_7d_hosts=… first_seen_host=… last_seen=… truncated=…
    evidence.decoded_command: …                     (no example carries it yet)
    evidence.scan: sampled_packets=… distinct_dst_ports_sampled=… ports_sampled=… dst_ips=… actions=…
    evidence.context_logs (N entries):
    - key=value key=value …                         (one line per log)

No score is rendered — not `triage.score`, its parts, `rule_confidence` — and nothing of this reaches the facts
(`build_facts`), the verifier or `structured_basis`: the SIEM's number would be a second opinion the gate does not
weigh, so the model is not shown it either. Values are copied as they are (a backslash stays a backslash: a model
quotes them, and a quote must be a substring of the block); only whitespace is folded, so that a value cannot
start a line of its own and pose as a field, and a value with a space in it is wrapped in double quotes.

The block is capped at `MAX_BYTES` of UTF-8. Over it, the cut order is fixed: the surrounding logs go first
(they are the bulk, and the scan summary says the same in a line), then the sample of scanned ports, then —
only for an input that is over the cap even so — the tail of the text, cut by the block itself
(`Rendered.limit_bytes`), with the marker `wrap.truncate_block` puts inside it. Each cut is a warning, which
becomes `llm_runs.citation_warnings`.

Pure: no I/O, no clock, no randomness. Whatever the input — it is a JSON document from outside — it returns
a `Rendered` or `None`; it does not raise.
"""

from __future__ import annotations

import json
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from app.security import wrap

#: the block's UTF-8 size limit (S2 brief: ~8 KB)
MAX_BYTES = 8_192
#: room for the marker `wrap.truncate_block` appends, so that a cut block is still within `MAX_BYTES`
_MARKER_ALLOWANCE = 64

_VALUE_CAP = 300  # characters of one value
_TEXT_CAP = 600  # `signal_text`
_COMMAND_CAP = 2_000  # `evidence.decoded_command`
_KEY_CAP = 40
_LIST_CAP = 20  # entries of `signal_codes`, `ti`, `dst_ips`, `actions`
_PORTS_SAMPLE = 20
_LOG_CAP = 100  # log lines
_LOG_FIELDS_CAP = 20  # `key=value` pairs of one log line
#: the keys of a log line, and of an `ioc` entry, that come first, in this order, whatever the document's
#: order (see `_object_pairs`)
_LOG_KEYS_FIRST = ("ts", "eid", "user", "src_ip", "dst_ip", "dst_port", "proto", "pf_action")
_IOC_KEYS_FIRST = ("type", "value", "verdict", "reputation")

_GEO_KEYS = (
    "country",
    "country_simulated",
    "src_ip_type",
    "first_seen_country_30d",
    "seen_count_30d",
    "prior_failures_30m",
    "impossible_travel",
    "off_hours",
)
_ACTION_KEYS = ("type", "target", "tier", "mode")
_HISTORY_KEYS = (
    "rule_7d_total",
    "rule_7d_host",
    "rule_7d_hosts",
    "first_seen_host",
    "last_seen",
    "truncated",
)

LOGS_DROPPED = "siem_context_logs_dropped"
PORTS_DROPPED = "siem_context_ports_dropped"
CUT = "siem_context_cut"


@dataclass(frozen=True)
class Rendered:
    text: str
    warnings: tuple[str, ...]
    #: set only when `text` is still over the cap after the two cuts: the `limit_bytes` the block is built with
    limit_bytes: int | None = None


# ─────────────────────────────────────────────────────────── values
def _clean(value: Any, cap: int = _VALUE_CAP) -> str | None:
    """One value as one line of text: whitespace folded, cut at `cap` characters; `None` when it says nothing
    (a `None`, an empty string, a value this cannot print)."""
    try:
        if value is None:
            return None
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, str):
            text = value
        elif isinstance(value, int | float):
            text = str(value)
        elif isinstance(value, Mapping):
            text = json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":"))
        elif isinstance(value, Sequence):
            parts = (_clean(item, cap) for item in value[:_LIST_CAP])
            text = ",".join(part for part in parts if part)
        else:
            text = str(value)
    except (ValueError, TypeError, RecursionError):  # a 5 000-digit integer, a cycle
        return None
    text = text[: cap * 4]  # a megabyte of one value is not scanned character by character
    text = "".join(" " if unicodedata.category(char) == "Cc" else char for char in text)
    text = " ".join(text.split())
    if not text:
        return None
    return text if len(text) <= cap else text[: cap - 1] + "…"


def _pair(key: str, value: Any, cap: int = _VALUE_CAP) -> str | None:
    text = _clean(value, cap)
    if text is None:
        return None
    if " " in text:  # every whitespace is a plain space by now
        text = '"' + text.replace('"', "'") + '"'
    return f"{key}={text}"


def _get(node: Any, key: str) -> Any:
    return node.get(key) if isinstance(node, Mapping) else None


def _fields(label: str, node: Any, keys: Sequence[str]) -> str | None:
    pairs = [pair for key in keys if (pair := _pair(key, _get(node, key)))]
    return f"{label}: {' '.join(pairs)}" if pairs else None


def _entries(node: Any) -> list[Any]:
    """A list as it is, a single object as a list of one, anything else as none."""
    if isinstance(node, Mapping):
        return [node]
    if isinstance(node, Sequence) and not isinstance(node, str):
        return list(node[:_LIST_CAP])
    return []


# ─────────────────────────────────────────────────────────── sections
def _key(key: Any) -> str:
    return _clean(key, _KEY_CAP) or "?"


def _object_pairs(entry: Mapping[Any, Any], first_keys: Sequence[str]) -> list[str]:
    """All the fields of an object whose keys this does not know, as `key=value`: `first_keys` first, in
    their order, then the rest alphabetically. The order of the keys in the document is not used: the
    database holds it as `jsonb`, which does not keep it, and the same content must give the same lines.
    """
    first = [key for key in first_keys if key in entry]
    rest = sorted((key for key in entry if key not in first_keys), key=str)
    keys = (first + rest)[:_LOG_FIELDS_CAP]
    return [pair for key in keys if (pair := _pair(_key(key), entry[key]))]


def _ioc_lines(node: Any) -> list[str]:
    if isinstance(node, str | int | float) and not isinstance(node, bool):
        text = _clean(node)
        return [f"ioc: {text}"] if text else []
    lines = []
    for entry in _entries(node):
        pairs = _object_pairs(entry, _IOC_KEYS_FIRST) if isinstance(entry, Mapping) else []
        if pairs:
            lines.append(f"ioc: {' '.join(pairs)}")
    return lines


def _ports_pair(sampled: Any, shown: int) -> str | None:
    """`ports_sampled=…` with the first `shown` ports and how many there were; `shown == 0` says they were left out."""
    if sampled is None:
        return None
    if not isinstance(sampled, Sequence) or isinstance(sampled, str):
        return _pair("ports_sampled", sampled) if shown else "ports_sampled=omitted"
    if shown == 0:
        return "ports_sampled=omitted" if sampled else None
    ports = [port for port in (_clean(item, 20) for item in sampled[:shown]) if port]
    if not ports:
        return None
    note = f" (first {len(ports)} of {len(sampled)})" if len(sampled) > len(ports) else ""
    return f"ports_sampled={','.join(ports)}{note}"


def _scan_line(scan: Any, *, ports: int) -> str | None:
    """`ports`: how many of the sampled ports to show; `0` shows none and says so."""
    pairs = (
        _pair("sampled_packets", _get(scan, "sampled_packets")),
        _pair("distinct_dst_ports_sampled", _get(scan, "distinct_dst_ports_sampled")),
        _ports_pair(_get(scan, "ports_sampled"), ports),
        _pair("dst_ips", _get(scan, "dst_ips")),
        _pair("actions", _get(scan, "actions")),
    )
    found = [pair for pair in pairs if pair]
    return f"evidence.scan: {' '.join(found)}" if found else None


def _head(enrichment: Mapping[str, Any], *, ports: int) -> list[str]:
    """Everything before the surrounding logs."""
    lines: list[str | None] = [_fields("scenario", enrichment.get("scenario"), ("id", "name"))]
    triage = enrichment.get("triage")
    text = _clean(_get(triage, "signal_text"), _TEXT_CAP)
    lines.append(f"signal_text: {text}" if text else None)
    raw_codes = _get(triage, "signal_codes")
    if isinstance(raw_codes, str):
        raw_codes = [raw_codes]
    codes = []
    if isinstance(raw_codes, Sequence):
        codes = [c for c in (_clean(code) for code in raw_codes[:_LIST_CAP]) if c]
    lines.append(f"signal_codes: {', '.join(codes)}" if codes else None)
    lines.extend(
        _fields("ti", entry, ("type", "value", "verdict"))
        for entry in _entries(enrichment.get("ti"))
    )
    lines.extend(_ioc_lines(enrichment.get("ioc")))
    lines.append(_fields("geo", enrichment.get("geo"), _GEO_KEYS))
    lines.append(
        _fields("soar.planned_action", _get(enrichment.get("soar"), "planned_action"), _ACTION_KEYS)
    )
    lines.append(_fields("history", enrichment.get("history"), _HISTORY_KEYS))
    evidence = enrichment.get("evidence")
    command = _clean(_get(evidence, "decoded_command"), _COMMAND_CAP)
    lines.append(f"evidence.decoded_command: {command}" if command else None)
    lines.append(_scan_line(_get(evidence, "scan"), ports=ports))
    return [line for line in lines if line]


def _log_line(entry: Any) -> str | None:
    if isinstance(entry, Mapping):
        pairs = _object_pairs(entry, _LOG_KEYS_FIRST)
        return "- " + " ".join(pairs) if pairs else None
    text = _clean(entry)
    return f"- {text}" if text else None


def _logs(enrichment: Mapping[str, Any]) -> tuple[list[str], int] | None:
    """The header and the log lines, and how many entries the document held; `None` when it holds none."""
    logs = _get(enrichment.get("evidence"), "context_logs")
    if not isinstance(logs, Sequence) or isinstance(logs, str) or not logs:
        return None
    lines = [line for entry in logs[:_LOG_CAP] if (line := _log_line(entry))]
    if not lines:
        return None
    total = len(logs)
    if total > len(lines):
        count = f"first {len(lines)} of {total} entries"
    else:
        count = f"{total} entr{'y' if total == 1 else 'ies'}"
    return [f"evidence.context_logs ({count}):", *lines], total


# ─────────────────────────────────────────────────────────── the block
def _size(text: str) -> int:
    return len(text.encode("utf-8"))


def render(enrichment: Any, *, max_bytes: int = MAX_BYTES) -> Rendered | None:
    """The block's text for `enrichment` (a SOAR `enrichment` object, or anything a JSON document may hold in
    its place), or `None` when there is nothing to say — no enrichment, or none of the fields above.
    """
    if not isinstance(enrichment, Mapping) or not enrichment:
        return None
    head = _head(enrichment, ports=_PORTS_SAMPLE)
    logs = _logs(enrichment)
    if not head and logs is None:
        return None

    warnings: list[str] = []
    lines = head + (logs[0] if logs is not None else [])
    text = wrap.normalise("\n".join(lines))
    if _size(text) > max_bytes and logs is not None:
        lines = head + [
            f"evidence.context_logs: omitted ({logs[1]} entries, over the {max_bytes}-byte limit)"
        ]
        text = wrap.normalise("\n".join(lines))
        warnings.append(LOGS_DROPPED)
    if _size(text) > max_bytes:
        without_ports = _head(enrichment, ports=0)
        if without_ports != head:
            lines = without_ports + lines[len(head) :]
            text = wrap.normalise("\n".join(lines))
            warnings.append(PORTS_DROPPED)
    limit_bytes = None
    if _size(text) > max_bytes:
        # the tail is cut by the block itself (`wrap.untrusted_block(limit_bytes=…)`), which puts its marker
        # inside the block AND marks the block truncated: a marker in an untruncated block is what the
        # detector reports as a forged one
        limit_bytes = max(max_bytes - _MARKER_ALLOWANCE, 0)
        warnings.append(CUT)
    return Rendered(text=text, warnings=tuple(warnings), limit_bytes=limit_bytes)
