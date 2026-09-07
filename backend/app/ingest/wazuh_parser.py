"""Parse one Wazuh alert document (indexer or webhook shape) into the internal Alert fields.

Three document shapes reach this module (design note 1, measured on the live
indexer): an **indexer hit** (`_index, _id, _score, _source, sort`, and
`fields` only when the search body requested it), a **bare document** (the
`_source` object on its own — a webhook body or a Logstash-shaped line), and a
**raw archive line** (the manager's own object from `alerts.json`, no
envelope at all). The rule is structural, not shape-counting: a `_source` key
present means the alert is `_source` and the rest is envelope; otherwise the
object *is* the alert. `ParseResult.envelope` is `"indexer_hit"` or `"bare"`
— the second value covers both the bare document and the raw archive line,
which cannot be told apart once `_source` is absent (P2-tasks.md planning
decision 6; DEC-019).

Pure (R1): no clock, no DB, no network. `parse_wazuh_alert()` is total (R2) —
it never raises on the classification path; it rejects only when the alert
has no identity (`id`, `rule.id`, `rule.description` or a parseable
timestamp missing), naming the missing field, never an exception (phase-1
§Xử lý lỗi, G-15). Imports only `domain`, `infra` (for `Config.RAW_LOG_MAX_BYTES`)
and `ingest.category` (same package, not judged by the G1 AST scan).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from app.domain.alert import Alert, compute_event_bucket_hash, severity_from_level
from app.infra import config
from app.ingest import category

_OFFSET_NO_COLON_RE = re.compile(r"([+-]\d{2})(\d{2})$")


@dataclass(frozen=True)
class ParseResult:
    """The outcome of one `parse_wazuh_alert()` call."""

    alert: Alert | None
    rejection: str | None
    envelope: Literal["indexer_hit", "bare"]


def _dict(value: object) -> dict:
    """`value` if it is already a dict, else `{}` — never raise on a
    malformed nested object (rule/agent/data/... sent as `null` or a string)."""
    return value if isinstance(value, dict) else {}


def _str_list(value: object) -> list[str]:
    """`value` coerced to a list of strings if it is a list/tuple, else `[]`."""
    if not isinstance(value, (list, tuple)):
        return []
    return [str(item) for item in value]


def _safe_int(value: object, default: int = 0) -> int:
    """phase-1 Khối 2, verbatim: a port arrives as a string and may be
    `"unknown"`, empty, or padded with whitespace — never let that raise."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError, AttributeError):
        return default


def _parse_iso(value: object) -> datetime | None:
    """`datetime.fromisoformat`, tolerant of a trailing `Z` and of a
    `+HHMM`/`-HHMM` offset with no colon (phase-1 Khối 3's `+0700` trap) —
    `None` on anything that still does not parse, never a raise."""
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    text = _OFFSET_NO_COLON_RE.sub(r"\1:\2", text)
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _is_private(ip: str | None) -> bool | None:
    """phase-1 Khối 7, chốt C4, verbatim: `''`/unparseable -> `None` ("chưa
    khẳng định"), never a raise. Covers RFC1918, loopback, link-local, CGNAT,
    ULA IPv6 through the stdlib classifications."""
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved


def _truncate_raw_log(raw_log: str, max_bytes: int) -> tuple[str, bool]:
    """Cut at `max_bytes`, backing off one byte at a time to the nearest
    valid UTF-8 boundary so a multi-byte character is never split (chốt C3)."""
    encoded = raw_log.encode("utf-8")
    if len(encoded) <= max_bytes:
        return raw_log, False
    truncated = encoded[:max_bytes]
    while truncated:
        try:
            return truncated.decode("utf-8"), True
        except UnicodeDecodeError:
            truncated = truncated[:-1]
    return "", True


def _resolve_alert_time(doc: Mapping, alert_obj: Mapping, envelope: str) -> datetime | None:
    """`fields.timestamp[0]` when the envelope carries it (an indexer hit
    whose search requested `fields`); else `timestamp` on the alert object,
    which is both the replay path and the live-pull safety net (DEC-019,
    P2-tasks.md planning decision 6) — never `now()` (R7)."""
    if envelope == "indexer_hit":
        fields = _dict(doc.get("fields"))
        timestamps = fields.get("timestamp")
        if isinstance(timestamps, (list, tuple)) and timestamps:
            parsed = _parse_iso(timestamps[0])
            if parsed is not None:
                return parsed
    parsed = _parse_iso(alert_obj.get("timestamp"))
    return parsed


def parse_wazuh_alert(doc: Mapping) -> ParseResult:
    envelope: Literal["indexer_hit", "bare"] = (
        "indexer_hit" if isinstance(doc, Mapping) and "_source" in doc else "bare"
    )
    alert_obj: Mapping = _dict(doc.get("_source")) if envelope == "indexer_hit" else _dict(doc)

    alert_id = alert_obj.get("id")
    if not alert_id:
        return ParseResult(alert=None, rejection="id", envelope=envelope)
    alert_id = str(alert_id)

    rule = _dict(alert_obj.get("rule"))
    rule_id = rule.get("id")
    if rule_id in (None, ""):
        return ParseResult(alert=None, rejection="rule.id", envelope=envelope)
    rule_id = str(rule_id)

    description = rule.get("description")
    if not description:
        return ParseResult(alert=None, rejection="rule.description", envelope=envelope)

    alert_time = _resolve_alert_time(doc, alert_obj, envelope)
    if alert_time is None:
        return ParseResult(alert=None, rejection="timestamp", envelope=envelope)
    # R8: store the instant in UTC regardless of the offset it arrived with.
    alert_time = alert_time.astimezone(UTC)

    manager = _dict(alert_obj.get("manager"))
    manager_id = manager.get("name") or "default"

    agent = _dict(alert_obj.get("agent"))
    if agent:
        agent_name = agent.get("name") or manager_id
        agent_id = agent.get("id")
        agent_ip = agent.get("ip")
    else:
        # DEC-014: no `agent` object is a shape the manager can emit for a
        # manager-level alert -- fall back to manager.name, never reject.
        agent_name = manager_id
        agent_id = None
        agent_ip = None

    predecoder = _dict(alert_obj.get("predecoder"))
    origin_host = predecoder.get("hostname") or agent_name

    data = _dict(alert_obj.get("data"))
    srcip = data.get("srcip") or ""
    dstip = data.get("dstip") or ""
    src_port = _safe_int(data.get("srcport"), 0)
    dst_port = _safe_int(data.get("dstport"), 0)
    alert_user = data.get("dstuser") or data.get("srcuser") or None

    decoder_obj = _dict(alert_obj.get("decoder"))
    decoder = decoder_obj.get("name") or decoder_obj.get("parent") or None

    mitre = _dict(rule.get("mitre"))
    mitre_ids = tuple(_str_list(mitre.get("id")))
    rule_groups = tuple(_str_list(rule.get("groups")))

    rule_level = _safe_int(rule.get("level"), 0)
    severity = severity_from_level(rule_level)

    resolution = category.resolve(mitre_ids, rule_groups, decoder, dst_port)

    srcip_is_private = _is_private(srcip)
    dstip_is_private = _is_private(dstip)

    full_log = alert_obj.get("full_log") or ""
    raw_log, raw_log_truncated = _truncate_raw_log(full_log, config.load().RAW_LOG_MAX_BYTES)

    event_bucket_hash = compute_event_bucket_hash(rule_id, srcip, dstip, agent_name, alert_time)

    alert = Alert(
        alert_id=alert_id,
        manager_id=manager_id,
        rule_id=rule_id,
        description=description,
        agent_name=agent_name,
        agent_id=agent_id,
        agent_ip=agent_ip,
        origin_host=origin_host,
        alert_time=alert_time,
        # Always None in P2 (planning decision 5): the inventory has no
        # per-agent timezone field, so `predecoder.timestamp` cannot be
        # localised. It stays in raw_payload for a future reader.
        event_time=None,
        srcip=srcip,
        dstip=dstip,
        src_port=src_port,
        dst_port=dst_port,
        alert_user=alert_user,
        decoder=decoder,
        mitre_ids=mitre_ids,
        rule_groups=rule_groups,
        rule_level=rule_level,
        severity=severity,
        category=resolution.category,
        categories=resolution.categories,
        resolved_by=resolution.resolved_by,
        mapping_version=resolution.mapping_version,
        srcip_is_private=srcip_is_private,
        dstip_is_private=dstip_is_private,
        raw_log=raw_log,
        raw_log_truncated=raw_log_truncated,
        event_bucket_hash=event_bucket_hash,
        raw_payload=alert_obj,
    )
    return ParseResult(alert=alert, rejection=None, envelope=envelope)
