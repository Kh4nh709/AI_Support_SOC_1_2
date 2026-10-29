"""The SOAR enrichment of an alert, shaped for the detail page (S3): one display blob.

The SIEM's SOAR team puts an `enrichment` object in the alert it sends (`raw_payload->'enrichment'`,
schema `1.x`) and, for a pfSense port scan, a top-level `previous_output` with the filterlog lines.
`soar_view` turns the two into `view["soar"]`, the single key `queue.get_alert_view` adds to the
detail view before `visibility.strip`:

| key        | from                                   | shape |
|------------|----------------------------------------|-------|
| `case`     | `enrichment.case`                      | `case_number` (kept as `None` when the SOAR score was under 40 and no TheHive case was made), `thehive_alert_id`, `dedup_key`, `case_id` |
| `action`   | `enrichment.soar.planned_action`       | `type`, `target`, `tier`, `mode` |
| `scenario` | `enrichment.scenario`                  | `id`, `name` |
| `triage`   | `enrichment.triage`                    | `score`, `signal_text`, `signal_codes` — **display only** |
| `history`  | `enrichment.history`                   | `rule_7d_total`, `rule_7d_host`, `rule_7d_hosts`, `last_seen`, `first_seen_host` |
| `geo`      | `enrichment.geo` (GEO01)               | the Owner's eight fields, scalars only |
| `scan`     | `enrichment.evidence.scan` (SC03) and `previous_output` | counters, `ports_sampled` (+ `ports_total`), `dst_ips`, `actions`, `previous_output` (+ `previous_output_truncated`, `previous_output_lines` when cut) |
| `ti`       | `enrichment.ti`                        | list of `type`, `value`, `verdict` |

Present-only: a field that is absent, `null` or of a type this module does not expect is left
out; a block with nothing left is left out; no displayable block at all is `None`.

Everything here is untrusted SIEM free text. The builder never raises, keeps only scalars (never a
nested object it did not ask for), and bounds every string and list, so that a hostile or huge
payload cannot make the detail JSON unbounded. It does not strip or escape — the page renders
every value as a React text node.

**Read side only.** The SIEM's score, signal and TI verdict are shown to the analyst; they are never
a fact, a `structured_basis` field or a gate input (the ① facts come from the internal context,
`soar/pipeline._read_enrichment`, which reads the few fields it needs on its own). Nothing under
`llm/`, `security/`, `soar/` or `tier1/triage.py` imports this module — `test_soar_view.py` pins it.
"""

from __future__ import annotations

import math
from typing import Any

#: One text value (a name, a signal text, a dedup key) is cut to this many characters.
MAX_TEXT = 500
#: `scan.ports_sampled` (the sample is 50 long in the SC03 sample), `dst_ips`, `actions`,
#: `triage.signal_codes` and `ti` are cut to this many entries.
MAX_PORTS = 50
MAX_IPS = 20
MAX_ACTIONS = 10
MAX_CODES = 20
MAX_TI = 20
#: `previous_output` is cut on a line boundary to at most this many characters.
MAX_PREVIOUS_OUTPUT = 8000

#: The GEO01 fields the Owner listed; any other key of `enrichment.geo` is left out.
GEO_FIELDS: tuple[str, ...] = (
    "country",
    "country_simulated",
    "src_ip_type",
    "first_seen_country_30d",
    "seen_count_30d",
    "prior_failures_30m",
    "impossible_travel",
    "off_hours",
)


def _number(value: Any) -> int | float | None:
    """An int or a finite float; a bool is not a number here."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    return None


def _string(value: Any) -> str | None:
    """A string cut to `MAX_TEXT`; nothing else."""
    return value[:MAX_TEXT] if isinstance(value, str) else None


def _text(value: Any) -> str | None:
    """A string cut to `MAX_TEXT`; a number is shown as its text; nothing else is text."""
    if isinstance(value, str):
        return _string(value)
    number = _number(value)
    return None if number is None else str(number)[:MAX_TEXT]


def _flag(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _scalar(value: Any) -> str | bool | int | float | None:
    if isinstance(value, bool):
        return value
    number = _number(value)
    if number is not None:
        return number
    return value[:MAX_TEXT] if isinstance(value, str) else None


def _texts(value: Any, limit: int) -> list[str] | None:
    """The text items of a list, at most `limit`; `None` for a non-list or a list with none."""
    if not isinstance(value, list):
        return None
    shown = [text for item in value if (text := _text(item)) is not None]
    return shown[:limit] or None


def _pick(source: Any, fields: dict[str, Any]) -> dict[str, Any]:
    """`{name: converted}` for each `name -> converter` whose value converts to something
    other than `None`. `source` that is not a mapping gives `{}`."""
    if not isinstance(source, dict):
        return {}
    out: dict[str, Any] = {}
    for name, convert in fields.items():
        converted = convert(source.get(name))
        if converted is not None:
            out[name] = converted
    return out


def _case(source: Any) -> dict[str, Any]:
    if not isinstance(source, dict):
        return {}
    block = _pick(source, {"thehive_alert_id": _text, "dedup_key": _text, "case_id": _text})
    # `case_number` is null when the SOAR score was under 40: the page says "no case", so a
    # null (or an absent key with the rest of the block present) is kept, not dropped.
    if "case_number" in source:
        raw = source["case_number"]
        number = None if raw is None else _text(raw) if isinstance(raw, str) else _number(raw)
        if raw is None or number is not None:
            block = {"case_number": number, **block}
    return block


def _scan(scan: Any, previous_output: Any) -> dict[str, Any]:
    block: dict[str, Any] = _pick(
        scan,
        {
            "sampled_packets": _number,
            "distinct_dst_ports_sampled": _number,
            "dst_ips": lambda v: _texts(v, MAX_IPS),
            "actions": lambda v: _texts(v, MAX_ACTIONS),
        },
    )
    if isinstance(scan, dict) and isinstance(scan.get("ports_sampled"), list):
        ports = _texts(scan["ports_sampled"], len(scan["ports_sampled"]))
        if ports:
            block["ports_sampled"] = ports[:MAX_PORTS]
            block["ports_total"] = len(ports)
    block.update(_previous_output(previous_output))
    return block


def _previous_output(value: Any) -> dict[str, Any]:
    """The filterlog lines, cut on a line boundary to `MAX_PREVIOUS_OUTPUT` characters. A first
    line longer than the bound is itself cut, never dropped to nothing."""
    if not isinstance(value, str) or not value.strip():
        return {}
    lines = value.split("\n")
    kept: list[str] = []
    used = 0
    for line in lines:
        cost = len(line) + (1 if kept else 0)
        if used + cost > MAX_PREVIOUS_OUTPUT:
            break
        kept.append(line)
        used += cost
    truncated = len(kept) < len(lines)
    if not kept:
        kept = [lines[0][:MAX_PREVIOUS_OUTPUT]]
    out: dict[str, Any] = {
        "previous_output": "\n".join(kept),
        "previous_output_truncated": truncated,
    }
    if truncated:
        out["previous_output_lines"] = len(lines)
    return out


def _ti(value: Any) -> list[dict[str, str]] | None:
    if not isinstance(value, list):
        return None
    entries = []
    for entry in value:
        shown = _pick(entry, {"type": _text, "value": _text, "verdict": _text})
        if shown:
            entries.append(shown)
    return entries[:MAX_TI] or None


def _object(source: Any, *path: str) -> Any:
    node = source
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def soar_view(enrichment: Any, previous_output: Any = None) -> dict[str, Any] | None:
    """The display blob of one alert's SOAR enrichment (module docstring), or `None` when there is
    nothing in it to show. `enrichment` is `raw_payload->'enrichment'` and `previous_output` is
    `raw_payload->'previous_output'`, each as `psycopg` decodes the jsonb: any type, none trusted.
    """
    if not isinstance(enrichment, dict):
        return None
    blob: dict[str, Any] = {}

    def put(key: str, value: Any) -> None:
        if value:
            blob[key] = value

    put("case", _case(enrichment.get("case")))
    put(
        "action",
        _pick(
            _object(enrichment, "soar", "planned_action"),
            {"type": _text, "target": _text, "tier": _text, "mode": _text},
        ),
    )
    put("scenario", _pick(enrichment.get("scenario"), {"id": _text, "name": _text}))
    put(
        "triage",
        _pick(
            enrichment.get("triage"),
            {
                "score": _number,
                "signal_text": _text,
                "signal_codes": lambda v: _texts(v, MAX_CODES),
            },
        ),
    )
    put(
        "history",
        _pick(
            enrichment.get("history"),
            {
                "rule_7d_total": _number,
                "rule_7d_host": _number,
                "rule_7d_hosts": _number,
                "last_seen": _string,
                "first_seen_host": _flag,
            },
        ),
    )
    put("geo", _pick(enrichment.get("geo"), dict.fromkeys(GEO_FIELDS, _scalar)))
    put("scan", _scan(_object(enrichment, "evidence", "scan"), previous_output))
    put("ti", _ti(enrichment.get("ti")))
    return blob or None
