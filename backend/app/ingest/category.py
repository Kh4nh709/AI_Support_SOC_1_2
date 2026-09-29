"""Resolve an alert's internal category deterministically from rule id and MITRE technique.

Ported from `Final-Project`'s `category_resolver.py` mapping tables (DEC-002),
renamed onto the ten `kb/playbooks/` names, with the parent-technique tier split
out from the exact-technique tier and the priority-sort rule (phase-1 §Khối 5
chốt C5) applied uniformly at every tier, not only the first.

Five tiers, consulted in order — each one only when the ones above it produced
nothing:

  1. exact MITRE technique id (`"T1110.001"` as-is)      -> resolved_by='mitre'
  2. parent MITRE technique (`"T1543.003"` -> `"T1543"`) -> resolved_by='mitre_parent'
  3. `rule.groups`                                       -> resolved_by='rule_groups'
  4. `decoder` name, substring match                     -> resolved_by='decoder'
  5. destination port                                    -> resolved_by='dst_port'
  nothing matches                                        -> category='unknown', resolved_by='none'

A Windows tier sits in front of tier 1 and is consulted only when the decoder
name contains `windows_eventchannel` (P9-T02, DEC-149): an exact MITRE technique
id in `WINDOWS_TECHNIQUE_TO_CATEGORY` -> resolved_by='mitre' (the DB's
`ck_alerts_resolved_by` set has no other value for an exact technique match).
It files Windows credential attacks (T1110) under `brute_force` rather than
`ssh_brute_force`, and adds the Windows-only technique ids the shared table has
no key for. When it matches nothing, the five tiers run unchanged. The four
shared tables are not edited, so an alert from any other decoder cannot change
category.

Within a tier, ALL matching signals are collected — never "first match wins":
a real alert routinely carries two MITRE techniques that both resolve (the
canonical alert has `T1078` and `T1110` together). The collected set is
deduplicated and sorted by `PRIORITY`; `category` is the highest-priority
member and `categories` is the full sorted tuple. Sorting never depends on the
order the SIEM sent the array (R4).

Four `Final-Project` category values have no `kb/playbooks/` file and are
dropped from every table below (R5: a category with no playbook may never be
produced). The exact list, and which MITRE ids / `rule.groups` used to reach
them, is in the P2-T03 report — none of those old names appear anywhere in
this file, in code or in comments (a signal whose only mapping was dropped
simply falls through to the next tier, or to `unknown`).

Pure: no I/O, no clock, no DB. `resolve()` never raises on any input — an
empty list, `None`, a non-string element, a port that is not an `int` all
resolve to `unknown`/`none` instead (R1, R2).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

#: Bump in the same commit as any edit to the tables below (the four shared ones
#: and the Windows one) — it is what tells a later reader which alerts need
#: re-classifying. `test_category.py` hashes the tables and pins this value as a
#: reminder to do so. v3.3: the Windows tier (P9-T02); the shared tables are v3.2's.
MAPPING_VERSION = "v3.3"

#: phase-1 §Khối 5, verbatim — declared once, applied to every tier's
#: candidate set (not only the MITRE tier). `brute_force` (P9-T02) sits directly
#: after `ssh_brute_force`: the same attack, on Windows.
PRIORITY: tuple[str, ...] = (
    "ransomware",
    "malware",
    "c2_beacon",
    "data_exfiltration",
    "privilege_escalation",
    "ssh_brute_force",
    "brute_force",
    "web_attack",
    "suspicious_login",
    "recon",
    "policy_violation",
    "unknown",
)

#: The Windows tier's guard: a substring of the decoder name, like tier 4's keys.
WINDOWS_DECODER = "windows_eventchannel"

# The Windows tier (P9-T02, DEC-149) — exact technique ids only, and only for an
# alert whose decoder is `windows_eventchannel`. T1110 is MITRE ATT&CK "Brute
# Force" (.001 password guessing, .003 password spraying); the rest are
# Windows-only ids with no key in the shared table below.
WINDOWS_TECHNIQUE_TO_CATEGORY: dict[str, str] = {
    "T1110": "brute_force",
    "T1110.001": "brute_force",
    "T1110.003": "brute_force",
    "T1490": "ransomware",
    "T1485": "ransomware",
    "T1071.001": "c2_beacon",
    "T1573": "c2_beacon",
    "T1048": "data_exfiltration",
    "T1567": "data_exfiltration",
    "T1059.001": "malware",
}

# Tiers 1-2 share one table: a plain technique ("T1110") and a specific
# sub-technique ("T1110.001") may each be a key in their own right, or only the
# parent may be. `_tier_mitre_parent` tries the part before the first '.' —
# and only when no *exact* id anywhere in the array matched (tier 1 wins for
# the whole call, not id-by-id).
TECHNIQUE_TO_CATEGORY: dict[str, str] = {
    "T1110": "ssh_brute_force",
    "T1110.001": "ssh_brute_force",
    "T1078": "suspicious_login",
    "T1204": "malware",
    "T1105": "malware",
    "T1486": "ransomware",
    "T1190": "web_attack",
    "T1189": "web_attack",
    "T1505.003": "web_attack",
    "T1046": "recon",
    "T1548": "privilege_escalation",
    "T1071": "c2_beacon",
    "T1071.004": "c2_beacon",
    "T1041": "data_exfiltration",
}

# Tier 3 — rule.groups. The most reliable signal for the many rules that carry
# no rule.mitre block at all.
GROUP_TO_CATEGORY: dict[str, str] = {
    "authentication_failed": "ssh_brute_force",
    "authentication_failures": "ssh_brute_force",
    "invalid_login": "ssh_brute_force",
    "authentication_success": "suspicious_login",
    "privilege_escalation": "privilege_escalation",
    "sudo": "privilege_escalation",
    "rootcheck": "privilege_escalation",
    "web_scan": "recon",
    "recon": "recon",
    "nmap": "recon",
    "sql_injection": "web_attack",
    "sqlinjection": "web_attack",
    "web_attack": "web_attack",
    "virus": "malware",
    "malware": "malware",
    "clamd": "malware",
    "exfiltration": "data_exfiltration",
}

# Tier 4 — decoder name, substring match (the key is a substring of decoder.name).
DECODER_TO_CATEGORY: dict[str, str] = {
    "sshd": "ssh_brute_force",
    "apache": "web_attack",
    "nginx": "web_attack",
    "iis": "web_attack",
    "modsecurity": "web_attack",
    "web-accesslog": "web_attack",
    "suricata": "c2_beacon",
    "clamd": "malware",
}

# Tier 5 — destination port. Weakest signal, consulted last.
PORT_TO_CATEGORY: dict[int, str] = {
    22: "ssh_brute_force",
    80: "web_attack",
    443: "web_attack",
}


@dataclass(frozen=True)
class Resolution:
    """The outcome of one `resolve()` call."""

    category: str
    categories: tuple[str, ...]
    resolved_by: str
    mapping_version: str


def _safe_str(value: object) -> str:
    """`str(value).strip()` — the original's defensive coercion (design note 6).

    Every signal here comes from JSON (the indexer response, or a decoded
    archive line), so `value` is always `None`, `bool`, `int`, `float`, `str`,
    `list` or `dict` — none of which can make `str()` itself raise.
    """
    return str(value).strip()


def _iter(sequence: object):
    """Iterate `sequence`; yield nothing if it is not iterable at all (R2)."""
    try:
        return iter(sequence)
    except TypeError:
        return iter(())


def _sort_by_priority(categories: list[str]) -> tuple[str, ...]:
    """Dedup `categories` (first occurrence kept), then sort by `PRIORITY` (C5)."""
    seen: list[str] = []
    for c in categories:
        if c not in seen:
            seen.append(c)
    rank = {name: i for i, name in enumerate(PRIORITY)}
    seen.sort(key=lambda c: rank.get(c, len(PRIORITY)))
    return tuple(seen)


def _tier_windows(mitre_ids: Sequence[str], decoder: str | None) -> list[str]:
    """The Windows tier: nothing unless the decoder is `windows_eventchannel`."""
    if WINDOWS_DECODER not in _safe_str(decoder).lower():
        return []
    out: list[str] = []
    for raw in _iter(mitre_ids):
        tid = _safe_str(raw).upper()
        if tid and tid in WINDOWS_TECHNIQUE_TO_CATEGORY:
            out.append(WINDOWS_TECHNIQUE_TO_CATEGORY[tid])
    return out


def _tier_mitre_exact(mitre_ids: Sequence[str]) -> list[str]:
    out: list[str] = []
    for raw in _iter(mitre_ids):
        tid = _safe_str(raw).upper()
        if tid and tid in TECHNIQUE_TO_CATEGORY:
            out.append(TECHNIQUE_TO_CATEGORY[tid])
    return out


def _tier_mitre_parent(mitre_ids: Sequence[str]) -> list[str]:
    out: list[str] = []
    for raw in _iter(mitre_ids):
        tid = _safe_str(raw).upper()
        if not tid or "." not in tid:
            continue
        parent = tid.split(".")[0]
        if parent in TECHNIQUE_TO_CATEGORY:
            out.append(TECHNIQUE_TO_CATEGORY[parent])
    return out


def _tier_groups(groups: Sequence[str]) -> list[str]:
    out: list[str] = []
    for raw in _iter(groups):
        key = _safe_str(raw).lower()
        if key and key in GROUP_TO_CATEGORY:
            out.append(GROUP_TO_CATEGORY[key])
    return out


def _tier_decoder(decoder: str | None) -> list[str]:
    key = _safe_str(decoder).lower()
    if not key:
        return []
    return [category for name, category in DECODER_TO_CATEGORY.items() if name in key]


def _tier_port(dst_port: int) -> list[str]:
    try:
        category = PORT_TO_CATEGORY.get(dst_port)
    except TypeError:  # unhashable dst_port (e.g. a list) -- no match, never raise
        return []
    return [category] if category is not None else []


def resolve(
    mitre_ids: Sequence[str],
    groups: Sequence[str],
    decoder: str | None,
    dst_port: int,
) -> Resolution:
    """Resolve `category`/`categories` from all four signals, five tiers in order
    (after the Windows tier, for a `windows_eventchannel` alert).

    Never raises (R1, R2): every malformed signal — `None`, a non-string
    element, a port that is not an `int` — is simply skipped, not raised on.
    """
    for candidates, resolved_by in (
        (_tier_windows(mitre_ids, decoder), "mitre"),
        (_tier_mitre_exact(mitre_ids), "mitre"),
        (_tier_mitre_parent(mitre_ids), "mitre_parent"),
        (_tier_groups(groups), "rule_groups"),
        (_tier_decoder(decoder), "decoder"),
        (_tier_port(dst_port), "dst_port"),
    ):
        sorted_categories = _sort_by_priority(candidates)
        if sorted_categories:
            return Resolution(
                category=sorted_categories[0],
                categories=sorted_categories,
                resolved_by=resolved_by,
                mapping_version=MAPPING_VERSION,
            )
    return Resolution(
        category="unknown",
        categories=(),
        resolved_by="none",
        mapping_version=MAPPING_VERSION,
    )
