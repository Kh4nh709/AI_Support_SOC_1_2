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

For an alert whose decoder name contains `windows_eventchannel` (P9-T02,
DEC-149), three Windows tiers run first, in the shared tiers' own order on the
Windows tables, and the port tier never runs:

  W1. exact MITRE technique id, `WINDOWS_TECHNIQUE_TO_CATEGORY` -> resolved_by='mitre'
  W2. its parent technique id, same table                    -> resolved_by='mitre_parent'
  W3. `rule.groups`, `WINDOWS_GROUP_TO_CATEGORY`             -> resolved_by='rule_groups'
  then tiers 1-4; never tier 5 — a Windows host's destination port is not a
  category signal, so a Windows alert nothing else matches is `unknown`/`none`.

They file Windows login attempts under `brute_force` rather than
`ssh_brute_force` — by T1110 (any sub-technique, through W2) or by Wazuh's
`authentication_failed`/`authentication_failures` groups, which the stock
single-4625 rule carries with T1531 — and add the Windows-only technique ids the
shared table has no key for. resolved_by stays inside the DB's
`ck_alerts_resolved_by` set. The Windows tiers edit none of the four shared tables
and any other decoder skips W1-W3 and keeps tier 5, so the Windows tiers alone
cannot change another decoder's category. (S1, v3.4, did edit the shared technique
table, on purpose: three discovery techniques reach `recon` and T1003 reaches
`credential_access` for every decoder — see `MAPPING_VERSION`.)

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

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

#: Bump in the same commit as any edit to the tables below (the four shared ones
#: and the two Windows ones) — it is what tells a later reader which alerts need
#: re-classifying. `test_category.py` hashes the tables and pins this value as a
#: reminder to do so. v3.3: the Windows tiers (P9-T02); the shared tables are v3.2's.
#: v3.4 (S1): T1018/T1016/T1482 -> `recon` and T1003/T1003.001 -> the new
#: `credential_access` in the shared technique table (T1003/T1003.001 also in the
#: Windows one), `credential_access` in `PRIORITY` right after `privilege_escalation`.
MAPPING_VERSION = "v3.4"

#: phase-1 §Khối 5, verbatim — declared once, applied to every tier's
#: candidate set (not only the MITRE tier). `brute_force` (P9-T02) sits directly
#: after `ssh_brute_force`: the same attack, on Windows. `credential_access` (S1)
#: sits directly after `privilege_escalation`: LSASS credential theft ranks with it,
#: above the login, brute-force and recon categories.
PRIORITY: tuple[str, ...] = (
    "ransomware",
    "malware",
    "c2_beacon",
    "data_exfiltration",
    "privilege_escalation",
    "credential_access",
    "ssh_brute_force",
    "brute_force",
    "web_attack",
    "suspicious_login",
    "recon",
    "policy_violation",
    "unknown",
)

#: The Windows tiers' guard: a substring of the decoder name, like tier 4's keys.
WINDOWS_DECODER = "windows_eventchannel"

# Windows tiers W1-W2 (P9-T02, DEC-149), only for an alert whose decoder is
# `windows_eventchannel`: the exact id, then the part before the first '.', as
# tiers 1-2 do. T1110 is MITRE ATT&CK "Brute Force" — every sub-technique reaches
# it through W2; the rest are Windows-only ids with no key in the shared table below,
# except T1003 (S1, v3.4: OS Credential Dumping, the LSASS dump), which — like T1110 —
# is in both tables.
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
    "T1003": "credential_access",
    "T1003.001": "credential_access",
}

# Windows tier W3 — rule.groups. Wazuh's Windows logon rules carry these groups
# whatever their MITRE block says (the stock single-4625 rule is T1531 +
# `authentication_failed`), so a Windows login attempt reaches `brute_force` here
# before the shared tier 3 could file it under `ssh_brute_force`.
WINDOWS_GROUP_TO_CATEGORY: dict[str, str] = {
    "authentication_failed": "brute_force",
    "authentication_failures": "brute_force",
    "invalid_login": "brute_force",
    "authentication_success": "suspicious_login",
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
    # S1 (v3.4): discovery techniques — domain-controller / domain probing (rule 111438).
    # Shared-table only: a Windows alert reaches them by the fall-through from W1-W3.
    "T1018": "recon",
    "T1016": "recon",
    "T1482": "recon",
    "T1548": "privilege_escalation",
    # S1 (v3.4): OS Credential Dumping / LSASS memory (rule 111923); also in the Windows table.
    "T1003": "credential_access",
    "T1003.001": "credential_access",
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


def _is_windows(decoder: str | None) -> bool:
    """Whether the Windows tiers apply: `windows_eventchannel` in the decoder name."""
    return WINDOWS_DECODER in _safe_str(decoder).lower()


# Tiers 1-3 take their table as an argument so that W1-W3 run the very same code
# on the Windows tables; the default is the shared table, the only one any other
# decoder ever sees.


def _tier_mitre_exact(
    mitre_ids: Sequence[str], table: Mapping[str, str] = TECHNIQUE_TO_CATEGORY
) -> list[str]:
    out: list[str] = []
    for raw in _iter(mitre_ids):
        tid = _safe_str(raw).upper()
        if tid and tid in table:
            out.append(table[tid])
    return out


def _tier_mitre_parent(
    mitre_ids: Sequence[str], table: Mapping[str, str] = TECHNIQUE_TO_CATEGORY
) -> list[str]:
    out: list[str] = []
    for raw in _iter(mitre_ids):
        tid = _safe_str(raw).upper()
        if not tid or "." not in tid:
            continue
        parent = tid.split(".")[0]
        if parent in table:
            out.append(table[parent])
    return out


def _tier_groups(groups: Sequence[str], table: Mapping[str, str] = GROUP_TO_CATEGORY) -> list[str]:
    out: list[str] = []
    for raw in _iter(groups):
        key = _safe_str(raw).lower()
        if key and key in table:
            out.append(table[key])
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
    """Resolve `category`/`categories` from all four signals, five tiers in order —
    for a `windows_eventchannel` alert, W1-W3 first and no tier 5.

    Never raises (R1, R2): every malformed signal — `None`, a non-string
    element, a port that is not an `int` — is simply skipped, not raised on.
    """
    windows = _is_windows(decoder)
    windows_tiers = (
        (
            (_tier_mitre_exact(mitre_ids, WINDOWS_TECHNIQUE_TO_CATEGORY), "mitre"),
            (_tier_mitre_parent(mitre_ids, WINDOWS_TECHNIQUE_TO_CATEGORY), "mitre_parent"),
            (_tier_groups(groups, WINDOWS_GROUP_TO_CATEGORY), "rule_groups"),
        )
        if windows
        else ()
    )
    for candidates, resolved_by in (
        *windows_tiers,
        (_tier_mitre_exact(mitre_ids), "mitre"),
        (_tier_mitre_parent(mitre_ids), "mitre_parent"),
        (_tier_groups(groups), "rule_groups"),
        (_tier_decoder(decoder), "decoder"),
        # A Windows host's destination port is not a category signal.
        ([] if windows else _tier_port(dst_port), "dst_port"),
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
