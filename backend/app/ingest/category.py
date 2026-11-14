"""Resolve an alert's internal category deterministically from rule id and MITRE technique.

Ported from `Final-Project`'s `category_resolver.py` mapping tables (DEC-002),
renamed onto the ten `kb/playbooks/` names, with the parent-technique tier split
out from the exact-technique tier and the priority-sort rule (phase-1 §Khối 5
chốt C5) applied uniformly at every tier, not only the first.

Six tiers, consulted in order — each one only when the ones above it produced
nothing:

  1. exact MITRE technique id (`"T1110.001"` as-is)      -> resolved_by='mitre'
  2. parent MITRE technique (`"T1543.003"` -> `"T1543"`) -> resolved_by='mitre_parent'
  3. `rule.groups`                                       -> resolved_by='rule_groups'
  4. `decoder` name, substring match                     -> resolved_by='decoder'
  5. destination port                                    -> resolved_by='dst_port'
  6. `EXTENDED_TECHNIQUE_TO_CATEGORY` (v3.5, DEC-216): exact id -> 'mitre', else its parent -> 'mitre_parent'
  nothing matches                                        -> category='unknown', resolved_by='none'

Tier 6 is the fallback: it runs only when every tier above, the Windows ones included, found
nothing, so an alert v3.4 resolved keeps its category and only a v3.4 `unknown` can change.
Putting the extended ids into tier 1 instead would let a new exact id pre-empt a parent or
`rule.groups` answer that is correct today (an Office child process `T1047`+`T1204.002` would
leave `malware` for `execution`; a single 4625 `T1531`+`authentication_failed` would leave
`brute_force` for `impact`).

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
simply falls through to the next tier, or to `unknown`). v3.5 (DEC-216) maps the
ids that used to reach them again, in tier 6 only, onto the eight new categories,
which are bound by R5 like the twelve: each needs its playbook and table.

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
#: v3.5 (DEC-216): tier 6, `EXTENDED_TECHNIQUE_TO_CATEGORY`, and eight new categories in
#: `PRIORITY`; the six tables above it are v3.4's, byte for byte.
MAPPING_VERSION = "v3.5"

#: phase-1 §Khối 5, verbatim — declared once, applied to every tier's
#: candidate set (not only the MITRE tier). `brute_force` (P9-T02) sits directly
#: after `ssh_brute_force`: the same attack, on Windows. `credential_access` (S1)
#: sits directly after `privilege_escalation`: LSASS credential theft ranks with it,
#: above the login, brute-force and recon categories.
#: v3.5 (DEC-216) adds eight categories; the twelve keep their relative order. Destructive
#: outcomes first (`impact` after `ransomware`), then the stages that mean an attacker is
#: already in and moving (`collection` after `data_exfiltration`, `lateral_movement` before
#: `privilege_escalation`, `persistence` after `credential_access`), then the two broad
#: technique families (`defense_evasion`, `execution`) below every specific one, so a set like
#: {malware, defense_evasion} still reads `malware`; `initial_access` after `web_attack` (its
#: most specific case), `resource_development` just above `policy_violation`.
PRIORITY: tuple[str, ...] = (
    "ransomware",
    "impact",
    "malware",
    "c2_beacon",
    "data_exfiltration",
    "collection",
    "lateral_movement",
    "privilege_escalation",
    "credential_access",
    "persistence",
    "defense_evasion",
    "execution",
    "ssh_brute_force",
    "brute_force",
    "web_attack",
    "initial_access",
    "suspicious_login",
    "recon",
    "resource_development",
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

# Tier 6 (v3.5, DEC-216) — the Owner's MITRE ATT&CK technique map, consulted ONLY when every tier
# above (W1-W3 and 1-5) found nothing: exact id first, then its parent, the same two steps as tiers
# 1-2, with the same `resolved_by` values. Because it runs last, an alert any earlier tier resolves
# keeps exactly the category v3.4 gave it; only an alert that was `unknown` can change. A key that
# also sits in a table above is therefore never reached here (T1110, T1003, T1078, ...).
# Eight values are new categories (`persistence`, `defense_evasion`, `execution`,
# `lateral_movement`, `collection`, `impact`, `initial_access`, `resource_development`): R5 holds
# only once each has its playbook and decision table (docs/plan/prompts/kb-drafter-run-2026-11-14.md).
EXTENDED_TECHNIQUE_TO_CATEGORY: dict[str, str] = {
    "T1001": "c2_beacon",  # Data Obfuscation
    "T1003": "credential_access",  # OS Credential Dumping
    "T1003.001": "credential_access",  # LSASS Memory
    "T1005": "collection",  # Data from Local System
    "T1006": "defense_evasion",  # Direct Volume Access
    "T1007": "recon",  # System Service Discovery
    "T1008": "c2_beacon",  # Fallback Channels
    "T1010": "recon",  # Application Window Discovery
    "T1011": "data_exfiltration",  # Exfiltration Over Other Network Medium
    "T1012": "recon",  # Query Registry
    "T1014": "defense_evasion",  # Rootkit
    "T1016": "recon",  # System Network Configuration Discovery
    "T1018": "recon",  # Remote System Discovery
    "T1020": "data_exfiltration",  # Automated Exfiltration
    "T1021": "lateral_movement",  # Remote Services
    "T1025": "collection",  # Data from Removable Media
    "T1027": "malware",  # Obfuscated Files or Information
    "T1029": "data_exfiltration",  # Scheduled Transfer
    "T1030": "data_exfiltration",  # Data Transfer Size Limits
    "T1033": "recon",  # System Owner/User Discovery
    "T1036": "defense_evasion",  # Masquerading
    "T1037": "persistence",  # Boot or Logon Initialization Scripts
    "T1039": "collection",  # Data from Network Shared Drive
    "T1040": "credential_access",  # Network Sniffing
    "T1041": "data_exfiltration",  # Exfiltration Over C2 Channel
    "T1046": "recon",  # Network Service Discovery
    "T1047": "execution",  # Windows Management Instrumentation
    "T1048": "data_exfiltration",  # Exfiltration Over Alternative Protocol
    "T1049": "recon",  # System Network Connections Discovery
    "T1052": "data_exfiltration",  # Exfiltration Over Physical Medium
    "T1053": "persistence",  # Scheduled Task/Job
    "T1055": "privilege_escalation",  # Process Injection
    "T1056": "credential_access",  # Input Capture
    "T1057": "recon",  # Process Discovery
    "T1059": "malware",  # Command and Scripting Interpreter
    "T1068": "privilege_escalation",  # Exploitation for Privilege Escalation
    "T1069": "recon",  # Permission Groups Discovery
    "T1070": "defense_evasion",  # Indicator Removal
    "T1071": "c2_beacon",  # Application Layer Protocol
    "T1071.004": "c2_beacon",  # DNS
    "T1072": "lateral_movement",  # Software Deployment Tools
    "T1074": "collection",  # Data Staged
    "T1078": "suspicious_login",  # Valid Accounts
    "T1080": "lateral_movement",  # Taint Shared Content
    "T1082": "recon",  # System Information Discovery
    "T1083": "recon",  # File and Directory Discovery
    "T1087": "recon",  # Account Discovery
    "T1090": "c2_beacon",  # Proxy
    "T1091": "lateral_movement",  # Replication Through Removable Media
    "T1092": "c2_beacon",  # Communication Through Removable Media
    "T1095": "c2_beacon",  # Non-Application Layer Protocol
    "T1098": "persistence",  # Account Manipulation
    "T1102": "c2_beacon",  # Web Service
    "T1104": "c2_beacon",  # Multi-Stage Channels
    "T1105": "malware",  # Ingress Tool Transfer
    "T1106": "execution",  # Native API
    "T1110": "ssh_brute_force",  # Brute Force
    "T1110.001": "ssh_brute_force",  # Password Guessing
    "T1111": "credential_access",  # Multi-Factor Authentication Interception
    "T1112": "persistence",  # Modify Registry
    "T1113": "collection",  # Screen Capture
    "T1114": "collection",  # Email Collection
    "T1115": "collection",  # Clipboard Data
    "T1119": "collection",  # Automated Collection
    "T1120": "recon",  # Peripheral Device Discovery
    "T1123": "collection",  # Audio Capture
    "T1124": "recon",  # System Time Discovery
    "T1125": "collection",  # Video Capture
    "T1127": "execution",  # Trusted Developer Utilities Proxy Execution
    "T1129": "execution",  # Shared Modules
    "T1132": "c2_beacon",  # Data Encoding
    "T1133": "initial_access",  # External Remote Services
    "T1134": "privilege_escalation",  # Access Token Manipulation
    "T1135": "recon",  # Network Share Discovery
    "T1136": "persistence",  # Create Account
    "T1137": "persistence",  # Office Application Startup
    "T1140": "defense_evasion",  # Deobfuscate/Decode Files or Information
    "T1176": "persistence",  # Software Extensions
    "T1185": "collection",  # Browser Session Hijacking
    "T1187": "credential_access",  # Forced Authentication
    "T1189": "web_attack",  # Drive-by Compromise
    "T1190": "web_attack",  # Exploit Public-Facing Application
    "T1195": "initial_access",  # Supply Chain Compromise
    "T1197": "persistence",  # BITS Jobs
    "T1199": "initial_access",  # Trusted Relationship
    "T1200": "initial_access",  # Hardware Additions
    "T1201": "recon",  # Password Policy Discovery
    "T1202": "defense_evasion",  # Indirect Command Execution
    "T1203": "execution",  # Exploitation for Client Execution
    "T1204": "malware",  # User Execution
    "T1205": "c2_beacon",  # Traffic Signaling
    "T1207": "defense_evasion",  # Rogue Domain Controller
    "T1210": "lateral_movement",  # Exploitation of Remote Services
    "T1211": "defense_evasion",  # Exploitation for Stealth
    "T1212": "credential_access",  # Exploitation for Credential Access
    "T1213": "collection",  # Data from Information Repositories
    "T1216": "defense_evasion",  # System Script Proxy Execution
    "T1217": "recon",  # Browser Information Discovery
    "T1218": "defense_evasion",  # System Binary Proxy Execution
    "T1219": "c2_beacon",  # Remote Access Tools
    "T1220": "defense_evasion",  # XSL Script Processing
    "T1221": "defense_evasion",  # Template Injection
    "T1222": "defense_evasion",  # File and Directory Permissions Modification
    "T1480": "defense_evasion",  # Execution Guardrails
    "T1482": "recon",  # Domain Trust Discovery
    "T1484": "privilege_escalation",  # Domain or Tenant Policy Modification
    "T1485": "impact",  # Data Destruction
    "T1486": "ransomware",  # Data Encrypted for Impact
    "T1489": "impact",  # Service Stop
    "T1490": "ransomware",  # Inhibit System Recovery
    "T1491": "impact",  # Defacement
    "T1495": "impact",  # Firmware Corruption
    "T1496": "impact",  # Resource Hijacking
    "T1497": "defense_evasion",  # Virtualization/Sandbox Evasion
    "T1498": "impact",  # Network Denial of Service
    "T1499": "impact",  # Endpoint Denial of Service
    "T1505": "persistence",  # Server Software Component
    "T1505.003": "web_attack",  # Web Shell
    "T1518": "recon",  # Software Discovery
    "T1525": "persistence",  # Implant Internal Image
    "T1526": "recon",  # Cloud Service Discovery
    "T1528": "credential_access",  # Steal Application Access Token
    "T1529": "impact",  # System Shutdown/Reboot
    "T1530": "collection",  # Data from Cloud Storage
    "T1531": "impact",  # Account Access Removal
    "T1534": "lateral_movement",  # Internal Spear-Phishing
    "T1535": "defense_evasion",  # Unused/Unsupported Cloud Regions
    "T1537": "data_exfiltration",  # Transfer Data to Cloud Account
    "T1538": "recon",  # Cloud Service Dashboard
    "T1539": "credential_access",  # Steal Web Session Cookie
    "T1542": "persistence",  # Pre-OS Boot
    "T1543": "persistence",  # Create or Modify System Process
    "T1546": "persistence",  # Event Triggered Execution
    "T1547": "persistence",  # Boot or Logon Autostart Execution
    "T1548": "privilege_escalation",  # Abuse Elevation Control Mechanism
    "T1550": "lateral_movement",  # Use Alternate Authentication Material
    "T1552": "credential_access",  # Unsecured Credentials
    "T1553": "defense_evasion",  # Subvert Trust Controls
    "T1554": "persistence",  # Compromise Host Software Binary
    "T1555": "credential_access",  # Credentials from Password Stores
    "T1556": "credential_access",  # Modify Authentication Process
    "T1557": "credential_access",  # Adversary-in-the-Middle
    "T1558": "credential_access",  # Steal or Forge Kerberos Tickets
    "T1559": "execution",  # Inter-Process Communication
    "T1560": "collection",  # Archive Collected Data
    "T1561": "impact",  # Disk Wipe
    "T1562": "defense_evasion",  # Impair Defenses  [chỉ v18.1]
    "T1563": "lateral_movement",  # Remote Service Session Hijacking
    "T1564": "defense_evasion",  # Hide Artifacts
    "T1565": "impact",  # Data Manipulation
    "T1566": "initial_access",  # Phishing
    "T1567": "data_exfiltration",  # Exfiltration Over Web Service
    "T1568": "c2_beacon",  # Dynamic Resolution
    "T1569": "execution",  # System Services
    "T1570": "lateral_movement",  # Lateral Tool Transfer
    "T1571": "c2_beacon",  # Non-Standard Port
    "T1572": "c2_beacon",  # Protocol Tunneling
    "T1573": "c2_beacon",  # Encrypted Channel
    "T1574": "persistence",  # Hijack Execution Flow
    "T1578": "defense_evasion",  # Modify Cloud Compute Infrastructure
    "T1580": "recon",  # Cloud Infrastructure Discovery
    "T1583": "resource_development",  # Acquire Infrastructure
    "T1584": "resource_development",  # Compromise Infrastructure
    "T1585": "resource_development",  # Establish Accounts
    "T1586": "resource_development",  # Compromise Accounts
    "T1587": "resource_development",  # Develop Capabilities
    "T1588": "resource_development",  # Obtain Capabilities
    "T1589": "recon",  # Gather Victim Identity Information
    "T1590": "recon",  # Gather Victim Network Information
    "T1591": "recon",  # Gather Victim Org Information
    "T1592": "recon",  # Gather Victim Host Information
    "T1593": "recon",  # Search Open Websites/Domains
    "T1594": "recon",  # Search Victim-Owned Websites
    "T1595": "recon",  # Active Scanning
    "T1596": "recon",  # Search Open Technical Databases
    "T1597": "recon",  # Search Closed Sources
    "T1598": "recon",  # Phishing for Information
    "T1599": "defense_evasion",  # Network Boundary Bridging
    "T1600": "defense_evasion",  # Weaken Encryption
    "T1601": "defense_evasion",  # Modify System Image
    "T1602": "collection",  # Data from Configuration Repository
    "T1606": "credential_access",  # Forge Web Credentials
    "T1608": "resource_development",  # Stage Capabilities
    "T1609": "execution",  # Container Administration Command
    "T1610": "execution",  # Deploy Container
    "T1611": "privilege_escalation",  # Escape to Host
    "T1612": "defense_evasion",  # Build Image on Host
    "T1613": "recon",  # Container and Resource Discovery
    "T1614": "recon",  # System Location Discovery
    "T1615": "recon",  # Group Policy Discovery
    "T1619": "recon",  # Cloud Storage Object Discovery
    "T1620": "defense_evasion",  # Reflective Code Loading
    "T1621": "credential_access",  # Multi-Factor Authentication Request Generation
    "T1622": "defense_evasion",  # Debugger Evasion
    "T1647": "defense_evasion",  # Plist File Modification
    "T1648": "execution",  # Serverless Execution
    "T1649": "credential_access",  # Steal or Forge Authentication Certificates
    "T1650": "resource_development",  # Acquire Access
    "T1651": "execution",  # Cloud Administration Command
    "T1652": "recon",  # Device Driver Discovery
    "T1653": "persistence",  # Power Settings
    "T1654": "recon",  # Log Enumeration
    "T1656": "defense_evasion",  # Impersonation  [chỉ v18.1]
    "T1657": "impact",  # Financial Theft
    "T1659": "c2_beacon",  # Content Injection
    "T1665": "c2_beacon",  # Hide Infrastructure
    "T1666": "defense_evasion",  # Modify Cloud Resource Hierarchy
    "T1667": "impact",  # Email Bombing
    "T1668": "persistence",  # Exclusive Control
    "T1669": "initial_access",  # Wi-Fi Networks
    "T1671": "persistence",  # Cloud Application Integration
    "T1672": "defense_evasion",  # Email Spoofing  [chỉ v18.1]
    "T1673": "recon",  # Virtual Machine Discovery
    "T1674": "execution",  # Input Injection
    "T1675": "execution",  # ESXi Administration Command
    "T1677": "execution",  # Poisoned Pipeline Execution
    "T1678": "defense_evasion",  # Delay Execution
    "T1679": "defense_evasion",  # Selective Exclusion
    "T1680": "recon",  # Local Storage Discovery
    "T1681": "recon",  # Search Threat Vendor Data
    "T1682": "recon",  # Query Public AI Services  [chỉ v19.2]
    "T1683": "resource_development",  # Generate Content  [chỉ v19.2]
    "T1684": "defense_evasion",  # Social Engineering  [chỉ v19.2]
    "T1685": "defense_evasion",  # Disable or Modify Tools  [chỉ v19.2]
    "T1686": "defense_evasion",  # Disable or Modify System Firewall  [chỉ v19.2]
    "T1687": "defense_evasion",  # Exploitation for Defense Impairment  [chỉ v19.2]
    "T1688": "defense_evasion",  # Safe Mode Boot  [chỉ v19.2]
    "T1689": "defense_evasion",  # Downgrade Attack  [chỉ v19.2]
    "T1690": "defense_evasion",  # Prevent Command History Logging  [chỉ v19.2]
    # --- ID đã revoked/deprecated ở cả hai bản (rule cũ kiểu Wazuh 4.x vẫn có thể phát ra) ---
    "T1002": "data_exfiltration",  # Data Compressed
    "T1004": "persistence",  # Winlogon Helper DLL
    "T1009": "defense_evasion",  # Binary Padding
    "T1013": "persistence",  # Port Monitors
    "T1015": "persistence",  # Accessibility Features
    "T1017": "lateral_movement",  # Application Deployment Software
    "T1019": "persistence",  # System Firmware
    "T1022": "data_exfiltration",  # Data Encrypted
    "T1023": "persistence",  # Shortcut Modification
    "T1024": "c2_beacon",  # Custom Cryptographic Protocol
    "T1026": "c2_beacon",  # Multiband Communication
    "T1028": "lateral_movement",  # Windows Remote Management
    "T1031": "persistence",  # Modify Existing Service
    "T1032": "c2_beacon",  # Standard Cryptographic Protocol
    "T1034": "persistence",  # Path Interception
    "T1035": "execution",  # Service Execution
    "T1038": "persistence",  # DLL Search Order Hijacking
    "T1042": "persistence",  # Change Default File Association
    "T1043": "c2_beacon",  # Commonly Used Port
    "T1044": "persistence",  # File System Permissions Weakness
    "T1045": "defense_evasion",  # Software Packing
    "T1050": "persistence",  # New Service
    "T1051": "lateral_movement",  # Shared Webroot
    "T1054": "defense_evasion",  # Indicator Blocking
    "T1058": "persistence",  # Service Registry Permissions Weakness
    "T1060": "persistence",  # Registry Run Keys / Startup Folder
    "T1061": "execution",  # Graphical User Interface
    "T1062": "persistence",  # Hypervisor
    "T1063": "recon",  # Security Software Discovery
    "T1064": "malware",  # Scripting
    "T1065": "c2_beacon",  # Uncommonly Used Port
    "T1066": "defense_evasion",  # Indicator Removal from Tools
    "T1067": "persistence",  # Bootkit
    "T1073": "defense_evasion",  # DLL Side-Loading
    "T1075": "lateral_movement",  # Pass the Hash
    "T1076": "lateral_movement",  # Remote Desktop Protocol
    "T1077": "lateral_movement",  # Windows Admin Shares
    "T1079": "c2_beacon",  # Multilayer Encryption
    "T1081": "credential_access",  # Credentials in Files
    "T1084": "persistence",  # Windows Management Instrumentation Event Subscription
    "T1085": "execution",  # Rundll32
    "T1086": "malware",  # PowerShell
    "T1088": "privilege_escalation",  # Bypass User Account Control
    "T1089": "defense_evasion",  # Disabling Security Tools
    "T1093": "defense_evasion",  # Process Hollowing
    "T1094": "c2_beacon",  # Custom Command and Control Protocol
    "T1096": "defense_evasion",  # NTFS File Attributes
    "T1097": "lateral_movement",  # Pass the Ticket
    "T1099": "defense_evasion",  # Timestomp
    "T1100": "persistence",  # Web Shell
    "T1101": "persistence",  # Security Support Provider
    "T1103": "persistence",  # AppInit DLLs
    "T1107": "defense_evasion",  # File Deletion
    "T1108": "persistence",  # Redundant Access
    "T1109": "persistence",  # Component Firmware
    "T1116": "defense_evasion",  # Code Signing
    "T1117": "execution",  # Regsvr32
    "T1118": "execution",  # InstallUtil
    "T1121": "execution",  # Regsvcs/Regasm
    "T1122": "persistence",  # Component Object Model Hijacking
    "T1126": "defense_evasion",  # Network Share Connection Removal
    "T1128": "persistence",  # Netsh Helper DLL
    "T1130": "defense_evasion",  # Install Root Certificate
    "T1131": "persistence",  # Authentication Package
    "T1138": "persistence",  # Application Shimming
    "T1139": "credential_access",  # Bash History
    "T1141": "credential_access",  # Input Prompt
    "T1142": "credential_access",  # Keychain
    "T1143": "defense_evasion",  # Hidden Window
    "T1144": "defense_evasion",  # Gatekeeper Bypass
    "T1145": "credential_access",  # Private Keys
    "T1146": "defense_evasion",  # Clear Command History
    "T1147": "defense_evasion",  # Hidden Users
    "T1148": "defense_evasion",  # HISTCONTROL
    "T1149": "defense_evasion",  # LC_MAIN Hijacking
    "T1150": "persistence",  # Plist Modification
    "T1151": "execution",  # Space after Filename
    "T1152": "persistence",  # Launchctl
    "T1153": "execution",  # Source
    "T1154": "persistence",  # Trap
    "T1155": "execution",  # AppleScript
    "T1156": "persistence",  # Malicious Shell Modification
    "T1157": "persistence",  # Dylib Hijacking
    "T1158": "persistence",  # Hidden Files and Directories
    "T1159": "persistence",  # Launch Agent
    "T1160": "persistence",  # Launch Daemon
    "T1161": "persistence",  # LC_LOAD_DYLIB Addition
    "T1162": "persistence",  # Login Item
    "T1163": "persistence",  # Rc.common
    "T1164": "persistence",  # Re-opened Applications
    "T1165": "persistence",  # Startup Items
    "T1166": "persistence",  # Setuid and Setgid
    "T1167": "credential_access",  # Securityd Memory
    "T1168": "persistence",  # Local Job Scheduling
    "T1169": "privilege_escalation",  # Sudo
    "T1170": "execution",  # Mshta
    "T1171": "credential_access",  # LLMNR/NBT-NS Poisoning and Relay
    "T1172": "c2_beacon",  # Domain Fronting
    "T1173": "execution",  # Dynamic Data Exchange
    "T1174": "credential_access",  # Password Filter DLL
    "T1175": "lateral_movement",  # Component Object Model and Distributed COM
    "T1177": "persistence",  # LSASS Driver
    "T1178": "privilege_escalation",  # SID-History Injection
    "T1179": "credential_access",  # Hooking
    "T1180": "persistence",  # Screensaver
    "T1181": "privilege_escalation",  # Extra Window Memory Injection
    "T1182": "persistence",  # AppCert DLLs
    "T1183": "persistence",  # Image File Execution Options Injection
    "T1184": "lateral_movement",  # SSH Hijacking
    "T1186": "defense_evasion",  # Process Doppelgänging
    "T1188": "c2_beacon",  # Multi-hop Proxy
    "T1191": "execution",  # CMSTP
    "T1192": "initial_access",  # Spear-Phishing Link
    "T1193": "initial_access",  # Spear-Phishing Attachment
    "T1194": "initial_access",  # Spear-Phishing via Service
    "T1196": "execution",  # Control Panel Items
    "T1198": "persistence",  # SIP and Trust Provider Hijacking
    "T1206": "privilege_escalation",  # Sudo Caching
    "T1208": "credential_access",  # Kerberoasting
    "T1209": "persistence",  # Time Providers
    "T1214": "credential_access",  # Credentials in Registry
    "T1215": "persistence",  # Kernel Modules and Extensions
    "T1223": "execution",  # Compiled HTML File
    "T1483": "c2_beacon",  # Domain Generation Algorithms
    "T1487": "impact",  # Disk Structure Wipe
    "T1488": "impact",  # Disk Content Wipe
    "T1492": "impact",  # Stored Data Manipulation
    "T1493": "impact",  # Transmitted Data Manipulation
    "T1494": "impact",  # Runtime Data Manipulation
    "T1500": "defense_evasion",  # Compile After Delivery
    "T1501": "persistence",  # Systemd Service
    "T1502": "privilege_escalation",  # Parent PID Spoofing
    "T1503": "credential_access",  # Credentials from Web Browsers
    "T1504": "persistence",  # PowerShell Profile
    "T1506": "lateral_movement",  # Web Session Cookie
    "T1514": "privilege_escalation",  # Elevated Execution with Prompt
    "T1519": "persistence",  # Emond
    "T1522": "credential_access",  # Cloud Instance Metadata API
    "T1527": "lateral_movement",  # Application Access Token
    "T1536": "defense_evasion",  # Revert Cloud Instance
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
        # Tier 6 (v3.5): reached only when everything above found nothing (module docstring).
        (_tier_mitre_exact(mitre_ids, EXTENDED_TECHNIQUE_TO_CATEGORY), "mitre"),
        (_tier_mitre_parent(mitre_ids, EXTENDED_TECHNIQUE_TO_CATEGORY), "mitre_parent"),
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
