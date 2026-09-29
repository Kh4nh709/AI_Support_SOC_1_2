"""`ingest.category`'s Windows tiers and the `brute_force` knowledge base (P9-T02, DEC-149).

Card: docs/plan/tasks/P9/P9-tasks.md §4, with the Director's follow-up (open items 1-3).
For a `windows_eventchannel` alert three Windows tiers run before tier 1 — exact MITRE id,
parent MITRE id, then `rule.groups`, on the Windows tables — and tier 5 (destination port)
never runs. Any other decoder skips the Windows tiers and keeps tier 5, and the four shared
tables are not edited (their v3.2 hash is still pinned in `test_category.py`), so an alert
from any other decoder cannot change category. The parse-level cases use the synthetic
fixtures under `fixtures/windows/` (P9-T01).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from app.ingest.category import (
    GROUP_TO_CATEGORY,
    PRIORITY,
    TECHNIQUE_TO_CATEGORY,
    WINDOWS_DECODER,
    WINDOWS_GROUP_TO_CATEGORY,
    WINDOWS_TECHNIQUE_TO_CATEGORY,
    resolve,
)
from app.ingest.wazuh_parser import parse_wazuh_alert
from app.kb import lookup
from app.llm import builder
from app.tier1.triage import _make_rule_check

WIN = "windows_eventchannel"
FIXTURES = Path(__file__).parent / "fixtures"
WINDOWS_FIXTURES = FIXTURES / "windows"

#: The five shared playbooks that gain a Windows section (card §4 item 4).
SHARED_PLAYBOOKS = ("suspicious_login", "malware", "ransomware", "c2_beacon", "data_exfiltration")
WINDOWS_SECTION = "## 7 · Windows (added 29/09, P9-T02, not reviewed)"

#: What each Windows-tier id resolves to on any decoder other than `windows_eventchannel`:
#: the shared tiers' answer at v3.2, which the Windows tiers must leave untouched.
SHARED_TIER_ANSWER: dict[str, tuple[str, str]] = {
    "T1110": ("ssh_brute_force", "mitre"),
    "T1110.001": ("ssh_brute_force", "mitre"),
    "T1110.003": ("ssh_brute_force", "mitre_parent"),
    "T1490": ("unknown", "none"),
    "T1485": ("unknown", "none"),
    "T1071.001": ("c2_beacon", "mitre_parent"),
    "T1573": ("unknown", "none"),
    "T1048": ("unknown", "none"),
    "T1567": ("unknown", "none"),
    "T1059.001": ("unknown", "none"),
}


def _win(stem: str) -> dict:
    return json.loads((WINDOWS_FIXTURES / f"synthetic_{stem}.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# the Windows tables (card §4 item 1; follow-up item 1)
# ---------------------------------------------------------------------------


def test_windows_table_is_exactly_the_cards():
    assert WINDOWS_DECODER == WIN
    assert WINDOWS_TECHNIQUE_TO_CATEGORY == {
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


def test_windows_group_table_is_exactly_the_directors():
    assert WINDOWS_GROUP_TO_CATEGORY == {
        "authentication_failed": "brute_force",
        "authentication_failures": "brute_force",
        "invalid_login": "brute_force",
        "authentication_success": "suspicious_login",
    }


def test_windows_only_ids_have_no_key_in_the_shared_table():
    """Besides the T1110 family it overrides, the Windows table adds only ids the shared
    table has no key for — the shared table is never shadowed for them."""
    windows_only = set(WINDOWS_TECHNIQUE_TO_CATEGORY) - {"T1110", "T1110.001", "T1110.003"}
    assert windows_only & set(TECHNIQUE_TO_CATEGORY) == set()


# ---------------------------------------------------------------------------
# W1 exact id, W2 parent id (card §4 item 1; follow-up item 2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("technique_id", ["T1110", "T1110.001", "T1110.003"])
def test_windows_t1110_resolves_brute_force(technique_id):
    r = resolve([technique_id], ["windows", "authentication_failures"], WIN, 0)
    assert (r.category, r.categories, r.resolved_by) == ("brute_force", ("brute_force",), "mitre")


@pytest.mark.parametrize(
    "technique_id",
    [t for t in WINDOWS_TECHNIQUE_TO_CATEGORY if not t.startswith("T1110")],
)
def test_windows_only_ids_resolve_on_the_windows_decoder(technique_id):
    r = resolve([technique_id], [], WIN, 0)
    assert r.category == WINDOWS_TECHNIQUE_TO_CATEGORY[technique_id]
    assert r.resolved_by == "mitre"


@pytest.mark.parametrize(
    "technique_id,expected",
    [
        ("T1110.002", "brute_force"),
        ("T1110.004", "brute_force"),
        ("T1485.001", "ransomware"),
        ("T1573.002", "c2_beacon"),
        ("T1048.003", "data_exfiltration"),
        ("T1567.002", "data_exfiltration"),
    ],
)
def test_windows_sub_technique_reaches_its_parent(technique_id, expected):
    r = resolve([technique_id], [], WIN, 0)
    assert (r.category, r.resolved_by) == (expected, "mitre_parent")


def test_windows_exact_id_wins_over_a_parent_for_the_whole_call():
    """The shared tiers' rule, on the Windows table: W2 runs only when no id in the array
    matched W1 exactly."""
    r = resolve(["T1567.002", "T1110.001"], [], WIN, 0)
    assert (r.categories, r.resolved_by) == (("brute_force",), "mitre")


@pytest.mark.parametrize("decoder", [None, "", "pam", "auditd", "ossec", "windows", "eventchannel"])
@pytest.mark.parametrize("technique_id", list(SHARED_TIER_ANSWER))
def test_the_same_ids_resolve_as_before_on_any_other_decoder(technique_id, decoder):
    """By construction: without `windows_eventchannel` in the decoder name the Windows tiers
    do not run, so every id lands where the shared tiers put it at v3.2 (decoders with no
    tier-4 key, so the expected answer is the MITRE tiers' alone)."""
    r = resolve([technique_id], [], decoder, 0)
    assert (r.category, r.resolved_by) == SHARED_TIER_ANSWER[technique_id]


@pytest.mark.parametrize(
    "decoder", [WIN, "WINDOWS_EVENTCHANNEL", "  windows_eventchannel  ", "x-windows_eventchannel"]
)
def test_windows_guard_is_a_case_and_whitespace_insensitive_substring(decoder):
    assert resolve(["T1110"], [], decoder, 0).category == "brute_force"


def test_windows_tier_is_consulted_before_tier_1():
    """The canonical pair T1078 + T1110: on Linux tier 1 keeps both; on Windows W1
    answers first and alone."""
    linux = resolve(["T1078", "T1110"], [], "sshd", 0)
    windows = resolve(["T1078", "T1110"], [], WIN, 0)
    assert linux.categories == ("ssh_brute_force", "suspicious_login")
    assert (windows.category, windows.categories) == ("brute_force", ("brute_force",))


def test_windows_candidates_are_collected_and_sorted_by_priority():
    forward = resolve(["T1110", "T1490", "T1059.001"], [], WIN, 0)
    backward = resolve(["T1059.001", "T1490", "T1110"], [], WIN, 0)
    assert forward == backward
    assert forward.categories == ("ransomware", "malware", "brute_force")


# ---------------------------------------------------------------------------
# W3 groups (follow-up item 1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("group", list(WINDOWS_GROUP_TO_CATEGORY))
def test_windows_group_tier(group):
    windows = resolve([], ["windows", "windows_security", group], WIN, 0)
    assert (windows.category, windows.resolved_by) == (
        WINDOWS_GROUP_TO_CATEGORY[group],
        "rule_groups",
    )
    # The same group on any other decoder stays where the shared tier 3 puts it.
    linux = resolve([], [group], "pam", 0)
    assert (linux.category, linux.resolved_by) == (GROUP_TO_CATEGORY[group], "rule_groups")


def test_windows_mitre_tiers_come_before_the_windows_group_tier():
    exact = resolve(["T1110"], ["authentication_success"], WIN, 0)
    parent = resolve(["T1110.002"], ["authentication_success"], WIN, 0)
    assert (exact.category, exact.resolved_by) == ("brute_force", "mitre")
    assert (parent.category, parent.resolved_by) == ("brute_force", "mitre_parent")


def test_windows_group_tier_comes_before_the_shared_mitre_tiers():
    """The two real Windows logon rule signatures on the dev DB: 60122 (4625) is T1531, in
    no table, + `authentication_failed`; 60106/60118 (4624) are T1078 + `authentication_success`,
    which W3 answers before tier 1 would (same category, resolved_by `rule_groups`)."""
    failure = resolve(["T1531"], ["windows", "windows_security", "authentication_failed"], WIN, 0)
    success = resolve(["T1078"], ["windows", "windows_security", "authentication_success"], WIN, 0)
    assert (failure.category, failure.resolved_by) == ("brute_force", "rule_groups")
    assert (success.category, success.resolved_by) == ("suspicious_login", "rule_groups")


# ---------------------------------------------------------------------------
# fall-through, and no port tier for Windows (follow-up item 3)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mitre_ids,groups,expected",
    [
        (["T1486"], [], ("ransomware", "mitre")),
        (["T1204"], ["virus"], ("malware", "mitre")),
        (["T1071.999"], [], ("c2_beacon", "mitre_parent")),
        ([], ["sudo"], ("privilege_escalation", "rule_groups")),
        ([], [], ("unknown", "none")),
    ],
)
def test_no_windows_match_falls_through_to_tiers_1_to_4(mitre_ids, groups, expected):
    r = resolve(mitre_ids, groups, WIN, 0)
    assert (r.category, r.resolved_by) == expected


@pytest.mark.parametrize(
    "dst_port,linux_category", [(22, "ssh_brute_force"), (80, "web_attack"), (443, "web_attack")]
)
def test_windows_skips_the_port_tier(dst_port, linux_category):
    """A Windows host's destination port is not a category signal; any other decoder keeps
    tier 5."""
    windows = resolve([], ["windows", "sysmon_event3"], WIN, dst_port)
    assert (windows.category, windows.categories, windows.resolved_by) == ("unknown", (), "none")
    linux = resolve([], [], "pam", dst_port)
    assert (linux.category, linux.resolved_by) == (linux_category, "dst_port")


@pytest.mark.parametrize(
    "mitre_ids,groups,dst_port",
    [
        ([None, 3, ""], [None], "not-a-port"),
        (None, None, None),
        ([[1, 2]], [{"a": 1}], [1, 2]),
        (["t1110 "], [], 0),
    ],
)
def test_windows_tier_never_raises(mitre_ids, groups, dst_port):
    r = resolve(mitre_ids, groups, WIN, dst_port)
    assert r.resolved_by in {"mitre", "none"}


def test_priority_places_brute_force_directly_after_ssh_brute_force():
    assert PRIORITY.index("brute_force") == PRIORITY.index("ssh_brute_force") + 1
    assert tuple(c for c in PRIORITY if c != "brute_force") == (
        "ransomware",
        "malware",
        "c2_beacon",
        "data_exfiltration",
        "privilege_escalation",
        "ssh_brute_force",
        "web_attack",
        "suspicious_login",
        "recon",
        "policy_violation",
        "unknown",
    )


def test_every_windows_value_has_a_playbook_and_a_table():
    """R5 for both Windows tables, and the prompt builder's closed set knows the new name."""
    produced = set(WINDOWS_TECHNIQUE_TO_CATEGORY.values()) | set(WINDOWS_GROUP_TO_CATEGORY.values())
    for category in produced:
        assert lookup.get_playbook(category) is not None, category
        assert lookup.get_decision_table(category) is not None, category
    assert builder.Category("brute_force") is builder.Category.BRUTE_FORCE


# ---------------------------------------------------------------------------
# through the parser, on the synthetic fixtures
# ---------------------------------------------------------------------------
#
# No test asserts the lockout fixture's (4740, rule 60115) category: no real 60115
# alert exists on the dev DB to confirm which groups that rule carries (P9-T02 report).


def test_windows_single_logon_failure_resolves_brute_force():
    """60122-shaped: T1531 + `authentication_failed` — one wrong password reaches
    `brute_force` through W3."""
    alert = parse_wazuh_alert(_win("4625_network_logon_failure")).alert
    assert (alert.category, alert.categories, alert.resolved_by) == (
        "brute_force",
        ("brute_force",),
        "rule_groups",
    )


def test_windows_multiple_logon_failures_resolve_brute_force():
    """60204-shaped: T1110 + `authentication_failures` — W1."""
    alert = parse_wazuh_alert(_win("4625_multiple_logon_failures")).alert
    assert (alert.category, alert.resolved_by) == ("brute_force", "mitre")
    assert alert.mapping_version == "v3.3"


def test_windows_logon_success_resolves_suspicious_login():
    """60106-shaped: T1078 + `authentication_success` — W3, before tier 1."""
    alert = parse_wazuh_alert(_win("4624_rdp_logon_type_10")).alert
    assert (alert.category, alert.resolved_by) == ("suspicious_login", "rule_groups")


def test_windows_sysmon_3_on_port_443_with_no_other_signal_is_unknown():
    doc = _win("sysmon_3_network_connection")
    del doc["_source"]["rule"]["mitre"]
    doc["_source"]["data"]["win"]["eventdata"]["destinationPort"] = "443"
    alert = parse_wazuh_alert(doc).alert
    assert alert.dst_port == 443
    assert (alert.category, alert.categories, alert.resolved_by) == ("unknown", (), "none")


def test_sysmon_3_t1071_001_now_resolves_at_the_windows_tier():
    """Same category as v3.2 gave (tier 2, parent T1071), now answered by the exact id."""
    alert = parse_wazuh_alert(_win("sysmon_3_network_connection")).alert
    assert (alert.category, alert.resolved_by) == ("c2_beacon", "mitre")


def test_linux_sshd_alerts_resolve_as_before():
    """The canonical sshd alert, and the Windows group/port changes seen from Linux."""
    canonical = json.loads((FIXTURES / "alert_40112.json").read_text(encoding="utf-8"))
    alert = parse_wazuh_alert(canonical).alert
    assert (alert.category, alert.categories, alert.resolved_by) == (
        "ssh_brute_force",
        ("ssh_brute_force", "suspicious_login"),
        "mitre",
    )
    groups_only = resolve([], ["authentication_failed"], "sshd", 0)
    assert (groups_only.category, groups_only.resolved_by) == ("ssh_brute_force", "rule_groups")
    port_only = resolve([], [], "pam", 22)
    assert (port_only.category, port_only.resolved_by) == ("ssh_brute_force", "dst_port")


# ---------------------------------------------------------------------------
# the knowledge base (card §4 items 3-4)
# ---------------------------------------------------------------------------


def test_brute_force_playbook_is_agent_drafted_and_covers_the_cards_signals():
    text = lookup.get_playbook("brute_force")
    head = "\n".join(text.splitlines()[:4])
    assert "agent-drafted 29/09 (P9-T02), not reviewed" in head
    for signal in (
        "0xC000006A",
        "0xC0000064",
        "0xC0000234",
        "4771",
        "`0x18`",
        "`0x6`",
        "`0x12`",
        "4740",
        "Logon Type",
        "spraying",
        "T1110.001",
        "T1110.003",
    ):
        assert signal in text, signal


def test_gate_step_4_refuses_every_brute_force_rule_while_unsigned():
    """Even a point where the table's own false_positive rule holds is refused: ① cannot
    auto-close a `brute_force` alert until the Owner and the advisor sign the table."""
    table = lookup.get_decision_table("brute_force")
    assert lookup.check_consistency(table) == []
    fp_point = {
        "severity": "low",
        "rule_level": 3,
        "ioc_reputation": "not_found",
        "asset_criticality": "low",
        "identity_privileged": "false",
        "occurrence_count": 1,
    }
    assert lookup.apply_table(table, fp_point) == ("false_positive", "bf-1")
    for rule in table.rules:
        assert _make_rule_check(table, fp_point)(rule.id) == (False, "table_unreviewed")


@pytest.mark.parametrize("category", SHARED_PLAYBOOKS)
def test_shared_playbooks_end_with_one_windows_section(category):
    """Appended after section 6, so every line the signed tables cite keeps its number."""
    lines = lookup.get_playbook(category).splitlines()
    headings = [line for line in lines if line.startswith("## ")]
    assert headings[-1] == WINDOWS_SECTION
    assert lines.count(WINDOWS_SECTION) == 1
    assert headings[-2].startswith("## 6 · ")


@pytest.mark.parametrize("category", ["c2_beacon", "data_exfiltration"])
def test_network_playbooks_say_the_windows_signal_is_weak_without_an_ids(category):
    section = lookup.get_playbook(category).split(WINDOWS_SECTION, 1)[1]
    assert "Không có IDS mạng thì tín hiệu phía Windows yếu" in section
