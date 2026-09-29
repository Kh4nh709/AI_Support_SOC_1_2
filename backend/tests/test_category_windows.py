"""`ingest.category`'s Windows tier and the `brute_force` knowledge base (P9-T02, DEC-149).

Card: docs/plan/tasks/P9/P9-tasks.md §4. The Windows tier is consulted before tier 1 and
only for a `windows_eventchannel` alert; when it matches nothing the five shared tiers run
unchanged, and the four shared tables are not edited (their v3.2 hash is still pinned in
`test_category.py`), so an alert from any other decoder cannot change category. The
parse-level cases use the synthetic fixtures under `fixtures/windows/` (P9-T01).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from app.ingest.category import (
    PRIORITY,
    TECHNIQUE_TO_CATEGORY,
    WINDOWS_DECODER,
    WINDOWS_TECHNIQUE_TO_CATEGORY,
    resolve,
)
from app.ingest.wazuh_parser import parse_wazuh_alert
from app.kb import lookup
from app.llm import builder
from app.tier1.triage import _make_rule_check

WIN = "windows_eventchannel"
WINDOWS_FIXTURES = Path(__file__).parent / "fixtures" / "windows"

#: The five shared playbooks that gain a Windows section (card §4 item 4).
SHARED_PLAYBOOKS = ("suspicious_login", "malware", "ransomware", "c2_beacon", "data_exfiltration")
WINDOWS_SECTION = "## 7 · Windows (added 29/09, P9-T02, not reviewed)"

#: What each Windows-tier id resolves to on any decoder other than `windows_eventchannel`:
#: the shared tiers' answer at v3.2, which the Windows tier must leave untouched.
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
# the Windows tier (card §4 item 1)
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


def test_windows_only_ids_have_no_key_in_the_shared_table():
    """Besides the T1110 family it overrides, the Windows table adds only ids the shared
    table has no key for — the shared table is never shadowed for them."""
    windows_only = set(WINDOWS_TECHNIQUE_TO_CATEGORY) - {"T1110", "T1110.001", "T1110.003"}
    assert windows_only & set(TECHNIQUE_TO_CATEGORY) == set()


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


@pytest.mark.parametrize("decoder", [None, "", "pam", "auditd", "ossec", "windows", "eventchannel"])
@pytest.mark.parametrize("technique_id", list(SHARED_TIER_ANSWER))
def test_the_same_ids_resolve_as_before_on_any_other_decoder(technique_id, decoder):
    """By construction: without `windows_eventchannel` in the decoder name the Windows tier
    yields nothing, so every id lands where the shared tiers put it at v3.2 (decoders
    with no tier-4 key, so the expected answer is the MITRE tiers' alone)."""
    r = resolve([technique_id], [], decoder, 0)
    assert (r.category, r.resolved_by) == SHARED_TIER_ANSWER[technique_id]


@pytest.mark.parametrize(
    "decoder", [WIN, "WINDOWS_EVENTCHANNEL", "  windows_eventchannel  ", "x-windows_eventchannel"]
)
def test_windows_guard_is_a_case_and_whitespace_insensitive_substring(decoder):
    assert resolve(["T1110"], [], decoder, 0).category == "brute_force"


def test_windows_tier_is_consulted_before_tier_1():
    """The canonical pair T1078 + T1110: on Linux tier 1 keeps both; on Windows the
    Windows tier answers first and alone."""
    linux = resolve(["T1078", "T1110"], [], "sshd", 0)
    windows = resolve(["T1078", "T1110"], [], WIN, 0)
    assert linux.categories == ("ssh_brute_force", "suspicious_login")
    assert (windows.category, windows.categories) == ("brute_force", ("brute_force",))


def test_windows_candidates_are_collected_and_sorted_by_priority():
    forward = resolve(["T1110", "T1490", "T1059.001"], [], WIN, 0)
    backward = resolve(["T1059.001", "T1490", "T1110"], [], WIN, 0)
    assert forward == backward
    assert forward.categories == ("ransomware", "malware", "brute_force")


@pytest.mark.parametrize(
    "mitre_ids,groups,dst_port,expected",
    [
        (["T1078"], ["authentication_success"], 0, ("suspicious_login", "mitre")),
        (["T1486"], [], 0, ("ransomware", "mitre")),
        (["T1071.999"], [], 0, ("c2_beacon", "mitre_parent")),
        ([], ["authentication_success"], 0, ("suspicious_login", "rule_groups")),
        ([], [], 443, ("web_attack", "dst_port")),
        ([], [], 0, ("unknown", "none")),
    ],
)
def test_no_windows_match_falls_through_to_the_five_tiers_unchanged(
    mitre_ids, groups, dst_port, expected
):
    r = resolve(mitre_ids, groups, WIN, dst_port)
    assert (r.category, r.resolved_by) == expected


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
    """R5 for the Windows table, and the prompt builder's closed set knows the new name."""
    for category in set(WINDOWS_TECHNIQUE_TO_CATEGORY.values()):
        assert lookup.get_playbook(category) is not None, category
        assert lookup.get_decision_table(category) is not None, category
    assert builder.Category("brute_force") is builder.Category.BRUTE_FORCE


# ---------------------------------------------------------------------------
# through the parser, on the synthetic fixtures
# ---------------------------------------------------------------------------


def test_windows_multiple_logon_failures_resolve_brute_force():
    alert = parse_wazuh_alert(_win("4625_multiple_logon_failures")).alert
    assert (alert.category, alert.resolved_by) == ("brute_force", "mitre")
    assert alert.mapping_version == "v3.3"


def test_sysmon_3_t1071_001_now_resolves_at_the_windows_tier():
    """Same category as v3.2 gave (tier 2, parent T1071), now answered by the exact id."""
    alert = parse_wazuh_alert(_win("sysmon_3_network_connection")).alert
    assert (alert.category, alert.resolved_by) == ("c2_beacon", "mitre")


def test_windows_logon_success_falls_through_to_suspicious_login():
    alert = parse_wazuh_alert(_win("4624_rdp_logon_type_10")).alert
    assert (alert.category, alert.resolved_by) == ("suspicious_login", "mitre")


@pytest.mark.parametrize("stem", ["4625_network_logon_failure", "4740_account_lockout"])
def test_windows_failure_without_t1110_still_reaches_ssh_brute_force(stem):
    """The card's tier is MITRE-only. Wazuh's single-4625 rule (60122) and lockout rule
    (60115) carry T1531, not T1110, so the Windows tier matches nothing and tier 3 files
    them under `ssh_brute_force` by their `authentication_failed(s)` group. Pinned so the
    open item in the P9-T02 report stays visible; a Windows group rule would change it."""
    alert = parse_wazuh_alert(_win(stem)).alert
    assert (alert.category, alert.resolved_by) == ("ssh_brute_force", "rule_groups")


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
