"""`ingest.category` — the five-tier category resolver (P2-T03).

Ported from `Final-Project`'s `category_resolver.py` mapping tables (DEC-002),
renamed onto the ten `kb/playbooks/` names (R5), with the parent-technique tier
split out from the exact-technique tier and the priority-sort rule (phase-1
§Khối 5 chốt C5) applied uniformly at every tier, not only the first — the
canonical alert (context pack §8) is the regression: `T1078` and `T1110` both
match tier 1, and `T1110`'s `ssh_brute_force` outranks `T1078`'s
`suspicious_login` regardless of array order (R4).
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest
from app.ingest.category import (
    DECODER_TO_CATEGORY,
    GROUP_TO_CATEGORY,
    MAPPING_VERSION,
    PORT_TO_CATEGORY,
    PRIORITY,
    TECHNIQUE_TO_CATEGORY,
    WINDOWS_TECHNIQUE_TO_CATEGORY,
    Resolution,
    resolve,
)
from app.kb import lookup

REPO_ROOT = Path(__file__).resolve().parents[2]
PLAYBOOKS = {p.stem for p in (REPO_ROOT / "kb" / "playbooks").glob("*.md")}
SCHEMA_SQL = REPO_ROOT / "docs" / "Schema" / "schema.sql"
CATEGORY_PY = REPO_ROOT / "backend" / "app" / "ingest" / "category.py"

RESOLVED_BY_SET = {"mitre", "mitre_parent", "rule_groups", "decoder", "dst_port", "none"}

# The four `Final-Project` category values with no `kb/playbooks/` file — see the
# P2-T03 report for the full list and which MITRE ids / rule.groups reached them.
# Not spelled out here on purpose: this is exactly what acceptance 6 forbids from
# appearing anywhere in `category.py`, code or comments.
DROPPED_TECHNIQUE_IDS = ("T1566", "T1136", "T1098", "T1543", "T1053", "T1059", "T1059.001")
DROPPED_PORT = 3389


# --------------------------------------------------------------------------
# one test per tier
# --------------------------------------------------------------------------


def test_tier_1_exact_mitre_technique():
    r = resolve(["T1110"], [], None, 0)
    assert r.category == "ssh_brute_force"
    assert r.resolved_by == "mitre"


def test_tier_2_parent_mitre_technique():
    # T1071.999 is not itself a key; its parent T1071 is.
    r = resolve(["T1071.999"], [], None, 0)
    assert r.category == "c2_beacon"
    assert r.resolved_by == "mitre_parent"


def test_tier_3_rule_groups():
    r = resolve([], ["authentication_failed"], None, 0)
    assert r.category == "ssh_brute_force"
    assert r.resolved_by == "rule_groups"


def test_tier_4_decoder_substring():
    r = resolve([], [], "sshd", 0)
    assert r.category == "ssh_brute_force"
    assert r.resolved_by == "decoder"


def test_tier_5_destination_port():
    r = resolve([], [], None, 22)
    assert r.category == "ssh_brute_force"
    assert r.resolved_by == "dst_port"


def test_a_higher_tier_wins_even_though_a_lower_tier_also_matches():
    # rule.groups would also resolve to ssh_brute_force, but mitre answers first.
    r = resolve(["T1486"], ["authentication_failed"], None, 0)
    assert r.category == "ransomware"
    assert r.resolved_by == "mitre"


# --------------------------------------------------------------------------
# the canonical alert (context pack §8) and R4 (array-order independence)
# --------------------------------------------------------------------------


def test_canonical_alert_t1110_outranks_t1078():
    r = resolve(["T1078", "T1110"], ["syslog", "attacks"], "sshd", 0)
    assert r.category == "ssh_brute_force"
    assert r.categories == ("ssh_brute_force", "suspicious_login")
    assert r.resolved_by == "mitre"


@pytest.mark.parametrize(
    "mitre_ids,groups",
    [
        (["T1078", "T1110"], ["syslog", "attacks"]),
        (["T1110", "T1078"], ["syslog", "attacks"]),
        (["T1078", "T1110"], ["attacks", "syslog"]),
        (["T1110", "T1078"], ["attacks", "syslog"]),
    ],
)
def test_r4_array_order_never_changes_the_result(mitre_ids, groups):
    r = resolve(mitre_ids, groups, "sshd", 0)
    assert r.category == "ssh_brute_force"
    assert r.categories == ("ssh_brute_force", "suspicious_login")
    assert r.resolved_by == "mitre"


def test_resolution_equality_holds_across_array_permutations():
    a = resolve(["T1078", "T1110"], ["syslog", "attacks"], "sshd", 0)
    b = resolve(["T1110", "T1078"], ["attacks", "syslog"], "sshd", 0)
    assert a == b


# --------------------------------------------------------------------------
# tiers 4 and 5 are reachable, and a dropped mapping falls through
# --------------------------------------------------------------------------


def test_tier_4_is_reachable_with_nothing_above_it():
    assert resolve([], [], "apache-access", 0).resolved_by == "decoder"


def test_tier_5_is_reachable_with_nothing_above_it():
    assert resolve([], [], None, 80).resolved_by == "dst_port"


def test_dropped_port_mapping_falls_through_to_unknown():
    # port 3389 used to map to a category with no playbook; it now resolves to nothing.
    r = resolve([], [], None, DROPPED_PORT)
    assert r.category == "unknown"
    assert r.resolved_by == "none"
    assert r.categories == ()


@pytest.mark.parametrize("technique_id", DROPPED_TECHNIQUE_IDS)
def test_dropped_technique_ids_no_longer_match_any_tier(technique_id):
    r = resolve([technique_id], [], None, 0)
    assert r.category == "unknown"
    assert r.resolved_by == "none"


# --------------------------------------------------------------------------
# totality (R1, R2) — nothing on this path may ever raise
# --------------------------------------------------------------------------


def test_nothing_matches_resolves_to_unknown_and_does_not_raise():
    assert resolve([], [], None, 0) == Resolution("unknown", (), "none", MAPPING_VERSION)


@pytest.mark.parametrize(
    "mitre_ids,groups,decoder,dst_port",
    [
        ([None, 3, ""], [None], 7, "not-a-port"),
        (None, None, None, None),
        ([], [], "", None),
        (["not-a-technique"], ["not-a-group"], "not-a-decoder", -1),
        ([[1, 2]], [{"a": 1}], object(), [1, 2]),
    ],
)
def test_r2_total_never_raises_on_garbage_input(mitre_ids, groups, decoder, dst_port):
    r = resolve(mitre_ids, groups, decoder, dst_port)
    assert r.category == "unknown"
    assert r.resolved_by == "none"
    assert r.categories == ()


def test_resolve_is_deterministic_r3():
    a = resolve(["T1078", "T1110"], ["syslog"], "sshd", 22)
    b = resolve(["T1078", "T1110"], ["syslog"], "sshd", 22)
    assert a == b


# --------------------------------------------------------------------------
# R5 — every mapped value has a real playbook
# --------------------------------------------------------------------------


def test_r5_every_mapped_value_has_a_real_playbook():
    produced = (
        set(TECHNIQUE_TO_CATEGORY.values())
        | set(GROUP_TO_CATEGORY.values())
        | set(DECODER_TO_CATEGORY.values())
        | set(PORT_TO_CATEGORY.values())
    )
    assert produced - PLAYBOOKS == set()


def test_priority_table_is_covered_by_playbooks_plus_unknown():
    assert set(PRIORITY) - PLAYBOOKS - {"unknown"} == set()


def test_ten_playbooks_exist_on_disk_matching_r5s_premise():
    # If this fails, kb/playbooks/ changed shape and the two tests above are
    # trivially vacuous (an empty PLAYBOOKS set would pass both for free).
    # P9-T02 (DEC-149) adds an eleventh, `brute_force`; S1 a twelfth, `credential_access`;
    # the ten are named, not only counted.
    assert len(PLAYBOOKS) == 12
    assert PLAYBOOKS - {"brute_force", "credential_access"} == {
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
    }


# --------------------------------------------------------------------------
# resolved_by is exactly the DB's ck_alerts_resolved_by set
# --------------------------------------------------------------------------


def test_resolved_by_values_match_the_db_check_constraint():
    text = SCHEMA_SQL.read_text(encoding="utf-8")
    match = re.search(r"ck_alerts_resolved_by\s+CHECK \(resolved_by IN \(([^)]+)\)\)", text)
    assert match, "ck_alerts_resolved_by constraint not found in schema.sql"
    values = {v.strip().strip("'") for v in match.group(1).split(",")}
    assert values == RESOLVED_BY_SET


@pytest.mark.parametrize(
    "mitre_ids,groups,decoder,dst_port",
    [
        (["T1110"], [], None, 0),
        (["T1071.999"], [], None, 0),
        ([], ["sudo"], None, 0),
        ([], [], "nginx", 0),
        ([], [], None, 443),
        ([], [], None, 0),
    ],
)
def test_resolved_by_is_always_one_of_the_six_db_values(mitre_ids, groups, decoder, dst_port):
    assert resolve(mitre_ids, groups, decoder, dst_port).resolved_by in RESOLVED_BY_SET


# --------------------------------------------------------------------------
# MAPPING_VERSION is pinned to a hash of the four tables
# --------------------------------------------------------------------------


def test_mapping_version_is_pinned_to_a_hash_of_the_four_tables():
    canonical = json.dumps(
        {
            "technique": TECHNIQUE_TO_CATEGORY,
            "group": GROUP_TO_CATEGORY,
            "decoder": DECODER_TO_CATEGORY,
            "port": {str(k): v for k, v in PORT_TO_CATEGORY.items()},
        },
        sort_keys=True,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    # If this assertion fails, you edited a mapping table: bump MAPPING_VERSION
    # in category.py in the same commit, then update this literal to match.
    # v3.4 (S1): the shared technique table gained T1018/T1016/T1482 -> recon and
    # T1003/T1003.001 -> credential_access. Its v3.2/v3.3 digest, kept through P9-T02 (DEC-149) so
    # that no alert outside the Windows tiers could change category, was
    # 33ed2ec1be828c578f009b33b5e8ec27a746f7353238fa6b46551761bd720f2d. The other three
    # shared tables are untouched.
    assert digest == "fb54929f189a30ff407a6d13a3d22bf0989ad062cb6f17940e18801c0fc10702"
    # P9-T02 (DEC-149): the two Windows tables, with the decoder that guards them, are hashed as
    # well; they moved v3.2 -> v3.3 (the group table joined before v3.3 was ever merged), and
    # v3.3 -> v3.4 with T1003/T1003.001 -> credential_access (S1).
    from app.ingest.category import (
        WINDOWS_DECODER,
        WINDOWS_GROUP_TO_CATEGORY,
        WINDOWS_TECHNIQUE_TO_CATEGORY,
    )

    windows = json.dumps(
        {
            "decoder": WINDOWS_DECODER,
            "technique": WINDOWS_TECHNIQUE_TO_CATEGORY,
            "group": WINDOWS_GROUP_TO_CATEGORY,
        },
        sort_keys=True,
    )
    windows_digest = hashlib.sha256(windows.encode("utf-8")).hexdigest()
    assert windows_digest == "c24dc7197618f6a972942ed8f182323ed9f3ba555136961f5784be4e6c392141"
    assert MAPPING_VERSION == "v3.4"


# --------------------------------------------------------------------------
# case/whitespace insensitivity, and multi-match-then-sort within a tier
# --------------------------------------------------------------------------


def test_group_matching_is_case_and_whitespace_insensitive():
    r = resolve([], ["  AUTHENTICATION_FAILED  "], None, 0)
    assert r.category == "ssh_brute_force"
    assert r.resolved_by == "rule_groups"


def test_decoder_matching_is_case_and_whitespace_insensitive():
    r = resolve([], [], "  SSHD  ", 0)
    assert r.category == "ssh_brute_force"
    assert r.resolved_by == "decoder"


def test_multiple_group_matches_are_collected_and_sorted_by_priority():
    # "virus" -> malware, "sudo" -> privilege_escalation; malware outranks it.
    r = resolve([], ["sudo", "virus"], None, 0)
    assert r.category == "malware"
    assert r.categories == ("malware", "privilege_escalation")
    assert r.resolved_by == "rule_groups"


# --------------------------------------------------------------------------
# DEC-055 — `attack` was over-broad; `sqlinjection` and `web-accesslog` replace it
# --------------------------------------------------------------------------


def test_rule_100112_audit_log_cleared_is_not_a_web_attack():
    # Local rule 100112 "audit log cleared" (T1070.002/.003, defense evasion)
    # carries these four groups and nothing else. Before DEC-055 it reached
    # `web_attack` at tier 3 through GROUP_TO_CATEGORY["attack"] -- 8 of 8 live
    # `web_attack` clusters on the archive were this rule, on a host that runs
    # no web server. With `attack` gone it has no signal left and falls through.
    r = resolve([], ["local", "audit", "attack", "defense_evasion"], None, 0)
    assert r.category == "unknown"
    assert r.resolved_by == "none"
    assert r.categories == ()


def test_rule_31170_sql_injection_still_resolves_to_web_attack():
    # Stock rule 31170 "SQL injection attempt". The ported table spelled this
    # `sql_injection`; the stock ruleset writes `sqlinjection`, so removing
    # `attack` without adding that spelling would drop this rule to `unknown`.
    r = resolve([], ["attack", "sqlinjection", "pci_dss_6.5"], None, 0)
    assert r.category == "web_attack"
    assert r.resolved_by == "rule_groups"


def test_web_accesslog_decoder_reaches_web_attack_at_tier_4():
    # `0245-web_rules.xml` is decoded by `web-accesslog`; the substring table
    # reached `apache-errorlog` but nothing named `web-accesslog`, so the web
    # access log had no tier-4 route at all.
    r = resolve([], [], "web-accesslog", 0)
    assert r.category == "web_attack"
    assert r.resolved_by == "decoder"


# --------------------------------------------------------------------------
# docs/lab-scenarios.md §3 `ssh_brute_force` — "Expected rules" table, ported
# 1:1: each stock rule id's real mitre/group signature (read from the manager's
# own ruleset, not guessed) is pinned here so a ruleset upgrade that drops a
# `<mitre>` block or renames a group fails this suite before it fails a lab run.
# --------------------------------------------------------------------------


def test_rule_5710_non_existent_user_login_resolves_to_ssh_brute_force():
    # 0095-sshd_rules.xml: "sshd: Attempt to login using a non-existent user".
    # mitre T1110.001 + T1021.004 (T1021.004 has no table entry, ignored).
    r = resolve(
        ["T1110.001", "T1021.004"],
        [
            "authentication_failed",
            "invalid_login",
            "gdpr_IV_35.7.d",
            "gdpr_IV_32.2",
            "gpg13_7.1",
            "hipaa_164.312.b",
            "nist_800_53_AU.14",
            "nist_800_53_AC.7",
            "pci_dss_10.2.4",
            "pci_dss_10.2.5",
            "pci_dss_10.6.1",
            "tsc_CC6.1",
            "tsc_CC6.8",
            "tsc_CC7.2",
            "tsc_CC7.3",
        ],
        "sshd",
        0,
    )
    assert r.category == "ssh_brute_force"
    assert r.resolved_by == "mitre"


def test_rule_5760_sshd_authentication_failed_resolves_to_ssh_brute_force():
    # 0095-sshd_rules.xml: "sshd: authentication failed." (Failed password/keyboard).
    r = resolve(
        ["T1110.001", "T1021.004"],
        [
            "authentication_failed",
            "gdpr_IV_35.7.d",
            "gdpr_IV_32.2",
            "gpg13_7.1",
            "hipaa_164.312.b",
            "nist_800_53_AU.14",
            "nist_800_53_AC.7",
            "pci_dss_10.2.4",
            "pci_dss_10.2.5",
            "tsc_CC6.1",
            "tsc_CC6.8",
            "tsc_CC7.2",
            "tsc_CC7.3",
        ],
        "sshd",
        0,
    )
    assert r.category == "ssh_brute_force"
    assert r.resolved_by == "mitre"


def test_rule_5503_pam_user_login_failed_resolves_to_ssh_brute_force():
    # 0085-pam_rules.xml: "PAM: User login failed." — decoder is `pam`, not `sshd`,
    # so this one only resolves at all because tier 1 (mitre) fires first.
    r = resolve(
        ["T1110.001"],
        [
            "authentication_failed",
            "pci_dss_10.2.4",
            "pci_dss_10.2.5",
            "gpg13_7.8",
            "gdpr_IV_35.7.d",
            "gdpr_IV_32.2",
            "hipaa_164.312.b",
            "nist_800_53_AU.14",
            "nist_800_53_AC.7",
            "tsc_CC6.1",
            "tsc_CC6.8",
            "tsc_CC7.2",
            "tsc_CC7.3",
        ],
        "pam",
        0,
    )
    assert r.category == "ssh_brute_force"
    assert r.resolved_by == "mitre"


def test_rule_2501_syslog_authentication_failure_has_no_mitre_block_resolves_via_rule_groups():
    # 0020-syslog_rules.xml: "syslog: User authentication failure." carries no
    # <mitre> block at all (verified against the live ruleset) — tier 1/2 must
    # both come back empty and tier 3 (rule.groups) must be what actually resolves it.
    r = resolve(
        [],
        [
            "authentication_failed",
            "pci_dss_10.2.4",
            "pci_dss_10.2.5",
            "gpg13_7.8",
            "gdpr_IV_35.7.d",
            "gdpr_IV_32.2",
            "hipaa_164.312.b",
            "nist_800_53_AU.14",
            "nist_800_53_AC.7",
            "tsc_CC6.1",
            "tsc_CC6.8",
            "tsc_CC7.2",
            "tsc_CC7.3",
        ],
        None,
        0,
    )
    assert r.category == "ssh_brute_force"
    assert r.resolved_by == "rule_groups"


def test_rule_5712_sshd_brute_force_non_existent_user_resolves_to_ssh_brute_force():
    # 0095-sshd_rules.xml: "sshd: brute force trying to get access to the
    # system. Non existent user." — the frequency correlation rule itself.
    r = resolve(
        ["T1110"],
        [
            "authentication_failures",
            "gdpr_IV_35.7.d",
            "gdpr_IV_32.2",
            "hipaa_164.312.b",
            "nist_800_53_SI.4",
            "nist_800_53_AU.14",
            "nist_800_53_AC.7",
            "pci_dss_11.4",
            "pci_dss_10.2.4",
            "pci_dss_10.2.5",
            "tsc_CC6.1",
            "tsc_CC6.8",
            "tsc_CC7.2",
            "tsc_CC7.3",
        ],
        "sshd",
        0,
    )
    assert r.category == "ssh_brute_force"
    assert r.resolved_by == "mitre"


def test_rule_40112_multiple_failures_then_success_ssh_brute_force_outranks_suspicious_login():
    # 0280-attack_rules.xml: "Multiple authentication failures followed by a
    # success." carries both T1078 (suspicious_login) and T1110 (ssh_brute_force);
    # the runbook is explicit this resolves ssh_brute_force, not suspicious_login,
    # because T1110 outranks T1078 in PRIORITY — same rule as the canonical alert
    # above, pinned here under its own rule id so a PRIORITY reorder is caught
    # against the exact scenario the lab runbook names.
    r = resolve(
        ["T1078", "T1110"],
        [
            "pci_dss_10.2.4",
            "pci_dss_10.2.5",
            "pci_dss_11.4",
            "gpg13_7.1",
            "gpg13_7.8",
            "gdpr_IV_35.7.d",
            "gdpr_IV_32.2",
            "hipaa_164.312.b",
            "nist_800_53_AU.14",
            "nist_800_53_AC.7",
            "nist_800_53_SI.4",
            "tsc_CC6.1",
            "tsc_CC6.8",
            "tsc_CC7.2",
            "tsc_CC7.3",
        ],
        "sshd",
        0,
    )
    assert r.category == "ssh_brute_force"
    assert r.categories == ("ssh_brute_force", "suspicious_login")
    assert r.resolved_by == "mitre"


# --------------------------------------------------------------------------
# S1 (v3.4) — discovery techniques reach `recon`; LSASS credential theft gets its own
# category, `credential_access`, ranked right after `privilege_escalation`
# --------------------------------------------------------------------------

WIN = "windows_eventchannel"


@pytest.mark.parametrize("technique_id", ["T1018", "T1016", "T1482"])
@pytest.mark.parametrize("decoder", [None, "sshd", "pam", WIN])
def test_s1_discovery_techniques_resolve_to_recon_on_every_decoder(technique_id, decoder):
    """Rule 111438 (DC / domain probing) carries these; they sit in the SHARED table only,
    so a `windows_eventchannel` alert (no Windows-table key) reaches them by the fall-through
    from W1-W3 to tier 1."""
    r = resolve([technique_id], [], decoder, 0)
    assert (r.category, r.categories, r.resolved_by) == ("recon", ("recon",), "mitre")


@pytest.mark.parametrize("technique_id", ["T1018", "T1016", "T1482"])
def test_s1_recon_additions_are_in_the_shared_table_only(technique_id):
    assert TECHNIQUE_TO_CATEGORY[technique_id] == "recon"
    assert technique_id not in WINDOWS_TECHNIQUE_TO_CATEGORY


def test_s1_windows_t1018_falls_through_w1_w3_to_the_shared_tier():
    # Windows alert, no W1/W2 key and a W3-silent group set: tier 1 answers.
    r = resolve(["T1018"], ["windows", "windows_security"], WIN, 0)
    assert (r.category, r.resolved_by) == ("recon", "mitre")


def test_s1_non_windows_t1018_resolves_to_recon():
    r = resolve(["T1018"], ["syslog"], "sshd", 0)
    assert (r.category, r.categories, r.resolved_by) == ("recon", ("recon",), "mitre")


def test_s1_rule_111438_shape_all_three_techniques_resolve_to_recon():
    r = resolve(["T1018", "T1016", "T1482"], ["windows", "sysmon"], WIN, 0)
    assert (r.category, r.categories, r.resolved_by) == ("recon", ("recon",), "mitre")


@pytest.mark.parametrize("technique_id", ["T1003", "T1003.001"])
def test_s1_t1003_is_in_both_technique_tables_like_t1110(technique_id):
    assert TECHNIQUE_TO_CATEGORY[technique_id] == "credential_access"
    assert WINDOWS_TECHNIQUE_TO_CATEGORY[technique_id] == "credential_access"


def test_s1_rule_111923_lsass_dump_resolves_to_credential_access_by_mitre():
    """Rule 111923 shape: a `windows_eventchannel` alert carrying T1003 + T1003.001."""
    r = resolve(["T1003", "T1003.001"], ["windows", "sysmon"], WIN, 0)
    assert (r.category, r.categories, r.resolved_by) == (
        "credential_access",
        ("credential_access",),
        "mitre",
    )


@pytest.mark.parametrize("technique_id", ["T1003", "T1003.001"])
def test_s1_each_t1003_id_alone_resolves_on_windows(technique_id):
    r = resolve([technique_id], [], WIN, 0)
    assert (r.category, r.resolved_by) == ("credential_access", "mitre")


def test_s1_a_t1003_sub_technique_reaches_its_parent_on_windows():
    r = resolve(["T1003.002"], [], WIN, 0)
    assert (r.category, r.resolved_by) == ("credential_access", "mitre_parent")


def test_s1_t1003_resolves_on_a_non_windows_decoder_through_the_shared_table():
    r = resolve(["T1003.001"], [], "auditd", 0)
    assert (r.category, r.resolved_by) == ("credential_access", "mitre")


def test_s1_credential_access_is_ranked_right_after_privilege_escalation():
    assert PRIORITY.index("credential_access") == PRIORITY.index("privilege_escalation") + 1
    assert PRIORITY.index("credential_access") < PRIORITY.index("ssh_brute_force")
    assert PRIORITY.index("credential_access") < PRIORITY.index("suspicious_login")
    assert PRIORITY.index("credential_access") < PRIORITY.index("recon")


@pytest.mark.parametrize(
    "mitre_ids,expected",
    [
        (["T1003", "T1548"], ("privilege_escalation", "credential_access")),
        (["T1548", "T1003"], ("privilege_escalation", "credential_access")),
        (["T1078", "T1003"], ("credential_access", "suspicious_login")),
        (["T1018", "T1003"], ("credential_access", "recon")),
        (["T1003", "T1486"], ("ransomware", "credential_access")),
    ],
)
def test_s1_priority_sorts_credential_access_among_its_neighbours(mitre_ids, expected):
    r = resolve(mitre_ids, [], None, 0)
    assert r.categories == expected
    assert r.category == expected[0]


def test_s1_credential_access_has_a_playbook_and_a_decision_table():
    """R5 for the new value: the playbook exists, and the table loads (title line, rule shape,
    `playbook` name) and is self-consistent."""
    assert "credential_access" in PLAYBOOKS
    assert lookup.get_playbook("credential_access") is not None
    table = lookup.get_decision_table("credential_access")
    assert table is not None
    assert table.category == "credential_access"
    assert table.playbook == "credential_access_v1"
    assert table.rules
    assert lookup.check_consistency(table) == []


def test_s1_prompt_builder_closed_set_knows_credential_access():
    from app.llm import builder

    assert builder.Category("credential_access") is builder.Category.CREDENTIAL_ACCESS


# --------------------------------------------------------------------------
# acceptance 6, mirrored here so a code change fails pytest too
# --------------------------------------------------------------------------


def test_old_final_project_names_do_not_survive_the_port():
    text = CATEGORY_PY.read_text(encoding="utf-8")
    forbidden = re.compile(
        r"rdp_brute_force|phishing|suspicious_execution|malware_detection"
        r"|command_and_control|port_scan|web_attack_(sqli|xss|webshell)"
    )
    assert forbidden.search(text) is None
