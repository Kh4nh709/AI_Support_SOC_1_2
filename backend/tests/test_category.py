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
    Resolution,
    resolve,
)

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
    assert len(PLAYBOOKS) == 10


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
    assert digest == "e6bb6833fd382b2793935900cdf0dbe5d9bb0e07ab8126cf4543ca1caa78f128"
    assert MAPPING_VERSION == "v3.1"


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
# acceptance 6, mirrored here so a code change fails pytest too
# --------------------------------------------------------------------------


def test_old_final_project_names_do_not_survive_the_port():
    text = CATEGORY_PY.read_text(encoding="utf-8")
    forbidden = re.compile(
        r"rdp_brute_force|phishing|suspicious_execution|malware_detection"
        r"|command_and_control|port_scan|web_attack_(sqli|xss|webshell)"
    )
    assert forbidden.search(text) is None
