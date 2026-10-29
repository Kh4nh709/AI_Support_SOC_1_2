"""P13-T02 / DEC-210, spec §7.4 — `rag.tags`: the closed tag vocabulary and the rule-group mapping.

`backend/app/rag/tags.yaml` is code: tracked in git, reviewed by the Owner. A draft's `tags` are a
subset of it (V1), and the fingerprint's `tags` are derived from the rule groups through the map
in the same file. Only a group that means one thing is mapped; the rest are ignored on purpose.

The expected tags for the two samples are written out, not computed by the code under test.
Pure: no database.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from app.llm.builder import Category
from app.rag import tags as tags_module
from app.rag.tags import load_tags, tags_from_rule_groups

from tests.soar_payloads import mw03, sc03

TAGS_YAML = Path(tags_module.__file__).with_name("tags.yaml")


def test_the_vocabulary_is_short_and_made_of_snake_case_words() -> None:
    vocabulary = load_tags()
    assert isinstance(vocabulary, frozenset)
    assert 15 <= len(vocabulary) <= 25
    for tag in vocabulary:
        assert re.fullmatch(r"[a-z][a-z0-9_]{1,39}", tag), tag


def test_the_vocabulary_names_what_the_samples_need() -> None:
    vocabulary = load_tags()
    assert {"port_scan", "reconnaissance", "firewall", "windows_host", "malware_detection"} <= (
        vocabulary
    )
    assert {"external_source", "blocked", "remediated", "test_activity"} <= vocabulary


#: The behaviour tag of each category the resolver (`ingest/category.py`, `llm.builder.Category`) can give an
#: alert. A category is a code; a tag is what an admin reads and a draft is found by, so the map is explicit:
#: two categories may share a tag (`ssh_brute_force` and `brute_force`), none may lack one.
CATEGORY_TAG = {
    "ransomware": "ransomware",
    "malware": "malware_detection",
    "c2_beacon": "c2_beaconing",
    "data_exfiltration": "data_exfiltration",
    "privilege_escalation": "privilege_escalation",
    "credential_access": "credential_access",
    "ssh_brute_force": "brute_force",
    "brute_force": "brute_force",
    "web_attack": "web_attack",
    "suspicious_login": "successful_login",
    "recon": "reconnaissance",
    "policy_violation": "policy_violation",
}


def test_every_category_of_the_resolver_has_a_behaviour_tag() -> None:
    """INT-T01 F2: the list used to be a literal, so S1's `credential_access` went by unseen. It is derived
    from `llm.builder.Category` now: a category added there without a line in `CATEGORY_TAG` fails the first
    assert, and a line without its tag in `tags.yaml` fails the second."""
    categories = {category.value for category in Category} - {"unknown"}
    assert categories == set(
        CATEGORY_TAG
    ), "a new category needs a tag in tags.yaml and a line here"
    assert set(CATEGORY_TAG.values()) <= load_tags()


def test_the_file_is_what_load_tags_reads_and_every_tag_has_a_description() -> None:
    document = yaml.safe_load(TAGS_YAML.read_text(encoding="utf-8"))
    assert set(document) == {"tags", "rule_groups"}
    assert set(document["tags"]) == set(load_tags())
    for tag, description in document["tags"].items():
        assert isinstance(description, str) and description.strip(), tag


def test_every_mapped_tag_is_in_the_vocabulary() -> None:
    document = yaml.safe_load(TAGS_YAML.read_text(encoding="utf-8"))
    assert document["rule_groups"], "the map is empty"
    assert set(document["rule_groups"].values()) <= set(load_tags())
    for group in document["rule_groups"]:
        assert group == group.lower() and group == group.strip()


def test_load_tags_is_stable() -> None:
    assert load_tags() == load_tags()


def test_the_port_scan_sample_groups_give_firewall_and_reconnaissance() -> None:
    groups = sc03()["rule"]["groups"]
    assert groups == ["pfsense", "firewall", "recon", "custom"]
    assert tags_from_rule_groups(groups) == ("firewall", "reconnaissance")


def test_the_defender_sample_groups_give_windows_and_malware() -> None:
    groups = mw03()["rule"]["groups"]
    assert groups == ["windows", "windows_defender", "virus"]
    assert tags_from_rule_groups(groups) == ("malware_detection", "windows_host")


def test_a_group_that_means_many_things_is_not_mapped() -> None:
    assert tags_from_rule_groups(["syslog", "custom", "sshd", "windows_defender", "local"]) == ()


def test_the_result_is_sorted_and_without_duplicates() -> None:
    out = tags_from_rule_groups(["virus", "malware", "clamd", "pfsense", "firewall", "virus"])
    assert out == ("firewall", "malware_detection")


def test_the_order_of_the_groups_does_not_matter() -> None:
    groups = ["recon", "pfsense", "firewall", "windows", "virus"]
    assert tags_from_rule_groups(groups) == tags_from_rule_groups(list(reversed(groups)))


def test_a_group_is_matched_without_regard_to_case_or_padding() -> None:
    assert tags_from_rule_groups([" PfSense ", "RECON"]) == ("firewall", "reconnaissance")


def test_a_value_that_is_not_a_string_is_ignored() -> None:
    assert tags_from_rule_groups(["recon", None, 5, b"virus", ["virus"]]) == (  # type: ignore[list-item]
        "reconnaissance",
    )


def test_no_groups_no_tags() -> None:
    assert tags_from_rule_groups([]) == ()
    assert tags_from_rule_groups(()) == ()


def test_a_tuple_of_groups_is_accepted() -> None:
    assert tags_from_rule_groups(("recon",)) == ("reconnaissance",)


@pytest.mark.parametrize(
    "broken",
    [
        {"tags": {"Bad Tag": "x"}, "rule_groups": {}},
        {"tags": {"ok_tag": ""}, "rule_groups": {}},
        {"tags": {"ok_tag": "x"}, "rule_groups": {"g": "not_in_vocabulary"}},
        {"tags": ["a_list_not_a_map"], "rule_groups": {}},
        {"tags": {"ok_tag": "x"}},
        {"tags": {}, "rule_groups": {}},
    ],
)
def test_a_malformed_file_is_refused_not_half_read(broken: dict, tmp_path: Path) -> None:
    path = tmp_path / "tags.yaml"
    path.write_text(yaml.safe_dump(broken), encoding="utf-8")
    with pytest.raises(ValueError):
        tags_module.read_tags_file(path)
