"""P0-T05 — `enrichment.inventory.validate()` and its three checkers.

The three shipped `conf/*.example` files are the contract with the Owner: they
must validate clean. Every other test builds one temporary file (or one parsed
document) for one rule and asserts on the *content* of the message, because a
message that does not name the file and the offending key is useless to the
person holding the editor.
"""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from app.enrichment.inventory import (
    validate,
    validate_assets,
    validate_identities,
    validate_iocs,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = (
    "conf/inventory.yaml.example",
    "conf/identities.yaml.example",
    "conf/iocs.csv.example",
)


def _write(tmp_path: Path, name: str, text: str) -> str:
    path = tmp_path / name
    path.write_text(dedent(text).lstrip("\n"), encoding="utf-8")
    return str(path)


def _only(problems: list[str]) -> str:
    assert len(problems) == 1, problems
    return problems[0]


# --------------------------------------------------------------------------
# the shipped examples
# --------------------------------------------------------------------------


def test_the_three_shipped_examples_validate_clean() -> None:
    assert validate([str(REPO_ROOT / name) for name in EXAMPLES]) == []


def test_the_examples_carry_the_lab_host_and_the_lab_user() -> None:
    inventory = (REPO_ROOT / "conf/inventory.yaml.example").read_text(encoding="utf-8")
    identities = (REPO_ROOT / "conf/identities.yaml.example").read_text(encoding="utf-8")
    assert "user1-IA1803" in inventory
    assert "username: user1" in identities


# --------------------------------------------------------------------------
# assets
# --------------------------------------------------------------------------


def test_bad_criticality_names_the_file_the_index_and_the_allowed_set() -> None:
    doc = {"version": 1, "assets": [{"hostname": "h1", "criticality": "urgent"}]}
    problem = _only(validate_assets(doc, "conf/inventory.yaml"))
    assert "conf/inventory.yaml" in problem
    assert "assets[0]" in problem
    assert "criticality" in problem
    assert "urgent" in problem
    for allowed in ("high", "medium", "low", "unknown"):
        assert allowed in problem


def test_retired_criticality_values_are_rejected_naming_dec_004() -> None:
    doc = {
        "version": 1,
        "assets": [
            {"hostname": "h", "criticality": "crown_jewel"},
            {"hostname": "i", "criticality": "normal"},
        ],
    }
    problems = validate_assets(doc, "x")
    assert len(problems) == 2, problems
    assert "crown_jewel" in problems[0] and "DEC-004" in problems[0]
    assert "normal" in problems[1] and "DEC-004" in problems[1]


def test_duplicate_hostname_is_reported_with_both_positions() -> None:
    doc = {
        "version": 1,
        "assets": [
            {"hostname": "user1-IA1803", "criticality": "medium"},
            {"hostname": "user1-IA1803", "criticality": "low"},
        ],
    }
    problem = _only(validate_assets(doc, "conf/inventory.yaml"))
    assert "duplicate" in problem.lower()
    assert "user1-IA1803" in problem
    assert "assets[1]" in problem
    assert "assets[0]" in problem


def test_owner_over_200_characters_is_reported() -> None:
    doc = {"version": 1, "assets": [{"hostname": "h", "criticality": "low", "owner": "x" * 201}]}
    problem = _only(validate_assets(doc, "conf/inventory.yaml"))
    assert "owner" in problem
    assert "200" in problem
    assert "201" in problem


def test_unknown_key_in_an_asset_is_reported_as_a_typo_candidate() -> None:
    doc = {
        "version": 1,
        "assets": [{"hostname": "h", "criticality": "low", "critcality": "high"}],
    }
    problem = _only(validate_assets(doc, "conf/inventory.yaml"))
    assert "unknown key" in problem
    assert "critcality" in problem
    assert "criticality" in problem  # the allowed set is spelled out


def test_missing_hostname_names_the_index() -> None:
    doc = {"version": 1, "assets": [{"criticality": "low"}]}
    problem = _only(validate_assets(doc, "conf/inventory.yaml"))
    assert "assets[0]" in problem
    assert "hostname" in problem


def test_missing_version_is_reported(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "inventory.yaml",
        """
        assets:
          - hostname: h
            criticality: low
        """,
    )
    problem = _only(validate([path]))
    assert "version" in problem
    assert "inventory.yaml" in problem


# --------------------------------------------------------------------------
# identities
# --------------------------------------------------------------------------


def test_is_privileged_as_the_string_false_is_rejected(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "identities.yaml",
        """
        version: 1
        identities:
          - username: user1
            is_privileged: "false"
        """,
    )
    problem = _only(validate([path]))
    assert "is_privileged" in problem
    assert "boolean" in problem
    assert "'false'" in problem
    assert "identities[0]" in problem


def test_duplicate_username_is_reported() -> None:
    doc = {
        "version": 1,
        "identities": [
            {"username": "user1", "is_privileged": False},
            {"username": "user1", "is_privileged": True},
        ],
    }
    problem = _only(validate_identities(doc, "conf/identities.yaml"))
    assert "duplicate" in problem.lower()
    assert "user1" in problem
    assert "identities[1]" in problem


# --------------------------------------------------------------------------
# iocs
# --------------------------------------------------------------------------


def test_bad_reputation_names_the_value_and_the_allowed_set() -> None:
    rows = [{"value": "203.0.113.10", "reputation": "bogus", "expires_at": "2030-01-01T00:00:00Z"}]
    problem = _only(validate_iocs(rows, "conf/iocs.csv"))
    assert "conf/iocs.csv" in problem
    assert "203.0.113.10" in problem
    assert "bogus" in problem
    for allowed in ("malicious", "suspicious", "clean"):
        assert allowed in problem


def test_an_expired_ioc_is_a_warning_shaped_entry(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "iocs.csv",
        """
        value,reputation,expires_at,source
        203.0.113.10,malicious,2020-01-01T00:00:00Z,manual
        """,
    )
    problem = _only(validate([path]))
    assert problem.startswith("warning:")
    assert "203.0.113.10" in problem
    assert "expires_at" in problem


def test_expires_at_without_a_timezone_is_rejected() -> None:
    rows = [{"value": "203.0.113.10", "reputation": "clean", "expires_at": "2030-01-01T00:00:00"}]
    problem = _only(validate_iocs(rows, "conf/iocs.csv"))
    assert "expires_at" in problem
    assert "timezone" in problem
    assert not problem.startswith("warning:")


def test_duplicate_ioc_value_is_reported() -> None:
    rows = [
        {"value": "203.0.113.10", "reputation": "clean", "expires_at": "2030-01-01T00:00:00Z"},
        {"value": "203.0.113.10", "reputation": "malicious", "expires_at": "2030-01-01T00:00:00Z"},
    ]
    problem = _only(validate_iocs(rows, "conf/iocs.csv"))
    assert "duplicate" in problem.lower()
    assert "iocs[1]" in problem


def test_a_comment_line_in_the_csv_is_not_a_row(tmp_path: Path) -> None:
    # DEC-007: were the '#' line parsed, its bogus reputation would be reported.
    path = _write(
        tmp_path,
        "iocs.csv",
        """
        # notes about this file

        value,reputation,expires_at,source
        # 198.51.100.9,bogus,2030-01-01T00:00:00Z,manual
        203.0.113.10,malicious,2030-01-01T00:00:00Z,manual
        """,
    )
    assert validate([path]) == []


def test_a_hash_inside_a_quoted_field_is_not_a_comment(tmp_path: Path) -> None:
    # The row must still be read, and the '#' must survive inside the field.
    path = _write(
        tmp_path,
        "iocs.csv",
        """
        value,reputation,expires_at,source
        "198.51.100.7#1",bogus,2030-01-01T00:00:00Z,"manual # trusted feed"
        """,
    )
    problem = _only(validate([path]))
    assert "198.51.100.7#1" in problem
    assert "bogus" in problem


# --------------------------------------------------------------------------
# files, routing and INVENTORY_PATHS
# --------------------------------------------------------------------------


def test_a_missing_file_is_one_message_naming_the_path(tmp_path: Path) -> None:
    problem = _only(validate([str(tmp_path / "nope.yaml")]))
    assert "nope.yaml" in problem
    assert "not found" in problem.lower()


def test_unparseable_yaml_is_one_message_not_a_traceback(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "inventory.yaml",
        """
        version: 1
        assets:
          - hostname: h
           criticality: low
        """,
    )
    problem = _only(validate([path]))
    assert "inventory.yaml" in problem
    assert "parse" in problem.lower()
    assert "\n" not in problem
    assert "Traceback" not in problem


def test_routing_is_by_content_not_by_basename(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "people.txt",
        """
        version: 1
        identities:
          - username: user1
            is_privileged: false
        """,
    )
    assert validate([path]) == []


def test_a_file_matching_none_of_the_three_shapes_names_the_keys(tmp_path: Path) -> None:
    path = _write(tmp_path, "thing.yaml", "version: 1\nassetz: []\n")
    problem = _only(validate([path]))
    assert "thing.yaml" in problem
    assert "assets" in problem
    assert "identities" in problem


def test_inventory_paths_that_is_not_json_is_a_configuration_error(monkeypatch) -> None:
    monkeypatch.setenv("INVENTORY_PATHS", "conf/inventory.yaml")
    problem = _only(validate())
    assert "INVENTORY_PATHS" in problem
    assert "JSON" in problem


def test_inventory_paths_that_is_not_a_list_of_strings_is_a_configuration_error(
    monkeypatch,
) -> None:
    monkeypatch.setenv("INVENTORY_PATHS", '["conf/inventory.yaml", 3]')
    problem = _only(validate())
    assert "INVENTORY_PATHS" in problem
    assert "string" in problem


def test_an_empty_inventory_paths_array_is_a_configuration_error(monkeypatch) -> None:
    monkeypatch.setenv("INVENTORY_PATHS", "[]")
    problem = _only(validate())
    assert "INVENTORY_PATHS" in problem


def test_unset_inventory_paths_falls_back_to_the_three_conf_defaults(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("INVENTORY_PATHS", raising=False)
    monkeypatch.chdir(tmp_path)
    problems = validate()
    assert len(problems) == 3, problems
    assert all("not found" in p.lower() for p in problems)
    for default in ("conf/inventory.yaml", "conf/identities.yaml", "conf/iocs.csv"):
        assert any(default in p for p in problems)
