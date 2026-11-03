"""`kb.lookup` — playbook lookup, the decision-table format, and the pure evaluators
`apply_table` / `rule_holds` / `check_consistency` (P3-T06).

The ten real skeletons under `kb/decision_tables/` are exercised directly (their content
is the Owner's + advisor's, context pack §11 — this file only proves the format, the
loader and the shipped skeletons); the loader-rejection tests build throwaway tables
under `tmp_path` so a crafted defect never touches the real files.
"""

from __future__ import annotations

import math
from pathlib import Path

import pytest
from app.ingest.category import PRIORITY
from app.kb import lookup

CATEGORIES = tuple(c for c in PRIORITY if c != "unknown")


# ---------------------------------------------------------------------------
# tmp_path fixture helpers — a throwaway kb/ root with one playbook + one table
# ---------------------------------------------------------------------------


def _write_playbook(root: Path, category: str, playbook_name: str | None = None) -> None:
    name = playbook_name if playbook_name is not None else f"{category}_v1"
    directory = root / "playbooks"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{category}.md").write_text(
        f"# Playbook · `{category}` · `{name}`\n\nBody.\n", encoding="utf-8"
    )


def _write_table(root: Path, filename: str, yaml_text: str) -> None:
    directory = root / "decision_tables"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / filename).write_text(yaml_text, encoding="utf-8")


def _table(rules, *, reviewed=False) -> lookup.DecisionTable:
    return lookup.DecisionTable(
        category="widget",
        playbook="widget_v1",
        reviewed_by="Owner + advisor" if reviewed else None,
        reviewed_at="2026-09-17" if reviewed else None,
        rules=tuple(rules),
    )


# ---------------------------------------------------------------------------
# KB_ROOT and the two-way category <-> playbook <-> table check
# ---------------------------------------------------------------------------


def test_kb_root_is_the_repo_root_kb():
    expected = Path(__file__).resolve().parents[2] / "kb"
    assert lookup.KB_ROOT == expected
    assert (lookup.KB_ROOT / "playbooks").is_dir()


def test_every_category_has_one_playbook_and_one_table():
    playbook_stems = {p.stem for p in (lookup.KB_ROOT / "playbooks").glob("*.md")}
    table_stems = {p.stem for p in (lookup.KB_ROOT / "decision_tables").glob("*.yaml")}
    assert set(CATEGORIES) == playbook_stems, "a table without a playbook or vice versa"
    assert set(CATEGORIES) == table_stems, "a table without a playbook or vice versa"


# ---------------------------------------------------------------------------
# get_playbook / get_decision_table
# ---------------------------------------------------------------------------


def test_get_playbook_unknown_is_none():
    assert lookup.get_playbook("unknown") is None


def test_get_decision_table_unknown_is_none():
    assert lookup.get_decision_table("unknown") is None


def test_get_playbook_missing_file_is_none(tmp_path):
    assert lookup.get_playbook("nonexistent", root=tmp_path) is None


def test_get_decision_table_missing_file_is_none(tmp_path):
    assert lookup.get_decision_table("nonexistent", root=tmp_path) is None


def test_get_playbook_returns_the_file_text(tmp_path):
    _write_playbook(tmp_path, "widget")
    text = lookup.get_playbook("widget", root=tmp_path)
    assert text is not None
    assert "widget_v1" in text


# ---------------------------------------------------------------------------
# loader rejections (design note 2) — every one names the file, the rule id, the key
# ---------------------------------------------------------------------------


def test_loader_rejects_unknown_key(tmp_path):
    _write_playbook(tmp_path, "widget")
    _write_table(
        tmp_path,
        "widget.yaml",
        """
category: widget
playbook: widget_v1
reviewed_by: null
reviewed_at: null
rules:
  - id: wg-1
    if: {hostname: [foo]}
    then: escalate
""",
    )
    with pytest.raises(lookup.DecisionTableError):
        lookup.get_decision_table("widget", root=tmp_path)


def test_loader_rejects_value_outside_vocabulary(tmp_path):
    _write_playbook(tmp_path, "widget")
    # crown_jewel is the DEC-004-superseded asset_criticality value — a realistic defect.
    _write_table(
        tmp_path,
        "widget.yaml",
        """
category: widget
playbook: widget_v1
reviewed_by: null
reviewed_at: null
rules:
  - id: wg-1
    if: {asset_criticality: [crown_jewel]}
    then: escalate
""",
    )
    with pytest.raises(lookup.DecisionTableError):
        lookup.get_decision_table("widget", root=tmp_path)


def test_loader_rejects_unquoted_boolean(tmp_path):
    _write_playbook(tmp_path, "widget")
    _write_table(
        tmp_path,
        "widget.yaml",
        """
category: widget
playbook: widget_v1
reviewed_by: null
reviewed_at: null
rules:
  - id: wg-1
    if: {identity_privileged: [false]}
    then: escalate
""",
    )
    with pytest.raises(lookup.DecisionTableError, match="quote"):
        lookup.get_decision_table("widget", root=tmp_path)


def test_loader_rejects_duplicate_rule_id(tmp_path):
    _write_playbook(tmp_path, "widget")
    _write_table(
        tmp_path,
        "widget.yaml",
        """
category: widget
playbook: widget_v1
reviewed_by: null
reviewed_at: null
rules:
  - id: wg-1
    if: {rule_level_gte: 5}
    then: escalate
  - id: wg-1
    if: {rule_level_gte: 12}
    then: escalate
""",
    )
    with pytest.raises(lookup.DecisionTableError):
        lookup.get_decision_table("widget", root=tmp_path)


def test_loader_rejects_category_filename_mismatch(tmp_path):
    _write_playbook(tmp_path, "widget")
    _write_table(
        tmp_path,
        "widget.yaml",
        """
category: gadget
playbook: widget_v1
reviewed_by: null
reviewed_at: null
rules: []
""",
    )
    with pytest.raises(lookup.DecisionTableError):
        lookup.get_decision_table("widget", root=tmp_path)


def test_loader_rejects_bad_rule_id_shape(tmp_path):
    _write_playbook(tmp_path, "widget")
    _write_table(
        tmp_path,
        "widget.yaml",
        """
category: widget
playbook: widget_v1
reviewed_by: null
reviewed_at: null
rules:
  - id: widgetlong-1
    if: {rule_level_gte: 5}
    then: escalate
""",
    )
    with pytest.raises(lookup.DecisionTableError):
        lookup.get_decision_table("widget", root=tmp_path)


def test_loader_rejects_playbook_name_mismatch(tmp_path):
    _write_playbook(tmp_path, "widget", playbook_name="widget_v2")
    _write_table(
        tmp_path,
        "widget.yaml",
        """
category: widget
playbook: widget_v1
reviewed_by: null
reviewed_at: null
rules: []
""",
    )
    with pytest.raises(lookup.DecisionTableError):
        lookup.get_decision_table("widget", root=tmp_path)


def test_loader_accepts_a_well_formed_table(tmp_path):
    _write_playbook(tmp_path, "widget")
    _write_table(
        tmp_path,
        "widget.yaml",
        """
category: widget
playbook: widget_v1
reviewed_by: null
reviewed_at: null
rules:
  - id: wg-1
    if: {severity: [low], identity_privileged: ["false"], occurrence_lt: 5}
    then: false_positive
""",
    )
    table = lookup.get_decision_table("widget", root=tmp_path)
    assert table.category == "widget"
    assert table.playbook == "widget_v1"
    assert table.reviewed is False
    assert [r.id for r in table.rules] == ["wg-1"]


# ---------------------------------------------------------------------------
# rule_matches / apply_table / rule_holds — pure evaluators
# ---------------------------------------------------------------------------


def test_apply_table_first_match_wins():
    table = _table(
        [
            lookup.Rule(
                id="wg-1", condition={"severity": ("low", "medium")}, action="false_positive"
            ),
            lookup.Rule(id="wg-2", condition={"rule_level_gte": 0}, action="true_positive"),
        ]
    )
    facts = {"severity": "low", "rule_level": 20}
    assert lookup.apply_table(table, facts) == ("false_positive", "wg-1")


def test_apply_table_no_match_is_none():
    table = _table(
        [lookup.Rule(id="wg-1", condition={"severity": ("critical",)}, action="true_positive")]
    )
    assert lookup.apply_table(table, {"severity": "low"}) is None


def test_apply_table_ignores_reviewed():
    table = _table(
        [lookup.Rule(id="wg-1", condition={"severity": ("low",)}, action="false_positive")],
        reviewed=False,
    )
    assert table.reviewed is False
    assert lookup.apply_table(table, {"severity": "low"}) == ("false_positive", "wg-1")


def test_rule_holds_unknown_id_is_none():
    table = _table(
        [lookup.Rule(id="wg-1", condition={"severity": ("low",)}, action="false_positive")]
    )
    assert lookup.rule_holds(table, "zz-9", {"severity": "low"}) is None


def test_missing_fact_never_matches_and_never_raises():
    table = _table(
        [
            lookup.Rule(
                id="wg-1",
                condition={"asset_criticality": ("low",), "occurrence_lt": 5},
                action="false_positive",
            )
        ]
    )
    assert lookup.apply_table(table, {}) is None
    assert lookup.rule_holds(table, "wg-1", {}) is False


def test_rule_matches_ands_every_condition_key():
    table = _table(
        [
            lookup.Rule(
                id="wg-1",
                condition={"severity": ("low",), "identity_privileged": ("false",)},
                action="false_positive",
            )
        ]
    )
    # severity holds but identity_privileged does not -> the rule must not hold
    assert lookup.apply_table(table, {"severity": "low", "identity_privileged": "true"}) is None


# ---------------------------------------------------------------------------
# the consistency grid
# ---------------------------------------------------------------------------


def test_grid_severity_follows_rule_level_band():
    assert [lookup.severity_for(rl) for rl in (0, 3, 5, 8, 12, 15)] == [
        "low",
        "low",
        "medium",
        "high",
        "critical",
        "critical",
    ]


def test_fact_grid_has_2520_points():
    assert sum(1 for _ in lookup.fact_grid()) == 2520


def test_skeletons_are_consistent():
    for category in CATEGORIES:
        table = lookup.get_decision_table(category)
        assert lookup.check_consistency(table) == [], category


def test_contradictory_table_is_named():
    table = _table(
        [
            lookup.Rule(id="x-1", condition={"severity": ("low",)}, action="false_positive"),
            lookup.Rule(id="x-2", condition={"rule_level_lt": 5}, action="true_positive"),
        ]
    )
    problems = lookup.check_consistency(table)
    joined = " ".join(problems)
    assert "x-1" in joined
    assert "x-2" in joined


def test_same_action_overlap_is_not_a_contradiction():
    table = _table(
        [
            lookup.Rule(id="x-1", condition={"severity": ("low",)}, action="true_positive"),
            lookup.Rule(id="x-2", condition={"rule_level_lt": 5}, action="true_positive"),
        ]
    )
    assert lookup.check_consistency(table) == []


# ---------------------------------------------------------------------------
# the canonical alert (context pack §8 / architecture §3.10)
# ---------------------------------------------------------------------------


def test_sbf_rules_from_architecture_3_10():
    table = lookup.get_decision_table("ssh_brute_force")
    facts = {
        "severity": "critical",
        "rule_level": 12,
        "ioc_reputation": "skipped",
        "asset_criticality": "unknown",
        "identity_privileged": "unknown",
        "occurrence_count": 1,
    }
    assert lookup.apply_table(table, facts) == ("true_positive", "sbf-3")
    assert lookup.rule_holds(table, "sbf-1", facts) is False


# ---------------------------------------------------------------------------
# the token bound and the review gate on the shipped skeletons
# ---------------------------------------------------------------------------


def test_largest_playbook_under_3000_tokens():
    try:
        from app.llm.adapter import estimate_tokens
    except ImportError:  # pragma: no cover - P3-T04 not merged yet in this checkout

        def estimate_tokens(text: str) -> int:
            return math.ceil(len(text.encode("utf-8")) / 2.5)

    sizes = {category: estimate_tokens(lookup.get_playbook(category)) for category in CATEGORIES}
    assert max(sizes.values()) < 3000, sizes


#: DEC-145: all ten tables signed at the 28/09 sitting, in this exact form.
SIGNED_BY = "NCK + MNN"
SIGNED_AT = "2026-09-28"
#: The ten categories signed on 28/09, by name — not derived from PRIORITY, so a category
#: added later (`brute_force`, P9-T02) cannot join them without a signing.
SIGNED_CATEGORIES = (
    "ssh_brute_force",
    "suspicious_login",
    "privilege_escalation",
    "ransomware",
    "data_exfiltration",
    "c2_beacon",
    "malware",
    "recon",
    "web_attack",
    "policy_violation",
)


@pytest.mark.parametrize("category", SIGNED_CATEGORIES)
def test_tables_are_reviewed(category):
    table = lookup.get_decision_table(category)
    assert table.reviewed_by == SIGNED_BY
    assert table.reviewed_at == SIGNED_AT
    assert table.reviewed is True


def test_brute_force_table_is_unreviewed():
    """P9-T02 (DEC-149): agent-drafted, not signed. While reviewed_by/reviewed_at are null the
    gate's step 4 answers `table_unreviewed`, so ① never auto-closes a `brute_force` alert."""
    table = lookup.get_decision_table("brute_force")
    assert table.reviewed_by is None
    assert table.reviewed_at is None
    assert table.reviewed is False
    # Every category is one of the ten signed on 28/09 or one of the two unsigned ones
    # (`brute_force`, `credential_access`) — nothing else.
    assert set(CATEGORIES) == set(SIGNED_CATEGORIES) | {"brute_force", "credential_access"}


def test_credential_access_table_is_unreviewed():
    """S1 (v3.4): agent-drafted, not signed. `reviewed_by` is left blank for a human to fill;
    while it is blank the gate's step 4 answers `table_unreviewed`, so ① never auto-closes a
    `credential_access` alert."""
    from app.tier1.triage import _make_rule_check

    table = lookup.get_decision_table("credential_access")
    assert not table.reviewed_by
    assert table.reviewed is False
    assert lookup.check_consistency(table) == []
    # No false_positive rule: a low alert is never auto-closed (nothing in the facts can tell a
    # registered security product or an admin's diagnostic dump from a real LSASS dump).
    assert {rule.action for rule in table.rules} == {"true_positive", "needs_review"}
    low_point = {
        "severity": "low",
        "rule_level": 3,
        "ioc_reputation": "not_found",
        "asset_criticality": "low",
        "identity_privileged": "false",
        "occurrence_count": 1,
    }
    assert lookup.apply_table(table, low_point) == ("needs_review", "cra-4")
    high_point = {**low_point, "severity": "high", "rule_level": 10}
    assert lookup.apply_table(table, high_point) == ("true_positive", "cra-3")
    # Even a point where a rule holds is refused while the table is unsigned.
    for rule in table.rules:
        assert _make_rule_check(table, low_point)(rule.id) == (False, "table_unreviewed")
