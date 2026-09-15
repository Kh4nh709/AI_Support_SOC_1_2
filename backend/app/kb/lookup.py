"""`kb.lookup` — playbook lookup, the decision-table YAML format, and the pure rule
evaluators `apply_table` / `rule_holds` / `check_consistency` (context pack §11: the
table *content* is the Owner's and the advisor's; this module ships the format, the
loader and the ten unreviewed skeletons with the architecture §3.10 example rules).

`apply_table` ignores `DecisionTable.reviewed` on purpose: it is P7's B1 baseline and
must evaluate authored tables offline regardless of review status. The *gate*
(P3-T10, wrapping `rule_holds`) is what reads `reviewed` — while a table is
unreviewed, the gate's `rule_check` answers "missing" and `gate_result.warnings`
carries `decision_table_unreviewed:<category>` (architecture §3.10); the playbook
text block is still sent to the model either way.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

import yaml

#: `backend/app/kb/lookup.py` -> `kb` -> `app` -> `backend` -> repo root, then `kb`
#: (P2-T03 put the ten playbooks at the repo-root `kb/playbooks/`, pinned by
#: `test_category.py`; the decision tables sit beside them — planning decision 5).
KB_ROOT = Path(__file__).resolve().parents[3] / "kb"

#: `if` keys whose value is a list of strings from a closed vocabulary (context pack
#: §6.2). `identity_privileged` ranges over the *strings* `"true"|"false"|"unknown"`,
#: never the YAML booleans `true`/`false` — a table that writes them unquoted has said
#: something its author did not mean, and the loader refuses it rather than repairing it.
_VOCAB: dict[str, tuple[str, ...]] = {
    "severity": ("critical", "high", "medium", "low"),
    "ioc_reputation": ("malicious", "suspicious", "clean", "not_found", "skipped"),
    "asset_criticality": ("high", "medium", "low", "unknown"),
    "identity_privileged": ("true", "false", "unknown"),
}
#: `if` keys whose value is a plain int, compared against `facts["occurrence_count"]`
#: or `facts["rule_level"]`.
_INT_CONDITION_KEYS: dict[str, str] = {
    "occurrence_lt": "occurrence_count",
    "occurrence_gte": "occurrence_count",
    "rule_level_lt": "rule_level",
    "rule_level_gte": "rule_level",
}
_ACTIONS = ("false_positive", "needs_review", "escalate")
#: Design note 2 gives this as `^[a-z]{2,6}-\d{1,2}$`; widened to admit digits in the
#: abbreviation (`[a-z0-9]`) because design note 5's own abbreviation list includes
#: `c2b` (c2_beacon) — letters-only cannot match it. Deviation noted in the report;
#: everything else (2-6 chars, one hyphen, a 1-2 digit suffix, unique per file) holds.
_RULE_ID_RE = re.compile(r"^[a-z0-9]{2,6}-\d{1,2}$")
_TITLE_TOKEN_RE = re.compile(r"`([^`]+)`")

#: The consistency grid (design note 4). `rule_level` is a free axis; `severity` is
#: derived from it below, never generated on its own — `alerts.severity` is itself
#: `rule_level`-banded (DEC-053), so a point like `severity=low, rule_level=12` cannot
#: exist, and generating it would make every false-positive rule "contradict" every
#: `rule_level_gte: 12` escalate rule at an impossible point.
_GRID_RULE_LEVELS = (0, 3, 5, 8, 12, 15)
_GRID_OCCURRENCE_COUNTS = (1, 10, 49, 50, 100, 999, 1000)


class DecisionTableError(Exception):
    """A `kb/decision_tables/<category>.yaml` file fails validation."""


@dataclass(frozen=True)
class Rule:
    id: str
    condition: Mapping[str, Any]
    action: str


@dataclass(frozen=True)
class DecisionTable:
    category: str
    playbook: str
    reviewed_by: str | None
    reviewed_at: str | None
    rules: tuple[Rule, ...]

    @property
    def reviewed(self) -> bool:
        return bool(self.reviewed_by and self.reviewed_at)


def severity_for(rule_level: int) -> str:
    """DEC-053's band, pinned: >= 12 critical, >= 8 high, >= 5 medium, else low."""
    if rule_level >= 12:
        return "critical"
    if rule_level >= 8:
        return "high"
    if rule_level >= 5:
        return "medium"
    return "low"


def fact_grid() -> Iterator[dict[str, Any]]:
    """The 2,520-point consistency grid: `rule_level` (with `severity` derived from it)
    x `ioc_reputation` (5) x `asset_criticality` (4) x `identity_privileged` (3) x
    `occurrence_count` (7)."""
    for rule_level in _GRID_RULE_LEVELS:
        for ioc_reputation in _VOCAB["ioc_reputation"]:
            for asset_criticality in _VOCAB["asset_criticality"]:
                for identity_privileged in _VOCAB["identity_privileged"]:
                    for occurrence_count in _GRID_OCCURRENCE_COUNTS:
                        yield {
                            "severity": severity_for(rule_level),
                            "rule_level": rule_level,
                            "ioc_reputation": ioc_reputation,
                            "asset_criticality": asset_criticality,
                            "identity_privileged": identity_privileged,
                            "occurrence_count": occurrence_count,
                        }


def rule_matches(rule: Rule, facts: Mapping[str, Any]) -> bool:
    """Every key of `rule.condition` holds against `facts`. A fact the condition needs
    but `facts` does not carry makes the rule not match — it never raises."""
    for key, value in rule.condition.items():
        if key in _VOCAB:
            if facts.get(key) not in value:
                return False
            continue
        fact_key = _INT_CONDITION_KEYS[key]
        fact_value = facts.get(fact_key)
        if fact_value is None:
            return False
        if key.endswith("_lt"):
            if not fact_value < value:
                return False
        elif not fact_value >= value:
            return False
    return True


def apply_table(table: DecisionTable, facts: Mapping[str, Any]) -> tuple[str, str] | None:
    """The first rule (file order) whose condition holds, as `(action, rule_id)` — or
    `None` if none match. Pure, and ignores `table.reviewed` on purpose (module
    docstring): it is B1 (P7), which must evaluate authored tables offline."""
    for rule in table.rules:
        if rule_matches(rule, facts):
            return rule.action, rule.id
    return None


def rule_holds(table: DecisionTable, rule_id: str, facts: Mapping[str, Any]) -> bool | None:
    """Whether the rule named `rule_id` holds against `facts` — `None` when no rule in
    `table` carries that id."""
    for rule in table.rules:
        if rule.id == rule_id:
            return rule_matches(rule, facts)
    return None


def check_consistency(table: DecisionTable) -> list[str]:
    """Every `(rule_a, rule_b, fact point)` where both rules hold with a different
    `then`, walking `fact_grid()`. Same-action overlap is fine — rules are ordered in
    the file and the first match wins; only a differing action at a shared point is a
    contradiction."""
    problems: list[str] = []
    for point in fact_grid():
        holding = [rule for rule in table.rules if rule_matches(rule, point)]
        for i, rule_a in enumerate(holding):
            for rule_b in holding[i + 1 :]:
                if rule_a.action != rule_b.action:
                    problems.append(
                        f"{rule_a.id} ({rule_a.action}) and {rule_b.id} ({rule_b.action}) "
                        f"both hold at {point}"
                    )
    return problems


def _playbook_path(category: str, root: Path) -> Path:
    return root / "playbooks" / f"{category}.md"


def _table_path(category: str, root: Path) -> Path:
    return root / "decision_tables" / f"{category}.yaml"


def _playbook_name(path: Path) -> str | None:
    """The `<category>_v1` token from a playbook's title line — `kb/playbooks/*.md`'s
    first line carries two backtick-quoted tokens, the category and the playbook name;
    this is the second one. `None` if the line carries fewer than two."""
    first_line = path.read_text(encoding="utf-8").splitlines()[0]
    tokens = _TITLE_TOKEN_RE.findall(first_line)
    return tokens[1] if len(tokens) >= 2 else None


def get_playbook(category: str, *, root: Path = KB_ROOT) -> str | None:
    """The playbook's raw markdown text (the P3-T09 `kb_playbook` block source) — `None`
    for the `unknown` category or one with no playbook file at `root`."""
    if category == "unknown":
        return None
    path = _playbook_path(category, root)
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def _fail(path: Path, rule_id: str | None, message: str) -> NoReturn:
    where = f"{path.name}: rule {rule_id!r}" if rule_id is not None else path.name
    raise DecisionTableError(f"{where}: {message}")


def _validate_condition(path: Path, rule_id: str, condition: Any) -> dict[str, Any]:
    if not isinstance(condition, dict) or not condition:
        _fail(path, rule_id, "'if' must be a non-empty mapping")
    parsed: dict[str, Any] = {}
    for key, value in condition.items():
        if key in _VOCAB:
            if not isinstance(value, list) or not value:
                _fail(path, rule_id, f"condition {key!r} must be a non-empty list")
            checked: list[str] = []
            for item in value:
                if isinstance(item, bool):
                    _fail(
                        path,
                        rule_id,
                        f"condition {key!r} value {item!r} is a YAML boolean — quote it "
                        f'as a string, e.g. "true"/"false"',
                    )
                if not isinstance(item, str) or item not in _VOCAB[key]:
                    _fail(
                        path,
                        rule_id,
                        f"condition {key!r} value {item!r} is outside {_VOCAB[key]}",
                    )
                checked.append(item)
            parsed[key] = tuple(checked)
        elif key in _INT_CONDITION_KEYS:
            if isinstance(value, bool) or not isinstance(value, int):
                _fail(path, rule_id, f"condition {key!r} must be an int, got {value!r}")
            parsed[key] = value
        else:
            _fail(path, rule_id, f"unknown condition key {key!r}")
    return parsed


def _validate_rule(path: Path, raw: Any, seen_ids: set[str]) -> Rule:
    if not isinstance(raw, dict):
        _fail(path, None, f"rule {raw!r} must be a mapping")
    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not _RULE_ID_RE.fullmatch(rule_id):
        _fail(path, str(rule_id), f"id {rule_id!r} must match {_RULE_ID_RE.pattern}")
    if rule_id in seen_ids:
        _fail(path, rule_id, "duplicate rule id")
    seen_ids.add(rule_id)
    action = raw.get("then")
    if action not in _ACTIONS:
        _fail(path, rule_id, f"then {action!r} must be one of {_ACTIONS}")
    condition = _validate_condition(path, rule_id, raw.get("if"))
    return Rule(id=rule_id, condition=condition, action=action)


def get_decision_table(category: str, *, root: Path = KB_ROOT) -> DecisionTable | None:
    """Load and validate `kb/decision_tables/<category>.yaml` — `None` for the `unknown`
    category or one with no table file at `root`. Raises `DecisionTableError` naming
    the file, the rule id and the key for anything the format (design note 2) forbids:
    an unknown condition key, a value outside its vocabulary (including an unquoted
    YAML boolean where `identity_privileged` wants a string), a non-list where a list
    is required, a `then` outside the three actions, a duplicate rule id, a bad rule id
    shape, a `category` that does not match the file name, or a `playbook` name that is
    not the one in the playbook file's title line.
    """
    if category == "unknown":
        return None
    path = _table_path(category, root)
    if not path.is_file():
        return None
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        _fail(path, None, "top-level document must be a mapping")

    file_category = raw.get("category")
    if file_category != path.stem:
        _fail(path, None, f"category {file_category!r} does not match file name {path.stem!r}")

    playbook = raw.get("playbook")
    playbook_path = _playbook_path(category, root)
    if not playbook_path.is_file():
        _fail(path, None, f"no playbook file at {playbook_path}")
    expected_playbook = _playbook_name(playbook_path)
    if playbook != expected_playbook:
        _fail(
            path,
            None,
            f"playbook {playbook!r} does not match {playbook_path.name}'s title line "
            f"({expected_playbook!r})",
        )

    seen_ids: set[str] = set()
    rules = tuple(_validate_rule(path, raw_rule, seen_ids) for raw_rule in raw.get("rules") or [])

    return DecisionTable(
        category=file_category,
        playbook=playbook,
        reviewed_by=raw.get("reviewed_by"),
        reviewed_at=raw.get("reviewed_at"),
        rules=rules,
    )
