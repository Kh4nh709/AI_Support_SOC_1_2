"""G1 import-rule AST scan.

Any future change to ALLOWED or ALLOWLIST requires a docs/plan/DECISIONS.md id —
this is the layering contract from context pack §2 G1 and §4 (the "May import"
column; §4 is narrower than G1 and wins where they seem to disagree).
"""

import ast
import pathlib

# context pack §4 — "May import" column. Keys and values are package names under backend/app/.
ALL = frozenset(
    {
        "ingest",
        "soar",
        "tier1",
        "tier2",
        "domain",
        "infra",
        "audit",
        "security",
        "llm",
        "kb",
        "enrichment",
        "web",
    }
)
ALLOWED: dict[str, frozenset[str] | set[str]] = {
    "ingest": {"domain", "infra", "audit", "enrichment"},
    "soar": {"enrichment", "domain", "infra", "audit"},
    "tier1": {"domain", "llm", "kb", "security", "infra", "audit"},
    "tier2": {"domain", "llm", "kb", "security", "infra", "audit", "enrichment"},
    "domain": {"infra", "audit"},
    "infra": set(),
    "audit": {"infra"},
    "security": {"infra"},
    "llm": {"security", "infra", "kb"},
    "kb": {"infra"},
    "enrichment": {"infra"},
    "web": ALL,  # composition root — may import everything
}
# G1's single exception, allowlisted: soar/pipeline.py may import ingest/.
ALLOWLIST: set[tuple[str, str]] = {("soar.pipeline", "ingest")}

APP_ROOT = pathlib.Path(__file__).resolve().parent.parent / "app"


def _absolute_target(name: str) -> str | None:
    """Resolve an absolute import target ('app.<pkg>...' or bare '<pkg>...') to a
    package name in ALL, or None if it is not an app.*/sibling-package import."""
    if not name:
        return None
    first, _, rest = name.partition(".")
    candidate = rest.partition(".")[0] if first == "app" and rest else first
    return candidate if candidate in ALL else None


def _relative_target(module: str, level: int, from_module: str | None) -> str | None:
    """Resolve a relative import ('from .x import y', node.level dots) to a package
    name in ALL, using the importing module's own dotted path and node.level."""
    package_parts = module.split(".")[:-1]
    if level > 1:
        cut = level - 1
        package_parts = package_parts[:-cut] if cut <= len(package_parts) else []
    base = ".".join(package_parts)
    full = f"{base}.{from_module}" if base and from_module else (from_module or base)
    if not full:
        return None
    candidate = full.split(".")[0]
    return candidate if candidate in ALL else None


def violations_in(source: str, module: str) -> list[str]:
    """All G1 violations in `source`, the text of the module named `module`
    (dotted path relative to backend/app/, e.g. 'soar.pipeline')."""
    tree = ast.parse(source)
    pkg = module.split(".")[0]
    allowed = ALLOWED.get(pkg, frozenset())
    violations = []
    for node in ast.walk(tree):
        targets = []
        if isinstance(node, ast.Import):
            for alias in node.names:
                target = _absolute_target(alias.name)
                if target is not None:
                    targets.append(target)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                target = _absolute_target(node.module or "")
            else:
                target = _relative_target(module, node.level, node.module)
            if target is not None:
                targets.append(target)
        for target in targets:
            if target == pkg:
                continue  # same-package import, not judged
            if (module, target) in ALLOWLIST:
                continue
            if target in allowed:
                continue
            violations.append(f"{module} imports {target} — not in ALLOWED[{pkg}]")
    return violations


def _module_name_for(path: pathlib.Path) -> str:
    rel = path.relative_to(APP_ROOT).with_suffix("")
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def test_real_tree_has_zero_import_violations():
    violations = []
    for path in sorted(APP_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        module = _module_name_for(path)
        violations.extend(violations_in(path.read_text(), module))
    assert violations == [], "\n".join(violations)


def test_soar_pipeline_importing_ingest_is_allowed():
    assert violations_in("from app.ingest import dedup\n", "soar.pipeline") == []


def test_soar_risk_importing_ingest_is_a_violation():
    violations = violations_in("from app.ingest import dedup\n", "soar.risk")
    assert violations == ["soar.risk imports ingest — not in ALLOWED[soar]"]


def test_infra_importing_domain_is_a_violation():
    violations = violations_in("from app.domain import alert\n", "infra.db")
    assert violations == ["infra.db imports domain — not in ALLOWED[infra]"]


def test_tier_importing_another_tier_is_a_violation():
    violations = violations_in("from app.tier2 import dossier\n", "tier1.triage")
    assert violations == ["tier1.triage imports tier2 — not in ALLOWED[tier1]"]


def test_relative_import_of_ingest_is_allowed_in_soar_pipeline():
    assert violations_in("from ..ingest import dedup\n", "soar.pipeline") == []


def test_relative_import_of_ingest_is_a_violation_in_tier1_triage():
    violations = violations_in("from ..ingest import dedup\n", "tier1.triage")
    assert violations == ["tier1.triage imports ingest — not in ALLOWED[tier1]"]


def test_deferred_import_inside_function_is_still_judged():
    source = "def f():\n    from app.tier2 import dossier\n    return dossier\n"
    violations = violations_in(source, "tier1.triage")
    assert violations == ["tier1.triage imports tier2 — not in ALLOWED[tier1]"]


def test_deferred_import_inside_type_checking_block_is_still_judged():
    source = (
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    from app.tier2 import dossier\n"
    )
    violations = violations_in(source, "tier1.triage")
    assert violations == ["tier1.triage imports tier2 — not in ALLOWED[tier1]"]


def test_stdlib_and_third_party_imports_are_ignored():
    source = "import json\nimport pytest\nfrom collections import OrderedDict\n"
    assert violations_in(source, "tier1.triage") == []


def test_same_package_import_is_never_judged():
    assert violations_in("from app.soar import risk\n", "soar.pipeline") == []
    assert violations_in("from . import risk\n", "soar.pipeline") == []


def test_allowlist_is_keyed_by_module_not_package():
    assert ("soar.pipeline", "ingest") in ALLOWLIST
    assert ("soar.risk", "ingest") not in ALLOWLIST
