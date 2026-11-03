"""G1 import-rule AST scan.

Any future change to ALLOWED or ALLOWLIST requires a docs/plan/DECISIONS.md id —
this is the layering contract from context pack §2 G1 and §4 (the "May import"
column; §4 is narrower than G1 and wins where they seem to disagree).
"""

import ast
import pathlib

import pytest

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
        "rag",  # DEC-210 (P13-T01)
        "lab",  # DEC-213 (P14-T09)
        "web",
    }
)
ALLOWED: dict[str, frozenset[str] | set[str]] = {
    "ingest": {"domain", "infra", "audit", "enrichment"},
    "soar": {"enrichment", "domain", "infra", "audit"},
    "tier1": {"domain", "llm", "kb", "security", "infra", "audit", "rag"},
    "tier2": {"domain", "llm", "kb", "security", "infra", "audit", "enrichment", "rag"},
    # DEC-210: the learned-knowledge package. It imports no tier and no `web`; tier1, tier2 and
    # `web` import it, and nothing else does.
    "rag": {"infra", "audit", "security", "llm", "kb", "domain"},
    # DEC-213 (P14-T09): the lab runs and labels. It reads the blind view of an alert from `tier1`
    # (`visibility.strip`) and writes audit events; no other package imports it but `web`.
    "lab": {"infra", "audit", "tier1"},
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


# --- P13-T01 / DEC-210: the `rag` package ------------------------------------------------------


def _package_names_on_disk() -> set[str]:
    return {
        path.name
        for path in APP_ROOT.iterdir()
        if path.is_dir() and (path / "__init__.py").is_file()
    }


def test_every_package_on_disk_is_in_the_table():
    """A package missing from `ALL` is invisible to the scan: an import OF it is never judged
    (`_absolute_target` returns None), so a tier could import it unchecked. `rag` arrived with
    DEC-210; the next package must not slip in the same way."""
    on_disk = _package_names_on_disk()
    assert on_disk - ALL == set(), f"packages the scan cannot see: {sorted(on_disk - ALL)}"
    assert (
        on_disk - set(ALLOWED) == set()
    ), f"packages with no row: {sorted(on_disk - set(ALLOWED))}"
    assert set(ALLOWED) <= ALL


def test_the_rag_package_exists_and_is_only_a_docstring():
    init = APP_ROOT / "rag" / "__init__.py"
    assert init.is_file(), "backend/app/rag/__init__.py"
    tree = ast.parse(init.read_text(encoding="utf-8"))
    assert ast.get_docstring(tree), "rag/__init__.py must open with a docstring"
    assert len(tree.body) == 1, "rag/__init__.py holds a docstring and nothing else (T01)"


@pytest.mark.parametrize("target", ["infra", "audit", "security", "llm", "kb", "domain"])
def test_rag_may_import_its_six_packages(target):
    assert violations_in(f"from app.{target} import x\n", "rag.lookup") == []


@pytest.mark.parametrize("target", ["tier1", "tier2", "web", "ingest", "soar", "enrichment"])
def test_rag_importing_a_tier_or_any_other_package_is_a_violation(target):
    assert violations_in(f"from app.{target} import x\n", "rag.lookup") == [
        f"rag.lookup imports {target} — not in ALLOWED[rag]"
    ]


@pytest.mark.parametrize("pkg", ["tier1", "tier2", "web"])
def test_tier1_tier2_and_web_may_import_rag(pkg):
    assert violations_in("from app.rag import lookup\n", f"{pkg}.mod") == []
    assert violations_in("from ..rag import lookup\n", f"{pkg}.mod") == []


@pytest.mark.parametrize(
    "pkg",
    ["infra", "audit", "security", "llm", "kb", "domain", "ingest", "soar", "enrichment", "lab"],
)
def test_no_other_package_may_import_rag(pkg):
    assert violations_in("from app.rag import lookup\n", f"{pkg}.mod") == [
        f"{pkg}.mod imports rag — not in ALLOWED[{pkg}]"
    ]


def test_a_deferred_import_of_rag_inside_a_function_is_still_judged():
    source = "def f():\n    from app.rag import lookup\n    return lookup\n"
    assert violations_in(source, "domain.transitions") == [
        "domain.transitions imports rag — not in ALLOWED[domain]"
    ]


# --- P14-T09 / DEC-213: the `lab` package ------------------------------------------------------


def test_the_lab_package_exists_and_is_only_a_docstring():
    init = APP_ROOT / "lab" / "__init__.py"
    assert init.is_file(), "backend/app/lab/__init__.py"
    tree = ast.parse(init.read_text(encoding="utf-8"))
    assert ast.get_docstring(tree), "lab/__init__.py must open with a docstring"
    assert len(tree.body) == 1, "lab/__init__.py holds a docstring and nothing else"


def test_the_lab_row_is_infra_audit_and_tier1():
    assert ALLOWED["lab"] == {"infra", "audit", "tier1"}


@pytest.mark.parametrize("target", ["infra", "audit", "tier1"])
def test_lab_may_import_its_three_packages(target):
    assert violations_in(f"from app.{target} import x\n", "lab.labels") == []
    assert violations_in(f"from app.{target}.y import x\n", "lab.runs") == []


@pytest.mark.parametrize(
    "target",
    ["tier2", "web", "ingest", "soar", "enrichment", "domain", "llm", "kb", "security", "rag"],
)
def test_lab_importing_any_other_package_is_a_violation(target):
    assert violations_in(f"from app.{target} import x\n", "lab.labels") == [
        f"lab.labels imports {target} — not in ALLOWED[lab]"
    ]


def test_web_may_import_lab():
    assert violations_in("from app.lab import runs\n", "web.routers.admin_lab") == []
    assert violations_in("from ..lab import labels\n", "web.routers.admin_lab") == []


@pytest.mark.parametrize(
    "pkg",
    [
        "infra",
        "audit",
        "security",
        "llm",
        "kb",
        "domain",
        "ingest",
        "soar",
        "enrichment",
        "rag",
        "tier1",
        "tier2",
    ],
)
def test_no_package_but_web_may_import_lab(pkg):
    assert violations_in("from app.lab import runs\n", f"{pkg}.mod") == [
        f"{pkg}.mod imports lab — not in ALLOWED[{pkg}]"
    ]


def test_a_deferred_import_of_lab_inside_a_function_is_still_judged():
    source = "def f():\n    from app.lab import runs\n    return runs\n"
    assert violations_in(source, "tier1.queue") == [
        "tier1.queue imports lab — not in ALLOWED[tier1]"
    ]
