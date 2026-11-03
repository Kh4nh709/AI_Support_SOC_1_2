"""P13 whole-branch fix wave, items 16 and 18: the entries ① and ② may put in the learned section.

`llm.builder` owns the contract both prompts share (`LearnedLike`, `MAX_LEARNED_ENTRIES`) and the one
function that turns a lookup's material into the entries a prompt renders (`prompt_entries`): the cap, the
closed level and (P14-T06) the percentage, as `(level, pct, text)`. ① (`llm.triage`) and ② (`tier2.dossier`) call it and nothing else; neither defines the
contract again. The drop of an entry with a forged line is `test_learned_structure.py`.

PURE. No database, no network.
"""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

import pytest
from app.llm import builder as B
from app.llm import triage as T
from app.llm.builder import KbLearnedLevel
from app.tier2 import dossier

APP = Path(__file__).resolve().parent.parent / "app"


@dataclasses.dataclass(frozen=True)
class Material:
    history_text: str | None
    entries: tuple


def entries_of(*texts: str, level: KbLearnedLevel = KbLearnedLevel.GIONG) -> Material:
    return Material(None, tuple((level, 72, text) for text in texts))


# ── item 16: where the contract lives ─────────────────────────────────────────────────────────


def _defined_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = {node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return names


def test_the_shared_contract_is_defined_in_llm_builder() -> None:
    assert B.MAX_LEARNED_ENTRIES == 3
    assert B.LearnedLike.__module__ == "app.llm.builder"
    assert {"history_text", "entries"} <= set(dir(B.LearnedLike))


@pytest.mark.parametrize("module", [T, dossier], ids=["llm.triage", "tier2.dossier"])
def test_neither_prompt_defines_the_contract_again_nor_re_exports_the_cap(module) -> None:
    defined = _defined_names(Path(module.__file__))
    assert "LearnedLike" not in defined and "MAX_LEARNED_ENTRIES" not in defined
    assert not hasattr(module, "MAX_LEARNED_ENTRIES")  # no compatibility re-export of the cap


def test_both_prompts_take_their_entries_from_the_one_function() -> None:
    for path in (APP / "llm" / "triage.py", APP / "tier2" / "dossier.py"):
        source = path.read_text(encoding="utf-8")
        assert "prompt_entries(" in source, path.name


# ── the cap and the closed level (items 16, 18) ───────────────────────────────────────────────


def test_no_material_has_no_entries() -> None:
    assert B.prompt_entries(None) == ()
    assert B.prompt_entries(Material("h", ())) == ()


def test_at_most_the_cap_is_kept_best_first() -> None:
    texts = [f"# entry {n}" for n in range(B.MAX_LEARNED_ENTRIES + 2)]
    kept = B.prompt_entries(entries_of(*texts))
    assert [text for _, _, text in kept] == texts[: B.MAX_LEARNED_ENTRIES]
    assert {pct for _, pct, _ in kept} == {72}


def test_a_level_that_is_not_a_closed_learned_level_is_a_type_error_that_does_not_echo_it() -> None:
    bad = Material(None, ((B.Severity.HIGH, 72, "# entry"),))
    with pytest.raises(TypeError) as raised:
        B.prompt_entries(bad)
    assert "high" not in str(raised.value) and "HIGH" not in str(raised.value)


def test_a_string_level_is_a_type_error_too() -> None:
    with pytest.raises(TypeError):
        B.prompt_entries(Material(None, (("giong", 72, "# entry"),)))


def test_a_bad_level_beyond_the_cap_is_never_looked_at() -> None:
    entries = tuple(
        (KbLearnedLevel.GIONG, 72, f"# entry {n}") for n in range(B.MAX_LEARNED_ENTRIES)
    )
    late = (B.Severity.HIGH, 72, "# late")
    assert len(B.prompt_entries(Material(None, (*entries, late)))) == 3


# ── the percentage (P14-T06, DEC-213) ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("pct", [-1, 101])
def test_a_percentage_out_of_range_is_a_value_error(pct) -> None:
    with pytest.raises(ValueError):
        B.prompt_entries(Material(None, ((KbLearnedLevel.GIONG, pct, "# entry"),)))


@pytest.mark.parametrize("pct", ["72", 72.0, None, True])
def test_a_percentage_that_is_not_an_int_is_a_type_error(pct) -> None:
    with pytest.raises(TypeError):
        B.prompt_entries(Material(None, ((KbLearnedLevel.GIONG, pct, "# entry"),)))


def test_a_bad_percentage_beyond_the_cap_is_never_looked_at() -> None:
    entries = tuple(
        (KbLearnedLevel.GIONG, 72, f"# entry {n}") for n in range(B.MAX_LEARNED_ENTRIES)
    )
    late = (KbLearnedLevel.GIONG, 1000, "# late")
    assert len(B.prompt_entries(Material(None, (*entries, late)))) == 3


def test_the_edges_of_the_percentage_are_entries() -> None:
    kept = B.prompt_entries(
        Material(None, ((KbLearnedLevel.GIONG, 0, "# a"), (KbLearnedLevel.GIONG, 100, "# b")))
    )
    assert [pct for _, pct, _ in kept] == [0, 100]
