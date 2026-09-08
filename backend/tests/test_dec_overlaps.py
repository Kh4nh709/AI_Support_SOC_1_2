"""`scripts/dec_overlaps.py` — where two decisions edited the same rule-bearing artifact.

The DEC-044 class: two rules, each correct in isolation, that stop composing, with no
artifact wrong on its own — three instances in three days (DEC-044, DEC-046, DEC-047).
`Propagated to:` already records what each decision touched, so the overlap is computable
from the log; nothing computed it. This is the smallest thing that does: it reports the
pairs and asks whether they still compose. Scoped to rule-bearing artifacts — the
context pack, reviewer.md, 01-plan.md, and any task card touched twice — never STATE.md,
which seventeen decisions touch because churn is its function.
"""

from __future__ import annotations

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))  # the pattern test_config.py uses for scripts/
import dec_overlaps

FIXTURE = """\
# DECISIONS

## DEC-001 · 2026-09-05 · First
Scope: tactical
Propagated to: `01-plan.md:8` (gate) · `STATE.md` (P1 row) · `tasks/P1/P1-T06.prompt.md`
Context: one.
Decision: one.

## DEC-002 · 2026-09-05 · Second
Scope: tactical
Propagated to: `01-plan.md:8,9` (gate re-dated) · `STATE.md` · `tasks/P1/P1-T04/T05/T06.prompt.md` (rule 1) · `00-context-pack.md` §6.3 (`LLM_TIMEOUT_S` annotated)
Context: two.
Decision: two, on its own.

## DEC-003 · 2026-09-06 · Third
Scope: tactical
Propagated to: `tasks/P1/P1-T05.prompt.md` acceptance 1 · `docs/plan/00-context-pack.md` (§6.1, §9) · `Makefile`
Context: three, which composes with DEC-002's rule 1 as follows.
Decision: three.

## DEC-004 · 2026-09-06 · No line
Scope: tactical
Context: four.
Decision: four.
"""


def test_parses_every_decision_and_only_those_with_a_propagated_line_carry_artifacts():
    decs = dec_overlaps.parse_decisions(FIXTURE)
    assert [d.id for d in decs] == ["DEC-001", "DEC-002", "DEC-003", "DEC-004"]
    assert decs[3].artifacts == []


def test_artifact_tokens_are_normalised_expanded_and_carry_their_loci():
    decs = {d.id: d for d in dec_overlaps.parse_decisions(FIXTURE)}
    two = {a.path: a.loci for a in decs["DEC-002"].artifacts}
    assert two["01-plan.md"] == {":8", ":9"}
    # `P1-T04/T05/T06.prompt.md` is three cards, not one token.
    assert {
        "tasks/P1/P1-T04.prompt.md",
        "tasks/P1/P1-T05.prompt.md",
        "tasks/P1/P1-T06.prompt.md",
    } <= set(two)
    assert two["00-context-pack.md"] == {"§6.3"}
    three = {a.path: a.loci for a in decs["DEC-003"].artifacts}
    # A leading `docs/plan/` is dropped; §-loci in the parenthetical are kept.
    assert three["00-context-pack.md"] == {"§6.1", "§9"}
    assert "Makefile" in three


def test_overlaps_are_reported_only_on_rule_bearing_artifacts_and_never_on_state():
    report = dec_overlaps.overlaps(dec_overlaps.parse_decisions(FIXTURE))
    assert "STATE.md" not in report
    assert "Makefile" not in report
    # A card touched once is not an overlap; a card touched twice is.
    assert "tasks/P1/P1-T04.prompt.md" not in report
    assert [d for d, _ in report["tasks/P1/P1-T06.prompt.md"]] == ["DEC-001", "DEC-002"]
    assert [d for d, _ in report["01-plan.md"]] == ["DEC-001", "DEC-002"]
    assert [d for d, _ in report["00-context-pack.md"]] == ["DEC-002", "DEC-003"]


def test_pairs_say_whether_the_later_decision_names_the_earlier_one_and_share_a_locus():
    decs = dec_overlaps.parse_decisions(FIXTURE)
    pairs = {(p.artifact, p.earlier, p.later): p for p in dec_overlaps.pairs(decs)}
    plan = pairs[("01-plan.md", "DEC-001", "DEC-002")]
    assert plan.acknowledged is False and plan.same_locus == {":8"}
    card = pairs[("tasks/P1/P1-T05.prompt.md", "DEC-002", "DEC-003")]
    assert card.acknowledged is True and card.same_locus == set()


def test_render_asks_the_question_for_every_unacknowledged_pair():
    text = dec_overlaps.render(dec_overlaps.parse_decisions(FIXTURE))
    assert "01-plan.md" in text and "DEC-001 × DEC-002" in text
    assert "still compose" in text
    assert "STATE.md" not in text


def test_a_phase_brief_touched_twice_is_reported_like_a_card():
    """A phase brief is what a Planner turns into cards, so two decisions editing one is the
    same seam as two editing a card (08/09: `prompts/P6.md` carried five decisions in three
    days and the report could not see it). Touched once, it is not an overlap."""
    decs = dec_overlaps.parse_decisions(
        (REPO_ROOT / "docs" / "plan" / "DECISIONS.md").read_text(encoding="utf-8")
    )
    report = dec_overlaps.overlaps(decs)
    assert "prompts/P6.md" in report
    touched = {d for d, _ in report["prompts/P6.md"]}
    assert {"DEC-055", "DEC-056"} <= touched
    assert "prompts/P0.md" not in report  # touched by no decision at all


def test_the_real_log_reproduces_the_dec_044_instance_and_excludes_state():
    """DEC-044: DEC-029 added the 015-absent rider to P1-T07's card and DEC-044 re-cut it —
    the first known instance of the class. The mechanism must at least see that one."""
    decs = dec_overlaps.parse_decisions(
        (REPO_ROOT / "docs" / "plan" / "DECISIONS.md").read_text(encoding="utf-8")
    )
    # 29 `Propagated to:` lines on 07/09, one of them the format template outside any entry.
    assert sum(1 for d in decs if d.artifacts) >= 28
    report = dec_overlaps.overlaps(decs)
    touched = [d for d, _ in report["tasks/P1/P1-T07.prompt.md"]]
    assert "DEC-029" in touched and "DEC-044" in touched
    assert "STATE.md" not in report
