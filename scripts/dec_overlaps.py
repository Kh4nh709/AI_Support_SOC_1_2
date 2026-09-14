#!/usr/bin/env python3
"""Where two decisions edited the same rule-bearing artifact — and do they still compose?

The DEC-044 class: two rules, each correct in isolation, that stop composing, with no
artifact wrong on its own. Three instances in three days (DEC-044 the card axes, DEC-046
the fast-forward treadmill, DEC-047 schema.sql) and no mechanism. DEC-044 named the seed —
``Propagated to:`` already records what every decision touched, so the overlap is computable
from the log — and nothing computed it. This does.

Scope, so the report is signal and not churn: rule-bearing artifacts only — the context
pack, ``prompts/reviewer.md``, ``01-plan.md``, and any task card **or phase brief** touched by
two decisions. The board is never reported: seventeen decisions touch it because churn is its
function.

What it sees and what it cannot, stated plainly. An artifact-level overlap is a proxy for a
rule-level one. DEC-044's own instance (DEC-029 then DEC-044 on P1-T07's card) is visible.
DEC-046's (a reviewer.md rule against the Director's merge cadence, which lives in
director.md) and DEC-047's (two task branches composing on a generated file) are not: the
two rules sat in different artifacts, or in no decision at all. It reports and asks the
question; it does not answer it. ``--all`` widens to every artifact except the board.

    python3 scripts/dec_overlaps.py [--decisions docs/plan/DECISIONS.md] [--all]
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from dataclasses import dataclass, field

RULE_BEARING = ("00-context-pack.md", "01-plan.md", "prompts/reviewer.md")
CARD = re.compile(r"tasks/P\d/P\d-T\d\d\.prompt\.md$")
#: A phase brief is what a Planner turns into cards, so two decisions editing one is the same
#: seam as two editing a card. Added 08/09 after the reporter's own first week: `prompts/P6.md`
#: took five decisions in three days (DEC-052, 053, 054, 055, 056) and the report could not see
#: it, because the original scoping rule named only the pack, `reviewer.md`, `01-plan.md` and
#: cards. Gated on "touched twice" exactly as cards are, so a brief edited once stays quiet.
BRIEF = re.compile(r"prompts/P\d\.md$")
BOARD = "STATE.md"

_HEADER = re.compile(r"^## (DEC-\d{3}) · (\S+) · (.*)$", re.MULTILINE)
_TOKEN = re.compile(r"`([^`]+)`")
_PATHLIKE = re.compile(r"\.(md|ya?ml|py|sql|sh|json|txt|example)$")
_TRAILING_LINES = re.compile(r"^(.*?)(:\d+(?:[,\-–]\d+)*)$")  # :16,22 or :8-9
_CARDS = re.compile(r"^(?:tasks/P\d/)?(P\d)-(T\d\d)((?:/T\d\d)*)\.prompt\.md$")
_INDEX = re.compile(r"^(?:tasks/P\d/)?(P\d)-tasks\.md$")
_PROMPT = re.compile(r"^(P\d|reviewer|director|coder-template)\.md$")
_LOCUS = re.compile(r"§\d+(?:\.\d+)?|(?<![\w/`])(:\d+)")


@dataclass(frozen=True)
class Artifact:
    path: str
    loci: frozenset[str]


@dataclass
class Decision:
    id: str
    date: str
    title: str
    body: str
    artifacts: list[Artifact] = field(default_factory=list)


@dataclass(frozen=True)
class Pair:
    artifact: str
    earlier: str
    later: str
    acknowledged: bool  # the later entry names the earlier id anywhere in its text
    same_locus: frozenset[str]


def _normalise(token: str) -> tuple[list[str], set[str]]:
    """One backticked token -> repo-relative paths (a card list expands) + its `:line` loci."""
    token = token.strip()
    for prefix in ("/project/project/AI_Support_SOC_1_2/docs/plan/", "docs/plan/"):
        token = token.removeprefix(prefix)
    loci: set[str] = set()
    m = _TRAILING_LINES.match(token)
    if m and m.group(2):
        token = m.group(1)
        loci = set()
        for part in m.group(2).lstrip(":").split(","):
            lo, _, hi = part.partition("-") if "-" in part else part.partition("–")
            span = (
                range(int(lo), int(hi) + 1)
                if hi and int(hi) - int(lo) <= 20
                else [int(lo)] + ([int(hi)] if hi else [])
            )
            loci |= {f":{n}" for n in span}
    if token in ("Makefile", ".gitignore", ".env.example"):
        return [token], loci
    if not _PATHLIKE.search(token):
        return [], loci
    m = _CARDS.match(token)
    if m:
        phase, first, rest = m.groups()
        tasks = [first] + [t for t in rest.split("/") if t]
        return [f"tasks/{phase}/{phase}-{t}.prompt.md" for t in tasks], loci
    m = _INDEX.match(token)
    if m:
        return [f"tasks/{m.group(1)}/{m.group(1)}-tasks.md"], loci
    if _PROMPT.match(token):
        return [f"prompts/{token}"], loci
    return [token], loci


def _artifacts(propagated: str) -> list[Artifact]:
    out: dict[str, set[str]] = {}
    for segment in propagated.split(" · "):
        segment_loci = set(re.findall(r"§\d+(?:\.\d+)?", segment))
        segment_loci |= {m for m in re.findall(r"(?<![\w/`])(:\d+)", segment)}
        for token in _TOKEN.findall(segment):
            paths, loci = _normalise(token)
            for path in paths:
                out.setdefault(path, set()).update(loci or segment_loci)
    return [Artifact(p, frozenset(l)) for p, l in out.items()]


def parse_decisions(text: str) -> list[Decision]:
    heads = list(_HEADER.finditer(text))
    decisions: list[Decision] = []
    for i, h in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        body = text[h.end() : end]
        prop = re.search(r"^Propagated to:\s*(.*)$", body, re.MULTILINE)
        d = Decision(id=h.group(1), date=h.group(2), title=h.group(3).strip(), body=body)
        if prop:
            d.artifacts = _artifacts(prop.group(1))
        decisions.append(d)
    return decisions


def _rule_bearing(path: str, touches: int) -> bool:
    if path == BOARD:
        return False
    if path in RULE_BEARING:
        return True
    return bool(CARD.search(path) or BRIEF.search(path)) and touches >= 2


def overlaps(
    decisions: list[Decision], everything: bool = False
) -> dict[str, list[tuple[str, frozenset[str]]]]:
    """artifact -> [(dec id, loci)] in log order, for artifacts two or more decisions touched."""
    touched: dict[str, list[tuple[str, frozenset[str]]]] = {}
    for d in decisions:
        for a in d.artifacts:
            touched.setdefault(a.path, []).append((d.id, a.loci))
    report = {}
    for path, decs in touched.items():
        if len({d for d, _ in decs}) < 2:
            continue
        if path == BOARD:
            continue
        if everything or _rule_bearing(path, len(decs)):
            report[path] = decs
    return report


def pairs(decisions: list[Decision], everything: bool = False) -> list[Pair]:
    by_id = {d.id: d for d in decisions}
    out: list[Pair] = []
    for path, decs in overlaps(decisions, everything).items():
        for i, (earlier, e_loci) in enumerate(decs):
            for later, l_loci in decs[i + 1 :]:
                if later == earlier:
                    continue
                out.append(
                    Pair(
                        artifact=path,
                        earlier=earlier,
                        later=later,
                        acknowledged=earlier in by_id[later].body,
                        same_locus=frozenset(e_loci & l_loci),
                    )
                )
    return out


def render(decisions: list[Decision], everything: bool = False) -> str:
    by_id = {d.id: d for d in decisions}
    with_line = sum(1 for d in decisions if d.artifacts)
    report = overlaps(decisions, everything)
    all_pairs = pairs(decisions, everything)
    intro = (
        f"Parsed {len(decisions)} decisions, {with_line} with a `Propagated to:` line. "
        f"Scope: {', '.join(RULE_BEARING)} and any task card or phase brief touched twice; "
        "the board is excluded "
        "by design (churn is its function). An overlap is a question, not a finding: "
        "**do the two rules still compose on that text?** A pair is *acknowledged* when the later "
        "entry names the earlier id anywhere in its text — a weak proxy for having asked."
    )
    lines = ["# Decision overlaps on rule-bearing artifacts", "", intro, ""]
    for path, decs in report.items():
        ids = []
        for d, _ in decs:
            if d not in ids:
                ids.append(d)
        lines.append(f"## `{path}` — touched by {len(ids)} decisions: {', '.join(ids)}")
        lines.append("")
        lines.append("| earlier | later | shared locus | later names earlier? | question |")
        lines.append("|---|---|---|---|---|")
        for p in (x for x in all_pairs if x.artifact == path):
            locus = ", ".join(sorted(p.same_locus)) or "—"
            ack = "yes" if p.acknowledged else "**no**"
            q = (
                f"{p.earlier} × {p.later}: do «{by_id[p.earlier].title[:60]}» and "
                f"«{by_id[p.later].title[:60]}» still compose on `{path}`"
                + (f" at {locus}" if p.same_locus else "")
                + "?"
            )
            lines.append(f"| {p.earlier} | {p.later} | {locus} | {ack} | {q} |")
        lines.append("")
    unack = [p for p in all_pairs if not p.acknowledged]
    same = [p for p in all_pairs if p.same_locus]
    lines.append("## Summary")
    lines.append("")
    lines.append(
        f"{len(report)} artifacts · {len(all_pairs)} pairs · **{len(unack)} unacknowledged** "
        f"(the ones to ask) · {len(same)} pairs share a locus (the likeliest seams)."
    )
    outside = {
        path: len({d for d, _ in decs})
        for path, decs in overlaps(decisions, everything=True).items()
        if path not in report
    }
    if outside and not everything:
        lines.append(
            "Touched ≥ 2 times but outside the rule-bearing set (pass `--all` to include): "
            + ", ".join(f"`{p}` ×{n}" for p, n in sorted(outside.items(), key=lambda x: -x[1]))
            + "."
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--decisions", default="docs/plan/DECISIONS.md")
    ap.add_argument("--all", action="store_true", help="every artifact except the board")
    args = ap.parse_args(argv)
    text = pathlib.Path(args.decisions).read_text(encoding="utf-8")
    sys.stdout.write(render(parse_decisions(text), everything=args.all))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
