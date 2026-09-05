"""A claim a decision has killed must not reappear in a forward-looking document.

Four earlier attempts at the propagation problem all reported to a human and none
detected: DEC-009's note, `Drafted by:`, `Propagated to:` and the manual sweep.
`Propagated to:` is still a self-report — it lists what the author remembers editing.
This test reads `docs/plan/superseded.yaml` and fails when a dead claim is back.

Scope is deliberately narrow (see the header of that file): only forward-looking
artifacts. Reports, reviews, audits, INBOX.md and DECISIONS.md are history and MUST
still contain the old wording. Scanning them would make this noisy, and a noisy
linter is an ignored linter.

  status: fixed  -> asserted hard. The regression guard.
  status: open   -> xfail, so `make test` stays green while the backlog burns down.
                    Count the remaining debt with `-rs`, or read the xfail total.

A live document may legitimately name a dead thing. Mark that line, the way noqa works:
    <!-- superseded-ok: DEC-nnn short reason -->
"""

from __future__ import annotations

import glob
import pathlib
import re

import pytest
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC_PATH = REPO_ROOT / "docs" / "plan" / "superseded.yaml"
EXEMPT_MARKER = "superseded-ok:"

_spec = yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))
_scan = _spec["scan"]
_rules = _spec["rules"]


def _in_scope() -> list[pathlib.Path]:
    """Forward-looking artifacts only — history is excluded by construction."""
    found: set[pathlib.Path] = set()
    for pattern in _scan["include"]:
        for hit in glob.glob(str(REPO_ROOT / pattern)):
            path = pathlib.Path(hit)
            if path.name in _scan["exclude_names"]:
                continue
            if any(path.name.endswith(sfx) for sfx in _scan["exclude_suffixes"]):
                continue
            found.add(path)
    return sorted(found)


SCOPE = _in_scope()


_DEC_TOKEN = re.compile(r"DEC-\d{3}")
# The marker's head: one or more DEC ids (optionally suffixed like "(a)"), comma/space
# separated, before any prose. Only the head counts.
_MARKER_HEAD = re.compile(r"\s*((?:DEC-\d{3}(?:\([a-z]\))?[\s,]*)+)")


def _exempted(line: str, rule: dict) -> bool:
    """A `superseded-ok:` marker exempts the line only for the DECs named in its head.

    Line-level markers silence every rule that matches the line. Measured 06/09: a
    marker written for DEC-024(a) on STATE.md:67 also silenced DEC-004's `013–016`
    rule on the same line and that row went XPASS — a fix nobody made, reported as
    made; and a DEC-004 marker on P1-T07.prompt.md:105 had been hiding DEC-016's
    withdrawn carve-out sentence since the DEC-027 sweep. So a marker names the DECs
    it exempts, first, before any prose: `<!-- superseded-ok: DEC-024(a), DEC-004 —
    why -->`. Prose is not parsed — "the pre-DEC-004 range" in a reason does not
    exempt DEC-004 — which is what makes the head the only thing a reviewer has to
    read. A marker for another DEC is not an exemption; it is a hit with a
    misleading comment.
    """
    if EXEMPT_MARKER not in line:
        return False
    head = _MARKER_HEAD.match(line[line.index(EXEMPT_MARKER) + len(EXEMPT_MARKER) :])
    named = set(_DEC_TOKEN.findall(head.group(1))) if head else set()
    wanted = set(_DEC_TOKEN.findall(str(rule["dec"])))
    return bool(named & wanted)


def _offending_lines(rule: dict) -> list[str]:
    """Every in-scope line carrying the dead claim, minus exempted and allowed ones."""
    allowed = set(rule.get("allow") or [])
    hits: list[str] = []
    for path in SCOPE:
        rel = str(path.relative_to(REPO_ROOT))
        if rel in allowed:
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if rule["pattern"] not in line:
                continue
            if _exempted(line, rule):  # visible, reviewable exception — for THIS rule's DEC
                continue
            if f"{rel}:{lineno}" in allowed:
                continue
            hits.append(f"{rel}:{lineno}: {line.strip()[:150]}")
    return hits


def test_scope_is_not_empty_and_excludes_history():
    """The scoping is load-bearing: if it silently caught nothing, every rule would pass."""
    assert SCOPE, "no forward-looking artifacts matched — the include globs are wrong"
    names = {p.name for p in SCOPE}
    assert "DECISIONS.md" not in names and "INBOX.md" not in names
    assert not [p for p in SCOPE if p.name.endswith((".report.md", ".review.md", ".audit.md"))]


def test_every_rule_is_well_formed():
    seen: set[str] = set()
    for rule in _rules:
        for field in ("id", "dec", "status", "pattern", "reason"):
            assert rule.get(field), f"rule {rule.get('id')!r} is missing {field}"
        assert rule["status"] in ("fixed", "open"), rule["id"]
        assert rule["id"] not in seen, f"duplicate rule id {rule['id']}"
        seen.add(rule["id"])


@pytest.mark.parametrize(
    "rule",
    [r for r in _rules if r["status"] == "fixed"],
    ids=lambda r: r["id"],
)
def test_fixed_claim_has_not_reappeared(rule):
    """Hard assertion. This is the guard the project did not have."""
    hits = _offending_lines(rule)
    assert not hits, (
        f"\n{rule['dec']} superseded this claim, and it is back in a forward-looking document."
        f"\n  pattern: {rule['pattern']!r}"
        f"\n  reason : {rule['reason']}"
        f"\n  found  :\n    "
        + "\n    ".join(hits)
        + "\n\n  Fix the document. If the mention is legitimate, put"
        f" '<!-- {EXEMPT_MARKER} {rule['dec']} why -->' on that line."
    )


@pytest.mark.parametrize(
    "rule",
    [r for r in _rules if r["status"] == "open"],
    ids=lambda r: r["id"],
)
@pytest.mark.xfail(reason="known propagation debt, tracked in superseded.yaml", strict=False)
def test_open_claim_still_present(rule):
    """xfail so the suite stays green while the backlog burns down.

    An open rule that PASSES is an xpass: the debt is gone and the row should be
    flipped to `status: fixed`, which turns it into a regression guard.
    """
    hits = _offending_lines(rule)
    assert not hits, f"{rule['dec']}: {rule['reason']}\n  " + "\n  ".join(hits)
