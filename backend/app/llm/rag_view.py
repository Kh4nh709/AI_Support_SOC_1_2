"""What the alert page and the case page say of the RAG beside the AI's conclusion (P14-T07, DEC-213, spec §4.3).

One set of values, the same on both pages: `{"best_pct": int | None, "not_applied": str | None,
"below_floor_pct": int | None, "floor_pct": int | None}`. The last two are DEC-220's (trial; the spec is
`docs/superpowers/specs/2026-11-15-rag-below-floor-percentage.md`).

* **`best_pct`** is how strongly the alert (or case) matched approved knowledge: the highest
  `round(score * 100)` among the `matches` of the lookup the run's prompt held (`llm_runs.rag_lookup_id`; the
  readers fetch that `rag_results.matches` in the statement that reads the run). The formula is `Match.pct`'s
  and the prompt fact `trung_pct`'s (`rag/match.py`): the page, the prompt and the admin page say one number,
  and `tests/test_rag_view.py` holds the two copies equal. `None` when the run holds no lookup or the lookup
  kept no match, and when ①'s token budget dropped the entries and kept only the decision history (the run
  then still names its lookup, but none of its matches reached the prompt; the run's `citation_warnings` carry
  `learned_entries_dropped`, P14 final fix wave M2).
* **`not_applied`** is the closed failure kind of the `rag_not_applied:<kind>` warning ① and ② put in the run's
  `citation_warnings` when the newest lookup of their subject failed and the learned section was left out
  (`llm.builder.rag_not_applied_warning`). Only a kind of `rag.failures.FAILURE_KINDS` leaves: `llm` may not
  import `rag`, so the readers (`tier1.queue`, `tier2.investigation_view`, which may) hand the list in as
  `kinds`. Anything else - a warning from a build that knew a seventh kind, a string a provider might have
  shaped - is `None`; the page then says nothing rather than something it cannot vouch for. (A `failed` lookup
  row with no stored kind is not such a case: `rag.lookup.lookup_failure` reads it as `UNKNOWN_FAILURE_KIND`,
  `provider_error`, so ① and ② warn with that closed kind and the pages word it.) The provider's own words are
  never stored (spec §5.5), so there are none to leave out here.

* **`below_floor_pct`** is the percentage of the best candidate the rerank scored, for a run whose lookup kept no
  match: the highest score among the `ranked` of the lookup the run held (`rag_results.ranked`,
  `[{entry_id, score}]`, every candidate scored, best first; the readers fetch it with the `matches`), under the
  same `score` rule as every other number here, **cut down** (`under_floor_pct`), not rounded (DEC-221, spec
  `2026-11-15-ai-analysis-panel-redesign.md` section 5): a raw 0.4999 is 49, so the number printed under the
  floor is always below `floor_pct`. `best_pct` of a kept match keeps `percent` (`round`). It is `None` when the lookup kept a match (`matches` holds one:
  `best_pct` is then the number, whether or not the budget dropped its entries - the two are never both set), when
  no candidate has a score, when the run names no lookup, and when the lookup failed (`not_applied` says so). It is
  also `None` when the best score is not under `floor`: the configuration's floor may have moved since the lookup
  ran, and a candidate the lookup would now keep is not "below the floor".
* **`floor_pct`** is `percent(floor)`, `floor` being `RAG_MIN_SCORE` of the running configuration; set exactly when
  `below_floor_pct` is, else `None`. `llm` may not import `rag` and takes plain values, so the readers hand the
  floor in.

The RAG rule (DEC-219; two-sided since DEC-225: `tier1.triage._rag_top_item`, `gate_result.rag_rule`) compares the
number this page prints for the run - `best_pct` of a kept match, else `below_floor_pct` of the best scored candidate -
and reads the side of that single top item (`top_entry_ids` below names it); `tests/test_rag_rule_db.py` pins the
rule's `best_pct` against these numbers. Tier 1 is not told that a rule exists: the page shows the percentage and
nothing of what decided the verdict.

The module reads values and builds no markup. The blind arm (DEC-101) is `tier1/visibility.py`'s: `rag` is an
`ANALYST_HIDE` key, because "trùng 87%" and "RAG not applied" say something about what ① was shown.
"""

from __future__ import annotations

import math
from collections.abc import Collection, Mapping
from typing import Any

from app.llm.builder import LEARNED_ENTRIES_DROPPED_WARNING, RAG_NOT_APPLIED_PREFIX


def percent(score: float) -> int:
    """`round(score * 100)`: how `rag.match.Match.pct` and the prompt's `trung_pct` say a relevance score."""
    return round(score * 100)


def score(item: Any) -> float | None:
    """The `score` of one stored item (a match of `rag_results.matches`, an entry of `rag_results.ranked`): a
    number in [0, 1], else `None` (a match written before T06 carries none; a bool, a string, NaN or a value
    outside the range is not a score). Public: the admin page reads the rerank's list through it, so there is one
    rule and no copy."""
    if not isinstance(item, Mapping):
        return None
    value = item.get("score")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value) or not 0 <= value <= 1:
        return None
    return float(value)


def cut_percent(score: float) -> int:
    """`score * 100` cut down to a whole number (`floor`), after the floating-point noise is rounded away:
    0.29 * 100 is 28.999999999999996, and it is 29 that the reranker returned."""
    return math.floor(round(score * 100, 9))


def under_floor_pct(score: float, floor: float) -> int:
    """The percentage of a candidate that scored under `floor` (DEC-221): cut down, not rounded, so that it is below
    `percent(floor)` - the number the page prints beside it. The `min` keeps that true for a floor that is not a
    whole percent (0.505 prints as 50): the number is at most one under the floor's own."""
    return min(cut_percent(score), max(percent(floor) - 1, 0))


def best_pct(matches: Any) -> int | None:
    """The highest percentage among a lookup's stored `matches` (`[{entry_id, level, content_sha256, score}]`),
    or `None` when there is no list or no match with a score."""
    if not isinstance(matches, list):
        return None
    pcts = [percent(found) for found in map(score, matches) if found is not None]
    return max(pcts, default=None)


def not_applied(warnings: Any, kinds: Collection[str]) -> str | None:
    """The kind of the first `rag_not_applied:<kind>` warning whose `<kind>` is one of `kinds`, else `None`."""
    if not isinstance(warnings, list):
        return None
    for warning in warnings:
        if isinstance(warning, str) and warning.startswith(RAG_NOT_APPLIED_PREFIX):
            kind = warning[len(RAG_NOT_APPLIED_PREFIX) :]
            if kind in kinds:
                return kind
    return None


def entries_dropped(warnings: Any) -> bool:
    """Whether the run's `citation_warnings` say the token budget dropped the learned entries (①'s first cut)."""
    return isinstance(warnings, list) and LEARNED_ENTRIES_DROPPED_WARNING in warnings


def below_floor_pct(
    matches: Any, ranked: Any, warnings: Any, kinds: Collection[str], floor: Any
) -> int | None:
    """DEC-220: the percentage of the best candidate of `ranked` (the lookup's stored `rag_results.ranked`) when
    the lookup kept no match and that candidate scored under `floor`, else `None` (module doc). DEC-221: cut down
    (`under_floor_pct`), never rounded up to the floor."""
    if not _is_score(floor) or not isinstance(ranked, list):
        return None
    if isinstance(matches, list) and matches:
        return None  # the lookup kept a match: `best_pct` is the number
    if not_applied(warnings, kinds) is not None:
        return None  # the lookup failed
    best = max((found for found in map(score, ranked) if found is not None), default=None)
    if best is None or not best < floor:
        return None
    return under_floor_pct(best, floor)


def _is_score(value: Any) -> bool:
    """A real number in [0, 1]: what a stored `score` must be, and so what a floor handed in must be."""
    return score({"score": value}) is not None


def rag_view(
    matches: Any,
    warnings: Any,
    kinds: Collection[str],
    *,
    ranked: Any = None,
    floor: Any = None,
) -> dict[str, int | str | None]:
    """`{"best_pct", "not_applied", "below_floor_pct", "floor_pct"}` of one run: `matches` is the stored `matches`
    of the lookup the run held (`None` when it held none), `warnings` the run's `citation_warnings`, `kinds`
    `rag.failures.FAILURE_KINDS`. No percentage when the run's budget cut dropped the entries (`entries_dropped`).
    `ranked` is the stored `ranked` of that same lookup and `floor` `RAG_MIN_SCORE` (DEC-220); without them the
    last two keys are `None`, so a caller that asks for `best_pct` alone (`tier1.triage`) is as it was. A new dict
    on every call."""
    below = below_floor_pct(matches, ranked, warnings, kinds, floor)
    return {
        "best_pct": None if entries_dropped(warnings) else best_pct(matches),
        "not_applied": not_applied(warnings, kinds),
        "below_floor_pct": below,
        "floor_pct": None if below is None else percent(floor),
    }


# ── the panel (DEC-221, AP-T2): the Tier 1 alert view's `analysis.rag`, and the case view's later ──────────────

#: What `rag_panel` calls a run's RAG standing, in the order the spec lists them (`2026-11-15-ai-analysis-panel-
#: redesign.md` section 5): `matched` (the lookup kept a match, so one at or over the floor), `below_floor` (it scored
#: candidates and none reached the floor), `no_candidate` (it ran and scored nothing that counts), `failed` (the closed
#: kind is `failure`), `no_lookup` (the run holds no lookup: RAG off, none usable, or the budget cut its entries). A
#: literal on purpose: the page words each one, and `tests/test_rag_panel.py` pins it.
STATES: tuple[str, ...] = ("matched", "below_floor", "no_candidate", "failed", "no_lookup")
#: How many of the ranking's best candidates the panel lists.
CANDIDATES_SHOWN = 3
_RANKED_STATES = frozenset({"matched", "below_floor", "no_candidate"})


def _ranking(items: Any) -> list[tuple[str | None, float]]:
    """`(entry_id, score)` of each item of a stored list (`matches`, `ranked`) that has a score, best first, ties in
    the stored order. The id is `None` when the item has none that is a string: it was scored and is not listed.
    """
    if not isinstance(items, list):
        return []
    found: list[tuple[str | None, float]] = []
    for item in items:
        value = score(item)
        if value is not None:
            entry = item.get("entry_id")
            found.append((entry if isinstance(entry, str) else None, value))
    return sorted(found, key=lambda pair: -pair[1])


def top_entry_ids(items: Any) -> list[str | None]:
    """The `entry_id`s of the single top item of a stored list (the kept `matches`, or the scored `ranked`), for the
    RAG rule (DEC-225): the items that share the highest valid `score` (the same `score` rule as every number on this
    page, so the maximum is the one `best_pct` and `below_floor_pct` print), in stored order, each entry once. One
    entry in practice; two or more when scores tie exactly, and the rule then decides between their sides. An item
    whose `entry_id` is not text is listed as `None`: it is the top item and cannot be named, so the caller must not
    read the next best in its place. Empty when there is no list or no item with a valid score."""
    ranking = _ranking(items)
    if not ranking:
        return []
    top = ranking[0][1]
    ids: list[str | None] = []
    for entry, value in ranking:
        if value != top:
            break
        if entry not in ids:
            ids.append(entry)
    return ids


def _candidate_pct(value: float, floor: Any) -> int:
    """A listed candidate's percentage: cut down when it scored under the floor (`under_floor_pct`, so the list and
    `best_pct` say one number for the best of them), `percent` otherwise."""
    return under_floor_pct(value, floor) if _is_score(floor) and value < floor else percent(value)


def rag_panel(
    matches: Any,
    warnings: Any,
    kinds: Collection[str],
    *,
    ranked: Any = None,
    floor: Any = None,
    threshold: Any = 0,
) -> dict[str, Any]:
    """The RAG standing of one run for the analysis panel: `{"state", "failure", "best_pct", "floor_pct",
    "threshold_pct", "scored", "candidates"}`. The arguments are `rag_view`'s (the stored `matches` and `ranked` of
    the lookup the run held, the run's `citation_warnings`, `rag.failures.FAILURE_KINDS`, `RAG_MIN_SCORE`) and a
    `threshold` (0 = none; anything that is not a positive integer is 0). Since DEC-225 no reader passes one: Tier 1
    is not told that the RAG rule exists (its `gate_result.rag_rule.threshold` is not served) and ② has no such rule,
    so `threshold_pct` is 0 on both pages; the parameter and the key stay for the shape both pages share.

    * `state` is one of `STATES`; `failure` is the closed kind when it is `failed`, else `None`.
    * `best_pct` is the number the page shows for the run: the best kept match (`rag_view`'s `best_pct`) when
      `matched`, the best candidate under the floor (its `below_floor_pct`, DEC-220, cut down) when `below_floor`,
      else `None` - never a number the pair does not give for the same run.
    * `floor_pct` is `percent(floor)` for a run whose lookup has a ranking to compare it with (`matched`,
      `below_floor`, `no_candidate`), else `None`. `scored` is how many items of the ranking carry a valid score
      (`None` for `failed` and `no_lookup`).
    * `candidates` is the top `CANDIDATES_SHOWN` of the ranking (the lookup's `ranked`; its kept `matches` for a
      lookup stored without one) as `{"entry_id", "pct"}` for `matched` and `below_floor`, else `[]`. An entry's title
      and conclusion are a database read the caller does (`rag.entries.entry_cards`); `llm` may not import `rag`.

    Entries the token budget dropped never reached the prompt, so such a run is `no_lookup` and lists nothing: the
    DEC-213 pair gives it no number either. Pure: it reads only its arguments and builds new objects.
    """
    pair = rag_view(matches, warnings, kinds, ranked=ranked, floor=floor)
    has_lookup = isinstance(matches, list) or isinstance(ranked, list)
    if pair["not_applied"] is not None:
        state = "failed"
    elif entries_dropped(warnings):
        state = "no_lookup"
    elif isinstance(matches, list) and matches:
        state = "matched"
    elif pair["below_floor_pct"] is not None:
        state = "below_floor"
    elif has_lookup:
        state = "no_candidate"
    else:
        state = "no_lookup"

    ranking = (_ranking(ranked) or _ranking(matches)) if state in _RANKED_STATES else []
    best = None
    if state == "matched":
        best = pair["best_pct"]
    elif state == "below_floor":
        best = pair["below_floor_pct"]
    listed = state in ("matched", "below_floor")
    threshold_ok = isinstance(threshold, int) and not isinstance(threshold, bool) and threshold > 0
    return {
        "state": state,
        "failure": pair["not_applied"] if state == "failed" else None,
        "best_pct": best,
        "floor_pct": percent(floor) if state in _RANKED_STATES and _is_score(floor) else None,
        "threshold_pct": threshold if threshold_ok else 0,
        "scored": len(ranking) if state in _RANKED_STATES else None,
        "candidates": (
            [
                {"entry_id": entry, "pct": _candidate_pct(value, floor)}
                for entry, value in ranking
                if entry is not None
            ][:CANDIDATES_SHOWN]
            if listed
            else []
        ),
    }
