"""What the alert page and the case page say of the RAG beside the AI's conclusion (P14-T07, DEC-213, spec §4.3).

One pair of values, the same on both pages: `{"best_pct": int | None, "not_applied": str | None}`.

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


def rag_view(matches: Any, warnings: Any, kinds: Collection[str]) -> dict[str, int | str | None]:
    """`{"best_pct", "not_applied"}` of one run: `matches` is the stored `matches` of the lookup the run held
    (`None` when it held none), `warnings` the run's `citation_warnings`, `kinds` `rag.failures.FAILURE_KINDS`.
    No percentage when the run's budget cut dropped the entries (`entries_dropped`). A new dict on every
    call."""
    return {
        "best_pct": None if entries_dropped(warnings) else best_pct(matches),
        "not_applied": not_applied(warnings, kinds),
    }
