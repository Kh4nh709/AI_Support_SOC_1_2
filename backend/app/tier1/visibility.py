"""The blind-branch filter: one pure function, two modes, applied inside `tier1/queue.py`'s
two readers (never in a template) and imported by P6-T02 for the labelling page.

Context pack §6.4: *the suggestion of ① is removed from any response (all roles) while
`suggestion_visible = false` and the alert is not yet decided* — so the role is not a
parameter here. `strip` rebuilds the dict it is given and never mutates it.

| mode       | when                                                  | drops                                                   | why |
|------------|-------------------------------------------------------|---------------------------------------------------------|-----|
| `analyst`  | `suggestion_visible` is false **and** `status` is not in `SHOW_STATES` | `ANALYST_HIDE` at the **top level** only | the blind arm: the analyst may know they are on it (`suggestion_visible` stays) but not what the model said; `triage_status` goes too because "ready"/"unavailable" leaks whether ① produced a verdict, and so does the queue row's top-level `run_id` — a blind row must not even say "① ran" (DEC-101). `triaged_count` and `needs_retriage` go for the same reason (R17): ① is the only first-time writer of `triaged_count`, so a count that ticks or a ⟳ that lights up says "① just ran" — and the queue's sort key ignores `needs_retriage` for such a head, or the row's move to the top would say it. `llm_stopped_by` (INT-T02, the alert view's reason ① gave up) goes with them: "gave up because the provider refused" says ① ran. `proposed_action` and `held_by` (P14-T03, DEC-213: the model's own answer and the reasons the gate held it) go with them: they are ①'s verdict by another name. `rag` (P14-T07: the match percentage and the "RAG not applied" notice beside that verdict) goes with them. Nested `correlation` rows keep their `status` — that is *other* clusters' history, which an analyst may see. |
| `analyst`  | otherwise (visible arm, or already decided)           | nothing — an equal copy                                 | once decided, the ① verdict is evaluation material (P8's agreement metric); `auto_closed` is in `SHOW_STATES` because D8's digest (P5) reviews auto-closed clusters *against* ①. A reopened alert (A17 → `queued_tier1`) is blind again. |
| `labeling` | **always**, whatever the two flags say                | `LABELING_DENYLIST` and every key starting with one of `LABELING_PREFIXES`, **recursively** through nested dicts and lists | `source` — DEC-019: `replay` vs `wazuh` lets a labeller infer the storm day; `status` — a pilot decision (a correlated cluster's `closed_fp` too) is human context the labeller must reach on their own; the rest is LLM-derived (`suggestion`, `gate*`, `verifier*`, `llm_*`, `run_id`; `triaged_count`/`needs_retriage` say how often ① ran — DEC-101) or enrichment (`risk_*`, `*_context`, `lookup_status`, and the SIEM's SOAR blob `soar` — its triage score and signal text, planned action and scenario say what the SIEM thinks of the alert, S3) the labeller must not be primed with. `soar` is **not** in `ANALYST_HIDE`: it says nothing about ①, so a blind undecided analyst view keeps it. |
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal

#: Once an alert is here, the ① verdict may be shown to everyone (planning decision 7).
#: `archived` (INT-T03, DEC-212: the old queue closed out without review) is deliberately NOT here:
#: nobody decided that alert, so there is no decision for the verdict to be evaluation material of, and
#: archiving a blind head must not reveal what ① said about it. It stays hidden like `queued_tier1`.
SHOW_STATES: frozenset[str] = frozenset(
    {"closed_fp", "closed_benign", "closed_confirmed", "escalated_tier2", "auto_closed"}
)

#: The keys a blind, undecided head loses in analyst mode — the ① verdict and everything
#: that would let an analyst infer it, including that ① ran at all (`run_id`, DEC-101).
#: R17: `triaged_count` and `needs_retriage` are on the list too — ① is the only first-time
#: writer of `triaged_count` (`tier1/triage.py`, +1 per run) and `needs_retriage` is computed
#: from it, so on a blind head a counter that ticks or a ⟳ that lights up says "① just ran",
#: the very thing the alerts NOTIFY trigger (migration 018, R12) is silent about. The queue's
#: sort key leaves `needs_retriage` out for such a head too (`queue._NEEDS_RETRIAGE_SORT_SQL`).
#: INT-T02 (DEC-211 R6): `llm_stopped_by`, the alert view's reason ① gave up (`llm_runs.stopped_by`
#: of the newest proposer run), is on the list for the reason `triage_status` is: "① gave up, because
#: the provider refused" says that ① ran. It also starts with `llm_`, so the labelling page drops it
#: by `LABELING_PREFIXES` even without this entry.
#: P14-T03 (DEC-213): `proposed_action`, the answer the model itself gave (``gate_result.proposed_verdict``),
#: and `held_by`, the closed reasons the system held it back (``llm.verdicts.held_reasons``), are on the list
#: because they ARE ①'s verdict: "AI kết luận: TP, held because ..." says what ① concluded even when
#: `suggested_action` is gone. Neither starts with `llm_`, so unlike `llm_stopped_by` the labelling page drops
#: them by this entry alone (`LABELING_DENYLIST` includes the set).
#: P14-T07 (DEC-213): `rag`, `{"best_pct", "not_applied"}` (`llm.rag_view`), is on the list too: "trùng 87% với tri
#: thức đã duyệt" and "không áp dụng RAG" are said beside ①'s conclusion and are what ① was shown (or not shown)
#: when it concluded, so on a blind, undecided head they would say that ① ran and on what. Like the two keys above
#: it does not start with `llm_`: the labelling page drops it by this entry alone.
ANALYST_HIDE: frozenset[str] = frozenset(
    {
        "suggestion",
        "suggested_action",
        "confidence",
        "gate_forced",
        "triage_status",
        "run_id",
        "triaged_count",
        "needs_retriage",
        "llm_stopped_by",
        "proposed_action",
        "held_by",
        "rag",
    }
)

#: Everything a labeller must never receive, at any depth (module docstring, row 3).
LABELING_DENYLIST: frozenset[str] = ANALYST_HIDE | frozenset(
    {
        "suggestion_visible",
        "source",
        "status",
        "risk_score",
        "risk_band",
        "risk_score_components",
        "asset_context",
        "identity_context",
        "ioc_context",
        "lookup_status",
        "case_id",
        "soar",
        "autoclose_rule_id",
        "acknowledged_at",
        "acknowledged_by",
        "acknowledged_by_name",
        "closed_at",
        "sealed_at",
        "close_reason",
        "duplicate_of",
        "gate_result",
        "verifier_result",
        "llm_run_id",
        "run_id",
        "gate",
        "correlated_at_analysis",
        "triaged_count",
        "needs_retriage",
    }
)

#: Any key starting with one of these is dropped in labeling mode, at any depth.
LABELING_PREFIXES: tuple[str, ...] = ("llm_", "verifier")

Mode = Literal["analyst", "labeling"]


def is_decided(status: str) -> bool:
    """Whether `status` is one the ① verdict may be shown in (P4-T05's template logic)."""
    return status in SHOW_STATES


def _denied_for_labeling(key: Any) -> bool:
    return key in LABELING_DENYLIST or (isinstance(key, str) and key.startswith(LABELING_PREFIXES))


def _scrub(value: Any) -> Any:
    """Labeling mode's walk: dicts lose denylisted and prefixed keys and are recursed
    into; lists and tuples are recursed into item by item; scalars come back as they are."""
    if isinstance(value, Mapping):
        return {k: _scrub(v) for k, v in value.items() if not _denied_for_labeling(k)}
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_scrub(item) for item in value)
    return value


def strip(
    view: Mapping[str, Any],
    *,
    status: str,
    suggestion_visible: bool,
    mode: Mode,
) -> dict[str, Any]:
    """A **new** dict with what `mode` allows (module docstring table). `view` is never
    mutated. The two flags are the head's own `status` and `suggestion_visible`; labeling
    mode ignores both — the labeller never gets the ① keys whatever the arm.

    A falsy `suggestion_visible` (including `None`, should a caller ever pass one) hides:
    the filter fails closed."""
    if mode == "analyst":
        if not suggestion_visible and status not in SHOW_STATES:
            return {k: v for k, v in view.items() if k not in ANALYST_HIDE}
        return dict(view)
    if mode == "labeling":
        return _scrub(view)
    raise ValueError(f"mode must be 'analyst' or 'labeling', got {mode!r}")
