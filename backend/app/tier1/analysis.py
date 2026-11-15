"""The `analysis` object of the Tier 1 alert view: everything the system knows about ①'s newest run, in the shape the
AI analysis panel is drawn from (DEC-221, card AP-T2; spec `docs/superpowers/specs/2026-11-15-ai-analysis-panel-
redesign.md` section 5). PURE: `build` reads one stored run, the alert's MITRE ids, the RAG floor and a function that
reads knowledge entries, and returns a new dict. It writes nothing, asks no model, and has no input the model's words
could steer: the highlights are built from stored system facts, the history, the RAG standing and the gate's
outcomes, never from the model's text.

    {"summary", "reading_attack", "reading_benign", "would_change", "next_checks",      the model's five texts
     "reasons": [{claim, quote, source, verified, why}],                               every reason, in its order
     "facts": [{field, system, model, match}],                                          the five fields step 2 compares
     "checks": [{id, outcome, detail}], "check_totals": {passed, applicable, warnings}, the gate steps and the tile
     "rag": {state, failure, best_pct, floor_pct, threshold_pct, scored, candidates},   `llm.rag_view.rag_panel` + entries
     "history": {key, total, by_conclusion, last_seen} | None,
     "playbook": {name, rule_id, rule_action},                                          the decision table, today
     "highlights": [{direction, code, params}],                                         at most four, server-built
     "tech": {input_tokens, output_tokens, latency_ms, cost_usd, analysed_at, mitre_ids, correlated_at_analysis}}

**The model's name is not an input.** `StoredRun` has no model column and the statement that feeds it
(`queue._SUGGESTION_SQL`) does not select one (the Owner's requirement, goal G5: the model's name appears nowhere in
what the Tier 1 pages are served).

**The model-written text is served as text and never fed back.** `summary`, `reading_attack`, `reading_benign`,
`would_change` and `next_checks` are the model's words about untrusted data (spec section 4): this module returns them
to a page and imports nothing that builds a prompt. `tests/test_panel_readers.py` lists the modules of `backend/app`
that may name them, and this one is on that list deliberately.

**A run the RAG default applied to (DEC-219, `gate_result.rag_rule.applied` is the JSON `true`)** is served nothing
that states or gives away the model's own verdict or confidence: no `reading_attack`, `reading_benign`,
`would_change` (`None`), no model column of `facts` (`None`, and `match` `None`), no verifier row (step 6 is left out
of `checks` and does not count in `check_totals`, so no highlight is derived from it), and the rule's `changed` is
never read. `summary`, `next_checks`, `reasons`, the system facts, `rag`, `history`, `playbook` and `tech` are
served. `tests/test_analysis_view.py` holds this with a pair of runs that differ in everything the model's answer
touches and must give the same analysis.

**A stored document of any age gives an analysis, never an error.** A version 1 `gate_result` (before DEC-217: no
`flagged_by`, no `rag_rule`), a version 3 result (before version 4: none of the five texts), a missing or garbled
`gate_result` all give what they have; a row that cannot be filled is `None` (or `[]`), a check that cannot be read is
`na` with the detail `not_run`.
"""

from __future__ import annotations

import dataclasses
import logging
import re
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from decimal import Decimal
from typing import Any

from app.kb.lookup import apply_table, get_decision_table
from app.llm import rag_view, verdicts
from app.rag.failures import FAILURE_KINDS
from app.rag.history import CONCLUSIONS, LEVELS

#: How many of the model's `next_checks` are served (the schema asks for one to three; a longer list is cut).
NEXT_CHECKS_SHOWN = 3
#: How many of the model's reasons are served: the first ten items of its answer, like `Suggestion.reasons`
#: (`queue._suggestion_of`), so the two lists cannot disagree about where they stop.
REASONS_SHOWN = 10
#: How many highlights are served, at most.
HIGHLIGHTS_SHOWN = 4

#: The gate steps that have a row, in step order. Step 7 (the output guard) is not a check of the run.
CHECK_IDS: tuple[str, ...] = ("1", "2", "3", "3r", "4", "5", "6")
CHECK_OUTCOMES: tuple[str, ...] = ("pass", "warn", "na")
#: Every `detail` a check row can carry, grouped by step in step order and ending with the one for a step that left no
#: record. The page words each one; a literal on purpose, pinned by `tests/test_analysis_view.py` the way
#: `llm.verdicts.HELD_REASONS` is. `outcome` is `pass` for the ones that say it passed, `warn` for the ones that
#: flag the run (they match `llm.verdicts.held_reasons`, plus the detector's findings) and `na` for the ones that say
#: the check did not apply or did not run.
CHECK_DETAILS: tuple[str, ...] = (
    "schema_ok",  # step 1, pass
    "schema_repaired",  # step 1, pass: the first answer needed the repair round
    "facts_match",  # step 2, pass
    "facts_mismatch",  # step 2, warn
    "quotes_verified",  # step 3, pass
    "quotes_some_dropped",  # step 3, pass: at least one quote verified, some did not
    "no_verified_quote",  # step 3, warn
    "rag_rule_applied",  # step 3r, pass: the RAG default applied (whether or not it changed an answer)
    "rag_rule_not_applied",  # step 3r, na: the rule is on and did not apply
    "rag_rule_off",  # step 3r, na: the rule is off (threshold 0), or the document has none
    "fp_policy_ok",  # step 4, pass
    "fp_policy_facts",  # step 4, warn: a fact forbids a false positive (and maybe the playbook too)
    "fp_policy_playbook",  # step 4, warn: only the playbook's rule check failed
    "not_false_positive",  # step 4, na: the policy is checked for a false positive only
    "no_injection_findings",  # step 5, pass
    "injection_findings",  # step 5, warn
    "verifier_agrees",  # step 6, pass
    "verifier_disagrees",  # step 6, warn
    "verifier_invalid",  # step 6, warn
    "not_run",  # any step, na: the document records nothing for it
)

#: The fields the gate's step 2 compares, in a fixed order: `gate._STEP2_STRING_FIELDS` and then the count.
FACT_FIELDS: tuple[str, ...] = (
    "severity",
    "ioc_reputation",
    "asset_criticality",
    "identity_privileged",
    "occurrence_count",
)

#: Why a reason's quote was not verified: the closed codes of step 3's `dropped_reasons`, in its order.
REASON_WHY: tuple[str, ...] = ("not_substring", "unknown_source", "empty_quote")

#: `up` raises the suspicion (towards `true_positive`), `down` lowers it (towards `false_positive`), `warn` is a
#: caution that points neither way.
HIGHLIGHT_DIRECTIONS: tuple[str, ...] = ("up", "down", "warn")
#: Every `code` a highlight can carry, in the order they are served (the first `HIGHLIGHTS_SHOWN` that apply): the
#: history's majority, the system facts that matter, the RAG standing, then each warning named after its check's
#: `detail`. Closed and pinned; the page words each one. `params` per code: `history_*` `{count, total}`;
#: `rag_matched` `{pct, conclusion}`; `rag_below_floor` `{pct, floor_pct}`; `rag_failed` `{failure}`; every other `{}`.
HIGHLIGHT_CODES: tuple[str, ...] = (
    "history_incident",
    "history_benign",
    "identity_privileged",
    "asset_high",
    "asset_unknown",
    "severity_critical",
    "rag_matched",
    "rag_below_floor",
    "rag_failed",
    "warning_facts_mismatch",
    "warning_no_verified_quote",
    "warning_fp_policy_facts",
    "warning_fp_policy_playbook",
    "warning_injection_findings",
    "warning_verifier_disagrees",
    "warning_verifier_invalid",
)

#: The history's conclusions that count as "closed as not an attack" for the majority highlight.
_BENIGN_CONCLUSIONS = ("tier1_closed_fp", "tier1_closed_benign", "concluded_fp")
#: A knowledge entry's conclusion -> the direction a kept match points.
_UP_ENTRY_CONCLUSIONS = frozenset({"confirmed_incident"})
_DOWN_ENTRY_CONCLUSIONS = frozenset({"closed_fp", "closed_benign", "concluded_fp"})

_LEVEL_NAMES = frozenset(name for _level, name in LEVELS)
#: A category is a closed token (`llm.builder.Category`); anything else is never turned into a file name.
_CATEGORY = re.compile(r"[a-z0-9_]+")
_COUNT_AFTER = re.compile(r"(?:dropped|findings):(\d+)")

logger = logging.getLogger(__name__)

#: `(entry ids) -> {entry id: (title, conclusion)}`; an id with no entry is absent (`rag.entries.entry_cards`).
CardReader = Callable[[Sequence[str]], Mapping[str, tuple[str | None, str | None]]]


@dataclasses.dataclass(frozen=True)
class StoredRun:
    """The columns of the newest ① proposer run (`queue._SUGGESTION_SQL`) the analysis reads, and no others: there is
    no model column (goal G5). `matches`, `ranked` and `history` are the stored JSON of the lookup the run's prompt
    held (`None` when it held none)."""

    result: Any
    gate_result: Any
    created_at: datetime
    citation_warnings: Any
    matches: Any
    ranked: Any
    history: Any
    input_tokens: Any
    output_tokens: Any
    latency_ms: Any
    cost_usd: Any
    #: The same four columns of the run's verifier row (the row whose `gate_result.proposer_run_id` names the run;
    #: `queue._SUGGESTION_SQL` sums them), `None` when there is none. `tech` is the sum of the two.
    verifier_input_tokens: Any = None
    verifier_output_tokens: Any = None
    verifier_latency_ms: Any = None
    verifier_cost_usd: Any = None


# ── small readers: a stored document is data, and a garbled one gives less ─────────────────────────────────────


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _text(value: Any) -> str | None:
    """A model-written text: a string with something in it, else None. Served as it was stored."""
    return value if isinstance(value, str) and value.strip() else None


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _is_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _scalar(value: Any) -> str | int | None:
    """A fact as the gate compares it: a string (a JSON boolean as its closed string) or an integer, else None."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return value if isinstance(value, (str, int)) else None


def _count_in(status: Any) -> int | None:
    """N of a step status `dropped:N` or `findings:N`, else None."""
    found = _COUNT_AFTER.fullmatch(status) if isinstance(status, str) else None
    return int(found.group(1)) if found else None


# ── the five texts ──────────────────────────────────────────────────────────────────────────────────────────────


def _next_checks(value: Any) -> list[str]:
    """The non-blank strings of the model's list, cut to `NEXT_CHECKS_SHOWN`; `[]` for anything but a list."""
    if not isinstance(value, list):
        return []
    return [item for item in value if _text(item) is not None][:NEXT_CHECKS_SHOWN]


# ── the reasons ─────────────────────────────────────────────────────────────────────────────────────────────────


def _dropped(gate: Mapping[str, Any]) -> dict[int, str]:
    """`{index of the model's reason: why step 3 did not verify it}`: the first record of an index wins, a record
    without an integer index is skipped, a code outside `REASON_WHY` is read as `not_substring`."""
    found: dict[int, str] = {}
    records = gate.get("dropped_reasons")
    for record in records if isinstance(records, list) else []:
        if not isinstance(record, Mapping):
            continue
        index = record.get("index")
        if isinstance(index, bool) or not isinstance(index, int) or index in found:
            continue
        why = record.get("why")
        found[index] = why if isinstance(why, str) and why in REASON_WHY else "not_substring"
    return found


def _reasons(result: Mapping[str, Any], gate: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Every reason of the model's answer in its order (`gate_result.proposer_raw.reasons`, which step 3 did not
    thin out), each with whether its quote was verified and, when it was not, the closed code step 3 recorded. With
    no usable `proposer_raw.reasons` the stored `result.reasons` (step 3's survivors, which is all that is stored) are
    served, each verified by construction. At most `REASONS_SHOWN` items are read, as `Suggestion.reasons` does: the
    first ten of the answer, of which the ones that are not objects are skipped."""
    raw = _mapping(gate.get("proposer_raw")).get("reasons")
    from_raw = isinstance(raw, list)
    items = raw if from_raw else result.get("reasons")
    dropped = _dropped(gate) if from_raw else {}
    rows: list[dict[str, Any]] = []
    for index, item in enumerate(items[:REASONS_SHOWN] if isinstance(items, list) else []):
        if not isinstance(item, Mapping):
            continue
        why = dropped.get(index)
        rows.append(
            {
                "claim": _str(item.get("claim")),
                "quote": _str(item.get("quote")),
                "source": _str(item.get("source")),
                "verified": why is None,
                "why": why,
            }
        )
    return rows


# ── the facts ───────────────────────────────────────────────────────────────────────────────────────────────────


def _facts(gate: Mapping[str, Any], withheld: bool) -> list[dict[str, Any]]:
    """One row per field the gate compares: the system's value (`gate_result.facts`), the model's declared value
    (`proposer_raw.structured_basis`) and whether they match, as step 2 recorded it (`mismatched_fields`). `match` is
    `None` when the two were not compared: the system has no value (a SOAR count), the model declared none, or step 2
    left no record. For a run the RAG default applied to the model column and `match` are `None`."""
    system = _mapping(gate.get("facts"))
    basis = _mapping(_mapping(gate.get("proposer_raw")).get("structured_basis"))
    mismatched = gate.get("mismatched_fields")
    compared = _mapping(gate.get("steps")).get("2") in ("ok", "mismatch") and isinstance(
        mismatched, list
    )
    rows: list[dict[str, Any]] = []
    for field in FACT_FIELDS:
        ours = _scalar(system.get(field))
        theirs = None if withheld else _scalar(basis.get(field))
        match = None
        if compared and ours is not None and theirs is not None:
            match = field not in mismatched  # type: ignore[operator]
        rows.append({"field": field, "system": ours, "model": theirs, "match": match})
    return rows


# ── the checks ──────────────────────────────────────────────────────────────────────────────────────────────────


def _check(check_id: str, outcome: str, detail: str) -> dict[str, str]:
    return {"id": check_id, "outcome": outcome, "detail": detail}


def _step4(steps: Mapping[str, Any], gate: Mapping[str, Any], withheld: bool) -> dict[str, str]:
    """Step 4, the false-positive policy. `missing` is read as the API serves it (`verdicts.served_missing`). For a
    run the RAG default applied to (`withheld`) step 4 is told from the SYSTEM facts only: the playbook condition is
    about the rule the MODEL cited (`gate._step4`: `structured_basis.playbook_rule_applied`), so which rule it cited
    would go with what it answered. It is `fp_policy_facts` (warn) when a fact field is in `missing`, else
    `fp_policy_ok` (pass) - never `fp_policy_playbook`."""
    status = steps.get("4")
    missing = verdicts.served_missing(gate)
    if withheld and status in ("ok", "missing"):
        if any(field in verdicts.FP_FACT_FIELDS for field in missing):
            return _check("4", "warn", "fp_policy_facts")
        return _check("4", "pass", "fp_policy_ok")
    if status == "ok":
        return _check("4", "pass", "fp_policy_ok")
    if status == "missing":
        only_playbook = bool(missing) and all(m == verdicts.PLAYBOOK_RULE_FIELD for m in missing)
        return _check("4", "warn", "fp_policy_playbook" if only_playbook else "fp_policy_facts")
    if status == "n/a" and gate.get("final_verdict") == "true_positive":
        return _check("4", "na", "not_false_positive")
    # `n/a` for a verdict that is not true_positive is a run the pre-DEC-217 gate had already forced
    return _check("4", "na", "not_run")


def _checks(gate: Mapping[str, Any], withheld: bool) -> list[dict[str, str]]:
    """One row per gate step in step order, `{id, outcome, detail}` (`CHECK_DETAILS`). The outcome is read from what
    the gate recorded (`steps`, `flagged_by` or `forced_by`, `missing`, `rag_rule`); a step with no record is `na` /
    `not_run`. For a run the RAG default applied to there is no row 6: the verifier compared its answer with the
    model's own verdict, so its row would give that verdict away."""
    steps = _mapping(gate.get("steps"))
    flagged = verdicts.flagged_steps(gate)
    rows: list[dict[str, str]] = []

    status = steps.get("1")
    if status in ("ok", "repaired"):
        rows.append(_check("1", "pass", "schema_ok" if status == "ok" else "schema_repaired"))
    else:
        rows.append(_check("1", "na", "not_run"))

    status = steps.get("2")
    if status == "mismatch" or "step2" in flagged:
        rows.append(_check("2", "warn", "facts_mismatch"))
    elif status == "ok":
        rows.append(_check("2", "pass", "facts_match"))
    else:
        rows.append(_check("2", "na", "not_run"))

    dropped = _count_in(steps.get("3"))
    if "step3" in flagged:
        rows.append(_check("3", "warn", "no_verified_quote"))
    elif dropped is None:
        rows.append(_check("3", "na", "not_run"))
    else:
        rows.append(
            _check("3", "pass", "quotes_some_dropped" if dropped > 0 else "quotes_verified")
        )

    rule = _mapping(gate.get("rag_rule"))
    threshold = rule.get("threshold")
    if steps.get("3r") in ("applied", "changed") or verdicts.rag_rule_applied(gate):
        # `applied` and `changed` read the same: which of them it was says what the model answered
        rows.append(_check("3r", "pass", "rag_rule_applied"))
    elif _is_count(threshold) and threshold > 0:
        rows.append(_check("3r", "na", "rag_rule_not_applied"))
    else:
        rows.append(_check("3r", "na", "rag_rule_off"))

    rows.append(_step4(steps, gate, withheld))

    findings = _count_in(steps.get("5"))
    if findings is None:
        rows.append(_check("5", "na", "not_run"))
    elif findings > 0:
        rows.append(_check("5", "warn", "injection_findings"))
    else:
        rows.append(_check("5", "pass", "no_injection_findings"))

    if not withheld:
        status = steps.get("6")
        if status == "agree":
            rows.append(_check("6", "pass", "verifier_agrees"))
        elif status == "disagree":
            rows.append(_check("6", "warn", "verifier_disagrees"))
        elif status == "invalid":
            rows.append(_check("6", "warn", "verifier_invalid"))
        else:
            rows.append(_check("6", "na", "not_run"))
    return rows


def _totals(checks: Sequence[Mapping[str, str]]) -> dict[str, int]:
    """The tile's figures, derived from the rows: checks passed, checks that apply (not `na`), warnings."""
    passed = sum(row["outcome"] == "pass" for row in checks)
    warnings = sum(row["outcome"] == "warn" for row in checks)
    return {"passed": passed, "applicable": passed + warnings, "warnings": warnings}


# ── the RAG block, the history, the playbook ────────────────────────────────────────────────────────────────────


def _rag(
    run: StoredRun, gate: Mapping[str, Any], floor: Any, read_cards: CardReader
) -> dict[str, Any]:
    """`llm.rag_view.rag_panel` for the run (the part the case view will call too), with each listed candidate
    `{pct, title, conclusion}`: the entry's title and conclusion are one database read (`read_cards`), made only when
    there is a candidate to list; an entry that is gone is a row with `title` and `conclusion` `None`.
    """
    panel = rag_view.rag_panel(
        run.matches,
        run.citation_warnings,
        FAILURE_KINDS,
        ranked=run.ranked,
        floor=floor,
        threshold=_mapping(gate.get("rag_rule")).get("threshold", 0),
    )
    ids = [candidate["entry_id"] for candidate in panel["candidates"]]
    cards = read_cards(ids) if ids else {}
    candidates = []
    for candidate in panel["candidates"]:
        card = cards.get(candidate["entry_id"])
        title, conclusion = card if isinstance(card, tuple) and len(card) == 2 else (None, None)
        candidates.append({"pct": candidate["pct"], "title": title, "conclusion": conclusion})
    return {**panel, "candidates": candidates}


def _valid_iso(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return None
    return value


def _history(raw: Any) -> dict[str, Any] | None:
    """The lookup's stored decision history as `{key, total, by_conclusion, last_seen}`, or None when it holds none
    (no object, or a total that is not a positive count). `by_conclusion` has all six of `rag.history.CONCLUSIONS`,
    0 where the store has no count; `key` is the name of one of the six levels, or None; `last_seen` is the stored
    ISO time, or None when it does not parse. The examples (alert ids) are not served."""
    if not isinstance(raw, Mapping):
        return None
    total = raw.get("total")
    if not _is_count(total) or total <= 0:
        return None
    counts = _mapping(raw.get("by_conclusion"))
    key = raw.get("key_name")
    return {
        "key": key if isinstance(key, str) and key in _LEVEL_NAMES else None,
        "total": total,
        "by_conclusion": {
            name: counts[name] if _is_count(counts.get(name)) else 0 for name in CONCLUSIONS
        },
        "last_seen": _valid_iso(raw.get("last_seen")),
    }


def _playbook(gate: Mapping[str, Any]) -> dict[str, str | bool | None]:
    """`{name, rule_id, rule_action, rule_table_reviewed}`: the playbook of the run's category (the decision table's
    `playbook`), the first rule of that table which holds against the facts the run stored (`kb.lookup.apply_table`,
    which ignores the table's review state on purpose) and whether that table is signed today
    (`rule_table_reviewed`, so the page can say that the matching rule comes from an unsigned table). All `None` when
    the category has no table; the rule is `None` when none holds.

    The decision table is a file the Owner edits: reading it is a boundary, and ANY failure there - a malformed file
    (`rules: 5` makes `kb.lookup.get_decision_table` raise a plain `TypeError`, an empty playbook an `IndexError`),
    an unreadable one, a table `apply_table` cannot compare the facts with - gives the all-`None` playbook and a log
    line (the exception's type and the category, never its text), never an error on the alert view.
    """
    nothing: dict[str, str | bool | None] = {
        "name": None,
        "rule_id": None,
        "rule_action": None,
        "rule_table_reviewed": None,
    }
    category = _mapping(gate.get("facts")).get("category")
    if not isinstance(category, str) or not _CATEGORY.fullmatch(category):
        return nothing
    try:
        table = get_decision_table(category)
        if table is None:
            return nothing
        rule = apply_table(table, _mapping(gate.get("facts")))
        return {
            "name": table.playbook,
            "rule_id": None if rule is None else rule[1],
            "rule_action": None if rule is None else rule[0],
            "rule_table_reviewed": bool(table.reviewed),
        }
    # the boundary of a file the Owner edits: anything it raises gives the all-null playbook (docstring)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "decision table of category %s unusable for the analysis panel: %s",
            category,
            type(exc).__name__,
        )
        return nothing


# ── the highlights ──────────────────────────────────────────────────────────────────────────────────────────────


def _entry_direction(conclusion: str | None) -> str:
    if conclusion in _UP_ENTRY_CONCLUSIONS:
        return "up"
    if conclusion in _DOWN_ENTRY_CONCLUSIONS:
        return "down"
    return "warn"


def _highlights(
    gate: Mapping[str, Any],
    history: Mapping[str, Any] | None,
    rag: Mapping[str, Any],
    checks: Sequence[Mapping[str, str]],
) -> list[dict[str, Any]]:
    """Up to `HIGHLIGHTS_SHOWN` rows `{direction, code, params}`, built by the server from stored system facts, the
    history, the RAG standing and the checks' outcomes: never from a text the model wrote, and (because a withheld run
    has no step 6 row) never from the verifier of such a run. Deterministic: the order is `HIGHLIGHT_CODES`'.
    """
    found: list[dict[str, Any]] = []

    def add(direction: str, code: str, **params: Any) -> None:
        found.append({"direction": direction, "code": code, "params": params})

    if history is not None:
        total, counts = history["total"], history["by_conclusion"]
        incident = counts["confirmed_incident"]
        benign = sum(counts[name] for name in _BENIGN_CONCLUSIONS)
        if incident * 2 > total:
            add("up", "history_incident", count=incident, total=total)
        elif benign * 2 > total:
            add("down", "history_benign", count=benign, total=total)

    system = _mapping(gate.get("facts"))
    if str(system.get("identity_privileged")).lower() == "true":
        add("up", "identity_privileged")
    asset = str(system.get("asset_criticality")).lower()
    if asset == "high":
        add("up", "asset_high")
    elif asset == "unknown":
        add("warn", "asset_unknown")
    if str(system.get("severity")).lower() == "critical":
        add("up", "severity_critical")

    if rag["state"] == "matched" and rag["best_pct"] is not None:
        best = rag["candidates"][0] if rag["candidates"] else {}
        conclusion = best.get("conclusion")
        add(_entry_direction(conclusion), "rag_matched", pct=rag["best_pct"], conclusion=conclusion)
    elif rag["state"] == "below_floor":
        add("warn", "rag_below_floor", pct=rag["best_pct"], floor_pct=rag["floor_pct"])
    elif rag["state"] == "failed":
        add("warn", "rag_failed", failure=rag["failure"])

    for row in checks:
        if row["outcome"] == "warn":
            add("warn", f"warning_{row['detail']}")

    found.sort(key=lambda row: HIGHLIGHT_CODES.index(row["code"]))
    return found[:HIGHLIGHTS_SHOWN]


# ── the technical figures ───────────────────────────────────────────────────────────────────────────────────────


def _cost(value: Any) -> Decimal | None:
    """A cost as an exact `Decimal` (`llm_runs.cost_usd` is `numeric`), else None: a bool, a string, NaN and an
    infinity are not a cost."""
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        return None
    number = Decimal(repr(value)) if isinstance(value, float) else Decimal(value)
    return number if number.is_finite() else None


def _sum_counts(first: Any, second: Any) -> int | None:
    """The sum of two whole numbers (tokens, milliseconds), None only when neither row has one."""
    a, b = _int_or_none(first), _int_or_none(second)
    return None if a is None and b is None else (a or 0) + (b or 0)


def _sum_cost(first: Any, second: Any) -> float | None:
    """The sum of two costs, added exactly and served as a float, None only when neither row has one."""
    a, b = _cost(first), _cost(second)
    return None if a is None and b is None else float((a or Decimal(0)) + (b or Decimal(0)))


def _tech(run: StoredRun, gate: Mapping[str, Any], mitre_ids: Sequence[Any]) -> dict[str, Any]:
    """What the whole analysis cost and when it ran, and the alert's MITRE ids. Tokens, time and cost are the SUM of
    the run's proposer row and its verifier row (the one whose `gate_result.proposer_run_id` names the run), a figure
    being None only when neither row has it. No model id."""
    return {
        "input_tokens": _sum_counts(run.input_tokens, run.verifier_input_tokens),
        "output_tokens": _sum_counts(run.output_tokens, run.verifier_output_tokens),
        "latency_ms": _sum_counts(run.latency_ms, run.verifier_latency_ms),
        "cost_usd": _sum_cost(run.cost_usd, run.verifier_cost_usd),
        "analysed_at": run.created_at,
        "mitre_ids": [item for item in mitre_ids if isinstance(item, str)],
        "correlated_at_analysis": _int_or_none(
            _mapping(gate.get("facts")).get("correlated_clusters")
        ),
    }


# ── the object ──────────────────────────────────────────────────────────────────────────────────────────────────


def build(
    run: StoredRun,
    *,
    mitre_ids: Sequence[Any],
    floor: Any,
    read_cards: CardReader,
) -> dict[str, Any] | None:
    """The `analysis` of one stored run, or None when the run has no result (① gave up: `result` is NULL, or is not an
    object). `mitre_ids` are the alert's, `floor` is `RAG_MIN_SCORE` (what `rag_view` compares the lookup's best
    candidate with), `read_cards` reads the title and the conclusion of the entries the RAG block lists. A new dict
    on every call; nothing it is given is changed."""
    result = run.result
    if not isinstance(result, Mapping):
        return None
    gate = _mapping(run.gate_result)
    withheld = verdicts.rag_rule_applied(gate)

    checks = _checks(gate, withheld)
    history = _history(run.history)
    rag = _rag(run, gate, floor, read_cards)
    return {
        "summary": _text(result.get("summary")),
        # DEC-219: the readings and what would change the verdict are the model's own case for its own answer
        "reading_attack": None if withheld else _text(result.get("reading_attack")),
        "reading_benign": None if withheld else _text(result.get("reading_benign")),
        "would_change": None if withheld else _text(result.get("would_change")),
        "next_checks": _next_checks(result.get("next_checks")),
        "reasons": _reasons(result, gate),
        "facts": _facts(gate, withheld),
        "checks": checks,
        "check_totals": _totals(checks),
        "rag": rag,
        "history": history,
        "playbook": _playbook(gate),
        "highlights": _highlights(gate, history, rag, checks),
        "tech": _tech(run, gate, mitre_ids),
    }
