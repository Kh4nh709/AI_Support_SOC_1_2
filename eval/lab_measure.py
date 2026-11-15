#!/usr/bin/env python3
"""The lab measurement (P14-T11, DEC-213, spec §6): how well ① and ② conclude, with the RAG off and on,
against the labels an admin gave by hand.

``measure`` scores the **model's own conclusion** over the alerts and cases of the ``test`` runs:

* **Subjects.** ①: the queue heads (``duplicate_of IS NULL``) received inside a test run's window; only the
  labelled ones are scored. ②: the cases with a head alert in a test run. A case is a real attack when
  any head is labelled TP; with no TP and a head nobody labelled it is *unlabelled*; otherwise it is FP. An
  unlabelled subject is excluded and counted, never scored as FP. A labelled case whose ② never ran has no
  ② answer: it is counted as ``no_investigation``.
* **Two runs per subject, each as of the subject's first look** (``as_of``), so a prompt holds what production
  could have shown then and not what arrived since. ①: ``evaluate_alert`` with ``DEPLOYED`` and ``rag`` off,
  then on, **as of the alert's first ① proposer run** (the ``created_at`` of its first ``triage`` / ``proposer``
  row in ``llm_runs``), else ``received_at + RAG_TRIAGE_DELAY_S``; the row records which of the two was used and the
  report counts both. The burst count (``DEDUP_ENABLED=false``) and the correlation section then hold only the
  alerts received before ``as_of``, and the RAG-on run reads the newest lookup created before it. ②:
  ``evaluate_case``, ``rag`` off then on, **as of the case's first ② run**: the dossier then holds no tier-2
  note and no earlier ② answer written after that instant, block 5 only alerts received before it, and the RAG
  arm reads the newest lookup created before it. Nothing is looked up again; a subject with no usable lookup is
  counted (failed lookups by kind, "no lookup", "budget") and scored without RAG.
* **The model's TP.** ①: ``proposed_verdict == "true_positive"``. ②: ``model_conclusion ==
  "confirmed_incident"``. **Held.** ①: ``final_verdict == "needs_review"`` (0 for a run since DEC-217: the gate's checks are warnings
  beside the model's verdict, not holds). ②: a non-empty ``held_by``, or a
  stored ``need_more_data`` beside a definite ``model_conclusion``.
* **Leaks** (reported, never silent). ``same_run``: a matched entry whose source alert or case lies in the
  subject's own run. ``after_cutoff``: the entry's ``approved_at`` is later than ``--kb-cutoff``, which
  defaults to the earliest ``test`` run's ``starts_at``. A flagged subject is listed by id and still counted.
* **The report**, Markdown and JSON with the same numbers, per tier and per arm: n and the unlabelled
  excluded; accuracy, TP recall and TP precision; held, split by whether the model was right; RAG coverage
  and the mean best percentage; failed lookups; leaks; the cost. Closed tokens and ids only: never a prompt, a
  model answer, a raw log, a DSN or a key.

``calibrate --runs NAME ...`` reads the named ``kb`` runs' labelled alerts and their stored
``rag_results.ranked`` and prints, for t = 0.30, 0.35 ... 0.95, the **coverage** (the share of those alerts
whose best score is at least t) and the **agreement** (of the alerts covered at t, the share whose best
entry's conclusion agrees with the label: ``confirmed_incident`` with TP, the other four with FP). With
``--rerank-model M`` it scores the same candidates again with Voyage rerank, over the entries' digests read
from the main database, and prints the second table beside the first. A ``test`` run is refused: the
thresholds must not be chosen on the test set.

**Money.** Both commands print an estimate first and stop with exit 5 unless ``--yes`` is given (the
convention of ``run_configs``' ``EXIT_APPROVAL``): ``measure`` always (it calls the model), ``calibrate`` when
``--rerank-model`` is given (it calls Voyage). The estimate is an upper bound (every prompt priced at its
token budget). ``--yes`` is the Owner's go-ahead. The month's cap is enforced per call by ``SpendGuard``: the
spend of this process is added to ``llm_runs`` of the month, a call that would pass the cap is refused, the
subject is counted ``cap`` and the exit code is 6. The measurement writes **nothing** to the database (it runs
in ``READ ONLY`` transactions), so its spend is in the report, not in ``llm_runs``.

An evaluation that raises something the pipelines do not handle is counted as an ``error`` outcome (no
answer), its class is said on stderr, and the run goes on: one subject does not lose a paid run. A model that
stops (``cap``, ``schema``, ``transient`` ...) is counted the same way, by outcome, in ``no_answer``.

The DSN is ``--dsn``, else ``DATABASE_URL`` from ``--env-file``. It is never printed, and no ``Config`` in this
process keeps it. A database error is one generic line (the class of the error, never its text: libpq quotes
a malformed address, password included).

Exit codes: 0 done; 2 usage (also: ``--out`` cannot be written, checked before the estimate); 3 not ready (no
test run, nothing to score, the Voyage key missing or refused); 4 the DSN or the database is unusable; 5 the estimate needs
approval (``--yes``); 6 stopped by the monthly cap (``cap`` and ``verifier_cap`` both count); 7 nothing was
answered in any arm; 8 stopped part-way (a database error or Ctrl-C): the subjects that finished are written as a
report marked PARTIAL.

**What the numbers may be flattered or biased by (the report's caveat).** The inputs of ① and ② are bounded at
the subject's first look (above): the burst count, the correlation section and block 5 hold only alerts
received before it, so a later stage of the attack is not in a prompt. What is NOT bounded is the neighbours'
CURRENT status: the section prints the status a neighbour has now, so a prompt may show an analyst decision made
after the subject's first look (``as_of``). It is the same in both arms, so the RAG difference is not biased by
it and the absolute accuracy may be flattered; the report counts and lists the subjects it can have touched.
That count is an estimate, not a bound. A neighbour counts when it was received before ``as_of`` (so the section
holds it), is in the +-2 h window, in a decided status (``closed_fp``, ``closed_benign``, ``closed_confirmed``,
``escalated_tier2``), and its decision is dated after ``as_of``: a closed one by ``sealed_at``, an escalated one
by the ``tier1.escalated`` event whose ``payload.alert_ids`` lists it (``transitions.escalate`` writes one event
per case, keyed on the trigger; until T2, DEC-215, it listed every head it swept in, so a swept sibling has none of
its own, and since T2 it lists the trigger alone). It OVER-counts because the section's
caps (20 groups, 5 samples) are not replayed: a neighbour the section cut is counted. It UNDER-counts a
neighbour in a decided status with no record that dates the decision (an escalation no event lists, as in
hand-made data), and a decision the section shows under a status outside the four above (none today). With
``DEDUP_ENABLED=true`` (the trial runs it off) an alert's own ``occurrence_count`` and the correlated heads'
counts are the ones stored now, not bounded.
The RAG-on arm alone also reads the stored decision history, which may hold same-run decisions
(``history_same_run``): those subjects make the RAG difference unreliable. Coverage, the mean best percentage and
the leak flags describe what reached each PROMPT (decided from the evaluation, with ``prompt_material``'s own
active/hash filter), not what the stored lookup held. The header's thresholds are today's settings, not the ones
the stored lookups used.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import json
import math
import os
import sys
import tempfile
import time
import uuid
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import psycopg

# eval/ is a composition root outside backend/ and not a package on sys.path: its siblings are imported by
# name once the directory is on the path (the pattern of run_configs.py), and `app.*` comes from the caller
# (PYTHONPATH=backend, or pytest's pythonpath).
sys.path.insert(0, str(Path(__file__).resolve().parent))

import llm_cache  # P7-T02: the spend guard
from app.audit import llm_runs
from app.domain.correlation import (
    RECEIVED_BEFORE_PREDICATE,
    STATUS_PREDICATE,
    WINDOW_PREDICATE,
    window_params,
)
from app.infra import config, db
from app.infra.errors import ConfigError
from app.llm import verdicts
from app.llm.adapter import DeepSeekAdapter
from app.llm.builder import LEARNED_ENTRIES_DROPPED_WARNING
from app.rag import fingerprint, match, voyage
from app.rag.entries import entry_by_id
from app.rag.failures import RagUnavailable
from app.rag.lookup import (
    UNKNOWN_FAILURE_KIND,
    USABLE_STATUSES,
    LookupResult,
    latest_lookup,
    prompt_material,
)
from app.rag.subject import Subject
from app.tier1.triage import DEPLOYED, evaluate_alert
from app.tier2.investigate import evaluate_case

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NOT_READY = 3
EXIT_DSN = 4
EXIT_APPROVAL = 5
EXIT_CAP = 6
EXIT_NO_ANSWER = 7
EXIT_PARTIAL = 8

TRUE_POSITIVE = "true_positive"
FALSE_POSITIVE = "false_positive"
CONFIRMED_INCIDENT = "confirmed_incident"
#: Kept in the report so the reader sees which `needs_review` is the system's.
NEEDS_REVIEW = "needs_review"
NEED_MORE_DATA = "need_more_data"

ARMS = ("off", "on")
LEAK_KINDS = ("same_run", "after_cutoff")
#: The outcomes that are the spend guard's refusal: ①'s verifier call can be the one that meets the cap.
CAP_OUTCOMES = ("cap", "verifier_cap")

#: One sentence, in the header of every report (the Director's ruling on the correlation section, the
#: Reviewer's on the decision history, and the final wave's C1 and item 50): what the numbers may be flattered or
#: biased by. The inputs are bounded at the first look; what is left is the neighbours' status and the history.
CAVEAT = (
    "The inputs of ① and ② are bounded at the subject's first look (the burst count, the correlation section "
    "and block 5 hold only alerts received before it, and the RAG-on arm reads only a lookup created before "
    "it), but the neighbours in them show their current status, so a prompt in either arm may still show an "
    "analyst decision made after that instant (that is the same in both arms: the RAG difference is not biased "
    "by it, the absolute accuracy may be flattered; the subjects counted under correlation_after_arrival are an "
    "estimate, which over-counts because the section's caps are not replayed and under-counts where a decision "
    "has no date), while only the RAG-on arm also reads the stored decision history, which may hold same-run "
    "analyst decisions (the subjects listed under history_same_run make the RAG difference unreliable)."
)

#: Under the table of every tier that read a lookup (deferred item 28): what the "no lookup" count cannot say.
#: A lookup rate-limited (429) on its first attempt is retried; a retry that finds ① finished writes nothing,
#: not even a `failed` row (`rag.lookup.run_lookup_job`, 1b), so the subject has no lookup and no failure kind.
NO_LOOKUP_NOTE = (
    '"No lookup" may hide a 429: a rate-limited lookup whose retry came after ① had finished is stored '
    "nowhere, so no failed-lookup count, in this report or in `rag_lookup_failures`, sees it."
)

#: Where a subject's `as_of` came from. ①: its first proposer run in `llm_runs`, else `received_at` plus the
#: triage delay. ②: its first investigation run.
AS_OF_FIRST_LOOK = "first_look"
AS_OF_DELAY = "delay"
AS_OF_FIRST_RUN = "first_run"

#: calibrate's grid: 0.30, 0.35 ... 0.95.
THRESHOLDS: tuple[float, ...] = tuple(round(0.30 + 0.05 * i, 2) for i in range(14))

#: The estimate's inputs. Per arm and subject: ① a proposer call and a verifier call, ② one call; +10 % for
#: the schema repair. Each call is priced at its prompt's token budget and a generous answer, so the figure is
#: an upper bound (a prompt is usually a tenth of its budget).
CALLS_PER_SUBJECT = {1: 2, 2: 1}
REPAIR_MARGIN = 1.10
ANSWER_TOKENS = {1: 800, 2: 2_500}

#: Voyage's free tier is rate limited: a 429 is waited out, up to RATE_LIMIT_RETRIES more attempts.
RATE_LIMIT_WAIT_S = 21
RATE_LIMIT_RETRIES = 2
#: Characters per token when the rerank is estimated from text (a low figure, so the estimate is high).
CHARS_PER_TOKEN = 3

_EPILOG = (
    "exit codes: 0 done; 2 usage; 3 not ready; 4 the DSN or the database is unusable; "
    "5 the estimate needs approval (--yes); 6 stopped by the monthly cap; 7 nothing was answered; "
    "8 stopped part-way (a database error or Ctrl-C), a PARTIAL report was written."
)


class Exit(Exception):
    """A controlled exit: a code from the table above and one line for stderr."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# ═══════════════════════════════════════════════════════════════════════════════════════════
# Pure: arguments, truth, statistics, leaks, calibration
# ═══════════════════════════════════════════════════════════════════════════════════════════


def parse_tiers(text: str) -> tuple[int, ...]:
    """`"1,2"` -> `(1, 2)`; `"2"` -> `(2,)`. A tier is 1 or 2, named once. `ValueError` otherwise."""
    tiers: list[int] = []
    for part in text.split(","):
        part = part.strip()
        if part not in ("1", "2"):
            raise ValueError("--tiers: a comma-separated list of 1 and 2")
        tiers.append(int(part))
    if len(set(tiers)) != len(tiers):
        raise ValueError("--tiers: each tier once")
    return tuple(sorted(tiers))


def parse_cutoff(text: str) -> datetime:
    """An ISO 8601 instant that says its zone (`Z` or an offset): a naive one would be read in the
    session's, which is not what the Owner meant. `ValueError` otherwise."""
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        raise ValueError(
            "--kb-cutoff: an ISO 8601 time with its zone, such as 2026-11-05T09:00:00Z"
        ) from None
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("--kb-cutoff: the time must say its zone (Z or +hh:mm)")
    return moment.astimezone(UTC)


def case_truth(labels: Sequence[str | None]) -> str | None:
    """A case's truth from the labels of its head alerts (`None`: a head nobody labelled). TP when any head
    is TP; unlabelled (`None`) when no head is TP and any head is unlabelled, or there is no head; else FP.
    An unlabelled case is excluded from the scores, never counted as FP."""
    if TRUE_POSITIVE in labels:
        return TRUE_POSITIVE
    if not labels or any(label is None for label in labels):
        return None
    return FALSE_POSITIVE


def _rate(num: float, den: float) -> float | None:
    return None if den == 0 else num / den


@dataclass(frozen=True)
class Seen:
    """What a RAG-on subject's PROMPT held of its lookup (decided from the evaluation, not from the newest
    row). `status`: `ok` / `empty` (the lookup's material reached the prompt), `failed` (with its closed
    `failure_kind`), `budget` (the newest lookup hit a cap: no material), `none` (no lookup at all) or
    `not_in_prompt` (a usable lookup exists but its section did not reach the prompt: the token budget cut it,
    or its read failed) or `error` (the evaluation raised, so nothing is known of its prompt; `failure_kind` is
    then the kind of the newest lookup when that one `failed`, so the failed-lookup count is complete). `matches`
    are `(entry_id, percentage)` of the matches the prompt kept, best first (the active, hash-intact ones:
    `prompt_material`'s own filter, and none at all when ①'s budget cut dropped the entries and kept only the
    history). The history fields are the stored decision history that came with the lookup: how many decisions,
    the newest activity, the example alerts.
    """

    status: str
    failure_kind: str | None
    matches: tuple[tuple[str, int], ...]
    history_total: int = 0
    history_last_seen: datetime | None = None
    history_examples: tuple[str, ...] = ()

    @property
    def best_pct(self) -> int | None:
        return max((pct for _entry, pct in self.matches), default=None)

    @property
    def applied(self) -> bool:
        return self.status in ("ok", "empty")

    @property
    def history_in_prompt(self) -> bool:
        """The prompt carried the decision history (`prompt_material` renders it when it has a decision)."""
        return self.applied and self.history_total > 0

    def to_json(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "failure_kind": self.failure_kind,
            "matches": len(self.matches),
            "best_pct": self.best_pct,
            "history_total": self.history_total,
        }


@dataclass(frozen=True)
class ArmRow:
    """One subject in one arm: closed tokens and numbers, nothing a model or an alert wrote. `model_tp` is
    None when the model gave no answer (`outcome` says why); `held` is the hold: ② 's override, and for ① a
    `final_verdict` of `needs_review`, which no new run has (DEC-217: the gate flags, it no longer holds), so it
    reads False there.
    """

    tier: int
    subject: str
    truth: str
    arm: str
    outcome: str
    model_verdict: str | None
    final_verdict: str | None
    model_tp: bool | None
    held: bool
    cost_usd: float
    seen: Seen | None = None
    leaks: tuple[str, ...] = ()
    held_by: tuple[str, ...] = ()
    history_same_run: bool = False
    unplaceable: int = 0
    #: The instant the subject was evaluated as of, and which of the two ways named it (`AS_OF_*`). None: the
    #: row was not evaluated as of an instant (a unit test's row).
    as_of: datetime | None = None
    as_of_source: str | None = None

    @property
    def correct(self) -> bool | None:
        return None if self.model_tp is None else self.model_tp == (self.truth == TRUE_POSITIVE)

    def to_json(self, *, leaks_computed: bool = True) -> dict[str, Any]:
        """The row of the JSON report. With `leaks_computed` False (the leak pass did not finish) the three
        values only that pass sets are `null`: `[]`, `false` and `0` would read as "checked, nothing found".
        """
        row: dict[str, Any] = {
            "tier": self.tier,
            "subject": self.subject,
            "arm": self.arm,
            "truth": self.truth,
            "outcome": self.outcome,
            "model": self.model_verdict,
            "final": self.final_verdict,
            "held": self.held,
            "held_by": list(self.held_by),
            "correct": self.correct,
            "cost_usd": self.cost_usd,
        }
        if self.as_of is not None:
            row["as_of"] = self.as_of.astimezone(
                UTC
            ).isoformat()  # UTC, whatever zone the session read in
            row["as_of_source"] = self.as_of_source
        if self.seen is not None:
            row["lookup"] = self.seen.to_json()
            row["leaks"] = list(self.leaks) if leaks_computed else None
            row["history_same_run"] = self.history_same_run if leaks_computed else None
            row["unplaceable"] = self.unplaceable if leaks_computed else None
        return row


def summarise(rows: Sequence[ArmRow], *, leaks_computed: bool = True) -> dict[str, Any]:
    """The numbers of one arm of one tier. `n` is every subject of the arm; the rates are over the subjects
    the model answered (`answered`), and `no_answer` says by outcome why the others were not scored. A rate
    with nothing to divide is None, never 0. Held is split by whether the model's own conclusion was right.
    `rag` is None for an arm that read no lookup. With `leaks_computed` False (a PARTIAL report: the run stopped
    during the leak pass) the leak and history-flag numbers are None: they are not zero, they are unknown.
    """
    scored = [row for row in rows if row.model_tp is not None]
    no_answer = Counter(row.outcome for row in rows if row.model_tp is None)
    correct = sum(1 for row in scored if row.correct)
    truth_tp = [row for row in scored if row.truth == TRUE_POSITIVE]
    said_tp = [row for row in scored if row.model_tp]
    recall = sum(1 for row in truth_tp if row.model_tp)
    precision = sum(1 for row in said_tp if row.truth == TRUE_POSITIVE)
    held = [row for row in scored if row.held]
    return {
        "n": len(rows),
        "answered": len(scored),
        "no_answer": dict(sorted(no_answer.items())),
        "correct": correct,
        "accuracy": _rate(correct, len(scored)),
        "tp_recall": {"num": recall, "den": len(truth_tp), "rate": _rate(recall, len(truth_tp))},
        "tp_precision": {
            "num": precision,
            "den": len(said_tp),
            "rate": _rate(precision, len(said_tp)),
        },
        "held": {
            "total": len(held),
            "model_wrong": sum(1 for row in held if not row.correct),
            "model_right": sum(1 for row in held if row.correct),
        },
        "cost_usd": round(math.fsum(row.cost_usd for row in rows), 5),
        "rag": _rag_summary(rows, leaks_computed),
    }


def _rag_summary(rows: Sequence[ArmRow], leaks_computed: bool = True) -> dict[str, Any] | None:
    """Coverage, the mean best percentage, the leaks and the history describe what reached the PROMPT of each
    RAG-on subject (`Seen`), not what the stored lookup held."""
    seen_rows = [row for row in rows if row.seen is not None]
    if not seen_rows:
        return None
    covered = [row for row in seen_rows if row.seen.matches]
    # An evaluation that raised (`error`) is counted here too when its newest lookup `failed`: it names the kind,
    # `evaluation_error` below counts it as an evaluation that raised, and neither hides the other.
    failed = Counter(
        (row.seen.failure_kind or UNKNOWN_FAILURE_KIND)
        for row in seen_rows
        if row.seen.status == "failed"
        or (row.seen.status == "error" and row.seen.failure_kind is not None)
    )
    leaks: dict[str, Any] = {
        kind: {
            "count": sum(1 for row in seen_rows if kind in row.leaks),
            "subjects": sorted(row.subject for row in seen_rows if kind in row.leaks),
        }
        for kind in LEAK_KINDS
    }
    leaks["unplaceable"] = {
        "count": sum(1 for row in seen_rows if row.unplaceable),
        "matches": sum(row.unplaceable for row in seen_rows),
        "subjects": sorted(row.subject for row in seen_rows if row.unplaceable),
    }
    leaks["flagged_subjects"] = sum(1 for row in seen_rows if row.leaks or row.history_same_run)
    best = [row.seen.best_pct for row in covered]
    return {
        "coverage": {
            "with_match": len(covered),
            "n": len(seen_rows),
            "rate": _rate(len(covered), len(seen_rows)),
        },
        "mean_best_pct": _rate(math.fsum(best), len(best)),
        "failed_lookups": {
            "by_kind": dict(sorted(failed.items())),
            "no_lookup": sum(1 for row in seen_rows if row.seen.status == "none"),
            "budget": sum(1 for row in seen_rows if row.seen.status == "budget"),
            "not_in_prompt": sum(1 for row in seen_rows if row.seen.status == "not_in_prompt"),
            "evaluation_error": sum(1 for row in seen_rows if row.seen.status == "error"),
        },
        "history": {
            "in_prompt": sum(1 for row in seen_rows if row.seen.history_in_prompt),
            "same_run": (
                {
                    "count": sum(1 for row in seen_rows if row.history_same_run),
                    "subjects": sorted(row.subject for row in seen_rows if row.history_same_run),
                }
                if leaks_computed
                else None
            ),
        },
        "leaks": leaks if leaks_computed else None,
    }


def paired(
    off_rows: Sequence[ArmRow], on_rows: Sequence[ArmRow], *, with_matches: bool = False
) -> dict[str, Any]:
    """Accuracy of the two arms over the SAME subjects: those the model answered in both. Each arm's own
    rates are over its own `answered` set, so the two can differ in who is scored; this is the exact
    comparison. With `with_matches` only the subjects whose RAG-on prompt carried at least one match: where the
    RAG could act (a failed, an empty, a no-lookup or a budget-cut subject cannot show an effect, and the first
    line mixes them in)."""
    on_by_subject = {
        row.subject: row
        for row in on_rows
        if row.model_tp is not None and (not with_matches or (row.seen and row.seen.matches))
    }
    pairs = [
        (row, on_by_subject[row.subject])
        for row in off_rows
        if row.model_tp is not None and row.subject in on_by_subject
    ]
    off_correct = sum(1 for off, _on in pairs if off.correct)
    on_correct = sum(1 for _off, on in pairs if on.correct)
    return {
        "n": len(pairs),
        "off": {"correct": off_correct, "accuracy": _rate(off_correct, len(pairs))},
        "on": {"correct": on_correct, "accuracy": _rate(on_correct, len(pairs))},
    }


@dataclass(frozen=True)
class EntryFacts:
    """What the leak test needs of an approved entry: where it was drafted from and when it was approved."""

    source_alerts: frozenset[str]
    source_cases: frozenset[str]
    approved_at: datetime | None


def leak_flags(
    matched: Iterable[str],
    *,
    subject_runs: frozenset[str],
    entries: Mapping[str, EntryFacts],
    alert_run: Mapping[str, str],
    case_runs: Mapping[str, frozenset[str]],
    cutoff: datetime,
) -> tuple[str, ...]:
    """The leaks among the entries a subject matched, in `LEAK_KINDS`' order. `same_run`: an entry whose
    source alert, or a head of whose source case, lies in one of the subject's runs. `after_cutoff`: an
    entry approved strictly after `cutoff`. An entry the database no longer has, or one with no approval
    time, cannot be placed and is not flagged."""
    flags: set[str] = set()
    for entry_id in matched:
        facts = entries.get(entry_id)
        if facts is None:
            continue
        runs = {alert_run[a] for a in facts.source_alerts if a in alert_run}
        for case_id in facts.source_cases:
            runs |= case_runs.get(case_id, frozenset())
        if runs & subject_runs:
            flags.add("same_run")
        if facts.approved_at is not None and facts.approved_at > cutoff:
            flags.add("after_cutoff")
    return tuple(kind for kind in LEAK_KINDS if kind in flags)


def unplaceable(matched: Iterable[str], entries: Mapping[str, EntryFacts]) -> list[str]:
    """The matched entries the leak test could not place: ones the database no longer has, and ones with no
    approval time (nothing to compare with the cut-off). Counted and shown, so they do not pass silently.
    """
    return [
        entry_id
        for entry_id in matched
        if entry_id not in entries or entries[entry_id].approved_at is None
    ]


def history_same_run(
    seen: Seen,
    *,
    subject_runs: frozenset[str],
    run_starts: Mapping[str, datetime],
    alert_run: Mapping[str, str],
) -> bool:
    """Whether the decision history in a RAG-on prompt holds same-run analyst decisions (the RAG-off arm reads
    no history). The history counts decisions on earlier alerts that share the subject's key, stored when the
    lookup ran, so the lookup is time-correct; but a decision taken while the run was going on is still a
    same-run decision. Flagged when an example alert lies in one of the subject's runs, or the newest counted
    activity (`last_seen`) is at or after the start of one of them. A prompt without a history is not
    flagged."""
    if not seen.history_in_prompt:
        return False
    if any(alert_run.get(alert) in subject_runs for alert in seen.history_examples):
        return True
    last = seen.history_last_seen
    if last is None:
        return False
    if last.tzinfo is None:
        last = last.replace(tzinfo=UTC)  # a time with no zone is read as UTC, not refused
    return any(last >= run_starts[run] for run in subject_runs if run in run_starts)


@dataclass(frozen=True)
class CalRow:
    """One labelled alert of a calibration: its best stored (or re-scored) candidate. `best_score` is None
    when the lookup had no candidate to score; `best_conclusion` the best entry's conclusion (None: the
    entry is not in the database any more, which agrees with nothing)."""

    alert_id: str
    label: str
    best_score: float | None
    best_conclusion: str | None


def agrees(conclusion: str, label: str) -> bool:
    """`confirmed_incident` agrees with TP; the other four conclusions agree with FP."""
    return (conclusion == CONFIRMED_INCIDENT) == (label == TRUE_POSITIVE)


def best_of(ranked: Any) -> tuple[str, float] | None:
    """The highest valid `(entry_id, score)` of a stored `rag_results.ranked`, or None. A valid item has an
    entry id and a number in [0, 1]; whatever else is in the column is ignored, as the lookup's own reader
    ignores it. The first of equal scores wins (the list is best first)."""
    if not isinstance(ranked, list):
        return None
    best: tuple[str, float] | None = None
    for item in ranked:
        if not isinstance(item, dict):
            continue
        entry_id, score = item.get("entry_id"), item.get("score")
        if not isinstance(entry_id, str) or not entry_id:
            continue
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            continue
        if not math.isfinite(score) or not 0 <= score <= 1:
            continue
        if best is None or score > best[1]:
            best = (entry_id, float(score))
    return best


def calibration_table(rows: Sequence[CalRow]) -> list[dict[str, Any]]:
    """One line per threshold: `covered` (best score at least t), `coverage` (of all the rows), `agree` (of
    the covered, the best entry's conclusion agrees with the label) and `agreement` (of the covered; None
    when none is covered)."""
    table = []
    for t in THRESHOLDS:
        covered = [row for row in rows if row.best_score is not None and row.best_score >= t]
        agree = sum(
            1
            for row in covered
            if row.best_conclusion is not None and agrees(row.best_conclusion, row.label)
        )
        table.append(
            {
                "t": t,
                "n": len(rows),
                "covered": len(covered),
                "coverage": _rate(len(covered), len(rows)),
                "agree": agree,
                "agreement": _rate(agree, len(covered)),
            }
        )
    return table


# ═══════════════════════════════════════════════════════════════════════════════════════════
# The database: read only
# ═══════════════════════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class Run:
    run_id: str
    name: str
    purpose: str
    starts_at: datetime
    ends_at: datetime


@dataclass(frozen=True)
class AlertSubject:
    """A queue head of a test run. `as_of` is the instant ① is evaluated as of (C1): `load_alert_subjects` sets
    it from the alert's first proposer run (`AS_OF_FIRST_LOOK`) or, with none, `received_at` plus the triage delay
    (`AS_OF_DELAY`). None - a subject built by hand - is evaluated with no bound, as before."""

    alert_id: str
    run_id: str
    label: str | None
    received_at: datetime
    as_of: datetime | None = None
    as_of_source: str | None = None


@dataclass(frozen=True)
class CaseSubject:
    case_id: str
    truth: str | None
    runs: frozenset[str]
    first_run_at: datetime | None


def _begin(conn: psycopg.Connection) -> None:
    """A fresh READ ONLY transaction: the server, not this module, refuses a write."""
    conn.rollback()
    conn.execute("SET TRANSACTION READ ONLY")


def load_runs(conn: psycopg.Connection) -> list[Run]:
    """Every run, the earliest window first. The instants are in UTC whatever zone the session reads in."""
    rows = conn.execute(
        "SELECT run_id::text, name, purpose, starts_at, ends_at FROM lab_runs ORDER BY starts_at"
    ).fetchall()
    return [
        Run(run_id, name, purpose, start.astimezone(UTC), end.astimezone(UTC))
        for run_id, name, purpose, start, end in rows
    ]


_ALERT_SUBJECTS_SQL = """
    SELECT a.alert_id, r.run_id::text, l.label, a.received_at
      FROM lab_runs r
      JOIN alerts a ON a.received_at >= r.starts_at AND a.received_at < r.ends_at
                   AND a.duplicate_of IS NULL
      LEFT JOIN lab_labels l ON l.alert_id = a.alert_id
     WHERE r.run_id = ANY(%s::uuid[])
     ORDER BY r.starts_at, a.received_at, a.alert_id
"""

#: Every head of every case that has a head in the runs, with its label and the run its `received_at` falls in
#: (any purpose): the truth of a case is read from all its heads.
_CASE_HEADS_SQL = """
    SELECT ca.case_id::text, ca.alert_id, l.label, r.run_id::text
      FROM case_alerts ca
      JOIN alerts a ON a.alert_id = ca.alert_id
      LEFT JOIN lab_labels l ON l.alert_id = ca.alert_id
      LEFT JOIN lab_runs r ON a.received_at >= r.starts_at AND a.received_at < r.ends_at
     WHERE ca.case_id IN (
            SELECT ca2.case_id
              FROM case_alerts ca2
              JOIN alerts a2 ON a2.alert_id = ca2.alert_id
              JOIN lab_runs r2 ON a2.received_at >= r2.starts_at AND a2.received_at < r2.ends_at
             WHERE r2.run_id = ANY(%s::uuid[]) AND a2.duplicate_of IS NULL)
     ORDER BY ca.case_id, a.received_at, ca.alert_id
"""

_FIRST_RUN_SQL = """
    SELECT subject_id, min(created_at) FROM llm_runs
     WHERE pipeline = 'investigate' AND subject_type = 'case' AND subject_id = ANY(%s)
     GROUP BY subject_id
"""


#: ①'s first look at an alert: the `created_at` of its first proposer run, whatever that run ended in (a `cap` or
#: a `transient` row is written after ① read the alert too). Production's own rows: the lab writes none.
_FIRST_LOOK_SQL = """
    SELECT subject_id, min(created_at) FROM llm_runs
     WHERE pipeline = 'triage' AND role = 'proposer' AND subject_id = ANY(%s)
     GROUP BY subject_id
"""


def load_alert_subjects(
    conn: psycopg.Connection, runs: Sequence[Run], *, triage_delay_s: int
) -> list[AlertSubject]:
    """The queue heads of `runs`, each with its `as_of`: the `created_at` of the alert's first ① proposer run,
    else `received_at + triage_delay_s` (`RAG_TRIAGE_DELAY_S`: ① starts that long after the alert, so by then the
    lookup was stored or it never would be). `as_of_source` says which."""
    rows = conn.execute(_ALERT_SUBJECTS_SQL, ([run.run_id for run in runs],)).fetchall()
    first = dict(conn.execute(_FIRST_LOOK_SQL, ([row[0] for row in rows],)).fetchall())
    subjects = []
    for alert_id, run_id, label, received_at in rows:
        looked = first.get(alert_id)
        if looked is not None:
            subjects.append(
                AlertSubject(alert_id, run_id, label, received_at, looked, AS_OF_FIRST_LOOK)
            )
        else:
            delayed = received_at + timedelta(seconds=triage_delay_s)
            subjects.append(
                AlertSubject(alert_id, run_id, label, received_at, delayed, AS_OF_DELAY)
            )
    return subjects


def load_case_subjects(conn: psycopg.Connection, runs: Sequence[Run]) -> list[CaseSubject]:
    rows = conn.execute(_CASE_HEADS_SQL, ([run.run_id for run in runs],)).fetchall()
    labels: dict[str, list[str | None]] = {}
    run_ids: dict[str, set[str]] = {}
    for case_id, _alert_id, label, run_id in rows:
        labels.setdefault(case_id, []).append(label)
        run_ids.setdefault(case_id, set())
        if run_id is not None:
            run_ids[case_id].add(run_id)
    first = dict(conn.execute(_FIRST_RUN_SQL, (list(labels),)).fetchall())
    return [
        CaseSubject(
            case_id, case_truth(labels[case_id]), frozenset(run_ids[case_id]), first.get(case_id)
        )
        for case_id in labels
    ]


def surviving_matches(
    conn: psycopg.Connection, result: LookupResult
) -> tuple[tuple[str, int], ...]:
    """The stored matches of `result` that reach a prompt, as `(entry_id, percentage)`: `prompt_material`'s
    own filter, one match at a time (the entry is active, and its content, its stored hash and the hash stored
    with the match are one value). The product's function decides; this module keeps no copy of its rule.
    """
    kept = []
    for found in result.matches[: match.MAX_MATCHES]:
        material = prompt_material(conn, dataclasses.replace(result, matches=(found,)))
        if material is not None and material.entries:
            kept.append((found.entry_id, found.pct))
    return tuple(kept)


def seen_for(
    conn: psycopg.Connection,
    subject: Subject,
    *,
    applied: uuid.UUID | None,
    failed_kind: str | None = None,
    before: datetime | None = None,
    skips_budget: bool = False,
    entries_dropped: bool = False,
) -> Seen:
    """What the RAG-on prompt of `subject` held of its lookup. Whether the material reached the prompt is
    decided by the evaluation: `applied` is its `rag_lookup_id` (set only when the section is in the prompt,
    after any budget cut), `failed_kind` its `rag_not_applied` (②). When `applied`, that lookup is read back
    (it is the newest usable one created before `before`) and only the matches the prompt kept are counted,
    with the stored history; with `entries_dropped` (①'s budget cut took the entries and kept the history,
    warning `learned_entries_dropped`) none is, for none reached the prompt. When not applied, the newest row
    before `before` says why: none, `failed`, `budget`, or a usable one that did not reach the prompt
    (`not_in_prompt`). ② looks past a newer `budget` row to the usable row before it (`skips_budget`, spec
    §7.6; ① reads the newest row whatever it is), so for ② a usable row behind a `budget` one makes it
    `not_in_prompt`: its section was cut."""
    if applied is not None:
        used = latest_lookup(conn, subject, statuses=USABLE_STATUSES, before=before)
        if used is None or used.lookup_id != applied:
            return Seen("not_in_prompt", None, ())
        history = used.history
        return Seen(
            used.status,
            None,
            () if entries_dropped else surviving_matches(conn, used),
            history.total,
            history.last_seen,
            tuple(history.examples),
        )
    if failed_kind is not None:
        return Seen("failed", failed_kind, ())
    newest = latest_lookup(conn, subject, before=before)
    if newest is None:
        return Seen("none", None, ())
    if newest.status == "failed":
        return Seen("failed", newest.failure_kind or UNKNOWN_FAILURE_KIND, ())
    if newest.status == "budget":
        behind = (
            skips_budget
            and latest_lookup(conn, subject, statuses=USABLE_STATUSES, before=before) is not None
        )
        return Seen("not_in_prompt" if behind else "budget", None, ())
    return Seen("not_in_prompt", None, ())


def error_seen(
    conn: psycopg.Connection, subject: Subject, *, before: datetime | None = None
) -> Seen:
    """`Seen` for a RAG-on subject whose evaluation raised: nothing is known of its prompt (`error`), but when
    the newest lookup before `before` `failed` its kind is kept, so the failed-lookup count by kind is complete
    (a `failed` row with no stored kind is told as `UNKNOWN_FAILURE_KIND`, as everywhere)."""
    newest = latest_lookup(conn, subject, before=before)
    if newest is not None and newest.status == "failed":
        return Seen("error", newest.failure_kind or UNKNOWN_FAILURE_KIND, ())
    return Seen("error", None, ())


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def leak_context(
    conn: psycopg.Connection, entry_ids: Sequence[str], extra_alerts: Sequence[str] = ()
) -> tuple[dict[str, EntryFacts], dict[str, str], dict[str, frozenset[str]]]:
    """For the entries matched: their facts, the run (any purpose) of each source alert (and of
    `extra_alerts`, the history's example alerts), and the runs of each source case's heads."""
    entries: dict[str, EntryFacts] = {}
    entry_ids = [entry_id for entry_id in entry_ids if _is_uuid(entry_id)]  # a stored id is text
    for entry_id, alerts, cases, approved in conn.execute(
        "SELECT entry_id::text, source_alert_ids, source_case_ids::text[], approved_at"
        " FROM knowledge_entries WHERE entry_id = ANY(%s::uuid[])",
        (list(entry_ids),),
    ):
        entries[entry_id] = EntryFacts(frozenset(alerts), frozenset(cases), approved)
    alerts = sorted(
        {a for facts in entries.values() for a in facts.source_alerts} | set(extra_alerts)
    )
    cases = sorted({c for facts in entries.values() for c in facts.source_cases})
    alert_run = dict(
        conn.execute(
            "SELECT a.alert_id, r.run_id::text FROM alerts a"
            " JOIN lab_runs r ON a.received_at >= r.starts_at AND a.received_at < r.ends_at"
            " WHERE a.alert_id = ANY(%s)",
            (alerts,),
        ).fetchall()
    )
    case_runs: dict[str, set[str]] = {}
    for case_id, run_id in conn.execute(
        "SELECT ca.case_id::text, r.run_id::text FROM case_alerts ca"
        " JOIN alerts a ON a.alert_id = ca.alert_id"
        " JOIN lab_runs r ON a.received_at >= r.starts_at AND a.received_at < r.ends_at"
        " WHERE ca.case_id = ANY(%s::uuid[])",
        (cases,),
    ):
        case_runs.setdefault(case_id, set()).add(run_id)
    return entries, alert_run, {case: frozenset(runs) for case, runs in case_runs.items()}


# ── the correlation section may show a decision made after the subject's first look

#: The statuses that record an analyst's decision on a neighbour, as ① and ② print them.
_DECIDED_STATUSES = ("closed_fp", "closed_benign", "closed_confirmed", "escalated_tier2")

#: The neighbours ① and ② print in their correlation section, narrowed to the decided ones: the same window
#: and status predicates (`domain.correlation`, which `tier2.dossier` uses in the same way), with when each was
#: decided. A closed one: `sealed_at`, which a human close must set (`ck_alerts_h2`). An escalated one: the
#: `tier1.escalated` event whose `payload.alert_ids` lists it. `transitions.escalate` (the only writer of that
#: event) wrote ONE event, keyed on the trigger, with every head it swept into the case in `alert_ids` until T2
#: (DEC-215; since then `alert_ids` is the trigger alone), so a swept sibling has no event of its own and only
#: this lookup dates it. Read from `audit_events` by the event
#: type and the payload, not by `cases.created_at`: the event is the record of the decision itself, and it
#: needs no join on `alerts.case_id`, which a duplicate also carries.
_DECISIONS_SQL = f"""
    SELECT n.status, n.sealed_at,
           (SELECT min(e.created_at) FROM audit_events e
             WHERE e.event_type = 'tier1.escalated'
               AND e.payload -> 'alert_ids' @> to_jsonb(n.alert_id::text))
      FROM alerts n
     WHERE {WINDOW_PREDICATE}
       AND {STATUS_PREDICATE}
       AND n.status = ANY(%(decided)s)
"""
#: ②'s block 5 leaves out the case's own alerts.
_DECISIONS_OUTSIDE_CASE_SQL = (
    _DECISIONS_SQL
    + " AND n.alert_id NOT IN (SELECT alert_id FROM case_alerts WHERE case_id = %(case_id)s)"
)


#: C1: the section holds only the neighbours received before the subject's `as_of`, so the count of the decisions
#: it can show narrows to those (`domain.correlation.RECEIVED_BEFORE_PREDICATE`, the predicate the section uses).
_RECEIVED_BEFORE_CLAUSE = f"       AND {RECEIVED_BEFORE_PREDICATE}\n"


def _decided_after(
    conn: psycopg.Connection,
    sql: str,
    params: dict[str, Any],
    since: datetime,
    received_before: datetime | None = None,
) -> bool:
    if received_before is not None:
        sql += _RECEIVED_BEFORE_CLAUSE
        params = {**params, "as_of": received_before}
    for status, sealed_at, escalated_at in conn.execute(sql, params).fetchall():
        decided_at = escalated_at if status == "escalated_tier2" else sealed_at
        if decided_at is not None and decided_at > since:
            return True
    return False


def _window(alert_id: str, row: Sequence[Any]) -> dict[str, Any]:
    agent_name, alert_user, srcip, alert_time = row
    return window_params(
        SimpleNamespace(
            alert_id=alert_id,
            agent_name=agent_name,
            alert_user=alert_user,
            srcip=srcip,
            alert_time=alert_time,
        )
    )


def alert_correlation_after(
    conn: psycopg.Connection,
    alert_id: str,
    since: datetime,
    *,
    received_before: datetime | None = None,
) -> bool:
    """Whether ①'s correlation section for the alert shows a neighbour with an analyst decision recorded after
    `since` (the alert's `as_of`, its first look). The section prints every neighbour's CURRENT status, so it
    can. With `received_before` only the neighbours received before that instant count: the section holds no
    other (the run is evaluated as of that instant, C1). The measurement passes the same instant for both.
    """
    row = conn.execute(
        "SELECT agent_name, alert_user, srcip, alert_time FROM alerts WHERE alert_id = %s",
        (alert_id,),
    ).fetchone()
    if row is None:
        return False
    params = {**_window(alert_id, row), "decided": list(_DECIDED_STATUSES)}
    return _decided_after(conn, _DECISIONS_SQL, params, since, received_before)


def case_correlation_after(
    conn: psycopg.Connection,
    case_id: str,
    since: datetime,
    *,
    received_before: datetime | None = None,
) -> bool:
    """The same for ②'s block 5, over the case's heads, with `since` the case's `as_of` (and, with
    `received_before`, the neighbours received before it only)."""
    heads = conn.execute(
        "SELECT a.alert_id, a.agent_name, a.alert_user, a.srcip, a.alert_time FROM alerts a"
        " JOIN case_alerts ca ON ca.alert_id = a.alert_id WHERE ca.case_id = %s",
        (case_id,),
    ).fetchall()
    for alert_id, *row in heads:
        params = {
            **_window(alert_id, row),
            "decided": list(_DECIDED_STATUSES),
            "case_id": case_id,
        }
        if _decided_after(conn, _DECISIONS_OUTSIDE_CASE_SQL, params, since, received_before):
            return True
    return False


# ═══════════════════════════════════════════════════════════════════════════════════════════
# The evaluations
# ═══════════════════════════════════════════════════════════════════════════════════════════


class _Metered:
    """The model, behind the month's cap. The measurement writes no `llm_runs`, so `SpendGuard` adds this
    process's own spend to the month's: a call that would pass the cap is refused (`LLMBudgetExceeded`, which
    ① and ② turn into the outcome `cap`), and every answered call is priced and added."""

    def __init__(self, inner: Any, guard: llm_cache.SpendGuard) -> None:
        self._inner = inner
        self._guard = guard

    @property
    def spent(self) -> float:
        """What this process has spent so far, in USD (every answered call, whichever row it lands in)."""
        return self._guard.live_spent_usd

    def complete(self, **kwargs: Any) -> Any:
        self._guard.check()
        result = self._inner.complete(**kwargs)
        self._guard.record(result.usage)
        return result


def _alert_row(
    subject: AlertSubject,
    truth: str,
    arm: str,
    evaluation: Any | None,
    seen: Seen | None,
    error_cost: float = 0.0,
) -> ArmRow:
    as_of = {"as_of": subject.as_of, "as_of_source": subject.as_of_source}
    if evaluation is None:
        return ArmRow(
            1,
            subject.alert_id,
            truth,
            arm,
            "error",
            None,
            None,
            None,
            False,
            error_cost,
            seen,
            **as_of,
        )
    answered = evaluation.outcome == "ok" and evaluation.proposed_verdict is not None
    return ArmRow(
        tier=1,
        subject=subject.alert_id,
        truth=truth,
        arm=arm,
        outcome=evaluation.outcome,
        model_verdict=evaluation.proposed_verdict,
        final_verdict=evaluation.final_verdict,
        model_tp=(evaluation.proposed_verdict == TRUE_POSITIVE) if answered else None,
        held=answered and evaluation.final_verdict == NEEDS_REVIEW,
        cost_usd=evaluation.cost_usd,
        seen=seen,
        **as_of,
    )


def _case_row(
    case_id: str,
    truth: str,
    arm: str,
    evaluation: Any | None,
    seen: Seen | None,
    error_cost: float = 0.0,
    as_of: datetime | None = None,
) -> ArmRow:
    when = {"as_of": as_of, "as_of_source": None if as_of is None else AS_OF_FIRST_RUN}
    if evaluation is None:
        return ArmRow(
            2, case_id, truth, arm, "error", None, None, None, False, error_cost, seen, **when
        )
    answered = (
        evaluation.outcome == "ok" and evaluation.model_conclusion in verdicts.MODEL_CONCLUSIONS
    )
    held = answered and (bool(evaluation.held_by) or evaluation.final_conclusion == NEED_MORE_DATA)
    return ArmRow(
        tier=2,
        subject=case_id,
        truth=truth,
        arm=arm,
        outcome=evaluation.outcome,
        model_verdict=evaluation.model_conclusion,
        final_verdict=evaluation.final_conclusion,
        model_tp=(evaluation.model_conclusion == CONFIRMED_INCIDENT) if answered else None,
        held=held,
        cost_usd=evaluation.cost_usd,
        seen=seen,
        held_by=tuple(evaluation.held_by),
        **when,
    )


def _spent(adapter: Any) -> float:
    return float(getattr(adapter, "spent", 0.0))


def _attempt(subject: str, arm: str, call: Callable[[], Any]) -> Any | None:
    """What `call` returns, or None when it raised (broad on purpose: a long, paid measurement does not lose its
    results to one subject). The subject is counted as an `error` outcome and the error's class (never its text: a provider's
    message is not ours to keep) is said on stderr. A database error is not swallowed: it ends the run with
    the one generic line."""
    try:
        return call()
    except psycopg.Error:
        raise
    except Exception as exc:  # noqa: BLE001 - broad on purpose
        print(
            f"lab_measure: {subject} (RAG {arm}): the evaluation raised {type(exc).__name__}; "
            "counted as an error",
            file=sys.stderr,
        )
        return None


def run_alert(
    conn: psycopg.Connection,
    subject: AlertSubject,
    truth: str,
    *,
    adapter: Any,
    cfg: config.Config,
) -> list[ArmRow]:
    """① twice for one alert, RAG off then on, each in its own READ ONLY transaction, as of the alert's first
    look (`subject.as_of`, C1): the burst count, the correlation section and the lookup are those of that
    instant. A subject with no `as_of` is evaluated with no bound, as `evaluate_alert` always did.
    """
    rows = []
    for arm in ARMS:
        _begin(conn)
        switches = dataclasses.replace(DEPLOYED, rag=arm == "on")
        spent_before = _spent(adapter)
        evaluation = _attempt(
            subject.alert_id,
            arm,
            lambda switches=switches: evaluate_alert(
                conn,
                subject.alert_id,
                adapter=adapter,
                cfg=cfg,
                switches=switches,
                as_of=subject.as_of,
            ),
        )
        seen = None
        if arm == "on":
            where = Subject("alert", subject.alert_id)
            seen = (
                error_seen(conn, where, before=subject.as_of)
                if evaluation is None
                else seen_for(
                    conn,
                    where,
                    applied=evaluation.rag_lookup_id,
                    before=subject.as_of,
                    entries_dropped=LEARNED_ENTRIES_DROPPED_WARNING in evaluation.built.warnings,
                )
            )
        conn.rollback()
        error_cost = max(_spent(adapter) - spent_before, 0.0) if evaluation is None else 0.0
        rows.append(_alert_row(subject, truth, arm, evaluation, seen, error_cost))
    return rows


def run_case(
    conn: psycopg.Connection,
    subject: CaseSubject,
    truth: str,
    as_of: datetime,
    *,
    adapter: Any,
    cfg: config.Config,
) -> list[ArmRow]:
    """② twice for one case, RAG off then on, as of the case's first ② run."""
    rows = []
    for arm in ARMS:
        _begin(conn)
        rag = arm == "on"
        spent_before = _spent(adapter)
        evaluation = _attempt(
            subject.case_id,
            arm,
            lambda rag=rag: evaluate_case(
                conn, subject.case_id, adapter=adapter, cfg=cfg, rag=rag, as_of=as_of
            ),
        )
        seen = None
        if arm == "on":
            where = Subject("case", subject.case_id.lower())
            seen = (
                error_seen(conn, where, before=as_of)
                if evaluation is None
                else seen_for(
                    conn,
                    where,
                    applied=evaluation.rag_lookup_id,
                    failed_kind=evaluation.rag_not_applied,
                    before=as_of,
                    skips_budget=True,
                )
            )
        conn.rollback()
        error_cost = max(_spent(adapter) - spent_before, 0.0) if evaluation is None else 0.0
        rows.append(_case_row(subject.case_id, truth, arm, evaluation, seen, error_cost, as_of))
    return rows


def with_leaks(
    conn: psycopg.Connection,
    rows: Sequence[ArmRow],
    runs_of: Mapping[tuple[int, str], frozenset[str]],
    cutoff: datetime,
    run_starts: Mapping[str, datetime],
) -> list[ArmRow]:
    """`rows` with the flags of every RAG-on row set: the leaks among the matches the prompt kept, whether
    its decision history holds same-run decisions, and how many of its matches could not be placed.
    `runs_of` is the runs each subject lies in, `run_starts` the start of every run."""
    seen_rows = [row for row in rows if row.seen is not None]
    matched = {entry for row in seen_rows for entry, _pct in row.seen.matches}
    examples = sorted(
        {a for row in seen_rows if row.seen.history_in_prompt for a in row.seen.history_examples}
    )
    if not matched and not any(row.seen.history_in_prompt for row in seen_rows):
        return list(rows)  # nothing to look up and no history to test
    _begin(conn)
    entries, alert_run, case_runs = leak_context(conn, sorted(matched), examples)
    conn.rollback()
    done = []
    for row in rows:
        if row.seen is None:
            done.append(row)
            continue
        ids = [entry for entry, _pct in row.seen.matches]
        subject_runs = runs_of[(row.tier, row.subject)]
        flags = leak_flags(
            ids,
            subject_runs=subject_runs,
            entries=entries,
            alert_run=alert_run,
            case_runs=case_runs,
            cutoff=cutoff,
        )
        history = history_same_run(
            row.seen, subject_runs=subject_runs, run_starts=run_starts, alert_run=alert_run
        )
        done.append(
            dataclasses.replace(
                row,
                leaks=flags,
                history_same_run=history,
                unplaceable=len(unplaceable(ids, entries)),
            )
        )
    return done


# ═══════════════════════════════════════════════════════════════════════════════════════════
# The estimate and the gate
# ═══════════════════════════════════════════════════════════════════════════════════════════


def estimate_measure(n1: int, n2: int, cfg: config.Config) -> tuple[int, float]:
    """`(calls, usd)` for `n1` alerts and `n2` cases, both arms, the repair margin included. An upper bound:
    each call is priced with its prompt at its token budget."""

    def per_call(budget: int, answer: int) -> float:
        return (budget * cfg.LLM_PRICE_IN_PER_M + answer * cfg.LLM_PRICE_OUT_PER_M) / 1_000_000

    calls = usd = 0.0
    for tier, n, budget in (
        (1, n1, cfg.PROMPT_TOTAL_BUDGET_TOKENS),
        (2, n2, cfg.CASE_PROMPT_BUDGET_TOKENS),
    ):
        count = n * len(ARMS) * CALLS_PER_SUBJECT[tier] * REPAIR_MARGIN
        calls += count
        usd += count * per_call(budget, ANSWER_TOKENS[tier])
    return math.ceil(round(calls, 9)), usd


def require_approval(args: argparse.Namespace, line: str) -> None:
    """Print the estimate; without `--yes` stop with exit 5. `--yes` is the Owner's go-ahead for this
    figure."""
    print(line)
    if not args.yes:
        raise Exit(
            EXIT_APPROVAL,
            "this spends money and needs the Owner's go-ahead: nothing was called. "
            "Run the same command again with --yes to spend up to the estimate.",
        )


# ═══════════════════════════════════════════════════════════════════════════════════════════
# Reports
# ═══════════════════════════════════════════════════════════════════════════════════════════


def _pct(rate: float | None) -> str:
    return "n/a" if rate is None else f"{rate * 100:.1f} %"


def _share(num: int, den: int) -> str:
    return f"{_pct(_rate(num, den))} ({num}/{den})"


def _write_text(path: Path, text: str) -> None:
    """A temporary file in the target directory, then a rename: a reader sees all or nothing."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_name)
        raise


def _json_text(doc: Mapping[str, Any]) -> str:
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def build_measure_report(
    *,
    test_runs: Sequence[Run],
    cutoff: datetime,
    cutoff_source: str,
    cfg: config.Config,
    tiers: dict[int, dict[str, Any]],
    rows: Sequence[ArmRow],
    partial: Mapping[str, Any] | None = None,
    spent_usd: float | None = None,
) -> dict[str, Any]:
    leaks_computed = partial is None or bool(partial["leaks_computed"])
    in_rows_usd = round(math.fsum(row.cost_usd for row in rows), 5)
    total_usd = in_rows_usd if spent_usd is None else round(max(spent_usd, in_rows_usd), 5)
    by_arm = {
        tier: {arm: [r for r in rows if r.tier == tier and r.arm == arm] for arm in ARMS}
        for tier in tiers
    }
    report_tiers = {}
    for tier, facts in tiers.items():
        report_tiers[str(tier)] = {
            **facts,
            "tier": tier,
            "arms": {
                arm: summarise(by_arm[tier][arm], leaks_computed=leaks_computed) for arm in ARMS
            },
            "paired": paired(by_arm[tier]["off"], by_arm[tier]["on"]),
            # where the RAG could act: the subjects whose RAG-on prompt carried at least one match
            "paired_with_matches": paired(
                by_arm[tier]["off"], by_arm[tier]["on"], with_matches=True
            ),
        }
    return {
        "tool": "lab_measure",
        "command": "measure",
        "partial": None if partial is None else dict(partial),
        "caveat": CAVEAT,
        "generated_at": datetime.now(UTC).isoformat(),
        "kb_cutoff": cutoff.isoformat(),
        "kb_cutoff_source": cutoff_source,
        "test_runs": [
            {
                "name": run.name,
                "starts_at": run.starts_at.isoformat(),
                "ends_at": run.ends_at.isoformat(),
            }
            for run in test_runs
        ],
        "thresholds_note": SETTINGS_NOTE,
        "thresholds": {
            "RAG_MIN_SCORE": cfg.RAG_MIN_SCORE,
            "RAG_LEVEL_GIONG": cfg.RAG_LEVEL_GIONG,
            "RAG_LEVEL_RAT_GIONG": cfg.RAG_LEVEL_RAT_GIONG,
            "RAG_RERANK_MODEL": cfg.RAG_RERANK_MODEL,
        },
        "model": cfg.LLM_MODEL_PROPOSER,
        "tiers": report_tiers,
        # what this run spent: the spend guard's total, which also holds the calls of a subject the run was
        # stopped in the middle of (they land in no row). The rows' own sum is beside it.
        "cost_usd": total_usd,
        "cost_in_rows_usd": in_rows_usd,
        "cost_unattributed_usd": round(max(total_usd - in_rows_usd, 0.0), 5),
        "rows": [row.to_json(leaks_computed=leaks_computed) for row in rows],
    }


#: What the header's thresholds and rerank model are: today's, not the lookups'.
SETTINGS_NOTE = "current settings (the stored lookups used the values in force when they ran)"

_TIER_TITLE = {1: "① alerts (triage)", 2: "② cases (investigation)"}


def _ids(ids: Sequence[str]) -> str:
    return ", ".join(f"`{i}`" for i in ids) if ids else "none"


def _tier_table(tier: Mapping[str, Any]) -> list[str]:
    """The rows of one tier's table: one line per measure, the RAG-off arm beside the RAG-on one."""
    off, on = tier["arms"]["off"], tier["arms"]["on"]
    rows = [
        ("answered", f"{off['answered']}/{off['n']}", f"{on['answered']}/{on['n']}"),
        ("no answer (by outcome)", _kv(off["no_answer"]), _kv(on["no_answer"])),
        (
            "accuracy",
            _share(off["correct"], off["answered"]),
            _share(on["correct"], on["answered"]),
        ),
    ]
    for key, name in (("tp_recall", "TP recall"), ("tp_precision", "TP precision")):
        rows.append(
            (
                name,
                _share(off[key]["num"], off[key]["den"]),
                _share(on[key]["num"], on[key]["den"]),
            )
        )
    rows += [
        ("held (gate / override)", str(off["held"]["total"]), str(on["held"]["total"])),
        (
            "- model wrong and held",
            str(off["held"]["model_wrong"]),
            str(on["held"]["model_wrong"]),
        ),
        (
            "- model right and held",
            str(off["held"]["model_right"]),
            str(on["held"]["model_right"]),
        ),
    ]
    rag = on["rag"]
    if rag is not None:
        coverage, failed, mean = rag["coverage"], rag["failed_lookups"], rag["mean_best_pct"]
        rows += [
            ("RAG coverage (>= 1 match)", "-", _share(coverage["with_match"], coverage["n"])),
            ("mean best match", "-", "n/a" if mean is None else f"{mean:.1f} %"),
            ("failed lookups", "-", _kv(failed["by_kind"])),
            (
                "no lookup / budget / not in the prompt",
                "-",
                f"{failed['no_lookup']} / {failed['budget']} / {failed['not_in_prompt']}",
            ),
            ("evaluation error (no prompt known)", "-", str(failed["evaluation_error"])),
        ]
    rows.append(("cost", f"${off['cost_usd']:.5f}", f"${on['cost_usd']:.5f}"))
    return ["| | RAG off | RAG on |", "|---|---|---|"] + [
        f"| {name} | {left} | {right} |" for name, left, right in rows
    ]


def render_measure_md(report: Mapping[str, Any]) -> str:
    thresholds = report["thresholds"]
    runs = ", ".join(
        f"`{run['name']}` ({run['starts_at']} to {run['ends_at']})" for run in report["test_runs"]
    )
    partial = report["partial"]
    lines = [
        "# Lab measurement" + ("" if partial is None else " - PARTIAL"),
        "",
        *(
            []
            if partial is None
            else [
                (
                    f"**PARTIAL: stopped by {partial['reason']} after {partial['done']['tier1']} of "
                    f"{partial['planned']['tier1']} alerts and {partial['done']['tier2']} of "
                    f"{partial['planned']['tier2']} cases; the rows below are the ones that finished.**"
                ),
                "",
            ]
        ),
        f"- Generated: {report['generated_at']}",
        (
            f"- Model: `{report['model']}`; rerank `{thresholds['RAG_RERANK_MODEL']}`; thresholds "
            f"{thresholds['RAG_MIN_SCORE']} / {thresholds['RAG_LEVEL_GIONG']} / "
            f"{thresholds['RAG_LEVEL_RAT_GIONG']} - {report['thresholds_note']}"
        ),
        f"- Test runs: {runs}",
        f"- KB cut-off: {report['kb_cutoff']} ({report['kb_cutoff_source']})",
        (
            f"- Cost: ${report['cost_usd']:.5f} (the spend guard's total for this run: "
            f"${report['cost_in_rows_usd']:.5f} is in the rows below, "
            f"${report['cost_unattributed_usd']:.5f} in no row)"
        ),
        "",
        (
            "The model's own conclusion is scored against the hand labels. Rates are over the subjects "
            "the model answered; a subject nobody labelled is excluded, never counted as FP. ①'s "
            "`verifier_*` outcomes (the proposer answered, the verifier did not) are unscored and are "
            "listed under no answer."
        ),
        "",
        f"**Caveat.** {report['caveat']}",
    ]
    for tier_key in sorted(report["tiers"]):
        tier = report["tiers"][tier_key]
        lines += ["", f"## {_TIER_TITLE[tier['tier']]}", ""]
        lines.append(
            f"- Subjects: {tier['subjects']}; unlabelled and excluded: {tier['unlabelled']} "
            f"({_ids(tier['unlabelled_ids'])}); scored population n = {tier['arms']['off']['n']}"
        )
        if tier["tier"] == 2:
            lines.append(
                f"- Labelled cases ② never ran on (no investigation): {tier['no_investigation']} "
                f"({_ids(tier['no_investigation_ids'])}); each case is evaluated as of its first ② run"
            )
        else:
            sources = tier["as_of_sources"]
            lines.append(
                "- Each alert is evaluated as of its first look: "
                f"{sources['first_look']} by the first ① proposer run of the alert, "
                f"{sources['delay']} by received_at + RAG_TRIAGE_DELAY_S ({tier['triage_delay_s']} s)"
            )
        lines += ["", *_tier_table(tier)]
        if tier["arms"]["on"]["rag"] is not None:
            lines += ["", NO_LOOKUP_NOTE]
        pair, pair_hit = tier["paired"], tier["paired_with_matches"]
        lines += [
            "",
            (
                f"Paired (the same {pair['n']} subjects, answered in both arms): accuracy RAG off "
                f"{_share(pair['off']['correct'], pair['n'])}, RAG on "
                f"{_share(pair['on']['correct'], pair['n'])}."
            ),
            "",
            (
                f"Paired, where the RAG could act (the same {pair_hit['n']} subjects whose RAG-on prompt "
                "carried at least one match, answered in both arms): accuracy RAG off "
                f"{_share(pair_hit['off']['correct'], pair_hit['n'])}, RAG on "
                f"{_share(pair_hit['on']['correct'], pair_hit['n'])}."
            ),
            "",
            (
                f"Correlation (both arms, an estimate): {tier['correlation_after_arrival']['count']} "
                "subject(s) whose correlation section shows a neighbour with an analyst decision recorded "
                "after the subject's first look: "
                f"{_ids(tier['correlation_after_arrival']['subjects'])}. It over-counts (the section's "
                "caps are not replayed) and under-counts (some decisions have no date)."
            ),
        ]
        rag = tier["arms"]["on"]["rag"]
        if rag is not None:
            leaks, history = rag["leaks"], rag["history"]
            if leaks is None:
                lines += [
                    "",
                    (
                        "Leaks and history (RAG on): not computed - the run stopped during the leak pass, "
                        "so `same_run`, `after_cutoff`, `history_same_run` and `unplaceable` are unknown, "
                        f"not zero. {history['in_prompt']} prompt(s) carried a decision history."
                    ),
                ]
                continue
            lines += [
                "",
                (
                    f"Leaks and history (RAG on): {leaks['flagged_subjects']} subject(s) flagged, "
                    "still counted above."
                ),
                f"- `same_run` ({leaks['same_run']['count']}): {_ids(leaks['same_run']['subjects'])}",
                (
                    f"- `after_cutoff` ({leaks['after_cutoff']['count']}): "
                    f"{_ids(leaks['after_cutoff']['subjects'])}"
                ),
                (
                    f"- `history_same_run` ({history['same_run']['count']} of {history['in_prompt']} "
                    f"prompts that carried a decision history): {_ids(history['same_run']['subjects'])}"
                ),
                (
                    f"- `unplaceable` ({leaks['unplaceable']['matches']} match(es) in "
                    f"{leaks['unplaceable']['count']} subject(s): the entry is gone or has no approval "
                    f"time, so the cut-off could not be tested): {_ids(leaks['unplaceable']['subjects'])}"
                ),
            ]
    return "\n".join(lines) + "\n"


def _kv(counts: Mapping[str, int]) -> str:
    return ", ".join(f"{k} {v}" for k, v in counts.items()) if counts else "none"


def render_table_md(title: str, table: Sequence[Mapping[str, Any]]) -> list[str]:
    lines = [
        f"### {title}",
        "",
        "| t | covered | coverage | agree | agreement (of covered) |",
        "|---|---|---|---|---|",
    ]
    for line in table:
        lines.append(
            f"| {line['t']:.2f} | {line['covered']}/{line['n']} | {_pct(line['coverage'])} "
            f"| {line['agree']}/{line['covered']} | {_pct(line['agreement'])} |"
        )
    return lines


def render_calibrate_md(report: Mapping[str, Any]) -> str:
    stored = report["stored"]
    runs = ", ".join(f"`{name}`" for name in report["runs"])
    lines = [
        "# Lab calibration",
        "",
        f"- Generated: {report['generated_at']}",
        f"- kb runs: {runs}",
        (
            f"- Labelled alerts with a stored ranking: n = {stored['n']}; unlabelled and excluded: "
            f"{stored['unlabelled']}; labelled without a stored ranking: {stored['no_ranking']}"
        ),
        "",
        (
            "Coverage: the share whose best score is at least t. Agreement: of those covered, the "
            "share whose best entry's conclusion agrees with the label (`confirmed_incident` with TP, "
            "the other four with FP)."
        ),
        "",
        *render_table_md("Stored ranking", stored["table"]),
    ]
    rescored = report["rescored"]
    if rescored is not None:
        lines += [
            "",
            *render_table_md(f"Re-scored with `{rescored['model']}`", rescored["table"]),
            "",
            (
                f"Alerts re-scored: {rescored['n']}; failed: {_kv(rescored['failed'])}; "
                f"tokens {rescored['tokens']}, cost ${rescored['cost_usd']:.5f}"
            ),
        ]
    return "\n".join(lines) + "\n"


# ═══════════════════════════════════════════════════════════════════════════════════════════
# The commands
# ═══════════════════════════════════════════════════════════════════════════════════════════


def _load_config(env_file: str) -> config.Config:
    try:
        return config.load(env_file=env_file)
    except ConfigError as exc:
        raise Exit(EXIT_DSN, f"cannot read the configuration: {exc}") from None


def _dsn_and_config(dsn_arg: str | None, cfg: config.Config) -> tuple[str, config.Config]:
    """The DSN (`--dsn`, else `DATABASE_URL`), and `cfg` with every DSN field blanked, so no `Config` this
    process holds can print one (DEC-122)."""
    dsn = dsn_arg or cfg.DATABASE_URL
    if not dsn:
        raise Exit(
            EXIT_DSN, "no DSN: pass --dsn, or set DATABASE_URL in the file named by --env-file"
        )
    blank = dataclasses.replace(
        cfg, DATABASE_URL="", DATABASE_URL_OWNER="", TEST_DATABASE_URL="", VECTOR_DATABASE_URL=""
    )
    return dsn, blank


def _connect(dsn: str) -> psycopg.Connection:
    try:
        return db.connect(dsn)
    except psycopg.Error as exc:  # a DSN libpq cannot parse or a server it cannot reach
        raise Exit(EXIT_DSN, f"could not open the database: {type(exc).__name__}") from None


def _runs_named(runs: Sequence[Run], names: Sequence[str], purpose: str) -> list[Run]:
    """The runs called `names`, each of the given purpose. An unknown name and a run of the other purpose are
    usage errors, named."""
    why = {
        "kb": "a test run: the thresholds must not be chosen on the test set",
        "test": "a kb run: it built the knowledge base and is not scored",
    }[purpose]
    by_name = {run.name: run for run in runs}
    chosen = []
    for name in names:
        run = by_name.get(name)
        if run is None:
            raise Exit(EXIT_USAGE, f"no lab run is called {name!r}")
        if run.purpose != purpose:
            raise Exit(EXIT_USAGE, f"{name!r} is {why}")
        chosen.append(run)
    return chosen


def _check_out_writable(out: Path) -> None:
    """The report directory exists and takes a file, checked BEFORE the estimate and the first paid call: a
    run that cannot write its report is not started."""
    try:
        out.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryFile(dir=out):
            pass
    except OSError as exc:
        raise Exit(
            EXIT_USAGE, f"--out cannot be written ({type(exc).__name__}): nothing was run"
        ) from None


def _listing(flagged: Mapping[str, bool]) -> dict[str, Any]:
    """`{"count", "subjects"}` of the subjects whose flag is set."""
    ids = sorted(subject for subject, flag in flagged.items() if flag)
    return {"count": len(ids), "subjects": ids}


def cmd_measure(args: argparse.Namespace) -> int:
    try:
        tiers = parse_tiers(args.tiers)
        cutoff_arg = parse_cutoff(args.kb_cutoff) if args.kb_cutoff else None
    except ValueError as exc:
        raise Exit(EXIT_USAGE, str(exc)) from None
    cfg = _load_config(args.env_file)
    if not cfg.llm_enabled:  # evaluate_alert does not check it
        raise Exit(
            EXIT_USAGE,
            "measure needs the LLM, and it is disabled here: LLM_MODEL_PROPOSER is empty in the "
            "environment and in --env-file",
        )
    dsn, cfg = _dsn_and_config(args.dsn, cfg)

    rows: list[ArmRow] = []
    guard: llm_cache.SpendGuard | None = None
    done = {"tier1": 0, "tier2": 0}
    interrupted: BaseException | None = None
    leaks_computed = True
    conn = _connect(dsn)
    try:
        _begin(conn)
        runs = load_runs(conn)
        all_test_runs = [run for run in runs if run.purpose == "test"]
        if args.test_runs:
            test_runs = _runs_named(runs, args.test_runs, "test")
        else:
            test_runs = all_test_runs
        if not test_runs:
            raise Exit(EXIT_NOT_READY, "no test run is recorded: there is nothing to score")
        if cutoff_arg is not None:
            cutoff, cutoff_source = cutoff_arg, "--kb-cutoff"
        else:
            # the knowledge base is frozen when testing starts: the earliest test run of all, not only the
            # ones scored here
            cutoff, cutoff_source = min(run.starts_at for run in all_test_runs), "earliest test run"
        run_starts = {run.run_id: run.starts_at for run in runs}

        facts: dict[int, dict[str, Any]] = {}
        alert_work: list[tuple[AlertSubject, str]] = []
        case_work: list[tuple[CaseSubject, str, datetime]] = []
        runs_of: dict[tuple[int, str], frozenset[str]] = {}
        if 1 in tiers:
            heads = load_alert_subjects(conn, test_runs, triage_delay_s=cfg.RAG_TRIAGE_DELAY_S)
            alert_work = [(s, s.label) for s in heads if s.label is not None]
            unlabelled = [s.alert_id for s in heads if s.label is None]
            sources = Counter(s.as_of_source for s, _label in alert_work)
            facts[1] = {
                "subjects": len(heads),
                "labelled": len(alert_work),
                "unlabelled": len(unlabelled),
                "unlabelled_ids": unlabelled,
                # which way each scored alert's `as_of` was named (C1): both are counted
                "as_of_sources": {
                    AS_OF_FIRST_LOOK: sources[AS_OF_FIRST_LOOK],
                    AS_OF_DELAY: sources[AS_OF_DELAY],
                },
                "triage_delay_s": cfg.RAG_TRIAGE_DELAY_S,
            }
            for subject, _label in alert_work:
                runs_of[(1, subject.alert_id)] = frozenset({subject.run_id})
        if 2 in tiers:
            cases = load_case_subjects(conn, test_runs)
            unlabelled = [c.case_id for c in cases if c.truth is None]
            not_run = [c.case_id for c in cases if c.truth is not None and c.first_run_at is None]
            case_work = [
                (c, c.truth, c.first_run_at)
                for c in cases
                if c.truth is not None and c.first_run_at is not None
            ]
            facts[2] = {
                "subjects": len(cases),
                "labelled": len(cases) - len(unlabelled),
                "unlabelled": len(unlabelled),
                "unlabelled_ids": unlabelled,
                "no_investigation": len(not_run),
                "no_investigation_ids": not_run,
            }
            for case, _truth, _as_of in case_work:
                runs_of[(2, case.case_id)] = case.runs
        if not alert_work and not case_work:
            raise Exit(
                EXIT_NOT_READY, "no labelled subject in the test runs: there is nothing to score"
            )

        month_spend = llm_runs.month_spend_usd(conn)
        calls, usd = estimate_measure(len(alert_work), len(case_work), cfg)
        _check_out_writable(Path(args.out))
        require_approval(
            args,
            f"estimate: lab_measure measure tiers={','.join(map(str, tiers))} n1={len(alert_work)} "
            f"n2={len(case_work)} calls≈{calls} usd≤{usd:.4f} (an upper bound: every prompt priced at its "
            f"token budget) month_spend={month_spend:.4f} cap={cfg.LLM_MONTHLY_USD_CAP}",
        )

        # R1: the subjects whose correlation section can show a decision taken after their first look (reads
        # only). The section holds the neighbours received before `as_of`, so only those are looked at.
        if 1 in tiers:
            facts[1]["correlation_after_arrival"] = _listing(
                {
                    s.alert_id: alert_correlation_after(
                        conn, s.alert_id, s.as_of, received_before=s.as_of
                    )
                    for s, _ in alert_work
                }
            )
        if 2 in tiers:
            facts[2]["correlation_after_arrival"] = _listing(
                {
                    c.case_id: case_correlation_after(conn, c.case_id, as_of, received_before=as_of)
                    for c, _t, as_of in case_work
                }
            )
        conn.rollback()

        guard = llm_cache.SpendGuard(lambda: month_spend, cfg.LLM_MONTHLY_USD_CAP, cfg)
        adapter = _Metered(DeepSeekAdapter(cfg, spent_usd=guard.total_usd), guard)
        try:
            for index, (subject, label) in enumerate(alert_work, 1):
                print(f"tier 1: {index}/{len(alert_work)} {subject.alert_id}")
                rows += run_alert(conn, subject, label, adapter=adapter, cfg=cfg)
                done["tier1"] += 1
            for index, (case, truth, as_of) in enumerate(case_work, 1):
                print(f"tier 2: {index}/{len(case_work)} {case.case_id}")
                rows += run_case(conn, case, truth, as_of, adapter=adapter, cfg=cfg)
                done["tier2"] += 1
        except (psycopg.Error, KeyboardInterrupt) as exc:
            # a paid run does not end without a report: what finished is written, marked PARTIAL
            interrupted = exc
        try:
            rows = with_leaks(conn, rows, runs_of, cutoff, run_starts)
        except (psycopg.Error, KeyboardInterrupt) as exc:
            leaks_computed = False  # the report says "not computed", never "0 flagged"
            interrupted = interrupted or exc
    finally:
        with contextlib.suppress(psycopg.Error):
            conn.rollback()
        conn.close()

    partial = None
    if interrupted is not None:
        partial = {
            "reason": type(interrupted).__name__,
            "done": done,
            "planned": {"tier1": len(alert_work), "tier2": len(case_work)},
            "leaks_computed": leaks_computed,
        }
    report = build_measure_report(
        test_runs=test_runs,
        cutoff=cutoff,
        cutoff_source=cutoff_source,
        cfg=cfg,
        tiers=facts,
        rows=rows,
        partial=partial,
        spent_usd=None if guard is None else guard.live_spent_usd,
    )
    stamp = _stamp() + ("_PARTIAL" if partial is not None else "")
    out = Path(args.out)
    _write_text(out / f"lab_measure_{stamp}.json", _json_text(report))
    _write_text(out / f"lab_measure_{stamp}.md", render_measure_md(report))
    for tier_key in sorted(report["tiers"]):
        for arm in ARMS:
            arm_report = report["tiers"][tier_key]["arms"][arm]
            print(
                f"tier {tier_key} RAG {arm}: n={arm_report['n']} answered={arm_report['answered']} "
                f"accuracy={_pct(arm_report['accuracy'])} cost=${arm_report['cost_usd']:.5f}"
            )
    print(f"report: {out / f'lab_measure_{stamp}'}.md and .json (cost ${report['cost_usd']:.5f})")

    if interrupted is not None:
        if isinstance(interrupted, psycopg.Error):
            # the class only: libpq quotes a malformed address, password included, in the text of the error
            print(f"lab_measure: database error: {type(interrupted).__name__}", file=sys.stderr)
        else:
            print("lab_measure: interrupted", file=sys.stderr)
        print(
            "lab_measure: a PARTIAL report was written for the subjects that finished",
            file=sys.stderr,
        )
        return EXIT_PARTIAL
    arms = [arm for tier in report["tiers"].values() for arm in tier["arms"].values()]
    capped = sum(arm["no_answer"].get(outcome, 0) for arm in arms for outcome in CAP_OUTCOMES)
    if capped:
        print(
            f"lab_measure: stopped by the monthly cap: {capped} evaluation(s) were refused a call and "
            "are counted as no answer (cap, verifier_cap)",
            file=sys.stderr,
        )
        return EXIT_CAP
    if not any(arm["answered"] for arm in arms):
        print(
            "lab_measure: nothing was answered in any arm: see no answer, by outcome, in the report",
            file=sys.stderr,
        )
        return EXIT_NO_ANSWER
    return EXIT_OK


# ── calibrate ──────────────────────────────────────────────────────────────────────────────

_CAL_INPUTS_SQL = """
    SELECT a.alert_id, l.label,
           (SELECT x.ranked FROM rag_results x
             WHERE x.subject_kind = 'alert' AND x.subject_id = a.alert_id AND x.ranked IS NOT NULL
             ORDER BY x.created_at DESC, x.lookup_id LIMIT 1)
      FROM lab_runs r
      JOIN alerts a ON a.received_at >= r.starts_at AND a.received_at < r.ends_at
                   AND a.duplicate_of IS NULL
      LEFT JOIN lab_labels l ON l.alert_id = a.alert_id
     WHERE r.run_id = ANY(%s::uuid[])
     ORDER BY r.starts_at, a.received_at, a.alert_id
"""


@dataclass
class _CalJob:
    """One labelled alert with a stored ranking: the best stored candidate, and what a re-score needs."""

    alert_id: str
    label: str
    ranked: list[Any]
    best: tuple[str, float] | None
    candidates: list[Any] = field(
        default_factory=list
    )  # entries (digest order), found in the database
    query: str = ""
    documents: list[str] = field(default_factory=list)


def _candidate_ids(ranked: Sequence[Any]) -> list[str]:
    seen: list[str] = []
    for item in ranked:
        entry_id = item.get("entry_id") if isinstance(item, dict) else None
        if isinstance(entry_id, str) and entry_id and entry_id not in seen:
            seen.append(entry_id)
    return seen


def _rerank(query: str, documents: list[str], cfg: config.Config) -> tuple[dict[int, float], int]:
    """One Voyage rerank, a 429 waited out (`RATE_LIMIT_WAIT_S`, at most `RATE_LIMIT_RETRIES` more tries).
    `RagUnavailable` reaches the caller with its closed kind."""
    for attempt in range(RATE_LIMIT_RETRIES + 1):
        try:
            scores, usage = voyage.rerank(query, documents, cfg=cfg)
            return scores, usage.total_tokens
        except RagUnavailable as exc:
            if exc.kind != "rate_limit" or attempt == RATE_LIMIT_RETRIES:
                raise
            time.sleep(RATE_LIMIT_WAIT_S)
    raise AssertionError("unreachable")  # pragma: no cover


def cmd_calibrate(args: argparse.Namespace) -> int:
    cfg = _load_config(args.env_file)
    dsn, cfg = _dsn_and_config(args.dsn, cfg)

    conn = _connect(dsn)
    try:
        _begin(conn)
        runs = _runs_named(load_runs(conn), args.runs, "kb")
        rows = conn.execute(_CAL_INPUTS_SQL, ([run.run_id for run in runs],)).fetchall()
        unlabelled = [alert_id for alert_id, label, _ranked in rows if label is None]
        labelled = [(a, label, ranked) for a, label, ranked in rows if label is not None]
        jobs = [
            _CalJob(alert_id, label, ranked, best_of(ranked))
            for alert_id, label, ranked in labelled
            if isinstance(ranked, list)
        ]
        no_ranking = len(labelled) - len(jobs)
        if not jobs:
            raise Exit(
                EXIT_NOT_READY,
                "no labelled alert of these runs has a stored ranking: there is nothing to calibrate",
            )
        entry_ids = sorted({e for job in jobs for e in _candidate_ids(job.ranked)})
        entries = {e: entry_by_id(conn, e) for e in entry_ids}
        stored_rows = [
            CalRow(
                job.alert_id,
                job.label,
                None if job.best is None else job.best[1],
                (
                    None
                    if job.best is None or entries.get(job.best[0]) is None
                    else entries[job.best[0]].conclusion
                ),
            )
            for job in jobs
        ]
        report: dict[str, Any] = {
            "tool": "lab_measure",
            "command": "calibrate",
            "generated_at": datetime.now(UTC).isoformat(),
            "runs": [run.name for run in runs],
            "stored": {
                "n": len(stored_rows),
                "unlabelled": len(unlabelled),
                "unlabelled_ids": unlabelled,
                "no_ranking": no_ranking,
                "table": calibration_table(stored_rows),
            },
            "rescored": None,
        }

        if args.rerank_model:
            rescore_cfg = dataclasses.replace(cfg, RAG_RERANK_MODEL=args.rerank_model)
            for job in jobs:
                job.candidates = [
                    entries[e] for e in _candidate_ids(job.ranked) if entries.get(e) is not None
                ]
                job.documents = [match.entry_digest(entry) for entry in job.candidates]
                if job.candidates:
                    job.query = fingerprint.alert_fingerprint(conn, job.alert_id).text
            conn.rollback()
            work = [job for job in jobs if job.candidates]
            chars = sum(
                len(job.query) * len(job.documents) + sum(map(len, job.documents)) for job in work
            )
            tokens_est = math.ceil(chars / CHARS_PER_TOKEN)
            usd = voyage.cost_usd(0, tokens_est, cfg)
            _check_out_writable(Path(args.out))
            require_approval(
                args,
                f"estimate: lab_measure calibrate rerank model={args.rerank_model} calls={len(work)} "
                f"tokens≤{tokens_est} usd≤{usd:.5f} (the stored candidates, re-scored once per alert)",
            )
            report["rescored"] = _rescore(jobs, rescore_cfg, args.rerank_model)
    finally:
        with contextlib.suppress(psycopg.Error):
            conn.rollback()
        conn.close()

    markdown = render_calibrate_md(report)
    print(markdown, end="")
    stamp = _stamp()
    out = Path(args.out)
    _write_text(out / f"lab_calibrate_{stamp}.json", _json_text(report))
    _write_text(out / f"lab_calibrate_{stamp}.md", markdown)
    return EXIT_OK


def _rescore(jobs: Sequence[_CalJob], cfg: config.Config, model: str) -> dict[str, Any]:
    rows: list[CalRow] = []
    failed: Counter[str] = Counter()
    tokens = 0
    for job in jobs:
        if not job.candidates:
            rows.append(
                CalRow(job.alert_id, job.label, None, None)
            )  # nothing to score, as when stored
            continue
        try:
            scores, used = _rerank(job.query, job.documents, cfg)
        except RagUnavailable as exc:
            if exc.kind in ("auth", "quota"):
                # `auth` is also what an EMPTY key gives (no request is sent), so it does not say "refused"
                cause = (
                    "the Voyage key is missing or was refused"
                    if exc.kind == "auth"
                    else "Voyage refused the request"
                )
                raise Exit(
                    EXIT_NOT_READY,
                    f"{cause} ({exc.kind}): check VOYAGE_API_KEY (set in this container) and the account",
                ) from None
            failed[exc.kind] += 1
            continue
        tokens += used
        ordered = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
        if ordered:
            index, score = ordered[0]
            rows.append(CalRow(job.alert_id, job.label, score, job.candidates[index].conclusion))
        else:
            rows.append(CalRow(job.alert_id, job.label, None, None))
    return {
        "model": model,
        "n": len(rows),
        "failed": dict(sorted(failed.items())),
        "tokens": tokens,
        "cost_usd": voyage.cost_usd(0, tokens, cfg),
        "table": calibration_table(rows),
    }


# ── the command line ───────────────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lab_measure.py",
        description="Score ① and ② against the lab's hand labels, RAG off and on, or calibrate the "
        "RAG thresholds on the knowledge-base runs.",
        epilog=_EPILOG,
        allow_abbrev=False,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--env-file", default=".env", metavar="PATH")
        p.add_argument("--out", default="eval/results/lab/", metavar="DIR")
        p.add_argument("--dsn", default=None, metavar="DSN", help="never printed")
        p.add_argument(
            "--yes",
            action="store_true",
            help="the Owner's go-ahead to spend the printed estimate (without it: exit 5)",
        )

    measure = sub.add_parser(
        "measure", help="score ① and ② over the test runs", epilog=_EPILOG, allow_abbrev=False
    )
    measure.add_argument("--test-runs", nargs="+", default=None, metavar="NAME")
    measure.add_argument("--kb-cutoff", default=None, metavar="ISO")
    measure.add_argument("--tiers", default="1,2", metavar="1,2")
    common(measure)

    calibrate = sub.add_parser(
        "calibrate",
        help="coverage and agreement per threshold, on kb runs",
        epilog=_EPILOG,
        allow_abbrev=False,
    )
    calibrate.add_argument("--runs", nargs="+", required=True, metavar="NAME")
    calibrate.add_argument("--rerank-model", default=None, metavar="M")
    common(calibrate)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:  # --help (0) or argparse's own usage error (2)
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE
    try:
        return cmd_measure(args) if args.command == "measure" else cmd_calibrate(args)
    except Exit as exc:
        print(f"lab_measure: {exc.message}", file=sys.stderr)
        return exc.code
    except psycopg.Error as exc:
        # The class only: libpq quotes a malformed address, password included, in the text of the error.
        print(f"lab_measure: database error: {type(exc).__name__}", file=sys.stderr)
        return EXIT_DSN


if __name__ == "__main__":
    raise SystemExit(main())
