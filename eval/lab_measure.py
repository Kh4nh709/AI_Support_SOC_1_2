#!/usr/bin/env python3
"""The lab measurement (P14-T11, DEC-213, spec §6): how well ① and ② conclude, with the RAG off and on,
against the labels an admin gave by hand.

``measure`` scores the **model's own conclusion** over the alerts and cases of the ``test`` runs:

* **Subjects.** ①: the queue heads (``duplicate_of IS NULL``) received inside a test run's window; only the
  labelled ones are scored. ②: the cases with a head alert in a test run. A case is a real attack when
  any head is labelled TP; with no TP and a head nobody labelled it is *unlabelled*; otherwise it is FP. An
  unlabelled subject is excluded and counted, never scored as FP. A labelled case whose ② never ran has no
  ② answer: it is counted as ``no_investigation``.
* **Two runs per subject.** ①: ``evaluate_alert`` with ``DEPLOYED`` and ``rag`` off, then on; the RAG-on run
  uses the lookup stored when the alert arrived (what ``evaluate_alert`` reads). ②: ``evaluate_case``, ``rag``
  off then on, **as of the case's first ② run** (``as_of``): the dossier then holds no tier-2 note and no
  earlier ② answer written after that instant, and the RAG arm reads the newest lookup created before it.
  Nothing is looked up again; a subject with no usable lookup is counted (failed lookups by kind, "no
  lookup", "budget") and scored without RAG.
* **The model's TP.** ①: ``proposed_verdict == "true_positive"``. ②: ``model_conclusion ==
  "confirmed_incident"``. **Held.** ①: ``final_verdict == "needs_review"``. ②: a non-empty ``held_by``, or a
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

The DSN is ``--dsn``, else ``DATABASE_URL`` from ``--env-file``. It is never printed, and no ``Config`` in this
process keeps it. A database error is one generic line (the class of the error, never its text: libpq quotes
a malformed address, password included).

Exit codes: 0 done; 2 usage; 3 not ready (no test run, nothing to score, Voyage refused the key); 4 the DSN or
the database is unusable; 5 the estimate needs approval (``--yes``); 6 stopped by the monthly cap.
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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg

# eval/ is a composition root outside backend/ and not a package on sys.path: its siblings are imported by
# name once the directory is on the path (the pattern of run_configs.py), and `app.*` comes from the caller
# (PYTHONPATH=backend, or pytest's pythonpath).
sys.path.insert(0, str(Path(__file__).resolve().parent))

import llm_cache  # P7-T02: the spend guard
from app.audit import llm_runs
from app.infra import config, db
from app.infra.errors import ConfigError
from app.llm import verdicts
from app.llm.adapter import DeepSeekAdapter
from app.rag import fingerprint, match, voyage
from app.rag.entries import entry_by_id
from app.rag.failures import RagUnavailable
from app.rag.lookup import UNKNOWN_FAILURE_KIND, LookupResult, latest_lookup
from app.rag.subject import Subject
from app.tier1.triage import DEPLOYED, evaluate_alert
from app.tier2.investigate import evaluate_case, lookups_before

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NOT_READY = 3
EXIT_DSN = 4
EXIT_APPROVAL = 5
EXIT_CAP = 6

TRUE_POSITIVE = "true_positive"
FALSE_POSITIVE = "false_positive"
CONFIRMED_INCIDENT = "confirmed_incident"
#: Kept in the report so the reader sees which `needs_review` is the system's.
NEEDS_REVIEW = "needs_review"
NEED_MORE_DATA = "need_more_data"

ARMS = ("off", "on")
LEAK_KINDS = ("same_run", "after_cutoff")

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
    "5 the estimate needs approval (--yes); 6 stopped by the monthly cap."
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
    """What a RAG-on subject saw of its lookup. `status`: `ok` / `empty` (a lookup a prompt may use),
    `failed` (with its closed `failure_kind`), `budget` (a cap was reached, no material) or `none` (no
    lookup at all). `matches` are `(entry_id, percentage)` in the stored order, best first."""

    status: str
    failure_kind: str | None
    matches: tuple[tuple[str, int], ...]

    @property
    def best_pct(self) -> int | None:
        return max((pct for _entry, pct in self.matches), default=None)

    def to_json(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "failure_kind": self.failure_kind,
            "matches": len(self.matches),
            "best_pct": self.best_pct,
        }


@dataclass(frozen=True)
class ArmRow:
    """One subject in one arm: closed tokens and numbers, nothing a model or an alert wrote. `model_tp` is
    None when the model gave no answer (`outcome` says why); `held` is the gate's or the override's hold.
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

    @property
    def correct(self) -> bool | None:
        return None if self.model_tp is None else self.model_tp == (self.truth == TRUE_POSITIVE)

    def to_json(self) -> dict[str, Any]:
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
        if self.seen is not None:
            row["lookup"] = self.seen.to_json()
            row["leaks"] = list(self.leaks)
        return row


def summarise(rows: Sequence[ArmRow]) -> dict[str, Any]:
    """The numbers of one arm of one tier. `n` is every subject of the arm; the rates are over the subjects
    the model answered (`answered`), and `no_answer` says by outcome why the others were not scored. A rate
    with nothing to divide is None, never 0. Held is split by whether the model's own conclusion was right.
    `rag` is None for an arm that read no lookup."""
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
        "rag": _rag_summary(rows),
    }


def _rag_summary(rows: Sequence[ArmRow]) -> dict[str, Any] | None:
    seen_rows = [row for row in rows if row.seen is not None]
    if not seen_rows:
        return None
    covered = [row for row in seen_rows if row.seen.matches]
    failed = Counter(
        (row.seen.failure_kind or UNKNOWN_FAILURE_KIND)
        for row in seen_rows
        if row.seen.status == "failed"
    )
    leaks = {
        kind: {
            "count": sum(1 for row in seen_rows if kind in row.leaks),
            "subjects": sorted(row.subject for row in seen_rows if kind in row.leaks),
        }
        for kind in LEAK_KINDS
    }
    leaks["flagged_subjects"] = sum(1 for row in seen_rows if row.leaks)
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
        },
        "leaks": leaks,
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
    alert_id: str
    run_id: str
    label: str | None


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
    SELECT a.alert_id, r.run_id::text, l.label
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


def load_alert_subjects(conn: psycopg.Connection, runs: Sequence[Run]) -> list[AlertSubject]:
    rows = conn.execute(_ALERT_SUBJECTS_SQL, ([run.run_id for run in runs],)).fetchall()
    return [AlertSubject(*row) for row in rows]


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


def seen_of(result: LookupResult | None) -> Seen:
    if result is None:
        return Seen("none", None, ())
    kind = (result.failure_kind or UNKNOWN_FAILURE_KIND) if result.status == "failed" else None
    return Seen(result.status, kind, tuple((m.entry_id, m.pct) for m in result.matches))


def seen_of_alert(conn: psycopg.Connection, alert_id: str) -> Seen:
    """The lookup ① reads (`evaluate_alert`): the alert's newest, whatever its status."""
    return seen_of(latest_lookup(conn, Subject("alert", alert_id)))


def seen_of_case(conn: psycopg.Connection, case_id: str, as_of: datetime) -> Seen:
    """The lookup ② reads as of an instant (`evaluate_case`): the newest created before it decides; a
    `failed` one is the notice, and a `budget` one beside an older usable one does not hide it."""
    newest, usable = lookups_before(conn, case_id, as_of)
    if newest is None or newest.status == "failed" or usable is None:
        return seen_of(newest)
    return seen_of(usable)


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def leak_context(
    conn: psycopg.Connection, entry_ids: Sequence[str]
) -> tuple[dict[str, EntryFacts], dict[str, str], dict[str, frozenset[str]]]:
    """For the entries matched: their facts, the run (any purpose) of each source alert, and the runs of each
    source case's heads."""
    entries: dict[str, EntryFacts] = {}
    entry_ids = [entry_id for entry_id in entry_ids if _is_uuid(entry_id)]  # a stored id is text
    for entry_id, alerts, cases, approved in conn.execute(
        "SELECT entry_id::text, source_alert_ids, source_case_ids::text[], approved_at"
        " FROM knowledge_entries WHERE entry_id = ANY(%s::uuid[])",
        (list(entry_ids),),
    ):
        entries[entry_id] = EntryFacts(frozenset(alerts), frozenset(cases), approved)
    alerts = sorted({a for facts in entries.values() for a in facts.source_alerts})
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

    def complete(self, **kwargs: Any) -> Any:
        self._guard.check()
        result = self._inner.complete(**kwargs)
        self._guard.record(result.usage)
        return result


def _alert_row(
    subject: AlertSubject, truth: str, arm: str, evaluation: Any | None, seen: Seen | None
) -> ArmRow:
    if evaluation is None:
        return ArmRow(1, subject.alert_id, truth, arm, "error", None, None, None, False, 0.0, seen)
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
    )


def _case_row(
    case_id: str, truth: str, arm: str, evaluation: Any | None, seen: Seen | None
) -> ArmRow:
    if evaluation is None:
        return ArmRow(2, case_id, truth, arm, "error", None, None, None, False, 0.0, seen)
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
    )


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
    """① twice for one alert, RAG off then on, each in its own READ ONLY transaction."""
    rows = []
    for arm in ARMS:
        _begin(conn)
        switches = dataclasses.replace(DEPLOYED, rag=arm == "on")
        evaluation = _attempt(
            subject.alert_id,
            arm,
            lambda switches=switches: evaluate_alert(
                conn, subject.alert_id, adapter=adapter, cfg=cfg, switches=switches
            ),
        )
        seen = seen_of_alert(conn, subject.alert_id) if arm == "on" else None
        conn.rollback()
        rows.append(_alert_row(subject, truth, arm, evaluation, seen))
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
        evaluation = _attempt(
            subject.case_id,
            arm,
            lambda rag=rag: evaluate_case(
                conn, subject.case_id, adapter=adapter, cfg=cfg, rag=rag, as_of=as_of
            ),
        )
        seen = seen_of_case(conn, subject.case_id, as_of) if arm == "on" else None
        conn.rollback()
        rows.append(_case_row(subject.case_id, truth, arm, evaluation, seen))
    return rows


def with_leaks(
    conn: psycopg.Connection,
    rows: Sequence[ArmRow],
    runs_of: Mapping[tuple[int, str], frozenset[str]],
    cutoff: datetime,
) -> list[ArmRow]:
    """`rows` with the leak flags of every RAG-on row set. `runs_of` is the runs each subject lies in."""
    matched = {entry for row in rows if row.seen is not None for entry, _pct in row.seen.matches}
    if not matched:
        return list(rows)
    _begin(conn)
    entries, alert_run, case_runs = leak_context(conn, sorted(matched))
    conn.rollback()
    done = []
    for row in rows:
        if row.seen is None or not row.seen.matches:
            done.append(row)
            continue
        flags = leak_flags(
            [entry for entry, _pct in row.seen.matches],
            subject_runs=runs_of[(row.tier, row.subject)],
            entries=entries,
            alert_run=alert_run,
            case_runs=case_runs,
            cutoff=cutoff,
        )
        done.append(dataclasses.replace(row, leaks=flags))
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
) -> dict[str, Any]:
    by_arm = {
        tier: {arm: [r for r in rows if r.tier == tier and r.arm == arm] for arm in ARMS}
        for tier in tiers
    }
    report_tiers = {}
    for tier, facts in tiers.items():
        report_tiers[str(tier)] = {
            **facts,
            "tier": tier,
            "arms": {arm: summarise(by_arm[tier][arm]) for arm in ARMS},
        }
    return {
        "tool": "lab_measure",
        "command": "measure",
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
        "thresholds": {
            "RAG_MIN_SCORE": cfg.RAG_MIN_SCORE,
            "RAG_LEVEL_GIONG": cfg.RAG_LEVEL_GIONG,
            "RAG_LEVEL_RAT_GIONG": cfg.RAG_LEVEL_RAT_GIONG,
            "RAG_RERANK_MODEL": cfg.RAG_RERANK_MODEL,
        },
        "model": cfg.LLM_MODEL_PROPOSER,
        "tiers": report_tiers,
        "cost_usd": round(math.fsum(row.cost_usd for row in rows), 5),
        "rows": [row.to_json() for row in rows],
    }


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
            ("no lookup / budget", "-", f"{failed['no_lookup']} / {failed['budget']}"),
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
    lines = [
        "# Lab measurement",
        "",
        f"- Generated: {report['generated_at']}",
        (
            f"- Model: `{report['model']}`; rerank `{thresholds['RAG_RERANK_MODEL']}`; thresholds "
            f"{thresholds['RAG_MIN_SCORE']} / {thresholds['RAG_LEVEL_GIONG']} / "
            f"{thresholds['RAG_LEVEL_RAT_GIONG']}"
        ),
        f"- Test runs: {runs}",
        f"- KB cut-off: {report['kb_cutoff']} ({report['kb_cutoff_source']})",
        f"- Cost: ${report['cost_usd']:.5f}",
        "",
        (
            "The model's own conclusion is scored against the hand labels. Rates are over the subjects "
            "the model answered; a subject nobody labelled is excluded, never counted as FP."
        ),
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
                f"({_ids(tier['no_investigation_ids'])})"
            )
        lines += ["", *_tier_table(tier)]
        rag = tier["arms"]["on"]["rag"]
        if rag is not None:
            leaks = rag["leaks"]
            lines += [
                "",
                f"Leaks (RAG on): {leaks['flagged_subjects']} subject(s) flagged, still counted above.",
                f"- `same_run` ({leaks['same_run']['count']}): {_ids(leaks['same_run']['subjects'])}",
                (
                    f"- `after_cutoff` ({leaks['after_cutoff']['count']}): "
                    f"{_ids(leaks['after_cutoff']['subjects'])}"
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

        facts: dict[int, dict[str, Any]] = {}
        alert_work: list[tuple[AlertSubject, str]] = []
        case_work: list[tuple[CaseSubject, str, datetime]] = []
        runs_of: dict[tuple[int, str], frozenset[str]] = {}
        if 1 in tiers:
            heads = load_alert_subjects(conn, test_runs)
            alert_work = [(s, s.label) for s in heads if s.label is not None]
            unlabelled = [s.alert_id for s in heads if s.label is None]
            facts[1] = {
                "subjects": len(heads),
                "labelled": len(alert_work),
                "unlabelled": len(unlabelled),
                "unlabelled_ids": unlabelled,
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
        require_approval(
            args,
            f"estimate: lab_measure measure tiers={','.join(map(str, tiers))} n1={len(alert_work)} "
            f"n2={len(case_work)} calls≈{calls} usd≤{usd:.4f} (an upper bound: every prompt priced at its "
            f"token budget) month_spend={month_spend:.4f} cap={cfg.LLM_MONTHLY_USD_CAP}",
        )

        guard = llm_cache.SpendGuard(lambda: month_spend, cfg.LLM_MONTHLY_USD_CAP, cfg)
        adapter = _Metered(DeepSeekAdapter(cfg, spent_usd=guard.total_usd), guard)
        rows: list[ArmRow] = []
        for index, (subject, label) in enumerate(alert_work, 1):
            print(f"tier 1: {index}/{len(alert_work)} {subject.alert_id}")
            rows += run_alert(conn, subject, label, adapter=adapter, cfg=cfg)
        for index, (case, truth, as_of) in enumerate(case_work, 1):
            print(f"tier 2: {index}/{len(case_work)} {case.case_id}")
            rows += run_case(conn, case, truth, as_of, adapter=adapter, cfg=cfg)
        rows = with_leaks(conn, rows, runs_of, cutoff)
    finally:
        with contextlib.suppress(psycopg.Error):
            conn.rollback()
        conn.close()

    report = build_measure_report(
        test_runs=test_runs,
        cutoff=cutoff,
        cutoff_source=cutoff_source,
        cfg=cfg,
        tiers=facts,
        rows=rows,
    )
    stamp = _stamp()
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
    capped = sum(
        arm["no_answer"].get("cap", 0)
        for tier in report["tiers"].values()
        for arm in tier["arms"].values()
    )
    if capped:
        print(
            f"lab_measure: stopped by the monthly cap: {capped} evaluation(s) were refused a call and "
            "are counted as no answer (cap)",
            file=sys.stderr,
        )
        return EXIT_CAP
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
                raise Exit(
                    EXIT_NOT_READY,
                    f"Voyage refused the request ({exc.kind}): check VOYAGE_API_KEY and the account",
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
