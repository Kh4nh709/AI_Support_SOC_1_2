#!/usr/bin/env python3
"""Export clusters awaiting a blind label and import the two labelers' verdicts.

Four subcommands the Owner runs on 27-28/09 from the primary checkout, always
as ``PYTHONPATH=backend python3 eval/label_export.py <command> ...``:

``kappa`` pivots the two labellers' ``gold_offline`` rows over the candidate
set (``eval/gold_candidates.csv``, P6-T01's format) and writes
``eval/kappa_v1.json`` -- Cohen's kappa over the fixed 3 x 3 label order
(``false_positive, benign, escalate``), overall, per ``gold_set`` and per
``category``, with the confusion matrix and the disagreement rate. The two
labeller ids are ``--labeler-a``/``--labeler-b`` if given, else the two
``labeler_id`` s with the most ``gold_offline`` rows over the candidate ids;
any count other than two among those rows refuses (the protocol is two
people).

``disagreements`` writes ``eval/adjudication_v1.csv``: one row per candidate
labelled by both with ``label_a != label_b``, both labels/confidences/notes,
empty ``final_label``/``final_note`` columns for the adjudication meeting.
Refuses to overwrite a file whose ``final_label`` column already carries a
verdict -- the meeting's work is never clobbered by a re-run.

``freeze`` reads the filled adjudication file and writes ``eval/gold_v1.csv``
+ ``eval/gold_v1.sha256`` -- never overwriting; a second freeze writes
``gold_v2.csv`` / ``gold_v2.sha256`` / ``gold_v1_to_v2.diff`` and leaves v1's
bytes untouched (version-by-existence, planning decision 12; there is no flag
that re-writes an existing version). With ``--adjudicator-id`` every
adjudicated cluster also gets a ``triage_labels(source='disagreement')`` row.

``report`` writes ``docs/gold-v1-report.md`` from this phase's own outputs
(the gold CSV, its sha and freeze sidecar, the kappa JSON, the adjudication
file) plus P6-T01's ``eval/gold_coverage.md``. It is the only subcommand that
touches no database.

Exit codes: 0 done; 1 a refusal the command explains; 2 a file or the DSN is
unreadable. The DSN is ``--dsn`` if given, else
``config.load(env_file=...).DATABASE_URL``; it is never printed.
"""

from __future__ import annotations

import argparse
import csv
import difflib
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import psycopg
from app.infra import config

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_UNREADABLE = 2

#: The fixed 3 x 3 label order every confusion matrix and every CSV column
#: is written in -- section 6.1's `triage_labels.label` CHECK set.
LABELS: tuple[str, ...] = ("false_positive", "benign", "escalate")

ADJUDICATION_COLUMNS: tuple[str, ...] = (
    "cluster_id",
    "gold_set",
    "category",
    "severity",
    "label_a",
    "confidence_a",
    "note_a",
    "label_b",
    "confidence_b",
    "note_b",
    "final_label",
    "final_note",
    # P6-T09 (DEC-115 ruling 3a): the row's basis, and for a window-basis row the
    # window truth, the disagreeing labeller and that labeller's label.
    "basis",
    "truth_label",
    "labeler",
    "labeler_label",
)
GOLD_COLUMNS: tuple[str, ...] = (
    "cluster_id",
    "gold_set",
    "alert_id",
    "category",
    "severity",
    "source",
    "label",
    "adjudicated",
    "note",
    "confidence_a",
    "confidence_b",
    "occurrence_count",
    "first_seen",
    "last_seen",
    "scenario_id",
    "kind",
)

_LABELER_COUNTS_SQL = (
    "SELECT labeler_id, count(*) FROM triage_labels "
    "WHERE source = 'gold_offline' AND alert_id = ANY(%s) "
    "GROUP BY labeler_id ORDER BY count(*) DESC, labeler_id"
)
_LABEL_ROWS_SQL = (
    "SELECT alert_id, labeler_id, label, confidence, note FROM triage_labels "
    "WHERE source = 'gold_offline' AND labeler_id = ANY(%s) AND alert_id = ANY(%s)"
)
_INSERT_DISAGREEMENT_SQL = (
    "INSERT INTO triage_labels (alert_id, labeler_id, source, label, confidence, note) "
    "VALUES (%s, %s, 'disagreement', %s, NULL, %s) ON CONFLICT DO NOTHING"
)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


# --- data shapes -------------------------------------------------------------------


@dataclass(frozen=True)
class Candidate:
    """One row of `eval/gold_candidates.csv` (P6-T01's format); extra columns
    (`stratum`, `agent_name`, `rule_id`) are read but not carried here. The G2
    columns `scenario_id`, `kind`, `truth_label` (P6-T07) are read when present
    and default to `""` for a committed G1 file that has no such columns."""

    cluster_id: str
    gold_set: str
    alert_id: str
    category: str
    severity: str
    source: str
    occurrence_count: str
    first_seen: str
    last_seen: str
    scenario_id: str = ""
    kind: str = ""
    truth_label: str = ""


@dataclass(frozen=True)
class LabelPair:
    cluster_id: str
    label_a: str | None
    confidence_a: str | None
    note_a: str | None
    label_b: str | None
    confidence_b: str | None
    note_b: str | None

    @property
    def both_labelled(self) -> bool:
        return self.label_a is not None and self.label_b is not None

    @property
    def disagrees(self) -> bool:
        return self.both_labelled and self.label_a != self.label_b


_EMPTY_PAIR = LabelPair("", None, None, None, None, None, None)


@dataclass(frozen=True)
class AdjudicationRow:
    final_label: str
    final_note: str


@dataclass(frozen=True)
class GoldRow:
    cluster_id: str
    gold_set: str
    alert_id: str
    category: str
    severity: str
    source: str
    label: str
    adjudicated: bool
    note: str
    confidence_a: str
    confidence_b: str
    occurrence_count: str
    first_seen: str
    last_seen: str
    scenario_id: str = ""
    kind: str = ""


@dataclass(frozen=True)
class KappaResult:
    n: int
    p_o: float
    p_e: float
    kappa: float | None
    confusion: dict[str, dict[str, int]]
    reason: str | None = None

    def to_json(self) -> dict:
        return {
            "n": self.n,
            "p_o": self.p_o,
            "p_e": self.p_e,
            "kappa": self.kappa,
            "confusion": self.confusion,
            "reason": self.reason,
        }


class DsnUnreadable(Exception):
    """`psycopg.connect` failed -- a DSN libpq cannot parse or a server it
    cannot reach. The DSN itself never enters the message."""


class TwoLabelerProtocolViolation(Exception):
    """Not exactly two distinct `gold_offline` labellers over the candidate
    ids -- the protocol is two people."""

    def __init__(self, counts: Sequence[tuple[object, int]]) -> None:
        super().__init__(str(len(counts)))
        self.counts = list(counts)


class PartialLabelled(Exception):
    """One or more candidates have fewer than two `gold_offline` labels and
    `--allow-partial` was not given."""

    def __init__(self, cluster_ids: Sequence[str]) -> None:
        super().__init__(str(len(cluster_ids)))
        self.cluster_ids = list(cluster_ids)


class MissingFinalLabel(Exception):
    """One or more disagreements have no valid `final_label` in the
    adjudication file."""

    def __init__(self, cluster_ids: Sequence[str]) -> None:
        super().__init__(str(len(cluster_ids)))
        self.cluster_ids = list(cluster_ids)


# --- kappa -- the 3 x 3 formula, ten lines (prompts/P6.md:31) ----------------------


def group_kappa(
    pairs_by_cluster: Mapping[str, tuple[str, str]], key_by_cluster: Mapping[str, str]
) -> dict[str, dict]:
    """Kappa computed independently within each group `key_by_cluster` maps a
    cluster to (e.g. `gold_set` or `category`) -- pure, no I/O."""
    grouped: dict[str, list[tuple[str, str]]] = {}
    for cluster_id, pair in pairs_by_cluster.items():
        grouped.setdefault(key_by_cluster[cluster_id], []).append(pair)
    return {key: cohen_kappa(grouped[key]).to_json() for key in sorted(grouped)}


def cohen_kappa(pairs: Sequence[tuple[str, str]]) -> KappaResult:
    n = len(pairs)
    confusion = {a: {b: 0 for b in LABELS} for a in LABELS}
    for label_a, label_b in pairs:
        confusion[label_a][label_b] += 1
    if n == 0:
        return KappaResult(n=0, p_o=0.0, p_e=0.0, kappa=None, confusion=confusion, reason="n = 0")
    p_o = sum(confusion[k][k] for k in LABELS) / n
    row_marginal = {k: sum(confusion[k].values()) for k in LABELS}
    col_marginal = {k: sum(confusion[a][k] for a in LABELS) for k in LABELS}
    p_e = sum((row_marginal[k] / n) * (col_marginal[k] / n) for k in LABELS)
    if p_e == 1.0:
        return KappaResult(n=n, p_o=p_o, p_e=p_e, kappa=None, confusion=confusion, reason="p_e = 1")
    kappa = (p_o - p_e) / (1 - p_e)
    return KappaResult(n=n, p_o=p_o, p_e=p_e, kappa=kappa, confusion=confusion, reason=None)


def vs_truth(
    candidates: Sequence[Candidate],
    pairs: Mapping[str, LabelPair],
    labeler_a: str,
    labeler_b: str,
) -> dict:
    """Each labeller's agreement with the window truth (DEC-111), pure, no I/O.

    Over the candidates that carry a non-empty `truth_label` and that *this*
    labeller labelled, the pairs are `(truth_label, labeller_label)`. `accuracy`
    duplicates `p_o` on purpose -- it is the human-baseline figure P7 compares
    the model against. One labeller's gap never shrinks the other's `n`; no
    truth rows leaves both entries at `n = 0`, `kappa = null` (`reason = "n = 0"`)."""
    truth_candidates = [c for c in candidates if c.truth_label]
    by_id = {c.cluster_id: c for c in truth_candidates}

    def entry(labeler_id: str, pick) -> dict:
        pairs_by_cluster: dict[str, tuple[str, str]] = {}
        for candidate in truth_candidates:
            label = pick(pairs.get(candidate.cluster_id, _EMPTY_PAIR))
            if label is not None:
                pairs_by_cluster[candidate.cluster_id] = (candidate.truth_label, label)
        result = cohen_kappa(list(pairs_by_cluster.values()))
        by_category = group_kappa(
            pairs_by_cluster, {cid: by_id[cid].category for cid in pairs_by_cluster}
        )
        return {
            "labeler_id": labeler_id,
            **result.to_json(),
            "accuracy": result.p_o,
            "by_category": by_category,
        }

    return {
        "a": entry(labeler_a, lambda pair: pair.label_a),
        "b": entry(labeler_b, lambda pair: pair.label_b),
    }


# --- shared I/O ---------------------------------------------------------------------


def read_candidates(path: Path) -> list[Candidate]:
    with path.open(newline="", encoding="utf-8") as handle:
        return [
            Candidate(
                cluster_id=row["cluster_id"],
                gold_set=row["gold_set"],
                alert_id=row["alert_id"],
                category=row["category"],
                severity=row["severity"],
                source=row["source"],
                occurrence_count=row["occurrence_count"],
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                scenario_id=row.get("scenario_id") or "",
                kind=row.get("kind") or "",
                truth_label=row.get("truth_label") or "",
            )
            for row in csv.DictReader(handle)
        ]


def resolve_labelers(
    conn: psycopg.Connection,
    candidate_ids: Sequence[str],
    labeler_a: str | None,
    labeler_b: str | None,
) -> tuple[str, str]:
    """`--labeler-a`/`--labeler-b` if both given; else the two `labeler_id`s
    with the most `gold_offline` rows over `candidate_ids`. Any count other
    than two among those rows raises `TwoLabelerProtocolViolation`."""
    if labeler_a and labeler_b:
        return labeler_a, labeler_b
    rows = conn.execute(_LABELER_COUNTS_SQL, (list(candidate_ids),)).fetchall()
    if len(rows) != 2:
        raise TwoLabelerProtocolViolation(rows)
    return str(rows[0][0]), str(rows[1][0])


def fetch_label_pairs(
    conn: psycopg.Connection,
    candidate_ids: Sequence[str],
    labeler_a: str,
    labeler_b: str,
) -> dict[str, LabelPair]:
    rows = conn.execute(_LABEL_ROWS_SQL, ([labeler_a, labeler_b], list(candidate_ids))).fetchall()
    by_cluster: dict[str, dict[str, tuple[str, str | None, str | None]]] = {}
    for alert_id, labeler_id, label, confidence, note in rows:
        by_cluster.setdefault(alert_id, {})[str(labeler_id)] = (label, confidence, note)
    pairs: dict[str, LabelPair] = {}
    for cluster_id in candidate_ids:
        entry = by_cluster.get(cluster_id, {})
        a = entry.get(str(labeler_a))
        b = entry.get(str(labeler_b))
        pairs[cluster_id] = LabelPair(
            cluster_id=cluster_id,
            label_a=a[0] if a else None,
            confidence_a=a[1] if a else None,
            note_a=a[2] if a else None,
            label_b=b[0] if b else None,
            confidence_b=b[1] if b else None,
            note_b=b[2] if b else None,
        )
    return pairs


def _adjudication_in_progress(path: Path) -> bool:
    """True when `path` exists and any row already carries a `final_label` --
    the meeting's work, never clobbered by a re-run."""
    if not path.exists():
        return False
    with path.open(newline="", encoding="utf-8") as handle:
        return any((row.get("final_label") or "").strip() for row in csv.DictReader(handle))


def read_adjudication(path: Path) -> dict[str, AdjudicationRow]:
    with path.open(newline="", encoding="utf-8") as handle:
        return {
            row["cluster_id"]: AdjudicationRow(
                final_label=(row.get("final_label") or "").strip(),
                final_note=(row.get("final_note") or "").strip(),
            )
            for row in csv.DictReader(handle)
        }


@dataclass(frozen=True)
class AdjRow:
    """One adjudication-file row. `basis='peer'` is a human-vs-human
    disagreement (the meeting fills `final_label`); `basis='window'` is a
    human-vs-window-truth disagreement (DEC-111: the window is the answer, so
    the row is the human-baseline record, not a decision to be made)."""

    cluster_id: str
    gold_set: str
    category: str
    severity: str
    label_a: str
    confidence_a: str
    note_a: str
    label_b: str
    confidence_b: str
    note_b: str
    basis: str
    truth_label: str
    labeler: str
    labeler_label: str


def build_adjudication_rows(
    candidates: Sequence[Candidate],
    pairs: Mapping[str, LabelPair],
    labeler_a: str,
    labeler_b: str,
) -> list[AdjRow]:
    """The adjudication rows (DEC-115 ruling 3a). A candidate carrying a window
    `truth_label` yields one **window**-basis row per labeller whose label
    differs from that truth (0, 1 or 2 rows); a candidate with no truth yields
    the original **peer**-basis row only when both humans labelled it and
    disagree. Ordered by `(cluster_id, basis, labeler)`."""
    rows: list[AdjRow] = []
    for candidate in candidates:
        pair = pairs.get(candidate.cluster_id, _EMPTY_PAIR)
        if candidate.truth_label:
            for labeler_id, label in ((labeler_a, pair.label_a), (labeler_b, pair.label_b)):
                if label is not None and label != candidate.truth_label:
                    rows.append(
                        AdjRow(
                            cluster_id=candidate.cluster_id,
                            gold_set=candidate.gold_set,
                            category=candidate.category,
                            severity=candidate.severity,
                            label_a="",
                            confidence_a="",
                            note_a="",
                            label_b="",
                            confidence_b="",
                            note_b="",
                            basis="window",
                            truth_label=candidate.truth_label,
                            labeler=str(labeler_id),
                            labeler_label=label,
                        )
                    )
        elif pair.both_labelled and pair.disagrees:
            rows.append(
                AdjRow(
                    cluster_id=candidate.cluster_id,
                    gold_set=candidate.gold_set,
                    category=candidate.category,
                    severity=candidate.severity,
                    label_a=pair.label_a or "",
                    confidence_a=pair.confidence_a or "",
                    note_a=pair.note_a or "",
                    label_b=pair.label_b or "",
                    confidence_b=pair.confidence_b or "",
                    note_b=pair.note_b or "",
                    basis="peer",
                    truth_label="",
                    labeler="",
                    labeler_label="",
                )
            )
    rows.sort(key=lambda r: (r.cluster_id, r.basis, r.labeler))
    return rows


def write_adjudication_csv(path: Path, rows: Sequence[AdjRow]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
        writer.writerow(ADJUDICATION_COLUMNS)
        for row in rows:
            writer.writerow(
                (
                    row.cluster_id,
                    row.gold_set,
                    row.category,
                    row.severity,
                    row.label_a,
                    row.confidence_a,
                    row.note_a,
                    row.label_b,
                    row.confidence_b,
                    row.note_b,
                    "",
                    "",
                    row.basis,
                    row.truth_label,
                    row.labeler,
                    row.labeler_label,
                )
            )


# --- freeze: the committed scenario exclusion (DEC-117, design decision B) ---------


@dataclass(frozen=True)
class ExclusionResult:
    kept: list[Candidate]
    dropped: int
    matched: list[str]
    unmatched: list[str]


def read_excluded_scenarios(path: Path) -> list[str]:
    """Ordered, de-duplicated `scenario_id`s from a committed
    `excluded_scenarios.csv` (`scenario_id,reason,decided_in`); `[]` when the
    file is absent. A blank id is skipped. A misfired scenario is excluded by
    this committed record, never by a flag typed at freeze time (DEC-117)."""
    if not path.exists():
        return []
    ordered: dict[str, None] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            scenario_id = (row.get("scenario_id") or "").strip()
            if scenario_id:
                ordered.setdefault(scenario_id, None)
    return list(ordered)


def apply_scenario_exclusions(
    candidates: Sequence[Candidate], excluded_ids: Sequence[str]
) -> ExclusionResult:
    """Drop every candidate whose `scenario_id` is listed. `matched` are the
    excluded ids that hit at least one candidate; `unmatched` the ids that hit
    none -- a warning, not an error (the scenario may have produced no in-scope
    head)."""
    excluded = set(excluded_ids)
    present = {c.scenario_id for c in candidates if c.scenario_id}
    kept = [c for c in candidates if c.scenario_id not in excluded]
    return ExclusionResult(
        kept=kept,
        dropped=len(candidates) - len(kept),
        matched=[sid for sid in excluded_ids if sid in present],
        unmatched=[sid for sid in excluded_ids if sid not in present],
    )


# --- freeze -- pure rules (design note 6, testable without a database) -----------


@dataclass(frozen=True)
class FreezeResult:
    rows: list[GoldRow]
    dropped_unlabelled: int


def build_gold_rows(
    candidates: Sequence[Candidate],
    pairs: Mapping[str, LabelPair],
    adjudication: Mapping[str, AdjudicationRow],
    *,
    allow_partial: bool,
) -> FreezeResult:
    """Rules (i)-(iii) of the freeze design note for candidates with no
    `truth_label`. A candidate that carries a window `truth_label` (P6-T07,
    DEC-111/DEC-114/DEC-115) freezes at that label with `adjudicated=False`,
    **whether or not the two humans agree or even labelled it** -- a human
    disagreement with the window is the human-baseline figure, not a freeze
    blocker -- so a truth row raises neither `PartialLabelled` nor
    `MissingFinalLabel`. Raises `ValueError` on a `truth_label` not in `LABELS`
    (a build defect)."""
    partial_ids = sorted(
        c.cluster_id
        for c in candidates
        if not c.truth_label and not pairs.get(c.cluster_id, _EMPTY_PAIR).both_labelled
    )
    if partial_ids and not allow_partial:
        raise PartialLabelled(partial_ids)

    missing_final: list[str] = []
    rows: list[GoldRow] = []
    for candidate in candidates:
        pair = pairs.get(candidate.cluster_id, _EMPTY_PAIR)
        if candidate.truth_label:
            if candidate.truth_label not in LABELS:
                raise ValueError(
                    f"candidate {candidate.cluster_id}: truth_label "
                    f"{candidate.truth_label!r} is not one of {LABELS}"
                )
            rows.append(
                GoldRow(
                    cluster_id=candidate.cluster_id,
                    gold_set=candidate.gold_set,
                    alert_id=candidate.alert_id,
                    category=candidate.category,
                    severity=candidate.severity,
                    source=candidate.source,
                    label=candidate.truth_label,
                    adjudicated=False,
                    note=pair.note_a or pair.note_b or "",
                    confidence_a=pair.confidence_a or "",
                    confidence_b=pair.confidence_b or "",
                    occurrence_count=candidate.occurrence_count,
                    first_seen=candidate.first_seen,
                    last_seen=candidate.last_seen,
                    scenario_id=candidate.scenario_id,
                    kind=candidate.kind,
                )
            )
            continue
        if not pair.both_labelled:
            continue
        if not pair.disagrees:
            rows.append(
                GoldRow(
                    cluster_id=candidate.cluster_id,
                    gold_set=candidate.gold_set,
                    alert_id=candidate.alert_id,
                    category=candidate.category,
                    severity=candidate.severity,
                    source=candidate.source,
                    label=pair.label_a,
                    adjudicated=False,
                    note=pair.note_a or pair.note_b or "",
                    confidence_a=pair.confidence_a or "",
                    confidence_b=pair.confidence_b or "",
                    occurrence_count=candidate.occurrence_count,
                    first_seen=candidate.first_seen,
                    last_seen=candidate.last_seen,
                )
            )
            continue
        adjudicated_row = adjudication.get(candidate.cluster_id)
        final_label = adjudicated_row.final_label if adjudicated_row else ""
        if final_label not in LABELS:
            missing_final.append(candidate.cluster_id)
            continue
        rows.append(
            GoldRow(
                cluster_id=candidate.cluster_id,
                gold_set=candidate.gold_set,
                alert_id=candidate.alert_id,
                category=candidate.category,
                severity=candidate.severity,
                source=candidate.source,
                label=final_label,
                adjudicated=True,
                note=(adjudicated_row.final_note if adjudicated_row else "") or "",
                confidence_a=pair.confidence_a or "",
                confidence_b=pair.confidence_b or "",
                occurrence_count=candidate.occurrence_count,
                first_seen=candidate.first_seen,
                last_seen=candidate.last_seen,
            )
        )
    if missing_final:
        raise MissingFinalLabel(sorted(missing_final))
    return FreezeResult(rows=rows, dropped_unlabelled=len(partial_ids))


def write_gold_csv(path: Path, rows: Sequence[GoldRow]) -> None:
    ordered = sorted(rows, key=lambda row: row.cluster_id)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
        writer.writerow(GOLD_COLUMNS)
        for row in ordered:
            writer.writerow(
                (
                    row.cluster_id,
                    row.gold_set,
                    row.alert_id,
                    row.category,
                    row.severity,
                    row.source,
                    row.label,
                    "true" if row.adjudicated else "false",
                    row.note,
                    row.confidence_a,
                    row.confidence_b,
                    row.occurrence_count,
                    row.first_seen,
                    row.last_seen,
                    row.scenario_id,
                    row.kind,
                )
            )


def write_sha_file(csv_path: str | Path, sha_path: str | Path, *, label: str | None = None) -> None:
    """`sha256sum -c`-compatible: `f"{sha256(bytes of csv_path)}  {label}\\n"`.
    `label` defaults to `csv_path` exactly as given -- `freeze` passes the
    constructed `eval/gold_vN.csv` path so the file verifies from the
    repository root."""
    csv_path = Path(csv_path)
    digest = hashlib.sha256(csv_path.read_bytes()).hexdigest()
    effective_label = label if label is not None else str(csv_path)
    Path(sha_path).write_text(f"{digest}  {effective_label}\n", encoding="utf-8", newline="\n")


def write_version_diff(prev_path: Path, new_path: Path, diff_path: Path) -> None:
    prev_lines = prev_path.read_text(encoding="utf-8").splitlines(keepends=True)
    new_lines = new_path.read_text(encoding="utf-8").splitlines(keepends=True)
    diff = difflib.unified_diff(
        prev_lines, new_lines, fromfile=str(prev_path), tofile=str(new_path)
    )
    diff_path.write_text("".join(diff), encoding="utf-8", newline="\n")


def next_free_version(out_dir: Path) -> int:
    version = 1
    while (out_dir / f"gold_v{version}.csv").exists():
        version += 1
    return version


@dataclass(frozen=True)
class FreezeFiles:
    version: int
    gold_path: Path
    sha_path: Path
    freeze_json_path: Path
    diff_path: Path | None


def write_freeze_outputs(
    out_dir: str | Path,
    rows: Sequence[GoldRow],
    *,
    dropped_unlabelled: int,
    candidates_total: int,
    adjudicator_id: str | None,
) -> FreezeFiles:
    """Version-by-existence (planning decision 12): the next free `gold_vN`
    stem; v1 is never reopened for writing once v2+ exists. Writes the CSV,
    the sha file, the diff (v2+ only) and the JSON sidecar."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    version = next_free_version(out_dir)
    gold_path = out_dir / f"gold_v{version}.csv"
    sha_path = out_dir / f"gold_v{version}.sha256"
    freeze_json_path = out_dir / f"gold_v{version}.freeze.json"

    write_gold_csv(gold_path, rows)
    write_sha_file(gold_path, sha_path, label=str(gold_path))
    sha_hex = hashlib.sha256(gold_path.read_bytes()).hexdigest()

    diff_path: Path | None = None
    if version > 1:
        prev_path = out_dir / f"gold_v{version - 1}.csv"
        diff_path = out_dir / f"gold_v{version - 1}_to_v{version}.diff"
        write_version_diff(prev_path, gold_path, diff_path)

    freeze_doc = {
        "candidates": candidates_total,
        "frozen": len(rows),
        "dropped_unlabelled": dropped_unlabelled,
        "adjudicated": sum(1 for row in rows if row.adjudicated),
        "sha256": sha_hex,
        "frozen_at": _now_iso(),
        "adjudicator_id": adjudicator_id,
    }
    freeze_json_path.write_text(
        json.dumps(freeze_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    return FreezeFiles(
        version=version,
        gold_path=gold_path,
        sha_path=sha_path,
        freeze_json_path=freeze_json_path,
        diff_path=diff_path,
    )


# --- report -------------------------------------------------------------------------


def read_gold_csv(path: Path) -> list[GoldRow]:
    with path.open(newline="", encoding="utf-8") as handle:
        return [
            GoldRow(
                cluster_id=row["cluster_id"],
                gold_set=row["gold_set"],
                alert_id=row["alert_id"],
                category=row["category"],
                severity=row["severity"],
                source=row["source"],
                label=row["label"],
                adjudicated=row["adjudicated"] == "true",
                note=row["note"],
                confidence_a=row["confidence_a"],
                confidence_b=row["confidence_b"],
                occurrence_count=row["occurrence_count"],
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
            )
            for row in csv.DictReader(handle)
        ]


def _count_csv_rows(path: Path) -> int:
    with path.open(newline="", encoding="utf-8") as handle:
        return sum(1 for _ in csv.DictReader(handle))


def _version_from_path(path: Path) -> int:
    match = re.fullmatch(r"gold_v(\d+)\.csv", path.name)
    return int(match.group(1)) if match else 1


def _default_gold_path(directory: Path) -> Path:
    """The highest `gold_vN.csv` present in `directory`, or `gold_v1.csv` if
    none exists yet (design note 5: "or the highest version present")."""
    versions: list[tuple[int, Path]] = []
    if directory.exists():
        for candidate_path in directory.glob("gold_v*.csv"):
            match = re.fullmatch(r"gold_v(\d+)\.csv", candidate_path.name)
            if match:
                versions.append((int(match.group(1)), candidate_path))
    if versions:
        return max(versions, key=lambda item: item[0])[1]
    return directory / "gold_v1.csv"


def _git_log_line(tracked_path: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%h", "--", str(tracked_path)],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return "commit: (not committed yet)"
    sha = result.stdout.strip()
    return f"commit: {sha}" if result.returncode == 0 and sha else "commit: (not committed yet)"


def _band_sentence(kappa: float | None) -> str:
    if kappa is None:
        return "kappa is undefined (p_e = 1) -- only adjudicated labels are used (architecture §6)."
    if kappa >= 0.6:
        return f"kappa = {kappa:.3f} -- target met (>= 0.6)."
    if kappa >= 0.4:
        return f"kappa = {kappa:.3f} -- below target, reported (0.4 <= kappa < 0.6)."
    return (
        f"kappa = {kappa:.3f} -- only adjudicated labels are used (architecture §6, kappa < 0.4)."
    )


def _md_table(rows: Sequence[tuple[str, str, int]], headers: tuple[str, str, str]) -> str:
    lines = [f"| {headers[0]} | {headers[1]} | {headers[2]} |", "|---|---|---|"]
    for a, b, n in rows:
        lines.append(f"| {a} | {b} | {n} |")
    return "\n".join(lines)


def _gate_line(label: str, n: int, floor: int) -> str:
    return f"- {label}: {n} (>= {floor}: {'met' if n >= floor else 'MISS'})"


def _extract_section(text: str, heading_prefix: str) -> str | None:
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith(heading_prefix)), None)
    if start is None:
        return None
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if lines[i].startswith("## "):
            end = i
            break
    return "\n".join(lines[start:end]).rstrip()


def _extract_line(text: str, prefix: str) -> str | None:
    for line in text.splitlines():
        if line.startswith(prefix):
            return line
    return None


def _crit_high_ratio(text: str, section_label: str) -> tuple[int, int, float] | None:
    """Parse "crit+high in the <section_label>: X of Y, of which `unknown`
    Z" and return `(crit_high, crit_high_unknown, (X - Z) / X)` -- the
    escalate-recall ceiling sentence re-derived on this fold's own numbers."""
    match = re.search(
        rf"crit\+high in the {re.escape(section_label)}: (\d+) of \d+, of which .unknown. (\d+)",
        text,
    )
    if not match:
        return None
    crit_high, unknown = int(match.group(1)), int(match.group(2))
    ratio = (crit_high - unknown) / crit_high if crit_high else 0.0
    return crit_high, unknown, ratio


def render_report(
    *,
    gold_rows: Sequence[GoldRow],
    version: int,
    sha256_hex: str | None,
    frozen_at: str | None,
    adjudicator_id: str | None,
    git_log_line: str,
    kappa_doc: dict | None,
    coverage_text: str | None,
    manifest_rows: int | None,
    adjudication_present: bool,
) -> str:
    """`docs/gold-v1-report.md`. A pure function of its inputs -- no clock, no
    subprocess call inside it -- so two renders of the same inputs are
    byte-identical."""
    lines: list[str] = [
        "# Gold v1 report",
        "",
        "Generated by `eval/label_export.py report`; never hand-edited.",
        "",
    ]

    # --- 1. Freeze ---
    lines += [
        "## 1. Freeze",
        "",
        f"- version: gold_v{version} ({len(gold_rows)} rows)",
        f"- sha256: {sha256_hex or f'(gold_v{version}.sha256 not found)'}",
        f"- frozen_at: {frozen_at or f'(unknown -- gold_v{version}.freeze.json not found)'}",
        "- adjudicator_id: "
        + (adjudicator_id or "(none -- disagreement rows carry no triage_labels row)"),
        f"- {git_log_line}",
        "",
    ]

    # --- 2. Counts ---
    by_gold_set_label: Counter = Counter((row.gold_set, row.label) for row in gold_rows)
    by_category_label: Counter = Counter((row.category, row.label) for row in gold_rows)
    gold_sets = sorted({row.gold_set for row in gold_rows})
    categories = sorted({row.category for row in gold_rows})
    gold_set_rows = [
        (gold_set, label, by_gold_set_label.get((gold_set, label), 0))
        for gold_set in gold_sets
        for label in LABELS
    ]
    category_rows = [
        (category, label, by_category_label.get((category, label), 0))
        for category in categories
        for label in LABELS
    ]
    g2_n = sum(1 for row in gold_rows if row.gold_set == "G2")
    g2_benign = sum(
        1 for row in gold_rows if row.gold_set == "G2" and row.label in ("benign", "false_positive")
    )
    g3_line = (
        f"- G3: {manifest_rows} of `eval/adversarial/manifest.csv`"
        if manifest_rows is not None
        else "- G3: not loaded -- P6-T04"
    )
    lines += [
        "## 2. Counts",
        "",
        "By gold_set x label:",
        "",
        _md_table(gold_set_rows, ("gold_set", "label", "n")),
        "",
        "By category x label:",
        "",
        _md_table(category_rows, ("category", "label", "n")),
        "",
        _gate_line("G2 rows", g2_n, 100),
        _gate_line("G2 benign clusters (benign + false_positive)", g2_benign, 20),
        g3_line,
        "",
    ]

    # --- 3. Coverage ---
    lines += ["## 3. Coverage", ""]
    if coverage_text is None:
        lines += ["(`eval/gold_coverage.md` not found -- run `build_gold.py` first)", ""]
    else:
        for heading in ("## G1 pool", "## G1 sample", "## G2 pool", "## G2 sample"):
            section = _extract_section(coverage_text, heading)
            if section is not None:
                lines += [section, ""]

    # --- 4. Agreement ---
    lines += ["## 4. Agreement", ""]
    if kappa_doc is None:
        lines += ["(`eval/kappa_v1.json` not found -- run `kappa` first)", ""]
    else:
        overall = kappa_doc["overall"]
        lines += [
            f"- overall: n={overall['n']} kappa={overall['kappa']}",
            f"  confusion: {json.dumps(overall['confusion'], sort_keys=True)}",
            f"- disagreements: {kappa_doc['disagreements']} (rate {kappa_doc['disagreement_rate']})",
            f"- adjudicated (this freeze): {sum(1 for row in gold_rows if row.adjudicated)}",
            f"- {_band_sentence(overall['kappa'])}",
            "",
            "By gold_set:",
        ]
        for gold_set, doc in sorted(kappa_doc.get("by_gold_set", {}).items()):
            lines.append(f"  - {gold_set}: n={doc['n']} kappa={doc['kappa']}")
        lines += ["", "By category:"]
        for category, doc in sorted(kappa_doc.get("by_category", {}).items()):
            lines.append(f"  - {category}: n={doc['n']} kappa={doc['kappa']}")
        lines += ["", "Human baseline vs window truth (DEC-111):"]
        vs = kappa_doc.get("vs_truth")
        if not vs:
            lines.append("  (not available -- kappa_v1.json carries no vs_truth)")
        else:
            for key in ("a", "b"):
                entry = vs.get(key) or {}
                lines.append(
                    f"  - {entry.get('labeler_id', '(unknown)')}: "
                    f"n={entry.get('n', 0)} accuracy={entry.get('accuracy')}"
                )
                for category, cat_doc in sorted((entry.get("by_category") or {}).items()):
                    lines.append(
                        f"    - {category}: n={cat_doc.get('n', 0)} accuracy={cat_doc.get('p_o')}"
                    )
        lines.append("")

    # --- 5. Limitations for P8 ---
    lines += ["## 5. Limitations for P8", ""]
    if coverage_text is None:
        lines += ["(`eval/gold_coverage.md` not found -- limitations cannot be re-derived)", ""]
    else:
        pool = _extract_section(coverage_text, "## G1 pool") or ""
        sample = _extract_section(coverage_text, "## G1 sample") or ""
        limitations: list[str] = []

        unknown_line = _extract_line(pool, "- `unknown` share of the pool:")
        if unknown_line:
            limitations.append(unknown_line.lstrip("- ") + " (DEC-057).")

        pool_ratio = _crit_high_ratio(pool, "pool")
        if pool_ratio:
            crit_high, crit_high_unknown, ratio = pool_ratio
            limitations.append(
                f"B1's escalate-recall ceiling on the pool: ({crit_high} - {crit_high_unknown}) / "
                f"{crit_high} = {ratio:.2f} before any rule fires (DEC-057, re-derived on this fold)."
            )
        sample_ratio = _crit_high_ratio(sample, "sample")
        if sample_ratio:
            crit_high, crit_high_unknown, ratio = sample_ratio
            limitations.append(
                f"The same ratio on the sample: ({crit_high} - {crit_high_unknown}) / {crit_high} "
                f"= {ratio:.2f}."
            )
        loopback_line = _extract_line(pool, "- excluded as loopback")
        if loopback_line:
            limitations.append(loopback_line.lstrip("- ") + " (DEC-053).")
        desktop_line = _extract_line(pool, "- `DESKTOP-MIRSO17`")
        if desktop_line:
            limitations.append(desktop_line.lstrip("- ") + " (DEC-058).")

        limitations.append(
            "`web_attack` and `policy_violation` are absent categories (DEC-055, DEC-057)."
        )
        g2_pool = _extract_section(coverage_text, "## G2 pool")
        for category in ("ransomware", "data_exfiltration", "c2_beacon"):
            count_text = "G2 not yet run"
            if g2_pool:
                match = re.search(rf"\| {re.escape(category)} \|.*\| (\d+) \| [\d.]+ % \|", g2_pool)
                count_text = f"{int(match.group(1))} G2 clusters" if match else "0 G2 clusters"
            limitations.append(
                f"`{category}` rests on detection rules the author wrote "
                f"(DEC-056 amendment 3); {count_text}."
            )
        overall_kappa = kappa_doc["overall"]["kappa"] if kappa_doc is not None else None
        limitations.append(
            "The two labellers are the author and the advisor (author-as-labeller, A3); "
            f"kappa = {overall_kappa if overall_kappa is not None else 'not computed yet'}."
        )
        limitations.append(
            "The lab host is the production host; `source='lab'` is a time window applied "
            "after the fact by `eval/lab_tag.py`, never an agent-name rule (DEC-085, planning "
            "decision 3)."
        )
        limitations.append(
            "G2's September dates are readable in `raw_log`, so a labeller can recognise a "
            "cluster as lab traffic by date; the control is the >= 20 benign lab clusters on "
            "the same host, not concealment."
        )
        enrich_line = _extract_line(sample, "- G1's severity mix")
        if enrich_line:
            limitations.append(enrich_line.lstrip("- ") + ".")
        if not adjudication_present:
            limitations.append(
                "No `eval/adjudication_v1.csv` was found for this report -- either no "
                "disagreement exists yet or the adjudication meeting has not run."
            )

        lines += [f"- {sentence}" for sentence in limitations]
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


# --- CLI --------------------------------------------------------------------------------


@contextmanager
def _connection(dsn: str) -> Iterator[psycopg.Connection]:
    try:
        conn = psycopg.connect(dsn)
    except psycopg.Error as exc:
        raise DsnUnreadable(type(exc).__name__) from None
    try:
        yield conn
    finally:
        conn.close()


def _resolve_dsn(dsn: str | None, env_file: str) -> str | None:
    if dsn:
        print("dsn: from --dsn (redacted)")
        return dsn
    resolved = config.load(env_file=env_file).DATABASE_URL
    if not resolved:
        return None
    print("dsn: from .env (redacted)")
    return resolved


def _print_labeler_violation(exc: TwoLabelerProtocolViolation) -> None:
    named = ", ".join(f"{labeler_id} ({count})" for labeler_id, count in exc.counts)
    print(
        "label_export: expected exactly two labellers with source='gold_offline' over the "
        f"candidate ids -- found {len(exc.counts)}: {named or '(none)'}",
        file=sys.stderr,
    )


def _add_common_args(sub: argparse.ArgumentParser) -> None:
    sub.add_argument("--candidates", default="eval/gold_candidates.csv", metavar="PATH")
    sub.add_argument("--dsn", default=None, metavar="DSN", help="never printed")
    sub.add_argument("--env-file", default=".env", metavar="PATH")
    sub.add_argument("--labeler-a", default=None, metavar="UUID")
    sub.add_argument("--labeler-b", default=None, metavar="UUID")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="label_export.py",
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exit codes: 0 done; 1 a refusal the command explains; "
            "2 a file or the DSN is unreadable."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_kappa = sub.add_parser("kappa", help="pivot the gold_offline rows into kappa_v1.json")
    _add_common_args(p_kappa)
    p_kappa.add_argument("--out", default="eval/kappa_v1.json", metavar="PATH")

    p_dis = sub.add_parser("disagreements", help="write the adjudication CSV for the meeting")
    _add_common_args(p_dis)
    p_dis.add_argument("--out", default="eval/adjudication_v1.csv", metavar="PATH")

    p_freeze = sub.add_parser("freeze", help="freeze the adjudicated labels into gold_vN.csv")
    _add_common_args(p_freeze)
    p_freeze.add_argument("--adjudication", default="eval/adjudication_v1.csv", metavar="PATH")
    p_freeze.add_argument(
        "--excluded-scenarios", default="eval/excluded_scenarios.csv", metavar="PATH"
    )
    p_freeze.add_argument("--out-dir", default="eval", metavar="DIR")
    p_freeze.add_argument("--adjudicator-id", default=None, metavar="UUID")
    p_freeze.add_argument("--allow-partial", action="store_true")

    p_report = sub.add_parser("report", help="render docs/gold-v1-report.md")
    p_report.add_argument("--gold", default=None, metavar="PATH")
    p_report.add_argument("--kappa", default="eval/kappa_v1.json", metavar="PATH")
    p_report.add_argument("--adjudication", default="eval/adjudication_v1.csv", metavar="PATH")
    p_report.add_argument("--coverage", default="eval/gold_coverage.md", metavar="PATH")
    p_report.add_argument("--manifest", default="eval/adversarial/manifest.csv", metavar="PATH")
    p_report.add_argument("--out", default="docs/gold-v1-report.md", metavar="PATH")

    return parser


def cmd_kappa(args: argparse.Namespace) -> int:
    try:
        candidates = read_candidates(Path(args.candidates))
    except OSError as exc:
        print(f"label_export: refusing --candidates {args.candidates!r}: {exc}", file=sys.stderr)
        return EXIT_UNREADABLE
    candidate_ids = [candidate.cluster_id for candidate in candidates]

    dsn = _resolve_dsn(args.dsn, args.env_file)
    if dsn is None:
        print(
            "label_export: no DSN -- pass --dsn, or set DATABASE_URL in the file named by "
            "--env-file",
            file=sys.stderr,
        )
        return EXIT_UNREADABLE
    try:
        with _connection(dsn) as conn:
            labeler_a, labeler_b = resolve_labelers(
                conn, candidate_ids, args.labeler_a, args.labeler_b
            )
            pairs = fetch_label_pairs(conn, candidate_ids, labeler_a, labeler_b)
    except DsnUnreadable as exc:
        print(f"label_export: DSN unreadable: {exc}", file=sys.stderr)
        return EXIT_UNREADABLE
    except TwoLabelerProtocolViolation as exc:
        _print_labeler_violation(exc)
        return EXIT_REFUSED

    candidates_by_id = {candidate.cluster_id: candidate for candidate in candidates}
    both = {cluster_id: pair for cluster_id, pair in pairs.items() if pair.both_labelled}
    pairs_by_cluster = {
        cluster_id: (pair.label_a, pair.label_b) for cluster_id, pair in both.items()
    }
    overall = cohen_kappa(list(pairs_by_cluster.values()))
    by_gold_set = group_kappa(
        pairs_by_cluster, {cid: candidates_by_id[cid].gold_set for cid in pairs_by_cluster}
    )
    by_category = group_kappa(
        pairs_by_cluster, {cid: candidates_by_id[cid].category for cid in pairs_by_cluster}
    )
    disagreements = sum(1 for pair in both.values() if pair.disagrees)

    doc = {
        "candidates": len(candidates),
        "labelled_by_both": len(both),
        "labeler_a": labeler_a,
        "labeler_b": labeler_b,
        "overall": overall.to_json(),
        "by_gold_set": by_gold_set,
        "by_category": by_category,
        "vs_truth": vs_truth(candidates, pairs, labeler_a, labeler_b),
        "disagreements": disagreements,
        "disagreement_rate": (disagreements / len(both)) if both else None,
        "computed_at": _now_iso(),
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"kappa: n={overall.n} kappa={overall.kappa} -> {out_path}")
    return EXIT_OK


def cmd_disagreements(args: argparse.Namespace) -> int:
    out_path = Path(args.out)
    if _adjudication_in_progress(out_path):
        print(
            "label_export: adjudication in progress -- refusing to overwrite; pass --out "
            "another path",
            file=sys.stderr,
        )
        return EXIT_REFUSED

    try:
        candidates = read_candidates(Path(args.candidates))
    except OSError as exc:
        print(f"label_export: refusing --candidates {args.candidates!r}: {exc}", file=sys.stderr)
        return EXIT_UNREADABLE
    candidate_ids = [candidate.cluster_id for candidate in candidates]

    dsn = _resolve_dsn(args.dsn, args.env_file)
    if dsn is None:
        print(
            "label_export: no DSN -- pass --dsn, or set DATABASE_URL in the file named by "
            "--env-file",
            file=sys.stderr,
        )
        return EXIT_UNREADABLE
    try:
        with _connection(dsn) as conn:
            labeler_a, labeler_b = resolve_labelers(
                conn, candidate_ids, args.labeler_a, args.labeler_b
            )
            pairs = fetch_label_pairs(conn, candidate_ids, labeler_a, labeler_b)
    except DsnUnreadable as exc:
        print(f"label_export: DSN unreadable: {exc}", file=sys.stderr)
        return EXIT_UNREADABLE
    except TwoLabelerProtocolViolation as exc:
        _print_labeler_violation(exc)
        return EXIT_REFUSED

    both = {cluster_id: pair for cluster_id, pair in pairs.items() if pair.both_labelled}
    not_yet_both = len(candidates) - len(both)
    rows = build_adjudication_rows(candidates, pairs, labeler_a, labeler_b)
    write_adjudication_csv(out_path, rows)
    window_n = sum(1 for row in rows if row.basis == "window")
    peer_n = sum(1 for row in rows if row.basis == "peer")
    print(f"not yet labelled by both: {not_yet_both}")
    print(f"disagreements: {len(rows)} ({window_n} vs-window, {peer_n} vs-peer) -> {out_path}")
    return EXIT_OK


def cmd_freeze(args: argparse.Namespace) -> int:
    try:
        candidates = read_candidates(Path(args.candidates))
    except OSError as exc:
        print(f"label_export: refusing --candidates {args.candidates!r}: {exc}", file=sys.stderr)
        return EXIT_UNREADABLE
    candidate_ids = [candidate.cluster_id for candidate in candidates]

    excluded_path = Path(args.excluded_scenarios)
    try:
        excluded_ids = read_excluded_scenarios(excluded_path)
    except OSError as exc:
        print(
            f"label_export: refusing --excluded-scenarios {args.excluded_scenarios!r}: {exc}",
            file=sys.stderr,
        )
        return EXIT_UNREADABLE
    if excluded_ids:
        exclusion = apply_scenario_exclusions(candidates, excluded_ids)
        ids_text = ", ".join(exclusion.matched) if exclusion.matched else "(none matched)"
        print(
            f"excluded {exclusion.dropped} candidates from {len(exclusion.matched)} scenarios: "
            f"{ids_text}"
        )
        for scenario_id in exclusion.unmatched:
            print(
                f"label_export: warning: excluded scenario {scenario_id!r} matched no candidate",
                file=sys.stderr,
            )
        candidates = exclusion.kept
        candidate_ids = [candidate.cluster_id for candidate in candidates]

    adjudication_path = Path(args.adjudication)
    try:
        adjudication = read_adjudication(adjudication_path) if adjudication_path.exists() else {}
    except OSError as exc:
        print(
            f"label_export: refusing --adjudication {args.adjudication!r}: {exc}", file=sys.stderr
        )
        return EXIT_UNREADABLE

    dsn = _resolve_dsn(args.dsn, args.env_file)
    if dsn is None:
        print(
            "label_export: no DSN -- pass --dsn, or set DATABASE_URL in the file named by "
            "--env-file",
            file=sys.stderr,
        )
        return EXIT_UNREADABLE

    try:
        with _connection(dsn) as conn:
            labeler_a, labeler_b = resolve_labelers(
                conn, candidate_ids, args.labeler_a, args.labeler_b
            )
            pairs = fetch_label_pairs(conn, candidate_ids, labeler_a, labeler_b)
            try:
                result = build_gold_rows(
                    candidates, pairs, adjudication, allow_partial=args.allow_partial
                )
            except PartialLabelled as exc:
                print(
                    f"label_export: {len(exc.cluster_ids)} candidate(s) labelled by fewer than "
                    "two labellers -- pass --allow-partial to drop them: "
                    + ", ".join(exc.cluster_ids),
                    file=sys.stderr,
                )
                return EXIT_REFUSED
            except MissingFinalLabel as exc:
                print(
                    f"label_export: {len(exc.cluster_ids)} disagreement(s) missing a valid "
                    f"final_label in {adjudication_path}: " + ", ".join(exc.cluster_ids),
                    file=sys.stderr,
                )
                return EXIT_REFUSED

            files = write_freeze_outputs(
                Path(args.out_dir),
                result.rows,
                dropped_unlabelled=result.dropped_unlabelled,
                candidates_total=len(candidates),
                adjudicator_id=args.adjudicator_id,
            )
            if args.adjudicator_id:
                for row in result.rows:
                    if row.adjudicated:
                        conn.execute(
                            _INSERT_DISAGREEMENT_SQL,
                            (row.alert_id, args.adjudicator_id, row.label, row.note or None),
                        )
                conn.commit()
    except DsnUnreadable as exc:
        print(f"label_export: DSN unreadable: {exc}", file=sys.stderr)
        return EXIT_UNREADABLE
    except TwoLabelerProtocolViolation as exc:
        _print_labeler_violation(exc)
        return EXIT_REFUSED

    print(f"froze {len(result.rows)} rows -> {files.gold_path} (version {files.version})")
    if result.dropped_unlabelled:
        print(f"dropped (fewer than two labels): {result.dropped_unlabelled}")
    if not args.adjudicator_id:
        print(
            "label_export: no --adjudicator-id -- disagreement rows are frozen into the CSV "
            "but no triage_labels row was written"
        )
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    gold_path = Path(args.gold) if args.gold else _default_gold_path(Path("eval"))
    if not gold_path.exists():
        print(
            f"label_export: refusing --gold {str(gold_path)!r}: no such file or directory",
            file=sys.stderr,
        )
        return EXIT_UNREADABLE

    gold_rows = read_gold_csv(gold_path)
    version = _version_from_path(gold_path)

    sha_path = gold_path.with_suffix(".sha256")
    sha256_hex = None
    if sha_path.exists():
        first_field = sha_path.read_text(encoding="utf-8").split()
        sha256_hex = first_field[0] if first_field else None

    freeze_json_path = gold_path.with_name(gold_path.stem + ".freeze.json")
    freeze_doc: dict | None = None
    if freeze_json_path.exists():
        freeze_doc = json.loads(freeze_json_path.read_text(encoding="utf-8"))

    kappa_path = Path(args.kappa)
    kappa_doc = json.loads(kappa_path.read_text(encoding="utf-8")) if kappa_path.exists() else None

    coverage_path = Path(args.coverage)
    coverage_text = coverage_path.read_text(encoding="utf-8") if coverage_path.exists() else None

    manifest_path = Path(args.manifest)
    manifest_rows = _count_csv_rows(manifest_path) if manifest_path.exists() else None

    adjudication_path = Path(args.adjudication)

    text = render_report(
        gold_rows=gold_rows,
        version=version,
        sha256_hex=sha256_hex,
        frozen_at=(freeze_doc or {}).get("frozen_at"),
        adjudicator_id=(freeze_doc or {}).get("adjudicator_id"),
        git_log_line=_git_log_line(sha_path),
        kappa_doc=kappa_doc,
        coverage_text=coverage_text,
        manifest_rows=manifest_rows,
        adjudication_present=adjudication_path.exists(),
    )
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8", newline="\n")
    print(f"report: {out_path}")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "kappa":
        return cmd_kappa(args)
    if args.command == "disagreements":
        return cmd_disagreements(args)
    if args.command == "freeze":
        return cmd_freeze(args)
    if args.command == "report":
        return cmd_report(args)
    raise AssertionError(args.command)


if __name__ == "__main__":
    sys.exit(main())
