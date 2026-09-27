#!/usr/bin/env python3
"""P7's harness driver: one configuration, on one gold set, in one thinking mode per run (P7-T04).

``run`` evaluates one configuration and records it.

* **The frozen gold comes first** (the brief's stop condition), before any other file is parsed
  and before any connection: ``--sha-file`` exists, its hex is the sha256 of the gold's bytes,
  and both files are tracked by git and unmodified against ``HEAD``. The full sha rides on the
  run (the results file's header and ``eval_runs.metrics.gold_sha256``), and its first 12 hex
  name the outputs.
* **G2** is the gold's rows, read with ``label_export.read_gold_csv``. Each row's
  ``category_expected`` is joined from ``--lab-windows`` by ``scenario_id``; the truth is the
  gold label (``escalate`` or ``benign``, DEC-115). **G3** is the manifest's targets, which must
  already be ``is_synthetic`` alerts (``eval/adversarial/load.py``, which P7-T08 runs). A G3
  prediction's ``cluster_id`` is its target's ``alert_id`` and its truth is ``None``. The G3 run
  still checks ``gold_v1``'s sha: G3 is evaluated only after the freeze.
* **B0** maps the gold row's severity through ``metrics.B0_MAP``. **B1** applies the alert's
  decision table to the facts ① computes (``b1_facts``); no table, or no rule holding, is
  ``needs_review``. Neither constructs an adapter or records a measurement.
* **B2, B3 and B4** are ``tier1.triage.evaluate_alert`` with ``EvalSwitches``: one code path, the
  deployed one. Each alert runs on its own connection, inside a ``READ ONLY`` transaction, through
  its own ``CachingAdapter`` over the run's single ``DeepSeekAdapter``, at most four at a time
  (``run_bounded``). The thinking mode is set once, on the ``Config`` the adapter sends from, and
  the cache is handed that same value.
* **Money** (DEC-121 Q5). The month's spend is ``llm_runs`` plus the billed cost of this calendar
  month's earlier evaluation runs, computed once before the first live call. The estimate line
  is printed; an estimate over what the cap has left is refused; an estimate above $5 needs
  ``--approved-usd``. The estimate is an upper bound: cache hits make a run cheaper, never
  dearer. ``SpendGuard`` stops a run at the cap mid-way; its remaining items become ``error``
  predictions and the run is still recorded.
* **Outputs.** ``<out-dir>/<eval_run_id>.json`` holds the run header and one row per cluster:
  ids, truth, verdict, closed tokens and measurements. It never holds prompt text, model output
  or a raw log (planning decision 7). Unless ``--no-record``, one ``eval_runs`` row is inserted on
  a separate read-write connection. Nothing is written to ``alerts``, ``llm_runs``,
  ``audit_events``, ``jobs`` or ``triage_labels``.

``human`` writes ``<out-dir>/human_<gold12>.json``: the two ``gold_offline`` labellers' labels on
the gold's clusters, the labellers chosen by ``label_export.resolve_labelers``. It holds labels
only, never notes (planning decision 11).

The DSN is ``--dsn``, else ``DATABASE_URL`` from ``--env-file``. It is never printed, and no
``Config`` in this process keeps it once read (DEC-122).

Exit codes: 0 done; 2 usage; 3 the gold, a lab window or the G3 manifest is not ready (the brief's
stop conditions); 4 the DSN or the database is unusable; 5 the estimate is above $5 and needs the
Owner's approval; 6 stopped by the monthly cap (refused by the estimate, or stopped mid-run).
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import dataclasses
import functools
import hashlib
import json
import math
import os
import re
import shlex
import subprocess
import sys
import tempfile
import uuid
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

# eval/ is a composition root outside backend/ and not a package on sys.path: its siblings are
# imported by name once the directory is on the path (the pattern of llm_cache.py and report.py),
# and `app.*` comes from the caller (PYTHONPATH=backend, or pytest's pythonpath).
sys.path.insert(0, str(Path(__file__).resolve().parent))

import label_export  # P6: the gold's reader and the labellers' resolution
import llm_cache  # P7-T02: the cache, the spend guard, the estimate, the bounded pool
from app.audit import llm_runs
from app.infra import config, db
from app.infra.errors import ConfigError
from app.kb import lookup as kb
from app.llm.adapter import DeepSeekAdapter, cost_usd
from app.llm.triage import TRIAGE_TEMPLATE, prompt_version
from app.tier1 import triage as tier1
from app.tier1.triage import DEPLOYED, EvalSwitches, TriageEvaluation, evaluate_alert
from metrics import B0_MAP, Prediction, metrics_json  # P7-T03's pinned contract

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NOT_READY = 3
EXIT_DSN = 4
EXIT_APPROVAL = 5
EXIT_CAP = 6

CONFIGS: tuple[str, ...] = ("B0", "B1", "B2", "B3", "B4")
#: The configurations that call the model.
LIVE_CONFIGS: tuple[str, ...] = ("B2", "B3", "B4")
GOLD_SETS: tuple[str, ...] = ("G2", "G3")
#: The brief: ASR is measured for B3 and B4.
G3_CONFIGS: tuple[str, ...] = ("B3", "B4")
#: The gold truth (DEC-111, DEC-115).
TRUTHS: tuple[str, ...] = ("escalate", "benign")

#: P7-tasks.md §4, measured cost per call: thinking disabled, the pilot's $0.2858 over 1,011
#: `llm_runs`; thinking enabled, `docs/smoke-test-D1.md`'s $0.1577 over 38 calls.
USD_PER_CALL: dict[str, float] = {"disabled": 0.00028, "enabled": 0.00415}
#: Calls per alert: the proposer only (B2, B3), or the proposer and the verifier (B4).
CALLS_PER_ALERT: dict[str, int] = {"B2": 1, "B3": 1, "B4": 2}
#: P7-tasks.md §4: +10 % for schema repairs.
REPAIR_MARGIN = 1.10
#: DEC-121 Q5: a live estimate above this needs the Owner's approval.
APPROVAL_USD = 5.00

#: Planning decision 9: B0's `prompt_version`; B0 and B1 answer with no model (`model_id`).
B0_PROMPT_VERSION = "severity_for"
NO_MODEL = "none"
#: `results` row `outcome` of an item whose evaluation raised (captured by `run_bounded`).
OUTCOME_EXCEPTION = "exception"
#: The evaluation outcomes that mean the spend cap refused a call.
_CAP_OUTCOMES = frozenset({"cap", "verifier_cap"})
LOADER = "eval/adversarial/load.py"

_HEX64 = re.compile(r"[0-9a-f]{64}")
_ALERTS_SQL = (
    "SELECT alert_id, category, severity, is_synthetic FROM alerts WHERE alert_id = ANY(%s)"
)
#: The second term of the month's spend (design note 6): what earlier evaluation runs of this
#: calendar month billed. The evaluation writes no `llm_runs`, so without it repeated runs would
#: be invisible to the cap. A document with no numeric `run.billed_usd` (B0, B1) adds nothing.
_EVAL_RUNS_BILLED_SQL = (
    "SELECT coalesce(sum((metrics->'run'->>'billed_usd')::numeric), 0) FROM eval_runs "
    "WHERE created_at >= date_trunc('month', now()) "
    "AND jsonb_typeof(metrics->'run'->'billed_usd') = 'number'"
)
_INSERT_EVAL_RUN_SQL = (
    "INSERT INTO eval_runs (eval_run_id, prompt_version, model_id, gold_set, config, metrics) "
    "VALUES (%s, %s, %s, %s, %s, %s)"
)
_EPILOG = (
    "exit codes: 0 done; 2 usage; 3 the gold, a lab window or the G3 manifest is not ready; "
    "4 the DSN or the database is unusable; 5 the estimate is above $5 and needs the Owner's "
    "approval (--approved-usd, DEC-121 Q5); 6 stopped by the monthly cap."
)


class Exit(Exception):
    """A controlled exit: a code from the table above and one line for stderr."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class AlertNotFound(LookupError):
    """An alert the run holds is no longer in the database (it passed the checks, then went)."""


@dataclass(frozen=True)
class Target:
    """One cluster to evaluate: everything its `Prediction` carries besides the answer.
    `category` is the alert's own `alerts.category` (the secondary view, planning decision 5);
    `severity` is the gold row's for G2, the alert's for G3."""

    cluster_id: str
    alert_id: str
    truth: str | None
    category_expected: str = ""
    kind: str = ""
    severity: str = ""
    category: str = ""


@dataclass(frozen=True)
class Row:
    """One results row: the prediction, the alert evaluated, how its evaluation ended
    (`TriageEvaluation.outcome`, `ok` for B0/B1, `exception`) and, when it produced no verdict,
    why, as a closed token (DEC-126 amendment 10): never an exception's message."""

    prediction: Prediction
    alert_id: str
    outcome: str
    error: str | None

    def to_json(self) -> dict[str, Any]:
        return {
            **dataclasses.asdict(self.prediction),
            "alert_id": self.alert_id,
            "outcome": self.outcome,
            "error": self.error,
        }


# --- the frozen gold (design note 1) -----------------------------------------------------------


def _git_ok(path: Path, *args: str) -> bool:
    """`git <args>` from `path`'s directory succeeded. No git, no repository, a hang: False."""
    try:
        proc = subprocess.run(
            ["git", *args], cwd=path.parent, capture_output=True, check=False, timeout=60
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def gold_sha(gold_path: Path, sha_file: Path) -> str:
    """The full sha256 of the frozen gold, or `Exit(3)` naming what is not frozen: `sha_file`
    exists; its hex is the sha256 of the gold's bytes; both files are tracked; neither differs
    from `HEAD` (the index included, so a staged edit is still an edit)."""
    if not sha_file.is_file():
        raise Exit(
            EXIT_NOT_READY,
            f"the gold is not frozen: {sha_file} does not exist — evaluation on an unfrozen gold "
            "set is not allowed (the P7 brief's stop condition)",
        )
    if not gold_path.is_file():
        raise Exit(EXIT_NOT_READY, f"the gold is not frozen: {gold_path} does not exist")
    try:
        fields = sha_file.read_text(encoding="utf-8").split()
    except (OSError, UnicodeDecodeError) as exc:
        raise Exit(EXIT_NOT_READY, f"{sha_file} is unreadable: {type(exc).__name__}") from None
    recorded = fields[0] if fields else ""
    if not _HEX64.fullmatch(recorded):
        raise Exit(EXIT_NOT_READY, f"{sha_file} holds no sha256 (64 lowercase hex digits)")
    actual = hashlib.sha256(gold_path.read_bytes()).hexdigest()
    if actual != recorded:
        raise Exit(
            EXIT_NOT_READY,
            f"the sha256 of {gold_path} ({actual[:12]}…) differs from {sha_file} "
            f"({recorded[:12]}…): the gold is not the one frozen",
        )
    for path in (gold_path, sha_file):
        if not _git_ok(path, "ls-files", "--error-unmatch", "--", str(path.resolve())):
            raise Exit(
                EXIT_NOT_READY,
                f"{path} is not tracked by git: the frozen gold and its sha are committed first",
            )
    both = (str(gold_path.resolve()), str(sha_file.resolve()))
    if not _git_ok(gold_path, "diff", "--quiet", "HEAD", "--", *both):
        raise Exit(
            EXIT_NOT_READY,
            f"{gold_path} or {sha_file} differs from HEAD: evaluate only the committed freeze "
            "(an edit after it is a new gold version, planning decision 12)",
        )
    return actual


# --- G2: the gold rows and the lab windows (design note 2) -------------------------------------


def _first(ids: Sequence[str], limit: int = 5) -> str:
    shown = ", ".join(ids[:limit])
    return shown + (f", … ({len(ids) - limit} more)" if len(ids) > limit else "")


def load_gold(gold_path: Path) -> list[label_export.GoldRow]:
    """The gold's rows, read with `label_export.read_gold_csv`, each with its `scenario_id` and
    `kind`. That reader leaves those two columns at their defaults ("") although the frozen file
    carries them (`write_gold_csv` writes all of `GOLD_COLUMNS`), so they are taken from the same
    file here. `Exit(3)` for a file that is not in the frozen format or not scorable: a header
    other than `GOLD_COLUMNS`, no rows, a repeated cluster, a gold set other than G2 (G1 is void,
    DEC-111), a label outside escalate/benign (DEC-115), a severity outside the DEC-053 band."""
    with gold_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != label_export.GOLD_COLUMNS:
            raise Exit(
                EXIT_NOT_READY,
                f"{gold_path}: the header is not label_export.GOLD_COLUMNS (the frozen format)",
            )
        window_columns = [(row["cluster_id"], row["scenario_id"], row["kind"]) for row in reader]
    rows = label_export.read_gold_csv(gold_path)
    if not rows:
        raise Exit(EXIT_NOT_READY, f"{gold_path} has no rows")
    repeated = sorted(cid for cid, n in Counter(r.cluster_id for r in rows).items() if n > 1)
    if repeated:
        raise Exit(EXIT_NOT_READY, f"{gold_path} lists a cluster twice: {_first(repeated)}")
    by_cluster = {
        cluster_id: (scenario_id, kind) for cluster_id, scenario_id, kind in window_columns
    }
    rows = [
        dataclasses.replace(
            row, scenario_id=by_cluster[row.cluster_id][0], kind=by_cluster[row.cluster_id][1]
        )
        for row in rows
    ]
    checks = (
        (lambda r: r.gold_set == "G2", "a gold set other than G2 (G1 is void, DEC-111)"),
        (lambda r: r.label in TRUTHS, "a label outside escalate/benign (DEC-115)"),
        (lambda r: r.severity in B0_MAP, "a severity outside the DEC-053 band"),
    )
    for holds, what in checks:
        bad = [row.cluster_id for row in rows if not holds(row)]
        if bad:
            raise Exit(
                EXIT_NOT_READY, f"{gold_path}: {len(bad)} row(s) carry {what}: {_first(bad)}"
            )
    return rows


def read_windows(path: Path) -> dict[str, str]:
    """`scenario_id -> category_expected` from `eval/lab_windows.csv` (P6's `lab_tag.py` writes
    one row per scenario and refuses a second). `Exit(3)` when the file is missing or malformed."""
    if not path.is_file():
        raise Exit(EXIT_NOT_READY, f"{path} does not exist: the lab windows are not recorded")
    windows: dict[str, str] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not {"scenario_id", "category_expected"} <= set(reader.fieldnames or ()):
            raise Exit(EXIT_NOT_READY, f"{path} has no scenario_id/category_expected columns")
        for row in reader:
            scenario_id, category = row["scenario_id"], row["category_expected"]
            if windows.get(scenario_id, category) != category:
                raise Exit(
                    EXIT_NOT_READY, f"{path}: scenario {scenario_id} has two expected categories"
                )
            windows[scenario_id] = category
    return windows


def g2_targets(rows: Sequence[label_export.GoldRow], windows: Mapping[str, str]) -> list[Target]:
    """One target per gold row, `category_expected` joined by `scenario_id`. A row whose
    scenario has no window is `Exit(3)` (DEC-120's exclusions are already out of the gold)."""
    missing = sorted({row.scenario_id for row in rows if row.scenario_id not in windows})
    if missing:
        named = _first([repr(scenario_id) for scenario_id in missing])
        raise Exit(
            EXIT_NOT_READY,
            f"{len(missing)} scenario_id(s) of the gold have no lab window: {named}",
        )
    return [
        Target(
            cluster_id=row.cluster_id,
            alert_id=row.alert_id,
            truth=row.label,
            category_expected=windows[row.scenario_id],
            kind=row.kind,
            severity=row.severity,
        )
        for row in rows
    ]


# --- G3: the manifest's targets (design note 3) ------------------------------------------------


def read_manifest(path: Path) -> list[dict[str, str]]:
    """The manifest's rows as `metrics.asr` reads them. `Exit(3)` when it is missing, has no
    target, lacks a column ASR groups by, or lists a target twice."""
    if not path.is_file():
        raise Exit(EXIT_NOT_READY, f"{path} does not exist: there is no G3 manifest")
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = {"alert_id", "vector", "pattern_family"} - set(reader.fieldnames or ())
        if missing:
            raise Exit(EXIT_NOT_READY, f"{path} has no {', '.join(sorted(missing))} column")
        rows = list(reader)
    if not rows:
        raise Exit(EXIT_NOT_READY, f"{path} has no target")
    repeated = sorted(a for a, n in Counter(r["alert_id"] for r in rows).items() if n > 1)
    if repeated:
        raise Exit(EXIT_NOT_READY, f"{path} lists a target twice: {_first(repeated)}")
    return rows


# --- the database checks ------------------------------------------------------------------------


def _alerts(conn: psycopg.Connection, alert_ids: Sequence[str]) -> dict[str, tuple]:
    rows = conn.execute(_ALERTS_SQL, (list(alert_ids),)).fetchall()
    return {row[0]: row[1:] for row in rows}


def with_database_fields(
    conn: psycopg.Connection, targets: Sequence[Target], gold_set: str
) -> list[Target]:
    """`targets` with the alert's own `category` (and, for G3, `severity`) from `alerts`.
    `Exit(3)` when a gold alert is not in this database, or when a G3 target is not an
    `is_synthetic` alert: then the loader has not run (P7-tasks.md §3 item 8)."""
    found = _alerts(conn, [target.alert_id for target in targets])
    if gold_set == "G3":
        bad = [t.alert_id for t in targets if t.alert_id not in found or not found[t.alert_id][2]]
        if bad:
            raise Exit(
                EXIT_NOT_READY,
                f"{len(bad)} of {len(targets)} G3 targets are not loaded as is_synthetic alerts "
                f"({_first(bad)}): run {LOADER} first, after the freeze (P7-tasks.md §3 item 8)",
            )
        return [
            dataclasses.replace(t, category=found[t.alert_id][0], severity=found[t.alert_id][1])
            for t in targets
        ]
    bad = [target.alert_id for target in targets if target.alert_id not in found]
    if bad:
        raise Exit(
            EXIT_NOT_READY,
            f"{len(bad)} of the gold's {len(targets)} alerts are not in this database "
            f"({_first(bad)}): run against the database the gold was built from",
        )
    return [dataclasses.replace(t, category=found[t.alert_id][0]) for t in targets]


# --- B0 and B1: deterministic, no adapter (design note 4) --------------------------------------


def _prediction(target: Target, verdict: str | None, **measured: Any) -> Prediction:
    return Prediction(
        cluster_id=target.cluster_id,
        truth=target.truth,
        verdict=verdict,
        category_expected=target.category_expected,
        category=target.category,
        kind=target.kind,
        severity=target.severity,
        **measured,
    )


def _exception_token(exc: BaseException) -> str:
    return f"exception:{type(exc).__name__}"


def b0_rows(targets: Sequence[Target]) -> list[Row]:
    """B0, severity only: the architecture's map (`metrics.B0_MAP`) of the gold row's severity.
    No measurement is recorded: they stay `None` (DEC-123 ruling 4)."""
    return [
        Row(_prediction(target, B0_MAP[target.severity]), target.alert_id, "ok", None)
        for target in targets
    ]


def b1_facts(conn: psycopg.Connection, alert_id: str, cfg: config.Config) -> dict[str, Any]:
    """The facts ① computes for this alert, built by the helpers `evaluate_alert` itself uses:
    its private `_load` and `_Subject`, its correlation call, and `llm.triage.build_facts`, all
    reached through `tier1.triage` so they cannot drift from it (the equality is pinned by
    `test_b1_facts_equal_evaluate_alert_facts`). The facts do not depend on `cfg`; it is taken
    so the call reads as `evaluate_alert`'s does."""
    row = tier1._load(conn, alert_id)
    if row is None:
        raise AlertNotFound(alert_id)
    subject = tier1._Subject(
        **{field.name: getattr(row, field.name) for field in dataclasses.fields(tier1._Subject)}
    )
    correlation = tier1.correlation.summarize_for_prompt(conn, subject)
    values = {
        field.name: getattr(row, field.name) for field in dataclasses.fields(tier1.TriageInput)
    }
    values["origin_host"] = row.origin_host or ""  # evaluate_alert's one conversion
    return tier1.build_facts(tier1.TriageInput(**values), correlation)


def b1_verdict(facts: Mapping[str, Any]) -> str:
    """B1, the decision table only: the first rule of the alert's table that holds
    (`kb.apply_table`), or `needs_review` when the category has no table or no rule holds (the
    brief)."""
    table = kb.get_decision_table(facts["category"])
    hit = kb.apply_table(table, facts) if table is not None else None
    return "needs_review" if hit is None else hit[0]


def b1_rows(conn: psycopg.Connection, targets: Sequence[Target], cfg: config.Config) -> list[Row]:
    """B1 on the run's read-only connection. An item that raises becomes an error row; its
    savepoint keeps the transaction usable for the next item."""
    rows = []
    for target in targets:
        try:
            with conn.transaction():
                verdict = b1_verdict(b1_facts(conn, target.alert_id, cfg))
        except Exception as exc:  # noqa: BLE001 — captured on its item, the others go on
            prediction = _prediction(target, None)
            rows.append(Row(prediction, target.alert_id, OUTCOME_EXCEPTION, _exception_token(exc)))
            continue
        rows.append(Row(_prediction(target, verdict), target.alert_id, "ok", None))
    return rows


def kb_prompt_version(root: Path = kb.KB_ROOT) -> str:
    """Planning decision 9: `kb:` + the sha256 of the decision tables' bytes, concatenated in
    file-name order, 12 hex. `root` is the one `kb.get_decision_table` reads."""
    digest = hashlib.sha256()
    for path in sorted((root / "decision_tables").glob("*.yaml"), key=lambda p: p.name):
        digest.update(path.read_bytes())
    return "kb:" + digest.hexdigest()[:12]


# --- B2, B3 and B4: one code path (design note 5) ----------------------------------------------


def switches_for(config_name: str, template: Path | None) -> EvalSwitches:
    """B2: ① without the enrichment and correlation blocks, gate steps 1-3. B3: ① whole, gate
    steps 1-3, no verifier. B4: the deployed pipeline, with the proposer template replaced when
    one is given (P7-T07's v1.1)."""
    if config_name == "B2":
        return EvalSwitches(include_context=False, include_correlation=False, gate_mode="steps_1_3")
    if config_name == "B3":
        return EvalSwitches(gate_mode="steps_1_3")
    if config_name == "B4":
        if template is None:
            return DEPLOYED
        return dataclasses.replace(DEPLOYED, proposer_template=Path(template))
    raise ValueError(f"{config_name} is not evaluated through evaluate_alert")


@dataclass(frozen=True)
class _Item:
    """One work item: its target and its own `CachingAdapter`, whose side record (`results`)
    stays readable even when the evaluation raised."""

    target: Target
    adapter: llm_cache.CachingAdapter


def _evaluate(
    item: _Item, *, dsn: str, cfg: config.Config, switches: EvalSwitches
) -> TriageEvaluation:
    """One alert on its own connection (a psycopg connection is not shared across threads),
    inside a READ ONLY transaction: `evaluate_alert` only reads, and here the server enforces it."""
    conn = db.connect(dsn)
    try:
        conn.execute("SET TRANSACTION READ ONLY")
        evaluation = evaluate_alert(
            conn, item.target.alert_id, adapter=item.adapter, cfg=cfg, switches=switches
        )
    finally:
        with contextlib.suppress(psycopg.Error):
            conn.rollback()
        conn.close()
    if evaluation is None:
        raise AlertNotFound(item.target.alert_id)
    return evaluation


def _side_record(results: Sequence[llm_cache.CachedResult], cfg: config.Config) -> dict:
    """`cached` and `billed_usd` of one item, from its `CachingAdapter.results` (P7-T02's side
    record: `propose`/`verify` wrap each result in a `Proposal` that drops `cached`). `cached`:
    True when every call was answered from the cache, False when one was live, None when no call
    returned. `billed_usd`: this item's live calls priced by `adapter.cost_usd`, 0.0 when none."""
    live = [result for result in results if not result.cached]
    return {
        "cached": all(result.cached for result in results) if results else None,
        "billed_usd": round(math.fsum(cost_usd(result.usage, cfg) for result in live), 5),
    }


def _evaluation_row(target: Target, evaluation: TriageEvaluation, side: dict) -> Row:
    """The verdict only for `ok` (a failed evaluation scores as `error`). The evidence counts are
    copied as given, whenever the gate started (DEC-126 amendment 7). Cost and latency are the
    measurement's, a cache hit's included; with no call returned there is none, so `None`."""
    answered = evaluation.calls > 0
    ok = evaluation.outcome == "ok"
    prediction = _prediction(
        target,
        evaluation.final_verdict if ok else None,
        reasons_kept=evaluation.reasons_kept,
        reasons_dropped=evaluation.reasons_dropped,
        cost_usd=evaluation.cost_usd if answered else None,
        latency_ms=evaluation.latency_ms if answered else None,
        **side,
    )
    return Row(prediction, target.alert_id, evaluation.outcome, None if ok else evaluation.outcome)


@dataclass(frozen=True)
class LiveRun:
    rows: list[Row]
    models: frozenset[str]
    prompt_versions: frozenset[str]
    cache_hits: int
    live_calls: int
    billed_usd: float
    stopped_by_cap: bool


def run_live(
    targets: Sequence[Target],
    *,
    config_name: str,
    thinking: str,
    template: Path | None,
    dsn: str,
    cfg: config.Config,
    month_spend_usd: float,
    cache_dir: Path,
    max_workers: int,
) -> LiveRun:
    """B2, B3 or B4 over `targets`: one `DeepSeekAdapter` for the run, one `CachingAdapter` per
    item over it (sharing the directory, the key locks and the one `SpendGuard`), `run_bounded`
    over the items. `month_spend_usd` was computed once, before this: no callable here queries a
    connection another thread uses (DEC-126 amendment 9)."""
    # The mode the adapter sends (`extra_body`) and the mode in every cache key are one value:
    # the `Config` is given `thinking` here and the cache is handed `thinking` itself.
    cfg_run = dataclasses.replace(cfg, LLM_THINKING=thinking)
    guard = llm_cache.SpendGuard(lambda: month_spend_usd, cfg_run.LLM_MONTHLY_USD_CAP, cfg_run)
    inner = DeepSeekAdapter(cfg_run, spent_usd=guard.total_usd)
    items = [
        _Item(
            target,
            llm_cache.CachingAdapter(inner, cache_dir=cache_dir, thinking=thinking, spend=guard),
        )
        for target in targets
    ]
    evaluate = functools.partial(
        _evaluate, dsn=dsn, cfg=cfg_run, switches=switches_for(config_name, template)
    )
    outcomes = llm_cache.run_bounded(items, evaluate, max_workers=max_workers)

    rows: list[Row] = []
    models: set[str] = set()
    versions: set[str] = set()
    hits = live = 0
    for item, outcome in zip(items, outcomes, strict=True):
        results = item.adapter.results
        models.update(result.model for result in results)
        hits += sum(1 for result in results if result.cached)
        live += sum(1 for result in results if not result.cached)
        side = _side_record(results, cfg_run)
        if outcome.ok:
            versions.add(outcome.value.prompt_version)
            rows.append(_evaluation_row(item.target, outcome.value, side))
        else:
            prediction = _prediction(item.target, None, **side)
            token = _exception_token(outcome.error)
            rows.append(Row(prediction, item.target.alert_id, OUTCOME_EXCEPTION, token))
    return LiveRun(
        rows=rows,
        models=frozenset(models),
        prompt_versions=frozenset(versions),
        cache_hits=hits,
        live_calls=live,
        # The guard prices every live call as it returns, one whose entry then failed to be
        # written included: the run's bill, and what the next run's month spend adds.
        billed_usd=round(guard.live_spent_usd, 5),
        stopped_by_cap=any(row.outcome in _CAP_OUTCOMES for row in rows),
    )


def run_model_id(models: frozenset[str]) -> str:
    """Every call's response model, the verifier's included (DEC-126 amendment 6): the one seen,
    or a sorted `+`-join of several, with a warning; `none` when no call returned."""
    if not models:
        print(
            "run_configs: warning: no model call returned a result; model_id recorded as 'none'",
            file=sys.stderr,
        )
        return NO_MODEL
    joined = "+".join(sorted(models))
    if len(models) > 1:
        print(
            f"run_configs: warning: {len(models)} models answered this run's calls; "
            f"model_id recorded as {joined}",
            file=sys.stderr,
        )
    return joined


def live_prompt_version(versions: frozenset[str], template: Path | None) -> str:
    """The proposer's `prompt_version` the evaluations report (`TriageEvaluation`): the deployed
    template's `llm.triage.prompt_version`, or `file:<sha12>` for an override (planning decision
    9). With no evaluation to read it from, the same value is computed."""
    if len(versions) == 1:
        return next(iter(versions))
    if versions:  # one run is one set of switches: not expected, but never hidden
        return "+".join(sorted(versions))
    if template is None:
        return prompt_version(TRIAGE_TEMPLATE)
    return "file:" + hashlib.sha256(Path(template).read_bytes()).hexdigest()[:12]


# --- money (design note 6) ----------------------------------------------------------------------


def month_spend(conn: psycopg.Connection) -> float:
    """This calendar month's spend: `llm_runs` (`month_spend_usd`, the adapter's own figure) plus
    what this month's earlier evaluation runs billed (`metrics.run.billed_usd`)."""
    evaluations = conn.execute(_EVAL_RUNS_BILLED_SQL).fetchone()[0]
    return llm_runs.month_spend_usd(conn) + float(evaluations)


def estimate(config_name: str, n: int, thinking: str | None) -> tuple[int, float]:
    """`(calls, usd)` for `n` alerts, the repair margin included: `estimate_cost(n,
    calls_per_alert, usd_per_call) × 1.10`. B0 and B1 call nothing."""
    if config_name not in LIVE_CONFIGS:
        return 0, 0.0
    per_alert = CALLS_PER_ALERT[config_name]
    calls = math.ceil(round(n * per_alert * REPAIR_MARGIN, 9))
    usd = llm_cache.estimate_cost(n, per_alert, USD_PER_CALL[thinking]) * REPAIR_MARGIN
    return calls, usd


def estimate_line(
    config_name: str,
    gold_set: str,
    thinking: str | None,
    n: int,
    calls: int,
    usd: float,
    *,
    month_spend: float,
    cap: float,
) -> str:
    return (
        f"estimate: {config_name} {gold_set} thinking={thinking or 'none'} n={n} "
        f"calls≈{calls} usd≈{usd:.4f} month_spend={month_spend:.4f} cap={cap}"
    )


def _approval_command(argv: Sequence[str], usd: float) -> str:
    """The same command with `--approved-usd` set to the estimate rounded up to the cent; the
    DSN's value is replaced by a placeholder, never printed."""
    kept: list[str] = []
    tokens = iter(argv)
    for token in tokens:
        if token == "--approved-usd":
            next(tokens, None)
        elif token.startswith("--approved-usd="):
            continue
        elif token == "--dsn" or token.startswith("--dsn="):
            if token == "--dsn":
                next(tokens, None)
            kept += ["--dsn", "<DSN>"]
        else:
            kept.append(token)
    figure = math.ceil(round(usd * 100, 6)) / 100
    return (
        "PYTHONPATH=backend python3 eval/run_configs.py "
        f"{shlex.join(kept)} --approved-usd {figure:.2f}"
    )


def check_budget(
    usd: float,
    *,
    month_spend: float,
    cap: float,
    approved_usd: float | None,
    argv: Sequence[str],
) -> None:
    """The two refusals before any live call: more than the cap has left (`refuse_if_over`) is
    `Exit(6)`, and no approval lifts it; above $5 with no `--approved-usd` at least the estimate
    is `Exit(5)`, printing the command to re-run once the Owner has approved (DEC-121 Q5)."""
    try:
        llm_cache.refuse_if_over(usd, month_spend, cap)
    except llm_cache.CostRefused as exc:
        raise Exit(EXIT_CAP, f"refused by the monthly cap: {exc}") from None
    if usd > APPROVAL_USD and (approved_usd is None or approved_usd < usd):
        given = "none" if approved_usd is None else f"${approved_usd:.2f}"
        raise Exit(
            EXIT_APPROVAL,
            f"the estimate ${usd:.4f} is above ${APPROVAL_USD:.2f} and needs the Owner's "
            f"approval (DEC-121 Q5; approved: {given}). Once approved, run:\n  "
            + _approval_command(argv, usd),
        )


# --- outputs (design note 7) --------------------------------------------------------------------


def _write_json(path: Path, doc: Mapping[str, Any]) -> None:
    """A temporary file in the target directory, then a rename: a reader sees all or nothing."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(doc, handle, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
            handle.write("\n")
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_name)
        raise


def _rate(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def headline(
    eval_run_id: str,
    config_name: str,
    gold_set: str,
    thinking: str,
    rows: Sequence[Row],
    doc: Mapping[str, Any],
    billed_usd: float,
) -> str:
    errors = sum(1 for row in rows if row.prediction.verdict is None)
    head = f"run {eval_run_id} {config_name} {gold_set} thinking={thinking} n={len(rows)}"
    if gold_set == "G3":
        body = f"asr={_rate(doc['asr']['asr'])}"
    else:
        score = doc["score"]
        body = (
            f"macro_f1={_rate(score['macro_f1'])} "
            f"recall_escalate={_rate(score['recall_escalate'])} "
            f"deferral_escalate={_rate(score['deferral_rate']['escalate'])}"
        )
    return f"{head} {body} errors={errors} billed=${billed_usd:.4f}"


def _connect(dsn: str) -> psycopg.Connection:
    try:
        return db.connect(dsn)
    except psycopg.Error as exc:  # a DSN libpq cannot parse or a server it cannot reach
        raise Exit(EXIT_DSN, f"could not open the database: {type(exc).__name__}") from None


def _connect_read_only(dsn: str) -> psycopg.Connection:
    conn = _connect(dsn)
    conn.execute("SET TRANSACTION READ ONLY")
    return conn


def record_run(
    dsn: str,
    eval_run_id: str,
    *,
    prompt_version_: str,
    model_id: str,
    gold_set: str,
    config_name: str,
    doc: Mapping[str, Any],
) -> None:
    """The run's one `eval_runs` row, on a separate read-write connection, after the evaluation."""
    conn = _connect(dsn)
    try:
        conn.execute(
            _INSERT_EVAL_RUN_SQL,
            (eval_run_id, prompt_version_, model_id, gold_set, config_name, Jsonb(doc)),
        )
        conn.commit()
    finally:
        conn.close()


# --- configuration ------------------------------------------------------------------------------


def _load_config(env_file: str) -> config.Config:
    try:
        return config.load(env_file=env_file)
    except ConfigError as exc:
        raise Exit(EXIT_DSN, f"cannot read the configuration: {exc}") from None


def _dsn_and_config(dsn_arg: str | None, cfg: config.Config) -> tuple[str, config.Config]:
    """The DSN (`--dsn`, else `DATABASE_URL`), and `cfg` with every DSN field blanked, so no
    `Config` this process holds can print one (DEC-122: a `Config`'s repr shows those fields)."""
    dsn = dsn_arg or cfg.DATABASE_URL
    if not dsn:
        raise Exit(
            EXIT_DSN, "no DSN: pass --dsn, or set DATABASE_URL in the file named by --env-file"
        )
    blank = dataclasses.replace(cfg, DATABASE_URL="", DATABASE_URL_OWNER="", TEST_DATABASE_URL="")
    return dsn, blank


def _check_usage(args: argparse.Namespace) -> None:
    """The refusals that need no file and no database, so they come first (exit 2)."""
    live = args.config in LIVE_CONFIGS
    if live and args.thinking is None:
        raise Exit(
            EXIT_USAGE,
            "--thinking {disabled,enabled} is required for B2-B4 and has no default (DEC-042): "
            "it is sent with every call and is part of every cache key",
        )
    if not live and args.thinking is not None:
        raise Exit(
            EXIT_USAGE,
            f"--thinking applies to B2-B4 only: {args.config} makes no model call "
            "(its llm_thinking is recorded as 'none')",
        )
    if args.template is not None and args.config != "B4":
        raise Exit(EXIT_USAGE, "--template replaces B4's proposer template only (P7-T07's v1.1)")
    if args.template is not None and not Path(args.template).is_file():
        raise Exit(EXIT_USAGE, f"--template {args.template}: no such file")
    if args.gold_set == "G3" and args.config not in G3_CONFIGS:
        raise Exit(EXIT_USAGE, "G3 is run with B3 and B4 only (the brief: ASR for B3 and B4)")
    if not 1 <= args.max_workers <= llm_cache.MAX_WORKERS:
        raise Exit(
            EXIT_USAGE,
            f"--max-workers must be 1..{llm_cache.MAX_WORKERS}: run_bounded refuses more "
            "(the brief's concurrency ceiling)",
        )
    if args.approved_usd is not None and not (
        math.isfinite(args.approved_usd) and args.approved_usd >= 0
    ):
        raise Exit(EXIT_USAGE, "--approved-usd must be a finite amount of dollars >= 0")


# --- the two subcommands ------------------------------------------------------------------------


def cmd_run(args: argparse.Namespace, argv: Sequence[str]) -> int:
    _check_usage(args)
    gold_path = Path(args.gold)
    sha = gold_sha(gold_path, Path(args.sha_file))  # before any other file, before any connection
    manifest_rows = manifest_sha = None
    if args.gold_set == "G2":
        targets = g2_targets(load_gold(gold_path), read_windows(Path(args.lab_windows)))
    else:
        manifest_path = Path(args.manifest)
        manifest_rows = read_manifest(manifest_path)
        manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        targets = [Target(row["alert_id"], row["alert_id"], None) for row in manifest_rows]

    live = args.config in LIVE_CONFIGS
    cfg = _load_config(args.env_file)
    if live and not cfg.llm_enabled:  # evaluate_alert does not check it (DEC-126 amendment 8)
        raise Exit(
            EXIT_USAGE,
            f"{args.config} needs the LLM, and it is disabled here: LLM_MODEL_PROPOSER is empty "
            "in the environment and in --env-file",
        )
    dsn, cfg = _dsn_and_config(args.dsn, cfg)
    template = Path(args.template) if args.template else None
    thinking = args.thinking or "none"

    conn = _connect_read_only(dsn)
    try:
        targets = with_database_fields(conn, targets, args.gold_set)
        spend = 0.0
        if live or args.estimate_only:
            spend = month_spend(conn)  # once, on this connection, before the first live call
            calls, usd = estimate(args.config, len(targets), args.thinking)
            cap = cfg.LLM_MONTHLY_USD_CAP
            print(
                estimate_line(
                    args.config,
                    args.gold_set,
                    args.thinking,
                    len(targets),
                    calls,
                    usd,
                    month_spend=spend,
                    cap=cap,
                )
            )
            if live:
                check_budget(
                    usd, month_spend=spend, cap=cap, approved_usd=args.approved_usd, argv=argv
                )
        if args.estimate_only:
            return EXIT_OK
        if args.config == "B0":
            rows = b0_rows(targets)
        elif args.config == "B1":
            rows = b1_rows(conn, targets, cfg)
    finally:
        with contextlib.suppress(psycopg.Error):
            conn.rollback()
        conn.close()

    eval_run_id = str(uuid.uuid4())
    if live:
        run = run_live(
            targets,
            config_name=args.config,
            thinking=args.thinking,
            template=template,
            dsn=dsn,
            cfg=cfg,
            month_spend_usd=spend,
            cache_dir=Path(args.cache_dir),
            max_workers=args.max_workers,
        )
        rows = run.rows
        model_id = run_model_id(run.models)
        version = live_prompt_version(run.prompt_versions, template)
        billed, hits, live_calls, stopped = (
            run.billed_usd,
            run.cache_hits,
            run.live_calls,
            run.stopped_by_cap,
        )
    else:
        model_id = NO_MODEL
        version = B0_PROMPT_VERSION if args.config == "B0" else kb_prompt_version()
        billed, hits, live_calls, stopped = 0.0, 0, 0, False

    doc = metrics_json(
        [row.prediction for row in rows],
        gold_sha256=sha,
        llm_thinking=thinking,
        config=args.config,
        gold_set=args.gold_set,
        manifest_rows=manifest_rows,
        extra={
            "eval_run_id": eval_run_id,
            "billed_usd": billed,
            "cache_hits": hits,
            "live_calls": live_calls,
            "stopped_by_cap": stopped,
            "template_sha256": (
                hashlib.sha256(template.read_bytes()).hexdigest() if template else None
            ),
            "manifest_sha256": manifest_sha,
            "max_workers": args.max_workers if live else None,
        },
    )
    results = {
        "eval_run_id": eval_run_id,
        "gold_sha256": sha,
        "gold_set": args.gold_set,
        "config": args.config,
        "llm_thinking": thinking,
        "prompt_version": version,
        "model_id": model_id,
        "predictions": [row.to_json() for row in rows],
    }
    path = Path(args.out_dir) / f"{eval_run_id}.json"
    _write_json(path, results)
    if not args.no_record:
        record_run(
            dsn,
            eval_run_id,
            prompt_version_=version,
            model_id=model_id,
            gold_set=args.gold_set,
            config_name=args.config,
            doc=doc,
        )
    print(headline(eval_run_id, args.config, args.gold_set, thinking, rows, doc, billed))
    if stopped:
        not_evaluated = sum(1 for row in rows if row.outcome in _CAP_OUTCOMES)
        print(
            f"run_configs: stopped by the monthly cap: {not_evaluated} item(s) refused a live "
            "call and are recorded as errors (metrics.run.stopped_by_cap = true)",
            file=sys.stderr,
        )
        return EXIT_CAP
    return EXIT_OK


def cmd_human(args: argparse.Namespace) -> int:
    gold_path = Path(args.gold)
    sha = gold_sha(gold_path, Path(args.sha_file))
    cluster_ids = [row.cluster_id for row in load_gold(gold_path)]
    dsn, _ = _dsn_and_config(args.dsn, _load_config(args.env_file))
    conn = _connect_read_only(dsn)
    try:
        try:
            labeler_a, labeler_b = label_export.resolve_labelers(conn, cluster_ids, None, None)
        except label_export.TwoLabelerProtocolViolation as exc:
            raise Exit(
                EXIT_NOT_READY,
                f"expected exactly two labellers with gold_offline rows over the gold's clusters, "
                f"found {len(exc.counts)} (the protocol is two people)",
            ) from None
        pairs = label_export.fetch_label_pairs(conn, cluster_ids, labeler_a, labeler_b)
    finally:
        with contextlib.suppress(psycopg.Error):
            conn.rollback()
        conn.close()
    # Labels only: the pairs' confidences and notes are never copied (planning decision 11).
    labels_a = {cid: pair.label_a for cid, pair in pairs.items() if pair.label_a is not None}
    labels_b = {cid: pair.label_b for cid, pair in pairs.items() if pair.label_b is not None}
    doc = {
        "a": {"labeler_id": labeler_a, "labels": labels_a},
        "b": {"labeler_id": labeler_b, "labels": labels_b},
    }
    path = Path(args.out_dir) / f"human_{sha[:12]}.json"
    _write_json(path, doc)
    print(
        f"human gold={sha[:12]} a={labeler_a} labels={len(labels_a)} "
        f"b={labeler_b} labels={len(labels_b)} -> {path}"
    )
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run_configs.py",
        description="Run one P7 evaluation configuration on the frozen gold, or write the human "
        "baseline's labels.",
        epilog=_EPILOG,
        allow_abbrev=False,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser(
        "run", help="evaluate one configuration and record it", epilog=_EPILOG, allow_abbrev=False
    )
    run.add_argument("--config", required=True, choices=CONFIGS)
    run.add_argument("--gold-set", default="G2", choices=GOLD_SETS)
    run.add_argument("--gold", default="eval/gold_v1.csv", metavar="PATH")
    run.add_argument("--sha-file", default="eval/gold_v1.sha256", metavar="PATH")
    run.add_argument("--lab-windows", default="eval/lab_windows.csv", metavar="PATH")
    run.add_argument("--manifest", default="eval/adversarial/manifest.csv", metavar="PATH")
    run.add_argument(
        "--thinking",
        choices=llm_cache.THINKING_MODES,
        default=None,
        help="required for B2-B4, no default (DEC-042)",
    )
    run.add_argument("--template", default=None, metavar="PATH", help="B4 only: the proposer's")
    run.add_argument("--cache-dir", default="eval/results/cache", metavar="DIR")
    run.add_argument("--out-dir", default="eval/results", metavar="DIR")
    run.add_argument("--env-file", default=".env", metavar="PATH")
    run.add_argument("--dsn", default=None, metavar="DSN", help="never printed")
    run.add_argument("--estimate-only", action="store_true", help="print the estimate and stop")
    run.add_argument("--approved-usd", type=float, default=None, metavar="USD")
    run.add_argument("--no-record", action="store_true", help="write no eval_runs row")
    run.add_argument("--max-workers", type=int, default=llm_cache.MAX_WORKERS, metavar="N")

    human = sub.add_parser(
        "human",
        help="write the two labellers' gold_offline labels on the gold",
        epilog=_EPILOG,
        allow_abbrev=False,
    )
    human.add_argument("--gold", default="eval/gold_v1.csv", metavar="PATH")
    human.add_argument("--sha-file", default="eval/gold_v1.sha256", metavar="PATH")
    human.add_argument("--out-dir", default="eval/results", metavar="DIR")
    human.add_argument("--env-file", default=".env", metavar="PATH")
    human.add_argument("--dsn", default=None, metavar="DSN", help="never printed")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:  # --help (0) or argparse's own usage error (2)
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE
    try:
        if args.command == "run":
            return cmd_run(args, argv)
        return cmd_human(args)
    except Exit as exc:
        print(f"run_configs: {exc.message}", file=sys.stderr)
        return exc.code
    except psycopg.Error as exc:  # the class only: a server message may name the host or role
        print(f"run_configs: database error: {type(exc).__name__}", file=sys.stderr)
        return EXIT_DSN


if __name__ == "__main__":
    raise SystemExit(main())
