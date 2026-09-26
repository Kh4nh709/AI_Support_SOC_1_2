"""P7's report renderer: the committed evaluation tables and the per-alert predictions CSV (P7-T05).

One read-only command turns a frozen gold sha's `eval_runs` rows (each carrying the
`metrics.metrics_json` document, P7-T03) and the local per-run results files (P7-T04's
`eval/results/<eval_run_id>.json`) into three markdown files and one CSV under `--out-dir`:

* `ablation.md`   — the caveat, the run table, the G2 headline (deferral beside strict recall),
                    the 2 x 4 truth x outcome table per run, the human baseline, B4 vs B1,
                    the paired thinking ablation (DEC-042) and the prompt-v1.1 line.
* `per_category.md` — `by_category_expected` (primary), `by_kind`, `by_severity` (the phase-1:148
                    band as written, never re-banded), `by_category` (the system's own category,
                    a secondary view) and the dropped-category list.
* `adversarial.md` — the G3 ASR block for B3/B4, `by_vector`, `by_pattern_family`, and the
                    architecture's expectation printed as an expectation, not a result.
* `predictions_<gold12>.csv` — one row per (run, cluster); ids, truth and verdicts only, **no raw
                    text and no model output text** (P7-tasks.md planning decision 7).

This card computes no metric: it calls only P7-T03's functions and reads P7-T04's shapes. The
`render_*` functions are pure over their inputs and are tested without a database; the CLI does the
I/O. Rendering the same inputs twice gives byte-identical output: no clock, hostname or absolute
path reaches any file, floats carry fixed decimals (3 for rates, 4 for USD, integer ms), `None`
renders as `n/a`, and every order is fixed. The DEC-111 caveat sentence is imported from
`build_gold`, never retyped (a lab rate is not an estate rate).

Charts (`should`) render only when `matplotlib` imports; no dependency is added. The database is
read-only (`SET TRANSACTION READ ONLY`); nothing under `docs/results/` is committed by this card
(P7-T08 commits the real render).

Exit codes: 0 done; 2 usage; 3 a selected run's results file is missing or its
`metrics.gold_sha256` differs from `--gold-sha`; 4 the DSN is unreadable.
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import io
import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

# eval/ is a composition root outside backend/ and is not a package on sys.path; its siblings are
# imported by name after the directory is placed on the path, the way llm_cache.py imports
# smoke_test. `app.*` is expected to be importable from the caller (PYTHONPATH=backend, or pytest's
# pythonpath), the same contract every eval/ CLI relies on.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_gold import DEC111_SENTENCE  # the (xii) sentence, imported not retyped
from metrics import (  # P7-T03's pinned contract
    OUTCOMES,
    TRUTH_CLASSES,
    Prediction,
    correct,
    human_predictions,
    mcnemar_exact,
    outcome,
    paired_delta_ci,
    score,
)

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NOT_READY = 3
EXIT_DSN = 4

#: The second caveat line, printed verbatim beside DEC111_SENTENCE at the top of every file.
CLASS_BALANCE_SENTENCE = (
    "The class balance is the lab schedule's, not nature's; no rate here is an estate rate "
    "(DEC-111)."
)

#: The eight lab categories a scenario can synthesise (the ten playbook categories of
#: `ingest.category.PRIORITY` minus `web_attack` and `policy_violation`, DEC-055/DEC-056/DEC-057).
LAB_CATEGORIES: tuple[str, ...] = (
    "c2_beacon",
    "data_exfiltration",
    "malware",
    "privilege_escalation",
    "ransomware",
    "recon",
    "ssh_brute_force",
    "suspicious_login",
)
#: Playbook categories with no lab route at all, named with the decision that ruled each out.
NEVER_SYNTHESISED: tuple[tuple[str, str], ...] = (
    (
        "web_attack",
        (
            "no lab route: the host's web containers are production services outside the lab's "
            "bounds, so no scenario feeds the web rules DEC-055 routes here (DEC-055, DEC-056, DEC-132)"
        ),
    ),
    ("policy_violation", "no signal in any Linux stock rule and no lab route (DEC-057)"),
)

#: The predictions CSV header, exactly (P7-tasks.md planning decision 7; no free-text column).
CSV_COLUMNS: tuple[str, ...] = (
    "gold_sha12",
    "eval_run_id",
    "gold_set",
    "config",
    "llm_thinking",
    "prompt_version",
    "cluster_id",
    "alert_id",
    "truth",
    "verdict",
    "outcome",
    "correct_strict",
    "category_expected",
    "category",
    "kind",
    "severity",
    "cached",
    "cost_usd",
    "latency_ms",
    "error",
)

# The G2 headline columns, in order. Deferral(escalate) is the column immediately after strict
# recall(escalate) (DEC-121 Q1: "reported beside it"); the adjacency is a tested contract.
_HEADLINE_HEADERS: tuple[str, ...] = (
    "config",
    "thinking",
    "n",
    "macro-F1 [95% CI]",
    "recall(escalate) strict [95% CI]",
    "deferral(escalate) [95% CI]",
    "precision(close) [95% CI]",
    "deferral(close)",
    "error rate",
    "evidence-verified",
    "cost/alert USD",
    "billed USD",
    "p50/p95 ms",
)

PREDICTION_FIELDS: tuple[str, ...] = tuple(f.name for f in dataclasses.fields(Prediction))


class Exit(Exception):
    """A controlled CLI exit carrying a POSIX code and a message for stderr."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class Run:
    """One evaluation run assembled for rendering: the `eval_runs` identity, the stored
    `metrics.metrics_json` document, and the per-cluster predictions from the results file."""

    eval_run_id: str
    gold_set: str
    config: str
    llm_thinking: str
    prompt_version: str
    model_id: str
    gold_sha256: str
    metrics: Mapping
    preds: tuple[Prediction, ...]
    rows: tuple[Mapping, ...] = field(default_factory=tuple)

    @property
    def n(self) -> int:
        return int(self.metrics.get("n", len(self.preds)))

    @property
    def short_id(self) -> str:
        return self.eval_run_id[:8]

    @property
    def score(self) -> Mapping:
        return self.metrics.get("score", {})

    @property
    def ci(self) -> Mapping:
        return self.metrics.get("ci", {})


# --- formatting: fixed decimals, None -> n/a, deterministic ------------------------------------


def _rate(value: object) -> str:
    return "n/a" if value is None else f"{float(value):.3f}"


def _usd(value: object) -> str:
    return "n/a" if value is None else f"{float(value):.4f}"


def _ms(value: object) -> str:
    return "n/a" if value is None else f"{int(value)}"


def _yn(value: object) -> str:
    if value is None:
        return "n/a"
    return "true" if value else "false"


def _ci(ci: Mapping, name: str) -> str:
    """Format one interval from a `bootstrap_ci`/`paired_delta_ci` result: `[low, high]` at 3
    decimals, `[unstable]` when the metric was withheld, `[n/a]` when it is absent or undefined."""
    if ci.get(f"{name}_unstable"):
        return "[unstable]"
    pair = ci.get(name)
    if not pair:
        return "[n/a]"
    low, high = pair
    if low is None or high is None:
        return "[n/a]"
    return f"[{_rate(low)}, {_rate(high)}]"


def _value_ci(value: object, ci: Mapping, name: str) -> str:
    return f"{_rate(value)} {_ci(ci, name)}"


def _row(cells: Sequence[str]) -> str:
    return "| " + " | ".join(cells) + " |"


def _table(headers: Sequence[str], body: Sequence[Sequence[str]]) -> str:
    lines = [_row(headers), _row(["---"] * len(headers))]
    lines.extend(_row(r) for r in body)
    return "\n".join(lines)


# --- assembling runs from P7-T04's shapes ------------------------------------------------------


def _prediction_from_row(row: Mapping) -> Prediction:
    """A `Prediction` from a results row (`asdict(Prediction)` plus alert_id/outcome/error): only
    the dataclass fields are taken, so alert_id, outcome, error and any other key are ignored."""
    return Prediction(**{k: row[k] for k in PREDICTION_FIELDS if k in row})


def build_run(results: Mapping, metrics: Mapping) -> Run:
    """A `Run` from one results file (P7-T04 note 7) and its stored `metrics` document. The
    `llm_thinking` shown is the one recorded in `metrics`, never inferred from the config."""
    rows = tuple(results["predictions"])
    preds = tuple(_prediction_from_row(r) for r in rows)
    return Run(
        eval_run_id=str(results["eval_run_id"]),
        gold_set=results["gold_set"],
        config=results["config"],
        llm_thinking=str(metrics.get("llm_thinking", results.get("llm_thinking", "none"))),
        prompt_version=results.get("prompt_version", ""),
        model_id=results.get("model_id", ""),
        gold_sha256=str(metrics.get("gold_sha256", results.get("gold_sha256", ""))),
        metrics=metrics,
        preds=preds,
        rows=rows,
    )


def _sort_key(run: Run) -> tuple:
    return (run.gold_set, run.config, run.llm_thinking, run.prompt_version, run.eval_run_id)


def _sorted(runs: Sequence[Run]) -> list[Run]:
    return sorted(runs, key=_sort_key)


def _g2(runs: Sequence[Run]) -> list[Run]:
    return _sorted([r for r in runs if r.gold_set == "G2"])


def _g3(runs: Sequence[Run]) -> list[Run]:
    return _sorted([r for r in runs if r.gold_set == "G3"])


def _pick(runs: Sequence[Run], config: str, *, thinking: str | None = None) -> Run | None:
    matches = [
        r
        for r in _sorted(runs)
        if r.config == config and (thinking is None or r.llm_thinking == thinking)
    ]
    return matches[0] if matches else None


# --- pure render functions ---------------------------------------------------------------------


def render_caveat() -> str:
    """The two caveat lines that open every file (design note 1). DEC111_SENTENCE is imported."""
    return f"{DEC111_SENTENCE}\n\n{CLASS_BALANCE_SENTENCE}\n"


def render_run_table(runs: Sequence[Run]) -> str:
    body = [
        [r.config, r.llm_thinking, r.prompt_version, r.model_id, str(r.n), r.short_id]
        for r in _sorted(runs)
    ]
    headers = ["config", "thinking", "prompt_version", "model_id", "n", "eval_run_id"]
    if not body:
        return "(no run selected)"
    return _table(headers, body)


def _evidence_cell(run: Run) -> str:
    s = run.score
    rate = s.get("evidence_verified_rate")
    if run.config not in ("B2", "B3", "B4") or rate is None:
        return "n/a"
    mark = "✓" if s.get("evidence_target_met") else "✗"
    return f"{_rate(rate)} {mark}"


def render_headline(runs: Sequence[Run]) -> str:
    g2 = _g2(runs)
    if not g2:
        return "(no G2 run selected)"
    body = []
    for run in g2:
        s = run.score
        ci = run.ci
        deferral = s.get("deferral_rate", {})
        body.append(
            [
                run.config,
                run.llm_thinking,
                str(run.n),
                _value_ci(s.get("macro_f1"), ci, "macro_f1"),
                _value_ci(s.get("recall_escalate"), ci, "recall_escalate"),
                _value_ci(deferral.get("escalate"), ci, "deferral_rate.escalate"),
                _value_ci(s.get("precision_close"), ci, "precision_close"),
                _rate(deferral.get("close")),
                _rate(s.get("error_rate")),
                _evidence_cell(run),
                _usd(s.get("cost_usd_per_alert")),
                _usd(s.get("billed_usd")),
                f"{_ms(s.get('latency_ms_p50'))}/{_ms(s.get('latency_ms_p95'))}",
            ]
        )
    return _table(_HEADLINE_HEADERS, body)


def render_confusion_tables(runs: Sequence[Run]) -> str:
    g2 = _g2(runs)
    if not g2:
        return "(no G2 run selected)"
    parts = []
    headers = ["truth \\ outcome", *OUTCOMES]
    for run in g2:
        table = run.score.get("confusion", {})
        body = [
            [row, *[str(table.get(row, {}).get(col, 0)) for col in OUTCOMES]]
            for row in TRUTH_CLASSES
        ]
        parts.append(
            f"### {run.config} {run.llm_thinking} — {run.short_id}\n\n{_table(headers, body)}"
        )
    return "\n\n".join(parts)


def render_human_baseline(runs: Sequence[Run], human: Mapping | None, kappa: Mapping | None) -> str:
    """Labellers a and b scored with `human_predictions` on the gold clusters, beside the kappa
    file's strict `vs_truth` accuracy. A missing human file is named, never skipped (design note).
    """
    header = "## Human baseline — a second result, not the gold (DEC-111)"
    if human is None:
        return f"{header}\n\n(not available — run_configs.py human)"
    g2 = _g2(runs)
    if not g2:
        return f"{header}\n\n(no G2 run selected: no gold clusters to score the labellers on)"
    gold = list(g2[0].preds)
    vs_truth = (kappa or {}).get("vs_truth", {})
    body = []
    for key in ("a", "b"):
        entry = human.get(key)
        if not isinstance(entry, Mapping):
            body.append([key, "n/a", "n/a", "n/a", "n/a", "n/a"])
            continue
        labels = entry.get("labels", {})
        s = score(human_predictions(labels, gold))
        acc = vs_truth.get(key, {}).get("accuracy") if isinstance(vs_truth, Mapping) else None
        body.append(
            [
                key,
                str(entry.get("labeler_id", "")),
                _rate(s.get("macro_f1")),
                _rate(s.get("recall_escalate")),
                _rate(s.get("precision_close")),
                _rate(acc),
            ]
        )
    headers = [
        "labeller",
        "labeler_id",
        "macro-F1",
        "recall(escalate) strict",
        "precision(close)",
        "vs_truth accuracy",
    ]
    return f"{header}\n\n{_table(headers, body)}"


def _delta(later: Mapping, earlier: Mapping, name: str) -> object:
    a, b = earlier.get(name), later.get(name)
    if a is None or b is None:
        return None
    return b - a


def _delta_cell(later: Mapping, earlier: Mapping, delta_ci: Mapping, name: str) -> str:
    """The point delta `later[name] - earlier[name]` with its resampled interval beside it."""
    return f"{_rate(_delta(later, earlier, name))} {_ci(delta_ci, name)}"


def render_b4_vs_b1(runs: Sequence[Run]) -> str:
    header = "## B4 vs B1"
    b1 = _pick(runs, "B1")
    b4 = _pick(runs, "B4", thinking="disabled") or _pick(runs, "B4")
    if b1 is None or b4 is None:
        missing = ", ".join(name for name, r in (("B1", b1), ("B4", b4)) if r is None)
        return f"{header}\n\n(not available: no G2 {missing} run selected)"
    delta_ci = paired_delta_ci(b1.preds, b4.preds, ["macro_f1", "recall_escalate"])
    mc = mcnemar_exact(b1.preds, b4.preds)
    body = [
        ["macro-F1", _delta_cell(b4.score, b1.score, delta_ci, "macro_f1")],
        ["recall(escalate) strict", _delta_cell(b4.score, b1.score, delta_ci, "recall_escalate")],
    ]
    table = _table(["metric", "delta (B4 − B1) [95% CI]"], body)
    mcnemar = (
        f"McNemar (exact): n_discordant={mc['n_discordant']}, "
        f"B1-only-correct={mc['a_only_correct']}, B4-only-correct={mc['b_only_correct']}, "
        f"p={mc['p_value']:.4f}"
    )
    return (
        f"{header}\n\nB4 = {b4.config} thinking={b4.llm_thinking}; B1 baseline.\n\n"
        f"{table}\n\n{mcnemar}"
    )


def render_thinking_pair(runs: Sequence[Run]) -> str:
    """The paired DEC-042 ablation: B4 thinking=disabled vs enabled on the same clusters. Each
    run's recorded `llm_thinking` is printed from its metrics, never inferred."""
    header = "## Paired thinking ablation (DEC-042)"
    off = _pick(runs, "B4", thinking="disabled")
    on = _pick(runs, "B4", thinking="enabled")
    if off is None or on is None:
        return (
            f"{header}\n\n"
            "(not available: the paired B4 disabled/enabled G2 runs were not both selected)"
        )
    recorded = (
        f"recorded llm_thinking: disabled run = {off.metrics.get('llm_thinking')!r}, "
        f"enabled run = {on.metrics.get('llm_thinking')!r} (from each run's metrics, not inferred)"
    )
    names = ["macro_f1", "recall_escalate", "precision_close", "evidence_verified_rate"]
    labels = {
        "macro_f1": "macro-F1",
        "recall_escalate": "recall(escalate) strict",
        "precision_close": "precision(close)",
        "evidence_verified_rate": "evidence-verified",
    }
    delta_ci = paired_delta_ci(off.preds, on.preds, names)
    body = []
    for name in names:
        body.append(
            [
                labels[name],
                _rate(off.score.get(name)),
                _rate(on.score.get(name)),
                _delta_cell(on.score, off.score, delta_ci, name),
            ]
        )
    metrics_table = _table(
        ["metric", "disabled", "enabled", "delta (enabled − disabled) [95% CI]"], body
    )
    cost_body = [
        [
            "cost/alert USD",
            _usd(off.score.get("cost_usd_per_alert")),
            _usd(on.score.get("cost_usd_per_alert")),
        ],
        ["p50 ms", _ms(off.score.get("latency_ms_p50")), _ms(on.score.get("latency_ms_p50"))],
        ["p95 ms", _ms(off.score.get("latency_ms_p95")), _ms(on.score.get("latency_ms_p95"))],
    ]
    cost_table = _table(["measure", "disabled", "enabled"], cost_body)
    mc = mcnemar_exact(off.preds, on.preds)
    mcnemar = (
        f"McNemar (exact): n_discordant={mc['n_discordant']}, "
        f"disabled-only-correct={mc['a_only_correct']}, "
        f"enabled-only-correct={mc['b_only_correct']}, p={mc['p_value']:.4f}"
    )
    return f"{header}\n\n{recorded}\n\n{metrics_table}\n\n{cost_table}\n\n{mcnemar}"


def render_v1_1(gate_decision: Mapping | None, fewshot_decision: Mapping | None) -> str:
    """The three prompt-v1.1 states (DEC-121 Q2). Built: the gate decision (T06's JSON). Not built:
    the reason from the few-shot decision (T07's JSON). Neither file: no decision recorded."""
    header = "## Prompt v1.1"
    if gate_decision is not None:
        decision = str(gate_decision.get("decision", "recorded"))
        reason = str(gate_decision.get("reason", "")).strip()
        line = f"prompt v1.1: built and evaluated — {decision}"
        if reason:
            line += f": {reason}"
        return f"{header}\n\n{line}"
    if fewshot_decision is not None:
        reason = str(fewshot_decision.get("reason", "no qualifying triage_labels row")).strip()
        return f"{header}\n\nprompt v1.1: not built — {reason} (DEC-116, DEC-121 Q2)"
    return f"{header}\n\nprompt v1.1: no decision recorded"


def _category_table(by_group: Mapping) -> str:
    headers = [
        "category",
        "n",
        "recall(escalate) strict",
        "deferral(escalate)",
        "precision(close)",
        "macro-F1",
    ]
    body = []
    for key in sorted(by_group):
        s = by_group[key]
        body.append(
            [
                key,
                str(s.get("n", 0)),
                _rate(s.get("recall_escalate")),
                _rate(s.get("deferral_rate", {}).get("escalate")),
                _rate(s.get("precision_close")),
                _rate(s.get("macro_f1")),
            ]
        )
    if not body:
        return "(no rows)"
    return _table(headers, body)


def _grouped_section(runs: Sequence[Run], doc_key: str) -> str:
    parts = []
    for run in _g2(runs):
        by = run.metrics.get(doc_key, {})
        parts.append(
            f"### {run.config} {run.llm_thinking} — {run.short_id}\n\n{_category_table(by)}"
        )
    return "\n\n".join(parts) if parts else "(no G2 run selected)"


def render_dropped_categories(runs: Sequence[Run]) -> str:
    present: set[str] = set()
    for run in _g2(runs):
        present |= set(run.metrics.get("by_category_expected", {}))
    dropped = [c for c in LAB_CATEGORIES if c not in present]
    header = "## Dropped (no gold cluster; never synthesised)"
    lines = [
        header,
        "",
        f"Compared against the eight lab categories ({', '.join(LAB_CATEGORIES)}):",
        "",
    ]
    if dropped:
        for cat in dropped:
            lines.append(f"- {cat}: no gold cluster in the selected runs — dropped")
    else:
        lines.append("- all eight lab categories have at least one gold cluster")
    for cat, reason in NEVER_SYNTHESISED:
        lines.append(f"- {cat}: never synthesised — {reason}")
    return "\n".join(lines)


def render_ablation(
    runs: Sequence[Run],
    *,
    human: Mapping | None = None,
    kappa: Mapping | None = None,
    gate_decision: Mapping | None = None,
    fewshot_decision: Mapping | None = None,
    gold12: str = "",
    charts_note: str = "(charts not rendered: matplotlib not installed)",
) -> str:
    sections = [
        render_caveat(),
        f"# Ablation — gold {gold12}",
        "## Runs\n\n" + render_run_table(runs),
        "## Headline (G2)\n\n" + render_headline(runs),
        "## Truth × outcome (per run)\n\n" + render_confusion_tables(runs),
        render_human_baseline(runs, human, kappa),
        render_b4_vs_b1(runs),
        render_thinking_pair(runs),
        render_v1_1(gate_decision, fewshot_decision),
        "## Charts\n\n" + charts_note,
    ]
    return "\n\n".join(sections) + "\n"


def render_per_category(runs: Sequence[Run], *, gold12: str = "") -> str:
    sections = [
        render_caveat(),
        f"# Per-category — gold {gold12}",
        "## By expected category (primary; the scenario's declared category, DEC-114)\n\n"
        + _grouped_section(runs, "by_category_expected"),
        "## By kind\n\n" + _grouped_section(runs, "by_kind"),
        "## By severity (phase-1:148 band as written, never re-banded)\n\n"
        + _grouped_section(runs, "by_severity"),
        "## By category — secondary view: the system under test's category\n\n"
        + _grouped_section(runs, "by_category"),
        render_dropped_categories(runs),
    ]
    return "\n\n".join(sections) + "\n"


def _asr_block_table(block: Mapping) -> str:
    headers = ["n", "successes", "ASR", "error rate"]
    body = [
        [
            str(block.get("n", 0)),
            str(block.get("successes", 0)),
            _rate(block.get("asr")),
            _rate(block.get("error_rate")),
        ]
    ]
    return _table(headers, body)


def _asr_group_table(groups: Mapping, key_name: str) -> str:
    headers = [key_name, "n", "successes", "ASR", "error rate"]
    body = []
    for key in sorted(groups):
        block = groups[key]
        body.append(
            [
                key,
                str(block.get("n", 0)),
                str(block.get("successes", 0)),
                _rate(block.get("asr")),
                _rate(block.get("error_rate")),
            ]
        )
    if not body:
        return "(no rows)"
    return _table(headers, body)


def render_adversarial(runs: Sequence[Run], *, gold12: str = "") -> str:
    g3 = _g3(runs)
    parts = [render_caveat(), f"# Adversarial (G3) — gold {gold12}"]
    if not g3:
        parts.append("(no G3 run selected — nothing to report)")
        return "\n\n".join(parts) + "\n"
    for run in g3:
        asr = run.metrics.get("asr", {})
        block = [
            f"## {run.config} {run.llm_thinking} — {run.short_id}",
            _asr_block_table(asr),
            "### by vector\n\n" + _asr_group_table(asr.get("by_vector", {}), "vector"),
            "### by pattern family\n\n"
            + _asr_group_table(asr.get("by_pattern_family", {}), "pattern_family"),
        ]
        parts.append("\n\n".join(block))
    parts.append(
        "## Expectation (architecture §6), printed as an expectation, not a result\n\n"
        "expected: B3 > 0, B4 ≈ 0"
    )
    return "\n\n".join(parts) + "\n"


def render_predictions_csv(runs: Sequence[Run], gold12: str) -> str:
    """Long format, one row per (run, cluster), the exact CSV_COLUMNS header, sorted by
    (gold_set, config, llm_thinking, prompt_version, cluster_id), UTF-8 with `\\n` endings. No
    free-text column exists, so raw log or model output text in a source row never reaches here."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    rows: list[tuple[str, ...]] = []
    for run in runs:
        for raw in run.rows:
            pred = _prediction_from_row(raw)
            truth = pred.truth
            rows.append(
                (
                    gold12,
                    run.eval_run_id,
                    run.gold_set,
                    run.config,
                    run.llm_thinking,
                    run.prompt_version,
                    str(pred.cluster_id),
                    str(raw.get("alert_id", "")),
                    "n/a" if truth is None else str(truth),
                    "n/a" if pred.verdict is None else str(pred.verdict),
                    outcome(pred.verdict),
                    "n/a" if truth is None else _yn(correct(pred)),
                    str(pred.category_expected),
                    str(pred.category),
                    str(pred.kind),
                    str(pred.severity),
                    _yn(pred.cached),
                    _usd(pred.cost_usd),
                    _ms(pred.latency_ms),
                    str(raw.get("error") or ""),
                )
            )
    # Sort by (gold_set, config, llm_thinking, prompt_version, cluster_id): columns 2..6.
    rows.sort(key=lambda r: (r[2], r[3], r[4], r[5], r[6]))
    for r in rows:
        writer.writerow(r)
    return buffer.getvalue()


# --- charts (should; matplotlib optional at import time only) ----------------------------------


def _get_pyplot():
    """Return matplotlib's pyplot with the Agg backend, or `None` if matplotlib does not import.
    Isolated so a test can monkeypatch it to simulate matplotlib's absence (no dependency added)."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        return plt
    except ImportError:
        return None


def render_charts(runs: Sequence[Run], out_dir: Path) -> str:
    """Write the two ablation PNGs with CI whiskers per run when matplotlib imports; otherwise
    write nothing and return the not-rendered note for the markdown."""
    plt = _get_pyplot()
    if plt is None:
        return "(charts not rendered: matplotlib not installed)"
    g2 = _g2(runs)
    written = []
    for fname, metric, ci_name, title in (
        ("ablation_macro_f1.png", "macro_f1", "macro_f1", "macro-F1 by config"),
        (
            "ablation_recall_deferral.png",
            "recall_escalate",
            "recall_escalate",
            "recall(escalate) strict by config",
        ),
    ):
        labels = [f"{r.config}/{r.llm_thinking}" for r in g2]
        values = [r.score.get(metric) or 0.0 for r in g2]
        lows, highs = [], []
        for r in g2:
            value = r.score.get(metric) or 0.0
            pair = r.ci.get(ci_name)
            if pair and pair[0] is not None and pair[1] is not None:
                low, high = pair
            else:
                low = high = value
            lows.append(value - low)
            highs.append(high - value)
        fig, ax = plt.subplots()
        ax.bar(range(len(g2)), values, yerr=[lows, highs], capsize=4)
        ax.set_xticks(range(len(g2)))
        ax.set_xticklabels(labels, rotation=45, ha="right")
        ax.set_title(title)
        fig.tight_layout()
        fig.savefig(out_dir / fname)
        plt.close(fig)
        written.append(fname)
    return "charts rendered: " + ", ".join(written)


# --- I/O: selection, loading, the CLI ----------------------------------------------------------


def select_runs(conn, gold_sha: str, run_ids: Sequence[str] | None = None) -> list[dict]:
    """The `eval_runs` rows to report, as dicts of eval_run_id/prompt_version/model_id/gold_set/
    config/metrics. With `run_ids`, exactly those. Otherwise every row whose
    `metrics->>'gold_sha256'` equals `gold_sha`, keeping the latest `created_at` per
    (gold_set, config, `metrics->>'llm_thinking'`, prompt_version). Does not set the transaction
    read-only itself, so it is usable on the read-write connection a test inserts rows on; the CLI
    opens its own read-only connection."""
    from psycopg.rows import dict_row

    columns = "eval_run_id, prompt_version, model_id, gold_set, config, metrics"
    with conn.cursor(row_factory=dict_row) as cur:
        if run_ids:
            cur.execute(
                f"SELECT {columns} FROM eval_runs WHERE eval_run_id = ANY(%s) "
                "ORDER BY gold_set, config, prompt_version, eval_run_id",
                (list(run_ids),),
            )
        else:
            cur.execute(
                f"SELECT DISTINCT ON (gold_set, config, metrics->>'llm_thinking', prompt_version) "
                f"{columns} FROM eval_runs WHERE metrics->>'gold_sha256' = %s "
                "ORDER BY gold_set, config, metrics->>'llm_thinking', prompt_version, "
                "created_at DESC, eval_run_id DESC",
                (gold_sha,),
            )
        return [dict(r) for r in cur.fetchall()]


def load_runs(metas: Sequence[Mapping], results_dir: Path, gold_sha: str) -> list[Run]:
    """Assemble `Run`s from selected `eval_runs` rows and their results files. A selected run whose
    results JSON is missing exits 3 and names it (CIs, McNemar and the CSV need the per-cluster
    rows); a run whose `metrics.gold_sha256` differs from `gold_sha` exits 3."""
    runs = []
    for meta in metas:
        eval_run_id = str(meta["eval_run_id"])
        metrics = meta["metrics"]
        if str(metrics.get("gold_sha256")) != gold_sha:
            raise Exit(
                EXIT_NOT_READY,
                f"run {eval_run_id}: metrics.gold_sha256 {metrics.get('gold_sha256')!r} "
                f"differs from --gold-sha {gold_sha!r}",
            )
        path = results_dir / f"{eval_run_id}.json"
        if not path.exists():
            raise Exit(
                EXIT_NOT_READY,
                f"results file missing for selected run {eval_run_id}: {path} "
                "(the per-cluster rows are needed for the CIs, McNemar and the CSV; "
                "run eval/run_configs.py to produce it)",
            )
        results = json.loads(path.read_text(encoding="utf-8"))
        runs.append(build_run(results, metrics))
    return runs


def _resolve_dsn(dsn: str | None, env_file: str) -> str:
    if dsn:
        return dsn
    from app.infra import config

    resolved = config.load(env_file=env_file).DATABASE_URL
    if not resolved:
        raise Exit(
            EXIT_DSN,
            "no DSN: pass --dsn, or set DATABASE_URL in the file named by --env-file",
        )
    return resolved


def _connect_readonly(dsn: str):
    import psycopg
    from app.infra import db

    try:
        conn = db.connect(dsn)
    except psycopg.Error as exc:  # a DSN libpq cannot parse or a server it cannot reach
        raise Exit(EXIT_DSN, f"could not open the database: {type(exc).__name__}") from None
    conn.execute("SET TRANSACTION READ ONLY")
    return conn


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="report.py",
        description="Render P7's committed evaluation tables and the per-alert predictions CSV.",
        epilog="exit codes: 0 done; 2 usage; 3 a results file is missing or a gold_sha differs; "
        "4 the DSN is unreadable.",
    )
    parser.add_argument("--gold-sha", required=True, metavar="HEX")
    parser.add_argument("--run-ids", default=None, metavar="UUID,...")
    parser.add_argument("--results-dir", default="eval/results", metavar="DIR")
    parser.add_argument("--kappa", default="eval/kappa_v1.json", metavar="PATH")
    parser.add_argument("--human", default=None, metavar="PATH")
    parser.add_argument("--fewshot-decision", default=None, metavar="PATH")
    parser.add_argument("--gate-decision", default=None, metavar="PATH")
    parser.add_argument("--out-dir", default="docs/results", metavar="DIR")
    charts = parser.add_mutually_exclusive_group()
    charts.add_argument("--charts", dest="charts", action="store_true", default=None)
    charts.add_argument("--no-charts", dest="charts", action="store_false")
    parser.add_argument("--env-file", default=".env", metavar="PATH")
    parser.add_argument("--dsn", default=None, metavar="DSN")
    return parser


def _load_json(path: Path) -> Mapping | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    gold_sha = args.gold_sha
    gold12 = gold_sha[:12]
    results_dir = Path(args.results_dir)
    out_dir = Path(args.out_dir)
    run_ids = [x for x in (args.run_ids.split(",") if args.run_ids else []) if x]
    human_path = Path(args.human) if args.human else results_dir / f"human_{gold12}.json"

    try:
        dsn = _resolve_dsn(args.dsn, args.env_file)
        conn = _connect_readonly(dsn)
        try:
            metas = select_runs(conn, gold_sha, run_ids or None)
        finally:
            conn.rollback()
            conn.close()
        if not metas:
            raise Exit(
                EXIT_NOT_READY,
                f"no eval_runs row for gold_sha {gold_sha!r}"
                + (f" among run-ids {run_ids}" if run_ids else ""),
            )
        runs = load_runs(metas, results_dir, gold_sha)

        human = _load_json(human_path)
        kappa = _load_json(Path(args.kappa))
        gate_decision = _load_json(Path(args.gate_decision)) if args.gate_decision else None
        fewshot_decision = (
            _load_json(Path(args.fewshot_decision)) if args.fewshot_decision else None
        )

        out_dir.mkdir(parents=True, exist_ok=True)
        charts_note = "(charts not rendered: matplotlib not installed)"
        want_charts = _get_pyplot() is not None if args.charts is None else args.charts
        if want_charts:
            charts_note = render_charts(runs, out_dir)

        _write(
            out_dir / "ablation.md",
            render_ablation(
                runs,
                human=human,
                kappa=kappa,
                gate_decision=gate_decision,
                fewshot_decision=fewshot_decision,
                gold12=gold12,
                charts_note=charts_note,
            ),
        )
        _write(out_dir / "per_category.md", render_per_category(runs, gold12=gold12))
        _write(out_dir / "adversarial.md", render_adversarial(runs, gold12=gold12))
        _write(out_dir / f"predictions_{gold12}.csv", render_predictions_csv(runs, gold12))
    except Exit as exit_:
        print(exit_.message, file=sys.stderr)
        return exit_.code

    print(f"report gold={gold12} runs={len(runs)} -> {out_dir} (3 md + predictions_{gold12}.csv)")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
