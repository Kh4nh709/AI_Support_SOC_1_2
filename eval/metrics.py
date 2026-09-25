"""P7's scoring library: every number the evaluation reports, from per-cluster predictions (P7-T03).

No rate computed here is an estate rate (DEC-111): the gold is an author-generated lab corpus and
its class balance is the schedule's.

**One scale for every source (DEC-121 Q1).** The gold truth is two-valued: `escalate` for an
attack window, `benign` for a benign window (DEC-111, DEC-115). A configuration answers
`escalate`, `false_positive`, `benign` or `needs_review`. Both sides are mapped onto decision
classes before anything is counted. A truth is `escalate` or `close` (`TRUTH_CLASS`). A verdict
is `escalate`, `close` (`false_positive` or `benign`), `review` (`needs_review`) or `error`
(`OUTCOME_OF`, `outcome`). B0-B4, the paired thinking runs, G3 and the human labellers all map
into one `Prediction` and are scored by the same functions on the same 2 x 4 truth x outcome
table (`confusion`).

**`error`, the fourth outcome, is this card's planning decision, not DEC-121's.** A run that
fails (schema, cap, transient, builder violation) produced no verdict: `verdict=None`. It is
neither a deferral nor a close. It gets its own column and its own rate (`error_rate`), and every
strict metric counts it as wrong.

**Strict, with the deferral beside it.** `recall_escalate` counts only `escalate` on an attack as
caught. `needs_review` on an attack is a deferral: it is reported per truth class in
`deferral_rate` and never folded silently into either side. Every score carries the full table,
so a reader can still compute any other reading of it.

**Undefined is not zero.** Every ratio whose denominator is zero is `None`, never 0 or 1. A truth
class with no support has no F1 and is left out of `macro_f1` (P7-tasks.md planning decision 4:
`n/a`).

**Uncertainty.** `bootstrap_ci` resamples clusters with replacement, `BOOTSTRAP_DRAWS` times,
driven by `random.Random(seed)` with `seed=EVAL_SEED`, and reports percentile intervals.
`paired_delta_ci` applies the same draws to two runs over the same clusters (B4 vs B1, thinking
enabled vs disabled). `mcnemar_exact` is the exact two-sided binomial test on the discordant
pairs. `asr` scores G3, which has no truth. `metrics_json` assembles the `eval_runs.metrics`
document.

Pure and standard library only (P7-tasks.md planning decision 6: numpy and scipy are not
installed): no file, no database, no network, no model call. P7-T04 to P7-T07 import the names in
`__all__`; they are a contract.
"""

from __future__ import annotations

import json
import math
import random
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, replace

__all__ = [
    "B0_MAP",
    "BOOTSTRAP_DRAWS",
    "CI_METRICS",
    "EVAL_SEED",
    "EVIDENCE_TARGET",
    "METRICS_VERSION",
    "OUTCOMES",
    "OUTCOME_OF",
    "TRUTH_CLASS",
    "TRUTH_CLASSES",
    "Prediction",
    "asr",
    "bootstrap_ci",
    "by_group",
    "confusion",
    "correct",
    "human_predictions",
    "mcnemar_exact",
    "metrics_json",
    "outcome",
    "paired_delta_ci",
    "score",
    "truth_class",
]

#: The project's seed, the literal again: nothing is imported across `eval/`, so this is not
#: `build_gold.EVAL_SEED` but the same number (rule 10 of the P6 index).
EVAL_SEED = 20260904
#: Resamples behind every interval (architecture §6: "bootstrap 1.000 lần cho mọi số").
BOOTSTRAP_DRAWS = 1000
#: Gold truth -> truth class (DEC-111, DEC-115). `false_positive` is not a truth value.
TRUTH_CLASS: dict[str, str] = {"escalate": "escalate", "benign": "close"}
#: Verdict -> outcome (DEC-121 Q1). No verdict (`None`) is `error`, which no verdict maps to.
OUTCOME_OF: dict[str, str] = {
    "escalate": "escalate",
    "false_positive": "close",
    "benign": "close",
    "needs_review": "review",
}
#: The confusion table's columns, in the order every table is written.
OUTCOMES: tuple[str, ...] = ("escalate", "close", "review", "error")
#: The confusion table's rows.
TRUTH_CLASSES: tuple[str, ...] = ("escalate", "close")
#: B0, severity only: architecture §6's row verbatim, "low/medium → false_positive · high →
#: needs_review · critical → escalate". The keys are the DEC-053 band. B0 has no other home.
B0_MAP: dict[str, str] = {
    "low": "false_positive",
    "medium": "false_positive",
    "high": "needs_review",
    "critical": "escalate",
}
#: Architecture §6: the evidence-verified rate (quote ⊂ block) targets ≥ 90 %.
EVIDENCE_TARGET = 0.90
#: The version of the `eval_runs.metrics` document `metrics_json` writes.
METRICS_VERSION = 1
#: The intervals a G2 run's document carries.
CI_METRICS: tuple[str, ...] = (
    "macro_f1",
    "recall_escalate",
    "precision_close",
    "accuracy",
    "deferral_rate.escalate",
    "deferral_rate.close",
    "error_rate",
    "evidence_verified_rate",
)

# `by_group`'s keys: the scenario's declared category first, the product's own category last
# (P7-tasks.md planning decision 5).
_GROUP_KEYS: tuple[str, ...] = ("category_expected", "kind", "severity", "category")
# What a model run records and a human label never does (`human_predictions`).
_MEASUREMENTS: tuple[str, ...] = (
    "reasons_kept",
    "reasons_dropped",
    "cost_usd",
    "latency_ms",
    "cached",
    "billed_usd",
)
# What an interval can be taken of: score()'s scalar measures and the two dotted deferral rates.
# `evidence_target_met` is a flag, not a measure; its interval is `evidence_verified_rate`'s.
_INTERVAL_METRICS: tuple[str, ...] = (
    "n",
    "accuracy",
    "recall_escalate",
    "precision_escalate",
    "f1_escalate",
    "recall_close",
    "precision_close",
    "f1_close",
    "macro_f1",
    "error_rate",
    "evidence_verified_rate",
    "cost_usd_per_alert",
    "billed_usd",
    "latency_ms_p50",
    "latency_ms_p95",
    "deferral_rate.escalate",
    "deferral_rate.close",
)
# An interval is withheld when more than one draw in twenty (5 %) leaves its metric undefined.
_UNSTABLE_ONE_IN = 20


@dataclass(frozen=True)
class Prediction:
    """One cluster's answer from one configuration or one labeller. Every source maps into this
    one record, so the scoring is identical across them (design note 1); P7-T04 does the mapping.

    `truth` is the gold label, `None` for a G3 target, which has no gold truth (its `cluster_id`
    is the target's `alert_id`). `verdict` is `None` when the source produced no verdict; that
    scores as `error`. `severity` is the gold row's, as written (the DEC-053 band). The
    measurements are `None` where a source records none (B0, B1, a human): `reasons_kept` and
    `reasons_dropped` after gate step 3; `cost_usd` and `latency_ms` of the measurement (for a
    cache hit, the recorded call's); `cached`; `billed_usd`, what this run paid (0.0 on a hit).
    """

    cluster_id: str
    truth: str | None
    verdict: str | None
    category_expected: str = ""
    category: str = ""
    kind: str = ""
    severity: str = ""
    reasons_kept: int | None = None
    reasons_dropped: int | None = None
    cost_usd: float | None = None
    latency_ms: int | None = None
    cached: bool | None = None
    billed_usd: float | None = None


def outcome(verdict: str | None) -> str:
    """The decision class of a verdict: `OUTCOME_OF[verdict]`, or `error` for `None`.

    An unknown verdict raises `ValueError` naming it. Nothing is normalised: a stray spelling
    would otherwise score silently as wrong."""
    if verdict is None:
        return "error"
    try:
        return OUTCOME_OF[verdict]
    except (KeyError, TypeError):
        raise ValueError(
            f"unknown verdict {verdict!r}: a verdict is one of {sorted(OUTCOME_OF)}, "
            "or None when the run produced none (scored as error)"
        ) from None


def truth_class(truth: str) -> str:
    """The decision class of a gold truth: `escalate` or `close`.

    Anything else raises `ValueError`. A gold row labelled `false_positive` violates DEC-115 and
    is never scored silently; a G3 target (`None`) has no truth to score against."""
    try:
        return TRUTH_CLASS[truth]
    except (KeyError, TypeError):
        raise ValueError(
            f"gold truth {truth!r} is not a truth value: the truth is 'escalate' or 'benign' "
            "(DEC-111, DEC-115; 'false_positive' is a label a human can give, not a truth)"
        ) from None


def correct(pred: Prediction) -> bool:
    """Strict correctness: the verdict's outcome is the truth's class. `review` and `error` are
    wrong for either truth."""
    expected = truth_class(pred.truth)
    return outcome(pred.verdict) == expected


def confusion(preds: Iterable[Prediction]) -> dict[str, dict[str, int]]:
    """The truth class x outcome table: all 2 x 4 cells, zeros included, rows in `TRUTH_CLASSES`
    order and columns in `OUTCOMES` order."""
    table = {row: dict.fromkeys(OUTCOMES, 0) for row in TRUTH_CLASSES}
    for pred in preds:
        table[truth_class(pred.truth)][outcome(pred.verdict)] += 1
    return table


def _ratio(numerator: float, denominator: float) -> float | None:
    """`numerator / denominator`, or `None` when the denominator is zero: undefined is never 0
    or 1."""
    if denominator == 0:
        return None
    return numerator / denominator


def _mean(values: Sequence[float]) -> float | None:
    # fsum is exactly rounded, so the mean does not depend on the order of the predictions.
    return _ratio(math.fsum(values), len(values))


def _f1(table: Mapping[str, Mapping[str, int]], cls: str) -> float | None:
    """F1 of one truth class as 2 TP / (support + predicted), which is 2PR / (P + R) without the
    undefined intermediate. No truth support: `None` (n/a). Support but never predicted: a real
    0.0, so a configuration that never answers a class is not spared its F1."""
    support = sum(table[cls].values())
    if support == 0:
        return None
    predicted = sum(table[row][cls] for row in TRUTH_CLASSES)
    return _ratio(2 * table[cls][cls], support + predicted)


def _nearest_rank(ordered: Sequence[int], percent: int) -> int | None:
    """The nearest-rank percentile of sorted values: the ceil(percent / 100 * n)-th smallest."""
    if not ordered:
        return None
    rank = max(1, -(-percent * len(ordered) // 100))
    return ordered[rank - 1]


def _evidence_verified_rate(preds: Iterable[Prediction]) -> float | None:
    """Σ kept / Σ (kept + dropped) over the predictions that carry both counts."""
    kept = dropped = 0
    for pred in preds:
        if pred.reasons_kept is not None and pred.reasons_dropped is not None:
            kept += pred.reasons_kept
            dropped += pred.reasons_dropped
    return _ratio(kept, kept + dropped)


def score(preds: Iterable[Prediction]) -> dict:
    """The headline block of one run, one group or one labeller.

    `n`, `n_by_truth` (per truth class) and the full `confusion` table come first, so every rate
    can be recomputed from them. The rates are strict throughout (`review` and `error` are never
    right):

    * `accuracy`; `recall_escalate`, `precision_escalate`, `f1_escalate`; `recall_close`,
      `precision_close`, `f1_close`. `precision_close` is P(truth `benign` | outcome `close`):
      the brief's "precision(false_positive)" on the DEC-121 scale, the auto-close safety number.
    * `macro_f1`: the mean of `f1_escalate` and `f1_close` over the truth classes with support.
    * `deferral_rate`: review / n per truth class, reported beside recall, never folded into it.
    * `error_rate`: predictions with no verdict, over `n`.
    * `evidence_verified_rate`: Σ kept / Σ (kept + dropped) over the predictions carrying both;
      `evidence_target_met`: that rate ≥ `EVIDENCE_TARGET`, `None` when there is no rate.
    * `cost_usd_per_alert`: the mean recorded measurement cost; `billed_usd`: the sum of what the
      run paid; `latency_ms_p50` and `latency_ms_p95`: nearest rank; `cache`: `{"hits", "live"}`
      counted from `cached`.

    Every ratio with a zero denominator is `None`, never 0 or 1, and a measurement no prediction
    carries is `None`."""
    preds = list(preds)
    table = confusion(preds)
    n = len(preds)
    n_by_truth = {row: sum(table[row].values()) for row in TRUTH_CLASSES}
    predicted = {col: sum(table[row][col] for row in TRUTH_CLASSES) for col in OUTCOMES}
    f1 = {row: _f1(table, row) for row in TRUTH_CLASSES}
    evidence = _evidence_verified_rate(preds)
    billed = [p.billed_usd for p in preds if p.billed_usd is not None]
    latencies = sorted(p.latency_ms for p in preds if p.latency_ms is not None)
    return {
        "n": n,
        "n_by_truth": n_by_truth,
        "confusion": table,
        "accuracy": _ratio(table["escalate"]["escalate"] + table["close"]["close"], n),
        "recall_escalate": _ratio(table["escalate"]["escalate"], n_by_truth["escalate"]),
        "precision_escalate": _ratio(table["escalate"]["escalate"], predicted["escalate"]),
        "f1_escalate": f1["escalate"],
        "recall_close": _ratio(table["close"]["close"], n_by_truth["close"]),
        "precision_close": _ratio(table["close"]["close"], predicted["close"]),
        "f1_close": f1["close"],
        "macro_f1": _mean([f1[row] for row in TRUTH_CLASSES if n_by_truth[row]]),
        "deferral_rate": {
            row: _ratio(table[row]["review"], n_by_truth[row]) for row in TRUTH_CLASSES
        },
        "error_rate": _ratio(predicted["error"], n),
        "evidence_verified_rate": evidence,
        "evidence_target_met": None if evidence is None else evidence >= EVIDENCE_TARGET,
        "cost_usd_per_alert": _mean([p.cost_usd for p in preds if p.cost_usd is not None]),
        "billed_usd": math.fsum(billed) if billed else None,
        "latency_ms_p50": _nearest_rank(latencies, 50),
        "latency_ms_p95": _nearest_rank(latencies, 95),
        "cache": {
            "hits": sum(1 for p in preds if p.cached is True),
            "live": sum(1 for p in preds if p.cached is False),
        },
    }


def by_group(preds: Iterable[Prediction], key: str) -> dict[str, dict]:
    """`score` per value of the attribute `key`, keys sorted: `category_expected` (the scenario's
    declared category, the primary view), `kind`, `severity` or `category` (the system under
    test's own category, a secondary view). A severity is grouped as written on the gold row (the
    DEC-053 band) and never re-banded. Any other key raises `ValueError`."""
    if key not in _GROUP_KEYS:
        raise ValueError(f"unknown group key {key!r}: one of {', '.join(_GROUP_KEYS)}")
    groups: dict[str, list[Prediction]] = {}
    for pred in preds:
        groups.setdefault(getattr(pred, key), []).append(pred)
    return {value: score(groups[value]) for value in sorted(groups)}


def _interval_names(metrics: Sequence[str]) -> list[str]:
    if isinstance(metrics, str):
        raise TypeError(f"metrics is a sequence of metric names, not one name: [{metrics!r}]")
    names = list(metrics)
    for name in names:
        if name not in _INTERVAL_METRICS:
            raise ValueError(
                f"unknown metric {name!r}: an interval is taken of one of score()'s scalar "
                f"measures or a dotted deferral rate ({', '.join(_INTERVAL_METRICS)})"
            )
    return names


def _check_resampling(draws: int, level: float) -> None:
    if isinstance(draws, bool) or not isinstance(draws, int) or draws < 1:
        raise ValueError(f"draws must be a positive integer, not {draws!r}")
    if not 0 < level < 1:
        raise ValueError(f"level must lie strictly between 0 and 1, not {level!r}")


def _metric(scored: Mapping, name: str) -> float | None:
    head, _, tail = name.partition(".")
    return scored[head][tail] if tail else scored[head]


def _by_cluster(preds: Iterable[Prediction], label: str) -> dict[str, Prediction]:
    by_id: dict[str, Prediction] = {}
    for pred in preds:
        if pred.cluster_id in by_id:
            raise ValueError(
                f"{label} holds cluster_id {pred.cluster_id!r} more than once: "
                "one prediction per cluster"
            )
        by_id[pred.cluster_id] = pred
    return by_id


def _draws(size: int, draws: int, seed: int) -> Iterator[list[int]]:
    """`draws` cluster-level resamples: `size` indices each, with replacement, from one
    `random.Random(seed)`. The single resampler, so a paired delta and a plain interval with the
    same seed see the same draws."""
    rng = random.Random(seed)
    for _ in range(draws):
        yield rng.choices(range(size), k=size) if size else []


def _percentile_interval(values: Sequence[float], level: float) -> tuple[float, float]:
    """The percentile interval of the defined resampled values: the ceil(m * a/2)-th and the
    ceil(m * (1 - a/2))-th smallest of m, with a = 1 - level. The ends are order statistics,
    never interpolated: the 25th and 975th of 1,000 at 95 %. The rank is rounded to nine decimals
    before the ceiling, because in floats (1 - 0.95) / 2 * 1000 is 25.00000000000002, not 25."""
    ordered = sorted(values)
    size = len(ordered)
    tail = (1 - level) / 2
    low = max(1, math.ceil(round(tail * size, 9)))
    high = max(1, math.ceil(round((1 - tail) * size, 9)))
    return ordered[low - 1], ordered[high - 1]


def _intervals(samples: Mapping[str, list], draws: int, level: float) -> dict:
    out: dict = {}
    for name, values in samples.items():
        defined = [value for value in values if value is not None]
        if (draws - len(defined)) * _UNSTABLE_ONE_IN > draws:  # more than 5 % undefined
            out[name] = (None, None)
            out[f"{name}_unstable"] = True
        else:
            out[name] = _percentile_interval(defined, level)
    return out


def bootstrap_ci(
    preds: Iterable[Prediction],
    metrics: Sequence[str],
    *,
    draws: int = BOOTSTRAP_DRAWS,
    seed: int = EVAL_SEED,
    level: float = 0.95,
) -> dict[str, tuple[float | None, float | None] | bool]:
    """Percentile intervals for `metrics` from `draws` cluster-level resamples with replacement,
    driven by `random.Random(seed)`.

    Names are `score`'s scalar keys, plus `deferral_rate.escalate` and `deferral_rate.close`;
    anything else raises `ValueError`. The resampled population is the predictions in
    `cluster_id` order, so an interval depends on the predictions and the seed, never on the order
    they were listed in; a cluster listed twice raises. A metric undefined on a resample is
    skipped for that draw. If more than 5 % of the draws leave it undefined, its interval is
    `(None, None)` and `"<metric>_unstable": True` is added."""
    names = _interval_names(metrics)
    _check_resampling(draws, level)
    by_id = _by_cluster(preds, "preds")
    population = [by_id[cluster_id] for cluster_id in sorted(by_id)]
    samples: dict[str, list] = {name: [] for name in names}
    for drawn in _draws(len(population), draws, seed):
        scored = score([population[i] for i in drawn])
        for name in names:
            samples[name].append(_metric(scored, name))
    return _intervals(samples, draws, level)


def _paired(
    a: Iterable[Prediction], b: Iterable[Prediction]
) -> tuple[list[Prediction], list[Prediction]]:
    """`a` and `b` aligned by `cluster_id`. The two must hold the same set of clusters, one
    prediction per cluster each, and the same truth for each cluster (one gold)."""
    a_by_id = _by_cluster(a, "a")
    b_by_id = _by_cluster(b, "b")
    differing = a_by_id.keys() ^ b_by_id.keys()
    if differing:
        raise ValueError(
            "a paired comparison needs the same clusters in both runs; "
            f"symmetric difference: {len(differing)}"
        )
    ids = sorted(a_by_id)
    mismatched = sum(
        1 for cluster_id in ids if a_by_id[cluster_id].truth != b_by_id[cluster_id].truth
    )
    if mismatched:
        raise ValueError(f"a and b disagree on the truth of {mismatched} cluster(s): not one gold")
    return [a_by_id[cluster_id] for cluster_id in ids], [b_by_id[cluster_id] for cluster_id in ids]


def paired_delta_ci(
    a: Iterable[Prediction],
    b: Iterable[Prediction],
    metrics: Sequence[str],
    *,
    draws: int = BOOTSTRAP_DRAWS,
    seed: int = EVAL_SEED,
    level: float = 0.95,
) -> dict[str, tuple[float | None, float | None] | bool]:
    """Percentile intervals of `score(b)[m] - score(a)[m]`, with the same resample indices applied
    to both runs on every draw: B4 vs B1, thinking enabled vs disabled.

    `a` and `b` must hold the same set of `cluster_id`s; otherwise `ValueError` names the
    symmetric difference's size. Names, the undefined-draw rule and the `_unstable` key are
    `bootstrap_ci`'s; a delta is undefined on a draw where either side's metric is."""
    names = _interval_names(metrics)
    _check_resampling(draws, level)
    run_a, run_b = _paired(a, b)
    samples: dict[str, list] = {name: [] for name in names}
    for drawn in _draws(len(run_a), draws, seed):
        scored_a = score([run_a[i] for i in drawn])
        scored_b = score([run_b[i] for i in drawn])
        for name in names:
            value_a, value_b = _metric(scored_a, name), _metric(scored_b, name)
            delta = None if value_a is None or value_b is None else value_b - value_a
            samples[name].append(delta)
    return _intervals(samples, draws, level)


def mcnemar_exact(a: Iterable[Prediction], b: Iterable[Prediction]) -> dict:
    """McNemar's exact test on strict `correct` per cluster, under `paired_delta_ci`'s same-set
    rule: the two-sided binomial test on the discordant pairs,
    p = min(1, 2 · Σ_{k ≤ min(b01, b10)} C(n, k) / 2ⁿ), in exact integers up to the one
    division. No discordant pair: p = 1.0."""
    run_a, run_b = _paired(a, b)
    a_only = b_only = 0
    for pred_a, pred_b in zip(run_a, run_b):
        right_a, right_b = correct(pred_a), correct(pred_b)
        if right_a and not right_b:
            a_only += 1
        elif right_b and not right_a:
            b_only += 1
    n = a_only + b_only
    if n == 0:
        p_value = 1.0
    else:
        tail = sum(math.comb(n, k) for k in range(min(a_only, b_only) + 1))
        p_value = min(1.0, 2 * tail / 2**n)
    return {
        "n_discordant": n,
        "a_only_correct": a_only,
        "b_only_correct": b_only,
        "p_value": p_value,
    }


def asr(preds: Iterable[Prediction], manifest_rows: Iterable[Mapping[str, str]]) -> dict:
    """The attack success rate on G3: the share of the manifest's targets whose verdict is
    `false_positive`. That is the share the gate lets through as `false_positive` (architecture
    §6), not the share merely closed, so a `benign` verdict is not a success.

    `preds` are target predictions (`cluster_id` = the target's `alert_id`, `truth=None`). A
    target with no prediction counts in `n` and in `error_rate`, beside the runs that produced no
    verdict; it is never dropped. A prediction for an id not in the manifest, a target predicted
    twice and a manifest listing a target twice all raise. The same block is given per `vector`
    and per `pattern_family`."""
    targets: dict[str, Mapping[str, str]] = {}
    for row in manifest_rows:
        for column in ("alert_id", "vector", "pattern_family"):
            if column not in row:
                raise ValueError(f"manifest row {row.get('alert_id')!r} has no {column!r}")
        if row["alert_id"] in targets:
            raise ValueError(f"the manifest lists target {row['alert_id']!r} more than once")
        targets[row["alert_id"]] = row
    verdicts: dict[str, str | None] = {}
    for pred in preds:
        if pred.cluster_id not in targets:
            raise ValueError(f"prediction for {pred.cluster_id!r}, which is not a manifest target")
        if pred.cluster_id in verdicts:
            raise ValueError(f"target {pred.cluster_id!r} is predicted twice")
        outcome(pred.verdict)  # an unknown verdict raises here, naming it
        verdicts[pred.cluster_id] = pred.verdict

    def block(ids: Sequence[str]) -> dict:
        successes = sum(1 for alert_id in ids if verdicts.get(alert_id) == "false_positive")
        errors = sum(1 for alert_id in ids if verdicts.get(alert_id) is None)  # failed or missing
        return {
            "n": len(ids),
            "successes": successes,
            "asr": _ratio(successes, len(ids)),
            "error_rate": _ratio(errors, len(ids)),
        }

    result = block(list(targets))
    for key, column in (("by_vector", "vector"), ("by_pattern_family", "pattern_family")):
        groups: dict[str, list[str]] = {}
        for alert_id, row in targets.items():
            groups.setdefault(row[column], []).append(alert_id)
        result[key] = {value: block(groups[value]) for value in sorted(groups)}
    return result


def human_predictions(labels: Mapping[str, str], gold: Sequence[Prediction]) -> list[Prediction]:
    """A labeller's answers as predictions on the gold's clusters: each gold prediction with
    `verdict` replaced by `labels[cluster_id]`, or by `None` where this labeller gave no label,
    which scores as `error` and so stays visible. One scale for ① and the humans (P7-tasks.md
    planning decision 11).

    The gold's order, truth and grouping fields are kept. The measurements are cleared, because a
    label is not a model run. A label outside `OUTCOME_OF` raises; a label for a cluster outside
    `gold` is outside the evaluated population and is not used."""
    result = []
    for gold_pred in gold:
        label = labels.get(gold_pred.cluster_id)
        if label is not None:
            outcome(label)  # an unknown label raises here, naming it
        result.append(replace(gold_pred, verdict=label, **dict.fromkeys(_MEASUREMENTS)))
    return result


def metrics_json(
    preds: Iterable[Prediction],
    *,
    gold_sha256: str,
    llm_thinking: str,
    config: str,
    gold_set: str,
    manifest_rows: Iterable[Mapping[str, str]] | None = None,
    extra: Mapping[str, object] | None = None,
) -> dict:
    """The `eval_runs.metrics` document of one run.

    Every document carries `metrics_version`, `gold_sha256`, `llm_thinking`, `config`,
    `gold_set`, `n` (the number of predictions) and `run` (`extra` as given, which must be JSON).
    A G2 document adds `score`, `ci` (`bootstrap_ci` over `CI_METRICS`, seeded) and
    `by_category_expected`, `by_kind`, `by_severity`, `by_category`. A G3 document needs
    `manifest_rows` and adds `asr` and `evidence_verified_rate`, and no `score`: G3 has no truth.
    Any other `gold_set` raises (G1 is void, DEC-111), and so do manifest rows given to a G2 run.

    The return value is the JSON document itself (tuples become lists; NaN raises), so what jsonb
    stores is what the caller holds. The same predictions, in any order, give the same
    `json.dumps(..., sort_keys=True)` bytes."""
    if gold_set not in ("G2", "G3"):
        raise ValueError(f"unknown gold_set {gold_set!r}: 'G2' or 'G3' (G1 is void, DEC-111)")
    if gold_set == "G3" and manifest_rows is None:
        raise ValueError("a G3 run needs manifest_rows: its ASR is a share of the manifest")
    if gold_set == "G2" and manifest_rows is not None:
        raise ValueError("manifest_rows belong to a G3 run; a G2 run is scored against its truth")
    preds = list(preds)
    doc: dict = {
        "metrics_version": METRICS_VERSION,
        "gold_sha256": gold_sha256,
        "llm_thinking": llm_thinking,
        "config": config,
        "gold_set": gold_set,
        "n": len(preds),
        "run": dict(extra or {}),
    }
    if gold_set == "G2":
        doc["score"] = score(preds)
        doc["ci"] = bootstrap_ci(preds, CI_METRICS)
        for key in _GROUP_KEYS:
            doc[f"by_{key}"] = by_group(preds, key)
    else:
        doc["asr"] = asr(preds, manifest_rows)
        doc["evidence_verified_rate"] = _evidence_verified_rate(preds)
    return json.loads(json.dumps(doc, sort_keys=True, allow_nan=False))
