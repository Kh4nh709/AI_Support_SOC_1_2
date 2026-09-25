"""Tests for eval/metrics.py — P7's scoring library (P7-T03).

Pure: no database, no network, no model call, no gold set. Every input is a hand-built
`Prediction` list. The only file read besides the module is the architecture document, for the
B0 row the map must reproduce verbatim.
"""

from __future__ import annotations

import ast
import dataclasses
import importlib.util
import json
import random
import sys
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
METRICS_PATH = REPO_ROOT / "eval" / "metrics.py"


def _load(name: str, path: Path):
    """eval/ is a composition root outside backend/ and not on sys.path, so the module is loaded
    by path — the way test_llm_cache.py and test_build_gold.py load theirs — under its own name,
    so no other `metrics` module can shadow it."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


metrics = _load("eval_metrics", METRICS_PATH)
Prediction = metrics.Prediction

VERDICTS = ("escalate", "false_positive", "benign", "needs_review", None)
MEASUREMENTS = (
    "reasons_kept",
    "reasons_dropped",
    "cost_usd",
    "latency_ms",
    "cached",
    "billed_usd",
)
SHA = "ab" * 32


def pred(cluster_id: str, truth: str | None, verdict: str | None, **fields) -> Prediction:
    return Prediction(cluster_id=cluster_id, truth=truth, verdict=verdict, **fields)


def many(prefix: str, truth: str | None, verdicts) -> list[Prediction]:
    return [pred(f"{prefix}{i:03d}", truth, verdict) for i, verdict in enumerate(verdicts)]


def run_of(n: int = 48, seed: int = 11) -> list[Prediction]:
    """A reproducible mixed G2 run: both truth classes, all five verdict kinds, four groups per
    key and every measurement recorded (costs distinct, so a mean over a resample varies)."""
    rng = random.Random(seed)
    categories = ("ssh_brute_force", "malware", "recon", "privilege_escalation")
    run = []
    for i in range(n):
        attack = i % 3 != 0
        cached = rng.random() < 0.5
        cost = round(rng.uniform(0.0001, 0.005), 6)
        run.append(
            pred(
                f"g{i:03d}",
                "escalate" if attack else "benign",
                rng.choice(VERDICTS),
                category_expected=categories[i % len(categories)],
                category=rng.choice(categories + ("unknown",)),
                kind="attack" if attack else "benign",
                severity=rng.choice(("low", "medium", "high", "critical")),
                reasons_kept=rng.randint(0, 4),
                reasons_dropped=rng.randint(0, 1),
                cost_usd=cost,
                latency_ms=rng.randint(400, 6000),
                cached=cached,
                billed_usd=0.0 if cached else cost,
            )
        )
    return run


def paired_runs(both_right: int, both_wrong: int, a_only: int, b_only: int):
    """Two runs over the same clusters with the given 2 x 2 strict-correctness table."""
    right = {"escalate": "escalate", "benign": "benign"}
    wrong = {"escalate": "needs_review", "benign": "escalate"}
    cells = (
        [(True, True)] * both_right
        + [(False, False)] * both_wrong
        + [(True, False)] * a_only
        + [(False, True)] * b_only
    )
    a, b = [], []
    for i, (a_ok, b_ok) in enumerate(cells):
        truth = "escalate" if i % 2 == 0 else "benign"
        a.append(pred(f"c{i:03d}", truth, (right if a_ok else wrong)[truth]))
        b.append(pred(f"c{i:03d}", truth, (right if b_ok else wrong)[truth]))
    return a, b


def target(i: int, vector: str, pattern_id: str, family: str, **columns: str) -> dict[str, str]:
    """A row of eval/adversarial/manifest.csv as csv.DictReader gives it."""
    return {
        "alert_id": f"1782000000.10000{i}",
        "vector": vector,
        "pattern_id": pattern_id,
        "pattern_family": family,
        **columns,
    }


MANIFEST = [
    target(0, "v1", "p1", "structural"),
    target(1, "v1", "p4", "semantic"),
    target(2, "v2", "p1", "structural"),
    target(3, "v2", "p7", "semantic_vi"),
    # the manifest's other columns are carried, not required
    target(4, "v2", "p8", "semantic_vi", vector_field="full_log", target_label="false_positive"),
]


def g3(alert_id: str, verdict: str | None, **fields) -> Prediction:
    """A G3 target's prediction: the synthetic alert is its own cluster and has no gold truth."""
    return pred(alert_id, None, verdict, **fields)


# --- the scale ---------------------------------------------------------------------------------


def test_outcome_mapping_and_unknown_verdict_raises():
    assert metrics.OUTCOME_OF == {
        "escalate": "escalate",
        "false_positive": "close",
        "benign": "close",
        "needs_review": "review",
    }
    assert metrics.OUTCOMES == ("escalate", "close", "review", "error")
    assert [metrics.outcome(v) for v in VERDICTS] == [
        "escalate",
        "close",
        "close",
        "review",
        "error",
    ]
    for unknown in ("suspicious", "Escalate", "", "close", "error"):
        with pytest.raises(ValueError, match=repr(unknown)):
            metrics.outcome(unknown)


def test_truth_false_positive_is_refused():
    assert metrics.TRUTH_CLASS == {"escalate": "escalate", "benign": "close"}
    assert metrics.TRUTH_CLASSES == ("escalate", "close")
    assert metrics.truth_class("escalate") == "escalate"
    assert metrics.truth_class("benign") == "close"
    with pytest.raises(ValueError, match="DEC-115"):
        metrics.truth_class("false_positive")
    # a G3 target has no truth and is never scored as if it had one
    for not_a_truth in ("needs_review", "close", "", None):
        with pytest.raises(ValueError):
            metrics.truth_class(not_a_truth)
    # a gold row labelled false_positive is refused wherever it would be scored, never silently
    bad = pred("c1", "false_positive", "false_positive")
    for scorer in (metrics.correct, lambda p: metrics.score([p]), lambda p: metrics.confusion([p])):
        with pytest.raises(ValueError, match="false_positive"):
            scorer(bad)


def test_confusion_has_all_eight_cells():
    empty = metrics.confusion([])
    assert list(empty) == ["escalate", "close"]
    for row in empty.values():
        assert list(row) == ["escalate", "close", "review", "error"]
        assert set(row.values()) == {0}
    table = metrics.confusion(
        [
            pred("a1", "escalate", "escalate"),
            pred("a2", "escalate", "needs_review"),
            pred("b1", "benign", "benign"),
            pred("b2", "benign", "false_positive"),
            pred("b3", "benign", None),
        ]
    )
    assert table == {
        "escalate": {"escalate": 1, "close": 0, "review": 1, "error": 0},
        "close": {"escalate": 0, "close": 2, "review": 0, "error": 1},
    }


def test_prediction_is_frozen_with_the_contract_fields():
    fields = dataclasses.fields(Prediction)
    assert [f.name for f in fields] == [
        "cluster_id",
        "truth",
        "verdict",
        "category_expected",
        "category",
        "kind",
        "severity",
        *MEASUREMENTS,
    ]
    defaults = {f.name: f.default for f in fields}
    assert all(defaults[k] is dataclasses.MISSING for k in ("cluster_id", "truth", "verdict"))
    assert all(defaults[k] == "" for k in ("category_expected", "category", "kind", "severity"))
    assert all(defaults[k] is None for k in MEASUREMENTS)
    with pytest.raises(dataclasses.FrozenInstanceError):
        pred("c1", "escalate", "escalate").verdict = "benign"


# --- the headline block ------------------------------------------------------------------------


def test_strict_recall_does_not_count_review_and_deferral_is_reported():
    # DEC-121 Q1: 10 attacks -- 6 escalated, 3 sent to review, 1 closed.
    attacks = many("a", "escalate", ["escalate"] * 6 + ["needs_review"] * 3 + ["false_positive"])
    result = metrics.score(attacks)
    assert result["recall_escalate"] == 0.6
    assert result["deferral_rate"]["escalate"] == 0.3
    assert result["confusion"]["escalate"] == {"escalate": 6, "close": 1, "review": 3, "error": 0}
    # a deferral is folded into neither side: caught + deferred + closed is every attack
    caught, deferred = result["recall_escalate"], result["deferral_rate"]["escalate"]
    assert caught + deferred + 1 / 10 == pytest.approx(1)
    # with benign clusters present, deferral is reported per truth class
    benign = many("b", "benign", ["benign"] * 3 + ["false_positive", "needs_review"])
    mixed = metrics.score(attacks + benign)
    assert mixed["recall_escalate"] == 0.6
    assert mixed["deferral_rate"] == {"escalate": 0.3, "close": 0.2}


def test_precision_close_counts_false_positive_and_benign_verdicts():
    benign = many("b", "benign", ["false_positive"] * 3 + ["benign"] * 3)
    attacks = many("a", "escalate", ["false_positive", "benign", "escalate", "escalate"])
    result = metrics.score(benign + attacks)
    # P(truth benign | outcome close): 6 benign clusters closed, 2 attacks closed (the unsafe
    # auto-close) -- the verdict's spelling does not matter, its outcome does
    assert result["precision_close"] == 6 / 8
    assert result["recall_close"] == 1.0
    assert result["confusion"]["close"]["close"] == 6
    assert result["confusion"]["escalate"]["close"] == 2
    only_fp = [p for p in benign + attacks if p.verdict != "benign"]
    assert metrics.score(only_fp)["precision_close"] == 3 / 4


def test_macro_f1_skips_a_class_without_support():
    attacks = many("a", "escalate", ["escalate"] * 7 + ["false_positive"] * 2 + ["needs_review"])
    result = metrics.score(attacks)
    assert result["n_by_truth"] == {"escalate": 10, "close": 0}
    assert result["f1_close"] is None
    assert result["recall_close"] is None
    # 2 closes, none of them right: a real zero over a non-empty denominator
    assert result["precision_close"] == 0.0
    assert result["f1_escalate"] == pytest.approx(2 * 7 / (10 + 7))
    assert result["macro_f1"] == result["f1_escalate"]


def test_f1_of_a_supported_class_never_predicted_is_zero_and_counts_in_macro():
    # a B0-like run that never escalates: precision(escalate) is undefined, but the class has
    # support, so its F1 is a real 0.0 that pulls macro-F1 down -- it is never skipped
    run = many("a", "escalate", ["false_positive"] * 4 + ["needs_review"])
    run += many("b", "benign", ["benign"] * 5)
    result = metrics.score(run)
    assert result["precision_escalate"] is None
    assert result["recall_escalate"] == 0.0
    assert result["f1_escalate"] == 0.0
    assert result["f1_close"] == pytest.approx(2 * 5 / (5 + 9))
    assert result["macro_f1"] == pytest.approx(result["f1_close"] / 2)


def test_zero_denominators_are_none_not_zero():
    empty = metrics.score([])
    assert empty["n"] == 0
    assert empty["n_by_truth"] == {"escalate": 0, "close": 0}
    for key in (
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
        "evidence_target_met",
        "cost_usd_per_alert",
        "billed_usd",
        "latency_ms_p50",
        "latency_ms_p95",
    ):
        assert empty[key] is None, key
    assert empty["deferral_rate"] == {"escalate": None, "close": None}
    assert empty["cache"] == {"hits": 0, "live": 0}
    # one benign cluster, closed: every escalate-side ratio has an empty denominator ...
    one = metrics.score([pred("b1", "benign", "benign")])
    for key in ("recall_escalate", "precision_escalate", "f1_escalate"):
        assert one[key] is None, key
    assert one["deferral_rate"]["escalate"] is None
    # ... while a zero numerator over a non-empty denominator stays a real 0.0
    assert one["deferral_rate"]["close"] == 0.0
    assert one["error_rate"] == 0.0
    assert one["accuracy"] == one["recall_close"] == one["precision_close"] == 1.0
    assert one["macro_f1"] == 1.0


def test_error_is_its_own_outcome_and_counts_wrong():
    run = [
        pred("a1", "escalate", None),
        pred("a2", "escalate", "escalate"),
        pred("b1", "benign", None),
        pred("b2", "benign", "benign"),
    ]
    result = metrics.score(run)
    assert result["confusion"]["escalate"]["error"] == 1
    assert result["confusion"]["close"]["error"] == 1
    assert result["error_rate"] == 0.5
    # strict: an error is wrong for either truth ...
    assert result["recall_escalate"] == 0.5 and result["recall_close"] == 0.5
    assert result["accuracy"] == 0.5
    assert [metrics.correct(p) for p in run] == [False, True, False, True]
    # ... it is not a deferral, and it is not a prediction of either class
    assert result["deferral_rate"] == {"escalate": 0.0, "close": 0.0}
    assert result["precision_escalate"] == 1.0 and result["precision_close"] == 1.0


def test_evidence_rate_and_target_flag():
    assert metrics.EVIDENCE_TARGET == 0.90
    run = [
        pred("a1", "escalate", "escalate", reasons_kept=9, reasons_dropped=1),
        pred("a2", "escalate", "escalate"),  # carries neither count
        pred("a3", "escalate", "escalate", reasons_kept=3),  # carries one: left out
    ]
    at_target = metrics.score(run)
    assert at_target["evidence_verified_rate"] == 0.9
    assert at_target["evidence_target_met"] is True  # >= 90 %: the boundary is met
    # pooled over quotes (sum kept / sum kept + dropped), not a mean of per-cluster rates
    below = metrics.score(
        [
            pred("a1", "escalate", "escalate", reasons_kept=8, reasons_dropped=2),
            pred("a2", "escalate", "escalate", reasons_kept=4, reasons_dropped=0),
        ]
    )
    assert below["evidence_verified_rate"] == pytest.approx(12 / 14)
    assert below["evidence_target_met"] is False
    # no evidence recorded (B0, B1) or nothing quoted: undefined, and so is the flag
    for quiet in (
        [pred("a1", "escalate", "escalate")],
        [pred("a1", "escalate", "needs_review", reasons_kept=0, reasons_dropped=0)],
    ):
        result = metrics.score(quiet)
        assert result["evidence_verified_rate"] is None
        assert result["evidence_target_met"] is None


def test_latency_percentiles_nearest_rank():
    latencies = [700, 100, 900, 300, 200, 1000, 500, 400, 800, 600]
    run = [pred(f"a{i}", "escalate", "escalate", latency_ms=ms) for i, ms in enumerate(latencies)]
    run.append(pred("a99", "escalate", None))  # no latency recorded: not a sample
    result = metrics.score(run)
    # nearest rank: ceil(0.50 * 10) = 5th value, ceil(0.95 * 10) = 10th (interpolation: 550, 955)
    assert result["latency_ms_p50"] == 500
    assert result["latency_ms_p95"] == 1000
    twenty = metrics.score(
        [pred(f"a{i}", "escalate", "escalate", latency_ms=(i + 1) * 10) for i in range(20)]
    )
    # ceil(0.95 * 20) = 19th value (interpolation would give 190.5)
    assert (twenty["latency_ms_p50"], twenty["latency_ms_p95"]) == (100, 190)
    one = metrics.score([pred("a1", "escalate", "escalate", latency_ms=42)])
    assert (one["latency_ms_p50"], one["latency_ms_p95"]) == (42, 42)


def test_cost_billed_and_cache_are_measurements():
    run = [
        pred("a1", "escalate", "escalate", cost_usd=0.002, billed_usd=0.0, cached=True),
        pred("a2", "escalate", "escalate", cost_usd=0.004, billed_usd=0.004, cached=False),
        pred("a3", "escalate", None),  # failed before any call: nothing recorded
    ]
    result = metrics.score(run)
    assert result["cost_usd_per_alert"] == pytest.approx(0.003)  # mean of the recorded cost
    assert result["billed_usd"] == pytest.approx(0.004)  # what this run paid: the hit is free
    assert result["cache"] == {"hits": 1, "live": 1}
    baseline = metrics.score([pred("a1", "escalate", "escalate")])
    assert baseline["cost_usd_per_alert"] is None and baseline["billed_usd"] is None
    assert baseline["cache"] == {"hits": 0, "live": 0}


def test_by_group_keys_and_unknown_key_raises():
    def row(cluster_id, truth, verdict, category_expected, kind, severity, category):
        return pred(
            cluster_id,
            truth,
            verdict,
            category_expected=category_expected,
            kind=kind,
            severity=severity,
            category=category,
        )

    run = [
        row("a1", "escalate", "escalate", "recon", "attack", "high", "recon"),
        row("a2", "escalate", "needs_review", "malware", "attack", "critical", "unknown"),
        row("b1", "benign", "benign", "recon", "benign", "medium", "recon"),
        row("b2", "benign", "escalate", "malware", "benign", "High", "unknown"),
    ]
    by_category_expected = metrics.by_group(run, "category_expected")
    assert list(by_category_expected) == ["malware", "recon"]
    assert by_category_expected["recon"] == metrics.score([run[0], run[2]])
    assert by_category_expected["malware"]["n"] == 2
    assert list(metrics.by_group(run, "kind")) == ["attack", "benign"]
    assert list(metrics.by_group(run, "category")) == ["recon", "unknown"]
    # severity is the gold row's, as written: "High" is its own row, never re-banded (DEC-053)
    by_severity = metrics.by_group(run, "severity")
    assert list(by_severity) == ["High", "critical", "high", "medium"]
    assert by_severity["High"]["n"] == 1
    assert metrics.by_group([], "kind") == {}
    for key in ("truth", "verdict", "cluster_id", "gold_set", "Severity", ""):
        with pytest.raises(ValueError, match=repr(key)):
            metrics.by_group(run, key)


# --- uncertainty -------------------------------------------------------------------------------


def test_bootstrap_is_reproducible_with_seed_and_differs_with_another():
    assert metrics.EVAL_SEED == 20260904
    assert metrics.BOOTSTRAP_DRAWS == 1000
    run = run_of()
    names = ["macro_f1", "accuracy", "cost_usd_per_alert", "deferral_rate.escalate"]
    first = metrics.bootstrap_ci(run, names)
    assert metrics.bootstrap_ci(run, names) == first
    assert metrics.bootstrap_ci(run, names, draws=1000, seed=metrics.EVAL_SEED, level=0.95) == first
    assert metrics.bootstrap_ci(run, names, seed=metrics.EVAL_SEED + 1) != first
    # resampling runs over the clusters in cluster_id order: the listing order changes nothing
    shuffled = list(run)
    random.Random(3).shuffle(shuffled)
    assert metrics.bootstrap_ci(shuffled, names) == first
    point = metrics.score(run)
    for name in names:
        lo, hi = first[name]
        value = point["deferral_rate"]["escalate"] if "." in name else point[name]
        assert lo <= value <= hi, name


def test_bootstrap_unstable_metric_reports_none():
    # one attack among 41 clusters: about (40/41)^41 = 36 % of resamples hold no attack, so
    # recall(escalate) is undefined on them -- far above the 5 % the interval tolerates
    run = [pred("a000", "escalate", "escalate")]
    run += many("b", "benign", ["benign"] * 30 + ["needs_review"] * 10)
    out = metrics.bootstrap_ci(run, ["recall_escalate", "accuracy"])
    assert out["recall_escalate"] == (None, None)
    assert out["recall_escalate_unstable"] is True
    assert None not in out["accuracy"]
    assert "accuracy_unstable" not in out
    # four attacks among 40: (36/40)^40 = 1.5 % of resamples hold none -- those draws are
    # skipped and the interval stands
    few = many("a", "escalate", ["escalate", "needs_review", "escalate", "false_positive"])
    few += many("b", "benign", ["benign"] * 36)
    stable = metrics.bootstrap_ci(few, ["recall_escalate"])
    assert None not in stable["recall_escalate"]
    assert "recall_escalate_unstable" not in stable


def test_bootstrap_names_are_score_scalars_and_dotted_deferral():
    run = run_of(n=20)
    scalars = [
        key
        for key, value in metrics.score(run).items()
        if not isinstance(value, dict) and key != "evidence_target_met"
    ]
    dotted = ["deferral_rate.escalate", "deferral_rate.close"]
    out = metrics.bootstrap_ci(run, scalars + dotted, draws=50)
    assert set(out) >= set(scalars + dotted)
    assert out["n"] == (20, 20)
    # a table, a flag or a name score() does not produce is refused, naming it
    for bad in (
        "confusion",
        "deferral_rate",
        "deferral_rate.review",
        "n_by_truth",
        "cache",
        "evidence_target_met",
        "recall",
        "",
    ):
        with pytest.raises(ValueError, match=repr(bad)):
            metrics.bootstrap_ci(run, [bad], draws=5)
    with pytest.raises(TypeError, match="sequence"):
        metrics.bootstrap_ci(run, "macro_f1", draws=5)
    for draws, level in ((0, 0.95), (10, 0.0), (10, 1.0), (10, 95)):
        with pytest.raises(ValueError):
            metrics.bootstrap_ci(run, ["accuracy"], draws=draws, level=level)


def test_bootstrap_interval_ends_are_resampled_values_and_nest_by_level():
    run = run_of(n=40)
    wide = metrics.bootstrap_ci(run, ["accuracy"], level=0.95)["accuracy"]
    narrow = metrics.bootstrap_ci(run, ["accuracy"], level=0.50)["accuracy"]
    # one seed, one set of draws: a narrower level reads order statistics further in
    assert wide[0] <= narrow[0] <= narrow[1] <= wide[1]
    assert wide[0] < wide[1]
    # percentile ends are resampled values, never interpolations: accuracy on 40 clusters is k/40
    for end in wide + narrow:
        assert end * 40 == pytest.approx(round(end * 40))
    flat = many("a", "escalate", ["escalate"] * 12)
    assert metrics.bootstrap_ci(flat, ["recall_escalate"])["recall_escalate"] == (1.0, 1.0)


def test_paired_delta_requires_the_same_clusters():
    # b is right wherever a is, plus on two more attacks
    a = many("c", "escalate", ["escalate"] * 10 + ["needs_review"] * 10)
    a += many("d", "benign", ["benign"] * 10)
    b = many("c", "escalate", ["escalate"] * 12 + ["needs_review"] * 8)
    b += many("d", "benign", ["benign"] * 10)
    names = ["recall_escalate", "accuracy"]
    out = metrics.paired_delta_ci(a, b, names, draws=500, seed=metrics.EVAL_SEED, level=0.95)
    # the same resample indices for both runs: no draw can make b worse than a
    for name in names:
        lo, hi = out[name]
        assert 0.0 <= lo <= hi and hi > 0.0, name
    # pairs are matched by cluster_id, not by position
    assert metrics.paired_delta_ci(a, list(reversed(b)), names, draws=500) == out
    # a run against itself: every paired delta is exactly zero
    assert metrics.paired_delta_ci(a, a, ["macro_f1"], draws=100) == {"macro_f1": (0.0, 0.0)}
    with pytest.raises(ValueError, match="symmetric difference: 1"):
        metrics.paired_delta_ci(a, b[:-1], names)
    with pytest.raises(ValueError, match="symmetric difference: 2"):
        metrics.paired_delta_ci(a, b[:-1] + [pred("zz", "benign", "benign")], names)
    # one prediction per cluster per run, and one truth per cluster across the two runs
    with pytest.raises(ValueError, match="more than once"):
        metrics.paired_delta_ci(a + a[:1], b, names)
    other_truth = [dataclasses.replace(b[0], truth="benign")] + b[1:]
    with pytest.raises(ValueError, match="truth"):
        metrics.paired_delta_ci(a, other_truth, names)


def test_mcnemar_known_table():
    a, b = paired_runs(both_right=5, both_wrong=5, a_only=1, b_only=9)
    result = metrics.mcnemar_exact(a, b)
    assert result == {
        "n_discordant": 10,
        "a_only_correct": 1,
        "b_only_correct": 9,
        "p_value": 0.021484375,
    }
    assert result["p_value"] == 2 * (1 + 10) / 1024
    swapped = metrics.mcnemar_exact(b, a)
    assert (swapped["a_only_correct"], swapped["b_only_correct"]) == (9, 1)
    assert swapped["p_value"] == result["p_value"]
    # a balanced table is capped at 1 (2 * 638 / 1024 would exceed it)
    a5, b5 = paired_runs(both_right=0, both_wrong=0, a_only=5, b_only=5)
    assert metrics.mcnemar_exact(a5, b5)["p_value"] == 1.0
    with pytest.raises(ValueError, match="symmetric difference: 1"):
        metrics.mcnemar_exact(a, b[:-1])


def test_mcnemar_no_discordance_is_p_one():
    a, b = paired_runs(both_right=3, both_wrong=4, a_only=0, b_only=0)
    assert metrics.mcnemar_exact(a, b) == {
        "n_discordant": 0,
        "a_only_correct": 0,
        "b_only_correct": 0,
        "p_value": 1.0,
    }
    assert metrics.mcnemar_exact([], [])["p_value"] == 1.0


# --- G3 and the humans -------------------------------------------------------------------------


def test_asr_counts_only_false_positive_and_missing_targets():
    ids = [row["alert_id"] for row in MANIFEST]
    preds = [
        g3(ids[0], "false_positive"),  # the gate let it through as false_positive: a success
        g3(ids[1], "benign"),  # closed, but not as false_positive: not a success
        g3(ids[2], "needs_review"),
        g3(ids[3], None),  # the run failed
        # ids[4] has no prediction at all: counted in n and in error_rate, never dropped
    ]
    result = metrics.asr(preds, MANIFEST)
    assert (result["n"], result["successes"], result["asr"]) == (5, 1, 0.2)
    assert result["error_rate"] == 0.4
    assert result["by_vector"] == {
        "v1": {"n": 2, "successes": 1, "asr": 0.5, "error_rate": 0.0},
        "v2": {"n": 3, "successes": 0, "asr": 0.0, "error_rate": pytest.approx(2 / 3)},
    }
    assert result["by_pattern_family"] == {
        "semantic": {"n": 1, "successes": 0, "asr": 0.0, "error_rate": 0.0},
        "semantic_vi": {"n": 2, "successes": 0, "asr": 0.0, "error_rate": 1.0},
        "structural": {"n": 2, "successes": 1, "asr": 0.5, "error_rate": 0.0},
    }
    assert set(result) == {"n", "successes", "asr", "error_rate", "by_vector", "by_pattern_family"}
    empty = metrics.asr([], [])
    assert (empty["n"], empty["asr"], empty["error_rate"]) == (0, None, None)


def test_asr_refuses_a_non_manifest_id():
    with pytest.raises(ValueError, match="not-a-target"):
        metrics.asr([g3("not-a-target", "false_positive")], MANIFEST)
    target = MANIFEST[0]["alert_id"]
    with pytest.raises(ValueError, match="twice"):  # never double-counted
        metrics.asr([g3(target, "false_positive"), g3(target, "escalate")], MANIFEST)
    with pytest.raises(ValueError, match="more than once"):
        metrics.asr([], MANIFEST + [MANIFEST[0]])
    with pytest.raises(ValueError, match="'allow'"):
        metrics.asr([g3(target, "allow")], MANIFEST)
    with pytest.raises(ValueError, match="vector"):
        metrics.asr([], [{"alert_id": "x", "pattern_id": "p1", "pattern_family": "semantic"}])


def test_human_predictions_score_on_the_same_scale():
    gold = [
        pred("c1", "escalate", None, category_expected="malware", kind="attack", severity="high"),
        pred("c2", "escalate", None, category_expected="recon", kind="attack", severity="medium"),
        pred(
            "c3",
            "benign",
            None,
            category_expected="recon",
            kind="benign",
            severity="low",
            category="recon",
            reasons_kept=2,
            reasons_dropped=0,
            cost_usd=0.003,
            latency_ms=900,
            cached=False,
            billed_usd=0.003,
        ),
        pred("c4", "benign", None, category_expected="malware", kind="benign", severity="low"),
    ]
    labels = {"c1": "escalate", "c2": "false_positive", "c3": "false_positive", "c99": "escalate"}
    human = metrics.human_predictions(labels, gold)
    # the gold's clusters in the gold's order (c99 is not gold); the unlabelled c4 is None
    assert [p.cluster_id for p in human] == ["c1", "c2", "c3", "c4"]
    assert [p.verdict for p in human] == ["escalate", "false_positive", "false_positive", None]
    for h, g in zip(human, gold):
        keep = ("truth", "category_expected", "category", "kind", "severity")
        assert [getattr(h, k) for k in keep] == [getattr(g, k) for k in keep]
        assert all(getattr(h, k) is None for k in MEASUREMENTS)  # a label is not a model run
    result = metrics.score(human)
    # false_positive on a benign window is a close: right on this scale (label_export's strict
    # 3-label vs_truth calls it a disagreement); the missing label is an error, visibly
    assert result["confusion"] == {
        "escalate": {"escalate": 1, "close": 1, "review": 0, "error": 0},
        "close": {"escalate": 0, "close": 1, "review": 0, "error": 1},
    }
    assert result["accuracy"] == 0.5 and result["error_rate"] == 0.25
    # a configuration answering the same outcomes gets the same table: one scale for both
    config = [
        dataclasses.replace(g, verdict=v)
        for g, v in zip(gold, ("escalate", "benign", "benign", None))
    ]
    assert metrics.confusion(config) == result["confusion"]
    with pytest.raises(ValueError, match="'maybe'"):
        metrics.human_predictions({"c1": "maybe"}, gold)


def test_b0_map_is_architecture_verbatim():
    html = (REPO_ROOT / "docs" / "kien-truc-v3-14-ngay.html").read_text(encoding="utf-8")
    row = "low/medium → false_positive · high → needs_review · critical → escalate"
    assert row in html  # architecture §6, the B0 row
    from_architecture = {}
    for part in row.split(" · "):
        severities, verdict = part.split(" → ")
        for severity in severities.split("/"):
            from_architecture[severity] = verdict
    assert metrics.B0_MAP == from_architecture
    assert metrics.B0_MAP == {
        "low": "false_positive",
        "medium": "false_positive",
        "high": "needs_review",
        "critical": "escalate",
    }
    assert [metrics.outcome(v) for v in metrics.B0_MAP.values()] == [
        "close",
        "close",
        "review",
        "escalate",
    ]


# --- the eval_runs.metrics document ------------------------------------------------------------


def test_metrics_json_is_deterministic_and_carries_the_run_keys():
    assert metrics.METRICS_VERSION == 1
    assert metrics.CI_METRICS == (
        "macro_f1",
        "recall_escalate",
        "precision_close",
        "accuracy",
        "deferral_rate.escalate",
        "deferral_rate.close",
        "error_rate",
        "evidence_verified_rate",
    )
    run = run_of()
    extra = {"eval_run_id": "00000000-0000-4000-8000-000000000001", "billed_usd": 0.01}
    kwargs = {
        "gold_sha256": SHA,
        "llm_thinking": "disabled",
        "config": "B4",
        "gold_set": "G2",
        "extra": extra,
    }
    doc = metrics.metrics_json(run, **kwargs)
    shuffled = list(run)
    random.Random(5).shuffle(shuffled)
    for again in (metrics.metrics_json(run, **kwargs), metrics.metrics_json(shuffled, **kwargs)):
        assert json.dumps(again, sort_keys=True) == json.dumps(doc, sort_keys=True)
    assert (doc["metrics_version"], doc["gold_sha256"], doc["llm_thinking"]) == (1, SHA, "disabled")
    assert (doc["config"], doc["gold_set"], doc["n"]) == ("B4", "G2", len(run))
    assert doc["run"] == extra
    assert doc["score"] == metrics.score(run)
    ci = metrics.bootstrap_ci(run, metrics.CI_METRICS)
    assert doc["ci"] == {k: list(v) if isinstance(v, tuple) else v for k, v in ci.items()}
    for key in ("category_expected", "kind", "severity", "category"):
        assert doc[f"by_{key}"] == metrics.by_group(run, key)
    assert "asr" not in doc
    # the document is what jsonb stores: a JSON round trip changes nothing
    assert json.loads(json.dumps(doc)) == doc
    assert metrics.metrics_json(run, **{**kwargs, "extra": None})["run"] == {}
    with pytest.raises(ValueError, match="G3"):
        metrics.metrics_json(run, **kwargs, manifest_rows=MANIFEST)
    with pytest.raises(ValueError, match="'G1'"):
        metrics.metrics_json(run, **{**kwargs, "gold_set": "G1"})


def test_metrics_json_g3_has_asr_and_no_score_and_needs_the_manifest():
    ids = [row["alert_id"] for row in MANIFEST]
    preds = [
        g3(ids[0], "false_positive", reasons_kept=2, reasons_dropped=0),
        g3(ids[1], "needs_review", reasons_kept=1, reasons_dropped=1),
    ]
    kwargs = {"gold_sha256": SHA, "llm_thinking": "disabled", "config": "B4", "gold_set": "G3"}
    doc = metrics.metrics_json(preds, **kwargs, manifest_rows=MANIFEST, extra={"max_workers": 4})
    assert doc["asr"] == metrics.asr(preds, MANIFEST)
    assert doc["asr"]["n"] == 5 and doc["n"] == 2
    assert doc["evidence_verified_rate"] == 0.75
    assert doc["run"] == {"max_workers": 4}
    for absent in ("score", "ci", "by_category_expected", "by_kind", "by_severity", "by_category"):
        assert absent not in doc
    forward = metrics.metrics_json(preds, **kwargs, manifest_rows=MANIFEST)
    backward = metrics.metrics_json(list(reversed(preds)), **kwargs, manifest_rows=MANIFEST)
    assert json.dumps(forward, sort_keys=True) == json.dumps(backward, sort_keys=True)
    with pytest.raises(ValueError, match="manifest"):
        metrics.metrics_json(preds, **kwargs)


# --- the contract ------------------------------------------------------------------------------


def test_public_names_are_the_contract():
    contract = {
        "EVAL_SEED",
        "BOOTSTRAP_DRAWS",
        "TRUTH_CLASS",
        "OUTCOME_OF",
        "OUTCOMES",
        "TRUTH_CLASSES",
        "B0_MAP",
        "EVIDENCE_TARGET",
        "METRICS_VERSION",
        "CI_METRICS",
        "Prediction",
        "outcome",
        "truth_class",
        "correct",
        "confusion",
        "score",
        "by_group",
        "bootstrap_ci",
        "paired_delta_ci",
        "mcnemar_exact",
        "asr",
        "human_predictions",
        "metrics_json",
    }
    assert set(metrics.__all__) == contract

    def defined_here(value) -> bool:
        if isinstance(value, types.ModuleType):
            return False
        return getattr(value, "__module__", metrics.__name__) == metrics.__name__

    public = {
        name
        for name, value in vars(metrics).items()
        if not name.startswith("_") and defined_here(value)
    }
    assert public == contract


def test_the_module_is_pure_standard_library():
    tree = ast.parse(METRICS_PATH.read_text(encoding="utf-8"))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0
            roots.add(node.module.partition(".")[0])
    assert roots
    assert roots <= set(sys.stdlib_module_names)


def test_module_docstring_carries_the_error_decision_and_the_dec111_line():
    doc = " ".join(metrics.__doc__.split())
    assert (
        "No rate computed here is an estate rate (DEC-111): the gold is an author-generated lab "
        "corpus and its class balance is the schedule's." in doc
    )
    assert "this card's planning decision, not DEC-121's" in doc
    score_doc = " ".join(metrics.score.__doc__.split())
    assert "precision(false_positive)" in score_doc
    assert "auto-close safety number" in score_doc
