"""Tests for eval/report.py — P7's report renderer (P7-T05).

The `render_*` functions are pure over their inputs: every fixture is a hand-built `Prediction`
list passed through `metrics.metrics_json` (P7-T03) and a results dict in P7-T04's shape (note 7).
No metric is recomputed here — only P7-T03's functions are called through `report`. One DB test
(`@pytest.mark.db`) covers `select_runs` (latest per key) and the missing-results exit 3.

eval/ is a composition root outside backend/ and not a package on sys.path; the module is loaded by
path, the way test_eval_metrics.py loads its own. `app.*` resolves through pytest's pythonpath.
"""

from __future__ import annotations

import builtins
import dataclasses
import importlib.util
import sys
import uuid
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
EVAL_DIR = REPO_ROOT / "eval"
sys.path.insert(0, str(EVAL_DIR))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


report = _load("eval_report", EVAL_DIR / "report.py")
import metrics  # the same module report imports; eval/ is on the path from above

SHA = "cd" * 32  # 64 hex
GOLD12 = SHA[:12]
Prediction = metrics.Prediction

# Pinned independently of report.CSV_COLUMNS, so adding a column to either the constant or the
# emitted header diverges from this literal (red step c).
EXPECTED_CSV_COLUMNS = (
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

EM_DASH = "—"
MINUS = "−"


def pred(cluster_id, truth, verdict, **fields):
    return Prediction(cluster_id=cluster_id, truth=truth, verdict=verdict, **fields)


def sample_g2(prefix: str) -> list:
    """A small G2 run touching both truth classes, all four outcomes (including a `None` verdict =
    error) and four of the eight lab categories, with the measurements a B2–B4 run records."""
    specs = [
        ("escalate", "escalate", "ssh_brute_force", "attack", "high"),
        ("escalate", "needs_review", "ssh_brute_force", "attack", "high"),
        ("escalate", "false_positive", "malware", "attack", "critical"),
        ("escalate", None, "recon", "attack", "medium"),
        ("benign", "benign", "ssh_brute_force", "benign", "low"),
        ("benign", "false_positive", "malware", "benign", "medium"),
        ("benign", "needs_review", "recon", "benign", "low"),
        ("benign", "escalate", "privilege_escalation", "benign", "high"),
    ]
    out = []
    for i, (truth, verdict, cat, kind, sev) in enumerate(specs):
        out.append(
            pred(
                f"{prefix}{i:02d}",
                truth,
                verdict,
                category_expected=cat,
                category=cat,
                kind=kind,
                severity=sev,
                reasons_kept=8,
                reasons_dropped=1,
                cost_usd=0.001 * (i + 1),
                latency_ms=100 + i,
                cached=(i % 2 == 0),
                billed_usd=0.0 if i % 2 == 0 else 0.001,
            )
        )
    return out


def revary(preds, changes: dict):
    """Same clusters, truth and groups; only the named verdicts changed (for a paired comparison)."""
    return [dataclasses.replace(p, verdict=changes.get(p.cluster_id, p.verdict)) for p in preds]


def results_dict(eval_run_id, config, thinking, preds, gold_set="G2", prompt_version="v1"):
    predictions = []
    for p in preds:
        row = dataclasses.asdict(p)
        row["alert_id"] = f"alert-{p.cluster_id}"
        row["outcome"] = "ok" if p.verdict is not None else "error"
        row["error"] = None if p.verdict is not None else "AdapterTimeout"
        predictions.append(row)
    return {
        "eval_run_id": eval_run_id,
        "gold_sha256": SHA,
        "gold_set": gold_set,
        "config": config,
        "llm_thinking": thinking,
        "prompt_version": prompt_version,
        "model_id": "deepseek-v4-flash",
        "predictions": predictions,
    }


def metrics_doc(config, thinking, preds, gold_set="G2", manifest_rows=None):
    return metrics.metrics_json(
        preds,
        gold_sha256=SHA,
        llm_thinking=thinking,
        config=config,
        gold_set=gold_set,
        manifest_rows=manifest_rows,
    )


def make_run(eval_run_id, config, thinking, preds, gold_set="G2", manifest_rows=None):
    md = metrics_doc(config, thinking, preds, gold_set=gold_set, manifest_rows=manifest_rows)
    res = results_dict(eval_run_id, config, thinking, preds, gold_set=gold_set)
    return report.build_run(res, md)


def g3_manifest():
    return [
        {"alert_id": "t1", "vector": "header", "pattern_family": "inject"},
        {"alert_id": "t2", "vector": "body", "pattern_family": "evade"},
        {"alert_id": "t3", "vector": "header", "pattern_family": "inject"},
    ]


def g3_preds():
    return [
        pred("t1", None, "false_positive", category="web_attack", kind="adversarial"),
        pred("t2", None, "escalate", category="web_attack", kind="adversarial"),
        pred("t3", None, "needs_review", category="web_attack", kind="adversarial"),
    ]


def full_run_set():
    """B0/B1/B2/B3, the paired B4 disabled/enabled, and two G3 runs — all over one shared cluster
    base, so every pairing (B4 vs B1, thinking pair) is well-formed."""
    base = sample_g2("a")
    b4_off = revary(base, {"a01": "escalate"})
    b4_on = revary(base, {"a01": "escalate", "a06": "benign", "a02": "escalate"})
    runs = [
        make_run("id_b0", "B0", "none", revary(base, {"a02": "needs_review"})),
        make_run("id_b1", "B1", "none", base),
        make_run("id_b2", "B2", "disabled", revary(base, {"a05": "benign"})),
        make_run("id_b3", "B3", "disabled", revary(base, {"a03": "escalate"})),
        make_run("id_b4_off", "B4", "disabled", b4_off),
        make_run("id_b4_on", "B4", "enabled", b4_on),
        make_run(
            "id_g3_b3", "B3", "disabled", g3_preds(), gold_set="G3", manifest_rows=g3_manifest()
        ),
        make_run(
            "id_g3_b4", "B4", "disabled", g3_preds(), gold_set="G3", manifest_rows=g3_manifest()
        ),
    ]
    return runs


def sample_human(gold):
    labels_a = {p.cluster_id: ("escalate" if p.truth == "escalate" else "benign") for p in gold}
    labels_b = {p.cluster_id: "needs_review" for p in gold[:4]}
    return {
        "a": {"labeler_id": "khanh-admin", "labels": labels_a},
        "b": {"labeler_id": "nguyen-admin", "labels": labels_b},
    }


def sample_kappa():
    return {
        "vs_truth": {
            "a": {"labeler_id": "khanh-admin", "accuracy": 0.875},
            "b": {"labeler_id": "nguyen-admin", "accuracy": None},
        }
    }


# --- tests -------------------------------------------------------------------------------------


def test_every_file_opens_with_the_dec111_caveat():
    runs = full_run_set()
    caveat = report.render_caveat()
    for content in (
        report.render_ablation(runs, gold12=GOLD12),
        report.render_per_category(runs, gold12=GOLD12),
        report.render_adversarial(runs, gold12=GOLD12),
    ):
        assert content.startswith(caveat)
        assert content.startswith(report.DEC111_SENTENCE)
        assert report.CLASS_BALANCE_SENTENCE in content
    # DEC111_SENTENCE is imported, never retyped — the constant is build_gold's.
    assert "author-generated lab traffic" in report.DEC111_SENTENCE


def test_headline_has_deferral_adjacent_to_strict_recall():
    runs = full_run_set()
    headline = report.render_headline(runs)
    header_line = headline.splitlines()[0]
    cells = [c.strip() for c in header_line.strip("|").split("|")]
    recall_idx = next(i for i, c in enumerate(cells) if c.startswith("recall(escalate)"))
    deferral_idx = next(i for i, c in enumerate(cells) if c.startswith("deferral(escalate)"))
    assert deferral_idx == recall_idx + 1, cells


def test_truth_outcome_table_per_run():
    r1 = make_run("id_b1", "B1", "none", sample_g2("a"))
    r2 = make_run("id_b4", "B4", "disabled", sample_g2("b"))
    out = report.render_confusion_tables([r1, r2])
    assert out.count("truth \\ outcome") == 2  # one 2 x 4 table per G2 run
    for col in metrics.OUTCOMES:
        assert col in out
    assert "| escalate |" in out and "| close |" in out
    # the escalate->escalate cell of sample_g2 is 1
    conf = r1.score["confusion"]
    assert conf["escalate"]["escalate"] == 1


def test_human_baseline_present_or_named_missing():
    runs = [make_run("id_b4", "B4", "disabled", sample_g2("a"))]
    missing = report.render_human_baseline(runs, None, None)
    assert f"(not available {EM_DASH} run_configs.py human)" in missing

    gold = list(report._g2(runs)[0].preds)
    present = report.render_human_baseline(runs, sample_human(gold), sample_kappa())
    assert "khanh-admin" in present and "nguyen-admin" in present
    assert "0.875" in present  # labeller a's strict vs_truth accuracy from the kappa file
    assert "a second result, not the gold (DEC-111)" in present


def test_thinking_pair_prints_each_runs_recorded_mode():
    base = sample_g2("a")
    off = make_run("id_off", "B4", "disabled", base)
    on = make_run("id_on", "B4", "enabled", revary(base, {"a01": "escalate"}))
    out = report.render_thinking_pair([off, on])
    # each run's recorded llm_thinking printed from its metrics (repr), not inferred
    assert "'disabled'" in out and "'enabled'" in out
    assert "not inferred" in out
    assert "McNemar" in out
    assert "cost/alert USD" in out and "p95 ms" in out


def test_b4_vs_b1_mcnemar_and_delta_rendered():
    base = sample_g2("a")
    b1 = make_run("id_b1", "B1", "none", base)
    b4 = make_run("id_b4", "B4", "disabled", revary(base, {"a01": "escalate", "a03": "escalate"}))
    out = report.render_b4_vs_b1([b1, b4])
    assert "McNemar" in out and "n_discordant=" in out
    assert "macro-F1" in out and "recall(escalate) strict" in out
    assert f"delta (B4 {MINUS} B1) [95% CI]" in out  # − minus sign


def test_dropped_categories_are_named():
    runs = [make_run("id_b4", "B4", "disabled", sample_g2("a"))]  # covers 4 of the 8 lab categories
    out = report.render_dropped_categories(runs)
    for cat in ("c2_beacon", "data_exfiltration", "ransomware", "suspicious_login"):
        assert cat in out
    assert "web_attack" in out and "DEC-055" in out
    assert "policy_violation" in out and "DEC-057" in out
    # framed as the comparison against the eight lab categories
    assert "eight lab categories" in out


def test_v1_1_line_three_states():
    built = report.render_v1_1({"decision": "v1.1 activated", "reason": "macro-F1 +0.04"}, None)
    assert "built and evaluated" in built and "v1.1 activated" in built
    assert "no decision recorded" not in built and "not built" not in built

    not_built = report.render_v1_1(None, {"reason": "no qualifying triage_labels row exists"})
    assert "not built" in not_built
    assert "no qualifying triage_labels row exists" in not_built
    assert "DEC-116" in not_built and "DEC-121 Q2" in not_built

    none = report.render_v1_1(None, None)
    assert "no decision recorded" in none


def test_adversarial_prints_expectation_not_as_result():
    run = make_run(
        "id_g3", "B4", "disabled", g3_preds(), gold_set="G3", manifest_rows=g3_manifest()
    )
    out = report.render_adversarial([run], gold12=GOLD12)
    assert "expected: B3 > 0, B4 ≈ 0" in out
    assert "not a result" in out  # framed as an expectation, never asserted as a measurement
    assert "ASR" in out
    assert "### by vector" in out and "### by pattern family" in out
    # no G3 selected -> says so
    empty = report.render_adversarial(
        [make_run("id_b4", "B4", "disabled", sample_g2("a"))], gold12=GOLD12
    )
    assert f"(no G3 run selected {EM_DASH} nothing to report)" in empty


def test_predictions_csv_columns_exact_and_no_free_text():
    preds = sample_g2("a")
    run = make_run("id_b4", "B4", "disabled", preds)
    marker = "RAWLOG-e3b0c44298fc-secret-payload"
    tampered = []
    for row in run.rows:
        row = dict(row)
        row["raw_log"] = marker  # a field a buggy renderer might dump; report must not
        row["model_output_text"] = marker
        tampered.append(row)
    run.rows = tuple(tampered)

    csv_text = report.render_predictions_csv([run], GOLD12)
    header = csv_text.splitlines()[0]
    assert report.CSV_COLUMNS == EXPECTED_CSV_COLUMNS  # a `note` column added anywhere breaks this
    assert header == ",".join(EXPECTED_CSV_COLUMNS)  # the emitted header equals the exact tuple
    assert marker not in csv_text  # no free-text column, so raw log never leaks
    assert len(csv_text.splitlines()) == 1 + len(preds)
    # deterministic sort by (gold_set, config, llm_thinking, prompt_version, cluster_id)
    body = csv_text.splitlines()[1:]
    cluster_ids = [line.split(",")[6] for line in body]
    assert cluster_ids == sorted(cluster_ids)


def test_render_is_byte_identical_twice():
    runs = full_run_set()
    gold = list(report._g2(runs)[0].preds)
    human, kappa = sample_human(gold), sample_kappa()
    gate = {"decision": "keep v1.0", "reason": "no qualifying rows"}

    def ablation():
        return report.render_ablation(
            runs, human=human, kappa=kappa, gate_decision=gate, gold12=GOLD12
        )

    assert ablation() == ablation()
    assert report.render_per_category(runs, gold12=GOLD12) == report.render_per_category(
        runs, gold12=GOLD12
    )
    assert report.render_adversarial(runs, gold12=GOLD12) == report.render_adversarial(
        runs, gold12=GOLD12
    )
    assert report.render_predictions_csv(runs, GOLD12) == report.render_predictions_csv(
        runs, GOLD12
    )


def test_charts_skipped_cleanly_without_matplotlib(monkeypatch, tmp_path):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "matplotlib" or name.startswith("matplotlib."):
            raise ImportError("matplotlib not installed (simulated)")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert report._get_pyplot() is None

    runs = [make_run("id_b4", "B4", "disabled", sample_g2("a"))]
    note = report.render_charts(runs, tmp_path)
    assert note == "(charts not rendered: matplotlib not installed)"
    assert list(tmp_path.iterdir()) == []  # nothing written
    ablation = report.render_ablation(runs, gold12=GOLD12, charts_note=note)
    assert "(charts not rendered: matplotlib not installed)" in ablation


@pytest.mark.db
def test_selection_latest_per_key_and_missing_results_exit_3(db, tmp_path):
    from psycopg.types.json import Jsonb

    key_old, key_new, other = (str(uuid.uuid4()) for _ in range(3))

    def insert(eval_run_id, thinking, config, age_hours):
        md = metrics_doc(config, thinking, sample_g2("a"))
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO eval_runs "
                "(eval_run_id, prompt_version, model_id, gold_set, config, metrics, created_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, now() - make_interval(hours => %s))",
                (eval_run_id, "v1", "deepseek-v4-flash", "G2", config, Jsonb(md), age_hours),
            )

    # same selection key (G2, B4, disabled, v1); the newer created_at must win
    insert(key_old, "disabled", "B4", 3)
    insert(key_new, "disabled", "B4", 0)
    # a different key (thinking=enabled) — also selected
    insert(other, "enabled", "B4", 0)

    selected = report.select_runs(db, SHA)
    ids = {str(r["eval_run_id"]) for r in selected}
    assert key_new in ids and other in ids
    assert key_old not in ids  # only the latest per key

    # every selected run's results JSON is absent from an empty dir -> exit 3, naming it
    with pytest.raises(report.Exit) as excinfo:
        report.load_runs(selected, tmp_path, SHA)
    assert excinfo.value.code == 3
    assert "results file missing" in excinfo.value.message
