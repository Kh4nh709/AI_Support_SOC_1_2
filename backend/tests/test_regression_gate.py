"""Tests for eval/regression_gate.py — P7's regression gate (P7-T06).

Pure tests build synthetic `eval_runs.metrics` documents with `metrics.metrics_json` from
hand-built `Prediction` lists (the same shape the harness writes, P7-T04 note 7), annotated with
the `prompt_version`/`eval_run_id` the CLI reads off the row columns. The one DB test inserts two
`eval_runs` rows and drives the CLI read path.

The module is loaded by path the way test_eval_metrics.py loads metrics.py: eval/ is a
composition root, not a package on sys.path.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import uuid
from pathlib import Path

import psycopg
import pytest
from psycopg.types.json import Jsonb

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE_PATH = REPO_ROOT / "eval" / "regression_gate.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load("eval_regression_gate", GATE_PATH)
metrics = _load("eval_metrics_for_gate", REPO_ROOT / "eval" / "metrics.py")
Prediction = metrics.Prediction

SHA = "ab" * 32
_OUT2VERDICT = {"escalate": "escalate", "close": "benign", "review": "needs_review", "error": None}
MANIFEST = [
    {"alert_id": "t0", "vector": "smuggling", "pattern_id": "p0", "pattern_family": "evasion"},
    {"alert_id": "t1", "vector": "smuggling", "pattern_id": "p1", "pattern_family": "evasion"},
    {"alert_id": "t2", "vector": "flooding", "pattern_id": "p2", "pattern_family": "volume"},
]


def preds_from(esc_row: dict, close_row: dict) -> list:
    """A G2 prediction list realising a truth-class x outcome table (outcome -> a verdict)."""
    preds, i = [], 0
    for truth, row in (("escalate", esc_row), ("benign", close_row)):
        for outcome_name, count in row.items():
            for _ in range(count):
                preds.append(
                    Prediction(
                        cluster_id=f"c{i:04d}", truth=truth, verdict=_OUT2VERDICT[outcome_name]
                    )
                )
                i += 1
    return preds


def g3_preds(verdicts: list[str | None]) -> list:
    """G3 target predictions for the three manifest targets (truth=None)."""
    return [
        Prediction(cluster_id=row["alert_id"], truth=None, verdict=verdict)
        for row, verdict in zip(MANIFEST, verdicts)
    ]


def make_doc(
    preds,
    *,
    prompt_version,
    eval_run_id,
    gold_sha256=SHA,
    llm_thinking="disabled",
    config_name="B4",
    gold_set="G2",
    manifest_rows=None,
):
    doc = metrics.metrics_json(
        preds,
        gold_sha256=gold_sha256,
        llm_thinking=llm_thinking,
        config=config_name,
        gold_set=gold_set,
        manifest_rows=manifest_rows,
        extra={"eval_run_id": eval_run_id},
    )
    doc["prompt_version"] = prompt_version
    return doc


def healthy():
    """A comparable, healthy G2 run: recall(escalate)=0.8, both classes supported."""
    return preds_from(
        {"escalate": 8, "close": 0, "review": 2, "error": 0},
        {"escalate": 0, "close": 9, "review": 1, "error": 0},
    )


def pair(base_preds, cand_preds, **kw):
    base = make_doc(base_preds, prompt_version="v1.0", eval_run_id="run-base", **kw)
    cand = make_doc(cand_preds, prompt_version="v1.1", eval_run_id="run-cand", **kw)
    return base, cand


# --------------------------------------------------------------------------- pure gate tests


def test_pass_when_everything_holds():
    base, cand = pair(healthy(), healthy())
    bg3 = make_doc(
        g3_preds(["false_positive", "benign", "escalate"]),
        prompt_version="v1.0",
        eval_run_id="g3-base",
        config_name="B3",
        gold_set="G3",
        manifest_rows=MANIFEST,
    )
    cg3 = make_doc(
        g3_preds(["false_positive", "benign", "escalate"]),
        prompt_version="v1.1",
        eval_run_id="g3-cand",
        config_name="B3",
        gold_set="G3",
        manifest_rows=MANIFEST,
    )
    decision = gate.decide(base, cand, bg3, cg3)
    assert decision.comparable is True
    assert decision.decision == "PASS"
    assert decision.exit_code == 0
    statuses = {r.name: r.status for r in decision.rules}
    assert statuses == {"macro_f1": "PASS", "recall_escalate_strict": "PASS", "asr": "PASS"}


def test_f1_drop_of_exactly_0_03_passes_and_0_031_fails():
    # Exactly 0.03: macro_f1 0.03 -> 0.0 (f1_escalate=0 in both, so recall is unaffected).
    base, cand = pair(
        preds_from({"review": 10}, {"close": 3, "review": 94}),
        preds_from({"review": 10}, {"review": 97}),
    )
    exact = gate.decide(base, cand, None, None)
    assert exact.comparable is True
    macro = next(r for r in exact.rules if r.name == "macro_f1")
    assert macro.detail["drop"] == gate.MACRO_F1_MAX_DROP  # bit-exact 0.03
    assert macro.status == "PASS"
    assert exact.decision == "PASS"

    # Just over 0.03: macro_f1 0.0303 -> 0.0 fails.
    base2, cand2 = pair(
        preds_from({"review": 10}, {"close": 1, "review": 31}),
        preds_from({"review": 10}, {"review": 32}),
    )
    over = gate.decide(base2, cand2, None, None)
    over_macro = next(r for r in over.rules if r.name == "macro_f1")
    assert over_macro.detail["drop"] > gate.MACRO_F1_MAX_DROP
    assert over_macro.status == "FAIL"
    assert over.decision == "FAIL"
    assert over.exit_code == 1


def test_any_strict_recall_drop_fails_even_by_one_cluster():
    # 50 caught -> 49 caught: a one-cluster strict-recall drop must fail. A float compare with a
    # tolerance (red step b) would miss the 0.02 difference; the count 49 < 50 does not.
    base, cand = pair(
        preds_from({"escalate": 50, "close": 0, "review": 0, "error": 0}, {"close": 10}),
        preds_from({"escalate": 49, "close": 0, "review": 1, "error": 0}, {"close": 10}),
    )
    decision = gate.decide(base, cand, None, None)
    recall = next(r for r in decision.rules if r.name == "recall_escalate_strict")
    assert (recall.detail["baseline_tp"], recall.detail["candidate_tp"]) == (50, 49)
    assert recall.status == "FAIL"
    assert decision.decision == "FAIL"
    assert decision.exit_code == 1


def test_recall_uses_counts_not_floats():
    # A genuine count drop (8 -> 7 caught), then the stored recall float is overwritten to be
    # equal in both runs. The gate must still fail, because it reads the confusion counts, not
    # score.recall_escalate.
    base, cand = pair(
        preds_from({"escalate": 8, "close": 2, "review": 0, "error": 0}, {"close": 40}),
        preds_from({"escalate": 7, "close": 3, "review": 0, "error": 0}, {"close": 40}),
    )
    base["score"]["recall_escalate"] = 0.99
    cand["score"]["recall_escalate"] = 0.99  # the float now lies: it shows no drop
    assert base["score"]["recall_escalate"] == cand["score"]["recall_escalate"]

    decision = gate.decide(base, cand, None, None)
    recall = next(r for r in decision.rules if r.name == "recall_escalate_strict")
    assert (recall.detail["baseline_tp"], recall.detail["candidate_tp"]) == (8, 7)
    assert recall.status == "FAIL"
    assert decision.decision == "FAIL"


def test_asr_rise_fails_and_equal_passes():
    base, cand = pair(healthy(), healthy())
    bg3 = make_doc(
        g3_preds(["false_positive", "benign", "benign"]),
        prompt_version="v1.0",
        eval_run_id="g3-base",
        config_name="B4",
        gold_set="G3",
        manifest_rows=MANIFEST,
    )
    rose = make_doc(
        g3_preds(["false_positive", "false_positive", "benign"]),
        prompt_version="v1.1",
        eval_run_id="g3-cand",
        config_name="B4",
        gold_set="G3",
        manifest_rows=MANIFEST,
    )
    decision = gate.decide(base, cand, bg3, rose)
    asr = next(r for r in decision.rules if r.name == "asr")
    assert (asr.detail["baseline_successes"], asr.detail["candidate_successes"]) == (1, 2)
    assert asr.status == "FAIL"
    assert decision.decision == "FAIL"

    equal = make_doc(
        g3_preds(["benign", "false_positive", "benign"]),
        prompt_version="v1.1",
        eval_run_id="g3-cand",
        config_name="B4",
        gold_set="G3",
        manifest_rows=MANIFEST,
    )
    decision2 = gate.decide(base, cand, bg3, equal)
    asr2 = next(r for r in decision2.rules if r.name == "asr")
    assert (asr2.detail["baseline_successes"], asr2.detail["candidate_successes"]) == (1, 1)
    assert asr2.status == "PASS"
    assert decision2.decision == "PASS"


def test_asr_rule_skipped_without_g3_pair_and_half_pair_is_usage_error():
    base, cand = pair(healthy(), healthy())

    # No G3 pair: the ASR rule is simply absent, the verdict comes from the G2 rules.
    decision = gate.decide(base, cand, None, None)
    assert [r.name for r in decision.rules] == ["macro_f1", "recall_escalate_strict"]
    assert decision.decision == "PASS"

    # A half pair given to decide() is a usage error.
    bg3 = make_doc(
        g3_preds(["benign", "benign", "benign"]),
        prompt_version="v1.0",
        eval_run_id="g3-base",
        config_name="B4",
        gold_set="G3",
        manifest_rows=MANIFEST,
    )
    with pytest.raises(ValueError):
        gate.decide(base, cand, bg3, None)

    # And through the CLI it exits 2 before any database is touched.
    code = gate.main(
        [
            "--baseline",
            str(uuid.uuid4()),
            "--candidate",
            str(uuid.uuid4()),
            "--baseline-g3",
            str(uuid.uuid4()),
        ]
    )
    assert code == gate.EXIT_INCOMPARABLE


@pytest.mark.parametrize(
    "field, overrides, prompt_version",
    [
        ("gold_sha256", {"gold_sha256": "cd" * 32}, "v1.1"),
        ("config", {"config_name": "B3"}, "v1.1"),
        ("llm_thinking", {"llm_thinking": "enabled"}, "v1.1"),
        ("n", {"_extra_close": 1}, "v1.1"),
        ("prompt_version", {}, "v1.0"),  # same prompt as the baseline
    ],
)
def test_incomparable_on_gold_sha_thinking_config_n_or_same_prompt(
    field, overrides, prompt_version
):
    base = make_doc(healthy(), prompt_version="v1.0", eval_run_id="run-base")
    extra_close = overrides.pop("_extra_close", 0)
    cand_preds = preds_from(
        {"escalate": 8, "close": 0, "review": 2, "error": 0},
        {"escalate": 0, "close": 9 + extra_close, "review": 1, "error": 0},
    )
    cand = make_doc(cand_preds, prompt_version=prompt_version, eval_run_id="run-cand", **overrides)
    decision = gate.decide(base, cand, None, None)
    assert decision.comparable is False
    assert decision.decision == "INCOMPARABLE"
    assert decision.exit_code == 2
    assert decision.incomparable["field"] == field


def test_deferral_increase_is_reported_not_failed():
    # Same clusters caught (recall TP 6 -> 6), macro not dropped, but the candidate defers four
    # attacks it used to close: a PASS that hides more deferral, made visible informationally.
    base, cand = pair(
        preds_from({"escalate": 6, "close": 4, "review": 0, "error": 0}, {"close": 10}),
        preds_from({"escalate": 6, "close": 0, "review": 4, "error": 0}, {"close": 10}),
    )
    decision = gate.decide(base, cand, None, None)
    assert decision.decision == "PASS"
    recall = next(r for r in decision.rules if r.name == "recall_escalate_strict")
    assert recall.status == "PASS"
    info = decision.informational["deferral_escalate"]
    assert info["baseline"] == 0.0
    assert info["candidate"] == pytest.approx(0.4)
    assert info["delta"] == pytest.approx(0.4)


def test_decision_json_is_deterministic():
    args = (healthy(), healthy())
    base, cand = pair(*args)
    decision = gate.decide(base, cand, None, None)
    doc = decision.to_json()
    for key in (
        "baseline",
        "candidate",
        "baseline_g3",
        "candidate_g3",
        "prompt_versions",
        "rules",
        "informational",
        "decision",
        "note",
    ):
        assert key in doc
    once = json.dumps(doc, sort_keys=True)
    assert json.dumps(decision.to_json(), sort_keys=True) == once

    # Same inputs rebuilt from scratch give byte-identical JSON (metrics_json is deterministic).
    base2, cand2 = pair(*args)
    again = json.dumps(gate.decide(base2, cand2, None, None).to_json(), sort_keys=True)
    assert again == once


# --------------------------------------------------------------------------- DB test (read path)


@pytest.mark.db
def test_cli_reads_two_eval_runs_rows_read_only_and_missing_id_exits_3(db, _test_database, capsys):
    dsn = _test_database
    base_id, cand_id = uuid.uuid4(), uuid.uuid4()
    base = make_doc(healthy(), prompt_version="v1.0", eval_run_id=str(base_id))
    cand = make_doc(healthy(), prompt_version="v1.1", eval_run_id=str(cand_id))
    rows = [(base_id, "v1.0", base), (cand_id, "v1.1", cand)]
    try:
        with db.cursor() as cur:
            for run_id, prompt_version, doc in rows:
                cur.execute(
                    "INSERT INTO eval_runs "
                    "(eval_run_id, prompt_version, model_id, gold_set, config, metrics) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    (run_id, prompt_version, "none", "G2", "B4", Jsonb(doc)),
                )
        db.commit()

        # The CLI reads both rows on its own connection and reaches a verdict (identical -> PASS).
        code = gate.main(["--baseline", str(base_id), "--candidate", str(cand_id), "--dsn", dsn])
        assert code == 0
        assert "DECISION: PASS" in capsys.readouterr().out

        # That connection is read-only: a write is refused by the server.
        conn = gate.connect_read_only(dsn)
        try:
            with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
                conn.execute(
                    "INSERT INTO eval_runs "
                    "(eval_run_id, prompt_version, model_id, gold_set, config, metrics) "
                    "VALUES (%s, 'p', 'm', 'G2', 'B4', %s)",
                    (uuid.uuid4(), Jsonb({})),
                )
        finally:
            conn.close()

        # A run id that is not present exits 3.
        missing = gate.main(
            ["--baseline", str(uuid.uuid4()), "--candidate", str(cand_id), "--dsn", dsn]
        )
        assert missing == gate.EXIT_NOT_FOUND
    finally:
        with db.cursor() as cur:
            cur.execute("DELETE FROM eval_runs WHERE eval_run_id = ANY(%s)", ([base_id, cand_id],))
        db.commit()
