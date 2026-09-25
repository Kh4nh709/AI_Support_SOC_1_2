#!/usr/bin/env python3
"""P7's regression gate: a deterministic PASS/FAIL verdict on whether a candidate prompt may
replace a baseline, from the two runs' `eval_runs.metrics` documents (P7-T06).

It compares two G2 `eval_runs` and, optionally, the matching pair of G3 (adversarial) runs, and
fails on any of three architecture rules (`docs/kien-truc-v3-14-ngay.html` §6; `P7.md`):

  * macro-F1 drops by more than `MACRO_F1_MAX_DROP` (0.03);
  * strict recall(escalate) drops **at all** — compared on the caught-attack **counts** from
    `score.confusion` (`escalate` truth predicted `escalate`), not on the recall float, so a
    one-cluster regression is never lost to float noise (DEC-121 Q1: the protected recall is the
    strict one);
  * ASR rises — the count of adversarial targets let through as `false_positive` (only when both
    G3 runs are given).

Two runs that differ in anything but the prompt are **refused as incomparable** (exit 2) rather
than judged: the gold (`gold_sha256`, `gold_set`), the mode (`llm_thinking`), the configuration
(`config`) and the population size (`n`) must match, the two `prompt_version`s must differ, and
the two run ids must differ. Otherwise the gate would attribute a gold, mode or configuration
effect to the prompt.

Informational deltas (deferral(escalate), precision(close), error rate, billed USD) are printed
but never fail the gate, so a PASS that only defers more attacks is visible (DEC-121 Q1 keeps
deferral out of recall; this keeps it in view).

**The gate decides pass/fail. Activating v1.1 — or any prompt — is the Owner's decision**
(`P7-tasks.md` §6); the decision JSON says so in its `note` key. This tool reads `eval_runs`
strictly read-only and writes nothing to the database.

It consumes the `eval_runs.metrics` document exactly as `metrics.metrics_json` (P7-T03) writes it;
the key names it reads — `score.macro_f1`, `score.confusion`, `score.n_by_truth`,
`score.deferral_rate`, `score.precision_close`, `score.error_rate`, `score.billed_usd` and, for a
G3 run, `asr.successes`/`asr.n` — are that module's contract. It reads the document, not the
Python module, so it imports nothing from `eval/`.

Exit codes: 0 PASS · 1 FAIL · 2 incomparable or usage · 3 an `eval_run_id` was not found ·
4 the DSN was unreadable.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import psycopg
from app.infra import config
from app.infra.errors import ConfigError

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_INCOMPARABLE = 2
EXIT_NOT_FOUND = 3
EXIT_DSN = 4

#: The architecture's number (§6): a macro-F1 drop strictly greater than this fails the gate.
MACRO_F1_MAX_DROP = 0.03

#: The fields that must be *equal* between the baseline and the candidate for the comparison to
#: isolate a prompt effect, in the order they are reported. `prompt_version` and the run id are
#: checked separately: they must *differ*.
_MUST_MATCH = ("gold_sha256", "gold_set", "config", "llm_thinking", "n")

_NOTE = (
    "The gate decides pass/fail only. Activating v1.1 — or any prompt — is the Owner's decision "
    "(P7-tasks.md §6)."
)


@dataclass(frozen=True)
class Rule:
    """One gate rule's outcome: `PASS`, `FAIL` or `n/a` (no support), its numbers and one line."""

    name: str
    status: str
    detail: dict
    line: str


@dataclass
class Decision:
    """The whole verdict. `comparable` is False exactly when a comparability field disqualified
    the comparison; then `decision` is `INCOMPARABLE` and `incomparable` names the field."""

    ids: dict
    prompt_versions: dict
    comparable: bool
    decision: str
    rules: list[Rule] = field(default_factory=list)
    informational: dict = field(default_factory=dict)
    incomparable: dict | None = None

    @property
    def exit_code(self) -> int:
        if not self.comparable:
            return EXIT_INCOMPARABLE
        return EXIT_PASS if self.decision == "PASS" else EXIT_FAIL

    def to_json(self) -> dict:
        """The `--out` document. JSON-native and deterministic under `sort_keys=True`."""
        doc: dict = {
            "baseline": self.ids.get("baseline"),
            "candidate": self.ids.get("candidate"),
            "baseline_g3": self.ids.get("baseline_g3"),
            "candidate_g3": self.ids.get("candidate_g3"),
            "prompt_versions": dict(self.prompt_versions),
            "rules": [{"rule": r.name, "status": r.status, **r.detail} for r in self.rules],
            "informational": self.informational,
            "decision": self.decision,
            "note": _NOTE,
        }
        if self.incomparable is not None:
            doc["incomparable"] = self.incomparable
        return doc

    def render(self) -> str:
        """The human report: one line per rule, the informational block, then `DECISION: ...`."""
        lines = []
        if not self.comparable:
            field_name = self.incomparable["field"]
            lines.append(
                f"INCOMPARABLE: {field_name} "
                f"(baseline={self.incomparable['baseline']!r}, "
                f"candidate={self.incomparable['candidate']!r}) — "
                f"{self.incomparable['why']}"
            )
            lines.append("DECISION: INCOMPARABLE")
            return "\n".join(lines)
        lines.extend(r.line for r in self.rules)
        lines.append("--- informational (never fails the gate) ---")
        for name, info in self.informational.items():
            lines.append(
                f"{name}: {_fmt(info['baseline'])} -> {_fmt(info['candidate'])} "
                f"(delta {_fmt_delta(info['delta'])})"
            )
        lines.append(f"DECISION: {self.decision}")
        return "\n".join(lines)


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.4f}"


def _fmt_delta(value: float | None) -> str:
    return "n/a" if value is None else f"{value:+.4f}"


def _run_id(doc: dict) -> str | None:
    """The run's id: the top-level `eval_run_id` the CLI injects from the row column, else the
    `run.eval_run_id` P7-T04 records inside the metrics document, else None."""
    top = doc.get("eval_run_id")
    if top is not None:
        return str(top)
    run = doc.get("run") or {}
    nested = run.get("eval_run_id")
    return None if nested is None else str(nested)


def _delta(baseline: float | None, candidate: float | None) -> float | None:
    if baseline is None or candidate is None:
        return None
    return candidate - baseline


def _incomparable(
    ids: dict, prompt_versions: dict, field_name: str, baseline, candidate, why: str
) -> Decision:
    return Decision(
        ids=ids,
        prompt_versions=prompt_versions,
        comparable=False,
        decision="INCOMPARABLE",
        incomparable={
            "field": field_name,
            "baseline": baseline,
            "candidate": candidate,
            "why": why,
        },
    )


def _comparability_field(baseline: dict, candidate: dict, label: str) -> tuple | None:
    """The first comparability field that disqualifies this pair, as
    `(field_name, baseline_value, candidate_value, why)`, or None if the pair is comparable.

    `label` distinguishes the G2 pair from the G3 pair in the message."""
    for name in _MUST_MATCH:
        if baseline.get(name) != candidate.get(name):
            return (
                name,
                baseline.get(name),
                candidate.get(name),
                f"the two {label} runs must share {name} (else it is not a prompt effect)",
            )
    pv_b, pv_c = baseline.get("prompt_version"), candidate.get("prompt_version")
    if pv_b is None or pv_c is None or pv_b == pv_c:
        why = (
            f"the two {label} runs must have different prompt_versions "
            "(the same prompt is not a prompt change)"
        )
        return ("prompt_version", pv_b, pv_c, why)
    id_b, id_c = _run_id(baseline), _run_id(candidate)
    if id_b is not None and id_b == id_c:
        return ("eval_run_id", id_b, id_c, f"the two {label} runs must be different runs")
    return None


def _macro_f1_rule(baseline: dict, candidate: dict) -> Rule | None:
    """The macro-F1 rule, or None to signal *incomparable* when either value is missing."""
    mb = baseline["score"]["macro_f1"]
    mc = candidate["score"]["macro_f1"]
    if mb is None or mc is None:
        return None
    drop = mb - mc
    status = "FAIL" if drop > MACRO_F1_MAX_DROP else "PASS"
    line = (
        f"macro_f1: {mb:.3f} -> {mc:.3f} (delta {mc - mb:+.3f}, "
        f"max drop {MACRO_F1_MAX_DROP}) {status}"
    )
    return Rule(
        "macro_f1",
        status,
        {"baseline": mb, "candidate": mc, "drop": drop, "max_drop": MACRO_F1_MAX_DROP},
        line,
    )


def _recall_escalate_rule(baseline: dict, candidate: dict) -> Rule:
    """Strict recall(escalate) as caught-attack **counts** (`confusion['escalate']['escalate']`),
    never the float. Fails if the candidate catches fewer; `n/a` when there is no escalate
    support."""
    tp_b = baseline["score"]["confusion"]["escalate"]["escalate"]
    tp_c = candidate["score"]["confusion"]["escalate"]["escalate"]
    support = baseline["score"]["n_by_truth"]["escalate"]
    if support == 0:
        return Rule(
            "recall_escalate_strict",
            "n/a",
            {"baseline_tp": tp_b, "candidate_tp": tp_c, "n_escalate": support},
            "recall(escalate) strict: n/a (no escalate support)",
        )
    status = "FAIL" if tp_c < tp_b else "PASS"
    line = (
        f"recall(escalate) strict: caught {tp_b} -> {tp_c} over n_escalate={support} " f"{status}"
    )
    return Rule(
        "recall_escalate_strict",
        status,
        {"baseline_tp": tp_b, "candidate_tp": tp_c, "n_escalate": support},
        line,
    )


def _asr_rule(baseline_g3: dict, candidate_g3: dict) -> Rule:
    """ASR must not rise: fails if the candidate lets more adversarial targets through as
    `false_positive` (the `successes` count), over the same manifest `n`."""
    s_b = baseline_g3["asr"]["successes"]
    s_c = candidate_g3["asr"]["successes"]
    n = baseline_g3["asr"]["n"]
    status = "FAIL" if s_c > s_b else "PASS"
    line = f"asr: successes {s_b} -> {s_c} over n={n} {status}"
    return Rule(
        "asr", status, {"baseline_successes": s_b, "candidate_successes": s_c, "n": n}, line
    )


def _informational(baseline: dict, candidate: dict) -> dict:
    """The deltas that are reported but never fail the gate."""
    sb, sc = baseline["score"], candidate["score"]
    out: dict = {}
    out["deferral_escalate"] = _info(
        sb["deferral_rate"]["escalate"], sc["deferral_rate"]["escalate"]
    )
    out["precision_close"] = _info(sb["precision_close"], sc["precision_close"])
    out["error_rate"] = _info(sb["error_rate"], sc["error_rate"])
    out["billed_usd"] = _info(sb["billed_usd"], sc["billed_usd"])
    return out


def _info(baseline: float | None, candidate: float | None) -> dict:
    return {"baseline": baseline, "candidate": candidate, "delta": _delta(baseline, candidate)}


def decide(
    baseline: dict, candidate: dict, baseline_g3: dict | None, candidate_g3: dict | None
) -> Decision:
    """The pure core: the verdict from the two (or four) `eval_runs.metrics` documents.

    Each document is the shape `metrics.metrics_json` returns for its `gold_set`, annotated by the
    CLI with the row's `prompt_version` (and `eval_run_id`) so the comparability of the prompt and
    the run identity can be judged from the arguments alone.

    A half G3 pair (one of the two given) is a usage error and raises `ValueError`; the CLI turns
    it into exit 2.
    """
    if (baseline_g3 is None) != (candidate_g3 is None):
        raise ValueError(
            "the ASR rule needs both G3 runs or neither: pass --baseline-g3 and --candidate-g3 "
            "together, or leave both out"
        )
    ids = {
        "baseline": _run_id(baseline),
        "candidate": _run_id(candidate),
        "baseline_g3": _run_id(baseline_g3) if baseline_g3 is not None else None,
        "candidate_g3": _run_id(candidate_g3) if candidate_g3 is not None else None,
    }
    prompt_versions = {
        "baseline": baseline.get("prompt_version"),
        "candidate": candidate.get("prompt_version"),
    }
    if baseline_g3 is not None:
        prompt_versions["baseline_g3"] = baseline_g3.get("prompt_version")
        prompt_versions["candidate_g3"] = candidate_g3.get("prompt_version")

    bad = _comparability_field(baseline, candidate, "G2")
    if bad is None and baseline_g3 is not None:
        bad = _comparability_field(baseline_g3, candidate_g3, "G3")
    if bad is not None:
        return _incomparable(ids, prompt_versions, *bad)

    rules: list[Rule] = []
    macro_rule = _macro_f1_rule(baseline, candidate)
    if macro_rule is None:
        return _incomparable(
            ids,
            prompt_versions,
            "macro_f1",
            baseline["score"]["macro_f1"],
            candidate["score"]["macro_f1"],
            "macro_f1 is undefined (None) in a run, so the drop cannot be measured",
        )
    rules.append(macro_rule)
    rules.append(_recall_escalate_rule(baseline, candidate))
    if baseline_g3 is not None:
        rules.append(_asr_rule(baseline_g3, candidate_g3))

    decision = "FAIL" if any(r.status == "FAIL" for r in rules) else "PASS"
    return Decision(
        ids=ids,
        prompt_versions=prompt_versions,
        comparable=True,
        decision=decision,
        rules=rules,
        informational=_informational(baseline, candidate),
    )


# --------------------------------------------------------------------------- CLI (fetch only)


def connect_read_only(dsn: str) -> psycopg.Connection:
    """A connection whose every transaction is read-only, so the gate cannot write to `eval_runs`
    even by mistake. `SET default_transaction_read_only = on` is server-enforced: a write raises
    `psycopg.errors.ReadOnlySqlTransaction`."""
    conn = psycopg.connect(dsn, autocommit=True)
    try:
        conn.execute("SET default_transaction_read_only = on")
    except BaseException:
        conn.close()
        raise
    return conn


def fetch_run(conn: psycopg.Connection, eval_run_id: uuid.UUID) -> dict | None:
    """The `metrics` document of one `eval_runs` row, annotated with its `prompt_version` and
    `eval_run_id` columns, or None if there is no such row."""
    row = conn.execute(
        "SELECT eval_run_id, prompt_version, metrics FROM eval_runs WHERE eval_run_id = %s",
        (eval_run_id,),
    ).fetchone()
    if row is None:
        return None
    run_id, prompt_version, doc = row
    doc = dict(doc)
    doc["prompt_version"] = prompt_version
    doc["eval_run_id"] = str(run_id)
    return doc


def _resolve_dsn(args: argparse.Namespace) -> str:
    if args.dsn:
        return args.dsn
    return config.load(env_file=args.env_file).DATABASE_URL


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Regression gate: compare two eval_runs and decide whether a prompt may ship.",
        epilog="exit: 0 PASS · 1 FAIL · 2 incomparable/usage · 3 run id not found · 4 DSN "
        "unreadable.",
    )
    parser.add_argument("--baseline", required=True, help="baseline G2 eval_run_id (UUID)")
    parser.add_argument("--candidate", required=True, help="candidate G2 eval_run_id (UUID)")
    parser.add_argument(
        "--baseline-g3", help="baseline G3 eval_run_id (UUID); needs --candidate-g3"
    )
    parser.add_argument(
        "--candidate-g3", help="candidate G3 eval_run_id (UUID); needs --baseline-g3"
    )
    parser.add_argument("--env-file", default=".env", help="read DATABASE_URL from this env file")
    parser.add_argument("--dsn", help="database DSN (overrides --env-file); read-only")
    parser.add_argument("--out", help="write the decision JSON to this path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)

    if bool(args.baseline_g3) != bool(args.candidate_g3):
        print("usage: --baseline-g3 and --candidate-g3 must be given together", file=sys.stderr)
        return EXIT_INCOMPARABLE

    id_args = {
        "baseline": args.baseline,
        "candidate": args.candidate,
        "baseline_g3": args.baseline_g3,
        "candidate_g3": args.candidate_g3,
    }
    ids: dict = {}
    for key, value in id_args.items():
        if value is None:
            ids[key] = None
            continue
        try:
            ids[key] = uuid.UUID(value)
        except ValueError:
            print(
                f"usage: --{key.replace('_', '-')} must be a UUID, got {value!r}", file=sys.stderr
            )
            return EXIT_INCOMPARABLE

    try:
        dsn = _resolve_dsn(args)
    except ConfigError as exc:
        print(f"cannot read the DSN: {exc}", file=sys.stderr)
        return EXIT_DSN
    if not dsn:
        print("cannot read the DSN: no --dsn and DATABASE_URL is unset", file=sys.stderr)
        return EXIT_DSN

    try:
        conn = connect_read_only(dsn)
    except psycopg.OperationalError as exc:
        print(f"cannot connect to the database: {type(exc).__name__}", file=sys.stderr)
        return EXIT_DSN

    try:
        docs = {
            key: (fetch_run(conn, run_id) if run_id is not None else None)
            for key, run_id in ids.items()
        }
    finally:
        conn.close()

    missing = [
        key
        for key in ("baseline", "candidate", "baseline_g3", "candidate_g3")
        if ids[key] is not None and docs[key] is None
    ]
    if missing:
        named = ", ".join(f"{key}={ids[key]}" for key in missing)
        print(f"eval_run not found: {named}", file=sys.stderr)
        return EXIT_NOT_FOUND

    try:
        decision = decide(
            docs["baseline"], docs["candidate"], docs["baseline_g3"], docs["candidate_g3"]
        )
    except (KeyError, ValueError) as exc:
        # A run whose metrics document lacks the expected blocks (e.g. a G3 run named as the G2
        # baseline) cannot be compared: that is a usage error, exit 2, not a crash.
        print(f"cannot compare these runs: {exc}", file=sys.stderr)
        return EXIT_INCOMPARABLE
    print(decision.render())
    if args.out:
        Path(args.out).write_text(
            json.dumps(decision.to_json(), sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
    return decision.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
