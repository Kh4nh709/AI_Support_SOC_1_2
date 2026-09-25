# P7 · Evaluation — task cards

> **Complete as of 25/09 late (DEC-122).** The first Planner run was stopped mid-way through P7-T03
> (DEC-121); a fresh Planner session the Owner opened wrote P7-T03 … P7-T08, committed verbatim at
> `108a8ac`. All eight cards now exist and passed E5 (DEC-122). Where this index and a card differ,
> **the card wins** — in particular §3 item 4 below, whose "safe" secondary metric was dropped
> (DEC-121 Q1 as landed in P7-T03). `must` is now **16.0 h** (T08, the Director's run card, adds 1.5 h).

Phase objective: numbers with confidence intervals for the five configurations B0–B4 on the frozen
gold set, ASR on the adversarial set G3, the paired thinking ablation (DEC-042), and at most one
controlled prompt iteration.
Written **25/09/2026** (Planner P7, forked by the Director under DEC-116), against `prompts/P7.md`
as swept 25/09 per DEC-111, and against DEC-111, DEC-114, DEC-115, DEC-116, DEC-117, DEC-119 and
DEC-120 in full. Where a DEC and the brief disagree, the DEC wins and the divergence is named in §3.

**Which copy is authoritative (DEC-007 item 7 / DEC-009).** Each task has a full
`docs/plan/tasks/P7/<TASK_ID>.prompt.md`. **The prompt is the card**; this file is the index —
estimates, waves, dependencies, the run order, the cost of the live runs, and the questions for the
Director.

---

## ⚠️ Budget note — `must` is 15.5 h against the brief's 1 agent-day; wall-clock ≈ 8 h at three coders

| | |
|---|---|
| Sum of `must` estimates | **15.5 h** (7 cards; T05's PNG charts and all of T07 are `should`) |
| Day budget (`prompts/P7.md`: 1 day) | 8 h agent; the × 1.3 rule allows **10.4 h** |
| Overbooking | **+49 %** against 10.4 h (+94 % against 8 h) — above the 30 % re-plan threshold, so this note is required |
| Why it is still feasible | The harness is **built now, on fixtures, in parallel with the lab** (26–28/09), not on 29/09. Three build days with up to three coders hold 15.5 h of cards in three waves (§2); only T08 (the live runs, 1.5 h) needs the frozen gold |
| Wall-clock at the 3-coder cap | **≈ 8 h** of card time over three waves (§2), plus review rounds |
| `should` | T05 PNG charts (0.5 h), T07 prompt v1.1 (2.5 h) |
| Cut order if short (the brief's own, extended) | T07 v1.1 → T05 charts → McNemar inside T03 → per-severity rows inside T03. **Never cut:** T01–T04, T06, T08 — the eval harness is on the never-cut list (context pack §10) |

**The harness is a build now, the evaluation is a run later.** The brief's stop condition —
"`eval/gold_v1.sha256` missing → stop; evaluation on an unfrozen gold set is not allowed" — governs
**running** B0–B4 on the gold set. Writing and testing harness code on fixtures and recorded samples
does not evaluate anything and is dispatchable today. Exactly one card, **P7-T08**, executes the
real runs, and it refuses to start without a committed `eval/gold_v1.sha256`.

---

## 1 · Cards

| Card | Title | Priority | Estimate | Depends on | Files (create **C** / modify **M**) | Dispatchable |
|---|---|---|---|---|---|---|
| **P7-T01** | ① core extracted with evaluation switches | must | 2.5 h | — | M `backend/app/tier1/triage.py` · C `backend/tests/test_triage_eval_switches.py` | **now** |
| **P7-T02** | Evaluation LLM cache, spend guard, bounded concurrency | must | 2 h | — | C `eval/llm_cache.py` · C `backend/tests/test_llm_cache.py` | **now** |
| **P7-T03** | Metrics: mapping, confusion, F1/recall/precision, per-group rows, bootstrap, McNemar, ASR | must | 3 h | — | C `eval/metrics.py` · C `backend/tests/test_eval_metrics.py` | **now** |
| **P7-T04** | Harness driver: gold loading, B0–B4, G3 targets, results, `eval_runs` writer | must | 3 h | T01, T02, T03 | M `eval/run_configs.py` · C `backend/tests/test_run_configs.py` | after wave 1 |
| **P7-T05** | Report: `docs/results/*.md` tables (+ charts, `should`) | must (charts `should`) | 2.5 h | T03 | M `eval/report.py` · C `backend/tests/test_eval_report.py` | after T03 |
| **P7-T06** | Regression gate | must | 1.5 h | T03 | M `eval/regression_gate.py` · C `backend/tests/test_regression_gate.py` | after T03 |
| **P7-T07** | Prompt v1.1 few-shot builder, with the DEC-116 guard | should | 2.5 h | T04, T06 | C `eval/fewshot.py` · C `backend/tests/test_fewshot.py` | after wave 2 |
| **P7-T08** | Live runs on the frozen gold set (run card, Director-executed) | must | 1.5 h + LLM time | T01–T06 merged, `eval/gold_v1.sha256` committed, Owner cost approval | outputs only: `docs/results/ablation.md`, `docs/results/adversarial.md`, `docs/results/per_category.md`, `docs/results/predictions_<gold12>.csv` | **29/09, gated on the freeze** |

No file appears in two cards' Files lists. Every card also writes its own report and its own
`STATE.md` row; those are not listed.

## 2 · Waves and the critical path

| Wave | When | Cards (≤ 3 coders) | Gate out |
|---|---|---|---|
| 1 | 25/09 night – 26/09 | T01 ‖ T02 ‖ T03 | each reviewed and merged |
| 2 | 27/09 | T04 ‖ T05 ‖ T06 | each reviewed and merged by 27/09 evening |
| 3 | 28/09 | T07 (`should`) | cut if the pilot has no qualifying decisions (Q2) |
| run | 29/09 | T08 (Director) | `eval_runs` rows + `docs/results/*.md` committed |
| buffer | 30/09 | v1.1 gate decision (Owner), re-runs if any, tables handed to P8 | P7 exit gate |

**Critical path:** T03 (3 h) → T04 (3 h) → T08 (runs). T01 and T02 run beside T03 and must merge
before T04 starts. T05 and T06 need only T03's metric names and run beside T04.

## 3 · Planning decisions

1. **One ① code path, several switches (brief design note 2).** T01 extracts the computation in
   `tier1/triage.py::run_triage_job` into `evaluate_alert(...)`, which reads the database, calls the
   adapter and runs the gate, and **writes nothing**. `run_triage_job` becomes "evaluate with the
   deployed switches, then write exactly what it writes today". B2 is the builder's existing
   `include_context=False, include_correlation=False`; B3 is gate steps 1–3 plus the step-7 output
   guard with no verifier, composed from the existing `security/gate.py` step functions; B4 is the
   deployed default. No orchestration is copied into `eval/`.
2. **The evaluation writes no `llm_runs`, no `alerts` column, no `triage_status`, no job.** It writes
   one `eval_runs` row per (gold set, config, thinking mode) and local result files. The pilot's
   `llm_runs` stay the pilot's; G11 governs the product path, which the evaluation does not replace.
3. **The cache key is smoke test's, not a second formula** (DEC-032, DEC-042): `cache_key(model,
   system, user, thinking)` from `eval/smoke_test.py`, with the per-build nonce folded out of `user`
   first (the same idea as `stable_user`). A message carrying two distinct nonces is refused, never
   cached. The thinking mode has no default anywhere in the key path.
4. **Label mapping under DEC-115 (Director question Q1).** The gold truth is two-valued
   (`escalate` for an attack window, `benign` for a benign window, DEC-111/115), while every config
   predicts in ①'s space `false_positive | needs_review | escalate`. T03 scores on **decision
   classes**: `close` (truth `benign`; prediction `false_positive`), `review` (prediction
   `needs_review`; no truth), `escalate` (both sides). **Strict** (primary, the brief's) counts
   `review` as wrong. *(Superseded 25/09, DEC-121 Q1 as landed in P7-T03: the "safe" secondary
   metric was dropped — the full truth × outcome table plus the deferral rate beside strict
   recall(escalate) let a reader derive it; a crashed or capped run is its own `error` outcome,
   counted wrong, DEC-122.)* Macro-F1 is
   taken only over classes with truth support (`close`, `escalate`); a zero-support class is
   reported `n/a`, never 0 or 1. The brief's "precision(false_positive)" becomes **precision of
   `close`** = P(truth `benign` | prediction `false_positive`) — the auto-close safety number. The
   mapping is one named constant in `eval/metrics.py`, so a different ruling is a one-line change.
5. **Per-category rows group by the scenario's declared category**, `category_expected`, joined from
   `eval/lab_windows.csv` by `scenario_id` — independent of the system under test, the DEC-114
   principle — with the alert's own `category` as a secondary view. A category with no gold cluster
   is dropped from the tables and named as dropped (architecture §6: "không giả").
6. **Stdlib only for statistics.** `numpy`, `scipy` and `matplotlib` are not in the venv or in
   `backend/requirements.txt` (measured 25/09). Bootstrap uses `random.Random(20260904)` (the
   project's `EVAL_SEED`) with cluster-level resampling, 1 000 draws; McNemar is the exact binomial
   test on the discordant pairs via `math.comb`. PNG charts render only if `matplotlib` imports; no
   dependency is added.
7. **What is committed as evidence.** `eval/results/` is git-ignored (`.gitignore:30`), so the cache
   and the per-run JSON stay local. The record is: the `eval_runs` rows (in `soc_dev`, backed up),
   `docs/results/{ablation,adversarial,per_category}.md`, and a per-alert predictions CSV
   `docs/results/predictions_<gold12>.csv` carrying ids, truth and verdicts but **no raw text and no
   model output text**.
8. **G3 is a frozen input.** It is loaded only through `eval/adversarial/load.py`, only after the
   freeze, and only by T08. No P7 card authors, extends or edits adversarial content. ASR = share of
   the 40 manifest targets whose final verdict is `false_positive` (architecture §6), for B3 and B4.
9. **`eval_runs` for the deterministic baselines.** B0: `model_id = 'none'`, `prompt_version =
   'severity_for'`. B1: `model_id = 'none'`, `prompt_version = 'kb:' + sha256 of the concatenated
   `kb/decision_tables/*.yaml` in name order, 12 hex`. B2–B4: `model_id` from the responses,
   `prompt_version` = `llm.triage.prompt_version(TRIAGE_TEMPLATE)`, or `'file:' + sha256(template)[:12]`
   for an override template (T07). `metrics` always carries `gold_sha256`, `llm_thinking` and `n`.
10. **B4 is ① as deployed**; auto-close is not part of the ablation (it is measured in the pilot
    chapter through the digest). Stated so the Director can object.
11. **Human baseline.** T04 fetches the two labellers' `gold_offline` labels for the gold clusters
    and T03 scores them with the same mapping as the configs, so ① and the humans are compared on
    one scale; `eval/kappa_v1.json`'s strict `vs_truth` is shown beside it.
12. **Whole-suite acceptance on every card** (DEC-119): each card runs `make lint`, `make test`
    (exactly the DEC-113 failure) and `make test-db` on its own database, not only its own file.
13. **T01 touches the deployed ① path.** A defect would break live triage (never the gold corpus,
    by G7). Merge it after the day's last lab window, then `docker compose restart worker`
    (`backend/app` is bind-mounted, `docker-compose.yml:66`).

## 4 · The live runs — order and cost (T08)

Run order on 29/09, after the freeze and the Owner's cost approval: load G3 into `soc_dev`
(`eval/adversarial/load.py`) → `run_configs.py --estimate-only` (prints the line the Owner approves)
→ B0, B1 on G2 → B2, B3, B4 on G2 with `LLM_THINKING=disabled` → B4 on G2 with
`LLM_THINKING=enabled` (the paired ablation) → B3, B4 on G3 → `report.py` → commit.

Calls, with N = the frozen G2 size (P6-T08 plans 103 in-scope clusters; `--g2-target 150`):

| Run | Calls |
|---|---|
| B0, B1 | 0 |
| B2, B3 (proposer only) | N each |
| B4 disabled, B4 enabled (proposer + verifier) | 2N each |
| G3: B3 + B4 on 40 targets | 40 + 80 |
| schema repairs | budget +10 % |

Cost per call, measured: **$0.00028** with thinking disabled (pilot, $0.2858 over 1,011 `llm_runs`),
**$0.00415** with thinking enabled (`docs/smoke-test-D1.md`, $0.1577 over 38 calls).

| N | Calls (+10 %) | Cost |
|---|---|---|
| 103 | 738 → 812 | 532 × 0.00028 + 206 × 0.00415 = **$1.00** → ≈ **$1.10** |
| 150 | 1,020 → 1,122 | 720 × 0.00028 + 300 × 0.00415 = **$1.45** → ≈ **$1.60** |

Both are far below the `LLM_MONTHLY_USD_CAP` of $30. Wall-clock at concurrency 4: ≈ 10 min for
the disabled runs, ≈ 20 min for the enabled run.

## 5 · Questions for the Director

- **Q1 · The label mapping (§3 item 4), before T03 merges.** Confirm `close`/`review`/`escalate`
  scoring with strict primary and safe secondary, macro-F1 over supported classes only, and
  "precision of `close`" in place of the brief's "precision(false_positive)". Without a ruling T03
  builds the proposed default.
- **Q2 · v1.1 under DEC-116, by 28/09.** P4's decision screens are deprioritized, so the pilot may
  have no human decisions to draw few-shot examples from. Proposal: T07 is cut on 28/09 if no
  qualifying row exists, and the P7 exit-gate item "regression gate applied to v1.1 with a recorded
  decision" is reworded to "v1.1 built and gated, **or** recorded as not built (DEC-116)".
- **Q3 · T01 merge timing (§3 item 13).** Confirm merge after the day's last lab window.
- **Q4 · Evidence (§3 item 7).** Confirm committing `docs/results/predictions_<gold12>.csv`.
- **Q5 · Who runs T08.** It reads and writes `soc_dev` and spends money, so it is not a Coder card.
  Proposal: the Director runs it under DEC-116 after the Owner approves the §4 cost line.

## 6 · Owner actions

- **29/09 morning:** approve the cost line T08 prints (≈ $1.10–$1.60).
- **30/09:** decide v1.0 vs v1.1 after the regression gate (if T07 was built).
