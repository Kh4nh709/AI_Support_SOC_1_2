# ② size-class measurement — `investigate_v2` at 60 k against the 12.8 k ceiling

DEC-032 amendment (b) / DEC-097: the measurement the 28/09 ② agent-day rests on. This report only measures format, latency and cost — the decision is DEC-097's and the Owner's (§8).

- **Date:** 2026-09-29T09:10:36+00:00
- **Model:** `deepseek-v4-flash` (`LLM_MODEL_PROPOSER`)
- **Mode:** `LLM_THINKING=disabled`
- **`LLM_TIMEOUT_S`:** 120 s (wall-clock, DEC-033)
- **`CASE_PROMPT_BUDGET_TOKENS`:** 60,000
- **Git sha:** `dc5cedd`
- **Calls per arm:** 3
- **Total calls:** 6
- **Total spend:** $0.01828
- **Provenance:** 6 live · 0 cached
- **Token estimate:** `len(text) / 4`, rounded — the crude estimator the card cites `eval/smoke_test.py` for; that script does not actually carry a pre-send estimator (a card inaccuracy, recorded in the task report). The exact byte count is printed alongside every estimate below so a reader can redo the arithmetic with a real tokeniser.

## 1 · Two-arm table

| Arm (tokens) | clusters | n | JSON parses | schema valid (1st) | schema valid (after repair) | p50 (s) | p95 (s) | max (s) | mean input tok | mean output tok | cost (USD) | over `LLM_TIMEOUT_S` |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 60,000 | 131 | 3 | 100.0 % | 100.0 % | 100.0 % | 14.60 | 14.65 | 14.65 | 98784 | 2828 | 0.00975 | 0 |
| 12,800 | 29 | 3 | 66.7 % | 66.7 % | 100.0 % | 13.40 | 14.68 | 14.68 | 28243 | 3709 | 0.00853 | 0 |

## 2 · Verdict against the §4.5 thresholds (DEC-032's reading)

| Arm (tokens) | Threshold | Required | Measured | Verdict |
|---|---|---|---|---|
| 60,000 | JSON parses | ≥ 90 % | 100.0 % | **PASS** |
| 60,000 | Schema-valid `investigate_v2`, first attempt | ≥ 90 % | 100.0 % | **PASS** |
| 60,000 | Schema-valid `investigate_v2`, after one repair | ≥ 98 % | 100.0 % | **PASS** |
| 60,000 | p95 latency | ≤ 60 s | 14.65 s | **PASS** |
| 12,800 | JSON parses | ≥ 90 % | 66.7 % | **FAIL** |
| 12,800 | Schema-valid `investigate_v2`, first attempt | ≥ 90 % | 66.7 % | **FAIL** |
| 12,800 | Schema-valid `investigate_v2`, after one repair | ≥ 98 % | 100.0 % | **PASS** |
| 12,800 | p95 latency | ≤ 60 s | 14.68 s | **PASS** |

## 3 · The ceiling this corpus can actually reach

The 200 largest alert heads in the whole corpus total **51,312 bytes ≈ 12,828 tokens** (measured 23/09 on `soc_dev`, `docs/plan/tasks/P5/P5-tasks.md` §1 — cited here, not re-derived: design note 14 forbids this card opening a database connection), and `MAX_ALERTS_PER_CASE = 200`. So the largest dossier a real case on this deployment can ever produce is ≈ 12,828 tokens — 21 % of `CASE_PROMPT_BUDGET_TOKENS = 60,000`. The 60 k arm below measures a class this deployment never reaches; the 12.8 k arm measures the class it actually will. Both numbers are in the table above — reporting only the 60 k arm would be a different way of measuring the wrong thing (the mistake DEC-025 exists to name).

## 4 · What this does not settle

This run measures **format, latency and cost** — never verdict quality, the same caveat DEC-042 insisted on for the smoke test and for the same reason: the synthesized dossiers built from six repeated committed fixtures are not the content of any real case, so `suggested_conclusion` and the hypotheses returned here are not evidence about accuracy in either direction. Nothing in this report is a proposal to accept or reject a verdict; only a `structured_basis`-shaped hallucination or evidence gate (P5-T03/T04's, not built yet) could answer that question, and it would still need a labelled gold set, not a synthetic dossier.

## 5 · Per call

| arm | # | origin | latency (s) | input tok | output tok | JSON | schema (1st) | schema (final) | cost (USD) | stopped_by |
|---|---|---|---|---|---|---|---|---|---|---|
| 60,000 | 1 | live | 12.14 | 98784 | 2544 | ok | ok | ok | 0.00306 | — |
| 60,000 | 2 | live | 14.65 | 98784 | 2993 | ok | ok | ok | 0.00336 | — |
| 60,000 | 3 | live | 14.60 | 98784 | 2947 | ok | ok | ok | 0.00333 | — |
| 12,800 | 1 | live | 14.68 | 21162 | 3141 | ok | ok | ok | 0.00237 | — |
| 12,800 | 2 | live | 12.64 | 21162 | 2724 | ok | ok | ok | 0.00209 | — |
| 12,800 | 3 | live | 13.40 | 42406 | 5261 | no | no | ok | 0.00407 | — |

## 6 · DEC-097

This is the measurement DEC-097 arms ② on: *"a surviving ② gets exactly one agent-day, 28/09, after DEC-032's measurement at its own prompt size."* The numbers above are that measurement. **This card reports numbers; it does not recommend a cut** (scope out) — the decision is DEC-097's and the Owner's.
