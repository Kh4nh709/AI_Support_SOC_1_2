# ② size-class measurement — `investigate_v2` at 60 k against the 12.8 k ceiling

DEC-032 amendment (b) / DEC-097: the measurement ②'s survival was conditioned on. DEC-151 has since reinstated the whole ② bundle outright, superseding DEC-097's 28/09 one-agent-day arming condition; this report only measures format, latency and cost — the decision on what to build atop these numbers is DEC-097's and the Owner's (§6).

- **Date:** 2026-09-29T12:17:10+00:00
- **Model:** `deepseek-v4-flash` (`LLM_MODEL_PROPOSER`)
- **Mode:** `LLM_THINKING=disabled`
- **`LLM_TIMEOUT_S`:** 120 s (wall-clock, DEC-033)
- **`CASE_PROMPT_BUDGET_TOKENS`:** 60,000
- **Git sha:** `5429143-dirty`
- **Calls per arm:** 3
- **Total calls:** 6
- **Total spend:** $0.01828
- **Provenance:** 6 live · 0 cached
- **Token estimate:** `len(text) / 4`, rounded — the crude estimator the card cites `eval/smoke_test.py` for; that script does not actually carry a pre-send estimator (a card inaccuracy, recorded in the task report). The nearest real precedent is `app.llm.adapter.estimate_tokens` (`len(text.encode('utf-8')) / 2.5`, ①'s per-send budget guard, not this script's own sizing loop). The exact system and user byte counts and the `len/4` estimate are in the two-arm table below, next to the real, model-reported token counts, so a reader can redo the arithmetic with a real tokeniser.
- **Scale:** 3 per arm (the card's own acceptance names 30; the Director's dispatch authorised a live measurement under $0.10, which a 30-call, two-arm run risked exceeding on the output side — see the task report's deviation 1). Two earlier live runs of the same two prompts, made while developing this script, are **not tabulated** here — only the 3 calls per arm stored under the cache this report was rendered from are. §2's verdicts are therefore indicative at n = 3, not a claim of statistical power.

## 1 · Two-arm table

| Arm (tokens) | clusters | system bytes | user bytes | `len/4` est. | n | JSON parses | schema valid (1st) | schema valid (after repair) | p50 (s) | p95 (s) | max (s) | mean input tok (incl. repair) | mean output tok (incl. repair) | cost (USD) | over `LLM_TIMEOUT_S` |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 60,000 | 131 | 2,586 | 235,061 | 59,254 | 3 | 100.0 % | 100.0 % | 100.0 % | 14.60 | 14.65 | 14.65 | 98784 | 2828 | 0.00975 | 0 |
| 12,800 | 29 | 2,586 | 49,795 | 12,938 | 3 | 66.7 % | 66.7 % | 100.0 % | 13.40 | 14.68 | 14.68 | 28243 | 3709 | 0.00853 | 0 |

The `len/4` estimate undershoots this model's real tokenizer by ≈ 1.64–1.67× (60,000: 98,784 real vs 59,254 estimated (1.67×, 2.41 bytes/real-token), 12,800: 21,162 real vs 12,938 estimated (1.64×, 2.48 bytes/real-token)) — real prompts run ≈ 2.41–2.48 bytes per real token, not 4; both arms above and the 12,828-token ceiling in §3 are expressed on the same crude `len/4` scale, so the same undershoot applies to the ceiling figure too.

## 2 · Verdict against the §4.5 thresholds (three from DEC-032, the first-attempt one from architecture §4.5 as quoted in `docs/smoke-test-D1-nothink.md:17-19`)

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

The 200 largest alert heads in the whole corpus total **51,312 bytes ≈ 12,828 tokens** (measured 23/09 on `soc_dev`, `docs/plan/tasks/P5/P5-tasks.md` §1 — cited here, not re-derived: design note 14 forbids this card opening a database connection), and `MAX_ALERTS_PER_CASE = 200`. So the largest dossier a real case on this deployment can ever produce is ≈ 12,828 tokens — 21 % of `CASE_PROMPT_BUDGET_TOKENS = 60,000`. The 60 k arm above measures a class this deployment never reaches; the 12.8 k arm measures the class it actually will. Both numbers are in the table above — reporting only the 60 k arm would be a different way of measuring the wrong thing (the mistake DEC-032 exists to name).

## 4 · What this does not settle

This run measures **format, latency and cost** — never verdict quality, the same caveat DEC-042 insisted on for the smoke test and for the same reason: the synthesized dossiers built from six repeated committed fixtures are not the content of any real case, so `suggested_conclusion` and the hypotheses returned here are not evidence about accuracy in either direction. Nothing in this report is a proposal to accept or reject a verdict; only a `structured_basis`-shaped hallucination or evidence gate (P5-T03/T04's, not built yet) could answer that question, and it would still need a labelled gold set, not a synthetic dossier.

## 5 · Per call

Row `12,800 / 3`'s `latency (s), end-to-end` predates `repair_latency_ms` — it renders as not recorded rather than the first-attempt-only number the old cache actually stored, which would silently understate its real end-to-end cost (see the task report's Review round 1 section).

| arm | # | origin | latency (s), end-to-end | input tok (incl. repair) | output tok (incl. repair) | JSON | schema (1st) | schema (final) | cost (USD) | stopped_by | first-attempt problems |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 60,000 | 1 | live | 12.14 | 98784 | 2544 | ok | ok | ok | 0.00306 | — | n/a (not recorded in this cache) |
| 60,000 | 2 | live | 14.65 | 98784 | 2993 | ok | ok | ok | 0.00336 | — | n/a (not recorded in this cache) |
| 60,000 | 3 | live | 14.60 | 98784 | 2947 | ok | ok | ok | 0.00333 | — | n/a (not recorded in this cache) |
| 12,800 | 1 | live | 14.68 | 21162 | 3141 | ok | ok | ok | 0.00237 | — | n/a (not recorded in this cache) |
| 12,800 | 2 | live | 12.64 | 21162 | 2724 | ok | ok | ok | 0.00209 | — | n/a (not recorded in this cache) |
| 12,800 | 3 | live | n/a (not recorded in this cache) | 42406 | 5261 | no | no | ok | 0.00407 | — | n/a (not recorded in this cache) |

## 6 · DEC-097

This is the measurement DEC-097 arms ② on: *"a surviving ② gets exactly one agent-day, 28/09, after DEC-032's measurement at its own prompt size."* (DEC-151 has since reinstated the ② bundle outright, so this no longer gates ②'s survival — it is still the measurement that arming condition was written for.) The numbers above are that measurement. **This card reports numbers; it does not recommend a cut** (scope out) — the decision is DEC-097's and the Owner's.
