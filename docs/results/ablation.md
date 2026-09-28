This corpus is author-generated lab traffic on the author's host with window-known truth: no rate computed from it is an estate rate, of any estate.

The class balance is the lab schedule's, not nature's; no rate here is an estate rate (DEC-111).


# Ablation — gold c5f43d77c922

## Runs

| config | thinking | prompt_version | model_id | n | eval_run_id |
| --- | --- | --- | --- | --- | --- |
| B0 | none | severity_for | none | 56 | 23b98113 |
| B1 | none | kb:667253d21351 | none | 56 | a3ba93e0 |
| B2 | disabled | 656e61e+c400da0dd25da638cf0f61ccc1ea299da6b763c34d21134633c779314b997cd5 | deepseek-flash | 56 | 28373b1e |
| B3 | disabled | 656e61e+c400da0dd25da638cf0f61ccc1ea299da6b763c34d21134633c779314b997cd5 | deepseek-flash | 56 | 818c4f90 |
| B4 | disabled | 656e61e+c400da0dd25da638cf0f61ccc1ea299da6b763c34d21134633c779314b997cd5 | deepseek-flash | 56 | 9880e9e0 |
| B4 | enabled | 656e61e+c400da0dd25da638cf0f61ccc1ea299da6b763c34d21134633c779314b997cd5 | deepseek-flash | 56 | 6d45e519 |
| B3 | disabled | 656e61e+c400da0dd25da638cf0f61ccc1ea299da6b763c34d21134633c779314b997cd5 | deepseek-flash | 40 | d43ebab4 |
| B4 | disabled | 656e61e+c400da0dd25da638cf0f61ccc1ea299da6b763c34d21134633c779314b997cd5 | deepseek-flash | 40 | 69a8d431 |

## Headline (G2)

| config | thinking | n | macro-F1 [95% CI] | recall(escalate) strict [95% CI] | deferral(escalate) [95% CI] | precision(close) [95% CI] | deferral(close) | error rate | evidence-verified | cost/alert USD | billed USD | p50/p95 ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| B0 | none | 56 | 0.485 [0.336, 0.617] | 0.333 [0.196, 0.462] | 0.292 [0.163, 0.417] | 0.308 [0.130, 0.481] | 0.000 | 0.000 | n/a | n/a | n/a | n/a/n/a |
| B1 | none | 56 | 0.585 [0.360, 0.769] | 0.625 [0.471, 0.760] | 0.375 [0.240, 0.524] | 1.000 [unstable] | 0.750 | 0.000 | n/a | n/a | n/a | n/a/n/a |
| B2 | disabled | 56 | 0.304 [0.140, 0.481] | 0.271 [0.149, 0.404] | 0.688 [0.553, 0.818] | 0.333 [0.000, 1.000] | 0.875 | 0.000 | 0.570 ✗ | 0.0004 | 0.0000 | 2507/3275 |
| B3 | disabled | 56 | 0.169 [0.089, 0.239] | 0.208 [0.100, 0.320] | 0.729 [0.612, 0.850] | 0.000 [0.000, 0.000] | 0.875 | 0.000 | 0.536 ✗ | 0.0005 | 0.0296 | 3209/4222 |
| B4 | disabled | 56 | 0.143 [0.062, 0.217] | 0.167 [0.067, 0.277] | 0.833 [0.723, 0.930] | n/a [unstable] | 1.000 | 0.000 | 0.536 ✗ | 0.0006 | 0.0067 | 4595/5912 |
| B4 | enabled | 56 | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 1.000 [1.000, 1.000] | n/a [unstable] | 1.000 | 0.000 | 0.672 ✗ | 0.0032 | 0.1819 | 16905/41663 |

## Truth × outcome (per run)

### B0 none — 23b98113

| truth \ outcome | escalate | close | review | error |
| --- | --- | --- | --- | --- |
| escalate | 16 | 18 | 14 | 0 |
| close | 0 | 8 | 0 | 0 |

### B1 none — a3ba93e0

| truth \ outcome | escalate | close | review | error |
| --- | --- | --- | --- | --- |
| escalate | 30 | 0 | 18 | 0 |
| close | 0 | 2 | 6 | 0 |

### B2 disabled — 28373b1e

| truth \ outcome | escalate | close | review | error |
| --- | --- | --- | --- | --- |
| escalate | 13 | 2 | 33 | 0 |
| close | 0 | 1 | 7 | 0 |

### B3 disabled — 818c4f90

| truth \ outcome | escalate | close | review | error |
| --- | --- | --- | --- | --- |
| escalate | 10 | 3 | 35 | 0 |
| close | 1 | 0 | 7 | 0 |

### B4 disabled — 9880e9e0

| truth \ outcome | escalate | close | review | error |
| --- | --- | --- | --- | --- |
| escalate | 8 | 0 | 40 | 0 |
| close | 0 | 0 | 8 | 0 |

### B4 enabled — 6d45e519

| truth \ outcome | escalate | close | review | error |
| --- | --- | --- | --- | --- |
| escalate | 0 | 0 | 48 | 0 |
| close | 0 | 0 | 8 | 0 |

## Human baseline — a second result, not the gold (DEC-111)

| labeller | labeler_id | macro-F1 | recall(escalate) strict | precision(close) | vs_truth accuracy |
| --- | --- | --- | --- | --- | --- |
| a | 1a794b27-b7c8-445d-bdc4-9edbc6041ddb | 0.736 | 0.854 | 0.462 | 0.821 |
| b | 4c5f8e18-7b8a-4f74-b940-44dd357dc47f | 0.699 | 0.812 | 0.400 | 0.786 |

## B4 vs B1

B4 = B4 thinking=disabled; B1 baseline.

| metric | delta (B4 − B1) [95% CI] |
| --- | --- |
| macro-F1 | -0.442 [-0.638, -0.211] |
| recall(escalate) strict | -0.458 [-0.600, -0.315] |

McNemar (exact): n_discordant=24, B1-only-correct=24, B4-only-correct=0, p=0.0000

## Paired thinking ablation (DEC-042)

recorded llm_thinking: disabled run = 'disabled', enabled run = 'enabled' (from each run's metrics, not inferred)

| metric | disabled | enabled | delta (enabled − disabled) [95% CI] |
| --- | --- | --- | --- |
| macro-F1 | 0.143 | 0.000 | -0.143 [-0.217, -0.065] |
| recall(escalate) strict | 0.167 | 0.000 | -0.167 [-0.277, -0.070] |
| precision(close) | n/a | n/a | n/a [unstable] |
| evidence-verified | 0.536 | 0.672 | 0.136 [0.080, 0.197] |

| measure | disabled | enabled |
| --- | --- | --- |
| cost/alert USD | 0.0006 | 0.0032 |
| p50 ms | 4595 | 16905 |
| p95 ms | 5912 | 41663 |

McNemar (exact): n_discordant=8, disabled-only-correct=8, enabled-only-correct=0, p=0.0078

## Prompt v1.1

prompt v1.1: not built — card cut (DEC-127); 0 digest labels and 0 auto-close reviews marked wrong existed at the run, so no example could qualify (DEC-116, DEC-121 Q2)

## Charts

(charts not rendered: matplotlib not installed)
