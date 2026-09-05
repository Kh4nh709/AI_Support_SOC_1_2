"""
eval/ - Composition root: the offline evaluation harness.

Builds the gold set, runs the five ablation configurations (B0-B4) against
it, reports metrics, and gates a new run against the last accepted baseline.
Run as scripts (`python3 eval/build_gold.py`, ...); never imported by
backend/app/.

Import rule: composition root. MAY import every other package. Nothing in
backend/app/ imports eval/.
"""
