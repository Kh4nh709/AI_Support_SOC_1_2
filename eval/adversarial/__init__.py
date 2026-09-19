"""
eval/adversarial/ - the G3 adversarial set: 40 prompt-injection fixtures and their loader.

`generate.py` writes the fixtures and `manifest.csv` deterministically from the
5503 base sample (5 vectors x 8 patterns, plus vector 5's eight neighbours);
`load.py` inserts them as `received`, `is_synthetic`, `source='lab'` heads with
enrichment context and no job. The loader runs in P7 only, after the gold
freeze (standing rule: G3 is never shown to the model before evaluation).

Import rule: part of the `eval/` composition root. MAY import every package
under backend/app/. Nothing in backend/app/ imports eval/.
"""
