"""`triage`'s handler, re-exported for `web/handlers/__init__.py`'s discovery
(P5-tasks.md planning decision 1). The tier code is
`tier1/triage.run_triage_job`; this module claims no logic of its own — not a
`functools.partial` or a lambda, so `run_triage_job`'s keyword-only `adapter`
parameter stays exactly what `test_g7_llm_off.py` and `test_triage_job.py`
monkeypatch.
"""

from __future__ import annotations

from app.tier1.triage import run_triage_job

JOB_TYPE = "triage"
handle = run_triage_job
