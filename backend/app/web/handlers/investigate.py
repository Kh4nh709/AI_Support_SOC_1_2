"""`investigate`'s handler, re-exported for `web/handlers/__init__.py`'s discovery
(P5-tasks.md planning decision 1). The tier code is
`tier2.investigate.run_investigate_job`; this module claims no logic of its own — not a
`functools.partial` or a lambda, so `run_investigate_job`'s keyword-only `adapter`
parameter stays exactly what `test_investigate.py` monkeypatches/passes.

`STATEMENT_TIMEOUT = "5s"` — the value `infra/worker.py`'s own docstring already
anticipated ("P5's `conclude`, for `investigate`, asks for 5s"): pipeline design note 7.
This bounds `SET LOCAL statement_timeout` for this job's transaction (`infra/db.py::
transaction()`), a per-statement cap distinct from the idle-in-transaction timeout this
job's first statement raises to `JOB_LOCK_TIMEOUT_S` (`tier2/investigate.py`'s own
`_raise_idle_timeout`) — the model call is client-side idle time to Postgres and is not
bound by `statement_timeout` at all; 5 s is for the SQL this job actually runs (the
dossier's queries, the evidence check, the `llm_runs` insert and the `cases` update).
"""

from __future__ import annotations

from app.tier2.investigate import run_investigate_job

JOB_TYPE = "investigate"
handle = run_investigate_job
STATEMENT_TIMEOUT = "5s"
