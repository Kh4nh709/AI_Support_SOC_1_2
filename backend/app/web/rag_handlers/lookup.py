"""`rag_lookup`'s handler, re-exported for `web/rag_handlers/__init__.py`'s discovery (P13-T03). The
code is `rag.lookup.run_lookup_job`; this module claims no logic of its own — not a `functools.partial`
or a lambda, so its keyword-only `adapter` parameter stays what `test_rag_lookup_job.py` passes.

`STATEMENT_TIMEOUT = "10s"` bounds each SQL statement of the job's transaction (`infra/db.py::
transaction()`), not the model call, which is client-side idle time to PostgreSQL and is bound by the
idle-in-transaction timeout the job raises as its first statement. The default of 3 s is for statements
that read a row or two; this job's decision history runs up to six aggregate queries over the alerts of
the last `RAG_HISTORY_DAYS` days, and the candidate search a full-text query over the entries.
"""

from __future__ import annotations

from app.rag.lookup import run_lookup_job

JOB_TYPE = "rag_lookup"
handle = run_lookup_job
STATEMENT_TIMEOUT = "10s"
