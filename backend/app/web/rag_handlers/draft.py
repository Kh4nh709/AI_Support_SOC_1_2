"""`knowledge_draft`'s handler, re-exported for `web/rag_handlers/__init__.py`'s discovery (P13-T04).
The code is `rag.draft.run_draft_job`; this module claims no logic of its own — not a
`functools.partial` or a lambda, so its keyword-only `adapter` parameter stays what
`test_rag_draft.py` passes.

`STATEMENT_TIMEOUT = "10s"` bounds each SQL statement of the job's transaction (`infra/db.py::
transaction()`), not the model call, which is client-side idle time to PostgreSQL and is bound by the
idle-in-transaction timeout the job raises as its first statement. The default of 3 s is for statements
that read a row or two; this job builds the source record (a fingerprint, the inventory's hostnames,
the case's notes) and runs the candidate search, a full-text query over the entries.
"""

from __future__ import annotations

from app.rag.draft import run_draft_job

JOB_TYPE = "knowledge_draft"
handle = run_draft_job
STATEMENT_TIMEOUT = "10s"
