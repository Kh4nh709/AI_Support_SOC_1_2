"""`digest`'s handler, re-exported for `web/handlers/__init__.py`'s discovery
(P5-tasks.md planning decision 1). The tier code is
`tier1.digest.run_digest_job`; this module claims no logic of its own. No
`STATEMENT_TIMEOUT`: the build query plus its own re-arm fit comfortably in
the 3s default.
"""

from __future__ import annotations

from app.tier1.digest import run_digest_job

JOB_TYPE = "digest"
handle = run_digest_job
