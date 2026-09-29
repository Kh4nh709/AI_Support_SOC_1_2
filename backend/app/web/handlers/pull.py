"""`pull`'s handler, re-exported for `web/handlers/__init__.py`'s discovery
(P5-tasks.md planning decision 1). The tier code is `infra/puller.pull_job`;
this module claims no logic of its own.
"""

from __future__ import annotations

from app.infra.puller import pull_job

JOB_TYPE = "pull"
handle = pull_job
