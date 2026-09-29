"""`pipeline`'s handler, re-exported for `web/handlers/__init__.py`'s
discovery (P5-tasks.md planning decision 1). The tier code is
`soar/pipeline.run_pipeline_job`; this module claims no logic of its own.
"""

from __future__ import annotations

from app.soar.pipeline import run_pipeline_job

JOB_TYPE = "pipeline"
handle = run_pipeline_job
