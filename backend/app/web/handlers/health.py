"""`health`'s handler, re-exported for `web/handlers/__init__.py`'s discovery
(P5-tasks.md planning decision 1). The tier code is `app.infra.health.check`;
this module wraps it in the job contract and keeps it self-perpetuating every
`_HEALTH_INTERVAL_S` (§6.5 "every 5 min"), the same `Reschedule` shape
`infra/puller.pull_job` uses for `pull`.

No `STATEMENT_TIMEOUT` here (P5-tasks.md §5: *"investigate declares '5s' and
nothing else does"*) — `health`'s ten checks stay under the worker's 3 s
default.
"""

from __future__ import annotations

from app.infra import config, health
from app.infra.config import Config
from app.infra.jobs import Job, Reschedule

JOB_TYPE = "health"

_HEALTH_INTERVAL_S = 300  # §6.5 "every 5 min"


def handle(conn, job: Job, *, cfg: Config | None = None) -> Reschedule:
    del job  # `health`'s subject_id is the constant "system" (P5-tasks.md §5); no per-job data
    cfg = cfg or config.load()
    health.check(conn, cfg)
    return Reschedule(_HEALTH_INTERVAL_S)
