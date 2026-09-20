"""The worker's composition root (P2-tasks.md planning decision 1) — `web/` may
import everything (context pack §4), so this is where the job-type -> handler
table is assembled. `infra/worker.py` names no handler and imports no tier
(G1); it exposes `run_forever(conn_factory, handlers, ...)` and this module
gives it a real one. `make run-worker` runs `python3 -m app.web.worker`.

Only `pull` and `pipeline` are wired here — `triage`/`investigate`/`digest`/
`health` arrive with their own tasks (P3+). Their absence from `HANDLERS`
just means `claim_job`'s `job_type = ANY(%s)` filter leaves those rows
untouched until then; nothing here needs to change when they land.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence

from app.infra import config, db
from app.infra.jobs import enqueue
from app.infra.puller import pull_job
from app.infra.worker import run_forever
from app.soar.pipeline import run_pipeline_job
from app.tier1.triage import run_triage_job

HANDLERS = {"pull": pull_job, "pipeline": run_pipeline_job, "triage": run_triage_job}


def main(argv: Sequence[str]) -> None:
    config.load()  # fail fast on a bad environment before a connection is opened
    conn = db.connect()
    # Single-flight through the partial unique index (ux_jobs_mot_job_song_moi_subject)
    # — a no-op once one `pull` job is already pending/running.
    enqueue(conn, "pull", "indexer")
    conn.commit()
    run_forever(lambda: conn, HANDLERS, once="--once" in argv)


if __name__ == "__main__":
    main(sys.argv[1:])
