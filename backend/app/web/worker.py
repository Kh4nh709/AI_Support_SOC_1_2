"""The worker's composition root (P2-tasks.md planning decision 1) — `web/` may
import everything (context pack §4), so this is where the job-type -> handler
table is assembled. `infra/worker.py` names no handler and imports no tier
(G1); it exposes `run_forever(conn_factory, handlers, ...)` and this module
gives it a real one. `make run-worker` runs `python3 -m app.web.worker`.

`HANDLERS` and `TIMEOUTS` are discovered from `app.web.handlers`
(P5-tasks.md planning decision 1), not a dict literal: every module there
exposing `JOB_TYPE` and `handle` (optionally `STATEMENT_TIMEOUT`) mounts
itself — `pull`, `pipeline` and `triage` today, `investigate`/`digest`/
`health` arriving with their own tasks (P5+) by adding one module apiece,
touching no shared file.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence

from app.infra import config, db
from app.infra.jobs import enqueue
from app.infra.worker import run_forever
from app.web.handlers import iter_handlers, iter_timeouts

HANDLERS = iter_handlers()
TIMEOUTS = iter_timeouts()


def main(argv: Sequence[str]) -> None:
    config.load()  # fail fast on a bad environment before a connection is opened
    conn = db.connect()
    # Single-flight through the partial unique index (ux_jobs_mot_job_song_moi_subject)
    # — a no-op once one `pull` job is already pending/running.
    enqueue(conn, "pull", "indexer")
    conn.commit()
    run_forever(lambda: conn, HANDLERS, once="--once" in argv, timeouts=TIMEOUTS)


if __name__ == "__main__":
    main(sys.argv[1:])
