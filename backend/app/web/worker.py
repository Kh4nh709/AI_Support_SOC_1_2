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

P5-T08 review round 1 · A2: `main()` also seeds/re-arms the digest chain on
every start (`digest.ensure_scheduled`) — idempotent, so a second start
enqueues nothing, and the Owner no longer has to run
`python3 -m app.tier1.digest --ensure` by hand. The Director lifted the
card's "no diff in worker.py" rule for this one line.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence

from app.infra import config, db
from app.infra.jobs import enqueue
from app.infra.worker import run_forever
from app.tier1 import digest
from app.web.handlers import iter_handlers, iter_timeouts

HANDLERS = iter_handlers()
TIMEOUTS = iter_timeouts()


def main(argv: Sequence[str]) -> None:
    cfg = config.load()  # fail fast on a bad environment before a connection is opened
    conn = db.connect()
    # Single-flight through the partial unique index (ux_jobs_mot_job_song_moi_subject)
    # — a no-op once one `pull` job is already pending/running, and a re-arm of
    # a dead chain on every restart otherwise.
    # DEC-207: with PULL_ENABLED=false alerts arrive by the webhook only, so no `pull` row is
    # seeded. A `pull` row already pending still finds its handler, which ends it after one
    # run without re-arming (`puller.pull_job`).
    if cfg.PULL_ENABLED:
        enqueue(conn, "pull", "indexer")
    # P5-T11 review round 1 seeding ruling: `health`'s subject_id is the
    # constant "system" (no per-job data) — re-enqueuing it here on every
    # worker start re-arms a dead `health` chain exactly as `pull`'s own does.
    enqueue(conn, "health", "system")
    # P5-T08 review round 1 · A2 — idempotent, same as both seeds above; the
    # Owner no longer has to run `python3 -m app.tier1.digest --ensure` by hand.
    digest.ensure_scheduled(conn)
    conn.commit()
    run_forever(lambda: conn, HANDLERS, once="--once" in argv, timeouts=TIMEOUTS)


if __name__ == "__main__":
    main(sys.argv[1:])
