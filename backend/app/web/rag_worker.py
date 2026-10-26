"""The `rag-worker`'s composition root (P13-T03, DEC-210, spec §7.1): `python -m app.web.rag_worker`.

The same `infra.worker.run_forever` as `web/worker.py`, with the handlers of `app.web.rag_handlers`
only. It claims `rag_lookup` and `knowledge_draft` and nothing else, and it reclaims only those types
too (`run_forever` passes its handler keys to `reclaim_stale`, so it can never take back a `triage` or
an `investigate` job the main worker is still running).

It claims every due `rag_lookup` before any `knowledge_draft` (`CLAIM_ORDER`).

It seeds nothing. The main worker re-arms its chains (`pull`, `health`, `digest`) at every start;
a RAG job has no chain: a lookup is enqueued by the alert or the case that needs it, a draft by the
conclusion that is to be learned from.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence

from app.infra import config, db
from app.infra.worker import run_forever
from app.web.rag_handlers import iter_handlers, iter_timeouts

HANDLERS = iter_handlers()
TIMEOUTS = iter_timeouts()
#: A lookup is on every alert and ① reads it 45 s later, a draft is on a conclusion and waits as long as it
#: must: `claim_job` takes the oldest due job, so a burst of drafts would hold lookups until ① had run (P13 fix
#: wave, item 21). The worker claims a lookup first and a draft only when no lookup is due.
CLAIM_ORDER = [["rag_lookup"], ["knowledge_draft"]]


def main(argv: Sequence[str]) -> None:
    config.load()  # fail fast on a bad environment before a connection is opened
    conn = db.connect()
    run_forever(
        lambda: conn,
        HANDLERS,
        once="--once" in argv,
        timeouts=TIMEOUTS,
        claim_order=CLAIM_ORDER,
    )


if __name__ == "__main__":
    main(sys.argv[1:])
