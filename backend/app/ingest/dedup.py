"""Compute the cluster key and apply the dedup predicates under an advisory lock.

Three functions, called in this order by the pipeline (P2-T10) inside one
transaction — `cluster_lock` **before any read**, then `find_open_cluster`,
then `bump_parent` if a head came back (phase-2 §Thuật toán steps 1-3a, D4):

    with db.transaction(conn):              # SET LOCAL statement_timeout = '3s'
        dedup.cluster_lock(conn, rule_id, srcip, dstip, agent_name)
        head = dedup.find_open_cluster(conn, alert)
        if head is not None:
            occurrence = dedup.bump_parent(conn, head.alert_id)

What this module deliberately does NOT do: insert the duplicate row, write the
`alert.duplicate_merged` audit event, or move any `status`. Only `domain/` may
change a status (G2); `soar/pipeline.py` (P2-T10) drives the sequence and owns
the transaction, including the `statement_timeout` above.

THREE TRAPS PHASE-2 NAMES, AND HOW EACH IS CLOSED HERE.

1. The advisory lock is taken on the **cluster key**, never on the 5-minute
   bucket column. Two alerts of one cluster that fall in different buckets must
   still serialise; lock the bucket column instead and the race walks back in
   intact (D4). Nothing in this file reads that column.

2. The lock string is concatenated **in SQL**, not in Python, so two
   application versions running side by side derive one key from one set of
   parameters (phase-2 step 1). Assembling it in Python would make a rolling
   deploy lock two different key spaces at once.

3. `bump_parent` writes `last_seen_at = now()` — the **database** clock, B2/D9.
   Measured: an agent running an hour fast stretches its clusters by an hour,
   and an agent running an hour slow puts every cluster outside its own window
   the moment it is opened, which kills dedup outright with no error anywhere.
   There is no parameter for a timestamp, so no caller can pass one in.

`srcip`/`dstip` are `TEXT NOT NULL DEFAULT ''` (B1/D10), which is why all four
key columns are compared with plain `=`. The null-safe comparison operator was
measured at 154 buffers against 4 on a 500,000-row table: it does not reach
`Index Cond` when the address is non-empty, which is nearly all the traffic.
"""

from __future__ import annotations

from dataclasses import dataclass

import psycopg

from app.domain.alert import Alert
from app.infra import config
from app.infra.errors import PermanentError


@dataclass(frozen=True)
class ClusterHead:
    """The open cluster `find_open_cluster` found, row-locked `FOR UPDATE`.

    Four columns, named explicitly rather than selected with `*`: G10 forbids
    `SELECT *` on `alerts`, and the caller needs exactly these — `alert_id` to
    point the duplicate at and to bump, `occurrence_count` for the audit
    payload, `triaged_count` for the re-triage flag (phase-2 `RETRIAGE_FACTOR`),
    `status` because a head can legitimately be `auto_closed` or
    `escalated_tier2` and the caller behaves differently for each.
    """

    alert_id: str
    occurrence_count: int
    triaged_count: int
    status: str


#: Phase-2 step 1. The four values are parameters; the `'|'` separators and the
#: concatenation are the server's, so the key does not depend on the client.
CLUSTER_LOCK_SQL = (
    "SELECT pg_advisory_xact_lock(hashtext(%s || '|' || %s || '|' || %s || '|' || %s))"
)

#: Phase-2 step 2, verbatim — six predicates. The predicate text matches
#: `ix_alerts_dedup`'s syntactically, which is D7's condition for the partial
#: index to be usable; changing a character of the two index-predicate lines
#: below silently costs a sequential scan inside the lock region.
FIND_OPEN_CLUSTER_SQL = """\
SELECT alert_id, occurrence_count, triaged_count, status
FROM alerts
WHERE rule_id     = %s
  AND srcip       = %s
  AND agent_name  = %s
  AND dstip       = %s
  AND (closed_at IS NULL OR sealed_at IS NULL)
  AND status <> 'duplicate'
  AND last_seen_at >= now() - (%s || ' minutes')::interval
  AND first_seen_at >= now() - (CASE WHEN status = 'auto_closed'
                                THEN (%s || ' minutes')::interval
                                ELSE (%s || ' hours')::interval END)
  AND occurrence_count < %s
ORDER BY last_seen_at DESC
LIMIT 1
FOR UPDATE"""

#: Phase-2 step 3a ②. `now()` is the database's, and `GREATEST(...)` is gone
#: with it: `now()` only moves forward, so there is nothing to guard against.
#: `ck_alerts_last_seen_khong_lui` is the database's own backstop (D6).
BUMP_PARENT_SQL = """\
UPDATE alerts
   SET occurrence_count = occurrence_count + 1,
       last_seen_at     = now()
 WHERE alert_id = %s
RETURNING occurrence_count"""


def cluster_lock(
    conn: psycopg.Connection,
    rule_id: str,
    srcip: str,
    dstip: str,
    agent_name: str,
) -> None:
    """Take the transaction-scoped advisory lock for one cluster key.

    Call this at the top of the transaction, before any read (D4): the lock is
    what makes the read-then-write of steps 2-3 atomic against a second worker
    holding the same key. It is `xact`-scoped, so it is released by the
    caller's `COMMIT`/`ROLLBACK` and by nothing else — there is no unlock to
    forget. It blocks only alerts of the *same* cluster; everything else runs
    in parallel.

    A `None` in any of the four is refused rather than passed through:
    `hashtext(NULL)` is NULL, `pg_advisory_xact_lock(NULL)` takes no lock and
    raises nothing, and the caller would then run the whole dedup region
    unserialised believing it was protected. All four are `NOT NULL` columns
    (B1/D10), so a `None` here is a bug upstream, not a transient condition.
    """
    key = (rule_id, srcip, dstip, agent_name)
    if any(value is None for value in key):
        raise PermanentError(
            "cluster_lock: the four cluster-key values are NOT NULL by B1/D10; "
            f"got {key!r} — a NULL makes hashtext() NULL, and "
            "pg_advisory_xact_lock(NULL) takes no lock and raises nothing"
        )
    conn.execute(CLUSTER_LOCK_SQL, key)


def find_open_cluster_query(
    alert: Alert, cfg: config.Config | None = None
) -> tuple[str, tuple[object, ...]]:
    """The step-2 query and its parameters, exactly as `find_open_cluster` runs
    them.

    Public so the D7 `EXPLAIN` test can plan the query the product actually
    runs instead of a retyped copy. A copy would keep naming `ix_alerts_dedup`
    long after this module's predicate stopped matching the index — which is
    the single thing D7 exists to catch.

    The four ceilings are bound as parameters, never interpolated into the SQL.
    """
    cfg = config.load() if cfg is None else cfg
    return FIND_OPEN_CLUSTER_SQL, (
        alert.rule_id,
        alert.srcip,
        alert.agent_name,
        alert.dstip,
        cfg.DEDUP_IDLE_GAP_MINUTES,
        cfg.MAX_CLUSTER_AGE_AUTOCLOSED_MINUTES,
        cfg.MAX_CLUSTER_AGE_HOURS,
        cfg.MAX_CLUSTER_SIZE,
    )


def find_open_cluster(
    conn: psycopg.Connection, alert: Alert, cfg: config.Config | None = None
) -> ClusterHead | None:
    """The open cluster `alert` belongs to, row-locked, or `None`.

    `None` means every candidate failed at least one of the six predicates —
    most often a ceiling — and the caller opens a new cluster. There is no
    separate "ceiling reached" branch and no new status: falling out of the
    query *is* the branch (phase-2 "Khi chạm bất kỳ trần nào").

    Requires the lock from `cluster_lock` to already be held, and the caller's
    transaction to stay open until it is done with the head: the `FOR UPDATE`
    row lock dies with that transaction.
    """
    statement, params = find_open_cluster_query(alert, cfg)
    row = conn.execute(statement, params).fetchone()
    return None if row is None else ClusterHead(*row)


def bump_parent(conn: psycopg.Connection, parent_id: str) -> int:
    """Count one more alert onto the head and slide its window; return the new
    `occurrence_count`.

    `last_seen_at` comes from the database and only from the database (B2/D9) —
    the signature has nowhere to put a timestamp, deliberately.

    A head that is not there is a caller bug (it was just read `FOR UPDATE` in
    the same transaction, so it cannot have gone anywhere) and raises
    `PermanentError`: retrying the job three times would not conjure the row
    back.
    """
    row = conn.execute(BUMP_PARENT_SQL, (parent_id,)).fetchone()
    if row is None:
        raise PermanentError(f"bump_parent: no alerts row with alert_id {parent_id!r}")
    return int(row[0])
