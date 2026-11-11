"""Find alerts correlated with a given alert in a time window, for pipeline context and evidence.

One read-only entry point (phase-4 P4-2): `summarize_for_prompt` returns a grouped ±2h summary
plus up to five representative alerts, for P3's prompt builder to place outside an
`<untrusted_data>` block — every `CorrelationRow` field is closed-set, numeric or a datetime
(G6'); only the samples carry free text (`description`/`raw_log`), which P3 wraps. The window
and status predicates it runs are public too (`WINDOW_PREDICATE`, `STATUS_PREDICATE`,
`rows_query`, `samples_query`), for `tier2.dossier` and `eval/lab_measure.py`.

It runs only `SELECT`s inside a transaction the caller owns (E4). Correlation is context, never
membership: since T2 (DEC-215) `escalate` no longer folds the correlated open alerts into a case
(it used to, through a `correlated_cluster_ids` that is gone), so nothing here is ever written.

`as_of` (P14 final fix wave, C1; the lab measurement, `eval/lab_measure.py`): `rows_query`,
`samples_query` and `summarize_for_prompt` take an optional instant and then keep only the alerts
received STRICTLY before it (`RECEIVED_BEFORE_PREDICATE`, on `received_at`: "when did we hear about
it", the question for what a prompt could have shown at that instant, as opposed to the event-time
window above). A later stage of the same attack is then neither counted nor sampled. `None` — every
caller of the product — is the statement it has always been, text and parameters.

`alert` is duck-typed: anything exposing `.alert_id`, `.agent_name`, `.alert_user`,
`.srcip`, `.alert_time` works (`tier1.queue` and `tier1.triage` pass a lightweight subject of
their own, not a full `Alert`).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

import psycopg

#: The three-way OR + ±2h window + "still a cluster" + "not myself" predicate
#: shared by every query below (phase-4 P4-2 / phase-6 §Escalate, verbatim).
#: Windows on `alert_time` — event-time semantics, "when did this happen" —
#: never on the column P4-3 warns against (that one answers "when did we
#: hear about it", the wrong question for correlation).
WINDOW_PREDICATE = """(agent_name = %(agent_name)s OR alert_user = %(alert_user)s OR srcip = ANY(%(srcips)s::text[]))
      AND alert_time BETWEEN %(alert_time)s - interval '2 hours'
                         AND %(alert_time)s + interval '2 hours'
      AND duplicate_of IS NULL
      AND alert_id <> %(alert_id)s"""
_WINDOW_PREDICATE = (
    WINDOW_PREDICATE  # the name `tier2.dossier` and the queries below import and use
)

#: What the grouped rows and the samples leave out by status. A duplicate is counted in its head.
#: An `archived` alert (INT-T03, DEC-212) is the Owner's fresh start: it is neither a decision nor in
#: play, `AlertStatus` (the vocabulary of ①'s and ②'s prompts) has no such value, and a row carrying it
#: would not render.
STATUS_PREDICATE = "status NOT IN ('duplicate', 'archived')"
_STATUS_PREDICATE = STATUS_PREDICATE

#: The bound `as_of` adds (C1): an alert counts only if it had been received before that instant. Public,
#: with the two above, so `tier2.dossier` and `eval/lab_measure.py` use this one predicate and never a copy.
RECEIVED_BEFORE_PREDICATE = "received_at < %(as_of)s"
#: What the bounded statements append to the status predicate; `""` for `as_of=None`, which leaves the
#: statement byte for byte what it was.
_RECEIVED_BEFORE_CLAUSE = "\n          AND " + RECEIVED_BEFORE_PREDICATE


@dataclass(frozen=True)
class CorrelationRow:
    """One grouped row of `summarize_for_prompt` — closed-set, numeric or
    datetime only (G6'), safe outside an `<untrusted_data>` block.
    `cluster_count` = number of clusters (`duplicate_of IS NULL` rows) sharing
    `(rule_id, category, status)`; `alert_count` = the sum of their
    `occurrence_count`."""

    rule_id: str
    category: str
    status: str
    cluster_count: int
    alert_count: int
    first_seen: datetime
    last_seen: datetime
    src_ip_count: int


@dataclass(frozen=True)
class CorrelationSummary:
    """`rows`: up to 20 grouped rows (E5), ordered by `alert_count` desc.
    `samples`: up to 5 representative alerts as dicts, explicit column list —
    the only place `description`/`raw_log` (free text) appear."""

    rows: tuple[CorrelationRow, ...]
    samples: tuple[dict[str, Any], ...]


def _srcips(srcip: str) -> list[str]:
    """`[]` for an empty srcip (FIM/rootcheck's default) so it does not
    correlate every other empty-srcip alert in the window; `[srcip]` otherwise."""
    return [srcip] if srcip else []


def window_params(alert: Any) -> dict[str, Any]:
    return {
        "agent_name": alert.agent_name,
        "alert_user": alert.alert_user,
        "srcips": _srcips(alert.srcip),
        "alert_time": alert.alert_time,
        "alert_id": alert.alert_id,
    }


def _bounded(params: dict[str, Any], as_of: datetime | None) -> tuple[str, dict[str, Any]]:
    """`(the clause to append, the parameters)` for an optional `as_of`: nothing and the same dict for None."""
    if as_of is None:
        return "", params
    return _RECEIVED_BEFORE_CLAUSE, {**params, "as_of": as_of}


_params = window_params  # the private name `tier2.dossier` and the queries below use


def rows_query(alert: Any, *, as_of: datetime | None = None) -> tuple[str, dict[str, Any]]:
    """The grouped query `summarize_for_prompt` runs. Exposed (as
    `ingest.dedup.find_open_cluster_query` is) so the EXPLAIN test proves the
    predicate this module actually executes, not a retyped copy. With `as_of` it also
    requires `received_at < as_of` (module docstring); without, it is unchanged."""
    bound, params = _bounded(_params(alert), as_of)
    sql = f"""
        SELECT rule_id, category, status,
               count(*) AS cluster_count,
               sum(occurrence_count) AS alert_count,
               min(alert_time) AS first_seen,
               max(alert_time) AS last_seen,
               count(DISTINCT srcip) AS src_ip_count
        FROM alerts
        WHERE {_WINDOW_PREDICATE}
          AND {_STATUS_PREDICATE}{bound}
        GROUP BY rule_id, category, status
        ORDER BY sum(occurrence_count) DESC
        LIMIT 20
    """
    return sql, params


def samples_query(alert: Any, *, as_of: datetime | None = None) -> tuple[str, dict[str, Any]]:
    """Up to 5 representative alerts: the newest heads with the highest
    `occurrence_count` inside the same window (design note 1). With `as_of`, only
    those received before it."""
    bound, params = _bounded(_params(alert), as_of)
    sql = f"""
        SELECT alert_id, rule_id, category, severity, status, occurrence_count,
               alert_time, description, raw_log
        FROM alerts
        WHERE {_WINDOW_PREDICATE}
          AND {_STATUS_PREDICATE}{bound}
        ORDER BY occurrence_count DESC, alert_time DESC
        LIMIT 5
    """
    return sql, params


def summarize_for_prompt(
    conn: psycopg.Connection, alert: Any, *, as_of: datetime | None = None
) -> CorrelationSummary:
    """Grouped ±2h summary (up to 20 rows) plus up to 5 representative
    samples. Read-only (E4): two `SELECT`s inside the caller's transaction. With
    `as_of`, only alerts received before it (module docstring)."""
    sql, params = rows_query(alert, as_of=as_of)
    rows = tuple(
        CorrelationRow(
            rule_id=r[0],
            category=r[1],
            status=r[2],
            cluster_count=r[3],
            alert_count=r[4],
            first_seen=r[5],
            last_seen=r[6],
            src_ip_count=r[7],
        )
        for r in conn.execute(sql, params).fetchall()
    )

    sql, params = samples_query(alert, as_of=as_of)
    cur = conn.execute(sql, params)
    columns = [column.name for column in cur.description]
    samples = tuple(dict(zip(columns, row)) for row in cur.fetchall())

    return CorrelationSummary(rows=rows, samples=samples)
