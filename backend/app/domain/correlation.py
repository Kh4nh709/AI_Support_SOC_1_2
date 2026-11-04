"""Find alerts correlated with a given alert in a time window, for pipeline context and evidence.

Two read-only entry points (phase-4 P4-2, phase-6 §Escalate). `summarize_for_prompt`
returns a grouped ±2h summary plus up to five representative alerts, for P3's prompt
builder to place outside an `<untrusted_data>` block — every `CorrelationRow` field is
closed-set, numeric or a datetime (G6'); only the samples carry free text
(`description`/`raw_log`), which P3 wraps. `correlated_cluster_ids` returns the
status-filtered cluster ids P2-T06's `escalate` folds into a case.

Both functions run only `SELECT`s inside a transaction the caller owns (E4) —
correlation is never persisted here; `escalate` is the only place it is ever written,
into `case_alerts`, once an analyst has confirmed it is worth keeping.

`as_of` (P14 final fix wave, C1; the lab measurement, `eval/lab_measure.py`): `rows_query`,
`samples_query` and `summarize_for_prompt` take an optional instant and then keep only the alerts
received STRICTLY before it (`RECEIVED_BEFORE_PREDICATE`, on `received_at`: "when did we hear about
it", the question for what a prompt could have shown at that instant, as opposed to the event-time
window above). A later stage of the same attack is then neither counted nor sampled. `None` — every
caller of the product — is the statement it has always been, text and parameters.

`alert` is duck-typed: anything exposing `.alert_id`, `.agent_name`, `.alert_user`,
`.srcip`, `.alert_time` works (`domain.transitions.escalate` passes a lightweight
`_CorrelationSubject`, not a full `Alert`).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

import psycopg

from app.infra import config

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
#: would not render. `cluster_ids_query` needs no such term: it takes `queued_tier1` / `tier1_active` only.
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


def cluster_ids_query(alert: Any, limit: int, *, actor_id: str) -> tuple[str, dict[str, Any]]:
    """Phase-6 §Escalate's predicate plus a tie-break (DEC-165) and one exclusion (DEC-166).
    The WHERE clause is the doc's: `status IN (...)` is kept literal rather than named so a
    reviewer can diff it against the doc. The doc orders by `occurrence_count DESC` only; with
    `DEDUP_ENABLED=false` every head has `occurrence_count` 1, so at `MAX_ALERTS_PER_CASE` that
    alone would leave the choice of siblings to heap order. `alert_time DESC, alert_id ASC` after
    it keeps the newest first and makes the order total, hence deterministic.

    The exclusion: a `tier1_active` alert that someone other than `actor_id` acknowledged is not
    swept. It is in another analyst's hands, and escalating a sibling must not take it from them.
    The test is `IS DISTINCT FROM`, so a `tier1_active` row with no recorded holder is left alone
    too (A7 always records one, the schema does not insist): only an alert the escalating analyst
    holds, or one nobody holds yet (`queued_tier1`), is swept. It sits in the WHERE, ahead of the
    LIMIT, so an alert left alone never uses up a place at the cap."""
    sql = f"""
        SELECT alert_id
        FROM alerts
        WHERE {_WINDOW_PREDICATE}
          AND status IN ('queued_tier1', 'tier1_active')
          AND NOT (status = 'tier1_active' AND acknowledged_by IS DISTINCT FROM %(actor_id)s::uuid)
        ORDER BY occurrence_count DESC, alert_time DESC, alert_id ASC
        LIMIT %(limit)s
    """
    params = _params(alert)
    params["limit"] = limit
    params["actor_id"] = actor_id
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


def correlated_cluster_ids(conn: psycopg.Connection, alert: Any, *, actor_id: str) -> list[str]:
    """The cluster ids `escalate` (P2-T06) folds into a case, capped at
    `Config.MAX_ALERTS_PER_CASE`. Do not quote 200 as a routinely-binding
    limit (phase-6): it is a guard rail against a pathological cluster, not a
    cut analysts hit day to day. `actor_id` is the analyst who escalates: an alert
    another analyst holds is not returned (`cluster_ids_query`, DEC-166). Read-only (E4)."""
    limit = config.load().MAX_ALERTS_PER_CASE
    sql, params = cluster_ids_query(alert, limit, actor_id=actor_id)
    return [row[0] for row in conn.execute(sql, params).fetchall()]
