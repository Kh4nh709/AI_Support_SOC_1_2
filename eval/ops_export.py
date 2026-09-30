"""P8-T01's operations export: what the system did online over one time window, read-only.

This command replaces the brief's `pilot_export.py` (DEC-129). One read-only transaction
produces one markdown file that describes the online operating period in numbers: intake and
dedup, the pull loop, pipeline ①'s online figures (the gate-forced rate included), auto-close.
Every figure names the query that produced it, and section 8 prints every query verbatim. Each
human-decision metric of architecture §6 is printed "not measured" with its missing
precondition, its DEC and the counted evidence, never as a zero.

**The human pilot (P10-T06).** With `--pilot-start` (and, to close the pilot, `--pilot-end`;
default the database's `now()`), section 6a computes the pilot's figures per arm (blind or
visible, DEC-101) and per source (`wazuh`, `lab`, all): decisions by type, the median
acknowledge → decide time on the database clock, and, on the blind arm only, ①'s agreement with
the human decision. ① is the suggestion as it was when the human decided: a `tier1.decided`
event's own payload (`llm_suggestion`), and, for a `tier1.escalated` event, which records none,
the latest proposer run created at or before it (a caveat line says a run in flight may be
included). ① `needs_review` is no verdict: it is left out of the agreement's denominator and
counted apart, and a small table crosses ①'s verdict with the human decision. The visible arm
never gets an agreement figure. Section 6's ② usefulness row is "not measured" in v1.0 (no
rating control, DEC-161), the `case.opened` count beside it being context. Without
`--pilot-start` the section prints "not measured: pilot start not given" and no pilot query
runs. The pilot has its own window: it is not the `--since`/`--until` window.

**Population (card design note 1).** Alert figures read `alerts` with `received_at` in the window
and `NOT is_synthetic`. `source` is not a filter: the lab-window heads are retagged
`source='lab'` (DEC-085), and they are the online traffic. G3's synthetic rows are counted on
one line and nowhere else. LLM figures read `llm_runs` with `pipeline='triage'` and `created_at`
in the window, joined to a non-synthetic alert. Event figures read `audit_events` with
`created_at` in the window, minus the events whose subject is a synthetic alert. Every window is
half-open, `[--since, --until)`, in UTC.

**The SQL is the citation (note 3).** Each query is one module-level `Query` constant, run once,
in `QUERIES` order, by `_Runner.run`, which records it. Section 8 prints the recorded list. No
other statement reaches the database through `build_report`.

**No free text, ever (note 4).** The file holds counts, identifiers, enums, category and agent
names, rule ids and timestamps. No query selects a description, a raw log or payload, a prompt,
a reason's quote or a text field of `result`/`gate_result`. **Undefined is not zero (note 5).**
A ratio over zero rows prints `n/a (0 rows)`. Rates carry 3 decimals, USD 5, milliseconds are
integers. No clock, hostname, DSN or path reaches the file, so two runs over the same window and
the same rows are byte-identical. No network, no model call.

Run from the repository root, with `PYTHONPATH=backend`::

    PYTHONPATH=backend python3 eval/ops_export.py --until 2026-10-01T00:00:00Z \\
        --pilot-start 2026-09-30T08:00:00Z --env-file .env --out docs/results/operations.md

Exit codes:
    0 written; 2 usage (an unparsable or inverted window, `--pilot-end` without `--pilot-start`,
    or no `--until`); 4 the DSN is unreadable.
"""

from __future__ import annotations

import argparse
import sys
import textwrap
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from fractions import Fraction
from pathlib import Path

# eval/ is a composition root outside backend/ and not a package on sys.path; its siblings are
# imported by name once the directory is on the path, as report.py does. `app.*` must be
# importable from the caller (PYTHONPATH=backend, or pytest's pythonpath).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_gold import DEC111_SENTENCE  # limitation (xii), imported, never retyped
from metrics import EVIDENCE_TARGET  # architecture §6: the evidence-verified rate targets ≥ 0.90

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_DSN = 4

#: `--since`'s default: the database reset of DEC-113.
DEFAULT_SINCE = "2026-09-26T00:00:00Z"
DEFAULT_OUT = "docs/results/operations.md"

#: The one sentence the header carries (card design note 2, item 1).
DESCRIPTIVE_SENTENCE = (
    "Descriptive: an operating record, not a controlled experiment (architecture §6)."
)
#: Architecture §6: a gate-forced rate above 60 % must be stated as the gate squeezing ①.
SQUEEZE_ABOVE = Fraction(3, 5)
SQUEEZE_SENTENCE = "the gate is squeezing ①"
R5_SENTENCE = (
    "R5 (architecture §9): the gate forces `needs_review` above 60 % because the inventory is "
    "sparse."
)
#: The read-only transaction every CLI run uses: one snapshot, so the figures agree.
READ_ONLY_STATEMENT = "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"

NA = "n/a (0 rows)"
#: What the pilot window's end reads as when `--pilot-end` is not given. Never a timestamp: the
#: file carries no run clock (two runs over the same rows are byte-identical).
PILOT_END_CLOCK = "the database clock at the run"
NO_PILOT_START = "not measured: pilot start not given"


class Exit(Exception):
    """A controlled CLI exit carrying a POSIX code and a message for stderr."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Query:
    """One query: its citation id, a title for the appendix, and the SQL that runs, verbatim."""

    qid: str
    title: str
    sql: str


@dataclass(frozen=True)
class Window:
    """The half-open UTC window `[since, until)` every figure is taken over."""

    since: datetime
    until: datetime

    @property
    def params(self) -> dict[str, datetime]:
        return {"since": self.since, "until": self.until}

    def __str__(self) -> str:
        return f"[{_ts(self.since)}, {_ts(self.until)})"


@dataclass(frozen=True)
class PilotWindow:
    """The half-open UTC window `[start, end)` the human pilot's figures are taken over. `end` is
    None when `--pilot-end` is not given: the queries then read the database's `now()`, which is
    the start of the read-only transaction, so every figure sees one instant."""

    start: datetime
    end: datetime | None = None

    @property
    def params(self) -> dict[str, datetime | None]:
        return {"pilot_start": self.start, "pilot_end": self.end}

    def __str__(self) -> str:
        return f"[{_ts(self.start)}, {_ts(self.end) if self.end else PILOT_END_CLOCK})"


# --- the queries: one constant each, in the order they run and the document cites them ---------


def _between(column: str) -> str:
    return f"{column} >= %(since)s AND {column} < %(until)s"


# Card design note 1: the alert population. `source` is deliberately not a filter (DEC-085).
_ALERTS = f"""FROM alerts a
WHERE {_between('a.received_at')}
  AND NOT a.is_synthetic"""
_HEADS = f"{_ALERTS}\n  AND a.duplicate_of IS NULL"
# ①'s rows: the triage pipeline, in the window, about a non-synthetic alert.
_RUNS_FROM = """FROM llm_runs r
JOIN alerts a ON a.alert_id = r.subject_id AND NOT a.is_synthetic"""
_RUNS_WHERE = f"""WHERE r.pipeline = 'triage'
  AND {_between('r.created_at')}"""
# The rows where the gate ran: a proposer row that no failure class stopped (`stopped_by` NULL).
_GATE_RAN = """  AND r.role = 'proposer'
  AND r.stopped_by IS NULL"""
_EVENTS_WHERE = f"""  AND {_between('e.created_at')}
  AND NOT EXISTS (SELECT 1 FROM alerts s WHERE s.alert_id = e.subject_id AND s.is_synthetic)"""

Q_SYNTHETIC = Query(
    "Q01",
    "synthetic rows in the window, excluded from every other figure",
    f"""SELECT count(*) AS synthetic
FROM alerts a
WHERE {_between('a.received_at')}
  AND a.is_synthetic""",
)
Q_INTAKE = Query(
    "Q02",
    "intake rows by via and outcome",
    f"""SELECT i.via, i.outcome, count(*) AS n
FROM intake i
WHERE {_between('i.received_at')}
GROUP BY i.via, i.outcome
ORDER BY i.via, i.outcome NULLS FIRST""",
)
Q_INTAKE_LATENCY = Query(
    "Q03",
    "intake latency, processed_at - received_at",
    f"""SELECT count(*) AS n,
       count(t.ms) AS processed,
       percentile_disc(0.5) WITHIN GROUP (ORDER BY t.ms) AS p50_ms,
       percentile_disc(0.95) WITHIN GROUP (ORDER BY t.ms) AS p95_ms,
       max(t.ms) AS max_ms,
       count(*) FILTER (WHERE t.over_60s) AS over_60s
FROM (
  SELECT round(extract(epoch FROM i.processed_at - i.received_at) * 1000)::bigint AS ms,
         i.processed_at - i.received_at > interval '60 seconds' AS over_60s
  FROM intake i
  WHERE {_between('i.received_at')}
) t""",
)
Q_REJECTED = Query(
    "Q04",
    "rejected_alerts rows",
    f"""SELECT count(*) AS n
FROM rejected_alerts x
WHERE {_between('x.received_at')}""",
)
Q_AGENTS = Query(
    "Q05",
    "alerts by source and agent_name",
    f"""SELECT a.source, a.agent_name, count(*) AS alerts,
       count(*) FILTER (WHERE a.duplicate_of IS NULL) AS heads
{_ALERTS}
GROUP BY a.source, a.agent_name
ORDER BY a.source, a.agent_name""",
)
Q_HEADS = Query(
    "Q06",
    "heads, duplicates merged, max occurrence_count",
    f"""SELECT count(*) AS alerts,
       count(*) FILTER (WHERE a.duplicate_of IS NULL) AS heads,
       count(*) FILTER (WHERE a.duplicate_of IS NOT NULL) AS duplicates,
       max(a.occurrence_count) FILTER (WHERE a.duplicate_of IS NULL) AS max_occurrence_count
{_ALERTS}""",
)
Q_PULL = Query(
    "Q07",
    "pull jobs by status",
    f"""SELECT j.status, count(*) AS n
FROM jobs j
WHERE j.job_type = 'pull'
  AND {_between('j.scheduled_at')}
GROUP BY j.status
ORDER BY j.status""",
)
Q_PULL_GAP = Query(
    "Q08",
    "largest gap between consecutive succeeded pull jobs",
    f"""WITH s AS (
  SELECT j.scheduled_at,
         lag(j.scheduled_at) OVER (ORDER BY j.scheduled_at, j.job_id) AS previous_at
  FROM jobs j
  WHERE j.job_type = 'pull'
    AND j.status = 'succeeded'
    AND {_between('j.scheduled_at')}
)
SELECT (SELECT count(*) FROM s) AS succeeded,
       round(extract(epoch FROM g.scheduled_at - g.previous_at) * 1000)::bigint AS gap_ms,
       g.previous_at AS gap_from,
       g.scheduled_at AS gap_to
FROM (SELECT 1) AS one
LEFT JOIN (
  SELECT s.scheduled_at, s.previous_at
  FROM s
  WHERE s.previous_at IS NOT NULL
  ORDER BY s.scheduled_at - s.previous_at DESC, s.scheduled_at
  LIMIT 1
) AS g ON true""",
)
Q_CURSOR = Query(
    "Q09",
    "source_cursor at the run (not windowed)",
    """SELECT c.manager_id, c.last_error IS NULL AS last_error_is_null
FROM source_cursor c
ORDER BY c.manager_id""",
)
Q_EXHAUSTED = Query(
    "Q10",
    "job.exhausted events",
    f"""SELECT count(*) AS n
FROM audit_events e
WHERE e.event_type = 'job.exhausted'
{_EVENTS_WHERE}""",
)
Q_STOPPED_BY = Query(
    "Q11",
    "proposer rows by stopped_by (NULL: the gate ran)",
    f"""SELECT r.stopped_by, count(*) AS n
{_RUNS_FROM}
{_RUNS_WHERE}
  AND r.role = 'proposer'
GROUP BY r.stopped_by
ORDER BY r.stopped_by NULLS FIRST""",
)
Q_VERDICT = Query(
    "Q12",
    "final verdict over the rows where the gate ran",
    f"""SELECT r.gate_result->>'final_verdict' AS final_verdict, count(*) AS n
{_RUNS_FROM}
{_RUNS_WHERE}
{_GATE_RAN}
GROUP BY final_verdict
ORDER BY final_verdict NULLS FIRST""",
)
Q_GATE = Query(
    "Q13",
    "gate-forced rate, hallucination flag, evidence-verified reasons",
    f"""SELECT count(*) AS gate_ran,
       count(*) FILTER (WHERE (r.gate_result->>'forced')::boolean) AS forced,
       count(*) FILTER (WHERE (r.gate_result->>'hallucination_flag')::boolean) AS hallucination,
       coalesce(sum(jsonb_array_length(r.result->'reasons')), 0) AS reasons_surviving,
       coalesce(sum(jsonb_array_length(r.gate_result->'dropped_reasons')), 0) AS reasons_dropped
{_RUNS_FROM}
{_RUNS_WHERE}
{_GATE_RAN}""",
)
Q_FORCED_BY = Query(
    "Q14",
    "forced_by, per step",
    f"""SELECT f.step, count(*) AS n
{_RUNS_FROM}
CROSS JOIN LATERAL jsonb_array_elements_text(r.gate_result->'forced_by') AS f(step)
{_RUNS_WHERE}
{_GATE_RAN}
GROUP BY f.step
ORDER BY f.step""",
)
Q_STEP6 = Query(
    "Q15",
    "verifier, gate step 6",
    f"""SELECT r.gate_result->'steps'->>'6' AS step6, count(*) AS n
{_RUNS_FROM}
{_RUNS_WHERE}
{_GATE_RAN}
GROUP BY step6
ORDER BY step6 NULLS FIRST""",
)
Q_LATENCY_ROLE = Query(
    "Q16",
    "latency per role",
    f"""SELECT r.role, count(r.latency_ms) AS n,
       percentile_disc(0.5) WITHIN GROUP (ORDER BY r.latency_ms) AS p50_ms,
       percentile_disc(0.95) WITHIN GROUP (ORDER BY r.latency_ms) AS p95_ms
{_RUNS_FROM}
{_RUNS_WHERE}
GROUP BY r.role
ORDER BY r.role""",
)
Q_LATENCY_ALERT = Query(
    "Q17",
    "latency per alert, proposer + verifier summed by subject_id",
    f"""SELECT count(t.ms) AS alerts,
       percentile_disc(0.5) WITHIN GROUP (ORDER BY t.ms) AS p50_ms,
       percentile_disc(0.95) WITHIN GROUP (ORDER BY t.ms) AS p95_ms
FROM (
  SELECT r.subject_id, sum(r.latency_ms) AS ms
{textwrap.indent(_RUNS_FROM, '  ')}
{textwrap.indent(_RUNS_WHERE, '  ')}
  GROUP BY r.subject_id
) t""",
)
Q_COST = Query(
    "Q18",
    "cost_usd, total and alerts with a run",
    f"""SELECT coalesce(sum(r.cost_usd), 0) AS cost_usd,
       count(DISTINCT r.subject_id) AS alerts
{_RUNS_FROM}
{_RUNS_WHERE}""",
)
Q_MODEL = Query(
    "Q19",
    "model_id by role",
    f"""SELECT r.role, r.model_id, count(*) AS n
{_RUNS_FROM}
{_RUNS_WHERE}
GROUP BY r.role, r.model_id
ORDER BY r.role, r.model_id NULLS FIRST""",
)
Q_PROMPT = Query(
    "Q20",
    "prompt_version by role",
    f"""SELECT r.role, r.prompt_version, count(*) AS n
{_RUNS_FROM}
{_RUNS_WHERE}
GROUP BY r.role, r.prompt_version
ORDER BY r.role, r.prompt_version NULLS FIRST""",
)
Q_TRIAGE_STATUS = Query(
    "Q21",
    "triage_status of the heads",
    f"""SELECT a.triage_status, count(*) AS n
{_HEADS}
GROUP BY a.triage_status
ORDER BY a.triage_status""",
)
Q_AUTOCLOSE_EVENTS = Query(
    "Q22",
    "auto-close events",
    f"""SELECT count(*) FILTER (WHERE e.event_type = 'alert.auto_closed') AS auto_closed,
       count(*) FILTER (WHERE e.event_type = 'alert.autoclose_blocked_critical') AS blocked
FROM audit_events e
WHERE e.event_type IN ('alert.auto_closed', 'alert.autoclose_blocked_critical')
{_EVENTS_WHERE}""",
)
Q_AUTOCLOSE_HEADS = Query(
    "Q23",
    "heads closed by an auto-close rule, per rule id",
    f"""SELECT a.autoclose_rule_id, count(*) AS n
{_HEADS}
  AND a.autoclose_rule_id IS NOT NULL
GROUP BY a.autoclose_rule_id
ORDER BY a.autoclose_rule_id""",
)
Q_HUMAN_EVENTS = Query(
    "Q24",
    "human-decision evidence: tier1.decided, alert.acknowledged, autoclose.reviewed, case.opened",
    f"""SELECT count(*) FILTER (WHERE e.event_type = 'tier1.decided') AS tier1_decided,
       count(*) FILTER (WHERE e.event_type = 'alert.acknowledged') AS alert_acknowledged,
       count(*) FILTER (WHERE e.event_type = 'autoclose.reviewed') AS autoclose_reviewed,
       count(*) FILTER (WHERE e.event_type = 'case.opened') AS case_opened
FROM audit_events e
WHERE e.event_type IN ('tier1.decided', 'alert.acknowledged', 'autoclose.reviewed', 'case.opened')
{_EVENTS_WHERE}""",
)
Q_REVIEWS = Query(
    "Q25",
    "autoclose_reviews rows",
    f"""SELECT count(*) AS n
FROM autoclose_reviews v
JOIN alerts a ON a.alert_id = v.alert_id AND NOT a.is_synthetic
WHERE {_between('v.reviewed_at')}""",
)
Q_BRANCHES = Query(
    "Q26",
    "branch sizes over the heads (suggestion_visible)",
    f"""SELECT count(*) FILTER (WHERE NOT a.suggestion_visible) AS blind,
       count(*) FILTER (WHERE a.suggestion_visible) AS visible
{_HEADS}""",
)
Q_LABEL_EVENTS = Query(
    "Q27",
    "label.created events (P6 labelling)",
    f"""SELECT count(*) AS label_created,
       count(*) FILTER (WHERE e.payload->>'undo' = 'true') AS undo
FROM audit_events e
WHERE e.event_type = 'label.created'
{_EVENTS_WHERE}""",
)
Q_LABELS = Query(
    "Q28",
    "triage_labels rows by source (P6 labelling)",
    f"""SELECT l.source, count(*) AS n
FROM triage_labels l
JOIN alerts a ON a.alert_id = l.alert_id AND NOT a.is_synthetic
WHERE {_between('l.created_at')}
GROUP BY l.source
ORDER BY l.source""",
)

# --- the pilot's queries (section 6a): they run only when `--pilot-start` is given ---------------
#
# The pilot has its own half-open window `[%(pilot_start)s, %(pilot_end)s)` on `audit_events.
# created_at`, the database clock; a NULL end reads as the transaction's `now()`. Alerts are not
# windowed by `received_at`: an alert received before the pilot and decided in it is a pilot
# decision. Synthetic alerts are excluded, as everywhere in this file. The three CTEs below are
# text pasted into each query that needs them, so every query stays self-contained in section 8.

_PILOT_END = "coalesce(%(pilot_end)s::timestamptz, now())"
# One row per human decision: `tier1.decided` (payload `decision`: closed_fp, closed_benign) or
# `tier1.escalated`, about a non-synthetic alert. The arm is `alerts.suggestion_visible` (DEC-101).
# `recorded_suggestion` is what `transitions.decide` wrote into the event: ① as the console had it
# when the analyst decided (NULL: no result then, or an escalation, whose payload has no ①).
_PILOT_DECISIONS = f"""d AS (
  SELECT e.subject_id AS alert_id,
         e.actor_id,
         e.created_at AS decided_at,
         CASE WHEN e.event_type = 'tier1.escalated' THEN 'escalated'
              WHEN e.payload->>'decision' = 'closed_fp' THEN 'false_positive'
              WHEN e.payload->>'decision' = 'closed_benign' THEN 'benign'
         END AS decision,
         CASE WHEN a.suggestion_visible THEN 'visible' ELSE 'blind' END AS arm,
         a.source,
         e.payload->>'llm_suggestion' AS recorded_suggestion
  FROM audit_events e
  JOIN alerts a ON a.alert_id = e.subject_id AND NOT a.is_synthetic
  WHERE e.created_at >= %(pilot_start)s
    AND e.created_at < {_PILOT_END}
    AND (e.event_type = 'tier1.escalated'
         OR (e.event_type = 'tier1.decided'
             AND e.payload->>'decision' IN ('closed_fp', 'closed_benign')))
)"""
# Each decision with its alert's latest `alert.acknowledged` at or after the pilot start and not
# after the decision, or NULL: a decision whose acknowledge is outside the window is counted, not
# timed.
_PILOT_TIMED = """t AS (
  SELECT d.arm, d.source, d.actor_id, d.decision, d.decided_at, k.acked_at
  FROM d
  LEFT JOIN LATERAL (
    SELECT max(x.created_at) AS acked_at
    FROM audit_events x
    WHERE x.event_type = 'alert.acknowledged'
      AND x.subject_id = d.alert_id
      AND x.created_at >= %(pilot_start)s
      AND x.created_at <= d.decided_at
  ) k ON true
)"""
# The blind arm's decisions, each with ① as it was when the human decided (`verdict`: escalate,
# false_positive, needs_review, or no_result). A `tier1.decided` event recorded ① in its payload,
# so that is what is read: a proposer row created before the decision but committed after it (a
# triage job in flight) was never on the analyst's console, and `created_at` cannot tell. A
# `tier1.escalated` event records none, so ① is the alert's latest proposer row created at or before
# the decision, which may include a run in flight at that moment (the caveat printed in section 6a).
# A latest row whose `result` is NULL, or a payload with no `llm_suggestion`, is `no_result`.
_PILOT_VERDICT = """v AS (
  SELECT x.source,
         x.decision,
         CASE WHEN x.suggested_action IN ('escalate', 'false_positive', 'needs_review')
              THEN x.suggested_action
              ELSE 'no_result'
         END AS verdict
  FROM (
    SELECT d.source,
           d.decision,
           CASE WHEN d.decision = 'escalated'
                THEN (SELECT r.result->>'suggested_action'
                      FROM llm_runs r
                      WHERE r.pipeline = 'triage'
                        AND r.role = 'proposer'
                        AND r.subject_id = d.alert_id
                        AND r.created_at <= d.decided_at
                      ORDER BY r.created_at DESC, r.run_id DESC
                      LIMIT 1)
                ELSE d.recorded_suggestion
           END AS suggested_action
    FROM d
    WHERE d.arm = 'blind'
  ) x
)"""


def _pilot_source(alias: str) -> str:
    return f"CASE WHEN GROUPING({alias}.source) = 1 THEN 'all' ELSE {alias}.source END AS source"


def _pilot_types(alias: str) -> str:
    return f"""count(*) FILTER (WHERE {alias}.decision = 'false_positive') AS false_positive,
       count(*) FILTER (WHERE {alias}.decision = 'benign') AS benign,
       count(*) FILTER (WHERE {alias}.decision = 'escalated') AS escalated,
       count(*) AS decisions"""


_PILOT_MEDIAN = """extract(epoch FROM percentile_cont(0.5)
         WITHIN GROUP (ORDER BY t.decided_at - t.acked_at))::numeric AS median_seconds,
       count(t.acked_at) AS acknowledged"""

Q_PILOT_DECISIONS = Query(
    "Q29",
    "pilot: human decisions by type, per arm and source",
    f"""WITH {_PILOT_DECISIONS}
SELECT d.arm,
       {_pilot_source('d')},
       {_pilot_types('d')}
FROM d
GROUP BY d.arm, ROLLUP (d.source)
ORDER BY d.arm, GROUPING(d.source), d.source""",
)
Q_PILOT_MEDIAN = Query(
    "Q30",
    "pilot: median acknowledge → decide, per arm and source",
    f"""WITH {_PILOT_DECISIONS},
{_PILOT_TIMED}
SELECT t.arm,
       {_pilot_source('t')},
       {_PILOT_MEDIAN},
       count(*) AS decisions
FROM t
GROUP BY t.arm, ROLLUP (t.source)
ORDER BY t.arm, GROUPING(t.source), t.source""",
)
Q_PILOT_AGREEMENT = Query(
    "Q31",
    "pilot: ① agreement with the human decision, blind arm only",
    f"""WITH {_PILOT_DECISIONS},
{_PILOT_VERDICT}
SELECT {_pilot_source('v')},
       count(*) AS decisions,
       count(*) FILTER (WHERE v.verdict = 'needs_review') AS needs_review,
       count(*) FILTER (WHERE v.verdict = 'no_result') AS no_result,
       count(*) FILTER (WHERE v.verdict IN ('escalate', 'false_positive')) AS denominator,
       count(*) FILTER (WHERE (v.verdict = 'escalate' AND v.decision = 'escalated')
                           OR (v.verdict = 'false_positive'
                               AND v.decision = 'false_positive')) AS agreed
FROM v
GROUP BY ROLLUP (v.source)
ORDER BY GROUPING(v.source), v.source""",
)
Q_PILOT_PERSON = Query(
    "Q32",
    "pilot: decisions and median acknowledge → decide, per person, arm and source",
    f"""WITH {_PILOT_DECISIONS},
{_PILOT_TIMED}
SELECT t.actor_id,
       t.arm,
       {_pilot_source('t')},
       {_pilot_types('t')},
       {_PILOT_MEDIAN}
FROM t
GROUP BY t.actor_id, t.arm, ROLLUP (t.source)
ORDER BY t.actor_id, t.arm, GROUPING(t.source), t.source""",
)
Q_PILOT_CROSS = Query(
    "Q33",
    "pilot: ① verdict × human decision, blind arm only",
    f"""WITH {_PILOT_DECISIONS},
{_PILOT_VERDICT}
SELECT {_pilot_source('v')},
       v.verdict,
       {_pilot_types('v')}
FROM v
GROUP BY ROLLUP (v.source), v.verdict
ORDER BY GROUPING(v.source), v.source, v.verdict""",
)

#: The pilot's queries, run after `QUERIES`, and only when `--pilot-start` is given.
PILOT_QUERIES: tuple[Query, ...] = (
    Q_PILOT_DECISIONS,
    Q_PILOT_MEDIAN,
    Q_PILOT_AGREEMENT,
    Q_PILOT_PERSON,
    Q_PILOT_CROSS,
)

#: Every query, in the order `collect` runs it and the document cites it.
QUERIES: tuple[Query, ...] = (
    Q_SYNTHETIC,
    Q_INTAKE,
    Q_INTAKE_LATENCY,
    Q_REJECTED,
    Q_AGENTS,
    Q_HEADS,
    Q_PULL,
    Q_PULL_GAP,
    Q_CURSOR,
    Q_EXHAUSTED,
    Q_STOPPED_BY,
    Q_VERDICT,
    Q_GATE,
    Q_FORCED_BY,
    Q_STEP6,
    Q_LATENCY_ROLE,
    Q_LATENCY_ALERT,
    Q_COST,
    Q_MODEL,
    Q_PROMPT,
    Q_TRIAGE_STATUS,
    Q_AUTOCLOSE_EVENTS,
    Q_AUTOCLOSE_HEADS,
    Q_HUMAN_EVENTS,
    Q_REVIEWS,
    Q_BRANCHES,
    Q_LABEL_EVENTS,
    Q_LABELS,
)


# --- architecture §6's online metrics that need a human-decision pilot -------------------------


@dataclass(frozen=True)
class HumanMetric:
    """One architecture §6 online metric that only a human-decision pilot can produce. The first
    evidence key is the metric's own n; every key's count is printed in the basis. `never` is the
    value of a metric that cannot be measured in this release whatever its evidence counts: its
    counts are context, printed in the basis and never as an n."""

    metric: str
    missing: str
    because: str
    evidence: tuple[str, ...]
    never: str = ""


#: Rows 0-2 without `--pilot-start`: what is missing, and where the figure comes from.
_NO_START = "pilot start not given"
_PASS_START = "pass `--pilot-start` for the pilot's figures (section 6a)"

HUMAN_METRICS: tuple[HumanMetric, ...] = (
    HumanMetric(
        "Decisions by branch (blind / visible) and by person", _NO_START, _PASS_START, ("tier1",)
    ),
    HumanMetric("Median acknowledge → decide, by branch", _NO_START, _PASS_START, ("tier1", "ack")),
    HumanMetric(
        "① agreement with human decisions, blind branch only", _NO_START, _PASS_START, ("tier1",)
    ),
    HumanMetric(
        "Auto-close wrong-close rate from the digest, with its Wilson CI",
        "no digest review ran",
        "live since P5 (DEC-154)",
        ("reviews", "reviewed"),
    ),
    HumanMetric(
        "② usefulness, 1–5",
        "no ② rating recorded",
        "built and run, no rating control in v1.0 (DEC-154, DEC-161)",
        ("case",),
        never="not measured: no rating control in v1.0 (DEC-161)",
    ),
)
GATE_FORCED_METRIC = "Gate-forced `needs_review` rate"
#: Evidence key -> how its count is named in a basis, with the query that counted it.
_EVIDENCE_LABEL: dict[str, str] = {
    "tier1": f"`tier1.decided` = {{}} ({Q_HUMAN_EVENTS.qid})",
    "ack": f"`alert.acknowledged` = {{}} ({Q_HUMAN_EVENTS.qid})",
    "reviewed": f"`autoclose.reviewed` = {{}} ({Q_HUMAN_EVENTS.qid})",
    "case": f"`case.opened` = {{}} ({Q_HUMAN_EVENTS.qid})",
    "reviews": f"`autoclose_reviews` rows = {{}} ({Q_REVIEWS.qid})",
}


# --- running and recording ---------------------------------------------------------------------


def _execute(conn, sql: str, params: Mapping[str, object]) -> list[tuple]:
    """The one place a query reaches the database."""
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


@dataclass
class _Runner:
    """Runs a `Query` and records it, so the appendix is the list of what actually ran."""

    conn: object
    window: Window
    pilot: PilotWindow | None = None
    ran: list[Query] = field(default_factory=list)
    results: dict[str, list[tuple]] = field(default_factory=dict)

    def run(self, query: Query, params: Mapping[str, object] | None = None) -> list[tuple]:
        self.ran.append(query)
        rows = _execute(self.conn, query.sql, self.window.params if params is None else params)
        self.results[query.qid] = rows
        return rows


def collect(conn, window: Window, pilot: PilotWindow | None = None) -> _Runner:
    """Run every query once, in `QUERIES` order, on `conn`, then, when `pilot` is given, the
    `PILOT_QUERIES` on the pilot window. Sets nothing on the connection: the CLI's own
    connection is read-only (`_connect_readonly`); a test passes its own."""
    runner = _Runner(conn, window, pilot)
    for query in QUERIES:
        runner.run(query)
    if pilot is not None:
        for query in PILOT_QUERIES:
            runner.run(query, pilot.params)
    return runner


# --- formatting: fixed decimals, undefined is not zero -----------------------------------------


def _ts(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _cell(value: object) -> str:
    if value is None:
        return "(null)"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, datetime):
        return _ts(value)
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _rate(num: int, den: int) -> str:
    return NA if not den else f"{num / den:.3f} ({num} / {den})"


def _ms(value: object) -> str:
    return NA if value is None else f"{int(value)} ms"


def _minutes(seconds: object) -> str:
    return NA if seconds is None else f"{Decimal(seconds) / 60:.2f} min"


def _usd(value: Decimal) -> str:
    return f"{value:.5f} USD"


def _count_or_na(value: object) -> str:
    return NA if value is None else str(value)


def _table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
    if not rows:
        return "(no rows)"
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines.extend("| " + " | ".join(_cell(v) for v in row) + " |" for row in rows)
    return "\n".join(lines)


def _squeezed(forced: int, gate_ran: int) -> bool:
    return gate_ran > 0 and Fraction(forced, gate_ran) > SQUEEZE_ABOVE


# --- rendering ---------------------------------------------------------------------------------


def _header(window: Window, res: Mapping[str, list[tuple]]) -> list[str]:
    synthetic = res[Q_SYNTHETIC.qid][0][0]
    return [
        f"# Operations export — {_ts(window.since)} to {_ts(window.until)}",
        "",
        "## 1 · Window, caveats and population",
        "",
        (
            f"- Window: `{window}`, half-open, UTC. The window is this document's identity: it "
            "carries no run timestamp."
        ),
        f"- {DEC111_SENTENCE}",
        f"- {DESCRIPTIVE_SENTENCE}",
        (
            "- Population: `alerts` with `received_at` in the window and `NOT is_synthetic`; "
            "`source` is not a filter (the lab-window heads are retagged `source='lab'`, "
            "DEC-085). LLM figures: `llm_runs` with `pipeline='triage'` and `created_at` in the "
            "window, joined to a non-synthetic alert. Event figures: `audit_events` with "
            "`created_at` in the window, minus the events about a synthetic alert."
        ),
        f"- synthetic rows in the window, excluded: {synthetic} ({Q_SYNTHETIC.qid})",
        (
            "- Every figure names the query that produced it (`Qnn`). Section 8 prints each "
            "query verbatim, in the order it ran."
        ),
    ]


def _intake_section(res: Mapping[str, list[tuple]]) -> list[str]:
    n, processed, p50, p95, max_ms, over_60s = res[Q_INTAKE_LATENCY.qid][0]
    alerts, heads, duplicates, max_occurrence = res[Q_HEADS.qid][0]
    return [
        "## 2 · Intake and dedup",
        "",
        f"### `intake` rows by `via` and `outcome` ({Q_INTAKE.qid})",
        "",
        _table(["via", "outcome", "rows"], res[Q_INTAKE.qid]),
        "",
        f"### Intake latency, `processed_at − received_at` ({Q_INTAKE_LATENCY.qid})",
        "",
        f"- intake rows: {n}",
        f"- with `processed_at`: {processed}",
        f"- without `processed_at` at the run: {n - processed}",
        f"- p50: {_ms(p50)}",
        f"- p95: {_ms(p95)}",
        f"- max: {_ms(max_ms)}",
        f"- over 60 s (G12's bound): {over_60s}",
        "",
        f"### Rejected ({Q_REJECTED.qid})",
        "",
        f"- `rejected_alerts` rows: {res[Q_REJECTED.qid][0][0]}",
        "",
        f"### `alerts` by `source` and `agent_name` ({Q_AGENTS.qid})",
        "",
        _table(["source", "agent_name", "alerts", "heads"], res[Q_AGENTS.qid]),
        "",
        f"### Heads and duplicates ({Q_HEADS.qid})",
        "",
        f"- alerts: {alerts}",
        f"- heads (`duplicate_of IS NULL`): {heads}",
        f"- duplicates merged (`duplicate_of IS NOT NULL`): {duplicates}",
        f"- alerts per head: {_rate(alerts, heads)}",
        (
            "- max `occurrence_count` over the heads, the column at the run: "
            f"{_count_or_na(max_occurrence)}"
        ),
    ]


def _pull_section(res: Mapping[str, list[tuple]]) -> list[str]:
    succeeded, gap_ms, gap_from, gap_to = res[Q_PULL_GAP.qid][0]
    if gap_ms is None:
        gap = "n/a (fewer than 2 succeeded pull jobs)"
    else:
        gap = f"{gap_ms} ms, from {_ts(gap_from)} to {_ts(gap_to)}"
    return [
        "## 3 · The pull loop",
        "",
        (
            "### `jobs` of type `pull` by `status` at the run, `scheduled_at` in the window "
            f"({Q_PULL.qid})"
        ),
        "",
        _table(["status", "jobs"], res[Q_PULL.qid]),
        "",
        (
            "### Largest gap between consecutive succeeded pull jobs' `scheduled_at` "
            f"({Q_PULL_GAP.qid})"
        ),
        "",
        f"- succeeded pull jobs: {succeeded}",
        f"- largest gap: {gap}",
        "",
        f"### `source_cursor` at the run, not windowed ({Q_CURSOR.qid})",
        "",
        _table(["manager_id", "`last_error IS NULL`"], res[Q_CURSOR.qid]),
        "",
        f"### `job.exhausted` ({Q_EXHAUSTED.qid})",
        "",
        f"- `job.exhausted` events: {res[Q_EXHAUSTED.qid][0][0]}",
    ]


def _online_section(res: Mapping[str, list[tuple]]) -> list[str]:
    stopped = [
        ("NULL (the gate ran)" if cls is None else cls, n) for cls, n in res[Q_STOPPED_BY.qid]
    ]
    gate_ran, forced, hallucination, surviving, dropped = res[Q_GATE.qid][0]
    reasons = surviving + dropped
    evidence = _rate(surviving, reasons)
    if reasons:
        mark = "✓" if surviving / reasons >= EVIDENCE_TARGET else "✗"
        evidence += f" {mark} target ≥ {EVIDENCE_TARGET:.2f}"
    if _squeezed(forced, gate_ran):
        squeeze = [f"- **{SQUEEZE_SENTENCE}** (architecture §6: above 0.60).", f"- {R5_SENTENCE}"]
    else:
        above = NA if not gate_ran else "no"
        squeeze = [f"- above 0.60 (architecture §6's squeeze threshold): {above}"]
    per_role = [(role, n, _ms(p50), _ms(p95)) for role, n, p50, p95 in res[Q_LATENCY_ROLE.qid]]
    alerts_timed, alert_p50, alert_p95 = res[Q_LATENCY_ALERT.qid][0]
    cost, alerts_run = res[Q_COST.qid][0]
    per_alert = NA if not alerts_run else _usd(cost / alerts_run)
    return [
        "## 4 · ① online",
        "",
        f"### Proposer rows by `stopped_by` ({Q_STOPPED_BY.qid})",
        "",
        _table(["stopped_by", "rows"], stopped),
        "",
        f"- proposer rows: {sum(n for _, n in stopped)}",
        "",
        f"### Final verdict, rows where the gate ran ({Q_VERDICT.qid})",
        "",
        _table(["final_verdict", "rows"], res[Q_VERDICT.qid]),
        "",
        f"### The gate ({Q_GATE.qid})",
        "",
        f"- rows where the gate ran: {gate_ran}",
        f"- `forced = true`: {forced}",
        f"- gate-forced rate: {_rate(forced, gate_ran)}",
        *squeeze,
        f"- `hallucination_flag = true`: {_rate(hallucination, gate_ran)}",
        f"- evidence-verified rate: {evidence}",
        (
            "- the evidence-verified rate is Σ surviving reasons ÷ Σ (surviving + dropped): "
            f"{surviving} surviving, {dropped} dropped"
        ),
        "",
        f"### `forced_by`, per step ({Q_FORCED_BY.qid})",
        "",
        _table(["step", "rows"], res[Q_FORCED_BY.qid]),
        "",
        f"### Verifier, gate step 6 ({Q_STEP6.qid})",
        "",
        _table(["step 6", "rows"], res[Q_STEP6.qid]),
        "",
        f"### Latency per role ({Q_LATENCY_ROLE.qid})",
        "",
        _table(["role", "rows with latency", "p50", "p95"], per_role),
        "",
        (
            "### Latency per alert, proposer + verifier summed by `subject_id` "
            f"({Q_LATENCY_ALERT.qid})"
        ),
        "",
        f"- alerts: {alerts_timed} · p50: {_ms(alert_p50)} · p95: {_ms(alert_p95)}",
        "",
        f"### Cost ({Q_COST.qid})",
        "",
        f"- Σ `cost_usd`: {_usd(cost)}",
        f"- alerts with a run: {alerts_run}",
        f"- per alert: {per_alert}",
        "- each call's `cost_usd` is stored rounded to 0.00001 USD (migration 016)",
        "",
        f"### `model_id` ({Q_MODEL.qid})",
        "",
        _table(["role", "model_id", "rows"], res[Q_MODEL.qid]),
        "",
        f"### `prompt_version` ({Q_PROMPT.qid})",
        "",
        _table(["role", "prompt_version", "rows"], res[Q_PROMPT.qid]),
        "",
        f"### `triage_status` of the heads, at the run ({Q_TRIAGE_STATUS.qid})",
        "",
        _table(["triage_status", "heads"], res[Q_TRIAGE_STATUS.qid]),
    ]


def _autoclose_section(res: Mapping[str, list[tuple]]) -> list[str]:
    auto_closed, blocked = res[Q_AUTOCLOSE_EVENTS.qid][0]
    by_rule = res[Q_AUTOCLOSE_HEADS.qid]
    closed_heads = sum(n for _, n in by_rule)
    return [
        "## 5 · Auto-close",
        "",
        f"- `alert.auto_closed` events: {auto_closed} ({Q_AUTOCLOSE_EVENTS.qid})",
        f"- `alert.autoclose_blocked_critical` events: {blocked} ({Q_AUTOCLOSE_EVENTS.qid})",
        f"- heads with `autoclose_rule_id IS NOT NULL`: {closed_heads} ({Q_AUTOCLOSE_HEADS.qid})",
        "",
        _table(["autoclose_rule_id", "heads"], by_rule),
    ]


def _human_row(metric: HumanMetric, counts: Mapping[str, int]) -> list[str]:
    evidence = "; ".join(_EVIDENCE_LABEL[key].format(counts[key]) for key in metric.evidence)
    if metric.never:
        # ②'s n is ratings, and v1.0 has no rating control (Director ruling R15): the evidence
        # counted (`case.opened`) says a case was opened, not that anyone rated ②'s usefulness
        value = metric.never
        basis = f"{metric.missing}: {metric.because}; {evidence}, context only, not a rating count"
    elif any(counts[key] for key in metric.evidence):
        value = f"descriptive, n = {counts[metric.evidence[0]]}"
        basis = f"descriptive only, not a pilot result: {metric.because}; {evidence}"
    else:
        value = "not measured"
        basis = f"{metric.missing}: {metric.because}; {evidence}"
    return [metric.metric, value, basis]


def _pilot_human_rows(res: Mapping[str, list[tuple]]) -> list[list[str]]:
    """Section 6's first three rows once a pilot window is given: each points at its section 6a
    figure and carries its n. A row with no n is `not measured`, never a zero."""
    decisions = sum(row[5] for row in res[Q_PILOT_DECISIONS.qid] if row[1] == "all")
    timed = sum(row[3] for row in res[Q_PILOT_MEDIAN.qid] if row[1] == "all")
    blind, denominator = 0, 0
    for row in res[Q_PILOT_AGREEMENT.qid]:
        if row[0] == "all":
            blind, denominator = row[1], row[4]
    specs = (
        (
            HUMAN_METRICS[0],
            Q_PILOT_DECISIONS,
            decisions,
            "pilot decisions",
            "no human decision in the pilot window",
            "",
        ),
        (
            HUMAN_METRICS[1],
            Q_PILOT_MEDIAN,
            timed,
            "decisions with an acknowledge in the window",
            "no decision with an acknowledge in the pilot window",
            "",
        ),
        (
            # n is what the agreement fraction is over, the denominator: the blind decisions
            # whose ① had a verdict. The blind decisions themselves stay in the basis.
            HUMAN_METRICS[2],
            Q_PILOT_AGREEMENT,
            denominator,
            "agreement denominator",
            "no blind decision with a ① verdict in the pilot window",
            f"; blind decisions = {blind}",
        ),
    )
    rows = []
    for metric, query, n, label, empty, extra in specs:
        if n > 0:
            value = f"measured, n = {n}"
            basis = (
                f"measured over the pilot window: section 6a ({query.qid}); {label} = {n}{extra}"
            )
        else:
            value = "not measured"
            basis = f"{empty}: section 6a ({query.qid}); {label} = {n}{extra}"
        rows.append([metric.metric, value, basis])
    return rows


def _architecture_section(
    res: Mapping[str, list[tuple]], pilot: PilotWindow | None = None
) -> list[str]:
    tier1, ack, reviewed, case = res[Q_HUMAN_EVENTS.qid][0]
    counts = {
        "tier1": tier1,
        "ack": ack,
        "reviewed": reviewed,
        "case": case,
        "reviews": res[Q_REVIEWS.qid][0][0],
    }
    gate_ran, forced, *_ = res[Q_GATE.qid][0]
    basis = (
        "measured: `forced = true` over the proposer rows where the gate ran "
        f"(section 4, {Q_GATE.qid})"
    )
    if _squeezed(forced, gate_ran):
        basis += f"; above 0.60: {SQUEEZE_SENTENCE} (architecture §6), R5 (architecture §9)"
    rows = [_human_row(m, counts) for m in HUMAN_METRICS]
    if pilot is not None:
        rows[:3] = _pilot_human_rows(res)
    rows.insert(3, [GATE_FORCED_METRIC, _rate(forced, gate_ran), basis])
    blind, visible = res[Q_BRANCHES.qid][0]
    return [
        "## 6 · Architecture §6's online metrics",
        "",
        (
            "Architecture §6 names six online metrics. One is measured here, from the gate. "
            "Three need the human pilot: with `--pilot-start` each is measured in section 6a "
            "over the pilot window, and without it each prints `not measured` beside the "
            "evidence counted over the export window, or `descriptive, n = k` when that "
            "evidence is not zero. The digest row prints the same beside its own evidence. "
            "The ② row is `not measured` in v1.0 whatever its evidence counts: there is no "
            "rating control, so there is no rating to count (DEC-161), and the `case.opened` "
            "count beside it is context."
        ),
        "",
        _table(["metric", "value", "basis"], rows),
        "",
        (
            f"Branch sizes over the heads ({Q_BRANCHES.qid}). The blind assignment happens at "
            "intake, whether or not anyone decides:"
        ),
        "",
        _table(
            ["branch", "heads"],
            [
                ["blind (`suggestion_visible = false`)", blind],
                ["visible (`suggestion_visible = true`)", visible],
            ],
        ),
    ]


# --- section 6a: the human pilot ----------------------------------------------------------------

ARMS = ("blind", "visible")
_STANDARD_SOURCES = ("wazuh", "lab")
#: A `tier1.escalated` event records no ①, so `Q31` and `Q33` read `llm_runs` for it.
ESCALATION_CAVEAT = (
    "escalations: ① taken as the latest run created at or before the decision; a run in flight "
    "at that moment may be included"
)


def _source_order(present: set[str]) -> list[str]:
    """`wazuh`, `lab`, any other source that has a row (sorted), then `all`: nothing that is in
    `all` is left out of a table."""
    others = sorted(present - {*_STANDARD_SOURCES, "all"})
    return [*_STANDARD_SOURCES, *others, "all"]


def _pilot_decisions_table(rows: Sequence[tuple]) -> str:
    by_key = {(arm, source): counts for arm, source, *counts in rows}
    sources = _source_order({source for _, source, *_ in rows})
    body = [
        [arm, source, *by_key.get((arm, source), (0, 0, 0, 0))]
        for arm in ARMS
        for source in sources
    ]
    headers = ["arm", "source", "false_positive", "benign", "escalated", "decisions"]
    return _table(headers, body)


def _pilot_median_table(rows: Sequence[tuple]) -> str:
    by_key = {(arm, source): rest for arm, source, *rest in rows}
    sources = _source_order({source for _, source, *_ in rows})
    body = []
    for arm in ARMS:
        for source in sources:
            median, acknowledged, decisions = by_key.get((arm, source), (None, 0, 0))
            body.append([arm, source, _minutes(median), acknowledged, decisions])
    headers = [
        "arm",
        "source",
        "median acknowledge → decide",
        "n (acknowledged in the window)",
        "decisions",
    ]
    return _table(headers, body)


def _pilot_agreement_table(rows: Sequence[tuple]) -> str:
    by_source = {source: counts for source, *counts in rows}
    body = []
    for source in _source_order(set(by_source)):
        decisions, needs_review, no_result, denominator, agreed = by_source.get(
            source, (0, 0, 0, 0, 0)
        )
        body.append(
            [
                source,
                decisions,
                needs_review,
                no_result,
                denominator,
                agreed,
                _rate(agreed, denominator),
            ]
        )
    headers = [
        "source",
        "decisions (n)",
        "① needs_review (no verdict)",
        "① no result",
        "denominator",
        "agreed",
        "agreement",
    ]
    return _table(headers, body)


#: ①'s verdict as `Q31` and `Q33` classify it: `no_result` is no proposer row, a NULL `result`, or
#: a recorded action that is none of the three. ① has no `benign` verdict.
VERDICTS = ("escalate", "false_positive", "needs_review", "no_result")


def _pilot_cross_table(rows: Sequence[tuple]) -> str:
    by_key = {(source, verdict): counts for source, verdict, *counts in rows}
    body = [
        [source, verdict, *by_key.get((source, verdict), (0, 0, 0, 0))]
        for source in _source_order({source for source, *_ in rows})
        for verdict in VERDICTS
    ]
    headers = ["source", "① verdict", "false_positive", "benign", "escalated", "decisions"]
    return _table(headers, body)


def _pilot_person_table(rows: Sequence[tuple]) -> str:
    sources = _source_order({row[2] for row in rows})

    def order(row: tuple) -> tuple:
        person = "" if row[0] is None else str(row[0])
        return (person, ARMS.index(row[1]), sources.index(row[2]))

    body = [
        [person, arm, source, fp, benign, escalated, decisions, _minutes(median), acknowledged]
        for person, arm, source, fp, benign, escalated, decisions, median, acknowledged in sorted(
            rows, key=order
        )
    ]
    headers = [
        "person",
        "arm",
        "source",
        "false_positive",
        "benign",
        "escalated",
        "decisions",
        "median acknowledge → decide",
        "n (acknowledged in the window)",
    ]
    return _table(headers, body)


def _pilot_section(res: Mapping[str, list[tuple]], pilot: PilotWindow | None) -> list[str]:
    heading = ["## 6a · The human pilot, per arm and source", ""]
    if pilot is None:
        return [
            *heading,
            (
                f"{NO_PILOT_START} (pass `--pilot-start ISO8601`, and `--pilot-end` to close the "
                "pilot). No pilot query ran."
            ),
        ]
    end_note = (
        ""
        if pilot.end
        else " `--pilot-end` was not given: the end is the `now()` of the read-only transaction, "
        "and no timestamp of it is printed."
    )
    return [
        *heading,
        (
            f"- Pilot window: `{pilot}`, half-open, UTC, on `audit_events.created_at`, which is "
            f"the database clock.{end_note} It is not the export window of section 1."
        ),
        (
            "- Decisions: `audit_events` of type `tier1.decided` (payload `decision` `closed_fp` "
            "= false_positive, `closed_benign` = benign) and `tier1.escalated` (= escalated), "
            "created in the pilot window, about a non-synthetic alert, whenever the alert was "
            "received. The arm is `alerts.suggestion_visible`: blind is `false` (DEC-101). The "
            "source is `alerts.source`, and `all` is the sum of the sources."
        ),
        (
            "- Acknowledge → decide: from the alert's latest `alert.acknowledged` event that is "
            "at or after the pilot start and not after the decision, to the decision; both are "
            "`audit_events.created_at`. A decision with no such acknowledge is counted in "
            "`decisions` and not timed. The median is `percentile_cont(0.5)`: the mean of the "
            "two middle values when n is even."
        ),
        (
            "- ① is the gated verdict the queue shows (the `suggested_action` of the alert's "
            "latest `proposer` `triage` row in `llm_runs`), as it was when the human decided. "
            "A `tier1.decided` event recorded it in its payload (`llm_suggestion`, `llm_run_id`), "
            "and that record is read, not `llm_runs` by time: the triage job still runs on an "
            "escalated alert, and one still running at the decision has a `created_at` before "
            "it although the analyst never saw its row."
        ),
        "",
        f"### Decisions by type ({Q_PILOT_DECISIONS.qid})",
        "",
        _pilot_decisions_table(res[Q_PILOT_DECISIONS.qid]),
        "",
        f"### Median acknowledge → decide ({Q_PILOT_MEDIAN.qid})",
        "",
        _pilot_median_table(res[Q_PILOT_MEDIAN.qid]),
        "",
        f"### ① agreement with the human, blind arm only ({Q_PILOT_AGREEMENT.qid})",
        "",
        (
            "- ① `escalate` agrees with a human escalation. ① `false_positive` agrees with a "
            "human `false_positive`. Any other pair is a disagreement, a human `benign` after ① "
            "`false_positive` included."
        ),
        (
            "- ① `needs_review` is no verdict: it is left out of the denominator and counted in "
            "its own column. A decision with no ① result (no proposer row, or its `result` is "
            "NULL, at the decision) is counted in its own column too."
        ),
        (
            "- decisions (`tier1.decided`): ① is the event's `llm_suggestion`; a null "
            "`llm_suggestion` (no `llm_run_id`) is no result at the decision, whatever run was "
            "created since."
        ),
        f"- {ESCALATION_CAVEAT}",
        "- the visible arm has no agreement figure: its analyst saw ①.",
        "",
        _pilot_agreement_table(res[Q_PILOT_AGREEMENT.qid]),
        "",
        f"### ① verdict × human decision, blind arm only ({Q_PILOT_CROSS.qid})",
        "",
        (
            "Every blind decision is in one row, by the ① it was taken against. ① has no "
            "`benign` verdict: a human `benign` after ① `false_positive` is a disagreement in "
            "the table above, and is a closure here. The counts are the agreement table's "
            f"({Q_PILOT_AGREEMENT.qid}), split by the human decision."
        ),
        "",
        _pilot_cross_table(res[Q_PILOT_CROSS.qid]),
        "",
        f"### Decisions per person ({Q_PILOT_PERSON.qid})",
        "",
        "`person` is the acting user's id (`audit_events.actor_id`), not a name.",
        "",
        _pilot_person_table(res[Q_PILOT_PERSON.qid]),
    ]


def _labelling_section(res: Mapping[str, list[tuple]]) -> list[str]:
    created, undo = res[Q_LABEL_EVENTS.qid][0]
    return [
        "## 7 · Labelling activity (P6), not triage decisions",
        "",
        (
            "The gold labelling of P6 is the offline labelling of lab clusters on the blind "
            "labelling page. It is not a triage decision, and no figure in section 6 reads it."
        ),
        "",
        f"- `label.created` events: {created}, of which undo records: {undo} ({Q_LABEL_EVENTS.qid})",
        "",
        f"`triage_labels` by `source` ({Q_LABELS.qid}):",
        "",
        _table(["source", "`triage_labels` rows"], res[Q_LABELS.qid]),
    ]


def _appendix(window: Window, ran: Sequence[Query], pilot: PilotWindow | None = None) -> list[str]:
    lines = [
        "## 8 · Appendix: SQL",
        "",
        (
            f"Bind parameters: `%(since)s` = `{_ts(window.since)}`, `%(until)s` = "
            f"`{_ts(window.until)}`. The command runs these queries in this order, in one "
            f"transaction opened with `{READ_ONLY_STATEMENT}`."
        ),
    ]
    if pilot is not None:
        end = (
            f"`{_ts(pilot.end)}`"
            if pilot.end
            else "`NULL`, which the queries read as `now()`, the database clock"
        )
        lines += [
            "",
            (
                f"The pilot queries ({PILOT_QUERIES[0].qid} to {PILOT_QUERIES[-1].qid}) bind "
                f"`%(pilot_start)s` = `{_ts(pilot.start)}` and `%(pilot_end)s` = {end}, and not "
                "`%(since)s` or `%(until)s`."
            ),
        ]
    for query in ran:
        lines += ["", f"### {query.qid} · {query.title}", "", "```sql", query.sql, "```"]
    return lines


def render(window: Window, runner: _Runner) -> str:
    """The document, from what `collect` ran. Pure: no clock, no host, no path."""
    res = runner.results
    parts = [
        _header(window, res),
        _intake_section(res),
        _pull_section(res),
        _online_section(res),
        _autoclose_section(res),
        _architecture_section(res, runner.pilot),
        _pilot_section(res, runner.pilot),
        _labelling_section(res),
        _appendix(window, runner.ran, runner.pilot),
    ]
    return "\n\n".join("\n".join(part) for part in parts) + "\n"


def build_report(conn, window: Window, pilot: PilotWindow | None = None) -> str:
    """Run every query on `conn` and render the document."""
    return render(window, collect(conn, window, pilot))


# --- the CLI -----------------------------------------------------------------------------------


def _instant(text: str, flag: str) -> datetime:
    try:
        value = datetime.fromisoformat(text)
    except ValueError:
        raise Exit(EXIT_USAGE, f"{flag}: not an ISO-8601 instant: {text!r}") from None
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise Exit(EXIT_USAGE, f"{flag}: must be UTC, ending in Z or +00:00: {text!r}")
    return value.astimezone(UTC)


def parse_window(since: str, until: str) -> Window:
    """Both ends parsed as UTC instants; `since` must be strictly earlier than `until`."""
    window = Window(_instant(since, "--since"), _instant(until, "--until"))
    if window.since >= window.until:
        raise Exit(EXIT_USAGE, f"inverted or empty window: --since {since} is not before --until")
    return window


def parse_pilot(start: str | None, end: str | None) -> PilotWindow | None:
    """No `--pilot-start` and no `--pilot-end`: no pilot (section 6a prints `not measured`). An
    end without a start is a usage error, and so is an end that is not after the start. A start
    alone leaves the end open: the database's `now()`."""
    if start is None:
        if end is not None:
            raise Exit(EXIT_USAGE, "--pilot-end needs --pilot-start")
        return None
    pilot = PilotWindow(
        _instant(start, "--pilot-start"),
        None if end is None else _instant(end, "--pilot-end"),
    )
    if pilot.end is not None and pilot.start >= pilot.end:
        raise Exit(
            EXIT_USAGE,
            f"inverted or empty pilot window: --pilot-start {start} is not before --pilot-end",
        )
    return pilot


def _resolve_dsn(dsn: str | None, env_file: str) -> str:
    if dsn:
        return dsn
    from app.infra import config
    from app.infra.errors import ConfigError

    try:
        resolved = config.load(env_file=env_file).DATABASE_URL
    except ConfigError:
        raise Exit(EXIT_DSN, "could not read the file named by --env-file") from None
    if not resolved:
        raise Exit(
            EXIT_DSN, "no DSN: pass --dsn, or set DATABASE_URL in the file named by --env-file"
        )
    return resolved


def _connect_readonly(dsn: str):
    import psycopg
    from app.infra import db

    try:
        conn = db.connect(dsn)
    except psycopg.Error as exc:  # a DSN libpq cannot parse, or a server it cannot reach
        raise Exit(EXIT_DSN, f"could not open the database: {type(exc).__name__}") from None
    conn.execute(READ_ONLY_STATEMENT)
    return conn


@contextmanager
def _readonly_connection(dsn: str):
    conn = _connect_readonly(dsn)
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ops_export.py",
        description="Write one markdown file of what the system did online over [--since, "
        "--until), measured read-only, every figure beside the query that produced it.",
        epilog="exit codes: 0 written; 2 usage (an unparsable or inverted window, "
        "--pilot-end without --pilot-start, or no --until); 4 the DSN is unreadable.",
    )
    parser.add_argument(
        "--since",
        default=DEFAULT_SINCE,
        metavar="ISO8601",
        help=f"UTC instant, inclusive (default {DEFAULT_SINCE}, the DB reset of DEC-113)",
    )
    parser.add_argument(
        "--until",
        required=True,
        metavar="ISO8601",
        help="UTC instant, exclusive; required, so two runs over one window are byte-identical",
    )
    parser.add_argument(
        "--pilot-start",
        default=None,
        metavar="ISO8601",
        help="UTC instant, inclusive: the human pilot's first moment. Without it section 6a "
        "prints 'not measured: pilot start not given' and no pilot query runs",
    )
    parser.add_argument(
        "--pilot-end",
        default=None,
        metavar="ISO8601",
        help="UTC instant, exclusive; needs --pilot-start (default: the database's now())",
    )
    parser.add_argument("--out", default=DEFAULT_OUT, metavar="PATH")
    parser.add_argument("--env-file", default=".env", metavar="PATH")
    parser.add_argument("--dsn", default=None, metavar="DSN")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:  # argparse: --help exits 0, a usage error 2
        return int(exc.code or 0)
    try:
        window = parse_window(args.since, args.until)
        pilot = parse_pilot(args.pilot_start, args.pilot_end)
        dsn = _resolve_dsn(args.dsn, args.env_file)
        with _readonly_connection(dsn) as conn:
            runner = collect(conn, window, pilot)
        text = render(window, runner)
        out = Path(args.out)
        _write(out, text)
    except Exit as exit_:
        print(exit_.message, file=sys.stderr)
        return exit_.code
    print(f"ops_export {window}: {len(runner.ran)} queries -> {out}")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
