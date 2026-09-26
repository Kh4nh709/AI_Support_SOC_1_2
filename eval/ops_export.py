"""P8-T01's operations export: what the system did online over one time window, read-only.

The human pilot never ran, so this command replaces the brief's `pilot_export.py` (DEC-129,
DEC-116). One read-only transaction produces one markdown file that describes the online
operating period in numbers: intake and dedup, the pull loop, pipeline ①'s online figures (the
gate-forced rate included), auto-close. Every figure names the query that produced it, and
section 8 prints every query verbatim. Each human-decision metric of architecture §6 is printed
"not measured" with its missing precondition, its DEC and the counted evidence, never as a zero.

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
        --env-file .env --out docs/results/operations.md

Exit codes:
    0 written; 2 usage (an unparsable or inverted window, or no `--until`);
    4 the DSN is unreadable.
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
    evidence key is the metric's own n; every key's count is printed in the basis."""

    metric: str
    missing: str
    because: str
    evidence: tuple[str, ...]


_NO_PILOT = "no human-decision pilot ran"
_CONSOLE = "the Tier-1 console was deprioritized (DEC-116)"

HUMAN_METRICS: tuple[HumanMetric, ...] = (
    HumanMetric(
        "Decisions by branch (blind / visible) and by person", _NO_PILOT, _CONSOLE, ("tier1",)
    ),
    HumanMetric("Median acknowledge → decide, by branch", _NO_PILOT, _CONSOLE, ("tier1", "ack")),
    HumanMetric(
        "① agreement with human decisions, blind branch only", _NO_PILOT, _CONSOLE, ("tier1",)
    ),
    HumanMetric(
        "Auto-close wrong-close rate from the digest, with its Wilson CI",
        "no digest review ran",
        "the digest (P5) was deprioritized (DEC-116)",
        ("reviews", "reviewed"),
    ),
    HumanMetric(
        "② usefulness, 1–5", "no ② run exists to rate", "② was cut (DEC-097, DEC-111)", ("case",)
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
    ran: list[Query] = field(default_factory=list)
    results: dict[str, list[tuple]] = field(default_factory=dict)

    def run(self, query: Query) -> list[tuple]:
        self.ran.append(query)
        rows = _execute(self.conn, query.sql, self.window.params)
        self.results[query.qid] = rows
        return rows


def collect(conn, window: Window) -> _Runner:
    """Run every query once, in `QUERIES` order, on `conn`. Sets nothing on the connection: the
    CLI's own connection is read-only (`_connect_readonly`); a test passes its own."""
    runner = _Runner(conn, window)
    for query in QUERIES:
        runner.run(query)
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
    if any(counts[key] for key in metric.evidence):
        value = f"descriptive, n = {counts[metric.evidence[0]]}"
        basis = f"descriptive only, not a pilot result: {metric.because}; {evidence}"
    else:
        value = "not measured"
        basis = f"{metric.missing}: {metric.because}; {evidence}"
    return [metric.metric, value, basis]


def _architecture_section(res: Mapping[str, list[tuple]]) -> list[str]:
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
    rows.insert(3, [GATE_FORCED_METRIC, _rate(forced, gate_ran), basis])
    blind, visible = res[Q_BRANCHES.qid][0]
    return [
        "## 6 · Architecture §6's online metrics",
        "",
        (
            "Architecture §6 names six online metrics. One is measured here. The other five "
            "need a human-decision pilot, which never ran (DEC-129): each prints `not measured` "
            "beside the evidence counted for it, or `descriptive, n = k` when that evidence is "
            "not zero."
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


def _appendix(window: Window, ran: Sequence[Query]) -> list[str]:
    lines = [
        "## 8 · Appendix: SQL",
        "",
        (
            f"Bind parameters: `%(since)s` = `{_ts(window.since)}`, `%(until)s` = "
            f"`{_ts(window.until)}`. The command runs these queries in this order, in one "
            f"transaction opened with `{READ_ONLY_STATEMENT}`."
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
        _architecture_section(res),
        _labelling_section(res),
        _appendix(window, runner.ran),
    ]
    return "\n\n".join("\n".join(part) for part in parts) + "\n"


def build_report(conn, window: Window) -> str:
    """Run every query on `conn` and render the document."""
    return render(window, collect(conn, window))


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
        epilog="exit codes: 0 written; 2 usage (an unparsable or inverted window, or no "
        "--until); 4 the DSN is unreadable.",
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
        dsn = _resolve_dsn(args.dsn, args.env_file)
        with _readonly_connection(dsn) as conn:
            runner = collect(conn, window)
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
