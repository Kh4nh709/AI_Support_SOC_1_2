"""The daily digest of auto-closed clusters for human review (P5-T08,
P5-tasks.md §6.5, `docs/kien-truc-v3-14-ngay.html` §3.4).

`build(conn, day)` reads every alert auto-closed in `day`'s 24h (UTC, §9),
disagreements first — ①'s verdict, read the one way this codebase reads it
(`tier1.queue.latest_suggestion`, P4 planning decision 5: one function reads
①, one place to change). `review(conn, alert_id, verdict, reviewer_id)` is
the human's one action on a row: `correct` confirms the auto-close and writes
the `false_positive` gold label; `wrong` reopens the alert through
`domain.transitions.reopen` (A17) and writes **no** label — a `wrong` verdict
says only that auto-closing was wrong, not what the alert *is* (design note
2(b); "Tỉ lệ đóng nhầm của báo cáo = wrong / reviewed ... đo bằng người ...
Không dùng model làm thước đo rule"); `unsure` writes only the review.
`rule.suspected_wrong` fires once per rule per 7-day window at >= 2 `wrong`
verdicts. `ensure_scheduled(conn)` is the self-chaining half: it enqueues
tomorrow's digest job at 08:00, `scheduled_at` evaluated by the database
(§9 — control timestamps are never a Python value), the same mechanism
`infra/puller.py` uses for `pull`'s `Reschedule`. `to_csv(rows)` is the cut
path (§10: "digest UI (CSV instead)") — it carries everything the page would
show, including ①'s verdict and the disagreement flag.

G2: only `domain/` writes `alerts.status` — this module calls `reopen`, it
never issues a status-setting UPDATE against `alerts` itself.
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import io
import json
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Literal

import psycopg
from psycopg import sql

from app.audit.events import write_event
from app.domain.transitions import reopen
from app.infra import config, db
from app.infra.jobs import Job, enqueue
from app.tier1.queue import latest_suggestion

_SUSPECTED_WRONG_THRESHOLD = 2


@dataclasses.dataclass(frozen=True)
class DigestRow:
    """One cluster on the digest — design note 1's column list, plus ①'s
    verdict and the disagreement flag `build()` computes from it."""

    alert_id: str
    rule_id: str
    description: str
    severity: str
    category: str
    agent_name: str
    occurrence_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    autoclose_rule_id: str | None
    autoclose_rule_name: str | None
    suggested_action: str | None
    disagreement: bool
    reviewed_verdict: str | None


_BUILD_SQL = """
    SELECT
        a.alert_id, a.rule_id, a.description, a.severity, a.category,
        a.agent_name, a.occurrence_count, a.first_seen_at, a.last_seen_at,
        a.autoclose_rule_id, r.name, rev.verdict
    FROM alerts a
    LEFT JOIN autoclose_rules r ON r.autoclose_rule_id = a.autoclose_rule_id
    LEFT JOIN autoclose_reviews rev ON rev.alert_id = a.alert_id
    WHERE a.status = 'auto_closed'
      AND a.closed_at >= %(day)s::date
      AND a.closed_at <  %(day)s::date + 1
"""


def build(conn: psycopg.Connection, day: str) -> list[DigestRow]:
    """Every cluster auto-closed in `day`'s 24h, disagreements first (design
    note 1): ①'s `suggested_action` sorts to the top when it is not
    `false_positive` — the rule closed it and the model would not have; ties
    break on `occurrence_count DESC`, then `alert_id`, so the order is total
    and the CSV is diffable. A row with no ① run at all (the `triage` job
    D8 enqueues on every auto-close has not finished yet) is left out of the
    disagreement group — there is no verdict to disagree with. Already
    reviewed alerts carry their verdict; they are not excluded."""
    records = conn.execute(_BUILD_SQL, {"day": day}).fetchall()
    rows: list[DigestRow] = []
    for (
        alert_id,
        rule_id,
        description,
        severity,
        category,
        agent_name,
        occurrence_count,
        first_seen_at,
        last_seen_at,
        autoclose_rule_id,
        autoclose_rule_name,
        reviewed_verdict,
    ) in records:
        suggestion = latest_suggestion(conn, alert_id)
        suggested_action = suggestion.suggested_action if suggestion else None
        disagreement = suggestion is not None and suggested_action != "false_positive"
        rows.append(
            DigestRow(
                alert_id=alert_id,
                rule_id=rule_id,
                description=description,
                severity=severity,
                category=category,
                agent_name=agent_name,
                occurrence_count=occurrence_count,
                first_seen_at=first_seen_at,
                last_seen_at=last_seen_at,
                autoclose_rule_id=str(autoclose_rule_id) if autoclose_rule_id else None,
                autoclose_rule_name=autoclose_rule_name,
                suggested_action=suggested_action,
                disagreement=disagreement,
                reviewed_verdict=reviewed_verdict,
            )
        )
    rows.sort(key=lambda r: (not r.disagreement, -r.occurrence_count, r.alert_id))
    return rows


def unreviewed_count(conn: psycopg.Connection, day: str) -> int:
    """How many of `day`'s auto-closed clusters have no `autoclose_reviews`
    row yet. Exposed for P5-T11's health job (the 17:00 threshold is its own,
    not this card's — this card only exposes the number)."""
    row = conn.execute(
        """
        SELECT count(*)
        FROM alerts a
        LEFT JOIN autoclose_reviews rev ON rev.alert_id = a.alert_id
        WHERE a.status = 'auto_closed'
          AND a.closed_at >= %(day)s::date
          AND a.closed_at <  %(day)s::date + 1
          AND rev.alert_id IS NULL
        """,
        {"day": day},
    ).fetchone()
    return row[0]


def review(
    conn: psycopg.Connection,
    alert_id: str,
    verdict: Literal["correct", "wrong", "unsure"],
    reviewer_id: str,
) -> None:
    """Design note 2's three effects, in the caller's transaction — this
    function never commits, matching every other domain-adjacent call in this
    codebase (`reopen`, `decide`, `conclude_case`).

    (a) One `autoclose_reviews` row per alert (the PK is `alert_id` alone): a
    second review of the same alert upserts — last reviewer wins.
    (b) `correct` confirms the auto-close read the cluster right and writes
    the gold `false_positive` label (`source='digest'`). `wrong` and `unsure`
    write **no** label: `wrong` says only that auto-closing was wrong, not
    what the alert *is*, and inventing a label from "not this" would put a
    fabricated row in P7's evaluation table (design note 2(b) — flagged for
    the Director in the report; a one-line change to `wrong -> escalate` if
    they prefer it).
    (c) `wrong` reopens the alert (A17, `auto_closed -> queued_tier1`,
    `autoclose_rule_id` untouched by `reopen`) and checks whether its rule
    now has >= 2 `wrong` verdicts in the last 7 days. A `StaleState` from
    `reopen` (the alert is no longer `auto_closed`) propagates uncaught — the
    caller renders it as a conflict, not a 500.
    """
    conn.execute(
        """
        INSERT INTO autoclose_reviews (alert_id, reviewer_id, verdict)
        VALUES (%s, %s, %s)
        ON CONFLICT (alert_id) DO UPDATE SET
            reviewer_id = EXCLUDED.reviewer_id,
            verdict = EXCLUDED.verdict,
            reviewed_at = now()
        """,
        (alert_id, reviewer_id, verdict),
    )
    if verdict == "correct":
        conn.execute(
            """
            INSERT INTO triage_labels (alert_id, labeler_id, source, label)
            VALUES (%s, %s, 'digest', 'false_positive')
            ON CONFLICT (alert_id, labeler_id, source) DO UPDATE SET
                label = EXCLUDED.label,
                created_at = now()
            """,
            (alert_id, reviewer_id),
        )
    elif verdict == "wrong":
        reopen(conn, alert_id, reviewer_id, reason="digest")
        _flag_rule_if_suspected_wrong(conn, alert_id)


def _flag_rule_if_suspected_wrong(conn: psycopg.Connection, alert_id: str) -> None:
    """Design note 3: after a `wrong` review, count that rule's `wrong`
    verdicts in the last 7 days (join `autoclose_reviews` to
    `alerts.autoclose_rule_id`); at >= 2, write `rule.suspected_wrong` once
    per rule per 7-day window — an existing event in the window stops a
    re-fire on every later `wrong`. Notification is P5-T11's; this writes the
    record, not a message."""
    row = conn.execute(
        "SELECT autoclose_rule_id FROM alerts WHERE alert_id = %s", (alert_id,)
    ).fetchone()
    rule_id = row[0] if row else None
    if rule_id is None:
        return
    rule_id = str(rule_id)

    wrong_count = conn.execute(
        """
        SELECT count(*)
        FROM autoclose_reviews rev
        JOIN alerts a ON a.alert_id = rev.alert_id
        WHERE a.autoclose_rule_id = %s
          AND rev.verdict = 'wrong'
          AND rev.reviewed_at >= now() - interval '7 days'
        """,
        (rule_id,),
    ).fetchone()[0]
    if wrong_count < _SUSPECTED_WRONG_THRESHOLD:
        return

    already_flagged = conn.execute(
        """
        SELECT count(*)
        FROM audit_events
        WHERE event_type = 'rule.suspected_wrong'
          AND subject_id = %s
          AND created_at >= now() - interval '7 days'
        """,
        (rule_id,),
    ).fetchone()[0]
    if already_flagged:
        return

    write_event(
        conn,
        "rule.suspected_wrong",
        rule_id,
        "system",
        payload={"wrong_count": wrong_count, "window": "7 days"},
    )


_CSV_COLUMNS = (
    "alert_id",
    "rule_id",
    "description",
    "severity",
    "category",
    "agent_name",
    "occurrence_count",
    "first_seen_at",
    "last_seen_at",
    "autoclose_rule_id",
    "autoclose_rule_name",
    "suggested_action",
    "disagreement",
    "reviewed_verdict",
)


def to_csv(rows: Sequence[DigestRow]) -> str:
    """One header row, one row per cluster, the column order above, `\\n`
    line endings, UTF-8, deterministic. Design note 5: with the digest UI cut
    this file *is* the digest, so it carries everything the page would show,
    including ①'s verdict and the disagreement flag."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(_CSV_COLUMNS)
    for row in rows:
        writer.writerow(
            [
                row.alert_id,
                row.rule_id,
                row.description,
                row.severity,
                row.category,
                row.agent_name,
                row.occurrence_count,
                row.first_seen_at.isoformat(),
                row.last_seen_at.isoformat(),
                row.autoclose_rule_id,
                row.autoclose_rule_name,
                row.suggested_action,
                "true" if row.disagreement else "false",
                row.reviewed_verdict,
            ]
        )
    return buf.getvalue()


def ensure_scheduled(conn: psycopg.Connection) -> int | None:
    """The self-chaining half (design note 4): enqueue tomorrow's `digest`
    job, or do nothing if one is already live. `scheduled_at` is a
    `psycopg.sql` expression the database evaluates —
    `now()::date + 1 + time '08:00'`, never a Python timestamp (§9: control
    timestamps come from the database's own clock) — the same mechanism
    `infra/puller.py` uses for `pull`'s `Reschedule`. `subject_id` (the ISO
    date that makes the job idempotent per day) is read back from that same
    `now()::date + 1`, so it never disagrees with the scheduled time or with
    this process's own clock. Also reachable from the CLI (`--ensure`) so a
    chain that was ever broken can be re-armed by hand."""
    tomorrow = conn.execute("SELECT (now()::date + 1)::text").fetchone()[0]
    return enqueue(
        conn,
        "digest",
        tomorrow,
        scheduled_at=sql.SQL("now()::date + 1 + time '08:00'"),
    )


def run_digest_job(conn: psycopg.Connection, job: Job) -> None:
    """§6.5's `digest` handler: build `job.subject_id`'s digest (so a broken
    query fails the job loudly, not silently — nothing here persists the
    rows; the CSV and the page, P5-T09, build on demand from `build()`
    itself), log a one-line summary, then re-arm tomorrow's job."""
    rows = build(conn, job.subject_id)
    print(json.dumps({"day": job.subject_id, "clusters": len(rows)}))
    ensure_scheduled(conn)


# =============================================================================
# CLI — design note 5's CSV path and design note 4's `--ensure`, neither of
# which needs a running worker or a browser.
# =============================================================================


def _cmd(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m app.tier1.digest",
        description=(
            "--ensure enqueues tomorrow's digest job if the chain is not "
            "already armed (re-arms it by hand after a break). --csv PATH "
            "writes the day's digest as CSV; --day YYYY-MM-DD picks the day "
            "(default: today, the database's own clock). Either or both."
        ),
    )
    parser.add_argument("--ensure", action="store_true", help="enqueue tomorrow's digest job")
    parser.add_argument("--csv", metavar="PATH", help="write the day's digest as CSV to PATH")
    parser.add_argument("--day", metavar="YYYY-MM-DD", help="default: today")
    parser.add_argument("--env-file", default=".env")
    args = parser.parse_args(argv)
    if not args.ensure and not args.csv:
        parser.error("nothing to do: pass --ensure and/or --csv PATH")

    cfg = config.load(env_file=args.env_file)
    conn = db.connect(cfg.DATABASE_URL)
    try:
        if args.ensure:
            job_id = ensure_scheduled(conn)
            conn.commit()
            print(f"digest: ensure_scheduled -> job_id={job_id}")
        if args.csv:
            day = args.day or conn.execute("SELECT now()::date::text").fetchone()[0]
            rows = build(conn, day)
            Path(args.csv).write_text(to_csv(rows), encoding="utf-8")
            print(f"digest: wrote {len(rows)} row(s) for {day} to {args.csv}")
    finally:
        conn.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    return _cmd(argv)


if __name__ == "__main__":
    raise SystemExit(main())
