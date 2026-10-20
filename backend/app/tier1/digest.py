"""The daily digest of auto-closed clusters for human review (P5-T08,
P5-tasks.md §6.5, `docs/kien-truc-v3-14-ngay.html` §3.4).

`build(conn, day)` reads every alert auto-closed in `day`'s 24h **in the
display zone** (`cfg.DISPLAY_TZ`, review round 1 · S4 — the digest is read by
people in that zone, not in UTC), disagreements first — ①'s verdict, read the
one way this codebase reads it (`tier1.queue.latest_suggestion`, P4 planning
decision 5: one function reads ①, one place to change). `review(conn,
alert_id, verdict, reviewer_id)` is the human's one action on a row, and its
whole body is one savepoint (review round 1 · B1/B3): a status guard applies
to every verdict, a second review of an already-reviewed alert is a conflict
(`AlreadyReviewed`, not an upsert — round 1 flips design note 2(a)), `correct`
writes the gold `false_positive` label, `wrong` reopens the alert through
`domain.transitions.reopen` (A17) and writes **no** label — a `wrong` verdict
says only that auto-closing was wrong, not what the alert *is* (design note
2(b); "Tỉ lệ đóng nhầm của báo cáo = wrong / reviewed ... đo bằng người ...
Không dùng model làm thước đo rule"); `unsure` writes only the review. Every
verdict writes an `autoclose.reviewed` audit event (G2/B2: every human
decision is one); `correct` also writes `label.created`. `rule.suspected_wrong`
fires once per rule per 7-day window at >= 2 `wrong` verdicts, guarded by a
transaction-scoped advisory lock on the rule id (round 1 · N9). `ensure_scheduled(conn)`
is the self-chaining half: it enqueues tomorrow's digest job at 08:00 **local**,
`scheduled_at` evaluated by the database (§9 — control timestamps are never a
Python value), the same mechanism `infra/puller.py` uses for `pull`'s
`Reschedule`. A job that fires on local day D reviews local day D-1 (round 1 ·
S4). `to_csv(rows)` is the cut path (§10: "digest UI (CSV instead)") — it
carries everything the page would show, including ①'s verdict and the
disagreement flag.

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
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Literal

import psycopg
from psycopg import sql

from app.audit.events import write_event
from app.domain.transitions import StaleState, reopen
from app.infra import config, db
from app.infra.errors import PermanentError
from app.infra.jobs import Job, enqueue
from app.tier1.queue import latest_suggestion, latest_suggestions

_SUSPECTED_WRONG_THRESHOLD = 2


class AlreadyReviewed(StaleState):
    """A second review of an alert that already has one (review round 1
    ruling on design note 2(a): the first review wins; someone who changes
    their mind uses the Tier-1 reopen, not a second digest review).
    Subclasses `StaleState` so a caller that only wants "this row moved under
    you, render a conflict" — P5-T09's one 409 path — needs no second
    `except`, while a caller that cares can still catch this specifically."""


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


# Day bounds, in the display zone (round 1 · S4): `day` is a naive calendar
# date; casting it (and day+1) to `timestamp` then `AT TIME ZONE tz`
# interprets that naive instant AS local wall-clock time in `tz` and converts
# it to the `timestamptz` `closed_at` actually is — never plain UTC, and `tz`
# is always a bound parameter (`%(tz)s`), never formatted into the SQL text.
_DAY_LOWER = "(%(day)s::date)::timestamp AT TIME ZONE %(tz)s"
_DAY_UPPER = "(%(day)s::date + 1)::timestamp AT TIME ZONE %(tz)s"

_BUILD_SQL = f"""
    SELECT
        a.alert_id, a.rule_id, a.description, a.severity, a.category,
        a.agent_name, a.occurrence_count, a.first_seen_at, a.last_seen_at,
        a.autoclose_rule_id, r.name, rev.verdict
    FROM alerts a
    LEFT JOIN autoclose_rules r ON r.autoclose_rule_id = a.autoclose_rule_id
    LEFT JOIN autoclose_reviews rev ON rev.alert_id = a.alert_id
    WHERE a.status = 'auto_closed'
      AND NOT a.is_synthetic
      AND a.closed_at >= {_DAY_LOWER}
      AND a.closed_at <  {_DAY_UPPER}
"""

# One alert instead of the day (P11-T07 fix round 1, F3): the JSON API's POST needs a single
# row, and building the whole day to find it cost one `latest_suggestion` query per row, twice.
# A constant string appended to the one above, so the day's own query is untouched.
_ONLY_ALERT_SQL = "      AND a.alert_id = %(alert_id)s\n"

_UNREVIEWED_COUNT_SQL = f"""
    SELECT count(*)
    FROM alerts a
    LEFT JOIN autoclose_reviews rev ON rev.alert_id = a.alert_id
    WHERE a.status = 'auto_closed'
      AND NOT a.is_synthetic
      AND a.closed_at >= {_DAY_LOWER}
      AND a.closed_at <  {_DAY_UPPER}
      AND rev.alert_id IS NULL
"""


def build(
    conn: psycopg.Connection,
    day: str,
    *,
    tz: str | None = None,
    alert_id: str | None = None,
) -> list[DigestRow]:
    """Every cluster auto-closed in `day`'s 24h **in the display zone**
    (`tz`, default `cfg.DISPLAY_TZ` — round 1 · S4), excluding synthetic
    alerts (round 1 · N8, matching `queue.py`'s `list_queue` and
    `ingest/autoclose.simulate`), disagreements first (design note 1): ①'s
    `suggested_action` sorts to the top when it is not `false_positive` — the
    rule closed it and the model would not have; ties break on
    `occurrence_count DESC`, then `alert_id`, so the order is total and the
    CSV is diffable. A row with no ① run at all (the `triage` job D8
    enqueues on every auto-close has not finished yet) is left out of the
    disagreement group — there is no verdict to disagree with. Already
    reviewed alerts carry their verdict; they are not excluded.

    `alert_id` (P11-T07 fix round 1) narrows the answer to that one alert: its row if it was
    auto-closed on `day`, else `[]`. Without it the query is the day's, as it always was."""
    tz = tz or config.load().DISPLAY_TZ
    if alert_id is None:
        records = conn.execute(_BUILD_SQL, {"day": day, "tz": tz}).fetchall()
    else:
        records = conn.execute(
            _BUILD_SQL + _ONLY_ALERT_SQL, {"day": day, "tz": tz, "alert_id": alert_id}
        ).fetchall()
    return _sorted_rows(_rows_from(conn, records))


def _sort_key(row: DigestRow) -> tuple[bool, int, str]:
    return (not row.disagreement, -row.occurrence_count, row.alert_id)


def _sorted_rows(rows: list[DigestRow]) -> list[DigestRow]:
    rows.sort(key=_sort_key)
    return rows


def _rows_from(conn: psycopg.Connection, records: Sequence[tuple]) -> list[DigestRow]:
    """`DigestRow`s from the twelve columns `_BUILD_SQL` (and `_REOPENED_BY_REVIEW_SQL`) select,
    unsorted. ① is read for all of them in ONE statement (`queue.latest_suggestions`, the
    batched form of `latest_suggestion`, P11-T20 row 20), so `build` and `reopened_by_review`
    cost a constant number of statements however many rows the day has; it was one query per
    row."""
    suggestions = latest_suggestions(conn, [record[0] for record in records])
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
        suggestion = suggestions.get(alert_id)
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
    return rows


def unreviewed_count(conn: psycopg.Connection, day: str, *, tz: str | None = None) -> int:
    """How many of `day`'s auto-closed clusters (display zone `tz`, real
    alerts only — same rules as `build`) have no `autoclose_reviews` row yet.
    Exposed for P5-T11's health job (the 17:00 threshold is its own, not this
    card's — this card only exposes the number)."""
    tz = tz or config.load().DISPLAY_TZ
    row = conn.execute(_UNREVIEWED_COUNT_SQL, {"day": day, "tz": tz}).fetchone()
    return row[0]


@dataclasses.dataclass(frozen=True)
class ReviewInfo:
    """What `autoclose_reviews` holds about one reviewed alert, with the reviewer's name
    (P11-T07, the digest JSON API): `reviewer_name` is `users.display_name`, or the username
    when the display name is blank; `None` only if the user row is gone, which the foreign key
    forbids. `DigestRow` is unchanged: it is what the CSV and `build` already carry."""

    verdict: str
    reviewer_name: str | None
    reviewed_at: datetime


_REVIEW_DETAILS_SQL = r"""
    SELECT rev.alert_id, rev.verdict,
           CASE WHEN btrim(u.display_name, E' \t\r\n') = '' THEN u.username
                ELSE u.display_name END,
           rev.reviewed_at
    FROM autoclose_reviews rev
    LEFT JOIN users u ON u.user_id = rev.reviewer_id
    WHERE rev.alert_id = ANY(%s)
"""


def review_details(conn: psycopg.Connection, alert_ids: Sequence[str]) -> dict[str, ReviewInfo]:
    """The review on file for each of `alert_ids` that has one, in one query (an alert with no
    review is absent from the answer). Read-only; the digest JSON API calls it after `build`
    and after `review`, so a row shows who reviewed it and when."""
    if not alert_ids:
        return {}
    records = conn.execute(_REVIEW_DETAILS_SQL, (list(alert_ids),)).fetchall()
    return {
        alert_id: ReviewInfo(verdict=verdict, reviewer_name=name, reviewed_at=reviewed_at)
        for alert_id, verdict, name, reviewed_at in records
    }


def rules_enabled(conn: psycopg.Connection) -> bool:
    """Whether any `autoclose_rules` row is enabled (the digest page's "no rule yet" empty
    state, P11-T07). `ix_autoclose_rules_enabled` is a partial index on exactly this."""
    (enabled,) = conn.execute(
        "SELECT EXISTS (SELECT 1 FROM autoclose_rules WHERE enabled)"
    ).fetchone()
    return enabled


# The `alert.auto_closed` event `domain.transitions.open_alert` writes in the transaction that
# sets `closed_at = now()` dates a closing for good: `reopen` clears `closed_at` but the event
# stays. `ix_audit_subject (subject_id, created_at)` serves the lookup. Same day bounds as above.
_AUTO_CLOSED_ON_DAY_SQL = f"""EXISTS (
        SELECT 1 FROM audit_events e
        WHERE e.subject_id = a.alert_id
          AND e.event_type = 'alert.auto_closed'
          AND e.created_at >= {_DAY_LOWER}
          AND e.created_at <  {_DAY_UPPER})"""

_REOPENED_BY_REVIEW_SQL = f"""
    SELECT
        a.alert_id, a.rule_id, a.description, a.severity, a.category,
        a.agent_name, a.occurrence_count, a.first_seen_at, a.last_seen_at,
        a.autoclose_rule_id, r.name, rev.verdict
    FROM autoclose_reviews rev
    JOIN alerts a ON a.alert_id = rev.alert_id
    LEFT JOIN autoclose_rules r ON r.autoclose_rule_id = a.autoclose_rule_id
    WHERE rev.verdict = 'wrong'
      AND a.status <> 'auto_closed'
      AND NOT a.is_synthetic
      AND {_AUTO_CLOSED_ON_DAY_SQL}
"""

_LEFT_DIGEST_SQL = f"""
    SELECT EXISTS (
        SELECT 1 FROM alerts a
        WHERE a.alert_id = %(alert_id)s
          AND a.status <> 'auto_closed'
          AND NOT a.is_synthetic
          AND a.autoclose_rule_id IS NOT NULL
          AND {_AUTO_CLOSED_ON_DAY_SQL})
"""


def reopened_by_review(
    conn: psycopg.Connection,
    day: str,
    *,
    tz: str | None = None,
    alert_id: str | None = None,
) -> list[DigestRow]:
    """The alerts a digest review reopened (P11-T07 fix round 1, F4): an `autoclose_reviews`
    row with verdict `wrong`, an alert no longer `auto_closed`, not synthetic, and an
    `alert.auto_closed` event inside `day` in the display zone. `build` cannot list them (it
    reads `status = 'auto_closed'`, and `reopen` has changed it), yet spec §4.5 has the row keep
    its verdict, its reviewer and "đã mở lại về hàng đợi Tier 1" after the review; the JSON API
    lists them beside `build`'s rows. Only a **`wrong` review** keeps a reopened alert on the
    day: one that Tier 1 reopened, or one reviewed `correct`/`unsure` and then reopened,
    leaves it as before. Same row shape and order as `build`; `alert_id` narrows it to one."""
    tz = tz or config.load().DISPLAY_TZ
    params = {"day": day, "tz": tz}
    sql = _REOPENED_BY_REVIEW_SQL
    if alert_id is not None:
        sql += _ONLY_ALERT_SQL
        params["alert_id"] = alert_id
    return _sorted_rows(_rows_from(conn, conn.execute(sql, params).fetchall()))


def left_digest_on(
    conn: psycopg.Connection, alert_id: str, day: str, *, tz: str | None = None
) -> bool:
    """Whether `alert_id` was auto-closed by a rule on `day` (display zone) and is now in another
    status: not synthetic, `autoclose_rule_id` set, an `alert.auto_closed` event inside the
    day's bounds, `status <> 'auto_closed'` (P11-T07 fix round 1, F1). The digest JSON API
    answers a review of such an alert with the conflict the page maps to "no longer
    auto-closed"; any other alert off the digest is "not in the digest". A plain read, no
    lock: `review` takes the lock and judges the status again."""
    tz = tz or config.load().DISPLAY_TZ
    (found,) = conn.execute(
        _LEFT_DIGEST_SQL, {"alert_id": alert_id, "day": day, "tz": tz}
    ).fetchone()
    return found


def review(
    conn: psycopg.Connection,
    alert_id: str,
    verdict: Literal["correct", "wrong", "unsure"],
    reviewer_id: str,
) -> None:
    """Review round 1 (B1/B2/B3): the whole body is one savepoint
    (`with conn.transaction():`), so a raise midway leaves nothing
    half-written — the caller's own transaction is untouched either way, the
    same pattern `tier1/labels.py`'s `submit_label` uses. In order:

    1. `SELECT status, autoclose_rule_id ... FOR UPDATE` — missing, or not
       `auto_closed`, is `StaleState`, for *every* verdict including
       `correct`/`unsure` (B1: there was no status guard at all before this
       round). The row lock also makes the read-then-write below atomic
       against a second reviewer.
    2. `INSERT INTO autoclose_reviews ... ON CONFLICT (alert_id) DO NOTHING
       RETURNING ...` — no row back means someone already reviewed this
       alert: `AlreadyReviewed` (round 1 ruling flips design note 2(a) —
       the first review wins; changing your mind goes through the Tier-1
       reopen, not a second digest review).
    3. `autoclose.reviewed` (B2/G2 — every human decision is an audit event),
       for every verdict: `{verdict, autoclose_rule_id, suggested_action,
       run_id}`, the last two from `latest_suggestion` (`None` when ① has
       not run yet).
    4. `correct` writes the gold `false_positive` label (`source='digest'`,
       a plain INSERT now — the upsert is gone with (2), so a second
       `correct` from the same reviewer can no longer reach this line) and
       its own `label.created` event (`tier1/labels.py`'s payload shape,
       plus `"source": "digest"`). `wrong` and `unsure` write **no** label: a
       `wrong` verdict says only that auto-closing was wrong, not what the
       alert *is* — inventing a label from "not this" would put a fabricated
       row in P7's evaluation table (design note 2(b), unchanged).
    5. `wrong` reopens the alert (A17, `auto_closed -> queued_tier1`,
       `autoclose_rule_id` untouched by `reopen`) inside the same savepoint,
       then checks `rule.suspected_wrong`.
    """
    with conn.transaction():
        row = conn.execute(
            "SELECT status, autoclose_rule_id FROM alerts WHERE alert_id = %s FOR UPDATE",
            (alert_id,),
        ).fetchone()
        if row is None:
            raise StaleState(f"review: alert_id={alert_id!r} does not exist")
        status, autoclose_rule_id = row
        if status != "auto_closed":
            raise StaleState(
                f"review: alert_id={alert_id!r} is in status {status!r}, " "expected 'auto_closed'"
            )
        rule_id = str(autoclose_rule_id) if autoclose_rule_id is not None else None

        inserted = conn.execute(
            """
            INSERT INTO autoclose_reviews (alert_id, reviewer_id, verdict)
            VALUES (%s, %s, %s)
            ON CONFLICT (alert_id) DO NOTHING
            RETURNING alert_id
            """,
            (alert_id, reviewer_id, verdict),
        ).fetchone()
        if inserted is None:
            raise AlreadyReviewed(f"review: alert_id={alert_id!r} already has a review")

        suggestion = latest_suggestion(conn, alert_id)
        write_event(
            conn,
            "autoclose.reviewed",
            alert_id,
            "admin",
            actor_id=reviewer_id,
            payload={
                "verdict": verdict,
                "autoclose_rule_id": rule_id,
                "suggested_action": suggestion.suggested_action if suggestion else None,
                "run_id": suggestion.run_id if suggestion else None,
            },
        )

        if verdict == "correct":
            conn.execute(
                """
                INSERT INTO triage_labels (alert_id, labeler_id, source, label)
                VALUES (%s, %s, 'digest', 'false_positive')
                """,
                (alert_id, reviewer_id),
            )
            write_event(
                conn,
                "label.created",
                alert_id,
                "admin",
                actor_id=reviewer_id,
                payload={
                    "alert_id": alert_id,
                    "labeler_id": reviewer_id,
                    "label": "false_positive",
                    "confidence": None,
                    "gold_set": None,
                    "source": "digest",
                },
            )
        elif verdict == "wrong":
            reopen(conn, alert_id, reviewer_id, reason="digest")
            _flag_rule_if_suspected_wrong(conn, rule_id)


_RULE_SUSPECTED_WRONG_LOCK_SQL = "SELECT pg_advisory_xact_lock(hashtext(%s))"


def _lock_rule_for_suspected_wrong(conn: psycopg.Connection, rule_id: str) -> None:
    """Round 1 · N9: a transaction-scoped advisory lock on one autoclose
    rule id, taken before the check-then-insert below —
    `ingest/dedup.py`'s `cluster_lock` pattern, one key instead of four, so
    two concurrent `wrong` reviews of the same rule serialise instead of
    both reading `wrong_count = 1` and neither firing, or both firing a
    duplicate event. `None` is refused rather than passed through:
    `pg_advisory_xact_lock(NULL)` silently takes no lock and raises nothing
    (`cluster_lock`'s own reasoning)."""
    if rule_id is None:
        raise PermanentError(
            "_lock_rule_for_suspected_wrong: rule_id is None; "
            "pg_advisory_xact_lock(NULL) takes no lock and raises nothing"
        )
    conn.execute(_RULE_SUSPECTED_WRONG_LOCK_SQL, (rule_id,))


def _flag_rule_if_suspected_wrong(conn: psycopg.Connection, rule_id: str | None) -> None:
    """Design note 3: after a `wrong` review, count that rule's `wrong`
    verdicts in the last 7 days (join `autoclose_reviews` to
    `alerts.autoclose_rule_id`); at >= 2, write `rule.suspected_wrong` once
    per rule per 7-day window — an existing event in the window stops a
    re-fire on every later `wrong`. Round 1 · N9: skipped entirely when the
    alert carries no `autoclose_rule_id` (should not happen for an
    `auto_closed` alert today, but "skip" — not "crash" — is the right
    response if it ever does), and otherwise guarded by the advisory lock
    above. Notification is P5-T11's; this writes the record, not a message."""
    if rule_id is None:
        return
    _lock_rule_for_suspected_wrong(conn, rule_id)

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


def _previous_day(day: str) -> str:
    """Pure calendar arithmetic on an already-fixed day string — not a
    control-timestamp read (§9), so plain Python `date` math is fine here:
    nothing about "yesterday" depends on this process's clock, only on the
    `day` value already handed in."""
    return (date.fromisoformat(day) - timedelta(days=1)).isoformat()


def _next_run_expr(tz: str, *, as_of: sql.Composable | None = None) -> sql.Composable:
    """The **next** 08:00 local (round 1 · A1): today's, if `as_of` (default
    `now()`, the database's own clock — §9) is still before 08:00 local;
    otherwise tomorrow's. A worker restart at 07:00 local after a broken
    chain must still get that day's digest, which is exactly the branch this
    adds — `run_digest_job`'s own self re-arm always lands in the "tomorrow"
    branch without any special-casing, because it runs at or after 08:00 (it
    *is* the 08:00 job).

    `tz` is embedded via `sql.Literal` (psycopg's own safe value quoting,
    not string formatting): `enqueue()` (`infra/jobs.py`, a shared file this
    card does not touch) binds only `job_type`/`subject_id` positionally, so
    a third bound parameter has nowhere to go — its own docstring names
    `sql.Literal` as the sanctioned way to build a `scheduled_at` expression.
    `as_of` is the same kind of seam, private to this module: every real
    caller leaves it `None` (`now()`); a test may pass a fixed
    `sql.Literal`-wrapped instant to exercise both sides of 08:00
    deterministically."""
    as_of = as_of or sql.SQL("now()")
    return sql.SQL(
        "((CASE WHEN ({as_of} AT TIME ZONE {tz})::time < time '08:00'"
        " THEN ({as_of} AT TIME ZONE {tz})::date"
        " ELSE ({as_of} AT TIME ZONE {tz})::date + 1 END)"
        " + time '08:00') AT TIME ZONE {tz}"
    ).format(as_of=as_of, tz=sql.Literal(tz))


def ensure_scheduled(
    conn: psycopg.Connection, *, tz: str | None = None, as_of: sql.Composable | None = None
) -> int | None:
    """The self-chaining half (design note 4, round 1 · S4/A1): enqueue the
    next `digest` job **at 08:00 local** (`tz`, default `cfg.DISPLAY_TZ`), or
    do nothing if one is already live. See `_next_run_expr` for "next".

    `subject_id` (the ISO date that makes the job idempotent per day) is
    that run's date *in the display zone*, read back from the database so it
    never disagrees with `scheduled_at` or with this process's own clock —
    both come from the one `_next_run_expr(...)` Composable, evaluated twice
    inside the same transaction (so the same `now()`, per Postgres's own
    transaction-stable clock) rather than computed twice by two different
    formulas that could drift apart. Reachable from the CLI (`--ensure`) and
    called once at every worker start (`web/worker.py`, round 1 · A2) so the
    chain seeds and re-arms itself without an Owner action; the CLI flag
    stays for re-arming by hand if the chain is ever found broken.
    """
    tz = tz or config.load().DISPLAY_TZ
    run_at = _next_run_expr(tz, as_of=as_of)
    # `({run_at}) AT TIME ZONE {tz}` converts the timestamptz back to a naive
    # local timestamp before `::date` — casting a timestamptz straight to
    # `date` uses the session's own TimeZone setting, not `tz`, and the two
    # need not agree.
    next_run_date = conn.execute(
        sql.SQL("SELECT (({run_at}) AT TIME ZONE {tz})::date::text").format(
            run_at=run_at, tz=sql.Literal(tz)
        )
    ).fetchone()[0]
    return enqueue(conn, "digest", next_run_date, scheduled_at=run_at)


def run_digest_job(conn: psycopg.Connection, job: Job) -> None:
    """§6.5's `digest` handler. Round 1 · S4: the job that fires on local day
    D (`job.subject_id`) reviews local day D-1 — `ensure_scheduled` always
    arms *tomorrow*, so the job that runs today is reviewing what closed
    yesterday. Builds the digest (so a broken query fails the job loudly,
    not silently — nothing here persists the rows; the CSV and the page,
    P5-T09, build on demand from `build()` itself), logs a one-line summary,
    then re-arms tomorrow's job."""
    cfg = config.load()
    reviewed_day = _previous_day(job.subject_id)
    rows = build(conn, reviewed_day, tz=cfg.DISPLAY_TZ)
    print(json.dumps({"day": reviewed_day, "clusters": len(rows)}))
    ensure_scheduled(conn, tz=cfg.DISPLAY_TZ)


# =============================================================================
# CLI — design note 5's CSV path and design note 4's `--ensure`, neither of
# which needs a running worker or a browser.
# =============================================================================


def _cmd(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m app.tier1.digest",
        description=(
            "--ensure enqueues tomorrow's digest job (08:00 local, cfg.DISPLAY_TZ) if "
            "the chain is not already armed (re-arms it by hand after a break). --csv "
            "PATH writes the day's digest as CSV; --day YYYY-MM-DD picks the day "
            "(default: today, local). Either or both."
        ),
    )
    parser.add_argument("--ensure", action="store_true", help="enqueue tomorrow's digest job")
    parser.add_argument("--csv", metavar="PATH", help="write the day's digest as CSV to PATH")
    parser.add_argument("--day", metavar="YYYY-MM-DD", help="default: today, local (DISPLAY_TZ)")
    parser.add_argument("--env-file", default=".env")
    args = parser.parse_args(argv)
    if not args.ensure and not args.csv:
        parser.error("nothing to do: pass --ensure and/or --csv PATH")

    cfg = config.load(env_file=args.env_file)
    tz = cfg.DISPLAY_TZ
    conn = db.connect(cfg.DATABASE_URL)
    try:
        if args.ensure:
            job_id = ensure_scheduled(conn, tz=tz)
            conn.commit()
            print(f"digest: ensure_scheduled -> job_id={job_id}")
        if args.csv:
            day = (
                args.day
                or conn.execute(
                    "SELECT (now() AT TIME ZONE %(tz)s)::date::text", {"tz": tz}
                ).fetchone()[0]
            )
            rows = build(conn, day, tz=tz)
            Path(args.csv).write_text(to_csv(rows), encoding="utf-8")
            print(f"digest: wrote {len(rows)} row(s) for {day} ({tz}) to {args.csv}")
    finally:
        conn.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    return _cmd(argv)


if __name__ == "__main__":
    raise SystemExit(main())
