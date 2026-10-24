"""The decision history of a subject: what analysts decided before, no AI (P13-T02, DEC-210, §7.6).

These are analysts' decisions themselves, so no approval is needed, and only closed fields and counts
are read: never an analyst's text. The key levels are tried from the tightest to the loosest; the
first one with at least one decision wins:

    0  soar_case      the SOAR `enrichment.case.dedup_key` without its `|yyyyMMdd-HH` bucket
    1  cluster        rule, source address, destination address, host
    2  scenario_host  `soar_scenario` and host
    3  rule_host      rule and host
    4  rule_source    rule, and the same source address or the same user
    5  category_host  category and host (skipped for the category `unknown`, which says nothing)

What is counted: head alerts (`duplicate_of IS NULL`) first seen within `RAG_HISTORY_DAYS` that carry
a decision, and the decision of a counted alert is

    no case, status closed_fp / closed_benign        tier1_closed_fp / tier1_closed_benign
    in a case still `investigating`                  escalated_open
    in a concluded case                              the case's status

An alert with no decision (queued, being worked, auto-closed) is not a past decision and is not
counted, so a level whose alerts are all undecided has no data and the next level is tried.

For a case subject the key of a level is the set of the keys of its heads: an earlier alert counts
when it matches any head at that level (once, however many heads it matches).

Self-exclusion (A5): the subject alert, its head and the head's duplicates, its case and that case's
alerts; for a case, the case and its alerts. Nothing here ever counts the thing being asked about.

`DEDUP_KEY_EXPRESSION` is written exactly as `ix_alerts_soar_dedup_key` (migration 020) is, because
an expression index serves only a query that spells the expression the same way. The query adds a
prefix test on that expression (a plain `LIKE`, which a btree can serve under the `C` collation) and
an exact test on the key with its bucket removed; the second one decides.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import psycopg

from app.infra.config import Config
from app.rag.subject import Subject

LEVELS: tuple[tuple[int, str], ...] = (
    (0, "soar_case"),
    (1, "cluster"),
    (2, "scenario_host"),
    (3, "rule_host"),
    (4, "rule_source"),
    (5, "category_host"),
)
#: The keys of `History.by_conclusion`: all six are always there, 0 where nothing happened.
CONCLUSIONS: tuple[str, ...] = (
    "tier1_closed_fp",
    "tier1_closed_benign",
    "escalated_open",
    "concluded_fp",
    "concluded_policy_violation",
    "confirmed_incident",
)
#: The category of an alert nothing resolved: not a signal at level 5.
UNKNOWN = "unknown"
EXAMPLES = 3

DEDUP_KEY_EXPRESSION = "(a.raw_payload #>> '{enrichment,case,dedup_key}')"
_SCENARIO_EXPRESSION = "(a.raw_payload #>> '{enrichment,scenario,id}')"
_BUCKET_IN_SQL = r"\|[0-9]{8}-[0-9]{2}$"
_BUCKET = re.compile(r"\|[0-9]{8}-[0-9]{2}\Z")
_LIKE_SPECIAL = re.compile(r"([\\%_])")
_NOT_PRINTABLE = re.compile(r"[^\x21-\x7e]")


@dataclass(frozen=True)
class History:
    level: int | None
    key_name: str | None
    total: int
    by_conclusion: dict[str, int]
    last_seen: datetime | None
    examples: tuple[str, ...]


@dataclass(frozen=True)
class Exclusion:
    alert_ids: frozenset[str]
    case_ids: frozenset[str]


_EMPTY = History(None, None, 0, dict.fromkeys(CONCLUSIONS, 0), None, ())


# ── self-exclusion ────────────────────────────────────────────────────────────────────────────


def as_uuids(values: Iterable[str]) -> list[uuid.UUID]:
    """The values that are UUIDs, as `uuid.UUID`; anything else is left out."""
    found = []
    for value in values:
        try:
            found.append(uuid.UUID(str(value)))
        except ValueError:
            continue
    return found


def _alerts_of_cases(conn: psycopg.Connection, case_ids: Iterable[str]) -> set[str]:
    """Every alert of the cases: those marked with the case, the heads in `case_alerts`, and the
    duplicates of those heads."""
    wanted = as_uuids(case_ids)
    if not wanted:
        return set()
    rows = conn.execute(
        "SELECT alert_id FROM alerts WHERE case_id = ANY(%(cases)s)"
        " UNION SELECT alert_id FROM case_alerts WHERE case_id = ANY(%(cases)s)"
        " UNION SELECT alert_id FROM alerts WHERE duplicate_of IN"
        " (SELECT alert_id FROM case_alerts WHERE case_id = ANY(%(cases)s))",
        {"cases": wanted},
    ).fetchall()
    return {alert_id for (alert_id,) in rows}


def self_exclusion(conn: psycopg.Connection, subject: Subject) -> Exclusion:
    """What the history and the candidate search must not count for `subject` (A5)."""
    if subject.kind == "case":
        cases = {subject.id}
        return Exclusion(frozenset(_alerts_of_cases(conn, cases)), frozenset(cases))

    row = conn.execute(
        "SELECT duplicate_of, case_id FROM alerts WHERE alert_id = %s", (subject.id,)
    ).fetchone()
    if row is None:
        return Exclusion(frozenset({subject.id}), frozenset())
    head_id = row[0] or subject.id
    cluster = {
        alert_id
        for (alert_id,) in conn.execute(
            "SELECT alert_id FROM alerts WHERE alert_id = %(head)s OR duplicate_of = %(head)s",
            {"head": head_id},
        ).fetchall()
    }
    cluster.add(subject.id)
    head_case = conn.execute(
        "SELECT case_id FROM alerts WHERE alert_id = %s", (head_id,)
    ).fetchone()
    cases = {str(case_id) for case_id in (row[1], head_case[0] if head_case else None) if case_id}
    return Exclusion(frozenset(cluster | _alerts_of_cases(conn, cases)), frozenset(cases))


# ── the keys of the subject ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _Head:
    rule_id: str
    srcip: str
    dstip: str
    agent_name: str
    alert_user: str | None
    category: str
    scenario: str | None
    dedup_base: str | None


_HEAD_SELECT = (
    "SELECT a.rule_id, a.srcip, a.dstip, a.agent_name, a.alert_user, a.category,"
    " CASE WHEN jsonb_typeof(a.raw_payload #> '{enrichment,scenario,id}') = 'string'"
    "      THEN a.raw_payload #>> '{enrichment,scenario,id}' END,"
    " CASE WHEN jsonb_typeof(a.raw_payload #> '{enrichment,case,dedup_key}') = 'string'"
    "      THEN a.raw_payload #>> '{enrichment,case,dedup_key}' END"
    " FROM alerts a"
)


def _heads(conn: psycopg.Connection, subject: Subject) -> list[_Head]:
    if subject.kind == "alert":
        rows = conn.execute(_HEAD_SELECT + " WHERE a.alert_id = %s", (subject.id,)).fetchall()
    else:
        rows = conn.execute(
            _HEAD_SELECT + " JOIN case_alerts ca ON ca.alert_id = a.alert_id"
            " WHERE ca.case_id = %s ORDER BY a.alert_id",
            (subject.id,),
        ).fetchall()
    heads = []
    for rule_id, srcip, dstip, agent_name, alert_user, category, scenario, dedup_key in rows:
        base = _BUCKET.sub("", dedup_key) if dedup_key else None
        heads.append(
            _Head(rule_id, srcip, dstip, agent_name, alert_user, category, scenario, base or None)
        )
    return heads


# ── the levels ────────────────────────────────────────────────────────────────────────────────

_PREFIX = (
    "WITH hit AS ("
    " SELECT a.alert_id, a.first_seen_at, a.last_seen_at,"
    "  CASE"
    "   WHEN a.case_id IS NULL AND a.status = 'closed_fp' THEN 'tier1_closed_fp'"
    "   WHEN a.case_id IS NULL AND a.status = 'closed_benign' THEN 'tier1_closed_benign'"
    "   WHEN c.status = 'investigating' THEN 'escalated_open'"
    "   WHEN c.status IN ('concluded_fp', 'concluded_policy_violation', 'confirmed_incident')"
    "    THEN c.status"
    "  END AS conclusion"
    " FROM alerts a LEFT JOIN cases c ON c.case_id = a.case_id"
    " WHERE a.duplicate_of IS NULL"
    "  AND a.first_seen_at >= now() - make_interval(days => %(days)s)"
    "  AND a.alert_id <> ALL(%(skip_alerts)s::text[])"
    "  AND ("
)
_SUMMARY = (
    "))"
    " SELECT conclusion, count(*), max(last_seen_at) FROM hit"
    " WHERE conclusion IS NOT NULL GROUP BY conclusion"
)
_EXAMPLES = (
    "))"
    " SELECT alert_id FROM hit WHERE conclusion IS NOT NULL"
    " ORDER BY first_seen_at DESC, alert_id LIMIT %(examples)s"
)

#: Levels that compare a tuple of columns with the tuples of the heads, and the column of each.
_TUPLE_COLUMNS: dict[int, tuple[str, ...]] = {
    1: ("a.rule_id", "a.srcip", "a.dstip", "a.agent_name"),
    2: (_SCENARIO_EXPRESSION, "a.agent_name"),
    3: ("a.rule_id", "a.agent_name"),
    5: ("a.category", "a.agent_name"),
}


def _tuple_clause(
    columns: Sequence[str], tag: str, rows: Sequence[Sequence[str]]
) -> tuple[str, dict]:
    """`(c1, c2) IN (SELECT * FROM unnest(%(tag_0)s, %(tag_1)s))` and its parameters: one array
    per column, so any number of key tuples is one statement of fixed text."""
    names = [f"{tag}_{position}" for position in range(len(columns))]
    unnest = ", ".join(f"%({name})s::text[]" for name in names)
    clause = f"({', '.join(columns)}) IN (SELECT * FROM unnest({unnest}))"
    arrays = {name: [row[position] for row in rows] for position, name in enumerate(names)}
    return clause, arrays


def _distinct(rows: Iterable[tuple[str, ...]]) -> list[tuple[str, ...]]:
    return list(dict.fromkeys(rows))


def _level_query(level: int, heads: Sequence[_Head]) -> tuple[str, dict] | None:
    """The predicate of `level` over the heads' keys and its parameters; None when no head has
    the data this level needs."""
    if level == 0:
        bases = list(dict.fromkeys(head.dedup_base for head in heads if head.dedup_base))
        if not bases:
            return None
        escaped = [_LIKE_SPECIAL.sub(r"\\\1", base) for base in bases]
        patterns = [pattern for text in escaped for pattern in (text, text + "|%")]
        predicate = (
            f"{DEDUP_KEY_EXPRESSION} LIKE ANY(%(like)s::text[])"
            f" AND regexp_replace({DEDUP_KEY_EXPRESSION}, %(bucket)s, '') = ANY(%(base)s::text[])"
        )
        return predicate, {"like": patterns, "bucket": _BUCKET_IN_SQL, "base": bases}
    if level == 1:
        rows = _distinct((h.rule_id, h.srcip, h.dstip, h.agent_name) for h in heads)
    elif level == 2:
        rows = _distinct((h.scenario, h.agent_name) for h in heads if h.scenario)
    elif level == 3:
        rows = _distinct((h.rule_id, h.agent_name) for h in heads)
    elif level == 5:
        rows = _distinct((h.category, h.agent_name) for h in heads if h.category != UNKNOWN)
    else:  # level 4: the rule with the same source address, or the rule with the same user
        by_source = _distinct((h.rule_id, h.srcip) for h in heads if h.srcip)
        by_user = _distinct((h.rule_id, h.alert_user) for h in heads if h.alert_user)
        if not by_source and not by_user:
            return None
        source_clause, source_params = _tuple_clause(("a.rule_id", "a.srcip"), "src", by_source)
        user_clause, user_params = _tuple_clause(("a.rule_id", "a.alert_user"), "usr", by_user)
        return f"{source_clause} OR {user_clause}", {**source_params, **user_params}
    if not rows:
        return None
    return _tuple_clause(_TUPLE_COLUMNS[level], f"k{level}", rows)


def decision_history(conn: psycopg.Connection, subject: Subject, cfg: Config) -> History:
    """The history of `subject` (module doc). Empty — `level` None, `total` 0 — when there is none,
    when the subject does not exist, or when `RAG_HISTORY_DAYS` is 0."""
    if cfg.RAG_HISTORY_DAYS <= 0:
        return _EMPTY
    heads = _heads(conn, subject)
    if not heads:
        return _EMPTY
    skip = self_exclusion(conn, subject)
    common: dict[str, Any] = {
        "days": cfg.RAG_HISTORY_DAYS,
        "skip_alerts": sorted(skip.alert_ids),
        "examples": EXAMPLES,
    }
    for level, key_name in LEVELS:
        built = _level_query(level, heads)
        if built is None:
            continue
        predicate, params = built
        arguments = {**common, **params}
        rows = conn.execute(_PREFIX + predicate + _SUMMARY, arguments).fetchall()
        if not rows:
            continue
        counts = {conclusion: count for conclusion, count, _ in rows}
        examples = conn.execute(_PREFIX + predicate + _EXAMPLES, arguments).fetchall()
        return History(
            level=level,
            key_name=key_name,
            total=sum(counts.values()),
            by_conclusion={name: counts.get(name, 0) for name in CONCLUSIONS},
            last_seen=max(last_seen for _, _, last_seen in rows),
            examples=tuple(alert_id for (alert_id,) in examples),
        )
    return _EMPTY


# ── rendering ─────────────────────────────────────────────────────────────────────────────────


def _id_text(value: str) -> str:
    return _NOT_PRINTABLE.sub("?", value)


def render_history(h: History) -> str:
    """One `key: value` line per field, for the `decision_history` block."""
    other = sorted(name for name in h.by_conclusion if name not in CONCLUSIONS)
    conclusions = ", ".join(
        f"{name}={h.by_conclusion.get(name, 0)}" for name in [*CONCLUSIONS, *other]
    )
    last_seen = "none" if h.last_seen is None else h.last_seen.astimezone(UTC).date().isoformat()
    examples = ", ".join(_id_text(alert_id) for alert_id in h.examples) or "none"
    return "\n".join(
        [
            f"level: {'none' if h.level is None else h.level}",
            f"key_name: {h.key_name or 'none'}",
            f"total: {h.total}",
            f"by_conclusion: {conclusions}",
            f"last_seen: {last_seen}",
            f"examples: {examples}",
        ]
    )
