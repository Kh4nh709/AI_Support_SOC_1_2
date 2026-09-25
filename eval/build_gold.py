#!/usr/bin/env python3
"""Build the gold-set candidates: G1 from the offline fold, G2 from the lab windows.

**G1 comes from the fold, not from `alerts` (DEC-084, Route A).** The database's
307 replay heads are the clustering of the afternoon the replay ran -- the
product's dedup anchors on `now()` (`ingest/dedup.py:90-91`) -- while
`eval/dedup_verify.py`'s fold over each alert's own `alert_time` reproduces the
Owner's independently measured 3,070 within 0.62 % (3,051 clusters from 92,011
parsed lines, DEC-077). So G1 is *materialised* from that fold into two
committed files (planning decision 1 -- files, not a table):
`eval/g1_clusters.csv` (one row per fold cluster; the head's fields, the
cluster's numbers, `excluded_reason`) and `eval/g1_members.csv.gz` (one row per
parsed alert, `cluster_id, alert_id, alert_time`). The only exclusion is
DEC-053's 67 loopback `ssh_brute_force` clusters / 662 alerts, flagged in the
file and left out of the **pool** (2,984 clusters) -- nothing else is filtered
(DEC-052: `unknown` is capped, never dropped; `DESKTOP-MIRSO17`'s 23 stay in,
DEC-058). `source` on every G1 row is the constant `replay`: those rows were
ingested as such (DEC-019/DEC-079) and nothing cluster-level is ever read from
`alerts` for G1 -- `--check-db` only proves each head *exists* there, because
`triage_labels.alert_id` is a foreign key to `alerts`.

**G2 still comes from `alerts`** (`source = 'lab'`, heads inside the windows
`eval/lab_tag.py` recorded in `eval/lab_windows.csv`), because the lab runs in
real time and `now()`-anchored dedup is its right clock. A head inside a
recorded window that is still `source <> 'lab'` is a forgotten tag: the run
stops with exit 3 and prints the exact `lab_tag.py` command -- it never shrinks
G2 silently (planning decision 3). Cluster numbers for G2 are recounted
clock-free from the members' own `alert_time` (`count(*)`, `min`, `max` over
`alert_id = head OR duplicate_of = head`), never from `first_seen_at` /
`last_seen_at`, which are DB-clock values.

**One allocator, every parameter on the CLI (planning decisions 2 and 10).**
Strata are `category x severity` on the DEC-053 band the parser already wrote
into `Alert.severity`. G1's defaults: every `critical`/`high` cluster of the
pool enters (`--take-all-crit-high`, 137 of 2,984 today), `unknown`'s share is
capped (`--unknown-cap-pct 40` -> 120 of 300), the rest is allocated over the
classified medium/low strata proportionally to pool size with largest-remainder
rounding and a per-category floor (`--category-floor 25`) topped up from the
largest allocation. G2 runs the same function with the take-all rule off:
classified clusters first (a scenario yields a handful), then `unknown` fills
to the target under its cap. Draws are `random.Random(f"{seed}:{stratum}")
.sample(sorted(ids), k)` -- sorted so the draw depends on the seed and the set,
seeded per stratum so equal-size strata do not repeat the same offsets. The
defaults are the Director's until INBOX `2026-09-16 . P6 / G1 sampling design`
is answered; `eval/gold_coverage.md` prints the parameters used, so a re-run
under the ruled values is one command and one diff.

**Every number with its denominator (DEC-052).** 3,051 is this fold's cluster
count; 3,070 / 1,812 are `scripts/measure_clusters.py`'s archive-order fold;
2,984 is the pool; 300 is the sample. They are never quoted against each other.

Run from the repository root, with `PYTHONPATH=backend`::

    # G2 only from the lab windows (DEC-111 -- the live build since G1 was dropped):
    PYTHONPATH=backend python3 eval/build_gold.py --g2 \\
        --lab-windows eval/lab_windows.csv --env-file .env --out-dir eval
    # G1 -- void since DEC-111, kept runnable as the record:
    PYTHONPATH=backend python3 eval/build_gold.py \\
        --archive-file /home/user1/archive/alerts-2026-08-08_09-07.jsonl --g1 \\
        --env-file .env --out-dir eval [--check-db]
    # G1 -- void since DEC-111, kept runnable as the record (G1 + G2 together):
    PYTHONPATH=backend python3 eval/build_gold.py --archive-file ... --g1 --g2 \\
        --lab-windows eval/lab_windows.csv --env-file .env --out-dir eval

`--archive-file` is required for `--g1` and `--check-db`; `--g2` on its own
runs without it and writes only the G2 files (DEC-111). Each G2 head is scoped
to its scenario's declared Expected rules in `docs/lab-scenarios.md` (DEC-114);
`truth_label` (attack -> `escalate`, benign window -> `benign`, DEC-111/DEC-115)
is written per candidate.

Exit codes: 0 files written, floors met . 1 files written, a floor missed
(`FLOOR MISS G1 <n> < 200` / `FLOOR MISS G2 <n> < 60`; the files are still
valid, the Director decides) . 2 `--archive-file` missing/unreadable or DSN
unreadable . 3 an untagged, missing or overlapping lab window, or unreadable
Expected rules . 4 `--check-db` found a G1 head missing from `alerts`.
The database is opened only for `--g2` and `--check-db`, read-only.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import itertools
import math
import random
import re
import sys
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from fractions import Fraction
from pathlib import Path

# Sibling import by path: eval/ is a composition root, not a package on
# sys.path -- this insert makes `import dedup_verify` work both as a script and
# under the tests, which load this file with `importlib` the same way.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import dedup_verify
import psycopg
from app.infra import config
from app.ingest.category import PRIORITY

EXIT_OK = 0
EXIT_FLOOR_MISS = 1
EXIT_ARCHIVE = 2
EXIT_LAB_WINDOW = 3
EXIT_CHECK_DB = 4

#: The seed for every draw (`prompts/P6.md:32`). `backend/app/tier1/labels.py`
#: carries the same literal as `LABEL_ORDER_SEED` -- two literals, no import
#: across the `eval` boundary (rule 10 of the P6 index).
EVAL_SEED = 20260904
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low")
CRIT_HIGH: frozenset[str] = frozenset({"critical", "high"})
UNKNOWN = "unknown"
PLAYBOOK_CATEGORIES: tuple[str, ...] = tuple(name for name in PRIORITY if name != UNKNOWN)
LOOPBACK_SRCIP = "127.0.0.1"
LOOPBACK_CATEGORY = "ssh_brute_force"
EXCLUDED_LOOPBACK = "loopback_ssh_brute_force"
DESKTOP_AGENT = "DESKTOP-MIRSO17"

#: A window's kind -> the gold label it implies. DEC-111 set `benign -> false_positive`;
#: the Director amended a benign window's truth to `benign` at E5 (DEC-115), so the
#: twin mapping is withdrawn and both twins and the benign block resolve to `benign`.
TRUTH_BY_KIND: dict[str, str] = {"attack": "escalate", "benign": "benign"}
#: `eval/lab_tag.py`'s extra `category_expected` for the once-a-day benign block; it
#: declares no Expected rules, so every head inside its window is in scope (DEC-114).
BENIGN_BLOCK = "benign"
#: `excluded_reason` for a head inside a window whose `rule_id` is not one of the
#: scenario's declared Expected rules: no candidate row, counted per window (DEC-114).
EXCLUDED_IN_WINDOW_UNEXPECTED = "in_window_unexpected"
#: Limitation (xii), written verbatim into `gold_coverage.md` right after the G2
#: enrichment line (DEC-111; P6-T06 would have placed DEC-086's G1 sentence, but it
#: was retired and never merged -- this is G2's).
DEC111_SENTENCE = (
    "This corpus is author-generated lab traffic on the author's host with "
    "window-known truth: no rate computed from it is an estate rate, of any estate."
)

CLUSTER_COLUMNS: tuple[str, ...] = (
    "cluster_id",
    "alert_id",
    "rule_id",
    "category",
    "severity",
    "agent_name",
    "alert_user",
    "srcip",
    "dstip",
    "first_seen",
    "last_seen",
    "occurrence_count",
    "closed_by",
    "excluded_reason",
)
MEMBER_COLUMNS: tuple[str, ...] = ("cluster_id", "alert_id", "alert_time")
CANDIDATE_COLUMNS: tuple[str, ...] = (
    "cluster_id",
    "gold_set",
    "alert_id",
    "category",
    "severity",
    "source",
    "stratum",
    "occurrence_count",
    "first_seen",
    "last_seen",
    "agent_name",
    "rule_id",
    "scenario_id",
    "kind",
    "truth_label",
)
LAB_WINDOWS_HEADER: tuple[str, ...] = (
    "scenario_id",
    "category_expected",
    "kind",
    "agent_name",
    "since",
    "until",
    "retagged_rows",
    "tagged_at",
)
CHECK_DB_CHUNK = 1_000

_G2_HEADS_SQL = (
    "SELECT alert_id, rule_id, category, severity, source, agent_name, alert_user, "
    "srcip, dstip, alert_time, occurrence_count "
    "FROM alerts "
    "WHERE duplicate_of IS NULL AND NOT is_synthetic AND agent_name = %s "
    "AND alert_time BETWEEN %s AND %s "
    "ORDER BY alert_time, alert_id"
)
_G2_RECOUNT_SQL = (
    "SELECT count(*), min(alert_time), max(alert_time) FROM alerts "
    "WHERE alert_id = %s OR duplicate_of = %s"
)
_CHECK_DB_SQL = "SELECT alert_id, source FROM alerts WHERE alert_id = ANY(%s)"


@dataclass(frozen=True)
class ClusterRow:
    """One candidate cluster: a fold cluster (G1) or a lab head (G2)."""

    cluster_id: str
    gold_set: str
    alert_id: str
    rule_id: str
    category: str
    severity: str
    agent_name: str
    alert_user: str | None
    srcip: str
    dstip: str
    source: str
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int
    closed_by: str
    excluded_reason: str
    scenario_id: str = ""
    kind: str = ""
    truth_label: str = ""

    @property
    def stratum(self) -> str:
        return f"{self.category}|{self.severity}"


@dataclass(frozen=True)
class AllocParams:
    """The allocator's parameters as given on the CLI, for the coverage table."""

    target: int
    floor: int
    unknown_cap_pct: float
    take_all_crit_high: bool
    category_floor: int
    seed: int

    def describe(self) -> str:
        return (
            f"target={self.target} floor={self.floor} unknown_cap_pct={self.unknown_cap_pct} "
            f"take_all_crit_high={self.take_all_crit_high} category_floor={self.category_floor} "
            f"seed={self.seed}"
        )


@dataclass(frozen=True)
class LabWindow:
    scenario_id: str
    category_expected: str
    kind: str
    agent_name: str
    since: datetime
    until: datetime


@dataclass(frozen=True)
class CheckDb:
    present: int
    replay: int
    missing: tuple[str, ...]


class DsnUnreadable(Exception):
    """`psycopg.connect` failed -- a DSN libpq cannot parse (`ProgrammingError`)
    or a server it cannot reach (`OperationalError`); the DSN itself is never
    carried in the message."""


class UntaggedWindow(Exception):
    def __init__(self, window: LabWindow, untagged: int) -> None:
        super().__init__(window.scenario_id)
        self.window = window
        self.untagged = untagged


class ExpectedRulesUnreadable(Exception):
    """`docs/lab-scenarios.md` could not yield the declared Expected rules: a
    playbook category with no table, a table with zero ids, the same id under two
    categories, or a lab window whose category has no declared table (DEC-114)."""


class OverlappingWindows(Exception):
    """Two windows of the same agent overlap, so a head could carry two truths
    (DEC-114). Both are named; the run stops before any query."""

    def __init__(self, first: LabWindow, second: LabWindow) -> None:
        super().__init__(f"{first.scenario_id} / {second.scenario_id}")
        self.first = first
        self.second = second


MemberRow = tuple[str, str, datetime]


def _iso(instant: datetime) -> str:
    return instant.astimezone(UTC).isoformat()


# --- G1: the fold ------------------------------------------------------------------


def g1_rows(
    stats: dedup_verify.ArchiveStats, clusters: list[dedup_verify.Cluster]
) -> list[ClusterRow]:
    """One `ClusterRow` per fold cluster, sorted by `cluster_id`.

    `cluster_id = alert_id = members[0]` (the head, by the fold's construction);
    the descriptive fields are the head `Alert`'s; `source` is the constant
    `replay` -- never a DB read (DEC-079). `excluded_reason` marks DEC-053's
    loopback `ssh_brute_force` clusters and nothing else.
    """
    by_id = {alert.alert_id: alert for alert in stats.alerts}
    rows: list[ClusterRow] = []
    for cluster in clusters:
        head = by_id[cluster.members[0]]
        excluded = (
            EXCLUDED_LOOPBACK
            if head.category == LOOPBACK_CATEGORY and head.srcip == LOOPBACK_SRCIP
            else ""
        )
        rows.append(
            ClusterRow(
                cluster_id=head.alert_id,
                gold_set="G1",
                alert_id=head.alert_id,
                rule_id=head.rule_id,
                category=head.category,
                severity=head.severity,
                agent_name=head.agent_name,
                alert_user=head.alert_user,
                srcip=head.srcip,
                dstip=head.dstip,
                source="replay",
                first_seen=cluster.first_seen,
                last_seen=cluster.last_seen,
                occurrence_count=cluster.count,
                closed_by=cluster.closed_by or "",
                excluded_reason=excluded,
            )
        )
    rows.sort(key=lambda row: row.cluster_id)
    return rows


def g1_members(
    stats: dedup_verify.ArchiveStats, clusters: list[dedup_verify.Cluster]
) -> list[MemberRow]:
    """`(cluster_id, alert_id, alert_time)` for every parsed alert, sorted by
    `(cluster_id, alert_time, alert_id)`."""
    by_id = {alert.alert_id: alert for alert in stats.alerts}
    members = [
        (cluster.members[0], alert_id, by_id[alert_id].alert_time)
        for cluster in clusters
        for alert_id in cluster.members
    ]
    members.sort(key=lambda member: (member[0], member[2], member[1]))
    return members


# --- G2: the lab windows -------------------------------------------------------------


def read_lab_windows(path: Path) -> list[LabWindow]:
    """P6-T05's provenance rows; `[]` when the file is absent or header-only."""
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    return [
        LabWindow(
            scenario_id=row["scenario_id"],
            category_expected=row["category_expected"],
            kind=row["kind"],
            agent_name=row["agent_name"],
            since=datetime.fromisoformat(row["since"]),
            until=datetime.fromisoformat(row["until"]),
        )
        for row in rows
    ]


_EXPECTED_ID_RE = re.compile(r"^\|\s*`(\d+)`")


def expected_rules(path: Path) -> dict[str, frozenset[str]]:
    """Parse the declared Expected rules from `docs/lab-scenarios.md` (DEC-114).

    A `### <name>` line whose `<name>` is a playbook category opens that
    category; its next `#### Expected rules` heading opens the table; each table
    row whose first cell is a backticked integer adds that id; any `## `/`### `/
    `#### ` heading closes the table. The runbook, committed before any window
    ran, is the single source of truth -- a constant in code would be a second
    copy that can drift, and an id added at build time is exactly the edit
    DEC-114 forbids. A category with no table, a table with zero ids, or the same
    id under two categories raises `ExpectedRulesUnreadable`.
    """
    playbook = set(PLAYBOOK_CATEGORIES)
    result: dict[str, set[str]] = {}
    seen_ids: dict[str, str] = {}
    current: str | None = None  # the open playbook category
    in_table = False  # inside its `#### Expected rules` table
    lines = path.read_text(encoding="utf-8").splitlines()
    for line in lines:
        if line.startswith("### "):
            name = line[4:].strip()
            in_table = False
            current = name if name in playbook else None
        elif line.startswith("#### "):
            in_table = current is not None and line.strip() == "#### Expected rules"
            if in_table:
                result.setdefault(current, set())
        elif line.startswith("## "):
            current, in_table = None, False
        elif in_table and current is not None:
            match = _EXPECTED_ID_RE.match(line)
            if match:
                rule_id = match.group(1)
                if rule_id in seen_ids and seen_ids[rule_id] != current:
                    raise ExpectedRulesUnreadable(
                        f"{path}: rule id {rule_id} is declared under both "
                        f"{seen_ids[rule_id]!r} and {current!r}"
                    )
                seen_ids[rule_id] = current
                result[current].add(rule_id)
    empty = sorted(name for name, ids in result.items() if not ids)
    if empty:
        raise ExpectedRulesUnreadable(
            f"{path}: playbook categor{'y' if len(empty) == 1 else 'ies'} "
            f"{', '.join(empty)} declare no Expected rules"
        )
    if not result:
        raise ExpectedRulesUnreadable(
            f"{path}: no `#### Expected rules` table found under any playbook category"
        )
    return {name: frozenset(ids) for name, ids in result.items()}


def assert_windows_disjoint(windows: Sequence[LabWindow]) -> None:
    """Refuse overlapping windows of the same agent (DEC-114): truth is per
    window, so a head inside two would carry two truths. Raises
    `OverlappingWindows` on the first overlap, before any query."""
    by_agent: dict[str, list[LabWindow]] = {}
    for window in windows:
        by_agent.setdefault(window.agent_name, []).append(window)
    for agent_windows in by_agent.values():
        ordered = sorted(agent_windows, key=lambda w: (w.since, w.until))
        for first, second in itertools.pairwise(ordered):
            if second.since <= first.until:
                raise OverlappingWindows(first, second)


def lab_tag_command(window: LabWindow) -> str:
    return (
        f"PYTHONPATH=backend python3 eval/lab_tag.py --agent {window.agent_name} "
        f"--since {window.since.isoformat()} --until {window.until.isoformat()} "
        f"--scenario {window.scenario_id} --category {window.category_expected} "
        f"--kind {window.kind} --env-file .env"
    )


def read_manifest_ids(path: Path) -> frozenset[str]:
    """Target and neighbour ids of `eval/adversarial/manifest.csv` (P6-T04), if
    it exists -- belt and braces beside `NOT is_synthetic`."""
    if not path.exists():
        return frozenset()
    ids: set[str] = set()
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            for column in ("alert_id", "neighbour_alert_id"):
                value = (row.get(column) or "").strip()
                if value:
                    ids.add(value)
    return frozenset(ids)


def _g2_select(
    conn: psycopg.Connection,
    windows: Sequence[LabWindow],
    *,
    expected: Mapping[str, frozenset[str]],
    manifest_ids: frozenset[str] = frozenset(),
) -> tuple[list[ClusterRow], dict[str, int], dict[str, int]]:
    """The in-scope heads, the raw head count per window, and the count of
    `in_window_unexpected` heads per window (DEC-114).

    A head is scoped by its `alerts.rule_id`, never by `alerts.category`: the
    category is the product's own output, and scoping by it would silently drop
    exactly the mis-categorised scenario alerts the evaluation exists to count.
    A benign-block window (`category_expected == BENIGN_BLOCK`) declares no ids,
    so every one of its heads is in scope. Overlapping windows of one agent are
    refused up front, so a head carries at most one truth.
    """
    assert_windows_disjoint(windows)
    rows: list[ClusterRow] = []
    seen: set[str] = set()
    heads_per_window: dict[str, int] = {}
    excluded_per_window: dict[str, int] = {}
    for window in windows:
        heads = conn.execute(
            _G2_HEADS_SQL, (window.agent_name, window.since, window.until)
        ).fetchall()
        heads_per_window[window.scenario_id] = len(heads)
        excluded_per_window.setdefault(window.scenario_id, 0)
        untagged = sum(1 for head in heads if head[4] != "lab")
        if untagged:
            raise UntaggedWindow(window, untagged)
        if window.category_expected != BENIGN_BLOCK and window.category_expected not in expected:
            raise ExpectedRulesUnreadable(
                f"lab window {window.scenario_id}: category "
                f"{window.category_expected!r} has no declared Expected rules table"
            )
        for head in heads:
            alert_id, rule_id, category, severity, _source, agent_name = head[:6]
            alert_user, srcip, dstip, _alert_time, db_count = head[6:]
            if alert_id in manifest_ids or alert_id in seen:
                continue
            in_scope = window.category_expected == BENIGN_BLOCK or (
                rule_id in expected[window.category_expected]
            )
            if not in_scope:
                excluded_per_window[window.scenario_id] += 1
                continue
            seen.add(alert_id)
            count, first_seen, last_seen = conn.execute(
                _G2_RECOUNT_SQL, (alert_id, alert_id)
            ).fetchone()
            if count != db_count:
                print(
                    f"build_gold: warning: head {alert_id} recounts to {count} members "
                    f"(alerts.occurrence_count says {db_count}); the recount is written",
                    file=sys.stderr,
                )
            rows.append(
                ClusterRow(
                    cluster_id=alert_id,
                    gold_set="G2",
                    alert_id=alert_id,
                    rule_id=rule_id,
                    category=category,
                    severity=severity,
                    agent_name=agent_name,
                    alert_user=alert_user,
                    srcip=srcip,
                    dstip=dstip,
                    source="lab",
                    first_seen=first_seen.astimezone(UTC),
                    last_seen=last_seen.astimezone(UTC),
                    occurrence_count=count,
                    closed_by="",
                    excluded_reason="",
                    scenario_id=window.scenario_id,
                    kind=window.kind,
                    truth_label=TRUTH_BY_KIND[window.kind],
                ),
            )
    rows.sort(key=lambda row: row.cluster_id)
    return rows, heads_per_window, excluded_per_window


def g2_rows(
    conn: psycopg.Connection,
    windows: Sequence[LabWindow],
    *,
    expected: Mapping[str, frozenset[str]],
    manifest_ids: frozenset[str] = frozenset(),
) -> list[ClusterRow]:
    """In-scope heads (`duplicate_of IS NULL AND NOT is_synthetic`, `rule_id` in
    the scenario's declared Expected rules) of each window's agent inside the
    window, all `source = 'lab'` or `UntaggedWindow` is raised; the cluster's
    numbers recounted clock-free over the members' `alert_time`. Overlapping
    windows of one agent are refused (`OverlappingWindows`)."""
    rows, _, _ = _g2_select(conn, windows, expected=expected, manifest_ids=manifest_ids)
    return rows


def check_db(conn: psycopg.Connection, cluster_ids: Sequence[str]) -> CheckDb:
    """Every G1 head must be an `alerts` row (`triage_labels.alert_id` FK)."""
    found: dict[str, str] = {}
    ids = list(cluster_ids)
    for start in range(0, len(ids), CHECK_DB_CHUNK):
        chunk = ids[start : start + CHECK_DB_CHUNK]
        for alert_id, source in conn.execute(_CHECK_DB_SQL, (chunk,)).fetchall():
            found[alert_id] = source
    missing = tuple(alert_id for alert_id in ids if alert_id not in found)
    replay = sum(1 for source in found.values() if source == "replay")
    return CheckDb(present=len(found), replay=replay, missing=missing)


# --- the allocator -------------------------------------------------------------------

Stratum = tuple[str, str]


def _category_rank(category: str) -> tuple[int, str]:
    return (PRIORITY.index(category) if category in PRIORITY else len(PRIORITY), category)


def _severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)


def _stratum_rank(stratum: Stratum) -> tuple[tuple[int, str], int]:
    return (_category_rank(stratum[0]), _severity_rank(stratum[1]))


def _largest_remainder(sizes: Sequence[tuple[object, int]], k: int) -> dict:
    """Allocate `k` over keys proportionally to `sizes`, exact and capped.

    Each key gets `floor(k * size / total)`; the units left over go to the
    largest fractional remainders, ties broken by the order of `sizes`. The
    result sums to exactly `min(k, total)` and never exceeds a key's size
    (a key with a positive remainder has `floor + 1 <= size`).
    """
    total = sum(size for _, size in sizes)
    if k <= 0 or total == 0:
        return {key: 0 for key, _ in sizes}
    if k >= total:
        return {key: size for key, size in sizes}
    exact = [(key, Fraction(k * size, total)) for key, size in sizes]
    alloc = {key: math.floor(share) for key, share in exact}
    leftover = k - sum(alloc.values())
    order = sorted(
        range(len(exact)), key=lambda index: (-(exact[index][1] - alloc[exact[index][0]]), index)
    )
    for index in order[:leftover]:
        alloc[exact[index][0]] += 1
    return alloc


def _floor_topup(
    alloc: dict[str, int],
    fixed: dict[str, int],
    pool_by_category: dict[str, int],
    floor: int,
    notes: list[str],
) -> None:
    """Raise every classified category below `min(floor, its pool size)` by
    taking from the category with the largest allocation -- a donor never
    gives below its own floor, so the loop terminates, and a category that
    cannot be lifted is reported rather than forced."""
    categories = sorted(alloc, key=_category_rank)

    def total(category: str) -> int:
        return fixed.get(category, 0) + alloc[category]

    def wanted(category: str) -> int:
        return min(floor, pool_by_category.get(category, 0))

    stuck: set[str] = set()
    while True:
        below = [c for c in categories if c not in stuck and total(c) < wanted(c)]
        if not below:
            return
        recipient = below[0]
        need = wanted(recipient) - total(recipient)
        donors = sorted(
            (c for c in categories if c != recipient),
            key=lambda c: (-alloc[c], _category_rank(c)),
        )
        moved = False
        for donor in donors:
            surplus = min(alloc[donor], total(donor) - wanted(donor))
            if surplus <= 0:
                continue
            give = min(surplus, need)
            alloc[donor] -= give
            alloc[recipient] += give
            moved = True
            break
        if not moved:
            stuck.add(recipient)
            notes.append(
                f"category floor {floor}: {recipient} stays at {total(recipient)} of "
                f"{wanted(recipient)} -- nothing can be moved"
            )


@dataclass(frozen=True)
class _Plan:
    target: int
    per_stratum: dict[Stratum, int]
    notes: tuple[str, ...]


def _plan(
    pool: Sequence[ClusterRow],
    target: int,
    *,
    unknown_cap_pct: float,
    take_all_crit_high: bool,
    category_floor: int,
) -> _Plan:
    """How many rows each stratum contributes (design note 3), before any draw."""
    size: Counter = Counter((row.category, row.severity) for row in pool)
    strata = sorted(size, key=_stratum_rank)
    categories = sorted({category for category, _ in strata}, key=_category_rank)
    classified = [category for category in categories if category != UNKNOWN]
    effective_target = min(target, len(pool))
    budget = math.floor(target * unknown_cap_pct / 100)
    plan: dict[Stratum, int] = {stratum: 0 for stratum in strata}
    notes: list[str] = []

    def category_size(category: str, severities: Sequence[str] = SEVERITIES) -> int:
        return sum(size[(category, severity)] for severity in severities)

    pool_by_category = {category: category_size(category) for category in categories}

    def split_category(category: str, k: int, severities: Sequence[str]) -> None:
        present = [
            ((category, severity), size[(category, severity)])
            for severity in severities
            if (category, severity) in size
        ]
        for stratum, n in _largest_remainder(present, k).items():
            plan[stratum] = n

    def proportional_over_all() -> None:
        alloc = _largest_remainder(
            [(category, pool_by_category[category]) for category in categories], effective_target
        )
        unknown_k = min(alloc.get(UNKNOWN, 0), budget)
        if unknown_k < alloc.get(UNKNOWN, 0):
            notes.append(
                f"unknown cap binds in the proportional allocation: {unknown_k} of "
                f"{alloc[UNKNOWN]} proportional (budget {budget})"
            )
        alloc = _largest_remainder(
            [(category, pool_by_category[category]) for category in classified],
            effective_target - unknown_k,
        )
        _floor_topup(alloc, {}, pool_by_category, category_floor, notes)
        for category in classified:
            split_category(category, alloc[category], SEVERITIES)
        if UNKNOWN in categories:
            split_category(UNKNOWN, unknown_k, SEVERITIES)

    if take_all_crit_high:
        crit_high = [stratum for stratum in strata if stratum[1] in CRIT_HIGH]
        n_crit_high = sum(size[stratum] for stratum in crit_high)
        if n_crit_high > effective_target:
            notes.append(
                f"take-all rule alone exceeds the target: {n_crit_high} > {effective_target}; "
                "fell through to proportional allocation over all strata under the cap"
            )
            proportional_over_all()
        else:
            for stratum in crit_high:
                plan[stratum] = size[stratum]
            taken_unknown = sum(size[stratum] for stratum in crit_high if stratum[0] == UNKNOWN)
            if taken_unknown > budget:
                notes.append(
                    f"unknown cap exceeded by the take-all rule: {taken_unknown} of {budget}"
                )
            room = effective_target - n_crit_high
            if UNKNOWN in categories:
                split_category(
                    UNKNOWN, min(max(0, budget - taken_unknown), room), ("medium", "low")
                )
            remaining = effective_target - sum(plan.values())
            fixed = {
                category: sum(plan.get((category, severity), 0) for severity in CRIT_HIGH)
                for category in classified
            }
            alloc = _largest_remainder(
                [(category, category_size(category, ("medium", "low"))) for category in classified],
                remaining,
            )
            _floor_topup(alloc, fixed, pool_by_category, category_floor, notes)
            for category in classified:
                split_category(category, alloc[category], ("medium", "low"))
    else:
        n_classified = sum(pool_by_category[category] for category in classified)
        if n_classified <= effective_target:
            for stratum in strata:
                if stratum[0] != UNKNOWN:
                    plan[stratum] = size[stratum]
            if UNKNOWN in categories:
                split_category(UNKNOWN, min(effective_target - n_classified, budget), SEVERITIES)
        else:
            notes.append(
                f"classified clusters alone exceed the target: {n_classified} > "
                f"{effective_target}; proportional allocation over classified strata, "
                "unknown draws 0"
            )
            alloc = _largest_remainder(
                [(category, pool_by_category[category]) for category in classified],
                effective_target,
            )
            _floor_topup(alloc, {}, pool_by_category, category_floor, notes)
            for category in classified:
                split_category(category, alloc[category], SEVERITIES)

    planned = sum(plan.values())
    assert planned <= effective_target, (planned, effective_target)
    if planned < effective_target:
        notes.append(
            f"sample short: {planned} of {effective_target} -- the unknown cap (budget "
            f"{budget}) binds and the classified pool is exhausted"
        )
    return _Plan(target=effective_target, per_stratum=plan, notes=tuple(notes))


def allocate(
    pool: Sequence[ClusterRow],
    target: int,
    *,
    unknown_cap_pct: float,
    take_all_crit_high: bool,
    category_floor: int,
    seed: int,
) -> list[ClusterRow]:
    """The stratified sample (design note 3), sorted by `cluster_id`.

    `min(target, len(pool))` rows whenever the cap allows it; when the cap binds
    and the classified pool is exhausted the sample is short and the coverage
    table says so -- the cap is the Owner's rule and this function never breaks
    it to fill up. Deterministic for a given pool and seed: within a stratum the
    ids are sorted and drawn by `random.Random(f"{seed}:{category}|{severity}")`
    (a string seed is the sha512 path, version 2 -- stable across processes).
    The G1/G2 floors are reported by `main`, not enforced here.
    """
    plan = _plan(
        pool,
        target,
        unknown_cap_pct=unknown_cap_pct,
        take_all_crit_high=take_all_crit_high,
        category_floor=category_floor,
    )
    ids_by_stratum: dict[Stratum, list[str]] = {}
    by_id: dict[str, ClusterRow] = {}
    for row in pool:
        ids_by_stratum.setdefault((row.category, row.severity), []).append(row.cluster_id)
        by_id[row.cluster_id] = row
    chosen: list[str] = []
    for (category, severity), k in plan.per_stratum.items():
        ids = sorted(ids_by_stratum.get((category, severity), []))
        if k >= len(ids):
            chosen.extend(ids)
        elif k > 0:
            chosen.extend(random.Random(f"{seed}:{category}|{severity}").sample(ids, k))
    return [by_id[cluster_id] for cluster_id in sorted(chosen)]


# --- the coverage table ---------------------------------------------------------------


def grid_table(rows: Sequence[ClusterRow], denominator: int) -> str:
    """`scripts/measure_clusters.py`'s `grid_table` shape: rows by category,
    most common first; `critical | high | medium | low | total | share`."""
    grid: Counter = Counter((row.category, row.severity) for row in rows)
    dist: Counter = Counter(row.category for row in rows)
    lines = [
        "| category | " + " | ".join(SEVERITIES) + " | total | share |",
        "|---|" + "---|" * 6,
    ]
    for category in sorted(dist, key=lambda c: (-dist[c], _category_rank(c))):
        row = [grid.get((category, severity), 0) for severity in SEVERITIES]
        cells = " | ".join(f"{v}{'' if v >= 10 else ' ·'}" for v in row)
        share = (100 * sum(row) / denominator) if denominator else 0.0
        lines.append(f"| {category} | {cells} | {sum(row)} | {share:.1f} % |")
    ge10 = sum(1 for v in grid.values() if v >= 10)
    lines.append(f"\n(· = under 10 clusters; cells ≥ 10: {ge10} of {len(grid)} non-empty)")
    return "\n".join(lines)


def _pct(part: int, whole: int) -> str:
    return f"{part} of {whole} ({(100 * part / whole) if whole else 0.0:.1f} %)"


def coverage_table(
    pool: Sequence[ClusterRow],
    sample: Sequence[ClusterRow],
    *,
    denominator_label: str,
    params: AllocParams,
    extra_pool_lines: Sequence[str] = (),
    extra_sample_lines: Sequence[str] = (),
    after_enrichment_lines: Sequence[str] = (),
) -> str:
    """The pool grid and the sample grid of one gold set, each with its
    denominator, the cap and floor lines, the enrichment sentence and the
    allocator's notes (design note 5 sections 2 and 3)."""
    label = denominator_label
    n_pool, n_sample = len(pool), len(sample)
    plan = _plan(
        pool,
        params.target,
        unknown_cap_pct=params.unknown_cap_pct,
        take_all_crit_high=params.take_all_crit_high,
        category_floor=params.category_floor,
    )
    budget = math.floor(params.target * params.unknown_cap_pct / 100)

    def crit_high(rows: Sequence[ClusterRow]) -> tuple[int, int]:
        rows_ch = [row for row in rows if row.severity in CRIT_HIGH]
        return len(rows_ch), sum(1 for row in rows_ch if row.category == UNKNOWN)

    pool_ch, pool_ch_unknown = crit_high(pool)
    sample_ch, sample_ch_unknown = crit_high(sample)
    pool_unknown = sum(1 for row in pool if row.category == UNKNOWN)
    sample_unknown = sum(1 for row in sample if row.category == UNKNOWN)
    agents: Counter = Counter(row.agent_name for row in pool)

    lines = [
        f"## {label} pool (denominator {n_pool})",
        "",
        f"- allocator: {params.describe()}",
        "",
        grid_table(pool, n_pool),
        "",
        f"- crit+high in the pool: {pool_ch} of {n_pool}, of which `unknown` {pool_ch_unknown}",
        f"- `unknown` share of the pool: {_pct(pool_unknown, n_pool)}",
        f"- clusters by agent (of {n_pool} in the pool): "
        + " · ".join(
            f"{agent} {count}"
            for agent, count in sorted(agents.items(), key=lambda item: (-item[1], item[0]))
        ),
        *extra_pool_lines,
        "",
        f"## {label} sample (denominator {n_sample})",
        "",
        grid_table(sample, n_sample),
        "",
        (
            f"- `unknown` in the sample: {_pct(sample_unknown, n_sample)} against the cap "
            f"{params.unknown_cap_pct} % (budget {budget})"
        ),
        (
            f"- crit+high in the sample: {sample_ch} of {n_sample}, of which `unknown` "
            f"{sample_ch_unknown}"
        ),
    ]
    by_category_pool: Counter = Counter(row.category for row in pool)
    by_category_sample: Counter = Counter(row.category for row in sample)
    parts = []
    for category in sorted(by_category_pool, key=_category_rank):
        n = by_category_sample.get(category, 0)
        if category == UNKNOWN:
            parts.append(f"{category} {n} (capped, not floored)")
        else:
            wanted = min(params.category_floor, by_category_pool[category])
            parts.append(f"{category} {n} {'≥' if n >= wanted else '<'} {wanted}")
    lines.append(
        f"- per-category totals against category_floor {params.category_floor}: "
        + " · ".join(parts)
    )
    if params.take_all_crit_high:
        lines.append(
            f"- {label}'s severity mix is enriched by design: {sample_ch} of {n_sample} "
            f"against {pool_ch} of {n_pool}"
        )
    else:
        lines.append(
            f"- {label}'s severity mix is not enriched by design (take-all rule off): "
            f"{sample_ch} of {n_sample} against {pool_ch} of {n_pool}"
        )
    lines.extend(after_enrichment_lines)
    lines.extend(extra_sample_lines)
    lines.append("- allocator notes: " + ("; ".join(plan.notes) if plan.notes else "none"))
    return "\n".join(lines)


@dataclass(frozen=True)
class G2Result:
    windows: tuple[LabWindow, ...]
    heads_per_window: dict[str, int]
    pool: list[ClusterRow]
    sample: list[ClusterRow]
    excluded_per_window: dict[str, int] = field(default_factory=dict)


def _g2_windows_table_lines(g2: G2Result) -> list[str]:
    """The per-window table (both modes): heads found, in scope, and the
    `in_window_unexpected` heads that DEC-114 excludes and counts."""
    total_heads = sum(g2.heads_per_window.values())
    total_unexpected = sum(g2.excluded_per_window.values())
    in_scope: Counter = Counter(row.scenario_id for row in g2.pool)
    lines = [
        "## G2 — lab windows (`eval/lab_windows.csv`)",
        "",
        (
            "| scenario_id | kind | category_expected | since | until | heads found | in scope "
            "| in_window_unexpected |"
        ),
        "|---|---|---|---|---|---|---|---|",
    ]
    for w in g2.windows:
        lines.append(
            f"| {w.scenario_id} | {w.kind} | {w.category_expected} | "
            f"{w.since.isoformat()} | {w.until.isoformat()} | "
            f"{g2.heads_per_window.get(w.scenario_id, 0)} | "
            f"{in_scope.get(w.scenario_id, 0)} | "
            f"{g2.excluded_per_window.get(w.scenario_id, 0)} |"
        )
    lines.append("")
    lines.append(
        f"- in_window_unexpected (DEC-114): {total_unexpected} of {total_heads} heads found, "
        "excluded, never labelled"
    )
    return lines


def _g2_coverage_table(g2: G2Result, g2_params: AllocParams) -> str:
    """The G2 pool/sample grids, with the window-truth counts, the ≥ 20 benign
    line, and the (xii) sentence right after the enrichment line (DEC-111/114/115)."""
    zero = [
        category
        for category in PLAYBOOK_CATEGORIES
        if not any(row.category == category for row in g2.pool)
    ]
    escalate = sum(1 for row in g2.sample if row.truth_label == "escalate")
    benign = sum(1 for row in g2.sample if row.truth_label == "benign")
    return coverage_table(
        g2.pool,
        g2.sample,
        denominator_label="G2",
        params=g2_params,
        extra_pool_lines=[
            f"- playbook categories with zero clusters in the G2 pool "
            f"({len(zero)} of {len(PLAYBOOK_CATEGORIES)}): "
            + (", ".join(zero) if zero else "none")
            + " — a zero row is what exists, never a synthetic one",
        ],
        after_enrichment_lines=[DEC111_SENTENCE],
        extra_sample_lines=[
            (
                f"- truth in the sample (window, DEC-111/114/115): escalate {escalate} · "
                f"benign {benign}"
            ),
            f"- benign lab clusters in the sample ≥ 20: {benign} — "
            + ("met" if benign >= 20 else "MISS"),
        ],
    )


def coverage_document(
    *,
    cfg: config.Config,
    g2: G2Result | None,
    g2_params: AllocParams,
    archive_file: str | None = None,
    stats: dedup_verify.ArchiveStats | None = None,
    clusters: int | None = None,
    g1_rows_all: Sequence[ClusterRow] | None = None,
    g1_sample: Sequence[ClusterRow] | None = None,
    g1_params: AllocParams | None = None,
    lab_windows_path: str | None = None,
    lab_scenarios_path: str | None = None,
    expected: Mapping[str, frozenset[str]] | None = None,
) -> str:
    """`eval/gold_coverage.md` (design note 5), deterministic given its inputs.

    `g1_rows_all is None` selects the **G2-only** document (DEC-111): no archive,
    no G1 grid, no G1 files -- just the run header, the windows table, the G2
    grids with window-known truth, and the floors."""
    if g1_rows_all is None:
        if g2 is None:
            raise ValueError("coverage_document: G2-only mode needs a G2Result")
        n_categories = len(expected) if expected is not None else 0
        n_ids = sum(len(ids) for ids in expected.values()) if expected is not None else 0
        lines = [
            "# Gold coverage — G2 only",
            "",
            "Generated by `eval/build_gold.py`; never hand-edited.",
            "",
            "## Run",
            "",
            f"- lab windows: `{lab_windows_path}`",
            (
                f"- lab scenarios: `{lab_scenarios_path}` — declared Expected rules: "
                f"{n_ids} ids in {n_categories} categories"
            ),
            (
                f"- ceilings (`Config`): DEDUP_IDLE_GAP_MINUTES={cfg.DEDUP_IDLE_GAP_MINUTES} · "
                f"MAX_CLUSTER_AGE_HOURS={cfg.MAX_CLUSTER_AGE_HOURS} · "
                f"MAX_CLUSTER_SIZE={cfg.MAX_CLUSTER_SIZE}"
            ),
            f"- seed: {g2_params.seed} (`EVAL_SEED`)",
            f"- G2 allocator: {g2_params.describe()}",
            "- run mode: G2 only",
            (
                "- G1: not built (DEC-111 — the 08/08–07/09 history is void; its files stay "
                "in git as the record)"
            ),
            "",
            *_g2_windows_table_lines(g2),
            "",
            _g2_coverage_table(g2, g2_params),
            "",
            "## Floors",
            "",
            (
                f"- G2 {len(g2.sample)} ≥ {g2_params.floor}: "
                f"{'met' if len(g2.sample) >= g2_params.floor else 'MISS'}"
            ),
            "- G1: not built (DEC-111)",
            "",
        ]
        return "\n".join(lines)

    if stats is None or clusters is None or g1_sample is None or g1_params is None:
        raise ValueError("coverage_document: G1 mode needs stats, clusters, g1_sample, g1_params")
    mode = "G1 + G2" if g2 is not None else "G1 only"
    pool = [row for row in g1_rows_all if not row.excluded_reason]
    excluded = [row for row in g1_rows_all if row.excluded_reason == EXCLUDED_LOOPBACK]
    desktop_fold = sum(1 for row in g1_rows_all if row.agent_name == DESKTOP_AGENT)
    desktop_pool = sum(1 for row in pool if row.agent_name == DESKTOP_AGENT)
    desktop_sample = sum(1 for row in g1_sample if row.agent_name == DESKTOP_AGENT)
    g1_extra_pool = [
        (
            f"- excluded as loopback `{LOOPBACK_CATEGORY}` from {LOOPBACK_SRCIP} (DEC-053): "
            f"{len(excluded)} of {clusters} clusters / "
            f"{sum(row.occurrence_count for row in excluded)} of {stats.parsed} alerts"
        ),
        (
            f"- `{DESKTOP_AGENT}` (DEC-058): {desktop_fold} of {clusters} fold clusters, "
            f"{desktop_pool} of {len(pool)} in the pool, {desktop_sample} of {len(g1_sample)} "
            "in the sample -- kept, `needs_review` by construction"
        ),
    ]
    lines = [
        f"# Gold coverage — {mode}",
        "",
        "Generated by `eval/build_gold.py`; never hand-edited.",
        "",
        "## Run",
        "",
        (
            f"- archive: `{archive_file}` — lines {stats.lines} / parsed {stats.parsed} / "
            f"rejected {stats.rejected} — clusters {clusters} (`dedup_verify.fold_clusters`, "
            "sorted by `alert_time`)"
        ),
        (
            f"- ceilings (`Config`): DEDUP_IDLE_GAP_MINUTES={cfg.DEDUP_IDLE_GAP_MINUTES} · "
            f"MAX_CLUSTER_AGE_HOURS={cfg.MAX_CLUSTER_AGE_HOURS} · "
            f"MAX_CLUSTER_SIZE={cfg.MAX_CLUSTER_SIZE}"
        ),
        f"- seed: {g1_params.seed} (`EVAL_SEED`)",
        f"- G1 allocator: {g1_params.describe()}",
        (
            f"- G2 allocator: {g2_params.describe()}"
            if g2 is not None
            else "- G2 allocator: not run (no `--g2`)"
        ),
        f"- run mode: {mode}",
        "",
        coverage_table(
            pool,
            g1_sample,
            denominator_label="G1",
            params=g1_params,
            extra_pool_lines=g1_extra_pool,
        ),
        "",
    ]
    if g2 is not None:
        lines.extend(
            [
                *_g2_windows_table_lines(g2),
                "",
                _g2_coverage_table(g2, g2_params),
                "",
            ]
        )
    lines.extend(
        [
            "## Floors",
            "",
            (
                f"- G1 {len(g1_sample)} ≥ {g1_params.floor}: "
                f"{'met' if len(g1_sample) >= g1_params.floor else 'MISS'}"
            ),
            (
                f"- G2 {len(g2.sample)} ≥ {g2_params.floor}: "
                f"{'met' if len(g2.sample) >= g2_params.floor else 'MISS'}"
                if g2 is not None
                else "- G2: not run"
            ),
            "",
            "## Denominators",
            "",
            (
                f"{clusters:,} is `dedup_verify.py`'s `alert_time`-sorted fold over {stats.parsed:,} "
                "parsed lines; the published 3,070 / 1,812 are `scripts/measure_clusters.py`'s "
                "archive-order fold — both are correct for their fold and are never quoted "
                "against each other (DEC-077, DEC-084)."
            ),
            "",
        ]
    )
    return "\n".join(lines)


# --- output files ----------------------------------------------------------------------


def _csv_writer(handle) -> csv.writer:
    return csv.writer(handle, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)


def write_outputs(
    out_dir: Path,
    *,
    g1_rows: Sequence[ClusterRow] | None,
    g1_members: Sequence[MemberRow] | None,
    sample: Sequence[ClusterRow],
    coverage_md: str,
) -> None:
    """The output files, byte-identical on a re-run (design note 4): UTF-8, `\\n`,
    `QUOTE_MINIMAL`, rows sorted by `cluster_id`, UTC `isoformat()` datetimes;
    the members gzip at level 9 with `mtime=0` and no embedded file name.

    `g1_rows`/`g1_members` are `None` in **G2-only** mode (DEC-111): the two
    `g1_*` files are then not opened at all, so a committed pair keeps its bytes.
    """
    out_dir = Path(out_dir)
    if g1_rows is not None:
        with (out_dir / "g1_clusters.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = _csv_writer(handle)
            writer.writerow(CLUSTER_COLUMNS)
            for row in sorted(g1_rows, key=lambda r: r.cluster_id):
                writer.writerow(
                    (
                        row.cluster_id,
                        row.alert_id,
                        row.rule_id,
                        row.category,
                        row.severity,
                        row.agent_name,
                        row.alert_user or "",
                        row.srcip,
                        row.dstip,
                        _iso(row.first_seen),
                        _iso(row.last_seen),
                        row.occurrence_count,
                        row.closed_by,
                        row.excluded_reason,
                    )
                )
    if g1_members is not None:
        with (
            (out_dir / "g1_members.csv.gz").open("wb") as raw,
            gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as gz,
            io.TextIOWrapper(gz, encoding="utf-8", newline="") as text,
        ):
            writer = _csv_writer(text)
            writer.writerow(MEMBER_COLUMNS)
            for cluster_id, alert_id, alert_time in sorted(
                g1_members, key=lambda m: (m[0], m[2], m[1])
            ):
                writer.writerow((cluster_id, alert_id, _iso(alert_time)))
    ordered = sorted(sample, key=lambda r: (r.gold_set, r.cluster_id))
    with (out_dir / "gold_candidates.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = _csv_writer(handle)
        writer.writerow(CANDIDATE_COLUMNS)
        for row in ordered:
            writer.writerow(
                (
                    row.cluster_id,
                    row.gold_set,
                    row.alert_id,
                    row.category,
                    row.severity,
                    row.source,
                    row.stratum,
                    row.occurrence_count,
                    _iso(row.first_seen),
                    _iso(row.last_seen),
                    row.agent_name,
                    row.rule_id,
                    row.scenario_id,
                    row.kind,
                    row.truth_label,
                )
            )
    (out_dir / "gold_coverage.md").write_text(coverage_md, encoding="utf-8", newline="\n")


# --- CLI --------------------------------------------------------------------------------


@contextmanager
def _read_only_connection(dsn: str) -> Iterator[psycopg.Connection]:
    """One transaction, `SET TRANSACTION READ ONLY` first -- this script never
    writes a row, and the server enforces it."""
    try:
        conn = psycopg.connect(dsn)
    except psycopg.Error as exc:
        raise DsnUnreadable(type(exc).__name__) from None
    try:
        conn.execute("SET TRANSACTION READ ONLY")
        yield conn
    finally:
        conn.rollback()
        conn.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="build_gold.py",
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exit codes: 0 files written, floors met; 1 a floor missed (files written); "
            "2 archive missing/unreadable or DSN unreadable; 3 an untagged, missing or "
            "overlapping lab window, or unreadable Expected rules; "
            "4 --check-db found a missing head. --g2 without --archive-file builds G2 alone "
            "(DEC-111); --g1 and --check-db still need --archive-file."
        ),
    )
    parser.add_argument(
        "--archive-file",
        default=None,
        metavar="PATH",
        help="the G1 fold's input; omit it with --g2 alone for a G2-only build (DEC-111)",
    )
    parser.add_argument("--g1", action="store_true", help="build G1 (implied when neither flag)")
    parser.add_argument("--g2", action="store_true", help="also select G2 from the lab windows")
    parser.add_argument("--lab-windows", default="eval/lab_windows.csv", metavar="PATH")
    parser.add_argument(
        "--lab-scenarios",
        default="docs/lab-scenarios.md",
        metavar="PATH",
        help="where the declared Expected rules are parsed from (DEC-114)",
    )
    parser.add_argument("--dsn", default=None, metavar="DSN", help="never printed")
    parser.add_argument("--env-file", default=".env", metavar="PATH")
    parser.add_argument("--out-dir", default="eval", metavar="DIR")
    parser.add_argument("--g1-target", type=int, default=300)
    parser.add_argument("--g1-floor", type=int, default=200)
    parser.add_argument("--g2-target", type=int, default=100)
    parser.add_argument("--g2-floor", type=int, default=60)
    parser.add_argument("--unknown-cap-pct", type=float, default=40.0)
    parser.add_argument("--g2-unknown-cap-pct", type=float, default=50.0)
    parser.add_argument("--take-all-crit-high", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--category-floor", type=int, default=25)
    parser.add_argument("--g2-category-floor", type=int, default=5)
    parser.add_argument("--seed", type=int, default=EVAL_SEED)
    parser.add_argument("--manifest", default="eval/adversarial/manifest.csv", metavar="PATH")
    parser.add_argument(
        "--check-db", action="store_true", help="prove every G1 head is an alerts row"
    )
    return parser


def _resolve_dsn(dsn: str | None, env_file: str) -> str | None:
    if dsn:
        print("dsn: from --dsn (redacted)")
        return dsn
    resolved = config.load(env_file=env_file).DATABASE_URL
    if not resolved:
        return None
    print("dsn: from .env (redacted)")
    return resolved


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    g2_only = args.archive_file is None
    g2_only_ok = args.g2 and not args.g1 and not args.check_db
    if g2_only and not g2_only_ok:
        print(
            "build_gold: --archive-file is required for --g1 and --check-db (the G1 fold and "
            "the head check read it); only --g2 on its own runs without it (DEC-111)",
            file=sys.stderr,
        )
        return EXIT_ARCHIVE

    cfg = config.load(env_file=args.env_file)
    g1_params = AllocParams(
        target=args.g1_target,
        floor=args.g1_floor,
        unknown_cap_pct=args.unknown_cap_pct,
        take_all_crit_high=args.take_all_crit_high,
        category_floor=args.category_floor,
        seed=args.seed,
    )
    g2_params = AllocParams(
        target=args.g2_target,
        floor=args.g2_floor,
        unknown_cap_pct=args.g2_unknown_cap_pct,
        take_all_crit_high=False,
        category_floor=args.g2_category_floor,
        seed=args.seed,
    )

    stats: dedup_verify.ArchiveStats | None = None
    clusters: list = []
    rows: list[ClusterRow] = []
    members: list[MemberRow] = []
    pool: list[ClusterRow] = []
    g1_sample: list[ClusterRow] = []
    archive_path: Path | None = None
    if not g2_only:
        archive_path = Path(args.archive_file)
        try:
            stats = dedup_verify.read_archive(archive_path)
        except OSError as exc:
            print(
                f"build_gold: refusing --archive-file {args.archive_file!r}: {exc}",
                file=sys.stderr,
            )
            print(
                "build_gold: the archive is exported by the Owner (P2-T13's scope-out); "
                "the procedure P2-T13's --help prints:",
                file=sys.stderr,
            )
            print(dedup_verify.OWNER_PROCEDURE, file=sys.stderr)
            return EXIT_ARCHIVE
        clusters = dedup_verify.fold_clusters(stats.alerts, cfg)
        rows = g1_rows(stats, clusters)
        members = g1_members(stats, clusters)
        pool = [row for row in rows if not row.excluded_reason]
        g1_sample = allocate(
            pool,
            g1_params.target,
            unknown_cap_pct=g1_params.unknown_cap_pct,
            take_all_crit_high=g1_params.take_all_crit_high,
            category_floor=g1_params.category_floor,
            seed=g1_params.seed,
        )

    windows: list[LabWindow] = []
    expected: dict[str, frozenset[str]] = {}
    if args.g2:
        try:
            expected = expected_rules(Path(args.lab_scenarios))
        except (OSError, ExpectedRulesUnreadable) as exc:
            print(f"build_gold: --lab-scenarios {args.lab_scenarios!r}: {exc}", file=sys.stderr)
            return EXIT_LAB_WINDOW
        try:
            windows = read_lab_windows(Path(args.lab_windows))
        except (OSError, KeyError, ValueError) as exc:
            print(f"build_gold: --lab-windows {args.lab_windows!r}: {exc}", file=sys.stderr)
            return EXIT_LAB_WINDOW
        if not windows:
            print(
                "build_gold: no lab windows recorded — run eval/lab_tag.py after each "
                "scenario (docs/lab-scenarios.md)",
                file=sys.stderr,
            )
            return EXIT_LAB_WINDOW
        try:
            assert_windows_disjoint(windows)
        except OverlappingWindows as exc:
            f, s = exc.first, exc.second
            print(
                f"build_gold: windows {f.scenario_id} ({f.since.isoformat()} .. "
                f"{f.until.isoformat()}) and {s.scenario_id} ({s.since.isoformat()} .. "
                f"{s.until.isoformat()}) overlap on agent {f.agent_name}; truth is per window, "
                "so overlapping windows are refused (DEC-114)",
                file=sys.stderr,
            )
            return EXIT_LAB_WINDOW

    g2: G2Result | None = None
    verdict: CheckDb | None = None
    if args.g2 or args.check_db:
        dsn = _resolve_dsn(args.dsn, args.env_file)
        if dsn is None:
            print(
                "build_gold: no DSN — pass --dsn, or set DATABASE_URL in the file named by "
                "--env-file",
                file=sys.stderr,
            )
            return EXIT_ARCHIVE
        try:
            with _read_only_connection(dsn) as conn:
                if args.check_db:
                    verdict = check_db(conn, [row.cluster_id for row in rows])
                if args.g2:
                    manifest_ids = read_manifest_ids(Path(args.manifest))
                    g2_pool, heads_per_window, excluded_per_window = _g2_select(
                        conn, windows, expected=expected, manifest_ids=manifest_ids
                    )
                    g2_sample = allocate(
                        g2_pool,
                        g2_params.target,
                        unknown_cap_pct=g2_params.unknown_cap_pct,
                        take_all_crit_high=False,
                        category_floor=g2_params.category_floor,
                        seed=g2_params.seed,
                    )
                    g2 = G2Result(
                        windows=tuple(windows),
                        heads_per_window=heads_per_window,
                        pool=g2_pool,
                        sample=g2_sample,
                        excluded_per_window=excluded_per_window,
                    )
        except DsnUnreadable as exc:
            print(f"build_gold: DSN unreadable: {exc}", file=sys.stderr)
            return EXIT_ARCHIVE
        except UntaggedWindow as exc:
            w = exc.window
            print(
                f"build_gold: window {w.scenario_id} ({w.since.isoformat()} .. "
                f"{w.until.isoformat()}): {exc.untagged} untagged head(s) still "
                "source <> 'lab' — a forgotten tag fails loudly, it never shrinks G2 "
                "silently. Fix it with:",
                file=sys.stderr,
            )
            print(f"  {lab_tag_command(w)}", file=sys.stderr)
            return EXIT_LAB_WINDOW
        except OverlappingWindows as exc:
            print(f"build_gold: overlapping windows: {exc}", file=sys.stderr)
            return EXIT_LAB_WINDOW
        except ExpectedRulesUnreadable as exc:
            print(f"build_gold: {exc}", file=sys.stderr)
            return EXIT_LAB_WINDOW

    if g2_only:
        coverage_md = coverage_document(
            cfg=cfg,
            g2=g2,
            g2_params=g2_params,
            lab_windows_path=args.lab_windows,
            lab_scenarios_path=args.lab_scenarios,
            expected=expected,
        )
    else:
        coverage_md = coverage_document(
            cfg=cfg,
            g2=g2,
            g2_params=g2_params,
            archive_file=str(archive_path),
            stats=stats,
            clusters=len(clusters),
            g1_rows_all=rows,
            g1_sample=g1_sample,
            g1_params=g1_params,
        )
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    write_outputs(
        out_dir,
        g1_rows=None if g2_only else rows,
        g1_members=None if g2_only else members,
        sample=list(g1_sample) + (list(g2.sample) if g2 is not None else []),
        coverage_md=coverage_md,
    )

    if g2_only and g2 is not None:
        print(
            f"G2 only · windows {len(g2.windows)} · heads {sum(g2.heads_per_window.values())} · "
            f"in scope {len(g2.pool)} · in_window_unexpected "
            f"{sum(g2.excluded_per_window.values())} · G2 sample {len(g2.sample)}"
        )
    else:
        g2_count = str(len(g2.sample)) if g2 is not None else "-"
        print(
            f"clusters {len(clusters)} · pool {len(pool)} · G1 sample {len(g1_sample)} · "
            f"G2 sample {g2_count}"
        )
    print(f"coverage: {out_dir / 'gold_coverage.md'}")
    rc = EXIT_OK
    if not g2_only and len(g1_sample) < g1_params.floor:
        print(f"FLOOR MISS G1 {len(g1_sample)} < {g1_params.floor}")
        rc = EXIT_FLOOR_MISS
    if g2 is not None and len(g2.sample) < g2_params.floor:
        print(f"FLOOR MISS G2 {len(g2.sample)} < {g2_params.floor}")
        rc = EXIT_FLOOR_MISS
    if verdict is not None:
        print(
            f"check-db: {verdict.present}/{len(rows)} heads present, "
            f"source=replay {verdict.replay}"
        )
        if verdict.missing:
            shown = ", ".join(verdict.missing[:20])
            print(
                f"build_gold: check-db: {len(verdict.missing)} head(s) missing from alerts "
                f"(first {min(20, len(verdict.missing))}): {shown}",
                file=sys.stderr,
            )
            rc = EXIT_CHECK_DB
    return rc


if __name__ == "__main__":
    sys.exit(main())
