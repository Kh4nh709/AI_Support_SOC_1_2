#!/usr/bin/env python3
"""Retag `alerts.source` to `'lab'` for one scenario window, by time — option D
(`docs/plan/DECISIONS.md` DEC-085; INBOX `2026-09-16 · P6 / lab tagging`).

`user1-IA1803` is both the lab host and the only Linux production host, so a
lab alert can only ever be told apart from real traffic by the seconds the
Owner wrote down while running `docs/lab-scenarios.md` — never by agent name
and never at intake time. This script is that tag: it moves `source` from
`'wazuh'` to `'lab'` for every non-duplicate row of one agent inside one
window, and records the window in `eval/lab_windows.csv` as the tag's
provenance. It changes `source` only — the lifecycle column G2 protects
(`00-context-pack.md` §2) is never named here, let alone written.

Every check below runs before the database is ever opened, in this order:
the two timestamps carry an explicit offset and describe a sane window, the
kind and category are in the closed sets, the scenario id is well formed and
not already used, and the window does not overlap an existing one of the same
agent. Only once all of that holds does the script connect and run one
transaction. A DSN is read, never printed.

Exit codes: 0 done (including a zero-row retag — a window with nothing to
retag is a finding, not a failure); 1 a refusal, explained on stderr; 2 the
DSN could not be resolved, the database could not be reached, or the windows
file exists but could not be read.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
from app.infra import config, db
from app.ingest.category import PRIORITY

REPO_ROOT = Path(__file__).resolve().parents[1]

WINDOWS_HEADER = (
    "scenario_id",
    "category_expected",
    "kind",
    "agent_name",
    "since",
    "until",
    "retagged_rows",
    "tagged_at",
)

#: The ten playbook categories minus `unknown`, plus `benign` for the once-a-day
#: benign block, whose alerts resolve to whatever they resolve to (they are not
#: one category's negative twin) -- design note 1.
VALID_CATEGORIES: tuple[str, ...] = tuple(name for name in PRIORITY if name != "unknown") + (
    "benign",
)
VALID_KINDS: tuple[str, ...] = ("attack", "benign")

MAX_WINDOW = timedelta(hours=12)
_SCENARIO_RE = re.compile(r"^[A-Za-z0-9_-]{1,16}$")

_RETAG_SQL = (
    "UPDATE alerts SET source = 'lab' "
    "WHERE agent_name = %s AND alert_time >= %s AND alert_time <= %s "
    "AND source = 'wazuh' AND NOT is_synthetic "
    "RETURNING alert_id"
)
_HEADS_SQL = "SELECT alert_id, duplicate_of FROM alerts WHERE alert_id = ANY(%s::text[])"
_DRY_RUN_SQL = (
    "SELECT count(*) FROM alerts "
    "WHERE agent_name = %s AND alert_time >= %s AND alert_time <= %s "
    "AND source = 'wazuh' AND NOT is_synthetic"
)

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_ENV = 2


class Refusal(Exception):
    """One of the pre-database validation checks failed. `str(exc)` is the
    complete message printed on stderr (exit 1)."""


class EnvironmentProblem(Exception):
    """The DSN or the windows file could not be resolved or read (exit 2) --
    a problem with where things live, not with what was asked."""


@dataclass(frozen=True)
class WindowRow:
    scenario_id: str
    category_expected: str
    kind: str
    agent_name: str
    since: str
    until: str
    retagged_rows: str
    tagged_at: str


def _parse_offset_instant(raw: str) -> datetime:
    """`raw` as an ISO 8601 instant carrying an explicit UTC offset.

    Bare `ValueError` on anything unparseable; a naive result (no offset) is
    reported the same way -- callers decide what that means for them."""
    instant = datetime.fromisoformat(raw)
    return instant


def _require_offset_instant(raw: str, flag: str) -> datetime:
    try:
        instant = _parse_offset_instant(raw)
    except ValueError:
        raise Refusal(f"--{flag}: not a valid ISO 8601 timestamp: {raw!r}") from None
    if instant.tzinfo is None:
        raise Refusal(f"--{flag}: give the offset — the log is written in +07:00")
    return instant


def validate_window(since: datetime, until: datetime) -> None:
    if until <= since:
        raise Refusal("--until must be after --since")
    if until - since > MAX_WINDOW:
        raise Refusal(
            f"--until - --since is {until - since}, over the {MAX_WINDOW} ceiling "
            "— a longer window is a typo"
        )


def validate_kind(kind: str) -> None:
    if kind not in VALID_KINDS:
        raise Refusal(f"--kind {kind!r}: must be one of {', '.join(VALID_KINDS)}")


def validate_category(category: str, kind: str) -> None:
    if category not in VALID_CATEGORIES:
        raise Refusal(f"--category {category!r}: must be one of {', '.join(VALID_CATEGORIES)}")
    if category == "benign" and kind != "benign":
        raise Refusal("--category benign is only valid together with --kind benign")


def validate_scenario_id(scenario_id: str) -> None:
    if not _SCENARIO_RE.match(scenario_id):
        raise Refusal(f"--scenario {scenario_id!r}: must match {_SCENARIO_RE.pattern}")


def read_windows(path: Path) -> list[WindowRow]:
    """Existing provenance rows, or `[]` if `path` does not exist yet (the
    first scenario of the phase creates the file). Any other read failure is
    an environment problem, not a refusal."""
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise EnvironmentProblem(f"--windows-file {str(path)!r}: {exc}") from exc
    reader = csv.DictReader(text.splitlines())
    return [WindowRow(**row) for row in reader]


def check_scenario_is_new(rows: list[WindowRow], scenario_id: str) -> None:
    for row in rows:
        if row.scenario_id == scenario_id:
            raise Refusal(
                f"scenario {scenario_id} already tagged at {row.tagged_at}; "
                "a re-run of the same scenario needs a new id"
            )


def check_no_overlap(
    rows: list[WindowRow],
    *,
    agent_name: str,
    since: datetime,
    until: datetime,
    allow_overlap: bool,
) -> None:
    if allow_overlap:
        return
    for row in rows:
        if row.agent_name != agent_name:
            continue
        existing_since = _parse_offset_instant(row.since)
        existing_until = _parse_offset_instant(row.until)
        if since <= existing_until and existing_since <= until:
            raise Refusal(
                f"overlaps scenario {row.scenario_id} ({row.since}..{row.until}) "
                f"for agent {agent_name}; pass --allow-overlap to force"
            )


def append_window_row(path: Path, row: WindowRow) -> None:
    write_header = not path.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        if write_header:
            writer.writerow(WINDOWS_HEADER)
        writer.writerow(
            (
                row.scenario_id,
                row.category_expected,
                row.kind,
                row.agent_name,
                row.since,
                row.until,
                row.retagged_rows,
                row.tagged_at,
            )
        )


def _resolve_dsn(dsn: str | None, env_file: str) -> str:
    if dsn:
        return dsn
    resolved = config.load(env_file=env_file).DATABASE_URL
    if not resolved:
        raise EnvironmentProblem(
            "no DSN: pass --dsn, or set DATABASE_URL in the file named by --env-file"
        )
    return resolved


def retag(
    conn: psycopg.Connection,
    *,
    agent_name: str,
    since: datetime,
    until: datetime,
) -> tuple[int, int, int]:
    """Retag inside one transaction; return `(retagged, heads, duplicates)`."""
    with db.transaction(conn):
        retagged_ids = [
            row[0] for row in conn.execute(_RETAG_SQL, (agent_name, since, until)).fetchall()
        ]
        if not retagged_ids:
            return 0, 0, 0
        rows = conn.execute(_HEADS_SQL, (retagged_ids,)).fetchall()
        heads = sum(1 for _alert_id, duplicate_of in rows if duplicate_of is None)
        duplicates = len(rows) - heads
    return len(retagged_ids), heads, duplicates


def count_would_retag(
    conn: psycopg.Connection, *, agent_name: str, since: datetime, until: datetime
) -> int:
    with db.transaction(conn):
        count = conn.execute(_DRY_RUN_SQL, (agent_name, since, until)).fetchone()[0]
    return int(count)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lab_tag.py",
        description=(
            "Retag one scenario's alerts from source='wazuh' to source='lab' by "
            "agent and time window, and record the window in a provenance file."
        ),
        epilog="Exit codes: 0 done, 1 refused (explained), 2 environment problem.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--agent", required=True, metavar="NAME", help="agent_name, e.g. user1-IA1803"
    )
    parser.add_argument("--since", required=True, metavar="ISO8601+OFFSET")
    parser.add_argument("--until", required=True, metavar="ISO8601+OFFSET")
    parser.add_argument("--scenario", required=True, metavar="ID", help="e.g. S03")
    parser.add_argument(
        "--category",
        required=True,
        metavar="CATEGORY",
        help=f"one of {', '.join(VALID_CATEGORIES)}",
    )
    parser.add_argument("--kind", required=True, metavar="KIND", help="attack or benign")
    parser.add_argument("--env-file", default=".env", metavar="PATH")
    parser.add_argument("--dsn", default=None, metavar="DSN")
    parser.add_argument(
        "--windows-file",
        default=str(REPO_ROOT / "eval" / "lab_windows.csv"),
        metavar="PATH",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--allow-overlap", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        since = _require_offset_instant(args.since, "since")
        until = _require_offset_instant(args.until, "until")
        validate_window(since, until)
        validate_kind(args.kind)
        validate_category(args.category, args.kind)
        validate_scenario_id(args.scenario)

        windows_path = Path(args.windows_file)
        existing_rows = read_windows(windows_path)
        check_scenario_is_new(existing_rows, args.scenario)
        check_no_overlap(
            existing_rows,
            agent_name=args.agent,
            since=since,
            until=until,
            allow_overlap=args.allow_overlap,
        )
    except Refusal as exc:
        print(f"lab_tag: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except EnvironmentProblem as exc:
        print(f"lab_tag: {exc}", file=sys.stderr)
        return EXIT_ENV

    try:
        dsn = _resolve_dsn(args.dsn, args.env_file)
        conn = db.connect(dsn)
    except EnvironmentProblem as exc:
        print(f"lab_tag: {exc}", file=sys.stderr)
        return EXIT_ENV
    except psycopg.OperationalError as exc:
        print(f"lab_tag: could not reach the database: {exc}", file=sys.stderr)
        return EXIT_ENV

    try:
        if args.dry_run:
            count = count_would_retag(conn, agent_name=args.agent, since=since, until=until)
            print(
                f"lab_tag: would retag {count} alerts for {args.scenario} "
                f"{args.since}..{args.until} (dry run, nothing written)"
            )
            return EXIT_OK

        retagged, heads, duplicates = retag(conn, agent_name=args.agent, since=since, until=until)
        tagged_at = datetime.now(UTC).isoformat()
        append_window_row(
            windows_path,
            WindowRow(
                scenario_id=args.scenario,
                category_expected=args.category,
                kind=args.kind,
                agent_name=args.agent,
                since=args.since,
                until=args.until,
                retagged_rows=str(retagged),
                tagged_at=tagged_at,
            ),
        )
        print(
            f"lab_tag: retagged {retagged} alerts ({heads} heads, {duplicates} duplicates) "
            f"for {args.scenario} {args.since}..{args.until}"
        )
        return EXIT_OK
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
