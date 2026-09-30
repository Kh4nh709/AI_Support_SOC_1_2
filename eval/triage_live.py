#!/usr/bin/env python3
"""Read what the production worker already wrote for ① (triage) and say whether the gate held.

**What this is (P3-T11, amended by DEC-156).** The card first meant to drive the queue with a fake
model and prove the worker's loop end to end. The production worker then ran ① on the live
database for real, so the proof became a *reading*: this module reads the `llm_runs`, `alerts` and
`jobs` rows that run left behind and checks the five things that must hold on every one of them.
It makes no model call, claims no job and writes nothing — the whole check is one SELECT, and the
CLI opens its session READ ONLY so that even a future edit cannot change a row by accident.

**The five conditions (`ok` holds iff all five do).**
1. at least `want` proposer rows carry a `gate_result` and a `cost_usd > 0` — the gate ran and the
   model was paid for, `want` times over;
2. no triage row (any role) has `gate_result IS NULL`;
3. no triage row has usage but no cost: `input_tokens IS NOT NULL AND cost_usd IS NULL`, a call
   that returned usage and whose cost was not recorded (review round 1: the triage worker writes
   `cost_usd=None` together with `input_tokens=None` on the paths where no call returned usage — a
   transient error, the cap, the linter — and `llm_runs` is append-only, so a plain NULL-cost
   count would fail for ever after the first of them; that plain count stays in the summary as
   context, by `stopped_by`, and never fails);
4. no proposer row is still a `false_positive` while the gate's `missing` list is non-empty — the
   gate must have forced that proposal away from `false_positive`;
5. no triage job is `failed`.

A proposer run stopped by the schema check (`stopped_by = 'schema'`) has no verdict to gate and no
verifier row, but it does carry its gate document and its cost, so it is a count in the summary and
never a failure. The rest of the summary is context for the reader: heads and proposer rows by alert
source, jobs by status, `stopped_by` and `suggested_action` counts, the forced count, verifier rows,
the rows with a NULL cost by `stopped_by`, `sum(cost_usd)`, and the first and last proposer
timestamps — each with its denominator.

**Run it** from the primary checkout, where `.env` holds `DATABASE_URL`::

    PYTHONPATH=backend .venv/bin/python eval/triage_live.py

The first line of stdout is the summary as one JSON object, then a short table, then one
`FAIL ...` line per failed condition. Exit codes: 0 every condition holds · 1 at least one fails ·
2 there is no database to read (no `DATABASE_URL`, the connection is refused, or a usage error).
The DSN is never printed: a connection error that would quote it is replaced by a fixed message.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
import sys
from urllib.parse import unquote

import psycopg
from app.infra import config
from app.infra.errors import ConfigError
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import tuple_row

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_NO_DATABASE = 2

DEFAULT_WANT = 50

#: One name per condition. A failure line starts with its name, so a test (and a reader) can tell
#: which condition fired without parsing prose.
COND_WANT = "too few gated, paid proposer rows"
COND_GATE_NULL = "triage rows with gate_result NULL"
COND_COST_NULL = "triage rows with usage but cost_usd NULL"
COND_FP_MISSING = "false_positive proposals that kept a non-empty gate missing list"
COND_FAILED_JOBS = "failed triage jobs"

NO_VALUE = "(none)"  # the key a NULL `stopped_by` / `suggested_action` is counted under
NO_ALERT = "(no alert)"  # a proposer row whose subject is not in `alerts`

# One statement, so every figure comes from the same snapshot even on a database the worker is
# still writing to, and so "this module only reads" is a fact about one string. A NULL `role` (a
# row written before migration 016) is a triage row of no role: counted in the row totals and in
# the NULL conditions, never as a proposer.
_FACTS_SQL = """
WITH runs AS (
    SELECT role, result, gate_result, cost_usd, input_tokens, stopped_by, created_at, subject_id
    FROM llm_runs
    WHERE pipeline = 'triage'
), proposer AS (
    SELECT * FROM runs WHERE role = 'proposer'
), false_positive AS (
    SELECT * FROM proposer WHERE result->>'suggested_action' = 'false_positive'
)
SELECT jsonb_build_object(
    'heads_by_source', (
        SELECT COALESCE(jsonb_object_agg(k, n), '{}'::jsonb) FROM (
            SELECT COALESCE(source, '(none)') AS k, count(*) AS n
            FROM alerts WHERE duplicate_of IS NULL GROUP BY 1) t),
    'proposer_by_source', (
        SELECT COALESCE(jsonb_object_agg(k, n), '{}'::jsonb) FROM (
            SELECT COALESCE(a.source, '(no alert)') AS k, count(*) AS n
            FROM proposer p LEFT JOIN alerts a ON a.alert_id = p.subject_id GROUP BY 1) t),
    'triage_rows', (SELECT count(*) FROM runs),
    'proposer_rows', (SELECT count(*) FROM proposer),
    'verifier_rows', (SELECT count(*) FROM runs WHERE role = 'verifier'),
    'proposer_with_result', (SELECT count(*) FROM proposer WHERE result IS NOT NULL),
    'proposer_with_gate_and_cost', (
        SELECT count(*) FROM proposer WHERE gate_result IS NOT NULL AND cost_usd > 0),
    'gate_null_rows', (SELECT count(*) FROM runs WHERE gate_result IS NULL),
    'cost_null_rows', (SELECT count(*) FROM runs WHERE cost_usd IS NULL),
    'usage_without_cost_rows', (
        SELECT count(*) FROM runs WHERE input_tokens IS NOT NULL AND cost_usd IS NULL),
    'cost_null_by_stopped_by', (
        SELECT COALESCE(jsonb_object_agg(k, n), '{}'::jsonb) FROM (
            SELECT COALESCE(stopped_by, '(none)') AS k, count(*) AS n
            FROM runs WHERE cost_usd IS NULL GROUP BY 1) t),
    'false_positive_rows', (SELECT count(*) FROM false_positive),
    'fp_with_missing', (
        SELECT count(*) FROM false_positive
        WHERE COALESCE(gate_result->'missing', 'null'::jsonb)
              NOT IN ('null'::jsonb, '[]'::jsonb, '{}'::jsonb, '""'::jsonb)),
    'forced_rows', (SELECT count(*) FROM proposer WHERE gate_result->>'forced' = 'true'),
    'suggested_action', (
        SELECT COALESCE(jsonb_object_agg(k, n), '{}'::jsonb) FROM (
            SELECT COALESCE(result->>'suggested_action', '(none)') AS k, count(*) AS n
            FROM proposer GROUP BY 1) t),
    'stopped_by', (
        SELECT COALESCE(jsonb_object_agg(k, n), '{}'::jsonb) FROM (
            SELECT COALESCE(stopped_by, '(none)') AS k, count(*) AS n
            FROM proposer GROUP BY 1) t),
    'jobs_by_status', (
        SELECT COALESCE(jsonb_object_agg(k, n), '{}'::jsonb) FROM (
            SELECT COALESCE(status, '(none)') AS k, count(*) AS n
            FROM jobs WHERE job_type = 'triage' GROUP BY 1) t),
    'cost_usd_sum', (SELECT COALESCE(sum(cost_usd), 0) FROM runs),
    'first_proposer_at', (SELECT min(created_at) FROM proposer),
    'last_proposer_at', (SELECT max(created_at) FROM proposer)
)
"""


@dataclasses.dataclass(frozen=True)
class LiveSummary:
    """The verdict and every fact behind it. Counts are of triage `llm_runs` rows unless the name
    says otherwise; the dicts map a label to a count."""

    ok: bool
    failures: list[str]
    want: int
    heads_by_source: dict[str, int]
    proposer_by_source: dict[str, int]
    triage_rows: int
    proposer_rows: int
    verifier_rows: int
    proposer_with_result: int
    proposer_with_gate_and_cost: int
    gate_null_rows: int
    cost_null_rows: int
    usage_without_cost_rows: int
    cost_null_by_stopped_by: dict[str, int]
    false_positive_rows: int
    fp_with_missing: int
    forced_rows: int
    suggested_action: dict[str, int]
    stopped_by: dict[str, int]
    jobs_by_status: dict[str, int]
    cost_usd_sum: float
    first_proposer_at: str | None
    last_proposer_at: str | None

    def as_json(self) -> str:
        return json.dumps(dataclasses.asdict(self))


def _failed_conditions(facts: dict, want: int) -> list[str]:
    """One line per condition that does not hold, in a fixed order."""
    failures: list[str] = []
    if facts["proposer_with_gate_and_cost"] < want:
        failures.append(
            f"{COND_WANT}: found {facts['proposer_with_gate_and_cost']} proposer rows with a "
            f"gate_result and cost_usd > 0, want at least {want}"
        )
    if facts["gate_null_rows"]:
        failures.append(
            f"{COND_GATE_NULL}: {facts['gate_null_rows']} of {facts['triage_rows']} triage rows"
        )
    if facts["usage_without_cost_rows"]:
        failures.append(
            f"{COND_COST_NULL}: {facts['usage_without_cost_rows']} of {facts['triage_rows']} "
            "triage rows"
        )
    if facts["fp_with_missing"]:
        failures.append(
            f"{COND_FP_MISSING}: {facts['fp_with_missing']} of "
            f"{facts['false_positive_rows']} false_positive proposals"
        )
    failed_jobs = facts["jobs_by_status"].get("failed", 0)
    if failed_jobs:
        failures.append(
            f"{COND_FAILED_JOBS}: {failed_jobs} of {sum(facts['jobs_by_status'].values())} "
            "triage jobs"
        )
    return failures


def check_live(conn: psycopg.Connection, *, want: int = DEFAULT_WANT) -> LiveSummary:
    """Read the triage rows on `conn` and judge them. Issues one SELECT; commits, rolls back and
    closes nothing — the caller owns the connection."""
    with conn.cursor(row_factory=tuple_row) as cursor:
        row = cursor.execute(_FACTS_SQL).fetchone()
    facts = row[0]
    failures = _failed_conditions(facts, want)
    return LiveSummary(ok=not failures, failures=failures, want=want, **facts)


# --------------------------------------------------------------------------
# the printed summary
# --------------------------------------------------------------------------


def _fractions(counts: dict[str, int], total: int, unit: str) -> str:
    if not counts:
        return f"0 / {total} {unit}"
    return ", ".join(f"{label} {n} / {total} {unit}" for label, n in sorted(counts.items()))


def format_table(summary: LiveSummary) -> str:
    """The short table: one line per fact, each with the number it is a part of."""
    s = summary
    heads = sum(s.heads_by_source.values())
    jobs = sum(s.jobs_by_status.values())
    rows = [
        ("heads by source", _fractions(s.heads_by_source, heads, "heads")),
        (
            "proposer rows by alert source",
            _fractions(s.proposer_by_source, s.proposer_rows, "proposer rows"),
        ),
        (
            "proposer rows with gate_result and cost_usd > 0",
            f"{s.proposer_with_gate_and_cost} / {s.proposer_rows} proposer rows (want at least {s.want})",
        ),
        (
            "proposer rows with a result",
            f"{s.proposer_with_result} / {s.proposer_rows} proposer rows",
        ),
        ("triage rows with gate_result NULL", f"{s.gate_null_rows} / {s.triage_rows} triage rows"),
        (
            "triage rows with usage but cost_usd NULL",
            f"{s.usage_without_cost_rows} / {s.triage_rows} triage rows",
        ),
        (
            "triage rows with cost_usd NULL (context)",
            f"{s.cost_null_rows} / {s.triage_rows} triage rows",
        ),
        (
            "cost_usd NULL by stopped_by",
            _fractions(
                s.cost_null_by_stopped_by, s.cost_null_rows, "triage rows with cost_usd NULL"
            ),
        ),
        (
            "false_positive proposals with a non-empty gate missing",
            f"{s.fp_with_missing} / {s.false_positive_rows} false_positive proposals",
        ),
        ("triage jobs by status", _fractions(s.jobs_by_status, jobs, "triage jobs")),
        ("stopped_by", _fractions(s.stopped_by, s.proposer_rows, "proposer rows")),
        ("suggested_action", _fractions(s.suggested_action, s.proposer_rows, "proposer rows")),
        ("forced by the gate", f"{s.forced_rows} / {s.proposer_rows} proposer rows"),
        ("verifier rows", f"{s.verifier_rows} / {s.triage_rows} triage rows"),
        ("sum(cost_usd) over triage rows", f"{s.cost_usd_sum:.5f} USD"),
        ("first proposer row", s.first_proposer_at or "-"),
        ("last proposer row", s.last_proposer_at or "-"),
    ]
    width = max(len(label) for label, _ in rows)
    lines = [f"{label + ':':<{width + 1}} {value}" for label, value in rows]
    lines.append(f"{'verdict:':<{width + 1}} {'ok' if s.ok else 'not ok'}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# the connection: read-only, and never quoting the DSN
# --------------------------------------------------------------------------


def connect_read_only(dsn: str) -> psycopg.Connection:
    """A connection whose every transaction is `BEGIN READ ONLY`: the server refuses a write, so
    this script's promise does not rest on its own SQL alone. A bounded statement time keeps a
    stuck query from holding the live database. `options` is left alone so `PGOPTIONS` still
    applies."""
    conn = psycopg.connect(dsn, autocommit=True, connect_timeout=10)
    try:
        conn.execute("SET statement_timeout = '30s'")
        conn.autocommit = False
        conn.read_only = True  # before the first statement of the next transaction
    except BaseException:
        conn.close()
        raise
    return conn


def database_url(*, env_file=".env") -> str:
    """`DATABASE_URL` from the environment or `env_file`; `ConfigError` (no DSN in the message)
    when it is empty — the same source as the API, so the check reads the database the API serves.
    """
    dsn = config.load(env_file=env_file).DATABASE_URL
    if not dsn:
        # The path is not quoted: `--env-file postgresql://user:pw@...` is a slip a person makes with
        # a DSN in the clipboard, and the message would print it whole.
        raise ConfigError(
            "DATABASE_URL: must be set (it is empty in the env file and in the environment; "
            "pass --dsn to name a database)"
        )
    return dsn


def _secret_tokens(dsn: str) -> list[str]:
    """Pieces of `dsn` that must never appear in a message: the whole string and every part of its
    password, cut at each delimiter — libpq reads the host of `user:pw@part@host` from the text
    after the FIRST `@` of a password that contains one, and then quotes it."""
    tokens = {dsn}
    passwords: set[str] = set()
    try:
        libpq_password = conninfo_to_dict(dsn).get("password")
    except psycopg.Error:
        libpq_password = None
    if libpq_password:
        passwords.add(str(libpq_password))
    userinfo = re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://(.*)@", dsn)
    if userinfo and ":" in userinfo.group(1):
        passwords.add(userinfo.group(1).split(":", 1)[1])
    for keyword in re.finditer(r"password\s*=\s*('(?:[^'\\]|\\.)*'|\S+)", dsn):
        passwords.add(keyword.group(1).strip("'"))
    for password in passwords:
        for variant in (password, unquote(password)):
            tokens.add(variant)
            tokens.update(
                piece for piece in re.split(r"[@/:?#\[\]%&=\s]+", variant) if len(piece) >= 4
            )
    return sorted(token for token in tokens if token)


def describe_connect_error(exc: BaseException, dsn: str) -> str:
    """Text safe to print for a failed connection. libpq's own message names the failure (a
    refused connection, a wrong password) and not the connection string, so it is shown — unless
    it quotes a piece of the DSN anyway (a password with an `@` in it is parsed as a host), and
    psycopg's parser error quotes the whole string, so that one is fixed text."""
    if isinstance(exc, (psycopg.OperationalError, ConfigError)):
        text = " ".join(str(exc).split())
        if not any(token in text for token in _secret_tokens(dsn)):
            return text
        return "the server could not be reached or refused the login (details withheld: the message quoted part of the DSN)"
    return "the DSN could not be parsed"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _non_negative_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        value = -1
    if value < 0:
        # a fixed message: argparse would otherwise echo the value it could not read
        raise argparse.ArgumentTypeError("must be a whole number, 0 or more")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 eval/triage_live.py",
        description="Read the triage rows the production worker wrote and check the gate held on "
        "every one of them. Reads only; makes no model call.",
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        help="where DATABASE_URL is read from when --dsn is not given (default: .env)",
    )
    parser.add_argument(
        "--dsn", default=None, help="read this database instead of DATABASE_URL (never printed)"
    )
    parser.add_argument(
        "--want",
        type=_non_negative_int,
        default=DEFAULT_WANT,
        help=f"least number of proposer rows with a gate_result and cost_usd > 0 (default: {DEFAULT_WANT})",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args, unknown = parser.parse_known_args(argv)
    if unknown:
        # not echoed: a mistyped `--dns postgresql://...` would print the DSN it was given
        print("error: unrecognised arguments (not echoed: they may hold a DSN)", file=sys.stderr)
        return EXIT_NO_DATABASE

    dsn = ""
    try:
        dsn = args.dsn or database_url(env_file=args.env_file)
        conn = connect_read_only(dsn)
    except (psycopg.Error, ConfigError) as exc:
        print(
            f"error: cannot connect to the database: {describe_connect_error(exc, dsn)}",
            file=sys.stderr,
        )
        return EXIT_NO_DATABASE

    try:
        summary = check_live(conn, want=args.want)
    except psycopg.Error as exc:
        # a server-side message (a missing table, a denied read) names no connection string
        detail = " ".join(str(exc).split())
        if any(token in detail for token in _secret_tokens(dsn)):
            detail = "the server refused the read"
        print(f"error: cannot read the triage tables: {detail}", file=sys.stderr)
        return EXIT_NO_DATABASE
    finally:
        conn.rollback()
        conn.close()

    print(summary.as_json())
    print(format_table(summary))
    for failure in summary.failures:
        print(f"FAIL {failure}")
    return EXIT_OK if summary.ok else EXIT_FAILED


if __name__ == "__main__":  # pragma: no cover — exercised through subprocess in test_triage_live.py
    sys.exit(main())
