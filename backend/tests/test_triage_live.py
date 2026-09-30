"""P3-T11 (amended by DEC-156) — the read-only check that ① wrote the gate and the cost on every
live triage row: `eval/triage_live.py` and its `@pytest.mark.live` test.

Nothing here calls a model, claims a job or writes to a live table. `check_live` reads the rows the
production worker already wrote; the CLI opens its session READ ONLY.

**Isolation.** `TEST_DATABASE_URL` is one database shared by every `db` test file, several of which
commit rows (and `llm_runs` is append-only, so a committed row can never be removed). `check_live`
counts whole tables, so a leaked row from another file would turn an exact assertion here red — or
an `ok` green — for a reason that has nothing to do with this file. Every `db` test below therefore
reads private copies of `alerts`, `llm_runs` and `jobs` (`CREATE TABLE … (LIKE public.… INCLUDING
ALL)`, so the columns and CHECK constraints are the real ones) that shadow the real tables through
`search_path`:
- the in-process tests create them inside the `db` fixture's transaction — rolled back with it,
  nothing is ever committed;
- the CLI tests need rows a subprocess can see, so they commit them into their own schema, reached
  through `PGOPTIONS`, and drop that schema in the fixture's teardown (a `DROP`, which the
  append-only triggers of the real tables do not touch). Nothing lands in `public`.
The three tests that need the REAL database (`check_live` inside a READ ONLY transaction, the CLI's
read-only session, and the session `main` opens) assert only that a statement is refused or that the
query runs — never a count.

`eval/` is a composition root outside `backend/` and not on `sys.path`, so `triage_live.py` is
loaded by path (the pattern of test_lab_tag.py).

The live test names `.env` explicitly (DEC-047) and only ever skips — never passes — without it:
a green live test that checked nothing is the DEC-047 failure shape.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import urllib.parse
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import psycopg
import pytest
from app.infra import config
from psycopg.types.json import Jsonb

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "eval" / "triage_live.py"
PYTEST_CONFIG = REPO_ROOT / "backend" / "pyproject.toml"
THIS_FILE = Path(__file__).resolve()

_spec = importlib.util.spec_from_file_location("triage_live", SCRIPT_PATH)
triage_live = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = triage_live
_spec.loader.exec_module(triage_live)

check_live = triage_live.check_live

# The tables `check_live` reads; a test that forgot one would read the real table and say so.
_TABLES = ("alerts", "llm_runs", "jobs")
_TX_SCHEMA = "p3t11_live_tx"  # created and rolled back inside the `db` transaction
_CLI_SCHEMA = "p3t11_live_cli"  # committed for a subprocess, dropped in the fixture's teardown

# Environment variables that could hand a subprocess a database it was not told to use.
_DATABASE_VARIABLES = (
    "DATABASE_URL",
    "DATABASE_URL_OWNER",
    "TEST_DATABASE_URL",
    "PGHOST",
    "PGPORT",
    "PGUSER",
    "PGPASSWORD",
    "PGDATABASE",
    "PGOPTIONS",
    "PGSERVICE",
)


# --- private copies of the three tables ---------------------------------------------------------


def _create_private_tables(conn: psycopg.Connection, schema: str) -> None:
    conn.execute(f'CREATE SCHEMA "{schema}"')
    for table in _TABLES:
        conn.execute(f'CREATE TABLE "{schema}"."{table}" (LIKE public.{table} INCLUDING ALL)')


@pytest.fixture
def live_db(db):
    """`db`, with empty private `alerts`/`llm_runs`/`jobs` in front of the real ones — for this
    transaction only."""
    _create_private_tables(db, _TX_SCHEMA)
    db.execute(f'SET LOCAL search_path TO "{_TX_SCHEMA}"')
    return db


@pytest.fixture
def committed_live_db(_test_database):
    """The same private tables, committed so a subprocess can read them, in an autocommit
    connection the test seeds through; the schema is dropped afterwards, pass or fail."""
    conn = psycopg.connect(_test_database, autocommit=True)
    try:
        conn.execute(f'DROP SCHEMA IF EXISTS "{_CLI_SCHEMA}" CASCADE')
        _create_private_tables(conn, _CLI_SCHEMA)
        conn.execute(f'SET search_path TO "{_CLI_SCHEMA}"')
        yield conn
    finally:
        conn.execute(f'DROP SCHEMA IF EXISTS "{_CLI_SCHEMA}" CASCADE')
        conn.close()


# --- seeding helpers -----------------------------------------------------------------------------

_GOOD_GATE = {"forced": False, "missing": []}


def _json(value):
    """`Jsonb(value)`, or SQL NULL for None (`Jsonb(None)` would store the JSON literal null)."""
    return Jsonb(value) if value is not None else None


def _alert(conn, alert_id: str, *, source: str = "wazuh", duplicate_of: str | None = None) -> str:
    duplicate = duplicate_of is not None
    conn.execute(
        "INSERT INTO alerts (alert_id, rule_id, rule_level, severity, description, agent_name, "
        "alert_time, category, resolved_by, mapping_version, event_bucket_hash, raw_payload, "
        "source, status, duplicate_of, closed_at, sealed_at) "
        "VALUES (%s, '5710', 5, 'low', 'seeded', 'agent', now(), 'unknown', 'none', 'v1', %s, "
        "'{}'::jsonb, %s, %s, %s, CASE WHEN %s THEN now() END, CASE WHEN %s THEN now() END)",
        (
            alert_id,
            hashlib.sha256(alert_id.encode()).hexdigest(),
            source,
            "duplicate" if duplicate else "queued_tier1",
            duplicate_of,
            duplicate,
            duplicate,
        ),
    )
    return alert_id


def _run(conn, subject_id: str, **overrides) -> None:
    """One triage `llm_runs` row. Defaults are a healthy proposer row (an `escalate` that the gate
    left alone, with a gate document, the usage the model returned and a cost); any column can be
    overridden, `None` included."""
    row = {
        "role": "proposer",
        "pipeline": "triage",
        "subject_type": "alert",
        "result": {"suggested_action": "escalate"},
        "gate_result": _GOOD_GATE,
        "cost_usd": Decimal("0.00024"),
        "input_tokens": 120,
        "stopped_by": None,
        "created_at": None,
    } | overrides
    conn.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt, "
        "user_message, result, role, gate_result, cost_usd, input_tokens, stopped_by, created_at) "
        "VALUES (gen_random_uuid(), %s, %s, %s, 's', 'u', %s, %s, %s, %s, %s, %s, "
        "COALESCE(%s::timestamptz, now()))",
        (
            row["pipeline"],
            row["subject_type"],
            subject_id,
            _json(row["result"]),
            row["role"],
            _json(row["gate_result"]),
            row["cost_usd"],
            row["input_tokens"],
            row["stopped_by"],
            row["created_at"],
        ),
    )


def _job(conn, subject_id: str, *, status: str, job_type: str = "triage") -> None:
    conn.execute(
        "INSERT INTO jobs (job_type, subject_id, status) VALUES (%s, %s, %s)",
        (job_type, subject_id, status),
    )


def _seed_healthy(conn, n: int, *, prefix: str = "ok", source: str = "wazuh") -> list[str]:
    """`n` heads, each with a healthy proposer row and a verifier row, and one succeeded job."""
    ids = []
    for i in range(n):
        alert_id = _alert(conn, f"{prefix}-{i}", source=source)
        _run(conn, alert_id)
        _run(conn, alert_id, role="verifier", result={"agree": True})
        _job(conn, alert_id, status="succeeded")
        ids.append(alert_id)
    return ids


def _failures_naming(summary, condition: str) -> list[str]:
    return [line for line in summary.failures if line.startswith(condition)]


# --- check_live ---------------------------------------------------------------------------------


@pytest.mark.db
def test_check_live_passes_on_a_clean_table(live_db):
    empty = check_live(live_db, want=0)
    assert empty.ok is True
    assert empty.failures == []
    assert (empty.triage_rows, empty.proposer_rows) == (0, 0)
    assert empty.first_proposer_at is None and empty.last_proposer_at is None
    assert check_live(live_db).ok is False  # the default `want` (50) is not met by an empty table

    _seed_healthy(live_db, 3)
    # A ② row is never judged by ①'s conditions: no gate document, no cost, still not a failure.
    live_db.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt, "
        "user_message, role) VALUES (gen_random_uuid(), 'investigate', 'case', 'case-1', 's', "
        "'u', 'investigator')"
    )
    summary = check_live(live_db, want=3)
    assert summary.failures == []
    assert summary.ok is True
    assert summary.proposer_with_gate_and_cost == 3
    assert summary.triage_rows == 6  # three proposers and three verifiers; the ② row is not one


@pytest.mark.db
def test_check_live_fails_below_want(live_db):
    _seed_healthy(live_db, 3)
    # A gate document with a cost of 0 is not a paid, gated run: it never counts toward `want`.
    _run(live_db, _alert(live_db, "free-run"), cost_usd=Decimal(0))
    # Nor does a row without a gate document.
    _run(live_db, _alert(live_db, "no-gate"), gate_result=None)

    assert check_live(live_db, want=3).proposer_with_gate_and_cost == 3
    summary = check_live(live_db, want=4)
    assert summary.ok is False
    below = _failures_naming(summary, triage_live.COND_WANT)
    assert len(below) == 1
    assert "3" in below[0] and "4" in below[0]  # what it found and what it wanted
    # The `no-gate` row also fails its own, separate condition; `want` is not the only one here.
    assert len(summary.failures) == 2


@pytest.mark.db
def test_check_live_fails_on_a_null_gate_result(live_db):
    _seed_healthy(live_db, 3)
    assert check_live(live_db, want=3).ok is True

    _run(live_db, _alert(live_db, "gate-null-proposer"), gate_result=None)
    summary = check_live(live_db, want=3)
    assert summary.ok is False
    assert summary.gate_null_rows == 1
    assert len(_failures_naming(summary, triage_live.COND_GATE_NULL)) == 1
    assert len(summary.failures) == 1  # `want` still holds: the ungated row is simply not counted

    # ANY role: a verifier row without a gate document fails the same condition.
    _run(live_db, _alert(live_db, "gate-null-verifier"), role="verifier", gate_result=None)
    assert check_live(live_db, want=3).gate_null_rows == 2


@pytest.mark.db
def test_check_live_fails_on_a_null_cost(live_db):
    """Condition 3 (as amended in review round 1): a call that RETURNED usage (`input_tokens` set)
    but has no `cost_usd` is a failure — the cost was there to record and was not."""
    _seed_healthy(live_db, 3)
    assert check_live(live_db, want=3).ok is True

    _run(live_db, _alert(live_db, "cost-null-proposer"), cost_usd=None)  # default: usage returned
    summary = check_live(live_db, want=3)
    assert summary.ok is False
    assert summary.usage_without_cost_rows == 1
    assert summary.cost_null_rows == 1
    assert len(_failures_naming(summary, triage_live.COND_COST_NULL)) == 1
    assert len(summary.failures) == 1

    _run(live_db, _alert(live_db, "cost-null-verifier"), role="verifier", cost_usd=None)
    assert check_live(live_db, want=3).usage_without_cost_rows == 2


@pytest.mark.db
def test_check_live_accepts_a_null_cost_when_no_call_returned_usage(live_db):
    """`backend/app/tier1/triage.py` writes `cost_usd=None` together with `input_tokens=None` on the
    paths where no model call returned usage (a transient error, the cap, the linter). `llm_runs`
    is append-only, so counting those as a failure would make the check exit 1 forever. They are
    context — counted, broken down by `stopped_by` — and never a failure."""
    _seed_healthy(live_db, 3)
    for name, stopped_by in (("capped", "cap"), ("transient", "transient")):
        _run(
            live_db,
            _alert(live_db, name),
            result=None,
            gate_result={"error": stopped_by},
            cost_usd=None,
            input_tokens=None,
            stopped_by=stopped_by,
        )
    # a verifier row written after the cap: no usage, no cost either
    _run(
        live_db,
        _alert(live_db, "verifier-after-cap"),
        role="verifier",
        result=None,
        cost_usd=None,
        input_tokens=None,
        stopped_by="cap",
    )

    summary = check_live(live_db, want=3)
    assert summary.ok is True, summary.failures
    assert summary.failures == []
    assert summary.usage_without_cost_rows == 0
    assert summary.cost_null_rows == 3  # the context count still sees them
    assert summary.cost_null_by_stopped_by == {"cap": 2, "transient": 1}
    assert summary.proposer_with_gate_and_cost == 3  # a row without a cost is never a paid run

    table = triage_live.format_table(summary)
    assert re.search(r"cost_usd NULL \(context\):\s+3 / 9 triage rows", table)
    assert re.search(r"usage but cost_usd NULL:\s+0 / 9 triage rows", table)
    assert re.search(r"cost_usd NULL by stopped_by:\s+cap 2 / 3 .*transient 1 / 3 ", table)


@pytest.mark.db
def test_check_live_counts_a_row_without_a_role(live_db):
    """`ck_llm_runs_role` admits a NULL `role` (a row written before migration 016). It is a
    triage row: counted in the total and judged by the NULL conditions, and never a proposer or a
    verifier."""
    _seed_healthy(live_db, 3)
    _run(live_db, _alert(live_db, "no-role-fine"), role=None)
    summary = check_live(live_db, want=3)
    assert summary.ok is True, summary.failures
    assert summary.triage_rows == 7
    assert (summary.proposer_rows, summary.verifier_rows) == (3, 3)

    _run(live_db, _alert(live_db, "no-role-no-gate"), role=None, gate_result=None)
    summary = check_live(live_db, want=3)
    assert summary.gate_null_rows == 1
    assert len(_failures_naming(summary, triage_live.COND_GATE_NULL)) == 1

    _run(live_db, _alert(live_db, "no-role-no-cost"), role=None, cost_usd=None)
    summary = check_live(live_db, want=3)
    assert summary.usage_without_cost_rows == 1
    assert len(_failures_naming(summary, triage_live.COND_COST_NULL)) == 1
    assert (summary.triage_rows, summary.proposer_rows, summary.verifier_rows) == (9, 3, 3)


@pytest.mark.db
def test_check_live_fails_on_a_surviving_false_positive_with_missing(live_db):
    _seed_healthy(live_db, 3)
    # Two rows that look alike and are fine: a false_positive the gate kept (nothing missing), and a
    # proposal the gate forced away from false_positive (`missing` is filled, the result is not FP).
    _run(
        live_db,
        _alert(live_db, "fp-kept"),
        result={"suggested_action": "false_positive"},
        gate_result={"forced": False, "missing": []},
    )
    _run(
        live_db,
        _alert(live_db, "fp-forced"),
        result={"suggested_action": "needs_review"},
        gate_result={"forced": True, "missing": ["asset_criticality"]},
    )
    fine = check_live(live_db, want=3)
    assert fine.ok is True
    assert fine.false_positive_rows == 1  # the denominator of the condition below
    assert fine.fp_with_missing == 0

    _run(
        live_db,
        _alert(live_db, "fp-survived"),
        result={"suggested_action": "false_positive"},
        gate_result={"forced": False, "missing": ["asset_criticality"]},
    )
    summary = check_live(live_db, want=3)
    assert summary.ok is False
    assert summary.fp_with_missing == 1
    assert summary.false_positive_rows == 2
    assert len(_failures_naming(summary, triage_live.COND_FP_MISSING)) == 1
    assert len(summary.failures) == 1


@pytest.mark.db
def test_check_live_fails_on_a_failed_triage_job(live_db):
    _seed_healthy(live_db, 3)
    # Neither of these is a failed TRIAGE job: a failed job of another type, a succeeded triage job.
    _job(live_db, "enrich-1", status="failed", job_type="pipeline")
    _job(live_db, "triage-ok", status="succeeded")
    assert check_live(live_db, want=3).ok is True

    _job(live_db, "triage-bad", status="failed")
    summary = check_live(live_db, want=3)
    assert summary.ok is False
    assert len(_failures_naming(summary, triage_live.COND_FAILED_JOBS)) == 1
    assert len(summary.failures) == 1
    assert summary.jobs_by_status == {"succeeded": 4, "failed": 1}  # triage jobs only


@pytest.mark.db
def test_check_live_counts_a_schema_stop_without_failing(live_db):
    """DEC-156 §2: a proposer run whose output the schema check rejected has no `result` and no
    verifier row, but it still carries its gate document and its cost — it is a count, not a
    failure."""
    _seed_healthy(live_db, 3)
    stopped = _alert(live_db, "schema-stop")
    _run(live_db, stopped, result=None, gate_result={"error": "schema"}, stopped_by="schema")

    summary = check_live(live_db, want=4)  # the schema stop is one of the four paid, gated runs
    assert summary.ok is True
    assert summary.failures == []
    assert summary.stopped_by == {"(none)": 3, "schema": 1}
    assert summary.suggested_action == {"escalate": 3, "(none)": 1}
    assert (summary.proposer_rows, summary.proposer_with_result) == (4, 3)
    assert summary.verifier_rows == 3  # none for the stopped run


@pytest.mark.db
def test_check_live_reports_the_facts_with_their_denominators(live_db):
    wazuh_head = _alert(live_db, "head-w1", source="wazuh")
    _alert(live_db, "head-w2", source="wazuh")
    lab_head = _alert(live_db, "head-l1", source="lab")
    _alert(live_db, "dup-of-w1", source="wazuh", duplicate_of=wazuh_head)  # not a head

    early, late = "2026-09-01 08:00:00+00", "2026-09-02 09:30:00+00"
    _run(live_db, wazuh_head, cost_usd=Decimal("0.001"), created_at=early)
    _run(
        live_db,
        lab_head,
        result={"suggested_action": "needs_review"},
        gate_result={"forced": True, "missing": ["asset_criticality"]},
        cost_usd=Decimal("0.002"),
        created_at=late,
    )
    _run(  # a run whose alert is gone
        live_db, "no-such-alert", cost_usd=Decimal("0.0005"), created_at="2026-09-01 12:00:00+00"
    )
    _run(live_db, wazuh_head, role="verifier", cost_usd=Decimal("0.003"))
    _job(live_db, wazuh_head, status="succeeded")
    _job(live_db, lab_head, status="pending")

    s = check_live(live_db, want=1)

    assert s.heads_by_source == {"wazuh": 2, "lab": 1}  # the duplicate is not counted
    assert s.proposer_by_source == {"wazuh": 1, "lab": 1, "(no alert)": 1}
    assert (s.triage_rows, s.proposer_rows, s.verifier_rows) == (4, 3, 1)
    assert s.proposer_with_result == 3
    assert s.proposer_with_gate_and_cost == 3
    assert (s.gate_null_rows, s.cost_null_rows, s.usage_without_cost_rows) == (0, 0, 0)
    assert s.cost_null_by_stopped_by == {}
    assert s.forced_rows == 1
    assert s.suggested_action == {"escalate": 2, "needs_review": 1}
    assert s.stopped_by == {"(none)": 3}
    assert s.jobs_by_status == {"succeeded": 1, "pending": 1}
    assert s.cost_usd_sum == pytest.approx(0.0065)
    assert datetime.fromisoformat(s.first_proposer_at) == datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
    assert datetime.fromisoformat(s.last_proposer_at) == datetime(2026, 9, 2, 9, 30, tzinfo=UTC)
    assert s.want == 1 and s.ok is True

    # The printed summary carries each figure with its denominator, and the JSON line round-trips.
    table = triage_live.format_table(s)
    assert re.search(r"gate_result and cost_usd > 0:\s+3 / 3 proposer rows", table)
    assert re.search(r"gate_result NULL:\s+0 / 4 triage rows", table)
    assert re.search(r"cost_usd NULL \(context\):\s+0 / 4 triage rows", table)
    assert re.search(r"usage but cost_usd NULL:\s+0 / 4 triage rows", table)
    assert re.search(r"forced by the gate:\s+1 / 3 proposer rows", table)
    assert re.search(r"verifier rows:\s+1 / 4 triage rows", table)
    assert json.loads(s.as_json())["proposer_by_source"] == s.proposer_by_source


@pytest.mark.db
def test_check_live_runs_inside_a_read_only_transaction(_test_database):
    """`check_live` issues only SELECTs: it completes on a connection that refuses every write.
    (Reads the REAL tables — nothing here depends on what they hold.)"""
    conn = triage_live.connect_read_only(_test_database)
    try:
        summary = check_live(conn, want=0)
        assert isinstance(summary, triage_live.LiveSummary)
    finally:
        conn.rollback()
        conn.close()


# --- the CLI ------------------------------------------------------------------------------------


@pytest.mark.db
def test_cli_session_is_read_only(_test_database):
    """A write through the CLI's own connection function is refused by the server."""
    conn = triage_live.connect_read_only(_test_database)
    try:
        assert conn.execute("SHOW transaction_read_only").fetchone() == ("on",)
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            conn.execute(
                "INSERT INTO jobs (job_type, subject_id) VALUES ('triage', 'p3t11-read-only-probe')"
            )
    finally:
        conn.rollback()  # if a mutation let the write through, it never leaves this transaction
        conn.close()


@pytest.mark.db
def test_main_reads_through_a_read_only_session(_test_database, monkeypatch, capsys):
    """The session `main` itself opens is READ ONLY — not just the helper it should be calling. A
    stand-in for `check_live` tries a write through the connection `main` hands it; the server must
    refuse it, and `main` must exit 2 rather than carry on. (Were `main` to open a plain
    connection, the write would go through, the real `check_live` would run and `main` would exit
    0 — and `main` rolls the transaction back either way, so nothing is left behind.)"""
    real_check_live = triage_live.check_live

    def writes_first(conn, *, want=triage_live.DEFAULT_WANT):
        conn.execute("CREATE TEMP TABLE p3t11_main_probe (x int)")
        return real_check_live(conn, want=want)

    monkeypatch.setattr(triage_live, "check_live", writes_first)

    code = triage_live.main(["--dsn", str(_test_database), "--want", "0"])
    captured = capsys.readouterr()
    assert code == triage_live.EXIT_NO_DATABASE, captured.out + captured.err
    assert "read-only transaction" in captured.err
    assert captured.out == ""  # no summary was printed


def _called_names(function: ast.FunctionDef) -> set[str]:
    """Every dotted name the function calls, e.g. `psycopg.connect`, `triage_live.connect_read_only`."""
    names = set()
    for node in ast.walk(function):
        if isinstance(node, ast.Call):
            parts = []
            target = node.func
            while isinstance(target, ast.Attribute):
                parts.append(target.attr)
                target = target.value
            if isinstance(target, ast.Name):
                parts.append(target.id)
                names.add(".".join(reversed(parts)))
    return names


def test_the_live_test_connects_through_connect_read_only():
    """The live test reads a database nobody may write to, so its connection must be the one that
    is READ ONLY by construction and whose errors are scrubbed — not a `psycopg.connect` of its
    own. Read from the source, because the live test cannot run from a worktree."""
    tree = ast.parse(THIS_FILE.read_text(encoding="utf-8"))
    (live_test,) = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and node.name == "test_live_triage_gate_holds_on_the_live_database"
    ]
    called = _called_names(live_test)
    assert "triage_live.connect_read_only" in called
    assert "psycopg.connect" not in called and "connect" not in called


def _cli(*args: str, cwd: Path, env_extra: dict[str, str] | None = None):
    """Run `eval/triage_live.py` in a subprocess with no database in its environment beyond what
    the caller passes; returns the CompletedProcess, so a failing test prints plain fields."""
    env = {k: v for k, v in os.environ.items() if k not in _DATABASE_VARIABLES}
    env["PYTHONPATH"] = str(REPO_ROOT / "backend")
    env.update(env_extra or {})
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _secret_pieces(dsn: str) -> list[str]:
    """The DSN itself and its password, whole and cut at every URI delimiter."""
    password = urllib.parse.urlsplit(dsn).password or ""
    pieces = {dsn, password, *urllib.parse.unquote(password).replace("@", " ").split()}
    return sorted(p for p in pieces if len(p) >= 4)


@pytest.mark.db
def test_cli_exit_codes_0_and_1(committed_live_db, _test_database, tmp_path):
    for i in range(3):
        alert_id = _alert(committed_live_db, f"cli-{i}")
        _run(committed_live_db, alert_id)
        _job(committed_live_db, alert_id, status="succeeded")
    private = {"PGOPTIONS": f"-c search_path={_CLI_SCHEMA}"}

    def run(want: int):
        return _cli(
            "--dsn", str(_test_database), "--want", str(want), cwd=tmp_path, env_extra=private
        )

    passed = run(3)
    code, out, err = passed.returncode, passed.stdout, passed.stderr
    assert code == 0, out + err
    summary = json.loads(out.splitlines()[0])  # the first line is the one-line JSON summary
    assert summary["ok"] is True and summary["proposer_with_gate_and_cost"] == 3
    assert "FAIL" not in out
    leaked = [p for p in _secret_pieces(str(_test_database)) if p in out + err]
    assert leaked == []

    short = run(4)  # one condition fails: fewer paid, gated runs than wanted
    code, out, err = short.returncode, short.stdout, short.stderr
    assert code == 1, out + err
    assert json.loads(out.splitlines()[0])["ok"] is False
    fail_lines = [line for line in out.splitlines() if line.startswith("FAIL")]
    assert len(fail_lines) == 1 and triage_live.COND_WANT in fail_lines[0]

    _job(committed_live_db, "cli-bad-job", status="failed")
    both = run(4)  # two conditions fail: each is named on a line of its own
    code, out, err = both.returncode, both.stdout, both.stderr
    assert code == 1, out + err
    fail_lines = [line for line in out.splitlines() if line.startswith("FAIL")]
    assert len(fail_lines) == 2
    assert triage_live.COND_WANT in fail_lines[0] and triage_live.COND_FAILED_JOBS in fail_lines[1]
    leaked = [p for p in _secret_pieces(str(_test_database)) if p in out + err]
    assert leaked == []


def test_cli_exit_2_without_a_database_url_never_prints_a_dsn(tmp_path):
    empty_env_file = tmp_path / "empty.env"
    empty_env_file.write_text("# nothing here\n", encoding="utf-8")

    result = _cli("--env-file", str(empty_env_file), cwd=tmp_path)
    code, out, err = result.returncode, result.stdout, result.stderr
    assert code == 2, out + err
    assert "DATABASE_URL: must be set" in err
    assert out == ""  # no summary: nothing was read

    # No --env-file and no .env in the working directory: the same exit, the same message.
    result = _cli(cwd=tmp_path)
    assert result.returncode == 2
    assert "DATABASE_URL: must be set" in result.stderr

    # Other DSNs sit in the same file (the owner's, the test database's) while DATABASE_URL is
    # empty. They are not the database this check was pointed at: it neither falls back to them
    # (that would be a connection error, not "must be set") nor prints them.
    owner = "postgresql://owner:0wnerpw9@127.0.0.1:1/owner_db"
    tester = "postgresql://tester:t3sterpw9@127.0.0.1:1/test_db"
    mixed_env_file = tmp_path / "mixed.env"
    mixed_env_file.write_text(
        f"DATABASE_URL=\nDATABASE_URL_OWNER={owner}\nTEST_DATABASE_URL={tester}\n",
        encoding="utf-8",
    )
    result = _cli("--env-file", str(mixed_env_file), cwd=tmp_path)
    code, out, err = result.returncode, result.stdout, result.stderr
    assert code == 2, out + err
    assert "DATABASE_URL: must be set" in err
    leaked = [p for p in (owner, tester, "0wnerpw9", "t3sterpw9") if p in out + err]
    assert leaked == []


def test_cli_exit_2_on_a_dsn_given_as_the_env_file_never_prints_it(tmp_path):
    """`--env-file postgresql://user:pw@…` is a slip a person makes with a DSN in the clipboard
    (argparse also accepts the prefix `--env`). The path names no file, so DATABASE_URL is empty and
    the check says so — without quoting the path it was given."""
    dsn = "postgresql://someone:s3cr3tpw@t0kenpiece@127.0.0.1:1/soc"
    tokens = triage_live._secret_tokens(dsn)
    assert dsn in tokens and "s3cr3tpw" in tokens  # the check below is not vacuous

    for flag in ("--env-file", "--env"):
        result = _cli(flag, dsn, cwd=tmp_path)
        code, text = result.returncode, result.stdout + result.stderr
        assert code == 2, text
        assert "DATABASE_URL: must be set" in text
        assert [t for t in tokens if t in text] == []
        assert [p for p in _secret_pieces(dsn) if p in text] == []


def test_cli_exit_2_on_a_refused_connection_never_prints_the_password(tmp_path):
    # Nothing listens on port 1. The password holds an `@`, so libpq's own message about the
    # host it could not resolve quotes a piece of it — the case a bare `print(exc)` would leak.
    dsn = "postgresql://someone:s3cr3t@t0kenpiece@127.0.0.1:1/soc"
    via_flag = _cli("--dsn", dsn, cwd=tmp_path)
    env_file = tmp_path / "leaky.env"
    env_file.write_text(f"DATABASE_URL={dsn}\n", encoding="utf-8")
    via_file = _cli("--env-file", str(env_file), cwd=tmp_path)

    for result in (via_flag, via_file):
        code, text = result.returncode, result.stdout + result.stderr
        assert code == 2, text
        assert "cannot connect to the database" in text
        leaked = [p for p in ("s3cr3t", "t0kenpiece", dsn) if p in text]
        assert leaked == []


def test_cli_exit_2_on_an_unparsable_dsn_never_prints_it(tmp_path):
    # psycopg's own parser quotes the whole string it could not parse.
    dsn = "postgresql://someone:s3cr3t@[not-an-ipv6/soc"
    result = _cli("--dsn", dsn, cwd=tmp_path)
    code, text = result.returncode, result.stdout + result.stderr
    assert code == 2, text
    assert "cannot connect to the database" in text
    assert [p for p in ("s3cr3t", dsn) if p in text] == []


# --- the live test ------------------------------------------------------------------------------


@pytest.mark.live
def test_live_triage_gate_holds_on_the_live_database():
    """Run by the Owner (and the Director) from the primary checkout, where `.env` is: reads the
    rows the production worker already wrote — no model call, no queue claim, nothing written."""
    cfg = config.load(env_file=".env")  # by name (DEC-047), relative to the working directory
    if not Path(".env").is_file():
        reason = (
            "live: no .env in the working directory — the Owner runs this from the primary "
            "checkout, where .env holds DATABASE_URL"
        )
    elif not cfg.DATABASE_URL:
        reason = (
            "live: DATABASE_URL is empty in .env and in the environment — the Owner runs this "
            "against the live database"
        )
    else:
        reason = None
    if reason:
        pytest.skip(reason)

    # Its own connection, never the `db` fixture: READ ONLY by construction, with the connection
    # error scrubbed. The failure is raised OUTSIDE the `except`, with `pytrace=False`: a traceback
    # would show psycopg's `connect` frame, whose locals hold the connection string — password
    # included — and nothing masks a password that only `.env` knows about.
    dsn = cfg.DATABASE_URL
    refusal = None
    try:
        conn = triage_live.connect_read_only(dsn)
    except psycopg.Error as exc:
        refusal = triage_live.describe_connect_error(exc, dsn)
    if refusal is not None:
        pytest.fail(f"cannot connect to the database: {refusal}", pytrace=False)
    try:
        summary = check_live(conn, want=50)
    finally:
        conn.rollback()
        conn.close()
    print(triage_live.format_table(summary))
    assert summary.ok, "\n".join(summary.failures)


def _live_test_in_a_bare_directory(
    cwd: Path,
    *,
    env_file_text: str | None,
    pytest_args: tuple[str, ...] = ("-rs",),
    env_extra: dict[str, str] | None = None,
):
    """`pytest -m live` on this file with `cwd` as the working directory, i.e. as the Owner would
    run it from a checkout that has no `.env` — or one whose `.env` is empty, or names a database.
    No database variable is passed on, so nothing masks a password the way the suite's own
    conftest does for the passwords of the environment."""
    if env_file_text is not None:
        (cwd / ".env").write_text(env_file_text, encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k not in _DATABASE_VARIABLES}
    env["PYTHONPATH"] = str(REPO_ROOT / "backend")
    env.update(env_extra or {})
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-c",
            str(PYTEST_CONFIG),
            "-p",
            "no:cacheprovider",
            "--color=no",
            "-m",
            "live",
            *pytest_args,
            str(THIS_FILE),
        ],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_live_test_skips_without_env(tmp_path):
    result = _live_test_in_a_bare_directory(tmp_path, env_file_text=None)
    code, out = result.returncode, result.stdout + result.stderr
    assert code == 0, out
    assert "1 skipped" in out
    assert "passed" not in out and "failed" not in out
    skipped = [line for line in out.splitlines() if line.startswith("SKIPPED")]
    assert len(skipped) == 1
    assert ".env" in skipped[0] and "the Owner runs this" in skipped[0]


def test_live_test_skips_with_an_empty_database_url(tmp_path):
    result = _live_test_in_a_bare_directory(tmp_path, env_file_text="DATABASE_URL=\n")
    code, out = result.returncode, result.stdout + result.stderr
    assert code == 0, out
    assert "1 skipped" in out
    assert "passed" not in out and "failed" not in out
    skipped = [line for line in out.splitlines() if line.startswith("SKIPPED")]
    assert len(skipped) == 1
    assert "DATABASE_URL" in skipped[0] and "the Owner runs this" in skipped[0]


# Nothing listens on port 1. The second password holds an `@`, so libpq's own message about the
# host it could not resolve quotes a piece of it — the case a bare `print(exc)` would leak.
_REFUSED_DSNS = (
    "postgresql://someone:s3cr3tpw@127.0.0.1:1/soc",
    "postgresql://someone:p4rt1al@t0kenpiece@127.0.0.1:1/soc",
)


@pytest.mark.parametrize("dsn", _REFUSED_DSNS, ids=["plain-password", "password-with-an-at-sign"])
def test_live_test_fails_when_the_connection_is_refused_without_leaking_the_password(tmp_path, dsn):
    """The Owner's command (`-m live -rs -vv`) against a `.env` whose DATABASE_URL cannot be
    reached. The outcome is a FAILURE — never a pass, never a skip — and the report shows the
    failure reason and none of the DSN: not the password, not the pieces of it a message could
    quote. The environment holds no database variable, so the suite's own masking, which knows
    only the passwords of the environment, cannot be what hides it. `--showlocals` is on: were the
    failure raised with a traceback, psycopg's `connect` frame would print the connection string."""
    tokens = triage_live._secret_tokens(dsn)
    password = urllib.parse.urlsplit(dsn).password
    assert dsn in tokens and password.split("@")[0] in tokens  # the checks below are not vacuous

    result = _live_test_in_a_bare_directory(
        tmp_path,
        env_file_text=f"DATABASE_URL={dsn}\n",
        pytest_args=("-rs", "-vv", "--showlocals"),
    )
    code, out = result.returncode, result.stdout + result.stderr
    # (the assertion messages print test ids only: were the report to leak, they must not repeat it)
    assert code == 1, [line for line in out.splitlines() if "::" in line]
    assert "1 failed" in out
    assert "passed" not in out and "skipped" not in out.lower()
    assert "cannot connect to the database" in out
    assert len([t for t in tokens if t in out]) == 0
    assert len([p for p in _secret_pieces(dsn) if p in out]) == 0


@pytest.mark.db
def test_live_test_passes_and_shows_its_table_only_under_rP(
    committed_live_db, _test_database, tmp_path
):
    """The live test end to end on a database that holds enough healthy rows (private schema,
    reached through `PGOPTIONS`; the `.env` is in a temporary directory, never in the repository).
    A pass hides what the test printed unless `-rP` asks for it — so the Owner's command carries
    `-rsP`, and this proves that with it the table, with its denominators and its verdict, is
    what the Owner reads."""
    _seed_healthy(committed_live_db, 50)
    private = {"PGOPTIONS": f"-c search_path={_CLI_SCHEMA}"}
    env_file_text = f"DATABASE_URL={_test_database}\n"

    plain = _live_test_in_a_bare_directory(
        tmp_path, env_file_text=env_file_text, pytest_args=("-rs", "-vv"), env_extra=private
    )
    assert plain.returncode == 0, plain.stdout
    assert "1 passed" in plain.stdout and "PASSED" in plain.stdout
    assert "verdict:" not in plain.stdout  # captured: a pass shows only PASSED

    shown = _live_test_in_a_bare_directory(
        tmp_path, env_file_text=env_file_text, pytest_args=("-rsP", "-vv"), env_extra=private
    )
    assert shown.returncode == 0, shown.stdout
    assert "1 passed" in shown.stdout
    assert re.search(r"gate_result and cost_usd > 0:\s+50 / 50 proposer rows", shown.stdout)
    assert re.search(r"triage rows with gate_result NULL:\s+0 / 100 triage rows", shown.stdout)
    assert re.search(r"verdict:\s+ok", shown.stdout)
