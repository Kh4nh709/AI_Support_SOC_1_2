"""INT-T03 / DEC-212 — `python -m app.domain.archive`, the Owner's command.

    python -m app.domain.archive --before <ISO-8601 with offset> --reason <text> [--apply]

Without `--apply` it is a dry run: `archive_before` runs in a transaction that is rolled back and the
counts are printed. With `--apply` it commits and prints the same counts. It reads the DSN the way
the other `python -m app...` commands do (`config.load`: `DATABASE_URL` from the environment or
`.env`), and it never prints one. A `--before` with no UTC offset is refused before the database is
touched.
"""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta, timezone

import psycopg
import pytest
from app.domain import archive, transitions
from app.infra import db as infra_db

from tests import conftest
from tests.scratch_db import scratch_database
from tests.test_archive import BEFORE, EARLIER, REASON, _put_alert, _put_case, insert_user

CUTOFF = BEFORE.isoformat()  # 2001-01-01T08:00:00+07:00


def _never_connect(monkeypatch) -> None:
    def refuse(*args, **kwargs):
        raise AssertionError("the command touched the database")

    monkeypatch.setattr(infra_db, "connect", refuse)


# ── no database: the arguments ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "before",
    [
        "2026-10-30T20:15:00",
        "2026-10-30",
        "2026-10-30 20:15:00",
        "yesterday",
        "",
        "2026-13-45T00:00:00+07:00",
    ],
)
def test_a_before_without_an_offset_or_not_a_date_is_refused_before_any_connection(
    monkeypatch, capsys, before
):
    _never_connect(monkeypatch)
    with pytest.raises(SystemExit) as caught:
        archive.main(["--before", before, "--reason", REASON])
    assert caught.value.code == 2
    err = capsys.readouterr().err
    assert "--before" in err


def test_the_refusal_names_the_missing_offset(monkeypatch, capsys):
    _never_connect(monkeypatch)
    with pytest.raises(SystemExit):
        archive.main(["--before", "2026-10-30T20:15:00", "--reason", REASON])
    assert "offset" in capsys.readouterr().err


@pytest.mark.parametrize("argv", [["--reason", REASON], ["--before", CUTOFF]])
def test_both_arguments_are_required(monkeypatch, argv):
    _never_connect(monkeypatch)
    with pytest.raises(SystemExit) as caught:
        archive.main(argv)
    assert caught.value.code == 2


@pytest.mark.parametrize("reason", ["", "   ", "x" * 501])
def test_a_reason_must_be_one_to_five_hundred_characters(monkeypatch, reason):
    _never_connect(monkeypatch)
    with pytest.raises(SystemExit) as caught:
        archive.main(["--before", CUTOFF, "--reason", reason])
    assert caught.value.code == 2


@pytest.mark.parametrize("offset", ["Z", "+00:00", "+07:00", "-05:30"])
def test_any_utc_offset_is_taken(offset):
    parsed = archive.parse_before(f"2026-10-30T20:15:00{offset}")
    assert parsed.utcoffset() is not None


def test_with_no_database_url_it_stops_and_names_the_key_only(monkeypatch, capsys, tmp_path):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    code = archive.main(
        ["--before", CUTOFF, "--reason", REASON, "--env-file", str(tmp_path / "none.env")]
    )
    assert code == 2
    assert "DATABASE_URL" in capsys.readouterr().err


# ── a scratch database: dry run and apply ───────────────────────────────────────────────────


def _seed(dsn) -> None:
    with psycopg.connect(dsn) as conn:
        tier2 = insert_user(conn, "tier2")
        _put_alert(conn, "cli-received", status="received")
        _put_alert(conn, "cli-queued", status="queued_tier1")
        _put_alert(
            conn, "cli-queued-2", status="queued_tier1", received_at=EARLIER - timedelta(days=4)
        )
        head = _put_alert(conn, "cli-case-head", status="escalated_tier2")
        _put_case(conn, tier2, [head])
        _put_alert(conn, "cli-closed", status="closed_fp")
        _put_alert(conn, "cli-after", received_at=BEFORE + timedelta(hours=1))
        conn.commit()


def _state(dsn) -> dict:
    with psycopg.connect(dsn) as conn:
        return {
            "statuses": dict(
                conn.execute("SELECT alert_id, status FROM alerts ORDER BY 1").fetchall()
            ),
            "cases": conn.execute("SELECT status FROM cases ORDER BY 1").fetchall(),
            "events": conn.execute(
                "SELECT count(*) FROM audit_events WHERE event_type IN ('alert.archived', 'case.archived')"
            ).fetchone()[0],
        }


def _count_lines(text: str) -> list[str]:
    """The lines a dry run and an apply must print alike."""
    return [
        line
        for line in text.splitlines()
        if line.startswith(("alerts:", "cases:", "oldest", "newest"))
    ]


def _run(monkeypatch, dsn, tmp_path, *extra: str) -> int:
    monkeypatch.setenv("DATABASE_URL", str(dsn))
    return archive.main(
        ["--before", CUTOFF, "--reason", REASON, "--env-file", str(tmp_path / "none.env"), *extra]
    )


@pytest.mark.db
def test_a_dry_run_prints_the_counts_and_changes_nothing(monkeypatch, capsys, tmp_path):
    with scratch_database("archivecli") as dsn:
        _seed(dsn)
        before = _state(dsn)
        assert _run(monkeypatch, dsn, tmp_path) == 0
        out = capsys.readouterr().out
        assert _state(dsn) == before  # rolled back: no status moved, no event written
    assert "DRY RUN" in out and "APPLIED" not in out
    assert "alerts: 4" in out and "cases: 1" in out
    assert "received=1" in out and "queued_tier1=2" in out and "escalated_tier2=1" in out
    assert "tier1_active=0" in out and "enriching=0" in out
    assert CUTOFF in out
    assert "--apply" in out  # and says how to do it for real


@pytest.mark.db
def test_apply_commits_and_prints_the_same_counts(monkeypatch, capsys, tmp_path):
    with scratch_database("archivecli") as dsn:
        _seed(dsn)
        assert _run(monkeypatch, dsn, tmp_path) == 0
        dry = capsys.readouterr().out
        assert _run(monkeypatch, dsn, tmp_path, "--apply") == 0
        applied = capsys.readouterr().out
        state = _state(dsn)
    assert "APPLIED" in applied and "DRY RUN" not in applied
    assert _count_lines(applied) == _count_lines(dry) and _count_lines(dry)
    assert state["statuses"]["cli-queued"] == "archived"
    assert state["statuses"]["cli-closed"] == "closed_fp"
    assert state["statuses"]["cli-after"] == "queued_tier1"
    assert state["cases"] == [("archived",)]
    assert state["events"] == 5


@pytest.mark.db
def test_applying_twice_archives_nothing_the_second_time(monkeypatch, capsys, tmp_path):
    with scratch_database("archivecli") as dsn:
        _seed(dsn)
        assert _run(monkeypatch, dsn, tmp_path, "--apply") == 0
        capsys.readouterr()
        state = _state(dsn)
        assert _run(monkeypatch, dsn, tmp_path, "--apply") == 0
        out = capsys.readouterr().out
        assert _state(dsn) == state
    assert "alerts: 0" in out and "cases: 0" in out


@pytest.mark.db
def test_the_command_runs_as_a_module_and_never_prints_the_dsn(tmp_path):
    with scratch_database("archivecli") as dsn:
        _seed(dsn)
        run = subprocess.run(
            [
                sys.executable,
                "-m",
                "app.domain.archive",
                "--before",
                CUTOFF,
                "--reason",
                REASON,
                "--env-file",
                str(tmp_path / "none.env"),
            ],
            cwd=conftest.REPO_ROOT,
            env={
                **os.environ,
                "DATABASE_URL": str(dsn),
                "PYTHONPATH": str(conftest.REPO_ROOT / "backend"),
            },
            capture_output=True,
            text=True,
            check=False,
        )
        assert run.returncode == 0, run.stderr
        shown = run.stdout + run.stderr
        assert "DRY RUN" in run.stdout
        assert str(dsn) not in shown
        assert "postgresql://" not in shown and "127.0.0.1" not in shown


@pytest.mark.db
def test_a_database_that_cannot_be_reached_is_reported_without_the_dsn(
    monkeypatch, capsys, tmp_path
):
    with scratch_database("archivecli") as dsn:
        pass  # the scratch database is dropped on leaving the block: this DSN now names nothing
    unreachable = str(dsn)
    monkeypatch.setenv("DATABASE_URL", unreachable)
    code = archive.main(
        ["--before", CUTOFF, "--reason", REASON, "--env-file", str(tmp_path / "none.env")]
    )
    shown = capsys.readouterr()
    assert code == 1
    assert unreachable not in shown.out + shown.err
    assert "postgresql://" not in shown.out + shown.err


# ── fix round 1, ruling 3: a --before later than the database's clock ───────────────────────


def _writes(dsn) -> dict:
    """Everything a refused run must not have touched: the archive's own state, and the whole audit
    log and job queue (no event or job of any kind)."""
    with psycopg.connect(dsn) as conn:
        return {
            **_state(dsn),
            "audit_events": conn.execute("SELECT count(*) FROM audit_events").fetchone()[0],
            "jobs": conn.execute("SELECT count(*) FROM jobs").fetchone()[0],
        }


def _one_line(text: str) -> str:
    lines = text.strip().splitlines()
    assert len(lines) == 1, lines
    return lines[0]


@pytest.mark.db
@pytest.mark.parametrize("extra", [[], ["--apply"]], ids=["dry-run", "apply"])
def test_a_before_later_than_the_database_clock_is_refused_and_writes_nothing(
    monkeypatch, capsys, tmp_path, extra
):
    """Review of INT-T03, Nit 3: `--before 2026-11-30` run on 30/10 with `--apply` would archive the
    live queue that arrived after the Owner's cutoff too, and only the backup brings it back."""
    ahead = (datetime.now(UTC) + timedelta(days=31)).astimezone(timezone(timedelta(hours=7)))
    with scratch_database("archivecli") as dsn:
        _seed(dsn)
        before = _writes(dsn)
        monkeypatch.setenv("DATABASE_URL", str(dsn))
        code = archive.main(
            [
                "--before",
                ahead.isoformat(),
                "--reason",
                REASON,
                "--env-file",
                str(tmp_path / "none.env"),
                *extra,
            ]
        )
        shown = capsys.readouterr()
        assert _writes(dsn) == before
    assert code == 2
    assert shown.out == ""  # no counts: nothing was run
    line = _one_line(shown.err)
    assert "later than the database" in line and ahead.isoformat() in line
    assert "nothing was changed" in line
    assert str(dsn) not in shown.err and "postgresql://" not in shown.err


@pytest.mark.db
def test_a_before_the_database_clock_has_already_passed_is_taken(monkeypatch, capsys, tmp_path):
    """The guard refuses only a cutoff in the future: one the clock already read is a cutoff."""
    with scratch_database("archivecli") as dsn:
        _seed(dsn)
        with psycopg.connect(dsn) as conn:
            clock = conn.execute("SELECT now()").fetchone()[0]
        monkeypatch.setenv("DATABASE_URL", str(dsn))
        code = archive.main(
            [
                "--before",
                clock.isoformat(),
                "--reason",
                REASON,
                "--env-file",
                str(tmp_path / "none.env"),
            ]
        )
    out = capsys.readouterr().out
    assert code == 0 and "DRY RUN" in out
    assert (
        "alerts: 5" in out and "cases: 1" in out
    )  # every open row of the seed is older than the clock


# ── fix round 1, ruling 4: psycopg.Error on connect and on rollback ─────────────────────────

SECRET = "s3cr3t-dsn-fragment"
GENERIC_CONNECT_LINE = "archive: cannot connect to the database named by DATABASE_URL"


def _no_env(tmp_path) -> list[str]:
    return ["--env-file", str(tmp_path / "none.env")]


def test_a_malformed_dsn_is_one_generic_line_without_the_dsn(monkeypatch, capsys, tmp_path):
    """Review of INT-T03, Nit 4: a DSN libpq cannot parse raises `ProgrammingError`, not
    `OperationalError`, and its text quotes the DSN, password included."""
    monkeypatch.setenv("DATABASE_URL", f"postgresql://archive:{SECRET}@[::1/db")
    code = archive.main(["--before", CUTOFF, "--reason", REASON, *_no_env(tmp_path)])
    shown = capsys.readouterr()
    assert code == 1
    assert shown.out == ""
    assert _one_line(shown.err) == GENERIC_CONNECT_LINE


def test_a_malformed_dsn_as_a_module_is_exit_1_with_no_traceback(tmp_path):
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "app.domain.archive",
            "--before",
            CUTOFF,
            "--reason",
            REASON,
            *_no_env(tmp_path),
        ],
        cwd=conftest.REPO_ROOT,
        env={
            **os.environ,
            "DATABASE_URL": f"postgresql://archive:{SECRET}@[::1/db",
            "PYTHONPATH": str(conftest.REPO_ROOT / "backend"),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 1
    assert run.stdout == ""
    assert _one_line(run.stderr) == GENERIC_CONNECT_LINE


@pytest.mark.parametrize(
    "error",
    [
        psycopg.OperationalError,
        psycopg.ProgrammingError,
        psycopg.InterfaceError,
        psycopg.errors.InvalidAuthorizationSpecification,
    ],
)
def test_any_psycopg_error_on_connect_is_the_generic_line(monkeypatch, capsys, tmp_path, error):
    def fail(*args, **kwargs):
        raise error(f"connection to server at 127.0.0.1 failed for user archive, password {SECRET}")

    monkeypatch.setenv("DATABASE_URL", "postgresql://archive@127.0.0.1/db")
    monkeypatch.setattr(infra_db, "connect", fail)
    code = archive.main(["--before", CUTOFF, "--reason", REASON, *_no_env(tmp_path)])
    shown = capsys.readouterr()
    assert code == 1
    assert _one_line(shown.err) == GENERIC_CONNECT_LINE
    assert shown.out == ""


class _Row:
    def __init__(self, value):
        self.value = value

    def fetchone(self):
        return (self.value,)


class _LostConnection:
    """A connection whose server went away: it answers `SELECT now()`, and its `rollback` raises text
    that quotes the host, the user and a password."""

    def __init__(self, error):
        self.error = error
        self.closed = False

    def execute(self, *args, **kwargs):
        return _Row(datetime.now(UTC))

    def commit(self):
        raise AssertionError("a rollback test never commits")

    def rollback(self):
        raise self.error(f"connection to server at 127.0.0.1 lost, user archive, password {SECRET}")

    def close(self):
        self.closed = True


def _empty_counts() -> transitions.ArchiveCounts:
    return transitions.ArchiveCounts(
        by_status=dict.fromkeys(
            ("received", "enriching", "queued_tier1", "tier1_active", "escalated_tier2"), 0
        ),
        cases=0,
        oldest_received_at=None,
        newest_received_at=None,
    )


def _deadlock(*args, **kwargs):
    raise psycopg.errors.DeadlockDetected(f"deadlock detected, process holds {SECRET}")


@pytest.mark.parametrize("error", [psycopg.OperationalError, psycopg.InterfaceError])
@pytest.mark.parametrize(
    "archive_before",
    [lambda *a, **k: _empty_counts(), _deadlock],
    ids=["dry-run's own rollback", "rollback after a query error"],
)
def test_a_rollback_that_fails_is_one_generic_line_and_the_connection_is_closed(
    monkeypatch, capsys, tmp_path, error, archive_before
):
    """Review of INT-T03, Nit 4: `conn.rollback()` can itself raise on a lost connection."""
    lost = _LostConnection(error)
    monkeypatch.setenv("DATABASE_URL", "postgresql://archive@127.0.0.1/db")
    monkeypatch.setattr(infra_db, "connect", lambda *args, **kwargs: lost)
    monkeypatch.setattr(transitions, "archive_before", archive_before)
    code = archive.main(["--before", CUTOFF, "--reason", REASON, *_no_env(tmp_path)])
    shown = capsys.readouterr()
    assert code == 1
    assert shown.out == ""
    line = _one_line(shown.err)
    assert "rollback" in line and "closed" in line
    for fragment in (SECRET, "127.0.0.1", "archive@", "deadlock"):
        assert fragment not in shown.err
    assert lost.closed
