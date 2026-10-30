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
from datetime import timedelta

import psycopg
import pytest
from app.domain import archive
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
