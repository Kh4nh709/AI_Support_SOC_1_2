"""Tests for eval/lab_tag.py -- the source='lab' time-window retag (DEC-085, option D).

Fixture alerts are built the way `test_dedup_verify.py` builds JSONL rows: a
copy of `archive_line_5503.json`'s `event.original` with `id`/`timestamp`/
`agent.name` edited, run through the real parser
(`app.ingest.wazuh_parser.parse_wazuh_alert`) to get a real `Alert`. Inserting
it is a **direct INSERT**, the `test_transitions.py` pattern
(`_insert_alert`), not `app.domain.transitions.open_alert` -- `open_alert`
writes an `audit_events` row on every call, and `audit_events` is append-only
at the database level (migration 017's trigger; no test can delete from it).
`TEST_DATABASE_URL` is a *session*-scoped database shared by every test file
`make test-db` runs, so a committed `audit_events` row here would outlive
this file and break `test_schema_v3_017.py`'s own row-count assertions on a
completely unrelated table -- confirmed by reproducing it once with
`open_alert`, then fixed by switching to the direct INSERT below.

`lab_tag.py` is loaded by file path (it lives in `eval/`, a composition root
outside `backend/` and not on `sys.path`), the same way `test_dedup_verify.py`
loads `eval/dedup_verify.py`.

Each database-backed test picks its own day in September 2026 for its window
so tests never share rows regardless of execution order -- the provenance
file is already isolated per test via `tmp_path`.
"""

from __future__ import annotations

import copy
import csv
import importlib.util
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from app.domain.alert import Alert
from app.ingest.wazuh_parser import parse_wazuh_alert
from psycopg.types.json import Jsonb

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "eval" / "lab_tag.py"
RUNBOOK_PATH = REPO_ROOT / "docs" / "lab-scenarios.md"
LOCAL_RULES_PATH = REPO_ROOT / "conf" / "local_rules.xml"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

_spec = importlib.util.spec_from_file_location("lab_tag", SCRIPT_PATH)
lab_tag = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = lab_tag
_spec.loader.exec_module(lab_tag)


# --- fixture construction ---------------------------------------------------

_EVENT_ORIGINAL = json.loads(
    json.loads((FIXTURES / "archive_line_5503.json").read_text(encoding="utf-8"))["event"][
        "original"
    ]
)


def _doc(alert_id: str, timestamp: str, agent_name: str = "user1-IA1803") -> dict:
    doc = copy.deepcopy(_EVENT_ORIGINAL)
    doc["id"] = alert_id
    doc["timestamp"] = timestamp
    doc["agent"] = dict(doc["agent"], name=agent_name)
    return doc


def _parsed_alert(alert_id: str, timestamp: str, agent_name: str = "user1-IA1803") -> Alert:
    result = parse_wazuh_alert(_doc(alert_id, timestamp, agent_name))
    assert result.alert is not None, result.rejection
    return result.alert


_ALERT_COLUMNS = (
    "alert_id",
    "manager_id",
    "rule_id",
    "description",
    "agent_name",
    "agent_id",
    "agent_ip",
    "origin_host",
    "alert_time",
    "event_time",
    "srcip",
    "dstip",
    "src_port",
    "dst_port",
    "alert_user",
    "decoder",
    "mitre_ids",
    "rule_groups",
    "rule_level",
    "severity",
    "category",
    "categories",
    "resolved_by",
    "mapping_version",
    "srcip_is_private",
    "dstip_is_private",
    "raw_log",
    "raw_log_truncated",
    "event_bucket_hash",
    "raw_payload",
    "source",
    "status",
    "duplicate_of",
    "closed_at",
    "sealed_at",
)


def _insert_alert_row(
    conn,
    alert: Alert,
    *,
    source: str = "wazuh",
    status: str = "received",
    duplicate_of: str | None = None,
) -> str:
    # A duplicate row's CHECK constraint (ck_alerts_ban_sao_phai_seal_va_tro_goc)
    # requires closed_at/sealed_at set -- open_alert(kind="duplicate") sets both
    # to now(); any non-null instant satisfies the constraint for a fixture row.
    sealed = datetime.now(UTC) if duplicate_of is not None else None
    values = (
        alert.alert_id,
        alert.manager_id,
        alert.rule_id,
        alert.description,
        alert.agent_name,
        alert.agent_id,
        alert.agent_ip,
        alert.origin_host,
        alert.alert_time,
        alert.event_time,
        alert.srcip,
        alert.dstip,
        alert.src_port,
        alert.dst_port,
        alert.alert_user,
        alert.decoder,
        list(alert.mitre_ids),
        list(alert.rule_groups),
        alert.rule_level,
        alert.severity,
        alert.category,
        list(alert.categories),
        alert.resolved_by,
        alert.mapping_version,
        alert.srcip_is_private,
        alert.dstip_is_private,
        alert.raw_log,
        alert.raw_log_truncated,
        alert.event_bucket_hash,
        Jsonb(dict(alert.raw_payload)),
        source,
        status,
        duplicate_of,
        sealed,
        sealed,
    )
    placeholders = ", ".join(["%s"] * len(_ALERT_COLUMNS))
    conn.execute(
        f"INSERT INTO alerts ({', '.join(_ALERT_COLUMNS)}) VALUES ({placeholders})",
        values,
    )
    conn.commit()
    return alert.alert_id


def _insert_received(conn, alert_id: str, timestamp: str, agent_name: str = "user1-IA1803") -> str:
    return _insert_alert_row(conn, _parsed_alert(alert_id, timestamp, agent_name))


def _insert_duplicate(
    conn, alert_id: str, timestamp: str, *, duplicate_of: str, agent_name: str = "user1-IA1803"
) -> str:
    return _insert_alert_row(
        conn,
        _parsed_alert(alert_id, timestamp, agent_name),
        status="duplicate",
        duplicate_of=duplicate_of,
    )


def _force_source(conn, alert_id: str, source: str) -> None:
    conn.execute("UPDATE alerts SET source = %s WHERE alert_id = %s", (source, alert_id))
    conn.commit()


def _force_synthetic(conn, alert_id: str) -> None:
    conn.execute("UPDATE alerts SET is_synthetic = true WHERE alert_id = %s", (alert_id,))
    conn.commit()


def _get_row(conn, alert_id: str, *columns: str) -> tuple:
    cols = ", ".join(columns)
    return conn.execute(f"SELECT {cols} FROM alerts WHERE alert_id = %s", (alert_id,)).fetchone()


def _read_windows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


@pytest.fixture(autouse=True)
def _cleanup_lab_tag_alerts(request):
    """`TEST_DATABASE_URL` is one database shared by every test file in a
    `make test-db` run; other files' tests (`test_schema_v3_016.py`'s
    unfiltered `SELECT source FROM alerts`, among others) assume the table
    holds only what they themselves inserted. `lab_tag.main()` commits (a
    second, real connection has to see the row), so every fixture alert_id in
    this file is prefixed `lt-` and swept up here once the test is done.

    `db`'s value is fetched *before* `yield`, not after: that is what makes
    `db`'s own finalizer (rollback + close) run after this one, instead of
    before it -- a fixture pulled in only at teardown time is not registered
    as this fixture's dependency and pytest may already have torn it down.
    """
    conn = request.getfixturevalue("db") if "db" in request.fixturenames else None
    yield
    if conn is not None:
        conn.execute("DELETE FROM alerts WHERE alert_id LIKE 'lt-%'")
        conn.commit()


# --- database-backed tests ---------------------------------------------------


@pytest.mark.db
def test_retags_only_wazuh_rows_of_the_agent_inside_the_window(db, _test_database, tmp_path):
    since, until = "2026-09-22T14:00:00+07:00", "2026-09-22T14:35:00+07:00"
    head = _insert_received(db, "lt-01-head", "2026-09-22T14:05:00.000+0700")
    dup = _insert_duplicate(db, "lt-01-dup", "2026-09-22T14:10:00.000+0700", duplicate_of=head)
    already_lab = _insert_received(db, "lt-01-lab", "2026-09-22T14:15:00.000+0700")
    _force_source(db, already_lab, "lab")
    outside = _insert_received(db, "lt-01-outside", "2026-09-22T15:00:00.000+0700")
    synthetic = _insert_received(db, "lt-01-synth", "2026-09-22T14:20:00.000+0700")
    _force_synthetic(db, synthetic)
    hr = _insert_received(db, "lt-01-hr", "2026-09-22T14:12:00.000+0700", agent_name="HR-computer")

    windows_file = tmp_path / "lab_windows.csv"
    rc = lab_tag.main(
        [
            "--agent",
            "user1-IA1803",
            "--since",
            since,
            "--until",
            until,
            "--scenario",
            "T01",
            "--category",
            "ransomware",
            "--kind",
            "attack",
            "--dsn",
            _test_database,
            "--windows-file",
            str(windows_file),
        ]
    )
    assert rc == lab_tag.EXIT_OK

    assert _get_row(db, head, "source") == ("lab",)
    assert _get_row(db, dup, "source") == ("lab",)
    assert _get_row(db, already_lab, "source") == ("lab",)  # unchanged, already lab
    assert _get_row(db, outside, "source") == ("wazuh",)
    assert _get_row(db, synthetic, "source") == ("wazuh",)
    assert _get_row(db, hr, "source") == ("wazuh",)


@pytest.mark.db
def test_status_column_is_untouched(db, _test_database, tmp_path):
    since, until = "2026-09-23T14:00:00+07:00", "2026-09-23T14:35:00+07:00"
    head = _insert_received(db, "lt-02-head", "2026-09-23T14:05:00.000+0700")
    dup = _insert_duplicate(db, "lt-02-dup", "2026-09-23T14:10:00.000+0700", duplicate_of=head)
    before = {alert_id: _get_row(db, alert_id, "status")[0] for alert_id in (head, dup)}

    rc = lab_tag.main(
        [
            "--agent",
            "user1-IA1803",
            "--since",
            since,
            "--until",
            until,
            "--scenario",
            "T02",
            "--category",
            "ransomware",
            "--kind",
            "attack",
            "--dsn",
            _test_database,
            "--windows-file",
            str(tmp_path / "lab_windows.csv"),
        ]
    )
    assert rc == lab_tag.EXIT_OK
    for alert_id in (head, dup):
        assert _get_row(db, alert_id, "status")[0] == before[alert_id]
        assert _get_row(db, alert_id, "source")[0] == "lab"


@pytest.mark.db
def test_appends_provenance_row_with_count(db, _test_database, tmp_path):
    since, until = "2026-09-24T14:00:00+07:00", "2026-09-24T14:35:00+07:00"
    head = _insert_received(db, "lt-03-head", "2026-09-24T14:05:00.000+0700")
    _insert_duplicate(db, "lt-03-dup", "2026-09-24T14:10:00.000+0700", duplicate_of=head)

    windows_file = tmp_path / "lab_windows.csv"
    rc = lab_tag.main(
        [
            "--agent",
            "user1-IA1803",
            "--since",
            since,
            "--until",
            until,
            "--scenario",
            "T03",
            "--category",
            "ransomware",
            "--kind",
            "attack",
            "--dsn",
            _test_database,
            "--windows-file",
            str(windows_file),
        ]
    )
    assert rc == lab_tag.EXIT_OK

    rows = _read_windows(windows_file)
    assert len(rows) == 1
    row = rows[0]
    assert row["scenario_id"] == "T03"
    assert row["category_expected"] == "ransomware"
    assert row["kind"] == "attack"
    assert row["agent_name"] == "user1-IA1803"
    assert row["since"] == since
    assert row["until"] == until
    assert row["retagged_rows"] == "2"
    assert row["tagged_at"]  # non-empty, ISO-parseable
    datetime.fromisoformat(row["tagged_at"])


@pytest.mark.db
def test_same_scenario_id_is_refused_and_appends_nothing(db, _test_database, tmp_path):
    since, until = "2026-09-25T14:00:00+07:00", "2026-09-25T14:35:00+07:00"
    _insert_received(db, "lt-04-head", "2026-09-25T14:05:00.000+0700")
    windows_file = tmp_path / "lab_windows.csv"
    argv = [
        "--agent",
        "user1-IA1803",
        "--since",
        since,
        "--until",
        until,
        "--scenario",
        "T04",
        "--category",
        "ransomware",
        "--kind",
        "attack",
        "--dsn",
        _test_database,
        "--windows-file",
        str(windows_file),
    ]
    assert lab_tag.main(argv) == lab_tag.EXIT_OK
    assert len(_read_windows(windows_file)) == 1

    rc = lab_tag.main(argv)  # same --scenario T04 again
    assert rc == lab_tag.EXIT_REFUSED
    assert len(_read_windows(windows_file)) == 1  # nothing appended


@pytest.mark.db
def test_overlap_refused_unless_allowed(db, _test_database, tmp_path):
    windows_file = tmp_path / "lab_windows.csv"
    base_argv = [
        "--agent",
        "user1-IA1803",
        "--dsn",
        _test_database,
        "--windows-file",
        str(windows_file),
    ]
    rc = lab_tag.main(
        base_argv
        + [
            "--since",
            "2026-09-26T14:00:00+07:00",
            "--until",
            "2026-09-26T14:30:00+07:00",
            "--scenario",
            "T05A",
            "--category",
            "ransomware",
            "--kind",
            "attack",
        ]
    )
    assert rc == lab_tag.EXIT_OK

    overlapping = base_argv + [
        "--since",
        "2026-09-26T14:10:00+07:00",
        "--until",
        "2026-09-26T14:40:00+07:00",
        "--scenario",
        "T05B",
        "--category",
        "ransomware",
        "--kind",
        "attack",
    ]
    rc = lab_tag.main(overlapping)
    assert rc == lab_tag.EXIT_REFUSED
    assert len(_read_windows(windows_file)) == 1

    rc = lab_tag.main(overlapping + ["--allow-overlap"])
    assert rc == lab_tag.EXIT_OK
    assert len(_read_windows(windows_file)) == 2


@pytest.mark.db
def test_dry_run_changes_nothing(db, _test_database, tmp_path, capsys):
    since, until = "2026-09-27T14:00:00+07:00", "2026-09-27T14:35:00+07:00"
    head = _insert_received(db, "lt-06-head", "2026-09-27T14:05:00.000+0700")
    dup = _insert_duplicate(db, "lt-06-dup", "2026-09-27T14:10:00.000+0700", duplicate_of=head)

    windows_file = tmp_path / "lab_windows.csv"
    rc = lab_tag.main(
        [
            "--agent",
            "user1-IA1803",
            "--since",
            since,
            "--until",
            until,
            "--scenario",
            "T06",
            "--category",
            "ransomware",
            "--kind",
            "attack",
            "--dsn",
            _test_database,
            "--windows-file",
            str(windows_file),
            "--dry-run",
        ]
    )
    assert rc == lab_tag.EXIT_OK
    out = capsys.readouterr().out
    assert "2" in out

    assert _get_row(db, head, "source")[0] == "wazuh"
    assert _get_row(db, dup, "source")[0] == "wazuh"
    assert not windows_file.exists()


def test_naive_timestamp_refused(tmp_path):
    rc = lab_tag.main(
        [
            "--agent",
            "user1-IA1803",
            "--since",
            "2026-09-22T14:00:00",
            "--until",
            "2026-09-22T14:35:00",
            "--scenario",
            "T07",
            "--category",
            "ransomware",
            "--kind",
            "attack",
            "--dsn",
            "postgresql:///does_not_exist",
            "--windows-file",
            str(tmp_path / "lab_windows.csv"),
        ]
    )
    assert rc == lab_tag.EXIT_REFUSED


@pytest.mark.db
def test_category_benign_only_with_kind_benign(db, _test_database, tmp_path):
    windows_file = tmp_path / "lab_windows.csv"
    rc = lab_tag.main(
        [
            "--agent",
            "user1-IA1803",
            "--since",
            "2026-09-28T14:00:00+07:00",
            "--until",
            "2026-09-28T14:35:00+07:00",
            "--scenario",
            "T08A",
            "--category",
            "benign",
            "--kind",
            "attack",
            "--dsn",
            _test_database,
            "--windows-file",
            str(windows_file),
        ]
    )
    assert rc == lab_tag.EXIT_REFUSED
    assert not windows_file.exists()

    rc = lab_tag.main(
        [
            "--agent",
            "user1-IA1803",
            "--since",
            "2026-09-28T14:00:00+07:00",
            "--until",
            "2026-09-28T14:35:00+07:00",
            "--scenario",
            "T08B",
            "--category",
            "benign",
            "--kind",
            "benign",
            "--dsn",
            _test_database,
            "--windows-file",
            str(windows_file),
        ]
    )
    assert rc == lab_tag.EXIT_OK


@pytest.mark.db
def test_zero_hit_window_is_recorded_not_an_error(db, _test_database, tmp_path):
    windows_file = tmp_path / "lab_windows.csv"
    rc = lab_tag.main(
        [
            "--agent",
            "user1-IA1803",
            "--since",
            "2026-09-29T14:00:00+07:00",
            "--until",
            "2026-09-29T14:35:00+07:00",
            "--scenario",
            "T09",
            "--category",
            "ransomware",
            "--kind",
            "attack",
            "--dsn",
            _test_database,
            "--windows-file",
            str(windows_file),
        ]
    )
    assert rc == lab_tag.EXIT_OK
    rows = _read_windows(windows_file)
    assert len(rows) == 1
    assert rows[0]["retagged_rows"] == "0"


# --- pure tests (no database) ------------------------------------------------

CATEGORY_ORDER = (
    "ssh_brute_force",
    "suspicious_login",
    "privilege_escalation",
    "recon",
    "malware",
    "ransomware",
    "data_exfiltration",
    "c2_beacon",
)


def _category_blocks(text: str) -> tuple[list[str], dict[str, str]]:
    """`(order, blocks)`: `order` is every `### `-titled section in document
    order; `blocks[title]` is the text strictly between that heading and the
    next heading of level <= 3 (or end of file)."""
    heading_re = re.compile(r"^(#{2,3}) (.+)$", re.MULTILINE)
    matches = list(heading_re.finditer(text))
    order: list[str] = []
    blocks: dict[str, str] = {}
    for i, match in enumerate(matches):
        if len(match.group(1)) != 3:
            continue
        title = match.group(2).strip()
        end = len(text)
        for later in matches[i + 1 :]:
            if len(later.group(1)) <= 3:
                end = later.start()
                break
        order.append(title)
        blocks[title] = text[match.end() : end]
    return order, blocks


def test_runbook_structure():
    text = RUNBOOK_PATH.read_text(encoding="utf-8")
    order, blocks = _category_blocks(text)

    assert order == list(CATEGORY_ORDER)
    assert "web_attack" not in order
    assert "policy_violation" not in order
    assert "never synthesised" in text

    ids = set(re.findall(r"1003[0-9]{2}", text))
    assert ids and ids <= {"100301", "100302", "100303"}

    assert text.count("lab_tag.py") >= 9

    negative_check_count = 0
    for name in CATEGORY_ORDER:
        block = blocks[name]
        assert "#### Attack" in block, name
        assert "#### Expected rules" in block, name
        assert "#### Benign twin" in block, name
        if "#### Negative check" in block:
            negative_check_count += 1
    assert negative_check_count == 3


def test_runbook_names_only_existing_local_rules():
    xml_text = LOCAL_RULES_PATH.read_text(encoding="utf-8")
    defined = set(re.findall(r'rule id="(1003[0-9]{2})"', xml_text))

    text = RUNBOOK_PATH.read_text(encoding="utf-8")
    referenced = set(re.findall(r"1003[0-9]{2}", text))

    assert referenced  # sanity: the runbook does name the local rules
    assert referenced <= defined
