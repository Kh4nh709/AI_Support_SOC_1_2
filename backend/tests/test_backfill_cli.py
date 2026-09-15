"""P2-T13: the backfill CLI — `backfill --since` (indexer) and `replay
--archive-file` (manager archive). No network, no root (design note 4):
`backfill` is exercised against `httpx.MockTransport` exactly as P2-T11's
tests exercise `pull_once`; `replay` is exercised on `tmp_path` files.

`TEST_DATABASE_URL=postgresql:///soc_p2t13_test` on every db-marked run
(design note 5, planning decision 11).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import httpx
import psycopg
import pytest
import yaml
from app.infra.config import Config
from app.infra.puller import (
    OWNER_PROCEDURE,
    PullResult,
    ReplayResult,
    _backfill_loop,
    _is_forbidden_archive_path,
    _known_hostnames,
    _pull_start_ms,
    _replay_sort_key,
    _unknown_agents,
    main,
    replay_lines,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
FIXTURE_5503 = json.loads((FIXTURES / "archive_line_5503.json").read_text(encoding="utf-8"))
ORIGINAL_LINE = FIXTURE_5503["event"]["original"]


def _base_cfg(**overrides) -> Config:
    fields = {
        "INDEXER_URL": "https://mock-indexer",
        "INDEXER_INDEX": "wazuh-alerts-*",
        "INDEXER_USER": "soc_ro",
        "INDEXER_PASSWORD": "s3cr3t-do-not-print",
        "INDEXER_CA": "/dev/null",
        "PULL_PAGE": 2,
        "PULL_START": "2026-08-01",
        "HEARTBEAT_RULE_ID": "100999",
        "INVENTORY_PATHS": [],
    }
    fields.update(overrides)
    return Config(**fields)


def _mock_client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _paged_handler(pages, requests=None):
    state = {"n": 0}

    def handler(request):
        if requests is not None:
            requests.append(request)
        idx = min(state["n"], len(pages) - 1)
        state["n"] += 1
        status, body_text = pages[idx]
        return httpx.Response(status, text=body_text, headers={"content-type": "application/json"})

    return handler


def _search_page(hits: list[dict]) -> str:
    return json.dumps(
        {
            "took": 1,
            "timed_out": False,
            "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
            "hits": {
                "total": {"value": len(hits), "relation": "eq"},
                "max_score": None,
                "hits": hits,
            },
        }
    )


def _hit(alert_id: str, sort: int, rule_id: str = "5503") -> dict:
    return {
        "_index": "wazuh-alerts-4.x-2026.09.02",
        "_id": alert_id,
        "_source": {
            "id": alert_id,
            "manager": {"name": "IA1803"},
            "rule": {"id": rule_id},
            "timestamp": "2026-09-02T00:00:00.000+0000",
        },
        "fields": {"timestamp": ["2026-09-02T00:00:00.000Z"]},
        "sort": [sort],
    }


EMPTY_PAGE = _search_page([])

_REPLAY_TEST_DBNAME = "soc_p2t13_replay_test"
_REPLAY_TEST_DSN = f"postgresql:///{_REPLAY_TEST_DBNAME}"
_REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def replay_db():
    """A throwaway database of its own — never `TEST_DATABASE_URL`.

    `intake` is append-only (migration 017's trigger binds even the owner:
    see `test_the_row_trigger_stops_the_owner_deleting` in
    test_schema_v3_017.py), so nothing can ever delete a row this writes. The
    crash/batch tests below commit ~1000 real rows each to prove design note
    4's recovery guarantee — reusing the shared `soc_p2t13_test` database for
    that would permanently dirty it for the rest of a `make test-db` session
    and break every other suite's exact intake row-count assertions (measured:
    `test_schema_v3_017.py` goes from `count == 1` to `count == 2008`). This
    database is created fresh, migrated, used, and dropped within this module
    alone."""
    admin = psycopg.connect("postgresql:///postgres", autocommit=True)
    try:
        admin.execute(f'DROP DATABASE IF EXISTS "{_REPLAY_TEST_DBNAME}"')
        admin.execute(f'CREATE DATABASE "{_REPLAY_TEST_DBNAME}"')
    finally:
        admin.close()

    result = subprocess.run(
        ["bash", "scripts/migrate.sh", _REPLAY_TEST_DSN],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"migrate.sh failed for {_REPLAY_TEST_DSN}:\n{result.stderr}"

    conn = psycopg.connect(_REPLAY_TEST_DSN)
    try:
        yield conn
    finally:
        conn.close()
        admin = psycopg.connect("postgresql:///postgres", autocommit=True)
        try:
            admin.execute(f'DROP DATABASE IF EXISTS "{_REPLAY_TEST_DBNAME}"')
        finally:
            admin.close()


# ---------------------------------------------------------------------------
# _is_forbidden_archive_path (acceptance 3)
# ---------------------------------------------------------------------------


def test_forbidden_prefix_var_ossec():
    assert _is_forbidden_archive_path("/var/ossec/logs/alerts/alerts.json") is True


def test_forbidden_prefix_data_wazuh():
    assert _is_forbidden_archive_path("/data/wazuh/logs/alerts/alerts.json") is True


def test_forbidden_prefix_survives_relative_dotdot_tricks():
    assert _is_forbidden_archive_path("/data/other/../wazuh/logs/alerts/alerts.json") is True


def test_not_forbidden_for_a_sibling_directory():
    """The failing case: a prefix check with no trailing separator would also
    reject /data/wazuh2, which is a different tree entirely."""
    assert _is_forbidden_archive_path("/data/wazuh2/logs/alerts/alerts.json") is False


def test_not_forbidden_for_home_archive(tmp_path):
    target = tmp_path / "alerts.jsonl"
    assert _is_forbidden_archive_path(str(target)) is False


def test_forbidden_check_never_stats_the_path():
    """Acceptance 3's `/var/ossec/...` no longer exists on this host at all —
    the refusal must be by string prefix, not by asking the filesystem."""
    assert Path("/var/ossec").exists() is False
    assert _is_forbidden_archive_path("/var/ossec/logs/alerts/alerts.json") is True


# ---------------------------------------------------------------------------
# CLI-level refusal (acceptance 3) — no DB touched, exit 2, procedure on stderr
# ---------------------------------------------------------------------------


def test_cli_refuses_data_wazuh_path_exit_2_with_procedure(capsys):
    rc = main(
        [
            "replay",
            "--archive-file",
            "/data/wazuh/logs/alerts/alerts.json",
            "--env-file",
            "/dev/null",
        ]
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "sudo sh -c" in err


def test_cli_refuses_var_ossec_path_that_no_longer_exists(capsys):
    rc = main(
        [
            "replay",
            "--archive-file",
            "/var/ossec/logs/alerts/alerts.json",
            "--env-file",
            "/dev/null",
        ]
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "sudo sh -c" in err


def test_cli_refuses_an_unreadable_archive_file(tmp_path, capsys):
    missing = tmp_path / "nope.jsonl"
    rc = main(["replay", "--archive-file", str(missing), "--env-file", "/dev/null"])
    assert rc == 2
    assert "sudo sh -c" in capsys.readouterr().err


def test_cli_help_names_both_subcommands_and_the_flags(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    for token in ("backfill", "replay", "--since", "--archive-file", "sudo sh -c", "ossec-alerts"):
        assert token in out


def test_replay_help_carries_the_owner_procedure(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["replay", "--help"])
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert out.count("ossec-alerts") >= 1
    assert OWNER_PROCEDURE.strip() in out


# ---------------------------------------------------------------------------
# replay — design note 2: both archive shapes ingest
# ---------------------------------------------------------------------------


def _line_with_id(alert_id: str) -> str:
    """A fresh copy of the canonical fixture (both archive shapes are derived
    from it) with `id` overridden — `replay_lines` commits, so every db test
    below needs an id namespace nothing else in this file ever reuses."""
    doc = dict(FIXTURE_5503)
    doc["id"] = alert_id
    return json.dumps(doc, separators=(",", ":"))


@pytest.mark.db
def test_replay_ingests_both_archive_shapes_as_two_rows(replay_db):
    db = replay_db
    first_line = _line_with_id("p2t13-shapes-a")
    second_line = ORIGINAL_LINE.replace("1788340536.1509017", "p2t13-shapes-b")
    data = (first_line + "\n" + second_line).encode("utf-8")
    ids = ["p2t13-shapes-a", "p2t13-shapes-b"]

    result = replay_lines(db, data, batch=500)

    assert result == ReplayResult(lines=2, new=2, duplicates=0, heartbeats=0, bad=0)

    rows = db.execute(
        "SELECT via, sort_key, raw_payload ? '_source', raw_text FROM intake "
        "WHERE source_alert_id = ANY(%s) ORDER BY intake_id",
        (ids,),
    ).fetchall()
    assert len(rows) == 2
    for via, sort_key, has_source_key, _raw_text in rows:
        assert via == "pull"
        assert sort_key == 1788340536255
        assert has_source_key is False

    lines_bytes = data.split(b"\n")
    assert rows[0][3].encode("utf-8") == lines_bytes[0]
    assert rows[1][3].encode("utf-8") == lines_bytes[1]

    jobs_count = db.execute(
        "SELECT count(*) FROM jobs j JOIN intake i ON i.intake_id::text = j.subject_id "
        "WHERE i.source_alert_id = ANY(%s) AND j.job_type = 'pipeline'",
        (ids,),
    ).fetchone()[0]
    assert jobs_count == 2


@pytest.mark.db
def test_g9_byte_identical_with_the_jsonb_control(replay_db):
    """The two-part test (DEC-023): byte-identical raw_text, and the control
    showing jsonb normalises whitespace so it is NOT equal to raw_text."""
    db = replay_db
    data = _line_with_id("p2t13-g9-check").encode("utf-8")
    replay_lines(db, data, batch=500)

    raw_text, equals_payload = db.execute(
        "SELECT raw_text, raw_payload::text = raw_text FROM intake WHERE source_alert_id = %s",
        ("p2t13-g9-check",),
    ).fetchone()
    assert raw_text.encode("utf-8") == data
    assert equals_payload is False


# ---------------------------------------------------------------------------
# replay — bad lines (acceptance-adjacent, design note 1)
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_replay_counts_bad_lines_and_writes_rejected_alerts(replay_db):
    db = replay_db
    good_line = _line_with_id("p2t13-badlines-ok")
    bad_line = "p2t13-badlines-marker not json at all"
    data = b"\n".join([good_line.encode("utf-8"), b"", bad_line.encode("utf-8")])

    result = replay_lines(db, data, batch=500)

    assert result == ReplayResult(lines=2, new=1, duplicates=0, heartbeats=0, bad=1)

    row = db.execute(
        "SELECT reason, raw_payload FROM rejected_alerts WHERE raw_payload ->> 'line' = %s",
        (bad_line,),
    ).fetchone()
    assert row[0] == "not valid json"
    assert row[1] == {"line": bad_line}


@pytest.mark.db
def test_replay_counts_missing_id_as_bad_not_as_a_crash(replay_db):
    """The failing case behind 'or has no id': a version that only checked
    json.loads() success would insert this line as a valid alert with id=None."""
    db = replay_db
    line = json.dumps(
        {"timestamp": "2026-09-02T00:00:00.000+0000", "manager": {"name": "p2t13-noid"}}
    )
    result = replay_lines(db, line.encode("utf-8"), batch=500)
    assert result == ReplayResult(lines=1, new=0, duplicates=0, heartbeats=0, bad=1)
    reason = db.execute(
        "SELECT reason FROM rejected_alerts WHERE raw_payload ->> 'line' = %s", (line,)
    ).fetchone()[0]
    assert reason == "missing id"


# ---------------------------------------------------------------------------
# replay — re-run idempotency (design note 4)
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_replay_rerun_of_the_same_file_finds_only_duplicates(replay_db):
    db = replay_db
    data = _line_with_id("p2t13-rerun-check").encode("utf-8")
    first = replay_lines(db, data, batch=500)
    assert first == ReplayResult(lines=1, new=1, duplicates=0, heartbeats=0, bad=0)

    second = replay_lines(db, data, batch=500)
    assert second == ReplayResult(lines=1, new=0, duplicates=1, heartbeats=0, bad=0)


# ---------------------------------------------------------------------------
# replay — batching and a crash losing at most one batch (design note 4)
# ---------------------------------------------------------------------------


def _synthetic_line(prefix: str, n: int) -> str:
    return _line_with_id(f"{prefix}-{n:07d}")


@pytest.mark.db
def test_replay_commits_every_batch_lines_and_a_crash_loses_at_most_one_batch(
    replay_db, monkeypatch
):
    db = replay_db
    prefix = "p2t13-crash"
    lines = [_synthetic_line(prefix, n) for n in range(1001)]
    data = "\n".join(lines).encode("utf-8")

    calls = {"n": 0}
    import app.infra.puller as puller_module

    real_insert_alert = puller_module._insert_alert

    def flaky_insert_alert(conn, source, raw_text, sort_value):
        calls["n"] += 1
        if calls["n"] == 1001:
            raise RuntimeError("simulated crash on line 1001")
        return real_insert_alert(conn, source, raw_text, sort_value)

    monkeypatch.setattr(puller_module, "_insert_alert", flaky_insert_alert)

    with pytest.raises(RuntimeError, match="simulated crash on line 1001"):
        replay_lines(db, data, batch=500)
    db.rollback()

    surviving = db.execute(
        "SELECT count(*) FROM intake WHERE source_alert_id LIKE %s", (f"{prefix}-%",)
    ).fetchone()[0]
    assert surviving == 1000
    assert calls["n"] == 1001


@pytest.mark.db
def test_replay_commits_are_not_a_single_transaction(replay_db, monkeypatch):
    """The failing case for the batching test above: a version with no
    intermediate commit() at all would lose all 1000 survivors too, and this
    test catches that regression directly."""
    import app.infra.puller as puller_module

    db = replay_db
    prefix = "p2t13-count"

    commits = {"n": 0}
    real_commit = db.commit

    def counting_commit():
        commits["n"] += 1
        real_commit()

    monkeypatch.setattr(db, "commit", counting_commit)
    lines = [_synthetic_line(prefix, n) for n in range(1001)]
    data = "\n".join(lines).encode("utf-8")
    result = puller_module.replay_lines(db, data, batch=500)
    assert result.new == 1001
    assert commits["n"] == 3  # 500, 1000, and the final flush at 1001


# ---------------------------------------------------------------------------
# replay — heartbeats never become jobs (design note 1)
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_replay_heartbeat_line_gets_no_job(replay_db):
    db = replay_db
    doc = dict(FIXTURE_5503)
    doc["id"] = "1788340999.0000001"
    doc["rule"] = dict(doc["rule"])
    doc["rule"]["id"] = "100999"
    line = json.dumps(doc, separators=(",", ":"))

    result = replay_lines(db, line.encode("utf-8"), batch=500)
    assert result == ReplayResult(lines=1, new=0, duplicates=0, heartbeats=1, bad=0)

    outcome, processed = db.execute(
        "SELECT outcome, processed_at IS NOT NULL FROM intake WHERE source_alert_id = %s",
        ("1788340999.0000001",),
    ).fetchone()
    assert (outcome, processed) == ("heartbeat", True)

    intake_id = db.execute(
        "SELECT intake_id FROM intake WHERE source_alert_id = %s", ("1788340999.0000001",)
    ).fetchone()[0]
    jobs = db.execute(
        "SELECT count(*) FROM jobs WHERE subject_id = %s", (str(intake_id),)
    ).fetchone()[0]
    assert jobs == 0


# ---------------------------------------------------------------------------
# _replay_sort_key (DEC-019's one new derivation)
# ---------------------------------------------------------------------------


def test_replay_sort_key_converts_plus_0700_and_matches_the_fixture():
    assert _replay_sort_key("2026-09-02T16:15:36.255+0700") == 1788340536255


def test_replay_sort_key_handles_a_colon_offset_too():
    assert _replay_sort_key("2026-09-02T09:15:36.255+00:00") == 1788340536255


# ---------------------------------------------------------------------------
# design note 3b — unknown agents reported, not filtered
# ---------------------------------------------------------------------------


def _write_inventory(tmp_path: Path, hostnames: list[str]) -> Path:
    path = tmp_path / "inventory.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "assets": [{"hostname": h, "criticality": "medium"} for h in hostnames],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_known_hostnames_reads_the_yaml_assets_list(tmp_path):
    inv = _write_inventory(tmp_path, ["IA1803", "user1-IA1803"])
    cfg = _base_cfg(INVENTORY_PATHS=[str(inv)])
    assert _known_hostnames(cfg) == {"IA1803", "user1-IA1803"}


def test_known_hostnames_empty_when_no_inventory_file_present(tmp_path):
    cfg = _base_cfg(INVENTORY_PATHS=[str(tmp_path / "does-not-exist.yaml")])
    assert _known_hostnames(cfg) == set()


def test_unknown_agents_reports_a_host_absent_from_inventory(tmp_path):
    inv = _write_inventory(tmp_path, ["IA1803"])
    cfg = _base_cfg(INVENTORY_PATHS=[str(inv)])

    known_doc = dict(FIXTURE_5503)  # agent.name == 'user1-IA1803', not in inventory
    line = json.dumps(known_doc, separators=(",", ":"))

    unknown = _unknown_agents(line.encode("utf-8"), cfg)
    assert set(unknown) == {"user1-IA1803"}
    assert unknown["user1-IA1803"].count == 1
    assert unknown["user1-IA1803"].first_date == "2026-09-02"
    assert unknown["user1-IA1803"].last_date == "2026-09-02"


def test_unknown_agents_empty_when_every_host_is_inventoried(tmp_path):
    inv = _write_inventory(tmp_path, ["user1-IA1803"])
    cfg = _base_cfg(INVENTORY_PATHS=[str(inv)])
    line = json.dumps(FIXTURE_5503, separators=(",", ":"))
    assert _unknown_agents(line.encode("utf-8"), cfg) == {}


# ---------------------------------------------------------------------------
# backfill — the page loop from --since, cursor untouched (acceptance 6)
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_backfill_first_request_gte_is_since_at_utc_midnight(db):
    cfg = _base_cfg()
    requests: list = []
    client = _mock_client(_paged_handler([(200, EMPTY_PAGE)], requests=requests))
    try:
        _backfill_loop(db, client, cfg, _pull_start_ms("2026-09-02"))
    finally:
        client.close()

    assert len(requests) == 1
    body = json.loads(requests[0].content)
    assert body["query"]["range"]["timestamp"]["gte"] == 1788307200000
    assert "lt" not in body["query"]["range"]["timestamp"]
    assert "search_after" not in body


@pytest.mark.db
def test_backfill_does_not_read_or_write_source_cursor(db):
    db.execute(
        "INSERT INTO source_cursor (manager_id, last_sort) VALUES ('indexer', %s)", (1786903000000,)
    )
    before = db.execute(
        "SELECT last_sort FROM source_cursor WHERE manager_id = 'indexer'"
    ).fetchone()

    cfg = _base_cfg()
    page = _search_page([_hit("1788400000.000001", 1788400000000)])
    client = _mock_client(_paged_handler([(200, page), (200, EMPTY_PAGE)]))
    try:
        result = _backfill_loop(db, client, cfg, _pull_start_ms("2026-09-02"))
    finally:
        client.close()

    assert result.new == 1
    after = db.execute(
        "SELECT last_sort FROM source_cursor WHERE manager_id = 'indexer'"
    ).fetchone()
    assert after == before == (1786903000000,)


@pytest.mark.db
def test_backfill_new_zero_before_02_09_is_not_a_failure(db):
    """DEC-017: the indexer holds nothing before 02/09, so a backfill run from
    PULL_START's default legitimately returns new == 0."""
    cfg = _base_cfg()
    client = _mock_client(_paged_handler([(200, EMPTY_PAGE)]))
    try:
        result = _backfill_loop(db, client, cfg, _pull_start_ms("2026-08-01"))
    finally:
        client.close()
    assert result == PullResult(hits=0, new=0, duplicates=0, heartbeats=0, last_sort=None)


@pytest.mark.db
def test_backfill_respects_an_until_upper_bound(db):
    cfg = _base_cfg()
    requests: list = []
    client = _mock_client(_paged_handler([(200, EMPTY_PAGE)], requests=requests))
    try:
        _backfill_loop(
            db, client, cfg, _pull_start_ms("2026-09-02"), until_ms=_pull_start_ms("2026-09-05")
        )
    finally:
        client.close()
    body = json.loads(requests[0].content)
    assert body["query"]["range"]["timestamp"] == {"gte": 1788307200000, "lt": 1788566400000}


@pytest.mark.db
def test_backfill_inserts_alerts_and_enqueues_pipeline_jobs(db):
    cfg = _base_cfg()
    page = _search_page(
        [_hit("1788400000.000001", 1788400000000), _hit("1788400001.000002", 1788400001000)]
    )
    client = _mock_client(_paged_handler([(200, page), (200, EMPTY_PAGE)]))
    try:
        result = _backfill_loop(db, client, cfg, _pull_start_ms("2026-09-02"))
    finally:
        client.close()

    assert result.new == 2
    jobs_count = db.execute(
        "SELECT count(*) FROM jobs j JOIN intake i ON i.intake_id::text = j.subject_id "
        "WHERE i.source_alert_id = ANY(%s) AND j.job_type = 'pipeline'",
        (["1788400000.000001", "1788400001.000002"],),
    ).fetchone()[0]
    assert jobs_count == 2


@pytest.mark.db
def test_backfill_rerun_is_idempotent_via_the_unique_constraint(db):
    cfg = _base_cfg()
    page = _search_page([_hit("1788400002.000003", 1788400002000)])

    client1 = _mock_client(_paged_handler([(200, page), (200, EMPTY_PAGE)]))
    try:
        first = _backfill_loop(db, client1, cfg, _pull_start_ms("2026-09-02"))
    finally:
        client1.close()
    assert first.new == 1

    client2 = _mock_client(_paged_handler([(200, page), (200, EMPTY_PAGE)]))
    try:
        second = _backfill_loop(db, client2, cfg, _pull_start_ms("2026-09-02"))
    finally:
        client2.close()
    assert second == PullResult(hits=1, new=0, duplicates=1, heartbeats=0, last_sort=1788400002000)


@pytest.mark.db
def test_backfill_heartbeat_hit_creates_no_job(db):
    cfg = _base_cfg()
    page = _search_page([_hit("1788400003.000004", 1788400003000, rule_id="100999")])
    client = _mock_client(_paged_handler([(200, page), (200, EMPTY_PAGE)]))
    try:
        result = _backfill_loop(db, client, cfg, _pull_start_ms("2026-09-02"))
    finally:
        client.close()
    assert result == PullResult(hits=1, new=0, duplicates=0, heartbeats=1, last_sort=1788400003000)


def test_backfill_on_page_callback_receives_per_page_counts():
    cfg = _base_cfg()
    page1 = _search_page([_hit("1788400010.1", 1788400010000), _hit("1788400011.2", 1788400011000)])
    conn = _FakeConn()
    client = _mock_client(_paged_handler([(200, page1), (200, EMPTY_PAGE)]))
    seen = []
    try:
        _backfill_loop(conn, client, cfg, _pull_start_ms("2026-09-02"), on_page=seen.append)
    finally:
        client.close()
    assert len(seen) == 1
    assert seen[0].hits == 2
    assert seen[0].new == 2


class _FakeConn:
    """A minimal stand-in for psycopg.Connection: `_backfill_loop`'s only DB
    calls are the INSERTs inside `_insert_alert`/`_insert_heartbeat`, which
    this records without a real database — used only where the callback
    behaviour, not persistence, is under test."""

    def __init__(self):
        self.next_id = 1
        self.executed: list[tuple] = []

    def execute(self, query, params=None):
        self.executed.append((query, params))
        return _FakeCursor(self.next_id) if "RETURNING intake_id" in query else _FakeCursor(None)


class _FakeCursor:
    def __init__(self, value):
        self._value = value

    def fetchone(self):
        return (self._value,) if self._value is not None else None
