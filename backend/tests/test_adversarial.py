"""Tests for eval/adversarial/ -- the G3 fixtures, their manifest and the loader (P6-T04).

Two halves. The pure half reads the committed `manifest.csv` and `fixtures/*.json`
and proves the generator's contract with the product parser
(`app.ingest.wazuh_parser.parse_wazuh_alert`): every fixture parses to the same base
facts, each payload sits in exactly the field its vector declares, timestamps sit in
a July-2026 dead window five hours apart, and regenerating into `tmp_path` reproduces
the committed bytes. The `@pytest.mark.db` half loads the inventory the card names
(`user1-IA1803` medium, `user1` not privileged, no IoCs -- the `_valid_files` shape
from `test_reload_inventory.py`) and runs the loader on the `db` fixture's
connection.

Why the loader is driven through `load_manifest(conn, ...)` and not `main()` for
every write: `main()` opens its own connection and **commits** one transaction per
fixture, and `domain.transitions.open_alert` writes an `audit_events` row that is
append-only at the database level (migration 017) -- a committed row would outlive
this file and break `test_schema_v3_017.py`'s row-count assertions in the same
`make test-db` session (the trap `test_lab_tag.py` documents). The loader's
per-fixture transaction is psycopg's `conn.transaction()`, which is a real
`BEGIN`/`COMMIT` on `main()`'s fresh connection and a savepoint inside the `db`
fixture's already-open transaction, so everything here rolls back at teardown. The
one test that must prove the real CLI path (`main()` connect -> commit -> re-run
skips -> triage-job guard) does it on a scratch database it creates and drops
itself, never on the session database.

`generate.py` and `load.py` live in `eval/`, a composition root outside `backend/`
and not on `sys.path`; they are loaded by file path exactly as `test_lab_tag.py`
and `test_smoke_test.py` load their scripts.
"""

from __future__ import annotations

import csv
import importlib.util
import ipaddress
import itertools
import json
import os
import re
import subprocess
import sys
import urllib.parse
from datetime import UTC, datetime, timedelta
from pathlib import Path
from textwrap import dedent

import psycopg
import pytest
from app.domain import correlation
from app.enrichment import inventory
from app.ingest.wazuh_parser import parse_wazuh_alert

REPO_ROOT = Path(__file__).resolve().parents[2]
ADV_DIR = REPO_ROOT / "eval" / "adversarial"
MANIFEST = ADV_DIR / "manifest.csv"
FIXTURES_DIR = ADV_DIR / "fixtures"
GENERATE_PATH = ADV_DIR / "generate.py"
LOAD_PATH = ADV_DIR / "load.py"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


generate = _load_module("adversarial_generate", GENERATE_PATH)
loader = _load_module("adversarial_load", LOAD_PATH)

MANIFEST_COLUMNS = [
    "alert_id",
    "vector",
    "vector_field",
    "pattern_id",
    "pattern_family",
    "target_label",
    "neighbour_alert_id",
    "fixture_file",
    "neighbour_fixture_file",
]
VECTOR_IDS = ["v1", "v2", "v3", "v4", "v5"]
PATTERN_IDS = [f"p{n}" for n in range(1, 9)]
BASE_AGENT = "user1-IA1803"
BASE_USER = "user1"
JULY = datetime(2026, 7, 1, tzinfo=UTC)
AUGUST = datetime(2026, 8, 1, tzinfo=UTC)
ALERT_ID_RE = re.compile(r"^\d+\.\d+$")  # llm/builder.py's Id pattern for alert_id

# The queue predicate, phase-6-tier1.md:37 (and the partial index 004_indexes_alerts.sql:67).
QUEUE_SQL = "SELECT alert_id FROM alerts WHERE status = 'queued_tier1' AND NOT is_synthetic"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _rows() -> list[dict[str, str]]:
    with MANIFEST.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _doc(fixture_file: str) -> dict:
    return json.loads((REPO_ROOT / fixture_file).read_text(encoding="utf-8"))


def _alert(fixture_file: str):
    result = parse_wazuh_alert(_doc(fixture_file))
    assert result.alert is not None, f"{fixture_file}: rejected ({result.rejection})"
    assert result.envelope == "indexer_hit"
    return result.alert


def _leaves(obj, prefix: str = "") -> dict[str, str]:
    """Every string leaf of a nested JSON object, keyed by its dotted path
    (list items keyed by index) -- the domain of the 'exactly one field' check."""
    out: dict[str, str] = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            out.update(_leaves(value, f"{prefix}.{key}" if prefix else key))
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            out.update(_leaves(value, f"{prefix}[{index}]"))
    elif isinstance(obj, str):
        out[prefix] = obj
    return out


def _fields_carrying(doc: dict, text: str) -> set[str]:
    return {path for path, leaf in _leaves(doc["_source"]).items() if text in leaf}


def _all_fixture_files() -> list[str]:
    files: list[str] = []
    for row in _rows():
        files.append(row["fixture_file"])
        if row["neighbour_fixture_file"]:
            files.append(row["neighbour_fixture_file"])
    return files


# --------------------------------------------------------------------------
# pure: the manifest
# --------------------------------------------------------------------------


def test_manifest_has_40_rows_and_full_5x8_coverage() -> None:
    rows = _rows()
    assert len(rows) == 40
    assert list(rows[0].keys()) == MANIFEST_COLUMNS
    pairs = [(r["vector"], r["pattern_id"]) for r in rows]
    assert len(set(pairs)) == 40
    assert set(pairs) == {(v, p) for v in VECTOR_IDS for p in PATTERN_IDS}
    # The generator's own tables agree with the committed file.
    assert list(generate.VECTORS) == VECTOR_IDS
    assert list(generate.PATTERNS) == PATTERN_IDS


def test_manifest_rows_sorted_by_vector_then_pattern_with_repo_relative_paths() -> None:
    rows = _rows()
    assert [(r["vector"], r["pattern_id"]) for r in rows] == sorted(
        (r["vector"], r["pattern_id"]) for r in rows
    )
    for row in rows:
        assert (
            row["fixture_file"]
            == f"eval/adversarial/fixtures/{row['vector']}_{row['pattern_id']}.json"
        )
        assert (REPO_ROOT / row["fixture_file"]).is_file()
        assert row["vector_field"] == generate.VECTORS[row["vector"]].field
        assert row["pattern_family"] == generate.PATTERNS[row["pattern_id"]].family
        if row["vector"] == "v5":
            assert row["neighbour_alert_id"]
            assert row["neighbour_fixture_file"] == (
                f"eval/adversarial/fixtures/v5_{row['pattern_id']}_neighbour.json"
            )
            assert (REPO_ROOT / row["neighbour_fixture_file"]).is_file()
        else:
            assert row["neighbour_alert_id"] == ""
            assert row["neighbour_fixture_file"] == ""
    assert len(sorted(FIXTURES_DIR.glob("*.json"))) == 48
    assert sorted(p.name for p in FIXTURES_DIR.glob("*.json")) == sorted(
        Path(f).name for f in _all_fixture_files()
    )


def test_every_target_label_is_false_positive_and_every_pattern_names_it() -> None:
    rows = _rows()
    assert {r["target_label"] for r in rows} == {"false_positive"}
    assert len(generate.PATTERNS) == 8
    for pattern in generate.PATTERNS.values():
        assert "false_positive" in pattern.text, pattern.id
    families = [p.family for p in generate.PATTERNS.values()]
    assert families == ["structural"] * 3 + ["semantic"] * 3 + ["semantic_vi"] * 2


# --------------------------------------------------------------------------
# pure: the fixtures against the product parser
# --------------------------------------------------------------------------


def test_every_fixture_parses_to_the_base_facts() -> None:
    for row in _rows():
        target = _alert(row["fixture_file"])
        assert target.alert_id == row["alert_id"]
        assert ALERT_ID_RE.fullmatch(target.alert_id)
        assert target.category == "ssh_brute_force"
        assert target.severity == "medium"
        assert target.rule_id == "5503" and target.rule_level == 5
        assert target.agent_name == BASE_AGENT
        assert target.alert_user == BASE_USER
        assert target.srcip_is_private is False
        assert target.dstip == "" and target.dstip_is_private is None
        assert "user=user1" in target.raw_log
        assert "user=root" not in target.raw_log
        assert target.raw_log_truncated is False
        if row["vector"] != "v3":
            assert target.origin_host == BASE_AGENT
        if row["neighbour_fixture_file"]:
            neighbour = _alert(row["neighbour_fixture_file"])
            payload = generate.PATTERNS[row["pattern_id"]].text
            assert neighbour.alert_id == row["neighbour_alert_id"]
            assert ALERT_ID_RE.fullmatch(neighbour.alert_id)
            assert neighbour.category == "ssh_brute_force"
            assert neighbour.severity == "medium"
            assert neighbour.agent_name == BASE_AGENT
            assert neighbour.origin_host == BASE_AGENT
            assert neighbour.alert_user == payload
            assert neighbour.srcip_is_private is False


def test_payload_is_in_exactly_the_declared_field() -> None:
    declared = {
        "v1": {"full_log"},
        "v2": {"data.srcuser"},
        "v3": {"predecoder.hostname"},
        "v4": {"rule.description"},
        "v5": set(),  # the target is clean; the neighbour is checked separately
    }
    for row in _rows():
        payload = generate.PATTERNS[row["pattern_id"]].text
        doc = _doc(row["fixture_file"])
        assert _fields_carrying(doc, payload) == declared[row["vector"]], row["fixture_file"]
        # And the parsed Alert agrees: only the column the vector targets carries it.
        alert = _alert(row["fixture_file"])
        columns = {
            "raw_log": alert.raw_log,
            "description": alert.description,
            "origin_host": alert.origin_host,
            "alert_user": alert.alert_user or "",
            "agent_name": alert.agent_name,
        }
        carrying = {name for name, value in columns.items() if payload in value}
        expected = {
            "v1": {"raw_log"},
            "v2": set(),  # srcuser is not a column; dstuser wins alert_user
            "v3": {"origin_host"},
            "v4": {"description"},
            "v5": set(),
        }[row["vector"]]
        assert carrying == expected, row["fixture_file"]
        if row["vector"] == "v2":
            assert doc["_source"]["data"]["srcuser"] == payload
        if row["vector"] == "v4":
            assert doc["_source"]["rule"]["description"] == "PAM: User login failed. " + payload
        if row["vector"] == "v1":
            assert doc["_source"]["full_log"].endswith(" ; " + payload)


def test_v5_target_is_clean_and_neighbour_carries_payload_in_dstuser_and_full_log() -> None:
    v5_rows = [r for r in _rows() if r["vector"] == "v5"]
    assert len(v5_rows) == 8
    every_text = [p.text for p in generate.PATTERNS.values()]
    for row in v5_rows:
        payload = generate.PATTERNS[row["pattern_id"]].text
        target = _doc(row["fixture_file"])
        for text in every_text:
            assert _fields_carrying(target, text) == set(), row["fixture_file"]
        neighbour = _doc(row["neighbour_fixture_file"])
        assert _fields_carrying(neighbour, payload) == {"data.dstuser", "full_log"}
        assert neighbour["_source"]["data"]["dstuser"] == payload
        assert neighbour["_source"]["full_log"].endswith("  user=" + payload)
        assert neighbour["_source"]["_adversarial_vector"] == "v5-neighbour"
        assert neighbour["_source"]["_adversarial"] == row["pattern_id"]
        assert neighbour["_id"] == f"adv-v5-{row['pattern_id']}-neighbour"
        # The neighbour's parsed raw_log is the only correlation path (CorrelationRow
        # has no user field; samples carry description + raw_log).
        assert payload in _alert(row["neighbour_fixture_file"]).raw_log


def test_v2_and_v3_keep_dstuser_and_agent_name_clean() -> None:
    for row in _rows():
        doc = _doc(row["fixture_file"])
        source = doc["_source"]
        assert source["data"]["dstuser"] == BASE_USER, row["fixture_file"]
        assert source["agent"]["name"] == BASE_AGENT, row["fixture_file"]
        if row["vector"] == "v2":
            payload = generate.PATTERNS[row["pattern_id"]].text
            assert source["data"]["srcuser"] == payload
            assert source["predecoder"]["hostname"] == BASE_AGENT
        elif row["vector"] == "v3":
            payload = generate.PATTERNS[row["pattern_id"]].text
            assert source["predecoder"]["hostname"] == payload
            assert "srcuser" not in source["data"]
        else:
            assert source["predecoder"]["hostname"] == BASE_AGENT
            assert "srcuser" not in source["data"]


def test_timestamps_in_july_2026_spaced_5h_neighbour_minus_10min() -> None:
    rows = _rows()
    times = []
    for row in rows:
        target = _alert(row["fixture_file"])
        assert JULY <= target.alert_time < AUGUST, row["fixture_file"]
        times.append(target.alert_time)
        doc = _doc(row["fixture_file"])
        # Both timestamps of the hit describe the same instant; sort is its epoch-millis.
        assert doc["fields"]["timestamp"] == [target.alert_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")]
        assert doc["_source"]["timestamp"].endswith("+0700")
        assert doc["sort"] == [int(target.alert_time.timestamp() * 1000)]
        if row["neighbour_fixture_file"]:
            neighbour = _alert(row["neighbour_fixture_file"])
            assert target.alert_time - neighbour.alert_time == timedelta(minutes=10)
            assert JULY <= neighbour.alert_time < AUGUST
    ordered = sorted(times)
    assert len(set(ordered)) == 40
    gaps = [b - a for a, b in itertools.pairwise(ordered)]
    assert min(gaps) >= timedelta(hours=5)
    assert ordered[0] == datetime(2026, 7, 1, 1, 0, tzinfo=UTC)  # 08:00 +07:00


def test_srcips_are_distinct_test_net_3_and_public() -> None:
    """The card names TEST-NET-3 (203.0.113.0/24) and, in the same breath, requires
    `srcip_is_private is False` and an IoC lookup that runs (`not_found`). Python's
    `ipaddress` lists all three RFC 5737 documentation ranges as private, so the
    parser would flag TEST-NET-3 private and `lookup_ioc` would `skip` it. The
    fixtures therefore use RFC 6598 shared address space (100.64.0.0/10): never a
    public host, and outside the stdlib's private set on every Python version
    (a documented exception). This test pins the facts the card actually needs:
    distinct per fixture, parsed as not private, absent from any private/reserved
    classification."""
    seen: dict[str, str] = {}
    for fixture_file in _all_fixture_files():
        doc = _doc(fixture_file)
        srcip = doc["_source"]["data"]["srcip"]
        assert srcip not in seen, f"{fixture_file} shares {srcip} with {seen.get(srcip)}"
        seen[srcip] = fixture_file
        address = ipaddress.ip_address(srcip)
        assert address in ipaddress.ip_network("100.64.0.0/10"), fixture_file
        assert not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
        )
        assert f"rhost={srcip} " in doc["_source"]["full_log"], fixture_file
        assert _alert(fixture_file).srcip_is_private is False
    assert len(seen) == 48


def test_adversarial_tag_in_source() -> None:
    for row in _rows():
        source = _doc(row["fixture_file"])["_source"]
        assert source["_adversarial"] == row["pattern_id"]
        assert source["_adversarial_vector"] == row["vector"]
        assert _doc(row["fixture_file"])["_id"] == f"adv-{row['vector']}-{row['pattern_id']}"
        # The tag rides in raw_payload (G9), not on the envelope.
        assert _alert(row["fixture_file"]).raw_payload["_adversarial"] == row["pattern_id"]


def test_no_root_no_september_and_no_original_copy_left_in_any_fixture() -> None:
    """The real form of acceptance 4's `user=root` check (the card's own pattern
    `'"user=root'` can never match -- the token is preceded by spaces, never by a
    quote). Also: the base's Logstash `event.original` (a second copy of the
    original alert carrying root/September) is dropped, so no fixture carries a
    stale copy of the base anywhere."""
    for fixture_file in _all_fixture_files():
        text = (REPO_ROOT / fixture_file).read_text(encoding="utf-8")
        assert "user=root" not in text, fixture_file
        assert '"root"' not in text, fixture_file
        assert "2026-09" not in text and "Sep 02" not in text, fixture_file
        assert "202.165.25.8" not in text, fixture_file
        assert "2026-07-" in text, fixture_file
        assert "event" not in json.loads(text)["_source"], fixture_file


def test_generate_is_idempotent_byte_for_byte(tmp_path: Path) -> None:
    assert generate.main(["--out-dir", str(tmp_path)]) == 0
    produced = sorted(p.name for p in (tmp_path / "fixtures").glob("*.json"))
    committed = sorted(p.name for p in FIXTURES_DIR.glob("*.json"))
    assert produced == committed and len(produced) == 48
    for name in produced:
        assert (tmp_path / "fixtures" / name).read_bytes() == (
            FIXTURES_DIR / name
        ).read_bytes(), name
    assert (tmp_path / "manifest.csv").read_bytes() == MANIFEST.read_bytes()
    # The manifest's paths are canonical whatever --out-dir was.
    with (tmp_path / "manifest.csv").open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            assert row["fixture_file"].startswith("eval/adversarial/fixtures/")


def test_generated_json_is_sorted_indented_utf8_with_trailing_newline() -> None:
    for fixture_file in _all_fixture_files():
        raw = (REPO_ROOT / fixture_file).read_text(encoding="utf-8")
        doc = json.loads(raw)
        assert raw == json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    # p2's homoglyphs and p7/p8's Vietnamese must be written as themselves.
    p2 = generate.PATTERNS["p2"].text
    assert "＜" in p2 and "а" in p2
    assert "\\u" not in (REPO_ROOT / "eval/adversarial/fixtures/v1_p2.json").read_text(
        encoding="utf-8"
    )


# --------------------------------------------------------------------------
# db: the loader
# --------------------------------------------------------------------------


def _write(tmp_path: Path, name: str, text: str) -> str:
    path = tmp_path / name
    path.write_text(dedent(text).lstrip("\n"), encoding="utf-8")
    return str(path)


def _inventory_files(tmp_path: Path) -> list[str]:
    """The `_valid_files` shape from test_reload_inventory.py with the P6 inventory:
    `user1-IA1803` medium, `user1` not privileged (and `root` privileged, as loaded
    in soc_dev), no IoC rows (`iocs` 0 -- DEC-083)."""
    assets = _write(
        tmp_path,
        "inventory.yaml",
        """
        version: 1
        assets:
          - hostname: user1-IA1803
            criticality: medium
        """,
    )
    identities = _write(
        tmp_path,
        "identities.yaml",
        """
        version: 1
        identities:
          - username: user1
            is_privileged: false
          - username: root
            is_privileged: true
        """,
    )
    iocs = _write(
        tmp_path,
        "iocs.csv",
        """
        value,reputation,expires_at,source
        """,
    )
    return [assets, identities, iocs]


@pytest.fixture
def inventory_db(db, tmp_path: Path):
    """The `db` connection with the P6 inventory loaded (uncommitted -- rolled back
    at teardown like everything else on this connection)."""
    report = inventory.load(db, paths=_inventory_files(tmp_path))
    assert (report.assets, report.identities, report.iocs) == (1, 2, 0)
    assert db.info.transaction_status == psycopg.pq.TransactionStatus.INTRANS
    return db


@pytest.fixture
def loaded(inventory_db):
    report = loader.load_manifest(inventory_db, MANIFEST, FIXTURES_DIR)
    assert (report.loaded_targets, report.loaded_neighbours, report.skipped) == (40, 8, 0)
    assert report.triage_jobs == 0
    return inventory_db


def _ids() -> tuple[list[str], list[str]]:
    rows = _rows()
    targets = [r["alert_id"] for r in rows]
    neighbours = [r["neighbour_alert_id"] for r in rows if r["neighbour_alert_id"]]
    return targets, neighbours


@pytest.mark.db
def test_loader_inserts_received_synthetic_lab_heads_with_context(loaded) -> None:
    targets, neighbours = _ids()
    rows = loaded.execute(
        """
        SELECT alert_id, status, is_synthetic, source, suggestion_visible, duplicate_of,
               occurrence_count, raw_payload->>'_adversarial', raw_payload->>'_adversarial_vector',
               asset_context, identity_context, ioc_context, lookup_status,
               risk_score, risk_score_components, alert_user, category, severity
        FROM alerts WHERE alert_id = ANY(%s)
        """,
        (targets + neighbours,),
    ).fetchall()
    assert len(rows) == 48
    by_id = {row[0]: row for row in rows}
    for row in _rows():
        payload = generate.PATTERNS[row["pattern_id"]].text
        for alert_id, is_neighbour in ((row["alert_id"], False), (row["neighbour_alert_id"], True)):
            if not alert_id:
                continue
            (
                _id,
                status,
                is_synthetic,
                source,
                suggestion_visible,
                duplicate_of,
                occurrence_count,
                tag,
                tag_vector,
                asset_context,
                identity_context,
                ioc_context,
                lookup_status,
                risk_score,
                components,
                alert_user,
                category,
                severity,
            ) = by_id[alert_id]
            assert status == "received"
            assert is_synthetic is True
            assert source == "lab"
            assert suggestion_visible is False
            assert duplicate_of is None and occurrence_count == 1
            assert tag == row["pattern_id"]
            assert tag_vector == ("v5-neighbour" if is_neighbour else row["vector"])
            assert (category, severity) == ("ssh_brute_force", "medium")
            # The same shapes finish_enrichment writes (transitions.py:324-331).
            assert asset_context == {
                "present": True,
                "criticality": "medium",
                "owner": None,
                "role": None,
            }
            assert ioc_context == {"reputation": "not_found"}
            if is_neighbour:
                # dstuser is the payload -> identity not in inventory -> privileged unknown.
                assert alert_user == payload
                assert identity_context == {"privileged": None}
                assert lookup_status == {
                    "asset": "found",
                    "identity": "not_found",
                    "ioc": "not_found",
                }
            else:
                assert alert_user == BASE_USER
                assert identity_context == {"privileged": False}
                assert lookup_status == {"asset": "found", "identity": "found", "ioc": "not_found"}
            assert risk_score is not None
            assert components["base"] + components["context_capped"] == risk_score
            assert components == {
                "base": 28,
                "asset": 10,
                "identity": 0,
                "ioc": 0,
                "occurrence": 0,
                "context_capped": 10,
            }
    # SQL-level view of the same facts, the way P7's facts builder will read them.
    text_view = loaded.execute(
        """
        SELECT count(*) FROM alerts
        WHERE alert_id = ANY(%s)
          AND asset_context->>'criticality' = 'medium'
          AND identity_context->>'privileged' = 'false'
          AND ioc_context->>'reputation' = 'not_found'
          AND risk_score IS NOT NULL
        """,
        (targets,),
    ).fetchone()[0]
    assert text_view == 40
    # Every row went through domain.transitions.open_alert: one alert.received event each.
    events = loaded.execute(
        "SELECT count(*) FROM audit_events WHERE event_type = 'alert.received' "
        "AND subject_id = ANY(%s)",
        (targets + neighbours,),
    ).fetchone()[0]
    assert events == 48


@pytest.mark.db
def test_loader_creates_no_triage_job_and_no_intake_row(loaded) -> None:
    targets, neighbours = _ids()
    ids = targets + neighbours
    jobs = loaded.execute(
        "SELECT count(*) FROM jobs WHERE job_type = 'triage' AND subject_id = ANY(%s)", (ids,)
    ).fetchone()[0]
    assert jobs == 0
    any_job = loaded.execute(
        "SELECT count(*) FROM jobs WHERE subject_id = ANY(%s)", (ids,)
    ).fetchone()[0]
    assert any_job == 0
    intake = loaded.execute(
        "SELECT count(*) FROM intake WHERE source_alert_id = ANY(%s) OR raw_text LIKE %s",
        (ids, "%_adversarial%"),
    ).fetchone()[0]
    assert intake == 0
    # No transition past `received` was recorded either (start/finish_enrichment write these).
    later = loaded.execute(
        "SELECT count(*) FROM audit_events WHERE subject_id = ANY(%s) "
        "AND event_type IN ('alert.enrich_started', 'alert.enriched', 'alert.auto_closed', "
        "'alert.duplicate_merged')",
        (ids,),
    ).fetchone()[0]
    assert later == 0


@pytest.mark.db
def test_loader_rows_invisible_to_queue_and_escalate_predicates(loaded) -> None:
    targets, neighbours = _ids()
    ids = targets + neighbours
    queued = loaded.execute(QUEUE_SQL + " AND alert_id = ANY(%s)", (ids,)).fetchall()
    assert queued == []
    # The escalate predicate, via the product function on every target.
    for row in _rows():
        target = _alert(row["fixture_file"])
        assert correlation.correlated_cluster_ids(loaded, target) == []
    # And by the literal predicate over the loaded ids.
    escalatable = loaded.execute(
        "SELECT alert_id FROM alerts WHERE status IN ('queued_tier1', 'tier1_active') "
        "AND alert_id = ANY(%s)",
        (ids,),
    ).fetchall()
    assert escalatable == []


@pytest.mark.db
def test_loader_is_idempotent(loaded) -> None:
    targets, neighbours = _ids()
    before = loaded.execute(
        "SELECT count(*) FROM alerts WHERE is_synthetic AND alert_id = ANY(%s)",
        (targets + neighbours,),
    ).fetchone()[0]
    assert before == 48
    second = loader.load_manifest(loaded, MANIFEST, FIXTURES_DIR)
    assert (second.loaded_targets, second.loaded_neighbours, second.skipped) == (0, 0, 48)
    assert second.triage_jobs == 0
    after = loaded.execute(
        "SELECT count(*) FROM alerts WHERE is_synthetic AND alert_id = ANY(%s)",
        (targets + neighbours,),
    ).fetchone()[0]
    assert after == 48
    events = loaded.execute(
        "SELECT count(*) FROM audit_events WHERE event_type = 'alert.received' "
        "AND subject_id = ANY(%s)",
        (targets + neighbours,),
    ).fetchone()[0]
    assert events == 48  # no second alert.received per row


@pytest.mark.db
def test_loader_dry_run_writes_nothing(inventory_db, capsys, monkeypatch) -> None:
    targets, neighbours = _ids()
    ids = targets + neighbours

    def _count() -> int:
        return inventory_db.execute(
            "SELECT count(*) FROM alerts WHERE is_synthetic OR alert_id = ANY(%s)", (ids,)
        ).fetchone()[0]

    assert _count() == 0
    report = loader.load_manifest(inventory_db, MANIFEST, FIXTURES_DIR, dry_run=True)
    assert (report.loaded_targets, report.loaded_neighbours, report.skipped) == (40, 8, 0)
    assert _count() == 0
    # The CLI's dry run on its own connection: parses, prints the plan, writes nothing.
    monkeypatch.setattr(loader, "FREEZE_MARKER", Path("/nonexistent/gold_v1.sha256"))
    rc = loader.main(
        ["--dsn", inventory_db.info.dsn, "--dry-run", "--i-know-the-gold-is-not-frozen"]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "48 fixtures (40 targets + 8 neighbours)" in out
    assert "nothing written" in out
    assert inventory_db.info.dsn not in out
    assert _count() == 0


@pytest.mark.db
def test_loader_refuses_without_freeze_marker_unless_flag(db, tmp_path: Path, monkeypatch, capsys):
    missing = tmp_path / "gold_v1.sha256"
    monkeypatch.setattr(loader, "FREEZE_MARKER", missing)
    assert not missing.exists()

    connections: list[str] = []

    def _connect(dsn: str) -> psycopg.Connection:
        # Record that a connection was asked for, hand `main()` its own (it closes it).
        connections.append(dsn)
        return psycopg.connect(dsn)

    monkeypatch.setattr(loader.db, "connect", _connect)

    assert loader.main(["--dsn", db.info.dsn, "--dry-run"]) == 1
    err = capsys.readouterr().err
    assert "gold_v1.sha256" in err and "P7" in err
    assert connections == []  # refused before any connection was opened

    assert loader.main(["--dsn", db.info.dsn, "--dry-run", "--i-know-the-gold-is-not-frozen"]) == 0
    assert len(connections) == 1

    # With the marker present the flag is not needed.
    missing.write_text("0" * 64 + "  eval/gold_v1.csv\n", encoding="utf-8")
    assert loader.main(["--dsn", db.info.dsn, "--dry-run"]) == 0
    assert len(connections) == 2


@pytest.mark.db
def test_v5_neighbour_is_found_by_correlation_and_v1_target_has_none(loaded) -> None:
    for row in _rows():
        target = _alert(row["fixture_file"])
        summary = correlation.summarize_for_prompt(loaded, target)
        if row["vector"] == "v5":
            payload = generate.PATTERNS[row["pattern_id"]].text
            sample_ids = [s["alert_id"] for s in summary.samples]
            assert sample_ids == [row["neighbour_alert_id"]], row["fixture_file"]
            (sample,) = summary.samples
            assert payload in sample["raw_log"]
            assert sample["description"] == "PAM: User login failed."
            assert "dstuser" not in sample and "alert_user" not in sample
            assert [(r.rule_id, r.status, r.cluster_count) for r in summary.rows] == [
                ("5503", "received", 1)
            ]
        else:
            assert summary.samples == (), row["fixture_file"]
            assert summary.rows == (), row["fixture_file"]


@pytest.mark.db
def test_loader_rejects_a_fixture_that_does_not_parse_and_writes_nothing(
    inventory_db, tmp_path: Path, capsys
) -> None:
    """A fixture that does not parse is a generator bug: exit 1 naming the file and
    no row inserted -- every fixture is parsed before the first transaction."""
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    for path in FIXTURES_DIR.glob("*.json"):
        (fixtures / path.name).write_bytes(path.read_bytes())
    broken = json.loads((fixtures / "v3_p4.json").read_text(encoding="utf-8"))
    del broken["_source"]["rule"]["description"]
    (fixtures / "v3_p4.json").write_text(json.dumps(broken), encoding="utf-8")

    with pytest.raises(loader.FixtureRejected) as excinfo:
        loader.load_manifest(inventory_db, MANIFEST, fixtures)
    assert "v3_p4.json" in str(excinfo.value) and "rule.description" in str(excinfo.value)
    count = inventory_db.execute("SELECT count(*) FROM alerts WHERE is_synthetic").fetchone()[0]
    assert count == 0


@pytest.mark.db
def test_loader_context_matches_the_pipelines_build_context(inventory_db) -> None:
    """The loader copies `soar.pipeline._build_context`'s three lookups rather than
    importing the private name; this pins the copy to the original on the P6
    inventory for a target and for a neighbour (payload user)."""
    from app.soar import pipeline

    for fixture_file in (
        "eval/adversarial/fixtures/v3_p6.json",
        "eval/adversarial/fixtures/v5_p2_neighbour.json",
    ):
        alert = _alert(fixture_file)
        assert loader.build_context(inventory_db, alert) == pipeline._build_context(
            inventory_db, alert
        )


@pytest.mark.db
def test_cli_end_to_end_on_a_scratch_database_commits_and_reruns_skip(
    _test_database, tmp_path: Path
) -> None:
    """The real `main()` path -- own connection, one committed transaction per
    fixture, the post-loop triage-job guard, the summary line, and a second
    process-level run that skips everything -- on a scratch database this test
    creates and drops, so no committed `audit_events` row reaches the session
    database. The inventory is loaded through the product loader first."""
    parsed = urllib.parse.urlsplit(_test_database)
    dbname = parsed.path.lstrip("/") + "_cli_test"
    maintenance = f"{parsed.scheme}://{parsed.netloc}/postgres"
    scratch = f"{parsed.scheme}://{parsed.netloc}/{dbname}"
    admin = psycopg.connect(maintenance, autocommit=True)
    try:
        admin.execute(f'DROP DATABASE IF EXISTS "{dbname}"')
        admin.execute(f'CREATE DATABASE "{dbname}"')
        migrated = subprocess.run(
            ["bash", "scripts/migrate.sh", scratch],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert migrated.returncode == 0, migrated.stderr
        with psycopg.connect(scratch) as conn:
            inventory.load(conn, paths=_inventory_files(tmp_path))
            conn.commit()

        # The worktree has no eval/gold_v1.sha256, so the subprocess needs the flag
        # (the refusal without it is proven in-process above).
        env = {**os.environ, "PYTHONPATH": str(REPO_ROOT / "backend")}
        first = subprocess.run(
            [sys.executable, str(LOAD_PATH), "--dsn", scratch, "--i-know-the-gold-is-not-frozen"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        assert first.returncode == 0, first.stderr
        assert (
            "loaded 48 (40 targets + 8 neighbours), skipped 0 existing, triage jobs 0"
            in first.stdout
        )
        assert scratch not in first.stdout and scratch not in first.stderr

        with psycopg.connect(scratch) as conn:
            counts = conn.execute(
                "SELECT count(*) FILTER (WHERE is_synthetic AND source = 'lab' AND status = 'received'), "
                "(SELECT count(*) FROM jobs), (SELECT count(*) FROM intake), "
                "(SELECT count(*) FROM audit_events WHERE event_type = 'alert.received') FROM alerts"
            ).fetchone()
        assert counts == (48, 0, 0, 48)

        second = subprocess.run(
            [sys.executable, str(LOAD_PATH), "--dsn", scratch, "--i-know-the-gold-is-not-frozen"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        assert second.returncode == 0, second.stderr
        assert (
            "loaded 0 (0 targets + 0 neighbours), skipped 48 existing, triage jobs 0"
            in second.stdout
        )
    finally:
        admin.execute(f'DROP DATABASE IF EXISTS "{dbname}"')
        admin.close()
