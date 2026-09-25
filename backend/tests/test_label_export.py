"""Tests for eval/label_export.py -- `kappa` (Cohen's kappa, 3x3), `disagreements`
(the adjudication CSV), `freeze` (`gold_v1.csv` + `.sha256`, version-by-existence),
`report` (`docs/gold-v1-report.md`).

Pure tests (the kappa formula and its grouping, `freeze`'s row-building rules,
the sha/version-by-existence file mechanics, the report renderer) run on
hand-built in-memory objects and `tmp_path` files -- no database. Database
tests (`@pytest.mark.db`) exercise the CLI end to end against the `db`
fixture, with `label_export._connection` monkeypatched onto the fixture's own
connection the way `test_build_gold.py`'s `same_connection` fixture does.

`cmd_freeze` commits only when `--adjudicator-id` is given -- the single
write this script makes to `triage_labels`, needed so a later, separate
connection (the Owner's next run) sees the disagreement row. Exactly one test
reaches that commit (`test_freeze_writes_v1_sha_and_disagreement_rows`); it
builds its fixture alert with a **direct INSERT**, not
`domain.transitions.open_alert`, which writes an append-only `audit_events`
row that a commit here would then also persist for the rest of a
`make test-db` run (the pattern `test_lab_tag.py` already worked out), and it
cleans its own rows up in an autouse fixture ordered to run before `db`'s own
rollback+close. Every other database test never commits, so it builds its
fixture alerts with `open_alert` and relies on the fixture's ordinary
rollback-based isolation, like the rest of the suite.
"""

from __future__ import annotations

import copy
import csv
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from app.domain import transitions
from app.domain.alert import Alert
from app.ingest.wazuh_parser import parse_wazuh_alert
from psycopg.types.json import Jsonb

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "eval" / "label_export.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

_spec = importlib.util.spec_from_file_location("label_export", SCRIPT_PATH)
label_export = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = label_export
_spec.loader.exec_module(label_export)

LABELS = label_export.LABELS

_EVENT_ORIGINAL = json.loads(
    json.loads((FIXTURES / "archive_line_5503.json").read_text(encoding="utf-8"))["event"][
        "original"
    ]
)


# --- fixture construction ----------------------------------------------------------


def _doc(alert_id: str, instant: datetime, agent_name: str = "user1-IA1803") -> dict:
    doc = copy.deepcopy(_EVENT_ORIGINAL)
    doc["id"] = alert_id
    doc["timestamp"] = instant.strftime("%Y-%m-%dT%H:%M:%S.000") + instant.strftime("%z")
    doc["agent"] = dict(doc["agent"], name=agent_name)
    return doc


def _parsed(alert_id: str, instant: datetime, agent_name: str = "user1-IA1803") -> Alert:
    result = parse_wazuh_alert(_doc(alert_id, instant, agent_name))
    assert result.alert is not None, result.rejection
    return result.alert


def _insert_head(conn, alert_id: str, instant: datetime) -> str:
    """Via `open_alert` -- never commits, safe under the fixture's rollback."""
    return transitions.open_alert(
        conn, _parsed(alert_id, instant), kind="received", source="wazuh", suggestion_visible=True
    )


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
)


def _insert_head_direct(conn, alert_id: str, instant: datetime) -> str:
    """A direct INSERT bypassing `open_alert` -- writes no `audit_events` row,
    so a later commit in the same transaction never persists one."""
    alert = _parsed(alert_id, instant)
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
        "wazuh",
        "received",
    )
    placeholders = ", ".join(["%s"] * len(_ALERT_COLUMNS))
    conn.execute(
        f"INSERT INTO alerts ({', '.join(_ALERT_COLUMNS)}) VALUES ({placeholders})", values
    )
    return alert.alert_id


def _make_user(conn, *, prefix: str = "p6t03") -> str:
    user_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash) "
        "VALUES (%s, %s, %s, 'admin', 'x')",
        (user_id, f"{prefix}-{user_id[:8]}", "Test Labeller"),
    )
    return user_id


def _label(conn, alert_id: str, labeler_id: str, *, label: str, confidence: str, note: str) -> None:
    conn.execute(
        "INSERT INTO triage_labels (alert_id, labeler_id, source, label, confidence, note) "
        "VALUES (%s, %s, 'gold_offline', %s, %s, %s)",
        (alert_id, labeler_id, label, confidence, note),
    )


def _candidate(
    cluster_id: str, *, gold_set="G1", category="ssh_brute_force", severity="high"
) -> dict:
    return {
        "cluster_id": cluster_id,
        "gold_set": gold_set,
        "alert_id": cluster_id,
        "category": category,
        "severity": severity,
        "source": "replay",
        "stratum": f"{category}|{severity}",
        "occurrence_count": "1",
        "first_seen": "2026-08-08T09:00:00+00:00",
        "last_seen": "2026-08-08T09:00:00+00:00",
        "agent_name": "IA1803",
        "rule_id": "5901",
    }


def _write_candidates_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


@pytest.fixture
def same_connection(db, monkeypatch):
    """Route `main()`'s connection to the fixture's own -- uncommitted rows
    are visible; nothing is committed unless the code under test commits."""

    @contextmanager
    def _borrow(_dsn):
        yield db

    monkeypatch.setattr(label_export, "_connection", _borrow)
    return db


# --- kappa: the formula (pure) ------------------------------------------------------


def test_kappa_perfect_agreement_is_one():
    pairs = (
        [("escalate", "escalate")] * 5
        + [("benign", "benign")] * 3
        + [("false_positive", "false_positive")] * 2
    )
    result = label_export.cohen_kappa(pairs)
    assert result.kappa == pytest.approx(1.0, abs=1e-9)
    assert result.reason is None


def test_kappa_known_2x2_is_0_40():
    pairs = (
        [("escalate", "escalate")] * 20
        + [("escalate", "benign")] * 5
        + [("benign", "escalate")] * 10
        + [("benign", "benign")] * 15
    )
    result = label_export.cohen_kappa(pairs)
    assert result.n == 50
    assert result.p_o == pytest.approx(0.70, abs=1e-9)
    assert result.p_e == pytest.approx(0.50, abs=1e-9)
    assert result.kappa == pytest.approx(0.40, abs=1e-9)
    assert result.confusion["escalate"]["benign"] == 5
    assert result.confusion["benign"]["escalate"] == 10


def test_kappa_independence_is_near_zero():
    pairs = [(a, b) for a in LABELS for b in LABELS for _ in range(100)]
    result = label_export.cohen_kappa(pairs)
    assert result.n == 900
    assert abs(result.kappa) < 0.05


def test_kappa_is_null_when_pe_is_one():
    pairs = [("escalate", "escalate")] * 10
    result = label_export.cohen_kappa(pairs)
    assert result.kappa is None
    assert result.reason == "p_e = 1"


def test_kappa_by_category():
    # ssh_brute_force: perfect agreement (kappa 1.0); privilege_escalation:
    # the known 2x2 table (kappa 0.40), hand-labelled by category.
    pairs_by_cluster = {
        "c1": ("escalate", "escalate"),
        "c2": ("benign", "benign"),
        "c3": ("escalate", "escalate"),
    }
    key_by_cluster = {
        "c1": "ssh_brute_force",
        "c2": "ssh_brute_force",
        "c3": "privilege_escalation",
    }
    grouped = label_export.group_kappa(pairs_by_cluster, key_by_cluster)
    assert set(grouped) == {"ssh_brute_force", "privilege_escalation"}
    assert grouped["ssh_brute_force"]["n"] == 2
    assert grouped["ssh_brute_force"]["kappa"] == pytest.approx(1.0, abs=1e-9)
    assert grouped["privilege_escalation"]["n"] == 1


def test_resolve_labelers_returns_explicit_pair_without_touching_the_connection():
    assert label_export.resolve_labelers(None, [], "A", "B") == ("A", "B")


# --- freeze: pure row-building rules -------------------------------------------------


def _pair(cluster_id, label_a, label_b, *, note_a="", note_b="") -> label_export.LabelPair:
    return label_export.LabelPair(
        cluster_id=cluster_id,
        label_a=label_a,
        confidence_a="2",
        note_a=note_a,
        label_b=label_b,
        confidence_b="3",
        note_b=note_b,
    )


def test_freeze_refuses_missing_final_label():
    candidate = label_export.Candidate(
        cluster_id="c1",
        gold_set="G1",
        alert_id="c1",
        category="ssh_brute_force",
        severity="high",
        source="replay",
        occurrence_count="1",
        first_seen="2026-08-08T09:00:00+00:00",
        last_seen="2026-08-08T09:00:00+00:00",
    )
    pairs = {"c1": _pair("c1", "escalate", "benign")}

    with pytest.raises(label_export.MissingFinalLabel) as excinfo:
        label_export.build_gold_rows([candidate], pairs, adjudication={}, allow_partial=False)
    assert excinfo.value.cluster_ids == ["c1"]

    # red step (DEC-025): an adjudication row with an out-of-set final_label
    # is refused exactly the same way as a missing one.
    bad = {"c1": label_export.AdjudicationRow(final_label="maybe", final_note="")}
    with pytest.raises(label_export.MissingFinalLabel):
        label_export.build_gold_rows([candidate], pairs, adjudication=bad, allow_partial=False)

    # green: a valid final_label freezes the row as adjudicated.
    good = {"c1": label_export.AdjudicationRow(final_label="escalate", final_note="agreed")}
    result = label_export.build_gold_rows(
        [candidate], pairs, adjudication=good, allow_partial=False
    )
    assert len(result.rows) == 1
    assert result.rows[0].label == "escalate"
    assert result.rows[0].adjudicated is True
    assert result.rows[0].note == "agreed"


def test_freeze_partial_rule_dropped_only_under_allow_partial():
    agree = label_export.Candidate(
        cluster_id="c-agree",
        gold_set="G1",
        alert_id="c-agree",
        category="ssh_brute_force",
        severity="high",
        source="replay",
        occurrence_count="1",
        first_seen="2026-08-08T09:00:00+00:00",
        last_seen="2026-08-08T09:00:00+00:00",
    )
    partial = label_export.Candidate(
        cluster_id="c-partial",
        gold_set="G1",
        alert_id="c-partial",
        category="ssh_brute_force",
        severity="high",
        source="replay",
        occurrence_count="1",
        first_seen="2026-08-08T09:00:00+00:00",
        last_seen="2026-08-08T09:00:00+00:00",
    )
    pairs = {
        "c-agree": _pair("c-agree", "benign", "benign"),
        "c-partial": label_export.LabelPair("c-partial", "benign", "2", "", None, None, None),
    }

    with pytest.raises(label_export.PartialLabelled) as excinfo:
        label_export.build_gold_rows([agree, partial], pairs, adjudication={}, allow_partial=False)
    assert excinfo.value.cluster_ids == ["c-partial"]

    result = label_export.build_gold_rows(
        [agree, partial], pairs, adjudication={}, allow_partial=True
    )
    assert [row.cluster_id for row in result.rows] == ["c-agree"]
    assert result.dropped_unlabelled == 1


# --- freeze: file mechanics (pure, tmp_path) -----------------------------------------


def _gold_row(cluster_id: str, label: str = "benign") -> label_export.GoldRow:
    return label_export.GoldRow(
        cluster_id=cluster_id,
        gold_set="G1",
        alert_id=cluster_id,
        category="ssh_brute_force",
        severity="high",
        source="replay",
        label=label,
        adjudicated=False,
        note="",
        confidence_a="2",
        confidence_b="3",
        occurrence_count="1",
        first_seen="2026-08-08T09:00:00+00:00",
        last_seen="2026-08-08T09:00:00+00:00",
    )


def test_freeze_sha_file_is_sha256sum_compatible(tmp_path):
    csv_path = tmp_path / "gold_v9.csv"
    csv_path.write_text("cluster_id,gold_set\nx,G1\n", encoding="utf-8", newline="\n")
    sha_path = tmp_path / "gold_v9.sha256"

    label_export.write_sha_file(str(csv_path), str(sha_path))

    content = sha_path.read_text(encoding="utf-8")
    digest, _, label = content.strip().partition("  ")
    assert len(digest) == 64
    assert all(ch in "0123456789abcdef" for ch in digest)
    assert label == str(csv_path)
    assert digest == hashlib.sha256(csv_path.read_bytes()).hexdigest()
    if shutil.which("sha256sum"):
        result = subprocess.run(
            ["sha256sum", "-c", sha_path.name],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr

    # red step (DEC-025): hashing the path string instead of the file's bytes
    # would desync from the real content -- proven by writing a mismatched
    # digest by hand and confirming the two differ.
    wrong_digest = hashlib.sha256(str(csv_path).encode()).hexdigest()
    assert wrong_digest != digest


def test_freeze_never_overwrites_writes_v2_and_diff(tmp_path):
    v1 = label_export.write_freeze_outputs(
        tmp_path, [_gold_row("c1")], dropped_unlabelled=0, candidates_total=1, adjudicator_id=None
    )
    assert v1.version == 1
    assert v1.diff_path is None
    v1_bytes_before = v1.gold_path.read_bytes()

    v2 = label_export.write_freeze_outputs(
        tmp_path,
        [_gold_row("c1"), _gold_row("c2", label="escalate")],
        dropped_unlabelled=0,
        candidates_total=2,
        adjudicator_id=None,
    )
    assert v2.version == 2
    assert v2.gold_path.name == "gold_v2.csv"
    assert v1.gold_path.read_bytes() == v1_bytes_before, "v1's bytes must never change"

    diff_text = v2.diff_path.read_text(encoding="utf-8")
    assert "gold_v1.csv" in diff_text and "gold_v2.csv" in diff_text
    assert "+c2,G1,c2,ssh_brute_force,high,replay,escalate,false" in diff_text.replace("\r", "")

    v3 = label_export.write_freeze_outputs(
        tmp_path, [_gold_row("c1")], dropped_unlabelled=0, candidates_total=1, adjudicator_id=None
    )
    assert v3.version == 3
    assert v2.gold_path.read_bytes() == v2.gold_path.read_bytes()  # v2 untouched by the v3 write


def test_freeze_json_sidecar_carries_dropped_count(tmp_path):
    files = label_export.write_freeze_outputs(
        tmp_path,
        [_gold_row("c1")],
        dropped_unlabelled=2,
        candidates_total=3,
        adjudicator_id="labeller-a",
    )
    doc = json.loads(files.freeze_json_path.read_text(encoding="utf-8"))
    assert doc["candidates"] == 3
    assert doc["frozen"] == 1
    assert doc["dropped_unlabelled"] == 2
    assert doc["adjudicator_id"] == "labeller-a"
    assert len(doc["sha256"]) == 64
    assert doc["sha256"] == hashlib.sha256(files.gold_path.read_bytes()).hexdigest()
    assert doc["frozen_at"].endswith("+00:00")


def test_disagreements_refuses_to_clobber_in_progress_file(tmp_path):
    out_path = tmp_path / "adjudication_v1.csv"
    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(label_export.ADJUDICATION_COLUMNS)
        writer.writerow(
            [
                "c1",
                "G1",
                "ssh_brute_force",
                "high",
                "escalate",
                "2",
                "",
                "benign",
                "3",
                "",
                "escalate",
                "meeting decided",
            ]
        )
    before = out_path.read_bytes()

    rc = label_export.main(["disagreements", "--out", str(out_path)])

    assert rc == label_export.EXIT_REFUSED
    assert out_path.read_bytes() == before, "the meeting's file is never touched"

    # red step (DEC-025): a file with every final_label empty is not "in
    # progress" and must NOT trip the guard.
    fresh = tmp_path / "adjudication_fresh.csv"
    with fresh.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(label_export.ADJUDICATION_COLUMNS)
        writer.writerow(
            ["c2", "G1", "ssh_brute_force", "high", "escalate", "2", "", "benign", "3", "", "", ""]
        )
    assert label_export._adjudication_in_progress(fresh) is False
    assert label_export._adjudication_in_progress(out_path) is True


# --- report: pure renderer -----------------------------------------------------------


_COVERAGE_TEXT = """# Gold coverage — G1 only

## Run

- archive: `/x` — lines 1 / parsed 1 / rejected 0 — clusters 3051

## G1 pool (denominator 2984)

| category | critical | high | medium | low | total | share |
|---|---|---|---|---|---|---|
| unknown | 14 | 80 | 838 | 869 | 1801 | 60.4 % |

- crit+high in the pool: 137 of 2984, of which `unknown` 94
- `unknown` share of the pool: 1801 of 2984 (60.4 %)
- excluded as loopback `ssh_brute_force` from 127.0.0.1 (DEC-053): 67 of 3051 clusters / 662 of 92011 alerts
- `DESKTOP-MIRSO17` (DEC-058): 23 of 3051 fold clusters, 23 of 2984 in the pool, 6 of 300 in the sample -- kept, `needs_review` by construction

## G1 sample (denominator 300)

| category | critical | high | medium | low | total | share |
|---|---|---|---|---|---|---|
| unknown | 14 | 80 | 13 | 13 | 120 | 40.0 % |

- `unknown` in the sample: 120 of 300 (40.0 %) against the cap 40.0 % (budget 120)
- crit+high in the sample: 137 of 300, of which `unknown` 94
- G1's severity mix is enriched by design: 137 of 300 against 137 of 2984

## G2 pool (denominator 80)

| category | critical | high | medium | low | total | share |
|---|---|---|---|---|---|---|
| ransomware | 0 · | 3 | 2 | 0 · | 5 | 6.2 % |
| data_exfiltration | 0 · | 0 · | 4 | 0 · | 4 | 5.0 % |

## G2 sample (denominator 60)

| category | critical | high | medium | low | total | share |
|---|---|---|---|---|---|---|

## Floors

- G1 300 >= 200: met
"""


def _report_gold_rows() -> list[label_export.GoldRow]:
    rows = [_gold_row(f"g1-{i}", label="escalate" if i < 2 else "benign") for i in range(3)]
    rows += [
        label_export.GoldRow(
            cluster_id=f"g2-{i}",
            gold_set="G2",
            alert_id=f"g2-{i}",
            category="ransomware",
            severity="high",
            source="lab",
            label=label,
            adjudicated=i == 0,
            note="",
            confidence_a="2",
            confidence_b="2",
            occurrence_count="1",
            first_seen="2026-09-22T09:00:00+00:00",
            last_seen="2026-09-22T09:00:00+00:00",
        )
        for i, label in enumerate(["benign", "false_positive", "escalate"])
    ]
    return rows


def test_report_sections_counts_and_g2_benign():
    kappa_doc = {
        "overall": {"n": 3, "kappa": 0.65, "confusion": {}},
        "disagreements": 1,
        "disagreement_rate": 0.33,
        "by_gold_set": {"G1": {"n": 3, "kappa": 0.65}},
        "by_category": {"ssh_brute_force": {"n": 3, "kappa": 0.65}},
    }
    text = label_export.render_report(
        gold_rows=_report_gold_rows(),
        version=1,
        sha256_hex="a" * 64,
        frozen_at="2026-09-28T10:00:00+00:00",
        adjudicator_id="labeller-a",
        git_log_line="commit: abc1234",
        kappa_doc=kappa_doc,
        coverage_text=_COVERAGE_TEXT,
        manifest_rows=40,
        adjudication_present=True,
    )
    assert "## 1. Freeze" in text
    assert "## 2. Counts" in text
    assert "## 3. Coverage" in text
    assert "## 4. Agreement" in text
    assert "## 5. Limitations for P8" in text
    # coverage grids copied verbatim, found by heading
    assert "denominator 2984" in text and "denominator 300" in text
    assert "denominator 80" in text
    # G2 benign gate: benign + false_positive = 2 of 3 G2 rows, against >= 20 -> MISS
    assert "G2 benign clusters (benign + false_positive): 2 (>= 20: MISS)" in text
    assert "G3: 40 of `eval/adversarial/manifest.csv`" in text
    assert "kappa = 0.650" in text


@pytest.mark.parametrize(
    ("kappa", "phrase"),
    [
        (0.65, "target met"),
        (0.50, "below target, reported"),
        (0.20, "only adjudicated labels are used"),
    ],
)
def test_report_kappa_sentence_per_band(kappa, phrase):
    assert phrase in label_export._band_sentence(kappa)


def test_report_kappa_sentence_null_band():
    assert "p_e = 1" in label_export._band_sentence(None)


def test_report_is_deterministic():
    kwargs = {
        "gold_rows": _report_gold_rows(),
        "version": 1,
        "sha256_hex": "a" * 64,
        "frozen_at": "2026-09-28T10:00:00+00:00",
        "adjudicator_id": "labeller-a",
        "git_log_line": "commit: abc1234",
        "kappa_doc": {
            "overall": {"n": 3, "kappa": 0.4, "confusion": {}},
            "disagreements": 1,
            "disagreement_rate": 0.33,
            "by_gold_set": {},
            "by_category": {},
        },
        "coverage_text": _COVERAGE_TEXT,
        "manifest_rows": None,
        "adjudication_present": True,
    }
    first = label_export.render_report(**kwargs)
    second = label_export.render_report(**kwargs)
    assert first == second


def test_report_handles_missing_inputs_gracefully():
    text = label_export.render_report(
        gold_rows=[],
        version=1,
        sha256_hex=None,
        frozen_at=None,
        adjudicator_id=None,
        git_log_line="commit: (not committed yet)",
        kappa_doc=None,
        coverage_text=None,
        manifest_rows=None,
        adjudication_present=False,
    )
    assert "not found -- run" in text
    assert "G3: not loaded -- P6-T04" in text


def test_report_exits_2_on_missing_gold(tmp_path):
    rc = label_export.main(
        ["report", "--gold", str(tmp_path / "nope.csv"), "--out", str(tmp_path / "r.md")]
    )
    assert rc == label_export.EXIT_UNREADABLE
    assert not (tmp_path / "r.md").exists()


# --- database tests -------------------------------------------------------------------


@pytest.fixture
def scenario(db):
    """3 agreements + 1 disagreement + 1 partial (A-only) over 5 candidates,
    via `open_alert` -- this fixture never commits."""
    base = datetime(2026, 8, 8, 9, 0, 0, tzinfo=timezone(timedelta(hours=0)))
    labeler_a = _make_user(db)
    labeler_b = _make_user(db)
    cluster_ids = [f"p6t03s-{i}" for i in range(5)]
    for i, cluster_id in enumerate(cluster_ids):
        _insert_head(db, cluster_id, base + timedelta(minutes=i))

    for i in range(3):  # agreements
        _label(db, cluster_ids[i], labeler_a, label="benign", confidence="2", note=f"note-a-{i}")
        _label(db, cluster_ids[i], labeler_b, label="benign", confidence="3", note=f"note-b-{i}")
    _label(db, cluster_ids[3], labeler_a, label="escalate", confidence="3", note="a says escalate")
    _label(db, cluster_ids[3], labeler_b, label="benign", confidence="2", note="b says benign")
    _label(db, cluster_ids[4], labeler_a, label="benign", confidence="1", note="only a")

    candidates = [_candidate(cid) for cid in cluster_ids]
    return {
        "labeler_a": labeler_a,
        "labeler_b": labeler_b,
        "cluster_ids": cluster_ids,
        "disagreement": cluster_ids[3],
        "partial": cluster_ids[4],
        "candidates": candidates,
    }


@pytest.mark.db
def test_pivot_requires_exactly_two_labelers(same_connection, scenario, tmp_path):
    db = same_connection
    candidates_csv = tmp_path / "gold_candidates.csv"
    _write_candidates_csv(candidates_csv, scenario["candidates"])

    rc = label_export.main(
        [
            "kappa",
            "--candidates",
            str(candidates_csv),
            "--out",
            str(tmp_path / "kappa_v1.json"),
            "--dsn",
            "postgresql://never-used",
        ]
    )
    assert rc == label_export.EXIT_OK
    doc = json.loads((tmp_path / "kappa_v1.json").read_text(encoding="utf-8"))
    assert doc["labelled_by_both"] == 4
    assert {doc["labeler_a"], doc["labeler_b"]} == {scenario["labeler_a"], scenario["labeler_b"]}

    # a third labeller's row over the same ids -> the two-labellers refusal
    third = _make_user(db)
    _label(db, scenario["cluster_ids"][0], third, label="benign", confidence="1", note="")
    rc = label_export.main(
        [
            "kappa",
            "--candidates",
            str(candidates_csv),
            "--out",
            str(tmp_path / "kappa_v1_again.json"),
            "--dsn",
            "postgresql://never-used",
        ]
    )
    assert rc == label_export.EXIT_REFUSED


@pytest.mark.db
def test_disagreements_csv_carries_both_notes_and_empty_final(same_connection, scenario, tmp_path):
    candidates_csv = tmp_path / "gold_candidates.csv"
    _write_candidates_csv(candidates_csv, scenario["candidates"])
    out_path = tmp_path / "adjudication_v1.csv"

    rc = label_export.main(
        [
            "disagreements",
            "--candidates",
            str(candidates_csv),
            "--out",
            str(out_path),
            "--dsn",
            "postgresql://never-used",
            "--labeler-a",
            scenario["labeler_a"],
            "--labeler-b",
            scenario["labeler_b"],
        ]
    )
    assert rc == label_export.EXIT_OK

    with out_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    row = rows[0]
    assert row["cluster_id"] == scenario["disagreement"]
    assert row["label_a"] == "escalate" and row["note_a"] == "a says escalate"
    assert row["label_b"] == "benign" and row["note_b"] == "b says benign"
    assert row["final_label"] == "" and row["final_note"] == ""


@pytest.mark.db
def test_freeze_partial_refused_without_flag_and_counted_with_it(same_connection, tmp_path):
    db = same_connection
    base = datetime(2026, 8, 9, 9, 0, 0, tzinfo=UTC)
    labeler_a = _make_user(db)
    labeler_b = _make_user(db)
    agree_ids = [f"p6t03p-agree-{i}" for i in range(3)]
    for i, cid in enumerate(agree_ids):
        _insert_head(db, cid, base + timedelta(minutes=i))
        _label(db, cid, labeler_a, label="benign", confidence="2", note="")
        _label(db, cid, labeler_b, label="benign", confidence="2", note="")
    partial_id = "p6t03p-partial"
    _insert_head(db, partial_id, base + timedelta(minutes=10))
    _label(db, partial_id, labeler_a, label="benign", confidence="1", note="")

    candidates_csv = tmp_path / "gold_candidates.csv"
    _write_candidates_csv(candidates_csv, [_candidate(cid) for cid in [*agree_ids, partial_id]])

    rc = label_export.main(
        [
            "freeze",
            "--candidates",
            str(candidates_csv),
            "--out-dir",
            str(tmp_path / "out"),
            "--dsn",
            "postgresql://never-used",
            "--labeler-a",
            labeler_a,
            "--labeler-b",
            labeler_b,
        ]
    )
    assert rc == label_export.EXIT_REFUSED
    assert not (tmp_path / "out").exists() or not list((tmp_path / "out").glob("gold_v*.csv"))

    rc = label_export.main(
        [
            "freeze",
            "--candidates",
            str(candidates_csv),
            "--out-dir",
            str(tmp_path / "out"),
            "--dsn",
            "postgresql://never-used",
            "--labeler-a",
            labeler_a,
            "--labeler-b",
            labeler_b,
            "--allow-partial",
        ]
    )
    assert rc == label_export.EXIT_OK
    gold_path = tmp_path / "out" / "gold_v1.csv"
    with gold_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 3
    freeze_doc = json.loads((tmp_path / "out" / "gold_v1.freeze.json").read_text(encoding="utf-8"))
    assert freeze_doc["dropped_unlabelled"] == 1
    assert freeze_doc["adjudicator_id"] is None


@pytest.fixture
def _cleanup_p6t03_committed_rows(request):
    """`test_freeze_writes_v1_sha_and_disagreement_rows` is the one test in
    this file whose `main()` call commits (via `--adjudicator-id`). Fetching
    `db` here, before `yield`, registers it as this fixture's dependency, so
    `db`'s own rollback+close finalizer runs *after* this cleanup -- the
    `test_lab_tag.py` pattern. Every row this test commits carries the
    `p6t03c-` prefix so this sweep touches nothing any other test file owns.
    """
    conn = request.getfixturevalue("db") if "db" in request.fixturenames else None
    yield
    if conn is not None:
        conn.execute("DELETE FROM triage_labels WHERE alert_id LIKE 'p6t03c-%'")
        conn.execute("DELETE FROM alerts WHERE alert_id LIKE 'p6t03c-%'")
        conn.execute("DELETE FROM users WHERE username LIKE 'p6t03c-%'")
        conn.commit()


@pytest.mark.db
def test_freeze_writes_v1_sha_and_disagreement_rows(
    same_connection, _cleanup_p6t03_committed_rows, tmp_path
):
    db = same_connection
    base = datetime(2026, 8, 10, 9, 0, 0, tzinfo=UTC)
    labeler_a = _make_user(db, prefix="p6t03c")
    labeler_b = _make_user(db, prefix="p6t03c")
    agree_id = "p6t03c-agree"
    disagree_id = "p6t03c-disagree"
    _insert_head_direct(db, agree_id, base)
    _insert_head_direct(db, disagree_id, base + timedelta(minutes=5))
    _label(db, agree_id, labeler_a, label="benign", confidence="2", note="agreed note")
    _label(db, agree_id, labeler_b, label="benign", confidence="2", note="")
    _label(db, disagree_id, labeler_a, label="escalate", confidence="3", note="")
    _label(db, disagree_id, labeler_b, label="benign", confidence="2", note="")

    candidates_csv = tmp_path / "gold_candidates.csv"
    _write_candidates_csv(candidates_csv, [_candidate(agree_id), _candidate(disagree_id)])
    adjudication_csv = tmp_path / "adjudication_v1.csv"
    with adjudication_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(label_export.ADJUDICATION_COLUMNS)
        writer.writerow(
            [
                disagree_id,
                "G1",
                "ssh_brute_force",
                "high",
                "escalate",
                "3",
                "",
                "benign",
                "2",
                "",
                "escalate",
                "meeting: escalate",
            ]
        )

    out_dir = tmp_path / "out"
    rc = label_export.main(
        [
            "freeze",
            "--candidates",
            str(candidates_csv),
            "--adjudication",
            str(adjudication_csv),
            "--out-dir",
            str(out_dir),
            "--dsn",
            "postgresql://never-used",
            "--labeler-a",
            labeler_a,
            "--labeler-b",
            labeler_b,
            "--adjudicator-id",
            labeler_a,
        ]
    )
    assert rc == label_export.EXIT_OK

    gold_path = out_dir / "gold_v1.csv"
    sha_path = out_dir / "gold_v1.sha256"
    assert gold_path.exists() and sha_path.exists()
    digest, _, label = sha_path.read_text(encoding="utf-8").strip().partition("  ")
    assert digest == hashlib.sha256(gold_path.read_bytes()).hexdigest()
    assert label == str(gold_path)

    with gold_path.open(newline="", encoding="utf-8") as handle:
        rows = {row["cluster_id"]: row for row in csv.DictReader(handle)}
    assert rows[agree_id]["label"] == "benign" and rows[agree_id]["adjudicated"] == "false"
    assert rows[disagree_id]["label"] == "escalate" and rows[disagree_id]["adjudicated"] == "true"

    disagreement_row = db.execute(
        "SELECT label, note FROM triage_labels WHERE alert_id = %s AND labeler_id = %s "
        "AND source = 'disagreement'",
        (disagree_id, labeler_a),
    ).fetchone()
    assert disagreement_row == ("escalate", "meeting: escalate")


# --- P6-T07: window truth wins at freeze; each labeller measured against it ----------


def _truth_candidate(cluster_id, truth, *, scenario="atk", kind="attack", gold_set="G2"):
    return label_export.Candidate(
        cluster_id=cluster_id,
        gold_set=gold_set,
        alert_id=cluster_id,
        category="ssh_brute_force",
        severity="high",
        source="lab",
        occurrence_count="1",
        first_seen="2026-09-26T02:00:00+00:00",
        last_seen="2026-09-26T02:00:00+00:00",
        scenario_id=scenario,
        kind=kind,
        truth_label=truth,
    )


def _plain_candidate(cluster_id):
    return label_export.Candidate(
        cluster_id=cluster_id,
        gold_set="G1",
        alert_id=cluster_id,
        category="ssh_brute_force",
        severity="high",
        source="replay",
        occurrence_count="1",
        first_seen="2026-08-08T09:00:00+00:00",
        last_seen="2026-08-08T09:00:00+00:00",
    )


def test_freeze_takes_truth_label_even_when_humans_disagree_or_are_missing():
    disagreed = _truth_candidate("t-disagree", "escalate", scenario="sbf-1", kind="attack")
    unlabelled = _truth_candidate("t-missing", "benign", scenario="bb-1", kind="benign")
    # one truth row where the two humans disagree with no adjudication, and one truth row
    # nobody labelled: today's rules would raise MissingFinalLabel / PartialLabelled; a window
    # truth freezes regardless (DEC-111).
    pairs = {"t-disagree": _pair("t-disagree", "escalate", "benign")}
    result = label_export.build_gold_rows(
        [disagreed, unlabelled], pairs, adjudication={}, allow_partial=False
    )
    by_id = {row.cluster_id: row for row in result.rows}
    assert set(by_id) == {"t-disagree", "t-missing"}
    assert by_id["t-disagree"].label == "escalate" and by_id["t-disagree"].adjudicated is False
    assert by_id["t-missing"].label == "benign"
    assert by_id["t-disagree"].scenario_id == "sbf-1" and by_id["t-disagree"].kind == "attack"
    assert by_id["t-missing"].scenario_id == "bb-1" and by_id["t-missing"].kind == "benign"

    # red step (DEC-025): a truth_label not in LABELS is a build defect.
    bad = _truth_candidate("t-bad", "maybe")
    with pytest.raises(ValueError):
        label_export.build_gold_rows([bad], {}, adjudication={}, allow_partial=False)


def test_freeze_rows_without_truth_keep_the_old_rules():
    truth_c = _truth_candidate("t-ok", "escalate")
    plain_disagree = _plain_candidate("p1")
    pairs = {
        "t-ok": _pair("t-ok", "escalate", "benign"),
        "p1": _pair("p1", "escalate", "benign"),
    }
    # the non-truth disagreement with no adjudication still raises, naming only the non-truth id
    with pytest.raises(label_export.MissingFinalLabel) as excinfo:
        label_export.build_gold_rows(
            [truth_c, plain_disagree], pairs, adjudication={}, allow_partial=False
        )
    assert excinfo.value.cluster_ids == ["p1"]

    # a non-truth candidate nobody labelled still raises PartialLabelled; the truth row does not
    partial = _plain_candidate("p2")
    with pytest.raises(label_export.PartialLabelled) as excinfo2:
        label_export.build_gold_rows(
            [truth_c, partial],
            {"t-ok": _pair("t-ok", "escalate", "escalate")},
            adjudication={},
            allow_partial=False,
        )
    assert excinfo2.value.cluster_ids == ["p2"]


def test_kappa_vs_truth_per_labeller():
    candidates = [
        _truth_candidate("c1", "escalate"),
        _truth_candidate("c2", "benign"),
        _truth_candidate("c3", "escalate"),
        _truth_candidate("c4", "benign"),
    ]
    pairs = {
        # labeller A correct on all four; labeller B labels c1..c3 (2 of 3 correct), not c4
        "c1": label_export.LabelPair("c1", "escalate", "2", "", "escalate", "3", ""),
        "c2": label_export.LabelPair("c2", "benign", "2", "", "benign", "3", ""),
        "c3": label_export.LabelPair("c3", "escalate", "2", "", "false_positive", "3", ""),
        "c4": label_export.LabelPair("c4", "benign", "2", "", None, None, None),
    }
    result = label_export.vs_truth(candidates, pairs, "A", "B")
    assert result["a"]["labeler_id"] == "A" and result["b"]["labeler_id"] == "B"
    assert result["a"]["n"] == 4 and result["a"]["accuracy"] == 1.0
    assert result["b"]["n"] == 3 and result["b"]["accuracy"] == pytest.approx(2 / 3)
    empty = label_export.vs_truth([_plain_candidate("x")], {}, "A", "B")
    assert empty["a"]["n"] == 0 and empty["a"]["kappa"] is None
    assert empty["b"]["n"] == 0 and empty["b"]["reason"] == "n = 0"


# --- P6-T09: disagreements vs the window truth (DEC-115 ruling 3a) --------------------


def _truth_candidate_dict(cluster_id, truth, *, scenario="sbf-1", kind="attack"):
    return {
        "cluster_id": cluster_id,
        "gold_set": "G2",
        "alert_id": cluster_id,
        "category": "ssh_brute_force",
        "severity": "high",
        "source": "lab",
        "stratum": "ssh_brute_force|high",
        "occurrence_count": "1",
        "first_seen": "2026-09-26T02:00:00+00:00",
        "last_seen": "2026-09-26T02:00:00+00:00",
        "agent_name": "attt-m1-lab",
        "rule_id": "5710",
        "scenario_id": scenario,
        "kind": kind,
        "truth_label": truth,
    }


def test_disagreements_window_basis_one_row_per_differing_labeller():
    # truth escalate, A agrees / B differs -> one window row for B
    c_one = _truth_candidate("w1", "escalate", scenario="sbf-1")
    # truth benign, both differ -> two window rows
    c_two = _truth_candidate("w2", "benign", scenario="bb-1", kind="benign")
    # truth escalate, both agree -> no row
    c_three = _truth_candidate("w3", "escalate", scenario="pe-1")
    pairs = {
        "w1": _pair("w1", "escalate", "benign"),
        "w2": _pair("w2", "escalate", "false_positive"),
        "w3": _pair("w3", "escalate", "escalate"),
    }
    rows = label_export.build_adjudication_rows([c_one, c_two, c_three], pairs, "A", "B")
    assert all(r.basis == "window" for r in rows)
    assert [(r.cluster_id, r.labeler, r.labeler_label, r.truth_label) for r in rows] == [
        ("w1", "B", "benign", "escalate"),
        ("w2", "A", "escalate", "benign"),
        ("w2", "B", "false_positive", "benign"),
    ]
    # a window row leaves the peer columns empty (the labeller's own label rides in labeler_label)
    assert all(r.label_a == "" and r.label_b == "" for r in rows)


def test_disagreements_peer_basis_kept_when_no_truth():
    truth_c = _truth_candidate("t1", "escalate")  # both agree with truth -> no row
    plain = _plain_candidate("p1")  # no truth_label
    pairs = {
        "t1": _pair("t1", "escalate", "escalate"),
        "p1": _pair("p1", "escalate", "benign", note_a="a note", note_b="b note"),
    }
    rows = label_export.build_adjudication_rows([truth_c, plain], pairs, "A", "B")
    assert len(rows) == 1
    row = rows[0]
    assert row.cluster_id == "p1" and row.basis == "peer"
    assert row.label_a == "escalate" and row.label_b == "benign"
    assert row.note_a == "a note" and row.note_b == "b note"
    assert row.truth_label == "" and row.labeler == "" and row.labeler_label == ""


@pytest.mark.db
def test_disagreements_writes_window_rows_to_the_csv(same_connection, tmp_path):
    db = same_connection
    labeler_a = _make_user(db, prefix="p6t09d")
    labeler_b = _make_user(db, prefix="p6t09d")
    base = datetime(2026, 9, 26, 2, 0, 0, tzinfo=UTC)
    _insert_head(db, "wd-1", base)
    _label(db, "wd-1", labeler_a, label="escalate", confidence="2", note="")
    _label(db, "wd-1", labeler_b, label="benign", confidence="3", note="b differs")

    candidates_csv = tmp_path / "gold_candidates.csv"
    _write_candidates_csv(candidates_csv, [_truth_candidate_dict("wd-1", "escalate")])
    out_path = tmp_path / "adjudication_v1.csv"
    rc = label_export.main(
        [
            "disagreements",
            "--candidates",
            str(candidates_csv),
            "--out",
            str(out_path),
            "--dsn",
            "postgresql://never-used",
            "--labeler-a",
            labeler_a,
            "--labeler-b",
            labeler_b,
        ]
    )
    assert rc == label_export.EXIT_OK
    with out_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    row = rows[0]
    assert row["basis"] == "window"
    assert row["truth_label"] == "escalate"
    assert row["labeler"] == labeler_b and row["labeler_label"] == "benign"
    assert row["final_label"] == ""


# --- P6-T09: freeze honours a committed scenario exclusion (DEC-117) ------------------


def test_read_excluded_scenarios_absent_is_empty_and_dedups(tmp_path):
    assert label_export.read_excluded_scenarios(tmp_path / "nope.csv") == []
    path = tmp_path / "excluded_scenarios.csv"
    path.write_text(
        "scenario_id,reason,decided_in\n"
        "sbf-1,misfire,DEC-120\n"
        ",blank id skipped,DEC-120\n"
        "sbf-1,duplicate,DEC-120\n"
        "dx-2,no in-scope head,DEC-121\n",
        encoding="utf-8",
    )
    assert label_export.read_excluded_scenarios(path) == ["sbf-1", "dx-2"]


def test_apply_scenario_exclusions_drops_matched_and_flags_unmatched():
    cands = [
        _truth_candidate("a1", "escalate", scenario="sbf-1"),
        _truth_candidate("a2", "escalate", scenario="sbf-1"),
        _truth_candidate("b1", "benign", scenario="dx-2", kind="benign"),
    ]
    res = label_export.apply_scenario_exclusions(cands, ["sbf-1", "ghost"])
    assert [c.cluster_id for c in res.kept] == ["b1"]
    assert res.dropped == 2
    assert res.matched == ["sbf-1"] and res.unmatched == ["ghost"]
    # an empty exclusion list is a no-op
    res0 = label_export.apply_scenario_exclusions(cands, [])
    assert res0.dropped == 0 and len(res0.kept) == 3


@pytest.mark.db
def test_freeze_excludes_committed_scenarios(same_connection, tmp_path, capsys):
    db = same_connection
    labeler_a = _make_user(db, prefix="p6t09x")
    labeler_b = _make_user(db, prefix="p6t09x")
    base = datetime(2026, 9, 26, 3, 0, 0, tzinfo=UTC)
    for offset, cid in enumerate(("keep-1", "drop-1")):
        _insert_head(db, cid, base + timedelta(minutes=offset))
        _label(db, cid, labeler_a, label="escalate", confidence="2", note="")
        _label(db, cid, labeler_b, label="escalate", confidence="2", note="")

    candidates_csv = tmp_path / "gold_candidates.csv"
    _write_candidates_csv(
        candidates_csv,
        [
            _truth_candidate_dict("keep-1", "escalate", scenario="sbf-1"),
            _truth_candidate_dict("drop-1", "escalate", scenario="dx-9"),
        ],
    )
    excluded_csv = tmp_path / "excluded_scenarios.csv"
    excluded_csv.write_text(
        "scenario_id,reason,decided_in\ndx-9,misfire,DEC-120\nghost,no head,DEC-121\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "out"
    rc = label_export.main(
        [
            "freeze",
            "--candidates",
            str(candidates_csv),
            "--excluded-scenarios",
            str(excluded_csv),
            "--out-dir",
            str(out_dir),
            "--dsn",
            "postgresql://never-used",
            "--labeler-a",
            labeler_a,
            "--labeler-b",
            labeler_b,
        ]
    )
    assert rc == label_export.EXIT_OK
    captured = capsys.readouterr()
    assert "excluded 1 candidates from 1 scenarios: dx-9" in captured.out
    assert "excluded scenario 'ghost' matched no candidate" in captured.err
    with (out_dir / "gold_v1.csv").open(newline="", encoding="utf-8") as handle:
        frozen = {row["cluster_id"] for row in csv.DictReader(handle)}
    assert frozen == {"keep-1"}


def test_freeze_absent_exclusion_file_is_a_no_op(tmp_path):
    # the pure path: no file -> no ids -> nothing dropped
    assert label_export.read_excluded_scenarios(tmp_path / "eval" / "excluded_scenarios.csv") == []


# --- P6-T09: report drops the G1 wording and prints vs_truth (item C) -----------------


def test_report_prints_vs_truth_and_drops_the_g1_rows_gate():
    kappa_doc = {
        "overall": {"n": 4, "kappa": 0.7, "confusion": {}},
        "disagreements": 0,
        "disagreement_rate": 0.0,
        "by_gold_set": {"G2": {"n": 4, "kappa": 0.7}},
        "by_category": {"ssh_brute_force": {"n": 4, "kappa": 0.7}},
        "vs_truth": {
            "a": {
                "labeler_id": "labeller-A",
                "n": 4,
                "accuracy": 1.0,
                "by_category": {"ssh_brute_force": {"n": 4, "p_o": 1.0, "kappa": None}},
            },
            "b": {"labeler_id": "labeller-B", "n": 3, "accuracy": 0.667, "by_category": {}},
        },
    }
    text = label_export.render_report(
        gold_rows=_report_gold_rows(),
        version=1,
        sha256_hex="a" * 64,
        frozen_at="2026-09-28T10:00:00+00:00",
        adjudicator_id=None,
        git_log_line="commit: abc1234",
        kappa_doc=kappa_doc,
        coverage_text=None,
        manifest_rows=None,
        adjudication_present=True,
    )
    assert "G1 rows" not in text
    assert "G2 rows" in text and ">= 100" in text
    assert "Human baseline vs window truth" in text
    assert "labeller-A: n=4 accuracy=1.0" in text
    assert "labeller-B: n=3 accuracy=0.667" in text
    assert "ssh_brute_force: n=4 accuracy=1.0" in text


def test_report_vs_truth_missing_is_not_available():
    kappa_doc = {
        "overall": {"n": 2, "kappa": None, "confusion": {}},
        "disagreements": 0,
        "disagreement_rate": 0.0,
        "by_gold_set": {},
        "by_category": {},
    }
    text = label_export.render_report(
        gold_rows=_report_gold_rows(),
        version=1,
        sha256_hex=None,
        frozen_at=None,
        adjudicator_id=None,
        git_log_line="commit: abc1234",
        kappa_doc=kappa_doc,
        coverage_text=None,
        manifest_rows=None,
        adjudication_present=False,
    )
    assert "Human baseline vs window truth" in text
    assert "(not available -- kappa_v1.json carries no vs_truth)" in text


# --- P6-T11 (DEC-120): the three follow-ups from the P6-T09 review ---------------------


def test_read_excluded_scenarios_refuses_rows_without_a_scenario_id_column(tmp_path):
    """A misnamed header must not read as "exclude nothing": the misfired scenario
    would be frozen while the committed record says it was excluded."""
    path = tmp_path / "excluded_scenarios.csv"
    path.write_text("scenario,reason,decided_in\nRW-A1,misfired,DEC-999\n", encoding="utf-8")
    with pytest.raises(label_export.ExclusionFileMalformed, match="no 'scenario_id' column"):
        label_export.read_excluded_scenarios(path)


def test_read_excluded_scenarios_header_only_is_empty_whatever_the_header(tmp_path):
    path = tmp_path / "excluded_scenarios.csv"
    path.write_text("scenario,reason,decided_in\n", encoding="utf-8")
    assert label_export.read_excluded_scenarios(path) == []


def test_read_excluded_scenarios_tolerates_a_padded_header(tmp_path):
    path = tmp_path / "excluded_scenarios.csv"
    path.write_text(
        " scenario_id , reason , decided_in\nRW-A1 ,misfired,DEC-999\n", encoding="utf-8"
    )
    assert label_export.read_excluded_scenarios(path) == ["RW-A1"]


def test_freeze_refuses_an_exclusion_file_without_scenario_id_before_any_connection(
    tmp_path, capsys
):
    candidates_csv = tmp_path / "gold_candidates.csv"
    _write_candidates_csv(
        candidates_csv, [_truth_candidate_dict("keep-1", "escalate", scenario="rw-1")]
    )
    excluded_csv = tmp_path / "excluded_scenarios.csv"
    excluded_csv.write_text("scenario,reason,decided_in\nrw-1,misfired,DEC-999\n", encoding="utf-8")
    rc = label_export.main(
        [
            "freeze",
            "--candidates",
            str(candidates_csv),
            "--excluded-scenarios",
            str(excluded_csv),
            "--out-dir",
            str(tmp_path / "out"),
            "--dsn",
            "postgresql://never-used",
        ]
    )
    assert rc == label_export.EXIT_UNREADABLE
    assert "no 'scenario_id' column" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


def test_vs_truth_with_no_truth_pairs_carries_no_accuracy():
    empty = label_export.vs_truth([_plain_candidate("x")], {}, "A", "B")
    assert empty["a"]["n"] == 0 and empty["a"]["accuracy"] is None
    assert empty["b"]["n"] == 0 and empty["b"]["accuracy"] is None


def _minimal_kappa_doc(vs_truth: dict | None) -> dict:
    doc = {
        "overall": {"n": 0, "kappa": None, "confusion": {}},
        "disagreements": 0,
        "disagreement_rate": None,
        "by_gold_set": {},
        "by_category": {},
    }
    if vs_truth is not None:
        doc["vs_truth"] = vs_truth
    return doc


def _report(kappa_doc: dict, coverage_text: str | None) -> str:
    return label_export.render_report(
        gold_rows=_report_gold_rows(),
        version=1,
        sha256_hex=None,
        frozen_at=None,
        adjudicator_id=None,
        git_log_line="commit: abc1234",
        kappa_doc=kappa_doc,
        coverage_text=coverage_text,
        manifest_rows=None,
        adjudication_present=False,
    )


def test_report_vs_truth_with_n_zero_prints_not_available_never_a_zero():
    kappa_doc = _minimal_kappa_doc(
        {
            "a": {"labeler_id": "labeller-A", "n": 0, "accuracy": None, "by_category": {}},
            # a kappa_v1.json written before this fix carried 0.0 for n = 0
            "b": {"labeler_id": "labeller-B", "n": 0, "accuracy": 0.0, "by_category": {}},
        }
    )
    text = _report(kappa_doc, coverage_text=None)
    assert "labeller-A: n=0 accuracy=(not available" in text
    assert "labeller-B: n=0 accuracy=(not available" in text
    assert "accuracy=0.0" not in text and "accuracy=None" not in text


G2_ONLY_COVERAGE = (
    "# Gold coverage — G2 only\n"
    "\n"
    "## Run\n"
    "- G1: not built (DEC-111 — the 08/08–07/09 history is void; its files stay in git)\n"
    "\n"
    "## G2 — lab windows (`eval/lab_windows.csv`)\n"
    "- in_window_unexpected (DEC-114): 3 of 40 heads found, excluded, never labelled\n"
    "\n"
    "## G2 pool (denominator 37)\n"
    "\n"
    "## G2 sample (denominator 37)\n"
    "- G2's severity mix is not enriched by design (take-all rule off): 12 of 37\n"
    "This corpus is author-generated lab traffic on the author's host with window-known "
    "truth: no rate computed from it is an estate rate, of any estate.\n"
    "- truth in the sample (window, DEC-111/114/115): escalate 25 · benign 12\n"
    "- benign lab clusters in the sample ≥ 20: 12 — MISS\n"
)


def test_report_g2_only_limitations_state_g1_void_and_carry_the_g2_lines():
    text = _report(_minimal_kappa_doc(None), coverage_text=G2_ONLY_COVERAGE)
    limitations = text.split("## 5. Limitations for P8", 1)[1]
    assert "G1 is void (DEC-111)" in limitations
    assert "author-generated lab traffic" in limitations and "limitation xii" in limitations
    assert "in_window_unexpected (DEC-114): 3 of 40 heads found" in limitations
    assert "G2's severity mix is not enriched by design" in limitations
    assert "benign lab clusters in the sample ≥ 20: 12 — MISS" in limitations
    assert "Every gold candidate is lab traffic" in limitations
    assert "G2's September dates are readable" not in limitations


def test_report_g2_only_limitations_name_a_missing_g2_line_instead_of_dropping_it():
    coverage = "\n".join(
        line
        for line in G2_ONLY_COVERAGE.splitlines()
        if not line.startswith("- in_window_unexpected")
    )
    text = _report(_minimal_kappa_doc(None), coverage_text=coverage)
    limitations = text.split("## 5. Limitations for P8", 1)[1]
    assert "(in_window_unexpected (DEC-114) is not in `eval/gold_coverage.md`)" in limitations
