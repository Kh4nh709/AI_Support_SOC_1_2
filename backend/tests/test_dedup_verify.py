"""Offline tests for eval/dedup_verify.py.

No archive is needed: every test builds JSONL files in `tmp_path` from
`archive_line_5503.json`'s `event.original` (one real archive line, minus its
indexer envelope) with `id`, `timestamp`, `data.srcip` and `data.dstuser`
edited, reproducing phase-2's "Ví dụ trên mẫu thật" A1-A8 table as three files
per card design note 5 -- file A (A1-A6, six literal rows), file B (A7,
generated: 1,001 alerts one second apart), file C (A8, generated: 31 alerts
ten minutes apart over five hours). These are not synthetic burst fixtures
(DEC-014 replaced those for *measurement*); they are unit tests of a table the
spec already wrote down.

Every DEC-025 failing case in the card's acceptance 2 is reproduced here as a
real, permanent test (`dataclasses.replace` on a fixture `Config`, never a
literal edited into the product code) rather than a one-off manual check, so
`make test` keeps proving the boundary rather than merely having proved it
once.
"""

from __future__ import annotations

import copy
import dataclasses
import importlib.util
import json
import sys
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from app.infra import config as config_module

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "eval" / "dedup_verify.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

# eval/ is a composition root outside backend/ and is not on sys.path, so the
# script is loaded by path rather than imported (mirrors test_indexer_probe.py).
_spec = importlib.util.spec_from_file_location("dedup_verify", SCRIPT_PATH)
dedup_verify = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = dedup_verify
_spec.loader.exec_module(dedup_verify)


# --- fixture construction ---------------------------------------------------

_EVENT_ORIGINAL = json.loads(
    json.loads((FIXTURES / "archive_line_5503.json").read_text(encoding="utf-8"))["event"][
        "original"
    ]
)

#: A1's anchor instant. Any zoned instant works; +07:00 with no colon in the
#: offset reproduces the manager's own timestamp shape (phase-1 Khối 3's
#: `+0700` trap) instead of a friendlier format the parser never actually sees.
T0 = datetime(2026, 8, 16, 17, 56, 56, 0, tzinfo=timezone(timedelta(hours=7)))


def _fmt(instant: datetime) -> str:
    return instant.strftime("%Y-%m-%dT%H:%M:%S.000") + instant.strftime("%z")


def _line(
    alert_id: str, instant: datetime, *, srcip: str | None = None, dstuser: str | None = None
) -> dict:
    doc = copy.deepcopy(_EVENT_ORIGINAL)
    doc["id"] = alert_id
    doc["timestamp"] = _fmt(instant)
    if srcip is not None:
        doc["data"]["srcip"] = srcip
    if dstuser is not None:
        doc["data"]["dstuser"] = dstuser
    return doc


def _write_jsonl(path: Path, docs: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(doc) for doc in docs) + "\n", encoding="utf-8")


def _file_a(path: Path) -> None:
    """A1-A6, six literal rows (design note 5)."""
    docs = [
        _line("a1", T0),
        _line("a2", T0 + timedelta(minutes=1, seconds=34)),
        _line("a3", T0 + timedelta(minutes=4, seconds=14)),
        _line("a4", T0 + timedelta(seconds=44), dstuser="someone-else"),
        _line("a5", T0 + timedelta(seconds=44), srcip="10.0.0.5"),
        _line("a6", T0 + timedelta(minutes=28, seconds=4)),
    ]
    _write_jsonl(path, docs)


def _file_b(path: Path) -> None:
    """A7, generated: 1,001 alerts on one key, one second apart."""
    docs = [_line(f"b{i}", T0 + timedelta(seconds=i)) for i in range(1001)]
    _write_jsonl(path, docs)


def _file_c(path: Path) -> None:
    """A8, generated: 31 alerts on one key, every 10 minutes for 5 hours."""
    docs = [_line(f"c{i}", T0 + timedelta(minutes=10 * i)) for i in range(31)]
    _write_jsonl(path, docs)


def _cfg(**overrides) -> config_module.Config:
    return dataclasses.replace(config_module.Config(), **overrides)


def _cluster_sizes_by_key(clusters) -> dict:
    sizes: dict = {}
    for cluster in clusters:
        sizes.setdefault(cluster.key, []).append(cluster.count)
    return sizes


def _fold(path: Path, cfg: config_module.Config | None = None):
    stats = dedup_verify.read_archive(path)
    return dedup_verify.fold_clusters(stats.alerts, cfg or _cfg()), stats


# --- A1-A6: file A -----------------------------------------------------------


def test_file_a_three_clusters_two_keys(tmp_path):
    path = tmp_path / "a.jsonl"
    _file_a(path)
    clusters, stats = _fold(path)

    assert stats.parsed == 6
    assert stats.rejected == 0
    assert len(clusters) == 3

    sizes = _cluster_sizes_by_key(clusters)
    assert len(sizes) == 2
    key1_sizes, key2_sizes = None, None
    for key, values in sizes.items():
        if key[1] == "10.0.0.5":
            key2_sizes = values
        else:
            key1_sizes = values
    assert key1_sizes == [4, 1], "A1+A4+A2+A3 join (size 4); A6 opens a fresh cluster (size 1)"
    assert key2_sizes == [1], "A5 changes srcip -> a second key, size 1"


def test_file_a_a4_dstuser_does_not_split_the_key(tmp_path):
    """The cluster key has no user column (design note 5) -- A4's different
    `dstuser` must still join A1's cluster, not open a third key."""
    path = tmp_path / "a.jsonl"
    _file_a(path)
    clusters, _ = _fold(path)
    assert len({cluster.key for cluster in clusters}) == 2


def test_file_a_idle_gap_30min_absorbs_a6(tmp_path):
    """Failing case (acceptance 2): DEDUP_IDLE_GAP_MINUTES=30 -> A6 (23m50s
    after A3) now joins instead of opening a cluster -- file A drops to 2."""
    path = tmp_path / "a.jsonl"
    _file_a(path)
    clusters, _ = _fold(path, cfg=_cfg(DEDUP_IDLE_GAP_MINUTES=30))
    assert len(clusters) == 2
    assert sorted(cluster.count for cluster in clusters) == [
        1,
        5,
    ], "A6 must join the size-4 cluster"


def test_file_a_idle_gap_20min_still_opens_a6(tmp_path):
    """Discriminates 'the predicate is read from cfg' from 'the predicate is
    simply disabled': at 20 minutes (still under A6's real 23m50s gap) A6 must
    still open a fresh cluster, same shape as the 15-minute default -- a fold
    that always joins (idle gap never checked) would wrongly report 2 here."""
    path = tmp_path / "a.jsonl"
    _file_a(path)
    clusters, _ = _fold(path, cfg=_cfg(DEDUP_IDLE_GAP_MINUTES=20))
    assert len(clusters) == 3
    assert sorted(cluster.count for cluster in clusters) == [1, 1, 4]


# --- A7: file B ---------------------------------------------------------------


def test_file_b_two_clusters_max_size_1000(tmp_path):
    path = tmp_path / "b.jsonl"
    _file_b(path)
    clusters, stats = _fold(path)

    assert stats.parsed == 1001
    assert len(clusters) == 2
    assert [cluster.count for cluster in clusters] == [1000, 1]
    assert clusters[0].closed_by == dedup_verify.REASON_MAX_SIZE


def test_file_b_max_size_2000_yields_one_cluster(tmp_path):
    """Failing case (acceptance 2): MAX_CLUSTER_SIZE=2000 -> file B gives 1."""
    path = tmp_path / "b.jsonl"
    _file_b(path)
    clusters, _ = _fold(path, cfg=_cfg(MAX_CLUSTER_SIZE=2000))
    assert len(clusters) == 1
    assert clusters[0].count == 1001


def test_file_b_max_size_500_still_splits(tmp_path):
    """Discriminates 'the ceiling is read from cfg' from 'the ceiling is
    simply disabled': at 500 (below the 1,001-alert span) the size cap must
    still bind, giving three clusters -- a fold that never checks the ceiling
    would wrongly report 1 here, same as the 2000-override case above."""
    path = tmp_path / "b.jsonl"
    _file_b(path)
    clusters, _ = _fold(path, cfg=_cfg(MAX_CLUSTER_SIZE=500))
    assert [cluster.count for cluster in clusters] == [500, 500, 1]


# --- A8: file C ---------------------------------------------------------------


def test_file_c_two_clusters_max_age_4h(tmp_path):
    path = tmp_path / "c.jsonl"
    _file_c(path)
    clusters, stats = _fold(path)

    assert stats.parsed == 31
    assert len(clusters) == 2
    assert [cluster.count for cluster in clusters] == [25, 6]
    assert clusters[0].closed_by == dedup_verify.REASON_MAX_AGE


def test_file_c_exactly_4h_still_joins(tmp_path):
    """The 25th alert lands at exactly +4h00m; phase-2's query is
    `first_seen_at >= now() - 4h`, i.e. exactly 4h still joins (design note 5)."""
    path = tmp_path / "c.jsonl"
    _file_c(path)
    clusters, _ = _fold(path)
    assert clusters[0].count == 25, "the 25th alert (+4h00m) must still be inside the first cluster"


def test_file_c_max_age_6h_yields_one_cluster(tmp_path):
    """Failing case (acceptance 2): MAX_CLUSTER_AGE_HOURS=6 -> file C gives 1."""
    path = tmp_path / "c.jsonl"
    _file_c(path)
    clusters, _ = _fold(path, cfg=_cfg(MAX_CLUSTER_AGE_HOURS=6))
    assert len(clusters) == 1
    assert clusters[0].count == 31


def test_file_c_max_age_3h_still_splits(tmp_path):
    """Discriminates 'the ceiling is read from cfg' from 'the ceiling is
    simply disabled': at 3 hours (below the file's 5-hour span) the age cap
    must still bind -- a fold that never checks it would wrongly report 1
    cluster here, same as the disabled-predicate case a 6-hour override alone
    cannot tell apart from a correct one (both give 1, since 5h < 6h either way)."""
    path = tmp_path / "c.jsonl"
    _file_c(path)
    clusters, _ = _fold(path, cfg=_cfg(MAX_CLUSTER_AGE_HOURS=3))
    assert [cluster.count for cluster in clusters] == [19, 12]


# --- rejected lines ------------------------------------------------------------


def test_rejected_lines_counted_and_excluded_not_guessed(tmp_path):
    path = tmp_path / "mixed.jsonl"
    good = _line("g1", T0)
    missing_id = copy.deepcopy(_EVENT_ORIGINAL)
    del missing_id["id"]
    missing_id["timestamp"] = _fmt(T0 + timedelta(minutes=1))
    with path.open("w", encoding="utf-8") as handle:
        handle.write(json.dumps(good) + "\n")
        handle.write(json.dumps(missing_id) + "\n")
        handle.write("not valid json at all\n")
        handle.write("[1, 2, 3]\n")
        handle.write("\n")  # blank line: not counted at all

    stats = dedup_verify.read_archive(path)
    assert stats.lines == 4, "the blank line is not a real archive record"
    assert stats.parsed == 1
    assert stats.rejected == 3
    assert stats.rejected_by_reason["id"] == 1
    assert stats.rejected_by_reason["invalid_json"] == 1
    assert stats.rejected_by_reason["not_an_object"] == 1


# --- ratio, per-day buckets, storm day -----------------------------------------


def test_ratio_is_parsed_over_clusters(tmp_path):
    path = tmp_path / "b.jsonl"
    _file_b(path)
    stats = dedup_verify.read_archive(path)
    clusters = dedup_verify.fold_clusters(stats.alerts, _cfg())
    report = dedup_verify.build_report(path, stats, clusters, _cfg(), expect=2, tolerance_pct=1.0)
    assert report["ratio"] == pytest.approx(1001 / 2)


def test_clusters_per_day_uses_display_tz_not_utc(tmp_path):
    """17:56:56 on 16/08 in UTC+7 is already 17/08 in UTC -- Config.DISPLAY_TZ
    (Asia/Ho_Chi_Minh) must be the boundary, not the alert's stored UTC instant."""
    path = tmp_path / "a.jsonl"
    _file_a(path)  # all six rows anchored on T0 = 2026-08-16T17:56:56+07:00
    stats = dedup_verify.read_archive(path)
    cfg = _cfg()
    clusters = dedup_verify.fold_clusters(stats.alerts, cfg)
    per_day = dedup_verify.clusters_per_day(clusters, dedup_verify.ZoneInfo(cfg.DISPLAY_TZ))
    assert per_day == {"2026-08-16": 3}
    # the stored instant is already past midnight UTC -- confirms the fold kept UTC internally.
    assert stats.alerts[0].alert_time.astimezone(UTC).date().isoformat() == "2026-08-16"


def test_storm_day_report_fields(tmp_path):
    path = tmp_path / "storm.jsonl"
    docs = [_line(f"s{i}", T0 + timedelta(seconds=i)) for i in range(1001)]  # T0 is 16/08 local
    _write_jsonl(path, docs)
    stats = dedup_verify.read_archive(path)
    cfg = _cfg()
    clusters = dedup_verify.fold_clusters(stats.alerts, cfg)
    report = dedup_verify.storm_day_report(
        stats.alerts, clusters, dedup_verify.ZoneInfo(cfg.DISPLAY_TZ), dedup_verify.STORM_DAY
    )
    assert report["alerts"] == 1001
    assert report["clusters"] == 2
    assert report["largest_cluster_size"] == 1000
    assert report["clusters_hit_max_size"] == 1
    assert report["clusters_hit_max_age"] == 0


# --- verdict boundaries ----------------------------------------------------------


def test_verdict_boundary_within_tolerance_passes():
    v = dedup_verify.compute_verdict(clusters=202, expect=200, tolerance_pct=1.0)
    assert v["passed"] is True  # 202 is exactly +1.00%, the tolerance is inclusive


def test_verdict_boundary_just_outside_tolerance_fails():
    v = dedup_verify.compute_verdict(clusters=203, expect=200, tolerance_pct=1.0)
    assert v["passed"] is False  # 203 is +1.50%


# --- CLI: main() ---------------------------------------------------------------


def test_main_missing_archive_file_exits_2_and_prints_owner_procedure(tmp_path, capsys):
    missing = tmp_path / "does-not-exist.jsonl"
    rc = dedup_verify.main(["--archive-file", str(missing), "--expect", "2778"])
    assert rc == dedup_verify.EXIT_ARCHIVE
    captured = capsys.readouterr()
    assert "sudo sh -c" in captured.err
    assert captured.out == ""


def test_main_archive_path_is_a_directory_exits_2(tmp_path, capsys):
    rc = dedup_verify.main(["--archive-file", str(tmp_path), "--expect", "2778"])
    assert rc == dedup_verify.EXIT_ARCHIVE
    assert "sudo sh -c" in capsys.readouterr().err


def test_main_json_output_matches_fold(tmp_path, monkeypatch):
    path = tmp_path / "a.jsonl"
    _file_a(path)
    monkeypatch.setattr(config_module, "load", lambda env_file=".env": _cfg())
    rc = dedup_verify.main(
        ["--archive-file", str(path), "--expect", "3", "--tolerance-pct", "0", "--json"]
    )
    assert rc == dedup_verify.EXIT_OK

    stats = dedup_verify.read_archive(path)
    clusters = dedup_verify.fold_clusters(stats.alerts, _cfg())
    assert len(clusters) == 3


def test_main_verdict_fail_exit_code(tmp_path, monkeypatch, capsys):
    path = tmp_path / "a.jsonl"
    _file_a(path)
    monkeypatch.setattr(config_module, "load", lambda env_file=".env": _cfg())
    rc = dedup_verify.main(
        ["--archive-file", str(path), "--expect", "999", "--tolerance-pct", "1.0"]
    )
    assert rc == dedup_verify.EXIT_VERDICT_FAIL
    assert "VERDICT: 3 vs 999" in capsys.readouterr().out


def test_no_raw_alert_content_in_stdout(tmp_path, monkeypatch, capsys):
    """The report may be pasted into a public repository (design note 3) --
    make sure a run over real-shaped data never puts srcip/dstuser on stdout."""
    path = tmp_path / "a.jsonl"
    _file_a(path)
    monkeypatch.setattr(config_module, "load", lambda env_file=".env": _cfg())
    dedup_verify.main(["--archive-file", str(path), "--expect", "3", "--tolerance-pct", "1.0"])
    out = capsys.readouterr().out
    assert "10.0.0.5" not in out
    assert "someone-else" not in out


# --- membership (P6-T01, DEC-084's first half) ----------------------------------


@pytest.mark.parametrize("build", [_file_a, _file_b, _file_c])
def test_members_match_count_and_head_is_first(tmp_path, build):
    """`count == len(members)` on every cluster, `members[0]` is the cluster's
    earliest alert (the head, by construction of the `alert_time` sort), and the
    union of every cluster's members is exactly the parsed ids -- nothing lost,
    nothing counted twice."""
    path = tmp_path / "in.jsonl"
    build(path)
    clusters, stats = _fold(path)
    by_id = {alert.alert_id: alert for alert in stats.alerts}

    seen: list[str] = []
    for cluster in clusters:
        assert cluster.count == len(cluster.members)
        assert cluster.members, "a cluster is opened by an alert, so it is never empty"
        head = by_id[cluster.members[0]]
        assert head.alert_time == cluster.first_seen
        assert all(
            by_id[member].alert_time >= head.alert_time for member in cluster.members[1:]
        ), "the head is the earliest alert of its cluster"
        assert by_id[cluster.members[-1]].alert_time == cluster.last_seen
        seen.extend(cluster.members)
    assert len(seen) == len(set(seen)) == stats.parsed
    assert set(seen) == set(by_id)


def test_json_report_carries_no_members(tmp_path):
    """The JSON report stays per-day counts (3,051 lines on the archive), never
    92,011 ids -- `members` is the fold's, not the report's."""
    path = tmp_path / "b.jsonl"
    _file_b(path)
    stats = dedup_verify.read_archive(path)
    clusters = dedup_verify.fold_clusters(stats.alerts, _cfg())
    assert clusters[0].members, "precondition: the fold did record members"
    rendered = dedup_verify.format_json(
        dedup_verify.build_report(path, stats, clusters, _cfg(), expect=2, tolerance_pct=1.0)
    )
    assert "members" not in rendered
    assert "b500" not in rendered, "no alert id of the fold leaks into the report"
