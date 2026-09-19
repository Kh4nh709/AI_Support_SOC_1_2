"""Tests for eval/build_gold.py -- G1 from the fold, G2 from the lab windows, one allocator.

Archives are JSONL files built in `tmp_path` from `archive_line_5503.json`'s
`event.original` the way `test_dedup_verify.py` builds them (`_line`,
`_write_jsonl` copied, not imported -- one test module never imports another),
with `rule.id` / `rule.level` / `rule.groups` / `rule.mitre.id` also editable so
`parse_wazuh_alert` + the real resolver yield `ssh_brute_force` / `unknown` /
`suspicious_login` / `privilege_escalation` rows across the four severities. The
allocator is tested on hand-built pools of twelve `ClusterRow`s whose expected
per-stratum sample sizes are written down by hand next to the call.

Database tests (`@pytest.mark.db`) insert heads and duplicates through
`domain.transitions.open_alert` on the `db` fixture's connection and never
commit: `open_alert` writes an append-only `audit_events` row per call, and
the session-scoped test database is shared with every other file
`make test-db` runs. `main()` is driven against that same connection by
monkeypatching `build_gold._read_only_connection`, so the uncommitted fixture
rows are visible to it and nothing outlives the test.
"""

from __future__ import annotations

import copy
import csv
import gzip
import hashlib
import importlib.util
import json
import sys
import time
from collections import Counter
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import psycopg
import pytest
from app.domain import transitions
from app.infra import config as config_module
from app.ingest.wazuh_parser import parse_wazuh_alert

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "eval" / "build_gold.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

_spec = importlib.util.spec_from_file_location("build_gold", SCRIPT_PATH)
build_gold = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = build_gold
_spec.loader.exec_module(build_gold)

SEED = build_gold.EVAL_SEED
UNKNOWN = "unknown"
SSH = "ssh_brute_force"
SUSP = "suspicious_login"
PRIV = "privilege_escalation"


# --- fixture construction ---------------------------------------------------

_EVENT_ORIGINAL = json.loads(
    json.loads((FIXTURES / "archive_line_5503.json").read_text(encoding="utf-8"))["event"][
        "original"
    ]
)

T0 = datetime(2026, 8, 16, 17, 56, 56, 0, tzinfo=timezone(timedelta(hours=7)))

#: `rule` edits that make the resolver land on each category (tiers 1 and 3).
_CATEGORY_RULE: dict[str, dict] = {
    SSH: {"mitre": ["T1110.001"], "groups": ["pam", "syslog", "authentication_failed"]},
    UNKNOWN: {"mitre": [], "groups": ["syscheck"]},
    SUSP: {"mitre": ["T1078"], "groups": ["authentication_success"]},
    PRIV: {"mitre": ["T1548"], "groups": ["sudo"]},
}
#: `rule.level` per severity band (`docs/phase-1-tiep-nhan-chuan-hoa.md:148`).
_LEVEL: dict[str, int] = {"critical": 12, "high": 8, "medium": 5, "low": 3}


def _fmt(instant: datetime) -> str:
    return instant.strftime("%Y-%m-%dT%H:%M:%S.000") + instant.strftime("%z")


def _line(
    alert_id: str,
    instant: datetime,
    *,
    srcip: str | None = None,
    dstuser: str | None = None,
    agent: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    rule_id: str | None = None,
) -> dict:
    doc = copy.deepcopy(_EVENT_ORIGINAL)
    doc["id"] = alert_id
    doc["timestamp"] = _fmt(instant)
    if srcip is not None:
        doc["data"]["srcip"] = srcip
    if dstuser is not None:
        doc["data"]["dstuser"] = dstuser
    if agent is not None:
        doc["agent"]["name"] = agent
    if category is not None:
        doc["rule"]["mitre"]["id"] = list(_CATEGORY_RULE[category]["mitre"])
        doc["rule"]["groups"] = list(_CATEGORY_RULE[category]["groups"])
    if severity is not None:
        doc["rule"]["level"] = _LEVEL[severity]
    if rule_id is not None:
        doc["rule"]["id"] = rule_id
    return doc


def _write_jsonl(path: Path, docs: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(doc) for doc in docs) + "\n", encoding="utf-8")


def _cfg(**overrides) -> config_module.Config:
    import dataclasses

    return dataclasses.replace(config_module.Config(), **overrides)


def _archive(path: Path, docs: list[dict]):
    """Write `docs`, read them back through the product parser, fold them."""
    _write_jsonl(path, docs)
    stats = build_gold.dedup_verify.read_archive(path)
    clusters = build_gold.dedup_verify.fold_clusters(stats.alerts, _cfg())
    return stats, clusters


def _mixed_docs() -> list[dict]:
    """Eight clusters, each its own srcip: four categories x a few severities,
    plus one loopback `ssh_brute_force` (excluded) and one joiner on `m1`."""
    spec = [
        ("m1", SSH, "medium", "10.0.0.1"),
        ("m2", SSH, "high", "10.0.0.2"),
        ("m3", UNKNOWN, "critical", "10.0.0.3"),
        ("m4", UNKNOWN, "medium", "10.0.0.4"),
        ("m5", UNKNOWN, "low", "10.0.0.5"),
        ("m6", SUSP, "low", "10.0.0.6"),
        ("m7", PRIV, "high", "10.0.0.7"),
        ("m8", SSH, "medium", "127.0.0.1"),
    ]
    docs = [
        _line(alert_id, T0 + timedelta(minutes=i), srcip=ip, category=cat, severity=sev)
        for i, (alert_id, cat, sev, ip) in enumerate(spec)
    ]
    docs.append(
        _line("m1b", T0 + timedelta(minutes=1), srcip="10.0.0.1", category=SSH, severity="medium")
    )
    return docs


# --- hand-built pools ---------------------------------------------------------


def _row(cluster_id: str, category: str, severity: str, *, agent_name: str = "user1-IA1803"):
    return build_gold.ClusterRow(
        cluster_id=cluster_id,
        gold_set="G1",
        alert_id=cluster_id,
        rule_id="5503",
        category=category,
        severity=severity,
        agent_name=agent_name,
        alert_user="root",
        srcip="10.0.0.1",
        dstip="",
        source="replay",
        first_seen=T0.astimezone(UTC),
        last_seen=T0.astimezone(UTC),
        occurrence_count=1,
        closed_by="",
        excluded_reason="",
    )


def _pool(spec: dict[tuple[str, str], int]) -> list:
    rows = []
    for (category, severity), n in spec.items():
        for i in range(n):
            rows.append(_row(f"{category}-{severity}-{i:03d}", category, severity))
    return rows


def _by_stratum(rows) -> Counter:
    return Counter((row.category, row.severity) for row in rows)


def _params(**overrides) -> dict:
    params = {
        "unknown_cap_pct": 40.0,
        "take_all_crit_high": True,
        "category_floor": 0,
        "seed": SEED,
    }
    params.update(overrides)
    return params


def _alloc_params(target: int, floor: int = 0, **overrides):
    p = _params(**overrides)
    return build_gold.AllocParams(
        target=target,
        floor=floor,
        unknown_cap_pct=p["unknown_cap_pct"],
        take_all_crit_high=p["take_all_crit_high"],
        category_floor=p["category_floor"],
        seed=p["seed"],
    )


# --- allocator ------------------------------------------------------------------


def test_allocate_sum_is_exact_by_largest_remainder():
    # Category totals 6 x (6, 3, 3) / 12 = 3.0, 1.5, 1.5: floors 3, 1, 1 leave one
    # to place; the .5 tie goes to privilege_escalation (resolver PRIORITY order)
    # -> 3, 1, 2. Within ssh, 3 x (3, 3) / 6 = 1.5, 1.5 -> medium first -> 2, 1.
    # `round()` would give 3, 2, 2 = 7 rows for a target of 6.
    pool = _pool({(SSH, "medium"): 3, (SSH, "low"): 3, (SUSP, "low"): 3, (PRIV, "medium"): 3})
    sample = build_gold.allocate(pool, 6, **_params())
    assert len(sample) == 6
    assert _by_stratum(sample) == {
        (SSH, "medium"): 2,
        (SSH, "low"): 1,
        (SUSP, "low"): 1,
        (PRIV, "medium"): 2,
    }

    # All shares .5: unknown medium/low 2 : 2 drawing 3 -> 1.5 / 1.5 -> 2 + 1.
    pool = _pool({(UNKNOWN, "medium"): 2, (UNKNOWN, "low"): 2})
    sample = build_gold.allocate(pool, 3, **_params(unknown_cap_pct=100.0))
    assert len(sample) == 3
    assert _by_stratum(sample) == {(UNKNOWN, "medium"): 2, (UNKNOWN, "low"): 1}


def test_allocate_take_all_crit_high_enters_every_crit_high():
    pool = _pool(
        {
            (UNKNOWN, "critical"): 1,
            (UNKNOWN, "high"): 2,
            (SSH, "high"): 1,
            (SSH, "medium"): 4,
            (SUSP, "low"): 4,
        }
    )
    crit_high = {row.cluster_id for row in pool if row.severity in ("critical", "high")}
    assert len(crit_high) == 4

    # take-all: 4 enter; unknown budget floor(8 x 50 %) = 4, 3 already taken, no
    # unknown medium/low to draw the fourth from; remaining 4 over ssh 4 : susp 4.
    sample = build_gold.allocate(pool, 8, **_params(unknown_cap_pct=50.0))
    assert len(sample) == 8
    assert crit_high <= {row.cluster_id for row in sample}
    assert _by_stratum(sample) == {
        (UNKNOWN, "critical"): 1,
        (UNKNOWN, "high"): 2,
        (SSH, "high"): 1,
        (SSH, "medium"): 2,
        (SUSP, "low"): 2,
    }

    # Rule off (G2's mode): classified strata alone are 9 > 8, so they are
    # allocated proportionally and unknown draws nothing -- the three unknown
    # crit+high rows stay out. This is what the flag changes.
    sample = build_gold.allocate(pool, 8, **_params(unknown_cap_pct=50.0, take_all_crit_high=False))
    assert len(sample) == 8
    assert not any(row.category == UNKNOWN for row in sample)
    assert _by_stratum(sample) == {(SSH, "high"): 1, (SSH, "medium"): 3, (SUSP, "low"): 4}


def test_allocate_take_all_overflow_falls_through_to_proportional():
    """12 crit+high for a target of 4: keeping them all would be silent; the
    allocator falls through to proportional-with-cap and says so."""
    pool = _pool({(UNKNOWN, "high"): 6, (SSH, "high"): 6})
    sample = build_gold.allocate(pool, 4, **_params(unknown_cap_pct=50.0))
    assert _by_stratum(sample) == {(UNKNOWN, "high"): 2, (SSH, "high"): 2}
    table = build_gold.coverage_table(
        pool, sample, denominator_label="G1", params=_alloc_params(4, unknown_cap_pct=50.0)
    )
    assert "take-all rule alone exceeds the target: 12 > 4" in table

    # ...and the cap still binds on the way through: budget floor(4 x 25 %) = 1.
    sample = build_gold.allocate(pool, 4, **_params(unknown_cap_pct=25.0))
    assert _by_stratum(sample) == {(UNKNOWN, "high"): 1, (SSH, "high"): 3}


def test_allocate_unknown_cap_binds_and_is_reported():
    pool = _pool({(UNKNOWN, "high"): 5, (UNKNOWN, "medium"): 3, (SSH, "medium"): 4})

    # budget floor(8 x 25 %) = 2 < the 5 unknown high the take-all rule took:
    # no unknown medium is drawn and the collision is printed, not resolved.
    sample = build_gold.allocate(pool, 8, **_params(unknown_cap_pct=25.0))
    assert _by_stratum(sample) == {(UNKNOWN, "high"): 5, (SSH, "medium"): 3}
    table = build_gold.coverage_table(
        pool, sample, denominator_label="G1", params=_alloc_params(8, unknown_cap_pct=25.0)
    )
    assert "unknown cap exceeded by the take-all rule: 5 of 2" in table

    # budget floor(8 x 75 %) = 6: one unknown medium is drawn, two ssh fill up.
    sample = build_gold.allocate(pool, 8, **_params(unknown_cap_pct=75.0))
    assert _by_stratum(sample) == {(UNKNOWN, "high"): 5, (UNKNOWN, "medium"): 1, (SSH, "medium"): 2}
    table = build_gold.coverage_table(
        pool, sample, denominator_label="G1", params=_alloc_params(8, unknown_cap_pct=75.0)
    )
    assert "cap exceeded" not in table


def test_allocate_category_floor_topup_moves_from_largest():
    pool = _pool({(SSH, "medium"): 8, (SUSP, "low"): 2, (PRIV, "low"): 2})

    # proportional: 8/12, 2/12, 2/12 of 6 -> 4, 1, 1
    sample = build_gold.allocate(pool, 6, **_params(category_floor=0))
    assert _by_stratum(sample) == {(SSH, "medium"): 4, (SUSP, "low"): 1, (PRIV, "low"): 1}

    # floor 2: both small categories are lifted to min(2, pool 2) = 2, each
    # unit taken from ssh, the largest allocation -> 2, 2, 2
    sample = build_gold.allocate(pool, 6, **_params(category_floor=2))
    assert _by_stratum(sample) == {(SSH, "medium"): 2, (SUSP, "low"): 2, (PRIV, "low"): 2}

    # floor 3: the small categories want min(3, pool 2) = 2 each, but ssh's own
    # floor is now 3 and a donor never gives below it -- one unit moves (to
    # privilege_escalation, first in resolver PRIORITY order), the second cannot,
    # and the table says which category stayed short.
    sample = build_gold.allocate(pool, 6, **_params(category_floor=3))
    assert _by_stratum(sample) == {(SSH, "medium"): 3, (SUSP, "low"): 1, (PRIV, "low"): 2}
    table = build_gold.coverage_table(
        pool, sample, denominator_label="G1", params=_alloc_params(6, category_floor=3)
    )
    assert "category floor 3: suspicious_login stays at 1 of 2 -- nothing can be moved" in table

    # two donors with surplus: privilege_escalation comes first in PRIORITY order
    # but ssh_brute_force holds the largest allocation, so ssh gives.
    # proportional 8 x (4, 7, 1) / 12 = 2.67, 4.67, 0.67 -> 3, 5, 0; floor 2 lifts
    # suspicious_login to min(2, pool 1) = 1, taken from ssh (5 -> 4), not priv.
    pool2 = _pool({(PRIV, "medium"): 4, (SSH, "medium"): 7, (SUSP, "low"): 1})
    sample = build_gold.allocate(pool2, 8, **_params(category_floor=2))
    assert _by_stratum(sample) == {(PRIV, "medium"): 3, (SSH, "medium"): 4, (SUSP, "low"): 1}

    # floor 10 is unsatisfiable for ssh itself (min(10, 8) = 8 > its 4): a donor
    # never gives below its own floor, so nothing can be moved and the
    # proportional allocation stands -- reported by the table, never forced.
    sample = build_gold.allocate(pool, 6, **_params(category_floor=10))
    assert _by_stratum(sample) == {(SSH, "medium"): 4, (SUSP, "low"): 1, (PRIV, "low"): 1}


def test_allocate_no_take_all_allocates_classified_first_then_unknown_under_cap():
    """G2's mode (planning decision 10): every classified cluster first, then
    unknown fills to the target under its cap."""
    pool = _pool(
        {
            (UNKNOWN, "medium"): 6,
            (UNKNOWN, "low"): 2,
            (SSH, "high"): 1,
            (SSH, "medium"): 1,
            (PRIV, "low"): 2,
        }
    )
    sample = build_gold.allocate(pool, 8, **_params(unknown_cap_pct=50.0, take_all_crit_high=False))
    assert _by_stratum(sample) == {
        (SSH, "high"): 1,
        (SSH, "medium"): 1,
        (PRIV, "low"): 2,
        (UNKNOWN, "medium"): 3,
        (UNKNOWN, "low"): 1,
    }

    # cap 25 % -> budget 2: the sample stops at 6 of 8 rather than breach the cap
    sample = build_gold.allocate(pool, 8, **_params(unknown_cap_pct=25.0, take_all_crit_high=False))
    assert len(sample) == 6
    assert _by_stratum(sample)[(UNKNOWN, "medium")] + _by_stratum(sample)[(UNKNOWN, "low")] == 2
    table = build_gold.coverage_table(
        pool,
        sample,
        denominator_label="G2",
        params=_alloc_params(8, unknown_cap_pct=25.0, take_all_crit_high=False),
    )
    assert "sample short: 6 of 8" in table


def test_allocate_returns_whole_pool_when_target_exceeds_it():
    pool = _pool({(SSH, "medium"): 5, (UNKNOWN, "low"): 7})
    sample = build_gold.allocate(pool, 100, **_params(unknown_cap_pct=100.0))
    assert sorted(row.cluster_id for row in sample) == sorted(row.cluster_id for row in pool)
    assert [row.cluster_id for row in sample] == sorted(row.cluster_id for row in sample)


def test_allocate_never_exceeds_the_target_when_take_all_fills_the_room():
    """Review finding: with the take-all rule on, the unknown medium/low draw
    is bounded by the room left under the target, not only by the cap --
    otherwise budget 4 on top of 6 crit+high would return 10 rows for 8."""
    pool = _pool({(SSH, "high"): 6, (UNKNOWN, "medium"): 10})
    sample = build_gold.allocate(pool, 8, **_params(unknown_cap_pct=50.0))
    assert len(sample) == 8
    assert _by_stratum(sample) == {(SSH, "high"): 6, (UNKNOWN, "medium"): 2}

    # crit+high exactly at the target: nothing else may enter
    pool = _pool({(SSH, "high"): 6, (UNKNOWN, "high"): 4, (UNKNOWN, "medium"): 10})
    sample = build_gold.allocate(pool, 10, **_params(unknown_cap_pct=50.0))
    assert _by_stratum(sample) == {(SSH, "high"): 6, (UNKNOWN, "high"): 4}


@pytest.mark.parametrize("take_all", [True, False])
@pytest.mark.parametrize("cap", [0.0, 25.0, 50.0, 100.0])
@pytest.mark.parametrize("target", [1, 5, 8, 12, 40])
def test_allocate_size_contract_across_branches(take_all, cap, target):
    """Never more than min(target, len(pool)); exactly that unless the cap
    binds (and then the table says so)."""
    pool = _pool(
        {
            (UNKNOWN, "critical"): 1,
            (UNKNOWN, "high"): 2,
            (UNKNOWN, "medium"): 3,
            (SSH, "high"): 1,
            (SSH, "medium"): 3,
            (PRIV, "low"): 2,
        }
    )
    params = _params(unknown_cap_pct=cap, take_all_crit_high=take_all, category_floor=1)
    sample = build_gold.allocate(pool, target, **params)
    bound = min(target, len(pool))
    assert len(sample) <= bound
    assert len({row.cluster_id for row in sample}) == len(sample)
    assert [row.cluster_id for row in sample] == sorted(row.cluster_id for row in sample)
    table = build_gold.coverage_table(
        pool, sample, denominator_label="G1", params=_alloc_params(target, **params)
    )
    if len(sample) < bound:
        assert f"sample short: {len(sample)} of {bound}" in table
    else:
        assert "sample short" not in table


def _stable_pool() -> list:
    return _pool({(SSH, "medium"): 30, (UNKNOWN, "low"): 30})


def test_allocate_is_seeded_and_stable():
    first = build_gold.allocate(_stable_pool(), 20, **_params(unknown_cap_pct=50.0))
    second = build_gold.allocate(_stable_pool(), 20, **_params(unknown_cap_pct=50.0))
    assert _by_stratum(first) == {(SSH, "medium"): 10, (UNKNOWN, "low"): 10}, "a real draw"
    assert [row.cluster_id for row in first] == [row.cluster_id for row in second]
    # and the order the pool arrives in does not change the draw (sorted ids)
    shuffled = list(reversed(_stable_pool()))
    third = build_gold.allocate(shuffled, 20, **_params(unknown_cap_pct=50.0))
    assert [row.cluster_id for row in first] == [row.cluster_id for row in third]


def test_allocate_different_seed_differs():
    first = build_gold.allocate(_stable_pool(), 20, **_params(unknown_cap_pct=50.0))
    other = build_gold.allocate(_stable_pool(), 20, **_params(unknown_cap_pct=50.0, seed=1))
    assert [row.cluster_id for row in first] != [row.cluster_id for row in other]


def test_allocate_strata_are_independently_seeded():
    """Two equal-size strata drawing the same k must not land on the same
    index positions -- `Random(seed)` restarted per stratum would."""
    pool = _pool({(SSH, "medium"): 40, (SUSP, "low"): 40})
    sample = build_gold.allocate(pool, 20, **_params())
    assert _by_stratum(sample) == {(SSH, "medium"): 10, (SUSP, "low"): 10}

    def positions(category: str) -> list[int]:
        ids = sorted(row.cluster_id for row in pool if row.category == category)
        drawn = {row.cluster_id for row in sample if row.category == category}
        return [index for index, cluster_id in enumerate(ids) if cluster_id in drawn]

    assert positions(SSH) != positions(SUSP)


# --- g1_rows ------------------------------------------------------------------------


def test_g1_rows_flag_loopback_and_keep_desktop_agent(tmp_path):
    docs = [
        _line("a", T0, srcip="127.0.0.1"),  # ssh_brute_force from loopback: excluded
        _line("b", T0 + timedelta(minutes=1), srcip="10.0.0.5"),
        # loopback too, but `unknown` (and its own rule -> its own cluster key)
        _line("c", T0 + timedelta(minutes=2), srcip="127.0.0.1", category=UNKNOWN, rule_id="550"),
        _line("d", T0 + timedelta(minutes=3), srcip="10.0.0.6", agent="DESKTOP-MIRSO17"),
        _line("e", T0 + timedelta(minutes=4), srcip="10.0.0.5"),  # joins b
    ]
    stats, clusters = _archive(tmp_path / "g1.jsonl", docs)
    rows = build_gold.g1_rows(stats, clusters)

    assert [row.cluster_id for row in rows] == ["a", "b", "c", "d"], "sorted by cluster_id"
    by_id = {row.cluster_id: row for row in rows}
    assert by_id["a"].excluded_reason == build_gold.EXCLUDED_LOOPBACK
    assert by_id["a"].category == SSH and by_id["a"].srcip == build_gold.LOOPBACK_SRCIP
    assert by_id["c"].excluded_reason == "", "loopback alone is not the exclusion"
    assert by_id["c"].category == UNKNOWN
    assert by_id["d"].excluded_reason == "" and by_id["d"].agent_name == "DESKTOP-MIRSO17"
    pool = [row for row in rows if not row.excluded_reason]
    assert [row.cluster_id for row in pool] == ["b", "c", "d"]

    b = by_id["b"]
    assert b.alert_id == b.cluster_id == "b"
    assert b.gold_set == "G1" and b.source == "replay"
    assert b.occurrence_count == 2
    assert b.first_seen == T0.astimezone(UTC) + timedelta(minutes=1)
    assert b.last_seen == T0.astimezone(UTC) + timedelta(minutes=4)
    assert b.first_seen.tzinfo is not None
    assert b.closed_by == "", "still open when the fold ended -> empty, never 'None'"
    assert b.stratum == f"{SSH}|medium"
    assert b.rule_id == "5503" and b.alert_user == "root" and b.dstip == ""


def test_g1_members_one_row_per_parsed_alert_head_first(tmp_path):
    stats, clusters = _archive(tmp_path / "g1.jsonl", _mixed_docs())
    members = build_gold.g1_members(stats, clusters)
    assert len(members) == stats.parsed == 9
    assert members == sorted(members, key=lambda m: (m[0], m[2], m[1]))
    m1 = [m for m in members if m[0] == "m1"]
    assert [m[1] for m in m1] == ["m1", "m1b"]


# --- output files --------------------------------------------------------------------


def _write_run(out_dir: Path, stats, clusters, *, sample=None, g2_rows=()):
    rows = build_gold.g1_rows(stats, clusters)
    pool = [row for row in rows if not row.excluded_reason]
    if sample is None:
        sample = build_gold.allocate(pool, 4, **_params(unknown_cap_pct=50.0))
    params = _alloc_params(4, unknown_cap_pct=50.0)
    coverage = build_gold.coverage_table(pool, sample, denominator_label="G1", params=params)
    build_gold.write_outputs(
        out_dir,
        g1_rows=rows,
        g1_members=build_gold.g1_members(stats, clusters),
        sample=list(sample) + list(g2_rows),
        coverage_md=coverage,
    )
    return rows, sample


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


OUTPUT_FILES = ("g1_clusters.csv", "g1_members.csv.gz", "gold_candidates.csv", "gold_coverage.md")


def test_g1_files_are_byte_identical_on_rerun(tmp_path, monkeypatch):
    stats, clusters = _archive(tmp_path / "g1.jsonl", _mixed_docs())
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    # gzip stamps `time.time()` into its header unless mtime is pinned -- make
    # the two runs happen at visibly different clocks.
    monkeypatch.setattr(time, "time", lambda: 1_700_000_000.0)
    _write_run(first, stats, clusters)
    monkeypatch.setattr(time, "time", lambda: 1_700_000_100.0)
    _write_run(second, stats, clusters)
    for name in OUTPUT_FILES:
        assert _sha256(first / name) == _sha256(second / name), name


def test_gold_candidates_header_and_row_shape(tmp_path):
    stats, clusters = _archive(tmp_path / "g1.jsonl", _mixed_docs())
    out = tmp_path / "out"
    out.mkdir()
    _write_run(out, stats, clusters)

    with (out / "gold_candidates.csv").open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == list(build_gold.CANDIDATE_COLUMNS)
        candidates = list(reader)
    assert len(candidates) == 4
    assert [c["cluster_id"] for c in candidates] == sorted(c["cluster_id"] for c in candidates)
    for c in candidates:
        assert c["gold_set"] == "G1" and c["source"] == "replay"
        assert c["alert_id"] == c["cluster_id"]
        assert c["stratum"] == f"{c['category']}|{c['severity']}"
        assert int(c["occurrence_count"]) >= 1
        for column in ("first_seen", "last_seen"):
            instant = datetime.fromisoformat(c[column])
            assert instant.tzinfo is not None and instant.utcoffset() == timedelta(0)
    text = (out / "gold_candidates.csv").read_bytes()
    assert b"\r" not in text and text.endswith(b"\n")

    with (out / "g1_clusters.csv").open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == list(build_gold.CLUSTER_COLUMNS)
        clusters_rows = list(reader)
    assert len(clusters_rows) == 8
    assert (
        sum(1 for r in clusters_rows if r["excluded_reason"] == build_gold.EXCLUDED_LOOPBACK) == 1
    )
    assert {r["closed_by"] for r in clusters_rows} <= {"", "idle_gap", "max_age", "max_size"}

    with gzip.open(out / "g1_members.csv.gz", "rt", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == list(build_gold.MEMBER_COLUMNS)
        members = list(reader)
    assert len(members) == 9
    assert {m["cluster_id"] for m in members} == {r["cluster_id"] for r in clusters_rows}


def test_g1_candidate_lines_are_identical_with_and_without_g2_rows(tmp_path):
    """A later `--g1 --g2` run must reproduce the G1 rows byte for byte."""
    stats, clusters = _archive(tmp_path / "g1.jsonl", _mixed_docs())
    g1_only, both = tmp_path / "g1", tmp_path / "both"
    g1_only.mkdir()
    both.mkdir()
    _write_run(g1_only, stats, clusters)
    g2 = build_gold.ClusterRow(
        cluster_id="lab-1",
        gold_set="G2",
        alert_id="lab-1",
        rule_id="5503",
        category=SSH,
        severity="medium",
        agent_name="user1-IA1803",
        alert_user=None,
        srcip="10.9.9.9",
        dstip="",
        source="lab",
        first_seen=T0.astimezone(UTC),
        last_seen=T0.astimezone(UTC),
        occurrence_count=3,
        closed_by="",
        excluded_reason="",
    )
    _write_run(both, stats, clusters, g2_rows=[g2])
    a = (g1_only / "gold_candidates.csv").read_text(encoding="utf-8").splitlines()
    b = (both / "gold_candidates.csv").read_text(encoding="utf-8").splitlines()
    assert b[: len(a)] == a
    assert len(b) == len(a) + 1 and b[-1].startswith("lab-1,G2,lab-1,")


# --- coverage table -------------------------------------------------------------------


def test_coverage_table_prints_parameters_denominators_and_enrichment_line():
    pool = _pool(
        {
            (UNKNOWN, "critical"): 1,
            (UNKNOWN, "high"): 2,
            (SSH, "high"): 1,
            (SSH, "medium"): 4,
            (SUSP, "low"): 4,
        }
    )
    sample = build_gold.allocate(pool, 8, **_params(unknown_cap_pct=50.0, category_floor=2))
    params = _alloc_params(8, floor=5, unknown_cap_pct=50.0, category_floor=2)
    table = build_gold.coverage_table(pool, sample, denominator_label="G1", params=params)

    for fragment in (
        "target=8",
        "floor=5",
        "unknown_cap_pct=50.0",
        "take_all_crit_high=True",
        "category_floor=2",
        f"seed={SEED}",
        "## G1 pool (denominator 12)",
        "## G1 sample (denominator 8)",
        "| category | critical | high | medium | low | total | share |",
        "G1's severity mix is enriched by design: 4 of 8 against 4 of 12",
        "crit+high in the pool: 4 of 12, of which `unknown` 3",
        "`unknown` in the sample: 3 of 8",
        "against the cap 50.0 % (budget 4)",
    ):
        assert fragment in table, fragment
    # every share carries its denominator -- no bare percentage anywhere
    for line in table.splitlines():
        if "%" in line and "|" not in line:
            assert " of " in line or "cap" in line, line


def test_coverage_table_is_deterministic():
    pool = _pool({(UNKNOWN, "medium"): 5, (SSH, "medium"): 5, (PRIV, "high"): 2})
    sample = build_gold.allocate(pool, 6, **_params(unknown_cap_pct=50.0))
    params = _alloc_params(6, unknown_cap_pct=50.0)
    assert build_gold.coverage_table(
        pool, sample, denominator_label="G1", params=params
    ) == build_gold.coverage_table(pool, sample, denominator_label="G1", params=params)


# --- lab windows (read only) ---------------------------------------------------------


def _windows_csv(path: Path, rows: list[tuple]) -> Path:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(build_gold.LAB_WINDOWS_HEADER)
        for row in rows:
            writer.writerow(row)
    return path


def test_read_lab_windows_parses_offsets(tmp_path):
    path = _windows_csv(
        tmp_path / "w.csv",
        [
            (
                "sbf-1",
                SSH,
                "attack",
                "user1-IA1803",
                "2026-09-22T09:00:00+07:00",
                "2026-09-22T09:10:00+07:00",
                "12",
                "2026-09-22T02:15:00+00:00",
            )
        ],
    )
    windows = build_gold.read_lab_windows(path)
    assert len(windows) == 1
    w = windows[0]
    assert (w.scenario_id, w.category_expected, w.kind, w.agent_name) == (
        "sbf-1",
        SSH,
        "attack",
        "user1-IA1803",
    )
    assert w.since == datetime(2026, 9, 22, 2, 0, tzinfo=UTC)
    assert w.until == datetime(2026, 9, 22, 2, 10, tzinfo=UTC)
    assert build_gold.read_lab_windows(tmp_path / "absent.csv") == []
    assert build_gold.read_lab_windows(_windows_csv(tmp_path / "empty.csv", [])) == []


def test_lab_tag_command_is_exact():
    window = build_gold.LabWindow(
        scenario_id="sbf-1",
        category_expected=SSH,
        kind="attack",
        agent_name="user1-IA1803",
        since=datetime.fromisoformat("2026-09-22T09:00:00+07:00"),
        until=datetime.fromisoformat("2026-09-22T09:10:00+07:00"),
    )
    assert build_gold.lab_tag_command(window) == (
        "PYTHONPATH=backend python3 eval/lab_tag.py --agent user1-IA1803 "
        "--since 2026-09-22T09:00:00+07:00 --until 2026-09-22T09:10:00+07:00 "
        "--scenario sbf-1 --category ssh_brute_force --kind attack --env-file .env"
    )


# --- main(): CLI and exit codes -------------------------------------------------------


def _run_main(tmp_path, monkeypatch, docs, *extra: str) -> tuple[int, Path]:
    archive = tmp_path / "archive.jsonl"
    _write_jsonl(archive, docs)
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    monkeypatch.setattr(config_module, "load", lambda env_file=".env": _cfg())
    rc = build_gold.main(["--archive-file", str(archive), "--out-dir", str(out), *extra])
    return rc, out


def test_missing_archive_exits_2(tmp_path, capsys):
    rc = build_gold.main(
        ["--archive-file", str(tmp_path / "nope.jsonl"), "--out-dir", str(tmp_path)]
    )
    assert rc == build_gold.EXIT_ARCHIVE == 2
    captured = capsys.readouterr()
    assert "sudo sh -c" in captured.err, "dedup_verify's Owner procedure is reused"
    assert not (tmp_path / "gold_candidates.csv").exists()


def test_floor_miss_exits_1_and_still_writes_files(tmp_path, monkeypatch, capsys):
    rc, out = _run_main(
        tmp_path, monkeypatch, _mixed_docs(), "--g1", "--g1-target", "300", "--g1-floor", "200"
    )
    assert rc == build_gold.EXIT_FLOOR_MISS == 1
    captured = capsys.readouterr()
    assert "FLOOR MISS G1 7 < 200" in captured.out
    assert "clusters 8 · pool 7 · G1 sample 7 · G2 sample -" in captured.out
    for name in OUTPUT_FILES:
        assert (out / name).exists(), name
    coverage = (out / "gold_coverage.md").read_text(encoding="utf-8")
    assert coverage.splitlines()[0].endswith("G1 only")
    assert "G1 7 ≥ 200: MISS" in coverage


def test_default_run_is_g1_only_and_meets_a_small_floor(tmp_path, monkeypatch, capsys):
    rc, out = _run_main(tmp_path, monkeypatch, _mixed_docs(), "--g1-target", "4", "--g1-floor", "4")
    assert rc == build_gold.EXIT_OK == 0
    out_text = capsys.readouterr().out
    assert "clusters 8 · pool 7 · G1 sample 4 · G2 sample -" in out_text
    assert "dsn" not in out_text, "no connection is opened without --g2/--check-db"
    with (out / "gold_candidates.csv").open(newline="", encoding="utf-8") as handle:
        assert {row["gold_set"] for row in csv.DictReader(handle)} == {"G1"}
    assert "G1 4 ≥ 4: met" in (out / "gold_coverage.md").read_text(encoding="utf-8")


def test_g2_without_recorded_windows_exits_3_before_any_connection(tmp_path, monkeypatch, capsys):
    def refuse(_dsn):
        raise AssertionError("no connection may be opened without a recorded window")

    monkeypatch.setattr(build_gold, "_read_only_connection", refuse)
    empty = _windows_csv(tmp_path / "windows.csv", [])
    rc, _ = _run_main(
        tmp_path, monkeypatch, _mixed_docs(), "--g2", "--lab-windows", str(empty), "--dsn", "x"
    )
    assert rc == build_gold.EXIT_LAB_WINDOW == 3
    assert "no lab windows recorded — run eval/lab_tag.py after each scenario" in (
        capsys.readouterr().err
    )
    rc, _ = _run_main(
        tmp_path,
        monkeypatch,
        _mixed_docs(),
        "--g2",
        "--lab-windows",
        str(tmp_path / "absent.csv"),
        "--dsn",
        "x",
    )
    assert rc == 3


def test_malformed_dsn_exits_2_without_printing_it(tmp_path, monkeypatch, capsys):
    """`psycopg.connect("x")` fails before any server is reached (a
    ProgrammingError, not an OperationalError): still exit 2, no traceback,
    no DSN on either stream, no files."""
    rc, out = _run_main(
        tmp_path, monkeypatch, _mixed_docs(), "--check-db", "--dsn", "x-not-a-dsn-secret"
    )
    assert rc == build_gold.EXIT_ARCHIVE == 2
    captured = capsys.readouterr()
    assert "DSN unreadable" in captured.err
    assert "x-not-a-dsn-secret" not in captured.out + captured.err
    assert not (out / "gold_candidates.csv").exists()


def test_no_dsn_exits_2_without_printing_one(tmp_path, monkeypatch, capsys):
    rc, _ = _run_main(tmp_path, monkeypatch, _mixed_docs(), "--check-db")
    assert rc == build_gold.EXIT_ARCHIVE == 2
    err = capsys.readouterr().err
    assert "DSN" in err and "postgresql" not in err


# --- database ----------------------------------------------------------------------------


def _parsed(alert_id: str, instant: datetime, **kw):
    result = parse_wazuh_alert(_line(alert_id, instant, **kw))
    assert result.alert is not None, result.rejection
    return result.alert


def _insert_head(conn, alert_id: str, instant: datetime, **kw) -> str:
    alert = _parsed(alert_id, instant, **kw)
    return transitions.open_alert(
        conn, alert, kind="received", source="wazuh", suggestion_visible=True
    )


def _insert_duplicate(conn, alert_id: str, instant: datetime, *, duplicate_of: str, **kw) -> str:
    alert = _parsed(alert_id, instant, **kw)
    return transitions.open_alert(
        conn,
        alert,
        kind="duplicate",
        source="wazuh",
        suggestion_visible=True,
        duplicate_of=duplicate_of,
    )


def _tag_lab(conn, *alert_ids: str) -> None:
    # what eval/lab_tag.py does in production, inline
    for alert_id in alert_ids:
        conn.execute("UPDATE alerts SET source = 'lab' WHERE alert_id = %s", (alert_id,))


@pytest.fixture
def same_connection(db, monkeypatch):
    """Route `main()`'s connection to the fixture's own (uncommitted rows are
    visible; nothing is committed or closed by the script). The production
    context's `SET TRANSACTION READ ONLY` is not replayed here -- the fixture's
    transaction already holds the rows -- and is proven on a real connection by
    `test_read_only_connection_refuses_writes` instead."""

    @contextmanager
    def _borrow(_dsn):
        yield db

    monkeypatch.setattr(build_gold, "_read_only_connection", _borrow)
    return db


LAB_AGENT = "user1-IA1803"
W0 = datetime(2026, 9, 22, 9, 0, 0, tzinfo=timezone(timedelta(hours=7)))


def _window(scenario: str, since: datetime, until: datetime, *, kind="attack", category=SSH):
    return (scenario, category, kind, LAB_AGENT, since.isoformat(), until.isoformat(), "0", "")


@pytest.mark.db
def test_read_only_connection_refuses_writes(db, _test_database):
    """The guard behind rule 7 ("this script never writes a row"): a real
    connection opened the way `main()` opens it rejects any write."""
    with build_gold._read_only_connection(_test_database) as conn:
        assert conn.execute("SELECT 1").fetchone() == (1,)
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            conn.execute("UPDATE alerts SET source = 'lab' WHERE alert_id = 'p6t01-none'")


@pytest.mark.db
def test_g2_rows_numbers_are_clock_free_min_max_alert_time(db, tmp_path, capsys):
    head_time = W0 + timedelta(hours=1)
    dup_time = W0  # one hour before the head, and months before its first_seen_at (now())
    head = _insert_head(db, "p6t01-head", head_time, srcip="10.1.1.1")
    _insert_duplicate(db, "p6t01-dup", dup_time, duplicate_of=head, srcip="10.1.1.1")
    _tag_lab(db, head, "p6t01-dup")
    windows = build_gold.read_lab_windows(
        _windows_csv(
            tmp_path / "w.csv",
            [_window("sbf-1", W0 - timedelta(minutes=1), W0 + timedelta(hours=2))],
        )
    )

    rows = build_gold.g2_rows(db, windows)
    assert [row.cluster_id for row in rows] == [head]
    row = rows[0]
    assert row.gold_set == "G2" and row.source == "lab"
    assert row.closed_by == "" and row.excluded_reason == ""
    assert row.occurrence_count == 2
    assert row.first_seen == dup_time.astimezone(UTC)
    assert row.last_seen == head_time.astimezone(UTC)
    db_first, db_last, db_count = db.execute(
        "SELECT first_seen_at, last_seen_at, occurrence_count FROM alerts WHERE alert_id = %s",
        (head,),
    ).fetchone()
    assert row.first_seen != db_first and row.last_seen != db_last, "the DB clock is not the number"
    assert db_count == 1
    assert "p6t01-head" in capsys.readouterr().err, "the recount differing is a warning line"


@pytest.mark.db
def test_g2_untagged_window_exits_3_and_prints_lab_tag_command(
    same_connection, tmp_path, monkeypatch, capsys
):
    db = same_connection
    _insert_head(db, "p6t01-untagged", W0 + timedelta(minutes=5), srcip="10.1.1.2")
    since, until = W0, W0 + timedelta(minutes=10)
    windows = _windows_csv(tmp_path / "w.csv", [_window("sbf-2", since, until)])

    rc, out = _run_main(
        tmp_path,
        monkeypatch,
        _mixed_docs(),
        "--g2",
        "--lab-windows",
        str(windows),
        "--dsn",
        "postgresql://never-used",
    )
    assert rc == build_gold.EXIT_LAB_WINDOW == 3
    err = capsys.readouterr().err
    assert "sbf-2" in err and since.isoformat() in err and until.isoformat() in err
    assert "1 untagged head" in err
    assert (
        f"PYTHONPATH=backend python3 eval/lab_tag.py --agent {LAB_AGENT} "
        f"--since {since.isoformat()} --until {until.isoformat()} "
        "--scenario sbf-2 --category ssh_brute_force --kind attack --env-file .env"
    ) in err
    assert "never-used" not in err
    assert not (out / "gold_candidates.csv").exists(), "a failed run writes nothing"


@pytest.mark.db
def test_g2_excludes_synthetic_and_manifest_ids(db, tmp_path):
    base = W0 + timedelta(hours=3)
    kept = _insert_head(db, "p6t01-kept", base, srcip="10.1.2.1")
    synthetic = _insert_head(db, "p6t01-synthetic", base + timedelta(minutes=1), srcip="10.1.2.2")
    listed = _insert_head(db, "p6t01-manifest", base + timedelta(minutes=2), srcip="10.1.2.3")
    _tag_lab(db, kept, synthetic, listed)
    db.execute("UPDATE alerts SET is_synthetic = true WHERE alert_id = %s", (synthetic,))
    # two overlapping windows both contain `kept`: it is emitted once
    windows = build_gold.read_lab_windows(
        _windows_csv(
            tmp_path / "w.csv",
            [
                _window("sbf-3", base - timedelta(minutes=1), base + timedelta(minutes=5)),
                _window(
                    "ben-1",
                    base - timedelta(minutes=2),
                    base + timedelta(minutes=1),
                    kind="benign",
                    category="benign",
                ),
            ],
        )
    )
    rows = build_gold.g2_rows(db, windows, manifest_ids=frozenset({listed}))
    assert [row.cluster_id for row in rows] == [kept]


@pytest.mark.db
def test_check_db_reports_missing_head_exit_4(same_connection, tmp_path, monkeypatch, capsys):
    db = same_connection
    docs = _mixed_docs()
    # every head of the archive but `m6` is in `alerts` as a replay row
    for doc in docs:
        if doc["id"] in ("m6", "m1b"):
            continue
        alert = parse_wazuh_alert(doc).alert
        transitions.open_alert(db, alert, kind="received", source="replay", suggestion_visible=True)
    rc, out = _run_main(
        tmp_path,
        monkeypatch,
        docs,
        "--g1",
        "--check-db",
        "--dsn",
        "postgresql://never-used",
        "--g1-target",
        "4",
        "--g1-floor",
        "1",
    )
    assert rc == build_gold.EXIT_CHECK_DB == 4
    captured = capsys.readouterr()
    assert "check-db: 7/8 heads present, source=replay 7" in captured.out
    assert "m6" in captured.err and "never-used" not in captured.out + captured.err
    assert (out / "g1_clusters.csv").exists(), "the files are the fold's; the check is a verdict"

    # the missing head added -> all present, exit 0
    alert = parse_wazuh_alert(next(doc for doc in docs if doc["id"] == "m6")).alert
    transitions.open_alert(db, alert, kind="received", source="replay", suggestion_visible=True)
    rc, _ = _run_main(
        tmp_path,
        monkeypatch,
        docs,
        "--g1",
        "--check-db",
        "--dsn",
        "postgresql://never-used",
        "--g1-target",
        "4",
        "--g1-floor",
        "1",
    )
    assert rc == 0
    assert "check-db: 8/8 heads present, source=replay 8" in capsys.readouterr().out


@pytest.mark.db
def test_g2_run_writes_g2_rows_after_g1_and_reports_floor(
    same_connection, tmp_path, monkeypatch, capsys
):
    db = same_connection
    base = W0 + timedelta(hours=6)
    ids = []
    for i, (category, severity) in enumerate([(SSH, "medium"), (PRIV, "high"), (UNKNOWN, "low")]):
        ids.append(
            _insert_head(
                db,
                f"p6t01-g2-{i}",
                base + timedelta(minutes=i),
                srcip=f"10.1.3.{i}",
                category=category,
                severity=severity,
            )
        )
    _tag_lab(db, *ids)
    windows = _windows_csv(
        tmp_path / "w.csv",
        [_window("mix-1", base - timedelta(minutes=1), base + timedelta(minutes=5))],
    )
    rc, out = _run_main(
        tmp_path,
        monkeypatch,
        _mixed_docs(),
        "--g1",
        "--g2",
        "--lab-windows",
        str(windows),
        "--dsn",
        "postgresql://never-used",
        "--g1-target",
        "4",
        "--g1-floor",
        "1",
        "--g2-target",
        "100",
        "--g2-floor",
        "60",
        "--g2-unknown-cap-pct",
        "50",
        "--g2-category-floor",
        "5",
    )
    assert rc == build_gold.EXIT_FLOOR_MISS == 1
    out_text = capsys.readouterr().out
    assert "clusters 8 · pool 7 · G1 sample 4 · G2 sample 3" in out_text
    assert "FLOOR MISS G2 3 < 60" in out_text
    with (out / "gold_candidates.csv").open(newline="", encoding="utf-8") as handle:
        candidates = list(csv.DictReader(handle))
    assert [c["gold_set"] for c in candidates] == ["G1"] * 4 + ["G2"] * 3
    g2 = [c for c in candidates if c["gold_set"] == "G2"]
    assert [c["cluster_id"] for c in g2] == sorted(ids)
    assert {c["source"] for c in g2} == {"lab"}
    coverage = (out / "gold_coverage.md").read_text(encoding="utf-8")
    assert coverage.splitlines()[0].endswith("G1 + G2")
    assert "## G2 pool (denominator 3)" in coverage and "## G2 sample (denominator 3)" in coverage
    assert "mix-1" in coverage
    assert "zero clusters" in coverage and "ransomware" in coverage
    assert "G2 3 ≥ 60: MISS" in coverage
