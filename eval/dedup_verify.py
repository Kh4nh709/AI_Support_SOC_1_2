#!/usr/bin/env python3
"""Verify the coded dedup predicates against the Owner's archive export, offline.

**Why a fold over `alert_time`, not a replay (design note 1, P2-T15).** The
product's `find_open_cluster` anchors `IDLE_GAP` on `last_seen_at` and
`MAX_AGE` on `first_seen_at` against the database's own clock, by design
(phase-2 B2/D9): replaying 29-30 days of archived alerts through the real
pipeline in an afternoon would put every alert of one key inside a single
wall-clock window and report a handful of clusters -- measuring the database's
speed, not the data (P2-tasks.md planning decision 9). The Owner's measured
figures came from applying the same predicates over the alerts' own
timestamps; this script does exactly that, reusing the product code for
everything that is not the clock: `parse_wazuh_alert` for the fields, the
four-column key `(rule_id, srcip, dstip, agent_name)` with `''` already
substituted for a missing IP by the parser (B1), and the three ceilings read
from `Config`. What this verifies: the key derivation and the predicate
arithmetic. What it does not: the database path -- that is P2-T05's job on a
real database.

**The fold (design note 2).** All parsed alerts are sorted by `alert_time`
(stable, then by `alert_id`). Per key the fold keeps one open cluster
`(first_seen, last_seen, count)`. Each alert either opens a new cluster --
there is none yet for its key, or the idle gap is exceeded, or the age
ceiling is exceeded, or the size ceiling is already met -- or joins the open
one. Three of the product's six predicates do not apply here and are not
folded: "still absorbing" and "not a duplicate" are structural offline
(every archive line is a fresh arrival, never a resubmission), and the
30-minute auto-closed ceiling needs a rule-disable event the archive does not
carry. Rejected lines (`ParseResult.rejection`) are counted and excluded,
never guessed at.

**Tolerance (design note 4).** The card's target was measured on one export;
this script may be pointed at a different one -- a different line count is a
different fact about the input, not automatically a defect. A result outside
`--tolerance-pct` of `--expect` is worth investigating (a wrong key column, a
`>=` where the fold wants `>`, a timezone slip) but the per-day table below
localises that rather than assuming it. This script never adjusts a
predicate or a `Config` ceiling to make the verdict agree with `--expect`.

Run it from the repository root::

    python3 eval/dedup_verify.py --archive-file /home/user1/archive/<export>.jsonl \\
        --expect 2778 --tolerance-pct 1.0 --env-file .env

Exit codes: 0 verdict PASS · 1 verdict FAIL · 2 `--archive-file` missing or
unreadable (the Owner export procedure is printed on stderr).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from app.domain.alert import Alert
from app.infra import config
from app.infra.puller import OWNER_PROCEDURE
from app.ingest.wazuh_parser import parse_wazuh_alert

EXIT_OK = 0
EXIT_VERDICT_FAIL = 1
EXIT_ARCHIVE = 2

#: DEC-014's fixture day -- 57 % of the 29-day archive, the day the size and
#: age ceilings actually bind (phase-2 "Ví dụ trên mẫu thật" A7/A8).
STORM_DAY = "2026-08-16"

#: The fold's three offline closure reasons, in the order design note 2 checks
#: them. Not one of the product's `Config` ceiling names on its own line, so
#: this file's own literal-constant guard never trips on its own vocabulary.
REASON_IDLE_GAP = "idle_gap"
REASON_MAX_AGE = "max_age"
REASON_MAX_SIZE = "max_size"

ClusterKey = tuple[str, str, str, str]


@dataclass
class Cluster:
    """One offline cluster: the open-cluster window the fold tracked for one key."""

    key: ClusterKey
    first_seen: datetime
    last_seen: datetime
    count: int = 1
    #: Why the *next* alert on this key opened a new cluster instead of
    #: joining -- idle_gap | max_age | max_size | None (still open when the
    #: fold ran out of alerts, i.e. it hit no ceiling at all).
    closed_by: str | None = None


@dataclass
class ArchiveStats:
    lines: int
    parsed: int
    rejected: int
    rejected_by_reason: Counter
    alerts: list[Alert]


def read_archive(path: Path) -> ArchiveStats:
    """Read `path` one JSON object per line, parse each with the product parser.

    Total, like `parse_wazuh_alert` itself (R2): a line that is not valid JSON,
    or whose JSON is not an object, is counted rejected and skipped -- never a
    raised exception, same treatment as a line the parser itself rejects for a
    missing `id` / `rule.id` / `rule.description` / timestamp.
    """
    lines = 0
    parsed = 0
    rejected_by_reason: Counter = Counter()
    alerts: list[Alert] = []
    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            stripped = raw_line.strip()
            if not stripped:
                continue
            lines += 1
            try:
                doc = json.loads(stripped)
            except json.JSONDecodeError:
                rejected_by_reason["invalid_json"] += 1
                continue
            if not isinstance(doc, dict):
                rejected_by_reason["not_an_object"] += 1
                continue
            result = parse_wazuh_alert(doc)
            if result.alert is None:
                rejected_by_reason[result.rejection or "unknown"] += 1
                continue
            parsed += 1
            alerts.append(result.alert)
    return ArchiveStats(
        lines=lines,
        parsed=parsed,
        rejected=sum(rejected_by_reason.values()),
        rejected_by_reason=rejected_by_reason,
        alerts=alerts,
    )


def fold_clusters(alerts: list[Alert], cfg: config.Config) -> list[Cluster]:
    """Design note 2's fold, over alerts already read from the archive.

    Sorted by `alert_time` (stable, then by `alert_id`) so the fold sees each
    key's alerts in the order they actually fired. The three ceilings are read
    from `cfg` -- this function never hardcodes a minute, an hour or a count.
    """
    ordered = sorted(alerts, key=lambda alert: (alert.alert_time, alert.alert_id))
    idle_gap = timedelta(minutes=cfg.DEDUP_IDLE_GAP_MINUTES)
    max_age = timedelta(hours=cfg.MAX_CLUSTER_AGE_HOURS)
    max_size = cfg.MAX_CLUSTER_SIZE

    open_by_key: dict[ClusterKey, Cluster] = {}
    all_clusters: list[Cluster] = []
    for alert in ordered:
        key: ClusterKey = (alert.rule_id, alert.srcip, alert.dstip, alert.agent_name)
        head = open_by_key.get(key)
        reason: str | None = None
        if head is not None:
            if alert.alert_time - head.last_seen > idle_gap:
                reason = REASON_IDLE_GAP
            elif alert.alert_time - head.first_seen > max_age:
                reason = REASON_MAX_AGE
            elif head.count >= max_size:
                reason = REASON_MAX_SIZE
        if head is None or reason is not None:
            if head is not None:
                head.closed_by = reason
            cluster = Cluster(key=key, first_seen=alert.alert_time, last_seen=alert.alert_time)
            open_by_key[key] = cluster
            all_clusters.append(cluster)
        else:
            head.count += 1
            head.last_seen = alert.alert_time
    return all_clusters


def _local_day(instant: datetime, tz: ZoneInfo) -> str:
    return instant.astimezone(tz).date().isoformat()


def clusters_per_day(clusters: list[Cluster], tz: ZoneInfo) -> dict[str, int]:
    """Each cluster attributed to the local day it *opened* on (its `first_seen`)."""
    counts: Counter = Counter(_local_day(cluster.first_seen, tz) for cluster in clusters)
    return dict(sorted(counts.items()))


def storm_day_report(alerts: list[Alert], clusters: list[Cluster], tz: ZoneInfo, day: str) -> dict:
    day_alerts = sum(1 for alert in alerts if _local_day(alert.alert_time, tz) == day)
    day_clusters = [cluster for cluster in clusters if _local_day(cluster.first_seen, tz) == day]
    return {
        "date": day,
        "alerts": day_alerts,
        "clusters": len(day_clusters),
        "largest_cluster_size": max((cluster.count for cluster in day_clusters), default=0),
        "clusters_hit_max_size": sum(
            1 for cluster in day_clusters if cluster.closed_by == REASON_MAX_SIZE
        ),
        "clusters_hit_max_age": sum(
            1 for cluster in day_clusters if cluster.closed_by == REASON_MAX_AGE
        ),
    }


def compute_verdict(clusters: int, expect: int, tolerance_pct: float) -> dict:
    pct_diff = ((clusters - expect) / expect * 100) if expect else 0.0
    return {
        "clusters": clusters,
        "expect": expect,
        "tolerance_pct": tolerance_pct,
        "pct_diff": pct_diff,
        "passed": abs(pct_diff) <= tolerance_pct,
    }


def build_report(
    archive_file: Path,
    stats: ArchiveStats,
    clusters: list[Cluster],
    cfg: config.Config,
    expect: int,
    tolerance_pct: float,
) -> dict:
    tz = ZoneInfo(cfg.DISPLAY_TZ)
    ratio = (stats.parsed / len(clusters)) if clusters else 0.0
    return {
        "archive_file": str(archive_file),
        "lines": stats.lines,
        "parsed": stats.parsed,
        "rejected": stats.rejected,
        "rejected_by_reason": dict(stats.rejected_by_reason),
        "clusters": len(clusters),
        "ratio": ratio,
        "clusters_per_day": clusters_per_day(clusters, tz),
        "storm_day": storm_day_report(stats.alerts, clusters, tz, STORM_DAY),
        "verdict": compute_verdict(len(clusters), expect, tolerance_pct),
    }


def format_text(report: dict) -> str:
    lines = [
        f"archive: {report['archive_file']}",
        (
            f"lines: {report['lines']}  parsed: {report['parsed']}  rejected: {report['rejected']}  "
            f"clusters: {report['clusters']}  ratio: {report['ratio']:.1f} : 1 (parsed / clusters)"
        ),
    ]
    if report["rejected_by_reason"]:
        breakdown = ", ".join(f"{k}={v}" for k, v in sorted(report["rejected_by_reason"].items()))
        lines.append(f"rejected by reason: {breakdown}")
    lines.append("")
    lines.append("clusters per day (local day, Config.DISPLAY_TZ):")
    for day, count in report["clusters_per_day"].items():
        lines.append(f"  {day}: {count}")
    storm = report["storm_day"]
    lines.append("")
    lines.append(f"storm day {storm['date']}:")
    lines.append(f"  alerts: {storm['alerts']}")
    lines.append(f"  clusters: {storm['clusters']}")
    lines.append(f"  largest cluster size: {storm['largest_cluster_size']}")
    lines.append(f"  clusters that hit MAX_CLUSTER_SIZE: {storm['clusters_hit_max_size']}")
    lines.append(f"  clusters that hit MAX_CLUSTER_AGE: {storm['clusters_hit_max_age']}")
    lines.append("")
    v = report["verdict"]
    result = "PASS" if v["passed"] else "FAIL"
    lines.append(f"VERDICT: {v['clusters']} vs {v['expect']} ({v['pct_diff']:+.2f}%) — {result}")
    return "\n".join(lines)


def format_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dedup_verify.py",
        description=(
            "Offline fold of the coded dedup predicates (idle gap, age ceiling, size "
            "ceiling) over the Owner's archive export, verified against a measured "
            "cluster count. Replays no pipeline and touches no database (planning "
            "decision 9) -- the fold runs on the alerts' own timestamps only."
        ),
        epilog=(
            "Exit codes: 0 verdict PASS, 1 verdict FAIL, 2 archive file missing or unreadable.\n"
            + OWNER_PROCEDURE
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--archive-file",
        required=True,
        metavar="PATH",
        help="the Owner's exported alerts JSONL file (one manager alert object per line)",
    )
    parser.add_argument(
        "--expect",
        type=int,
        default=2778,
        metavar="N",
        help="expected cluster count to verdict against (default: %(default)s)",
    )
    parser.add_argument(
        "--tolerance-pct",
        type=float,
        default=1.0,
        metavar="PCT",
        help="tolerance around --expect, in percent (default: %(default)s)",
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        metavar="PATH",
        help="file to read the dedup Config ceilings from (default: %(default)s)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the report as one JSON object instead of the table",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    archive_path = Path(args.archive_file)
    try:
        stats = read_archive(archive_path)
    except OSError as exc:
        print(
            f"dedup_verify: refusing --archive-file {args.archive_file!r}: {exc}",
            file=sys.stderr,
        )
        print(
            "dedup_verify: the archive is exported by the Owner (P2-T13's scope-out); "
            "the procedure P2-T13's --help prints:",
            file=sys.stderr,
        )
        print(OWNER_PROCEDURE, file=sys.stderr)
        return EXIT_ARCHIVE

    cfg = config.load(env_file=args.env_file)
    clusters = fold_clusters(stats.alerts, cfg)
    report = build_report(archive_path, stats, clusters, cfg, args.expect, args.tolerance_pct)

    print(format_json(report) if args.json else format_text(report))
    return EXIT_OK if report["verdict"]["passed"] else EXIT_VERDICT_FAIL


if __name__ == "__main__":
    sys.exit(main())
