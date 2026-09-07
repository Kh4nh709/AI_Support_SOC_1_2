#!/usr/bin/env python3
"""Fold the manager archive into clusters with the phase-2 predicates and the real resolver.

The measurement behind inventory rows A1/A2/A3/A5 (DEC-052, DEC-053), reproducible by command:
cluster key `(rule_id, srcip, dstip, agent_name)`; `DEDUP_IDLE_GAP_MINUTES=15` on `last_seen`,
`MAX_CLUSTER_AGE_HOURS=4` on `first_seen`, `MAX_CLUSTER_SIZE=1000`; alerts folded in archive
order with the alert's own timestamp as the clock (a pipeline replay measures the DB clock,
not the data — P2-tasks.md planning decision 9). Severity is `rule.level` banded per
`docs/phase-1-tiep-nhan-chuan-hoa.md:148` (>= 12 critical, >= 8 high, >= 5 medium, else low);
`--withdrawn-band` also prints the >= 12 / >= 9 / >= 7 banding DEC-053 withdrew, for comparison.
Category is `backend/app/ingest/category.py`'s `resolve()` on the cluster head.

    python3 scripts/measure_clusters.py --archive /home/user1/archive/alerts-2026-08-08_09-07.jsonl
    python3 scripts/measure_clusters.py --archive ... --routes     # the A5 decision table

Verified 07/09 against the Owner's and the Director's figures: 3,070 clusters; windows of
exactly N x 24 h before the last alert give 363 / 466 / 1,132 / 3,070 at 4 / 7 / 14 / 30 days;
spec band critical 25 / high 150 / medium 1,695 / low 1,200 (crit+high 175); withdrawn band
high 133 (crit+high 158); unknown 1,812; loopback ssh_brute_force 662 alerts; DESKTOP-MIRSO17 23.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))
from app.ingest.category import PRIORITY, resolve

IDLE = dt.timedelta(minutes=15)
MAX_AGE = dt.timedelta(hours=4)
MAX_SIZE = 1000
SEVERITIES = ("critical", "high", "medium", "low")
PLAYBOOKS = tuple(c for c in PRIORITY if c != "unknown")
# rule.groups families among `unknown` clusters, first match wins (07/09 measurement).
FAMILIES = (
    "vulnerability-detector",
    "syscheck",
    "sca",
    "audit",
    "systemd",
    "dpkg",
    "pam",
    "windows",
    "adduser",
    "ossec",
    "stats",
)
ROUTES = {
    "4 keep unknown, report it (as-is)": {},
    "1 extend (as framed): syscheck, vulnerability-detector -> new categories": {
        "syscheck": "file_integrity",
        "vulnerability-detector": "vulnerability",
    },
    "2 map onto existing: syscheck, vulnerability-detector -> policy_violation": {
        "syscheck": "policy_violation",
        "vulnerability-detector": "policy_violation",
    },
    "3a exclude syscheck + vulnerability-detector clusters from G1": {
        "syscheck": None,
        "vulnerability-detector": None,
    },
    "3b exclude every unknown cluster from G1": {f: None for f in FAMILIES + ("other",)},
    "1-wide extend: a new category per family >= 20 clusters": {
        "syscheck": "file_integrity",
        "vulnerability-detector": "vulnerability",
        "sca": "compliance_check",
        "audit": "system_audit",
        "systemd": "service_event",
        "dpkg": "package_change",
        "pam": "auth_session",
        "windows": "windows_event",
        "adduser": "account_change",
        "ossec": "wazuh_internal",
    },
}


def band_spec(level: int) -> str:
    return (
        "critical" if level >= 12 else "high" if level >= 8 else "medium" if level >= 5 else "low"
    )


def band_withdrawn(level: int) -> str:
    return (
        "critical" if level >= 12 else "high" if level >= 9 else "medium" if level >= 7 else "low"
    )


def parse_ts(value: str) -> dt.datetime:
    if len(value) >= 5 and value[-5] in "+-" and value[-3] != ":":
        value = value[:-2] + ":" + value[-2:]  # +0700 -> +07:00 (phase-1 §Khối 3)
    return dt.datetime.fromisoformat(value)


def safe_int(value, default=0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def load(archive: pathlib.Path) -> list[dict]:
    alerts = []
    with archive.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            doc = json.loads(line)
            rule = doc.get("rule") or {}
            data = doc.get("data") if isinstance(doc.get("data"), dict) else {}
            agent = doc.get("agent") or {}
            manager = doc.get("manager") or {}
            alerts.append(
                {
                    "t": parse_ts(doc["timestamp"]),
                    "rule_id": str(rule.get("id")),
                    "level": safe_int(rule.get("level")),
                    "srcip": str(data.get("srcip") or ""),
                    "dstip": str(data.get("dstip") or ""),
                    "agent": str(agent.get("name") or manager.get("name") or ""),
                    "mitre": (rule.get("mitre") or {}).get("id") or [],
                    "groups": list(rule.get("groups") or []),
                    "decoder": (doc.get("decoder") or {}).get("name"),
                    "dstport": safe_int(data.get("dstport"), 0),
                }
            )
    return alerts


def fold(alerts: list[dict], since: dt.datetime | None = None) -> list[dict]:
    """The six predicates, minus the three that need a live row (still absorbing, not a
    duplicate, auto-closed cap): one open cluster per key, joined while inside the caps."""
    latest: dict[tuple, dict] = {}
    clusters: list[dict] = []
    for a in alerts:
        if since is not None and a["t"] < since:
            continue
        key = (a["rule_id"], a["srcip"], a["dstip"], a["agent"])
        c = latest.get(key)
        if (
            c
            and a["t"] - c["last"] <= IDLE
            and a["t"] - c["first"] <= MAX_AGE
            and c["n"] < MAX_SIZE
        ):
            c["last"] = a["t"]
            c["n"] += 1
        else:
            c = {"head": a, "first": a["t"], "last": a["t"], "n": 1}
            latest[key] = c
            clusters.append(c)
    for c in clusters:
        h = c["head"]
        res = resolve(h["mitre"], h["groups"], h["decoder"], h["dstport"])
        c["cat"], c["by"], c["sev"] = res.category, res.resolved_by, band_spec(h["level"])
        c["family"] = next((f for f in FAMILIES if f in h["groups"]), "other")
    return clusters


def route_view(clusters: list[dict], mapping: dict[str, str | None]) -> list[dict]:
    out = []
    for c in clusters:
        cat = c["cat"]
        if cat == "unknown" and c["family"] in mapping:
            target = mapping[c["family"]]
            if target is None:
                continue
            cat = target
        out.append({**c, "cat2": cat})
    return out


def grid_table(view: list[dict], denominator: int) -> str:
    grid = collections.Counter((c["cat2"], c["sev"]) for c in view)
    dist = collections.Counter(c["cat2"] for c in view)
    lines = ["| category | " + " | ".join(SEVERITIES) + " | total | share |", "|---|" + "---|" * 6]
    for cat, _ in dist.most_common():
        row = [grid.get((cat, s), 0) for s in SEVERITIES]
        cells = " | ".join(f"{v}{'' if v >= 10 else ' ·'}" for v in row)
        lines.append(f"| {cat} | {cells} | {sum(row)} | {100 * sum(row) / denominator:.1f} % |")
    ge10 = sum(1 for v in grid.values() if v >= 10)
    lines.append(f"\n(· = under 10 clusters; cells ≥ 10: {ge10} of {len(grid)} non-empty)")
    return "\n".join(lines)


def routes_report(clusters: list[dict]) -> str:
    header = (
        "| route | G1 clusters | unknown (share) | B1 can express a rule for | crit+high | crit+high "
        "B1-expressible | non-empty cells | cells ≥ 10 | unknown in a proportional 300 | new categories |"
    )
    out = [header, "|---|---|---|---|---|---|---|---|---|---|"]
    grids = []
    for name, mapping in ROUTES.items():
        view = route_view(clusters, mapping)
        n = len(view)
        dist = collections.Counter(c["cat2"] for c in view)
        grid = collections.Counter((c["cat2"], c["sev"]) for c in view)
        new = sorted(set(dist) - set(PLAYBOOKS) - {"unknown"})
        tabled = set(PLAYBOOKS) | set(new)  # route 1 assumes its new tables get authored
        b1 = sum(1 for c in view if c["cat2"] in tabled)
        ch = [c for c in view if c["sev"] in ("critical", "high")]
        ch_b1 = sum(1 for c in ch if c["cat2"] in tabled)
        unk = dist["unknown"]
        out.append(
            f"| {name} | {n:,} | {unk:,} ({100 * unk / n:.1f} %) | {b1:,} ({100 * b1 / n:.1f} %) | "
            f"{len(ch)} ({100 * len(ch) / n:.1f} %) | {ch_b1} of {len(ch)} | {len(grid)} | "
            f"{sum(1 for v in grid.values() if v >= 10)} | {round(300 * unk / n)} | "
            f"{len(new)}: {', '.join(new) or '—'} |"
        )
        grids.append(
            f"\n### {name} — category × severity (clusters; denominator {n:,})\n\n"
            + grid_table(view, n)
        )
    return "\n".join(out) + "\n" + "\n".join(grids)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--archive", required=True, type=pathlib.Path)
    ap.add_argument("--routes", action="store_true", help="print the A5 decision table")
    ap.add_argument("--withdrawn-band", action="store_true", help="also band >=12/>=9/>=7")
    args = ap.parse_args(argv)

    alerts = load(args.archive)
    end = alerts[-1]["t"]
    print(f"alerts {len(alerts):,} · {alerts[0]['t']} → {end}")
    for days in (4, 7, 14, 30):
        n = len(fold(alerts, end - dt.timedelta(days=days)))
        print(f"clusters in the last {days:2d} × 24 h: {n:,}")
    clusters = fold(alerts)
    n = len(clusters)
    print(f"clusters, whole archive: {n:,} (denominator for every share below)")
    sev = collections.Counter(c["sev"] for c in clusters)
    print(
        "severity by cluster, spec band (phase-1:148): "
        + ", ".join(f"{s} {sev[s]:,}" for s in SEVERITIES)
        + f" — crit+high {sev['critical'] + sev['high']}"
    )
    if args.withdrawn_band:
        w = collections.Counter(band_withdrawn(c["head"]["level"]) for c in clusters)
        print(
            "severity by cluster, withdrawn band (>=12/>=9/>=7): "
            + ", ".join(f"{s} {w[s]:,}" for s in SEVERITIES)
            + f" — crit+high {w['critical'] + w['high']}"
        )
    cat = collections.Counter(c["cat"] for c in clusters)
    print("category by cluster: " + ", ".join(f"{k} {v:,}" for k, v in cat.most_common()))
    zero = [p for p in PLAYBOOKS if cat[p] == 0]
    print(
        f"playbook categories with zero live clusters: {len(zero)} of {len(PLAYBOOKS)} — {', '.join(zero)}"
    )
    unk = [c for c in clusters if c["cat"] == "unknown"]
    fam = collections.Counter(c["family"] for c in unk)
    print("unknown by rule.groups family: " + ", ".join(f"{k} {v}" for k, v in fam.most_common()))
    print(f"unknown crit+high clusters: {sum(1 for c in unk if c['sev'] in ('critical', 'high'))}")
    lb = [
        c for c in clusters if c["cat"] == "ssh_brute_force" and c["head"]["srcip"] == "127.0.0.1"
    ]
    print(f"loopback ssh_brute_force: {sum(c['n'] for c in lb)} alerts in {len(lb)} clusters")
    agents = collections.Counter(c["head"]["agent"] for c in clusters)
    print("clusters by agent: " + ", ".join(f"{k} {v:,}" for k, v in agents.most_common()))
    if args.routes:
        print("\n## A5 routes\n")
        print(routes_report(clusters))
        print("\n## Unknown crit+high clusters by rule\n")
        rows = collections.Counter(
            (c["head"]["rule_id"], c["head"]["level"], c["family"])
            for c in unk
            if c["sev"] in ("critical", "high")
        )
        print("| rule.id | level | family | clusters |\n|---|---|---|---|")
        for (rid, lvl, f), v in rows.most_common():
            print(f"| {rid} | {lvl} | {f} | {v} |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
