"""Alert and Case fields, and the status/triage_status/case_status closed-set constants.

`Alert` and `AlertContext` are shared values: `ingest/wazuh_parser.py` builds an
`Alert`, `enrichment/lookups.py` fills the dict that becomes an `AlertContext`
(`soar/pipeline.py` constructs it — `enrichment` may not import `domain`,
P2-tasks.md planning decision 4), `ingest/autoclose.py` and `soar/risk.py` read
it. `severity_from_level()` and `compute_event_bucket_hash()` live here, not in
`ingest/`, so both packages share one definition (phase-1 §Phụ thuộc).
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

#: phase-1 Khối 4, verbatim.
_SEVERITY_THRESHOLDS: tuple[tuple[int, str], ...] = (
    (12, "critical"),
    (8, "high"),
    (5, "medium"),
)


def severity_from_level(level: int) -> str:
    """`rule.level` -> SIEM severity (phase-1 Khối 4). Pipeline ① re-derives its
    own severity later; this is the SIEM's opinion, kept for comparison."""
    for threshold, name in _SEVERITY_THRESHOLDS:
        if level >= threshold:
            return name
    return "low"


def compute_event_bucket_hash(
    rule_id: str,
    srcip: str | None,
    dstip: str | None,
    agent_name: str,
    alert_time: datetime,
) -> str:
    """sha256 of `rule_id|srcip|dstip|agent_name|bucket`, `bucket = floor(epoch_utc / 300)`
    (phase-1 Khối 6, chốt C1/B6). Identifies an *event* inside one 5-minute bucket —
    it is NOT the cluster key (that is `(rule_id, srcip, dstip, agent_name)`, phase 2).

    `alert_time` is converted to UTC here regardless of the tzinfo it carries
    (R8: the same instant in two zones must hash the same); a `NULL` field is
    joined as `''`, never the string `'None'` (B1's convention holds for the
    hash too — the chốt value must not move when `''` replaces `NULL`).
    """
    bucket = int(alert_time.astimezone(UTC).timestamp()) // 300
    payload = "|".join(
        (
            rule_id or "",
            srcip or "",
            dstip or "",
            agent_name or "",
            str(bucket),
        )
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AlertContext:
    """Enrichment facts about one alert's asset/identity/IoC, in the DEC-004
    vocabulary. `ingest/autoclose.py` (hard blocks) and `soar/risk.py` read
    this; `enrichment/lookups.py` (P2-T08) produces the plain dict that
    `soar/pipeline.py` turns into one of these — `enrichment` may not import
    `domain` (P2-tasks.md planning decision 4).

    Three-state lookup result (phase-4 "Ba trạng thái"), not two:
    `found` (looked up, has a result), `not_found` (looked up, no result — a
    security signal), `skipped` (not looked up, e.g. a private IP — NOT a
    security signal, and `risk_score` must never penalise it).
    """

    asset_present: bool
    asset_criticality: str  # high | medium | low | unknown
    asset_owner: str | None
    asset_role: str | None
    identity_privileged: bool | None
    ioc_reputation: str  # malicious | suspicious | clean | not_found | skipped
    lookup_status: Mapping[str, str]  # values: found | not_found | skipped


@dataclass(frozen=True)
class Alert:
    """One alert, deterministically derived by `ingest/wazuh_parser.py` from
    whichever of the three Wazuh document shapes it was given, plus the
    lifecycle defaults phase-1's "Dữ liệu đầu ra kỳ vọng" lists for a row that
    has not yet gone through dedup/enrichment/auto-close/risk (P2-T05/T06/T08/
    T09/T10 own those). `raw_payload` is the alert object as read — the
    indexer envelope (`_id`, `_index`, `sort`) is not part of it (P2-T11/T13
    keep that on `intake.raw_text` instead, per G9 as re-worded by DEC-023).
    """

    # ── ① from the SIEM ──────────────────────────────────────────────────
    alert_id: str
    manager_id: str
    rule_id: str
    description: str
    agent_name: str
    agent_id: str | None
    agent_ip: str | None
    origin_host: str
    alert_time: datetime
    # Always None in P2 (planning decision 5): F4 fills it only when the
    # agent's timezone is declared in the inventory, and the inventory format
    # (P0-T05) has no such field. `predecoder.timestamp` stays in raw_payload.
    event_time: datetime | None
    srcip: str
    dstip: str
    src_port: int
    dst_port: int
    alert_user: str | None
    decoder: str | None
    mitre_ids: tuple[str, ...]
    rule_groups: tuple[str, ...]
    rule_level: int
    severity: str

    # ── category resolution (ingest.category.resolve, P2-T03) ──────────────
    category: str
    categories: tuple[str, ...]
    resolved_by: str
    mapping_version: str

    # ── ② derived flags ──────────────────────────────────────────────────
    srcip_is_private: bool | None
    dstip_is_private: bool | None
    raw_log: str
    raw_log_truncated: bool

    # ── audit/reconciliation ────────────────────────────────────────────
    event_bucket_hash: str

    # ── ④ the alert object, unmodified ──────────────────────────────────
    raw_payload: Mapping[str, object]

    # ── ③ lifecycle — not decided by the parser; one shape for P2-T06/T10 ──
    status: str = "received"
    duplicate_of: str | None = None
    occurrence_count: int = 1
    risk_score: int | None = None
    triage_status: str = "pending"
    triaged_count: int = 0
    case_id: str | None = None
    acknowledged_at: datetime | None = None
    closed_at: datetime | None = None
    close_reason: str | None = None
