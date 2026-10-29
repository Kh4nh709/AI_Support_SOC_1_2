"""tier2/case_view.py — the case page's read-side helpers behind the JSON case detail
(`GET /api/tier2/cases/{id}`, which the React case page reads) — P10-T04.

`supplement` and `enrich_heads` moved here from the Jinja case page's router (`_supplement`,
`_enrich_heads`; that page retired in P10-T13) unchanged in rule and behaviour; the one
difference is named below.
`usernames` is new: one read for the display names of a case's concluder and note authors.

**Layering (G1).** `tier2` may not import `tier1` or `web`, and the head's `risk_band` is
the *label* the queue rows show (`tier1.queue.risk_band`: "Thấp" / "Vừa" / "Cao" /
"Rất cao"). `head_band` therefore takes the thresholds from `llm.builder.risk_band` (the
same 0-24 / 25-49 / 50-74 / 75-100 bands, which `tier2.dossier` already imports) and maps
the four enum members to the four labels here. `test_case_view_api.py` pins that mapping to
`tier1.queue.risk_band` for every score, so the two cannot drift apart unseen.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import psycopg

from app.llm.builder import RiskBand
from app.llm.builder import risk_band as _band_of

_SUPPLEMENT_COLUMNS: tuple[str, ...] = (
    "alert_id",
    "raw_log",
    "raw_log_truncated",
    "risk_score",
    "last_seen_at",
)

#: `RiskBand` → the Vietnamese label the queue rows carry (`tier1.queue._BANDS`), one entry
#: per member. Pinned to `tier1.queue.risk_band` by `test_case_view_api.py`.
_BAND_LABELS: dict[RiskBand, str] = {
    RiskBand.LOW: "Thấp",
    RiskBand.MEDIUM: "Vừa",
    RiskBand.HIGH: "Cao",
    RiskBand.VERY_HIGH: "Rất cao",
}


def head_band(score: int | None) -> str | None:
    """`None` → `None`; else the band label of `score` — the same value
    `tier1.queue.risk_band` returns, computed without importing `tier1` (module docstring)."""
    band = _band_of(score)
    return None if band is None else _BAND_LABELS[band]


def supplement(conn: psycopg.Connection, alert_ids: list[str]) -> dict[str, dict[str, Any]]:
    """`raw_log`, `raw_log_truncated`, `risk_score` and `last_seen_at` for
    `alert_ids` — the fields `case_detail`'s own head query does not select. One
    `alert_id = ANY(...)` read, G10 explicit columns, `{}` for an empty case."""
    if not alert_ids:
        return {}
    rows = conn.execute(
        f"SELECT {', '.join(_SUPPLEMENT_COLUMNS)} FROM alerts WHERE alert_id = ANY(%s)",
        (alert_ids,),
    ).fetchall()
    return {row[0]: dict(zip(_SUPPLEMENT_COLUMNS[1:], row[1:], strict=True)) for row in rows}


def enrich_heads(
    conn: psycopg.Connection, heads: list[dict[str, Any]], since: datetime
) -> datetime | None:
    """Merges `supplement`'s fields into each head in place — `raw_log`
    (plain text in the JSON; the React UI renders it as text) with `raw_log_truncated`,
    `risk_band` (`risk_score` replaced by the band, never the bare number —
    P4's rule; `risk_score` itself is not stored on the dict, so it cannot
    leak into the response by accident) and `last_seen_at` (shown per head,
    formatted by the client, design note 3).

    Returns the latest `last_seen_at` among heads that are both still
    `escalated_tier2` **and** newer than `since` — `None` when no head
    qualifies. Review round 1, blocker B1: `alerts.last_seen_at` is `NOT NULL
    DEFAULT now()`, so `last_seen_at is not None` alone is always true and
    the old rule reduced to "the case is open." `since` is
    `case.last_analyzed_at or case.created_at`, matching
    `docs/phase-7-tier2.md:452`'s "`last_seen_at` mới hơn `last_analyzed_at`"
    once ② starts writing `last_analyzed_at`, and correct before that too:
    `escalate` inserts the case and its heads in one transaction (`now()` is
    the transaction start time), so an unbumped head's `last_seen_at` equals
    `case.created_at` exactly — not "newer than" — and only `bump_parent`
    (a duplicate arriving) ever moves it forward. Known limit, noted in the
    report: a duplicate whose dedup transaction overlaps the `escalate`
    transaction can be missed until the next duplicate arrives, since both
    transactions read their own `now()` snapshot.
    """
    extras = supplement(conn, [h["alert_id"] for h in heads])
    ongoing_last_seen = None
    for head in heads:
        extra = extras.get(head["alert_id"], {})
        head["raw_log"] = extra.get("raw_log", "")
        head["raw_log_truncated"] = bool(extra.get("raw_log_truncated"))
        head["risk_band"] = head_band(extra.get("risk_score"))
        last_seen = extra.get("last_seen_at")
        head["last_seen_at"] = last_seen
        is_growing = (
            head["status"] == "escalated_tier2" and last_seen is not None and last_seen > since
        )
        if is_growing and (ongoing_last_seen is None or last_seen > ongoing_last_seen):
            ongoing_last_seen = last_seen
    return ongoing_last_seen


def usernames(conn: psycopg.Connection, user_ids: set[Any]) -> dict[str, str]:
    """`{str(user_id): username}` for the ids in `user_ids` that name a user. `None`
    members are ignored and an unknown id is simply absent — never raises; a
    display-only lookup, one `user_id = ANY(...)` read, `{}` for an empty set."""
    ids = sorted({str(user_id) for user_id in user_ids if user_id is not None})
    if not ids:
        return {}
    rows = conn.execute(
        "SELECT user_id, username FROM users WHERE user_id = ANY(%s::uuid[])", (ids,)
    ).fetchall()
    return {str(user_id): username for user_id, username in rows}


_LAST_RUN_SQL = """
    SELECT created_at, result IS NOT NULL
    FROM llm_runs
    WHERE pipeline = 'investigate' AND subject_id = %s
    ORDER BY created_at DESC, run_id DESC
    LIMIT 1
"""


def last_run(conn: psycopg.Connection, case_id: str) -> dict[str, Any] | None:
    """The newest ② run of the case, `{"created_at": datetime, "has_result": bool}`, or `None`
    when ② has never run on it (INT-T02, DEC-211 R6).

    The case page's "Phân tích gần nhất" used to read `cases.last_analyzed_at`, which only a run
    *with a result* writes (`tier2/investigate.py`), so a run that stopped (a provider 402 is
    `stopped_by='permanent'`) left it empty and the page said "chưa phân tích" about a case ② had
    been run on. This is the field that follows the newest row of `llm_runs` instead, whatever
    its `stopped_by`: a retry's `transient` row counts too, as it is a run that ended without a
    result, and the next attempt's row replaces it once there is one. `last_analyzed_at` itself is
    unchanged and still drives `ongoing` and the timeline: a run that stopped is no analysis, so
    it does not make the case's growth "already analysed"."""
    row = conn.execute(_LAST_RUN_SQL, (case_id,)).fetchone()
    if row is None:
        return None
    return {"created_at": row[0], "has_result": bool(row[1])}
