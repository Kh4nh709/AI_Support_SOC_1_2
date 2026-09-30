"""Order and page the Tier-1 queue by risk score and arrival time for the analyst to work.

Two readers and one helper, all read-only (`SELECT`s inside the caller's transaction;
nothing here writes `alerts` — G2), every column list explicit (G10):

- `list_queue` — the phase-6 queue (`docs/phase-6-tier1.md` §Hàng đợi): `needs_retriage`
  computed at query time, `risk_score DESC NULLS LAST`, `first_seen_at ASC`, `NOT
  is_synthetic`, OFFSET paging. P10-T02 adds the optional `band`/`category`/`agent`/`status`
  filters and `counts_by_band` for the React queue; with none of them it is what it was.
- `get_alert_view` — everything the detail page (P4-T05) and the labelling page (P6-T02)
  render: the head, its targeted accounts, the ±2 h correlation *now*, the playbook, the ①
  suggestion, the acknowledger's name.
- `latest_suggestion` — **the one place in P4 that reads `llm_runs`** (planning decision
  5). The row shape is P3-T10's and may still move; every read here is `.get`-tolerant,
  and this function is where to follow it.

Both readers pass their dict through `visibility.strip` before returning it, so the blind
branch (context pack §6.4) is enforced here, never in a template. `risk_score` never
leaves this module as a bare number — the four-band `risk_band` replaces it (phase-4
constraint 5).
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Literal

import psycopg

from app.domain import correlation
from app.kb.lookup import get_playbook
from app.tier1 import visibility

#: `needs_retriage` — phase-2's v1 constants, `docs/phase-2-chong-trung-lap.md:321`.
#: Module constants on purpose, **not** `Config`: §6.3 is frozen and P2/P3 never needed
#: them (planning decision 6). Unvalidated in v1 — a P8 limitation, not a knob.
RETRIAGE_FACTOR = 10
RETRIAGE_ABS_DELTA = 200

PAGE_SIZE_DEFAULT = 50
PAGE_SIZE_MAX = 200

#: `docs/phase-4-enrichment.md:198-207` — the band, never the bare number.
_BANDS: tuple[tuple[int, str], ...] = ((24, "Thấp"), (49, "Vừa"), (74, "Cao"), (100, "Rất cao"))


def risk_band(score: int | None) -> str | None:
    """`None` → `None`; 0–24 Thấp · 25–49 Vừa · 50–74 Cao · 75–100 Rất cao. A value outside
    0–100 is clamped (the formula caps at 100 — phase-4 constraint 3)."""
    if score is None:
        return None
    clamped = max(0, min(100, score))
    for upper, label in _BANDS:
        if clamped <= upper:
            return label
    raise AssertionError("unreachable: clamped to 0-100")  # pragma: no cover


#: The four codes the API speaks for the risk band (P10-T02), in `_BANDS` order — `risk_band`'s
#: label for the same range is the row's own `risk_band` value and does not change. The filter's
#: SQL bounds and `counts_by_band`'s CASE are derived from `_BANDS`, never from a second copy.
BAND_CODES: tuple[str, ...] = ("low", "medium", "high", "critical")
if len(BAND_CODES) != len(_BANDS):  # pragma: no cover
    raise AssertionError("BAND_CODES must name every band in _BANDS")


def _band_bounds(band: str) -> tuple[int | None, int | None]:
    """Inclusive `(lo, hi)` score bounds of `band` (`None` = unbounded on that side, because
    `risk_band` clamps a score outside 0–100 into the end bands). An unknown `band` →
    `ValueError`."""
    try:
        i = BAND_CODES.index(band)
    except ValueError:
        raise ValueError(f"band must be one of {'|'.join(BAND_CODES)}, got {band!r}") from None
    lo = _BANDS[i - 1][0] + 1 if i > 0 else None
    hi = _BANDS[i][0] if i < len(_BANDS) - 1 else None
    return lo, hi


def _band_sql(lo: int | None, hi: int | None) -> str:
    """`WHERE` fragment for `_band_bounds`, built from fixed text and named parameters. A NULL
    `risk_score` fails every comparison, so it is in no band (`risk_band(None)` is `None`)."""
    parts = []
    if lo is not None:
        parts.append("a.risk_score >= %(band_lo)s")
    if hi is not None:
        parts.append("a.risk_score <= %(band_hi)s")
    return " AND ".join(parts) or "a.risk_score IS NOT NULL"


def _band_case() -> tuple[str, dict[str, Any]]:
    """The SQL twin of `risk_band` for `counts_by_band`: a `CASE` over `_BANDS` yielding the
    band code (NULL for a NULL score). Bounds and codes travel as parameters; the only text
    formatted in is the index of a band."""
    whens: list[str] = []
    params: dict[str, Any] = {}
    for i, (upper, _label) in enumerate(_BANDS[:-1]):
        whens.append(f"WHEN a.risk_score <= %(band_upper_{i})s THEN %(band_code_{i})s::text")
        params[f"band_upper_{i}"] = upper
        params[f"band_code_{i}"] = BAND_CODES[i]
    last = len(_BANDS) - 1
    params[f"band_code_{last}"] = BAND_CODES[last]
    sql = (
        "CASE WHEN a.risk_score IS NULL THEN NULL "
        + " ".join(whens)
        + f" ELSE %(band_code_{last})s::text END"
    )
    return sql, params


_BAND_CASE_SQL, _BAND_CASE_PARAMS = _band_case()


# ---------------------------------------------------------------------------
# ① — the one reader of llm_runs
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Suggestion:
    """The latest ① proposer run for one alert, in the shape the detail page and P4-T03's
    `decide` consume. `suggested_action` is `result["suggested_action"]` — already the
    gated verdict (G11), never `gate_result.proposed_verdict`."""

    run_id: str
    suggested_action: str | None
    confidence: str | None
    reasons: list[dict[str, Any]]
    gate: dict[str, Any]
    correlated_at_analysis: int | None
    created_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


_SUGGESTION_SQL = """
    SELECT run_id, result, gate_result, created_at
    FROM llm_runs
    WHERE subject_id = %s AND pipeline = 'triage' AND role = 'proposer'
    ORDER BY created_at DESC
    LIMIT 1
"""


def _reason(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, Mapping):
        return None
    return {"claim": item.get("claim"), "quote": item.get("quote"), "source": item.get("source")}


def latest_suggestion(conn: psycopg.Connection, alert_id: str) -> Suggestion | None:
    """The latest `role = 'proposer'` triage run for `alert_id`, or `None` when there is
    none or its `result` is NULL (① failed — `stopped_by` set). Every key is read with
    `.get`: a key P3-T10 does not write becomes `None`, never a `KeyError`."""
    row = conn.execute(_SUGGESTION_SQL, (alert_id,)).fetchone()
    if row is None:
        return None
    run_id, result, gate_result, created_at = row
    if result is None:
        return None
    gate_result = gate_result if isinstance(gate_result, Mapping) else {}
    facts = gate_result.get("facts")
    facts = facts if isinstance(facts, Mapping) else {}
    raw_reasons = result.get("reasons") or []
    reasons = [r for r in (_reason(item) for item in raw_reasons[:10]) if r is not None]
    return Suggestion(
        run_id=str(run_id),
        suggested_action=result.get("suggested_action"),
        confidence=result.get("confidence"),
        reasons=reasons,
        gate={
            "forced": gate_result.get("forced"),
            "forced_by": gate_result.get("forced_by"),
            "proposed_verdict": gate_result.get("proposed_verdict"),
            "final_verdict": gate_result.get("final_verdict"),
            "verifier_verdict": gate_result.get("verifier_verdict"),
            "warnings": gate_result.get("warnings") or [],
        },
        correlated_at_analysis=facts.get("correlated_clusters"),
        created_at=created_at,
    )


# ---------------------------------------------------------------------------
# The queue
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class QueuePage:
    """`total` is the count under every filter; `counts_by_band` is the count per band code
    under every filter **except** `band` (so the band chips still show the other bands), with
    all four keys always present. The default lets a caller that builds a page by hand
    (the Jinja page's tests) omit it."""

    rows: list[dict[str, Any]]
    total: int
    page: int
    page_size: int
    counts_by_band: dict[str, int] = dataclasses.field(
        default_factory=lambda: dict.fromkeys(reversed(BAND_CODES), 0)
    )


# The phase-6 SQL (docs/phase-6-tier1.md:24-39) with two changes:
#  1. the join is LATERAL on the latest `role = 'proposer'` row — ① writes a proposer
#     *and* a verifier row per alert, and the doc's plain `LEFT JOIN … pipeline = 'triage'`
#     would return every triaged head twice (planning decision 5);
#  2. the column list is explicit and wider (G10), and `status`/`suggestion_visible` are
#     read so `visibility.strip` can be applied per row.
# `LEFT JOIN`, not `JOIN` (H6): a `triage_status = 'unavailable'` head has no run and
# must still be listed. `needs_retriage` is computed here, not stored.
_QUEUE_COLUMNS = (
    "alert_id",
    "rule_id",
    "description",
    "category",
    "severity",
    "agent_name",
    "risk_score",
    "occurrence_count",
    "triaged_count",
    "first_seen_at",
    "last_seen_at",
    "alert_time",
    "suggestion_visible",
    "triage_status",
    "status",
    "run_id",
    "suggested_action",
    "confidence",
    "gate_forced",
    "needs_retriage",
)
_QUEUE_SQL = """
    SELECT a.alert_id, a.rule_id, a.description, a.category, a.severity, a.agent_name,
           a.risk_score, a.occurrence_count, a.triaged_count, a.first_seen_at, a.last_seen_at,
           a.alert_time, a.suggestion_visible, a.triage_status, a.status,
           r.run_id,
           r.result->>'suggested_action',
           r.result->>'confidence',
           r.gate_result->>'forced',
           (a.triaged_count > 0 AND
            (a.occurrence_count >= a.triaged_count * %(retriage_factor)s
             OR a.occurrence_count - a.triaged_count >= %(retriage_abs_delta)s)) AS needs_retriage
    FROM alerts a
    LEFT JOIN LATERAL (
        SELECT run_id, result, gate_result
        FROM llm_runs r
        WHERE r.subject_id = a.alert_id AND r.pipeline = 'triage' AND r.role = 'proposer'
        ORDER BY r.created_at DESC
        LIMIT 1
    ) r ON true
    WHERE {where}
    ORDER BY needs_retriage DESC, a.risk_score DESC NULLS LAST, a.first_seen_at ASC
    LIMIT %(limit)s OFFSET %(offset)s
"""
_QUEUE_COUNT_SQL = "SELECT count(*) FROM alerts a WHERE {where}"
_QUEUE_BAND_COUNTS_SQL = "SELECT {band_case}, count(*) FROM alerts a WHERE {where} GROUP BY 1"

#: The two lists a caller may ask for. Only these fixed fragments — and `_band_sql`'s — are ever
#: formatted into a `WHERE`; every user value travels as a named parameter.
_STATUS_WHERE = {
    "queued": "a.status = 'queued_tier1'",
    "mine": "a.status = 'tier1_active' AND a.acknowledged_by = %(actor_id)s",
}


def _no_nul(name: str, value: str) -> str:
    """A NUL byte cannot be sent as a `text` parameter (psycopg raises a driver-level error,
    not a clean 422): refuse it here, as the request bodies' own validators do."""
    if "\x00" in value:
        raise ValueError(f"{name} must not contain a NUL byte")
    return value


def _filters(
    band: str | None,
    category: str | None,
    agent: str | None,
    status: str,
    actor_id: str | None,
    *,
    with_band: bool,
) -> tuple[str, dict[str, Any]]:
    """The `WHERE` body and its named parameters. `with_band=False` is `counts_by_band`'s
    variant: every filter except the band (an unknown band is still refused)."""
    if status not in _STATUS_WHERE:
        raise ValueError(f"status must be one of {'|'.join(_STATUS_WHERE)}, got {status!r}")
    where = [_STATUS_WHERE[status], "NOT a.is_synthetic"]
    params: dict[str, Any] = {}
    if status == "mine":
        if actor_id is None:
            raise ValueError("status 'mine' needs actor_id")
        params["actor_id"] = actor_id
    if category is not None:
        where.append("a.category = %(category)s")
        params["category"] = _no_nul("category", category)
    if agent is not None:
        where.append("a.agent_name = %(agent)s")
        params["agent"] = _no_nul("agent", agent)
    if band is not None:
        lo, hi = _band_bounds(band)  # ValueError on an unknown band
        if with_band:
            where.append(_band_sql(lo, hi))
            if lo is not None:
                params["band_lo"] = lo
            if hi is not None:
                params["band_hi"] = hi
    return " AND ".join(where), params


#: `r.gate_result->>'forced'` is jsonb text (`'true'`/`'false'`/NULL); the row carries a bool.
_JSON_BOOL = {"true": True, "false": False}


def list_queue(
    conn: psycopg.Connection,
    *,
    page: int = 1,
    page_size: int = PAGE_SIZE_DEFAULT,
    band: str | None = None,
    category: str | None = None,
    agent: str | None = None,
    status: Literal["queued", "mine"] = "queued",
    actor_id: str | None = None,
) -> QueuePage:
    """One page of the Tier-1 queue in the phase-6 order. Each row carries the queue
    columns plus `risk_band` and **minus** `risk_score`, already passed through
    `visibility.strip(mode="analyst")` — a blind, undecided head has no
    `suggested_action`/`confidence`/`gate_forced`/`triage_status` keys at all, under every
    filter.

    Filters (P10-T02), all optional and ANDed: `band` — one of `BAND_CODES`
    (`low|medium|high|critical`), the score range `risk_band` labels with the matching name;
    `category`; `agent` (`agent_name`); `status` — `"queued"` (`queued_tier1`, the default and
    what this function always returned) or `"mine"` (`tier1_active` acknowledged by
    `actor_id`). `total` counts the filtered set; `counts_by_band` counts under every filter
    except `band`.

    `page < 1` or `page_size < 1`, an unknown `band` or `status`, `status="mine"` without an
    `actor_id`, or a NUL byte in `category`/`agent` → `ValueError`; `page_size >
    PAGE_SIZE_MAX` is clamped."""
    if page < 1:
        raise ValueError(f"page must be >= 1, got {page}")
    if page_size < 1:
        raise ValueError(f"page_size must be >= 1, got {page_size}")
    page_size = min(page_size, PAGE_SIZE_MAX)
    offset = (page - 1) * page_size

    where, params = _filters(band, category, agent, status, actor_id, with_band=True)
    cur = conn.execute(
        _QUEUE_SQL.format(where=where),
        {
            **params,
            "retriage_factor": RETRIAGE_FACTOR,
            "retriage_abs_delta": RETRIAGE_ABS_DELTA,
            "limit": page_size,
            "offset": offset,
        },
    )
    rows: list[dict[str, Any]] = []
    for record in cur.fetchall():
        row = dict(zip(_QUEUE_COLUMNS, record, strict=True))
        row["risk_band"] = risk_band(row.pop("risk_score"))
        if row["run_id"] is not None:
            row["run_id"] = str(row["run_id"])
        row["gate_forced"] = _JSON_BOOL.get(row["gate_forced"])
        rows.append(
            visibility.strip(
                row,
                status=row["status"],
                suggestion_visible=row["suggestion_visible"],
                mode="analyst",
            )
        )
    total = conn.execute(_QUEUE_COUNT_SQL.format(where=where), params).fetchone()[0]

    # One grouped query over every filter but the band. All four keys are always present;
    # a NULL-score head groups under NULL and is in no band.
    band_where, band_params = _filters(band, category, agent, status, actor_id, with_band=False)
    counts_by_band = dict.fromkeys(reversed(BAND_CODES), 0)
    for code, n in conn.execute(
        _QUEUE_BAND_COUNTS_SQL.format(band_case=_BAND_CASE_SQL, where=band_where),
        {**band_params, **_BAND_CASE_PARAMS},
    ).fetchall():
        if code is not None:
            counts_by_band[code] = n
    return QueuePage(
        rows=rows, total=total, page=page, page_size=page_size, counts_by_band=counts_by_band
    )


# ---------------------------------------------------------------------------
# The detail view
# ---------------------------------------------------------------------------


_VIEW_COLUMNS = (
    "alert_id",
    "rule_id",
    "rule_level",
    "description",
    "category",
    "categories",
    "severity",
    "agent_name",
    "origin_host",
    "alert_time",
    "event_time",
    "alert_user",
    "srcip",
    "dstip",
    "src_port",
    "dst_port",
    "decoder",
    "mitre_ids",
    "rule_groups",
    "raw_log",
    "raw_log_truncated",
    "source",
    "status",
    "triage_status",
    "suggestion_visible",
    "occurrence_count",
    "triaged_count",
    "first_seen_at",
    "last_seen_at",
    "acknowledged_at",
    "acknowledged_by",
    "closed_at",
    "close_reason",
    "case_id",
    "risk_score",
    "asset_context",
    "identity_context",
    "ioc_context",
    "lookup_status",
    "duplicate_of",
)
_VIEW_SQL = f"SELECT {', '.join(_VIEW_COLUMNS)} FROM alerts WHERE alert_id = %s"
_TARGETED_ACCOUNTS_SQL = """
    SELECT DISTINCT alert_user FROM alerts
    WHERE (alert_id = %s OR duplicate_of = %s) AND alert_user IS NOT NULL
    ORDER BY 1
"""
_DISPLAY_NAME_SQL = "SELECT display_name FROM users WHERE user_id = %s"


@dataclasses.dataclass(frozen=True)
class _CorrelationSubject:
    """Just enough of the head for `correlation.summarize_for_prompt`'s predicate — the
    same shape `transitions.escalate` builds for itself (duck-typed there)."""

    alert_id: str
    agent_name: str
    alert_user: str | None
    srcip: str
    alert_time: datetime


def _read_head(conn: psycopg.Connection, alert_id: str) -> dict[str, Any] | None:
    record = conn.execute(_VIEW_SQL, (alert_id,)).fetchone()
    if record is None:
        return None
    return dict(zip(_VIEW_COLUMNS, record, strict=True))


def get_alert_view(
    conn: psycopg.Connection,
    alert_id: str,
    *,
    mode: Literal["analyst", "labeling"] = "analyst",
) -> dict[str, Any] | None:
    """Everything the detail page and the labelling page render for one alert, or `None`
    when no such alert exists. A duplicate resolves to its **head's** view;
    `requested_alert_id` keeps the id that was asked for so the page can say
    *"bản sao của …"*. `correlated_now` (M) is the ±2 h cluster count at *this* moment;
    `suggestion.correlated_at_analysis` (N) is what ① saw — the page says *"gợi ý dựa
    trên N cụm liên quan tại thời điểm phân tích; hiện có M"* when they differ. The dict
    is passed through `visibility.strip(mode=mode)`; `risk_score` is dropped in both
    modes (the band replaces it). Timestamps are the database's `datetime`s — display
    formatting is the template's job."""
    view = _read_head(conn, alert_id)
    if view is None:
        return None
    if view["duplicate_of"] is not None:
        head = _read_head(conn, view["duplicate_of"])
        if head is not None:
            view = head
    view["requested_alert_id"] = alert_id
    head_id = view["alert_id"]

    view["targeted_accounts"] = [
        record[0] for record in conn.execute(_TARGETED_ACCOUNTS_SQL, (head_id, head_id)).fetchall()
    ]

    summary = correlation.summarize_for_prompt(
        conn,
        _CorrelationSubject(
            alert_id=head_id,
            agent_name=view["agent_name"],
            alert_user=view["alert_user"],
            srcip=view["srcip"],
            alert_time=view["alert_time"],
        ),
    )
    view["correlation"] = {
        "rows": [dataclasses.asdict(row) for row in summary.rows],
        "samples": [dict(sample) for sample in summary.samples],
    }
    view["correlated_now"] = sum(row.cluster_count for row in summary.rows)

    view["playbook"] = get_playbook(view["category"])

    suggestion = latest_suggestion(conn, head_id)
    view["suggestion"] = suggestion.to_dict() if suggestion is not None else None

    view["risk_band"] = risk_band(view.pop("risk_score"))

    view["acknowledged_by_name"] = None
    if view["acknowledged_by"] is not None:
        record = conn.execute(_DISPLAY_NAME_SQL, (view["acknowledged_by"],)).fetchone()
        view["acknowledged_by_name"] = record[0] if record is not None else None

    return visibility.strip(
        view, status=view["status"], suggestion_visible=view["suggestion_visible"], mode=mode
    )
