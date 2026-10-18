"""Order and page the Tier-1 queue by risk score and arrival time for the analyst to work.

Two readers and one helper, all read-only (`SELECT`s inside the caller's transaction;
nothing here writes `alerts` — G2), every column list explicit (G10):

- `list_queue` — the phase-6 queue (`docs/phase-6-tier1.md` §Hàng đợi): `needs_retriage`
  computed at query time, `risk_score DESC NULLS LAST`, `first_seen_at ASC`, `NOT
  is_synthetic`, OFFSET paging. P10-T02 adds the optional `band`/`category`/`agent`/`status`
  filters and `counts_by_band` for the React queue; with none of them it is what it was.
  R17: `needs_retriage` leads the order only for a head whose `needs_retriage` the analyst may
  see (the visible arm, or a status in `visibility.SHOW_STATES`) — a blind, undecided head
  sorts by risk and arrival alone, so its position cannot say "① ran" (DEC-101). P10-T14
  (DEC-164) adds `sort`/`direction`: `time`, `occurrences`, `agent` — a whitelist of literal
  `ORDER BY` fragments (`QUEUE_ORDER_BY`), none of which reads anything ① writes.
- `get_alert_view` — everything the detail page (P4-T05) and the labelling page (P6-T02)
  render: the head, its targeted accounts, the ±2 h correlation *now*, the playbook, the ①
  suggestion, the acknowledger's name.
- `latest_suggestion` — **the one place in P4 that reads `llm_runs`** (planning decision
  5). The row shape is P3-T10's and may still move; every read here is `.get`-tolerant,
  and this function is where to follow it. `latest_suggestions` is the same read for many
  alerts in ONE statement (P11-T20 row 20: the digest read one query per row), and shares
  the row-to-`Suggestion` step, so the two cannot drift apart.

Both readers pass their dict through `visibility.strip` before returning it, so the blind
branch (context pack §6.4) is enforced here, never in the client. `risk_score` never
leaves this module as a bare number — the four-band `risk_band` replaces it (phase-4
constraint 5).
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping, Sequence
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


def _suggestion_of(
    run_id: Any, result: Any, gate_result: Any, created_at: datetime
) -> Suggestion | None:
    """The `Suggestion` of one `llm_runs` row (the LATEST proposer run of an alert), or `None`
    when its `result` is NULL: ① failed, and an older run with a result does not stand in."""
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


def latest_suggestion(conn: psycopg.Connection, alert_id: str) -> Suggestion | None:
    """The latest `role = 'proposer'` triage run for `alert_id`, or `None` when there is
    none or its `result` is NULL (① failed — `stopped_by` set). Every key is read with
    `.get`: a key P3-T10 does not write becomes `None`, never a `KeyError`."""
    row = conn.execute(_SUGGESTION_SQL, (alert_id,)).fetchone()
    if row is None:
        return None
    return _suggestion_of(*row)


_SUGGESTIONS_SQL = """
    SELECT DISTINCT ON (subject_id) subject_id, run_id, result, gate_result, created_at
    FROM llm_runs
    WHERE subject_id = ANY(%s) AND pipeline = 'triage' AND role = 'proposer'
    ORDER BY subject_id, created_at DESC
"""


def latest_suggestions(conn: psycopg.Connection, alert_ids: Sequence[str]) -> dict[str, Suggestion]:
    """`latest_suggestion` for many alerts in ONE statement: `{alert_id: Suggestion}` for each
    of `alert_ids` that has one. An alert with no proposer run, or whose latest one has a NULL
    `result`, is absent from the answer, as `latest_suggestion` answers it `None`. The same row
    and the same conversion per id: the latest run is picked first and judged after, so a
    failed latest run is not replaced by an older good one. No statement at all for no ids.
    Like `latest_suggestion` it applies no blind-branch rule: `visibility.strip`, in the
    readers that serve an analyst, does."""
    if not alert_ids:
        return {}
    rows = conn.execute(_SUGGESTIONS_SQL, (list(alert_ids),)).fetchall()
    found = ((alert_id, _suggestion_of(*rest)) for alert_id, *rest in rows)
    return {alert_id: suggestion for alert_id, suggestion in found if suggestion is not None}


# ---------------------------------------------------------------------------
# The queue
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class QueuePage:
    """`total` is the count under every filter; `counts_by_band` is the count per band code
    under every filter **except** `band` (so the band chips still show the other bands), with
    all four keys always present. The default lets a caller that builds a page by hand
    (a test) omit it."""

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
    # P10-T15 / DEC-165: with grouping off a row is one alert, so it says whose and from where.
    # Neither is derived from ① (R12), so both stay on a blind row: `strip` is unchanged.
    "alert_user",
    "srcip",
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
_NEEDS_RETRIAGE_SQL = """(a.triaged_count > 0 AND
            (a.occurrence_count >= a.triaged_count * %(retriage_factor)s
             OR a.occurrence_count - a.triaged_count >= %(retriage_abs_delta)s))"""
# R17 / DEC-101: ① is the only first-time writer of `triaged_count`, so on a blind, undecided
# head `needs_retriage` turning on — and the row jumping to the top with it — would say "①
# just ran" (`visibility.strip` drops the two keys for the same rows). The sort key therefore
# counts `needs_retriage` only where the analyst may see it: on the visible arm, or once the head
# is in `visibility.SHOW_STATES`. That list travels as a bound parameter read from the module at
# call time (`list_queue`), never as a literal copied into the SQL, so the ordering and `strip`
# cannot disagree about what a decided head is. `COALESCE`: a NULL flag sorts as blind, as
# `strip` treats a falsy one — `NULL` would otherwise sort first under `DESC`.
_NEEDS_RETRIAGE_SORT_SQL = (
    f"({_NEEDS_RETRIAGE_SQL}\n"
    "            AND (COALESCE(a.suggestion_visible, false) OR a.status = ANY(%(show_states)s)))"
)
_QUEUE_SQL = """
    SELECT a.alert_id, a.rule_id, a.description, a.category, a.severity, a.agent_name,
           a.alert_user, a.srcip,
           a.risk_score, a.occurrence_count, a.triaged_count, a.first_seen_at, a.last_seen_at,
           a.alert_time, a.suggestion_visible, a.triage_status, a.status,
           r.run_id,
           r.result->>'suggested_action',
           r.result->>'confidence',
           r.gate_result->>'forced',
           {needs_retriage} AS needs_retriage
    FROM alerts a
    LEFT JOIN LATERAL (
        SELECT run_id, result, gate_result
        FROM llm_runs r
        WHERE r.subject_id = a.alert_id AND r.pipeline = 'triage' AND r.role = 'proposer'
        ORDER BY r.created_at DESC
        LIMIT 1
    ) r ON true
    WHERE {where}
    ORDER BY {order_by}
    LIMIT %(limit)s OFFSET %(offset)s
"""

# P10-T14 / DEC-164 — the sort. `QUEUE_ORDER_BY` is the whole whitelist: (sort, dir) -> the literal
# `ORDER BY` body, and `list_queue` formats *only* a value of this table into the SQL. A request's
# `sort`/`dir` are looked up here and never spliced, so an unknown one is a `ValueError` (a 422),
# not a query. `risk` is today's order, verbatim, and takes no direction (its key in the table is
# `("risk", None)`). The other keys end in one shared tie-break — risk DESC NULLS LAST, first_seen
# ASC, alert_id ASC — that does not turn with `dir`, so OFFSET paging walks a total order.
# R17 / DEC-101: the keys are exactly `risk|time|occurrences|agent`. Nothing ① writes or derives
# (`triaged_count`, `needs_retriage`, `triage_status`, the suggestion, its confidence, the gate) is
# a key, and `needs_retriage` is in the `risk` order only, through the visible-or-decided guard
# above — so a row's position under any other key cannot say "① ran". `agent_name` is `NOT NULL`;
# `NULLS LAST` is the contract's wording and costs nothing.
_SORT_TIE_BREAK_SQL = "a.risk_score DESC NULLS LAST, a.first_seen_at ASC, a.alert_id ASC"
QUEUE_ORDER_BY: dict[tuple[str, str | None], str] = {
    ("risk", None): (
        f"{_NEEDS_RETRIAGE_SORT_SQL} DESC, a.risk_score DESC NULLS LAST, a.first_seen_at ASC"
    ),
    ("time", "asc"): f"a.last_seen_at ASC NULLS LAST, {_SORT_TIE_BREAK_SQL}",
    ("time", "desc"): f"a.last_seen_at DESC NULLS LAST, {_SORT_TIE_BREAK_SQL}",
    ("occurrences", "asc"): f"a.occurrence_count ASC, {_SORT_TIE_BREAK_SQL}",
    ("occurrences", "desc"): f"a.occurrence_count DESC, {_SORT_TIE_BREAK_SQL}",
    ("agent", "asc"): f"a.agent_name ASC NULLS LAST, {_SORT_TIE_BREAK_SQL}",
    ("agent", "desc"): f"a.agent_name DESC NULLS LAST, {_SORT_TIE_BREAK_SQL}",
}
#: The direction a key takes when the caller gives none: newest first, most first, A→Z.
SORT_DEFAULT_DIR: dict[str, str] = {"time": "desc", "occurrences": "desc", "agent": "asc"}
_SORT_KEYS: tuple[str, ...] = tuple(dict.fromkeys(sort for sort, _direction in QUEUE_ORDER_BY))
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


def _order_by(sort: str, direction: str | None) -> str:
    """The `ORDER BY` body for a request's `sort`/`dir`: a value of `QUEUE_ORDER_BY`, never a
    string built from the arguments. `direction=None` takes the key's default; `risk` takes none
    (a `dir` with it is refused, not ignored). Anything else → `ValueError`."""
    if sort not in _SORT_KEYS:
        raise ValueError(f"sort must be one of {'|'.join(_SORT_KEYS)}, got {sort!r}")
    if sort == "risk":
        if direction is not None:
            raise ValueError(f"dir must not be given with sort=risk, got {direction!r}")
        return QUEUE_ORDER_BY[("risk", None)]
    if direction is None:
        direction = SORT_DEFAULT_DIR[sort]
    if (sort, direction) not in QUEUE_ORDER_BY:
        raise ValueError(f"dir must be one of asc|desc, got {direction!r}")
    return QUEUE_ORDER_BY[(sort, direction)]


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
    sort: str = "risk",
    direction: str | None = None,
) -> QueuePage:
    """One page of the Tier-1 queue, by default in the phase-6 order. Each row carries the queue
    columns plus `risk_band` and **minus** `risk_score`, already passed through
    `visibility.strip(mode="analyst")` — a blind, undecided head has no
    `suggested_action`/`confidence`/`gate_forced`/`triage_status`/`run_id` keys and no
    `triaged_count`/`needs_retriage` (R17) at all, under every filter, and its `needs_retriage`
    does not affect where it sorts (see `_NEEDS_RETRIAGE_SORT_SQL`).

    Filters (P10-T02), all optional and ANDed: `band` — one of `BAND_CODES`
    (`low|medium|high|critical`), the score range `risk_band` labels with the matching name;
    `category`; `agent` (`agent_name`); `status` — `"queued"` (`queued_tier1`, the default and
    what this function always returned) or `"mine"` (`tier1_active` acknowledged by
    `actor_id`). `total` counts the filtered set; `counts_by_band` counts under every filter
    except `band`.

    Sort (P10-T14, DEC-164): `sort` is `risk` (the default: the order above — `needs_retriage` for
    visible-or-decided heads, then risk, then arrival) or `time` (`last_seen_at`), `occurrences`
    (`occurrence_count`) or `agent` (`agent_name`), each in `direction` `asc`/`desc` — omitted, the
    key's own (`SORT_DEFAULT_DIR`). `risk` takes no direction. A non-risk order breaks its ties by
    risk, first seen, then `alert_id`, so paging is stable; `needs_retriage` plays no part in it.
    `total` and `counts_by_band` do not depend on the sort. The request's values only select a
    fragment of `QUEUE_ORDER_BY`; none is formatted into the SQL.

    `page < 1` or `page_size < 1`, an unknown `band`, `status`, `sort` or `direction`, a
    `direction` with `sort="risk"`, `status="mine"` without an `actor_id`, or a NUL byte in
    `category`/`agent` → `ValueError`; `page_size > PAGE_SIZE_MAX` is clamped."""
    if page < 1:
        raise ValueError(f"page must be >= 1, got {page}")
    if page_size < 1:
        raise ValueError(f"page_size must be >= 1, got {page_size}")
    page_size = min(page_size, PAGE_SIZE_MAX)
    offset = (page - 1) * page_size
    order_by = _order_by(sort, direction)

    where, params = _filters(band, category, agent, status, actor_id, with_band=True)
    cur = conn.execute(
        _QUEUE_SQL.format(where=where, needs_retriage=_NEEDS_RETRIAGE_SQL, order_by=order_by),
        {
            **params,
            "retriage_factor": RETRIAGE_FACTOR,
            "retriage_abs_delta": RETRIAGE_ABS_DELTA,
            "show_states": sorted(visibility.SHOW_STATES),
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
    formatting is the client's job."""
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
