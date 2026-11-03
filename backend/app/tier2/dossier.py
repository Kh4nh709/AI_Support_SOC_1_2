"""Assemble the case dossier: nine blocks (facts, logs, timeline, entities, playbooks), and a tenth, the
learned section, only when `learned` is given (DEC-210, below).

P5-T03 (DEC-151 wave 2). `build(conn, case_id, *, nonce, cfg=None) -> Dossier` reads the
nine blocks of context pack §7.6 / the card's design note 1 from the database only, inside
`cfg.CASE_PROMPT_BUDGET_TOKENS`, and is deterministic: two builds of the same case at the
same instant are byte-identical except the nonce (design note 3). This module sends
nothing to a model and imports nothing from `app.llm.adapter` itself — P5-T04 does that.

**Block 10, the learned section (P13-T08, DEC-210, spec §7.8).** `build(..., learned=None)` is the
nine-block dossier above, byte for byte. With `learned` (what `rag.lookup.prompt_material` returns:
`llm.builder.LearnedLike`) a tenth block follows block 8 and precedes the scope sentence, which stays
last: the heading, the decision history as a `decision_history` block, one `kb_learned_level: <level>` fact
per entry (a closed `KbLearnedLevel`, checked), the entries as one numbered `kb_learned` block (at most
`llm.builder.MAX_LEARNED_ENTRIES`, ①'s cap, through `llm.builder.prompt_entries`) and the fixed sentence that it is a reference and never a basis
for the verdict; or, when the lookup found nothing, the heading and the one sentence that says so. It is
reference material, not evidence about the case: `Dossier.learned_used` says whether it reached the prompt.
Over `CASE_PROMPT_BUDGET_TOKENS` it is the first thing dropped (`STEP_LEARNED_DROPPED`), before every
existing step.

**The block boundary is where trust ends (design note 1).** Block 1's closed-set facts
(severity, cluster/occurrence counts, the time span) are rendered through
`llm.builder.fact()` so they can stand outside a wrapper (G6'). Everything else this
module renders is free text — a case title, a raw log, a hostname, a username, an
analyst note, a previous ② result — and goes inside `security.wrap.untrusted_block` with
the session nonce, **including block 4 (entities) and block 6 (Tier-1 decisions)**, which
design note 1's summary sentence does not name among the wrapped blocks but which G6' and
this module's own linter acceptance test require regardless: entity values (IPv4/IPv6,
hashes, domains, usernames, hosts) match none of `llm.builder.ID_PATTERNS`, so they cannot
be rendered through `fact()`, and `event_type`/`actor_role` have no `FACT_NAMES` entry
either — see the task report's Deviations section. Nothing here is a proposal to change
`llm/builder.py`; that file is out of this card's scope and is not touched.

Deterministic build (design note 3): no read of the wall clock, no pseudo-random source, no
freshly generated id, no bare `set` iteration reaching the rendered text, and every query
that can return more than one row for its key carries an explicit `ORDER BY` sufficient to
make its output order repeatable — not always literally "ends in the table's primary key"
(a grouped query orders by its group key, which is what identifies *its* rows; see Review
round 1 finding 6 in the task report for where the first cut of this docstring overstated
it). The one non-deterministic input is `nonce`, a required keyword parameter — never
generated in here.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg

from app.domain.correlation import _STATUS_PREDICATE, _WINDOW_PREDICATE
from app.domain.correlation import _params as _correlation_params
from app.infra import config
from app.kb.lookup import get_playbook
from app.llm.builder import (
    HEADING_LEARNED,
    SENTENCE_ABSENT,
    SENTENCE_LEARNED_IS_REFERENCE,
    SENTENCE_NO_CORRELATION,
    SENTENCE_NO_LEARNED,
    SENTENCE_NO_PLAYBOOK,
    AlertStatus,
    AssetCriticality,
    Category,
    Id,
    IdentityPrivileged,
    IocReputation,
    KbLearnedLevel,
    LearnedLike,
    LookupStatus,
    Severity,
    fact,
    prompt_entries,
)
from app.security import wrap

# ─────────────────────────────────────────────────────── budget / truncation (design note 4)
#: "raw_log up to 8 KB" (design note 1 block 2) is the *baseline*, not itself a recorded
#: truncation; the cut from 8 KB to 4 KB is the first of the three budget-driven steps.
RAW_LOG_INITIAL_BYTES = 8_192
RAW_LOG_CUT_BYTES = 4_096
MAX_REPRESENTATIVE_CLUSTERS = 15
#: The 300-line baseline (design note 1 block 3) is a structural cap, not a budget-driven
#: cut: applied unconditionally, keeping the earliest and latest halves with a mark between
#: them (should 8) rather than only the earliest events. `STEP_TIMELINE_DROPPED` below is
#: the separate, budget-driven cascade step that removes the whole block.
TIMELINE_MAX_LINES = 300
TIMELINE_HEAD_LINES = 150
TIMELINE_TAIL_LINES = TIMELINE_MAX_LINES - TIMELINE_HEAD_LINES
MAX_ENTITIES = 50
ENTITY_HISTORY_DAYS = 7
#: Block 5's per-sample cap (design note "Block 5 samples are outside the cut cascade" —
#: Review round 1 finding 4/G): mirrors `llm.triage.SAMPLE_RAW_LOG_LIMIT_BYTES`'s role for
#: ①'s correlation section, applied unconditionally per sample, never part of the three
#: budget-driven steps below.
SAMPLE_RAW_LOG_LIMIT_BYTES = 2_048
MAX_CORRELATION_ROWS = 20
MAX_CORRELATION_SAMPLES = 5

STEP_RAW_LOG_CUT = "raw_log_8kb_to_4kb"
STEP_REPRESENTATIVES_CUT = "representatives_to_15_clusters"
STEP_TIMELINE_CAPPED = "timeline_cap_300"
STEP_TIMELINE_DROPPED = "timeline_dropped"
STEP_STILL_OVER_BUDGET = "budget_exceeded_after_cuts"
STEP_ENTITIES_CAPPED = "entities_cap_50"
#: P13-T08: block 10 dropped whole, the first of the budget-driven steps (before `STEP_RAW_LOG_CUT`).
STEP_LEARNED_DROPPED = "learned_dropped"

#: Should 8: the representatives cut's ranking, worst-first (design note 4 keeps the
#: *biggest* clusters — the same instinct DEC-034 named for `risk_score`'s own weights).
_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def _estimate_tokens(text: str) -> int:
    """`len(text) / 4`, rounded — the project's crude estimator, named here rather than
    imported: `eval/smoke_test.py` is cited by the card as its origin but carries no such
    function itself (P5-T02's report, §Token estimate, records the same finding). Real
    prompts run about 2.4-2.5 bytes per real token, not 4 (`docs/investigate-size-class.md`)
    — this estimator undershoots by roughly 1.65x and is not a tokeniser."""
    return round(len(text) / 4)


# ─────────────────────────────────────────────────────── headings, sentences (design note 1)
#: Block 9, verbatim (design note 1 item 9) — a developer-controlled literal, never built
#: from alert data, so it is safe outside a wrapper on its own merits; it has no entry in
#: `llm.builder.TEMPLATE_CONSTANTS` (that file is out of scope), so this module's own tests
#: add it to the `constants` they pass `security.linter.lint()`.
#:
#: P14-T02 (DEC-213): the second sentence used to say *"Thiếu thì trả need_more_data"* (answer
#: `need_more_data` when something is missing). ②'s model schema (`investigate_v3`) no longer has that
#: value, so it now says what to do instead: name the best conclusion and write what is missing in
#: `next_steps`. It is a member of `DOSSIER_TEMPLATE_CONSTANTS` below, so the linter and every caller
#: that passes that set follow the new wording without a second list.
SENTENCE_OUT_OF_SCOPE = (
    "Không có threat intel ngoài, dữ liệu gói tin, EDR. "
    "Thiếu thì nêu kết luận tốt nhất từ những gì có và ghi phần còn thiếu vào next_steps, "
    "không suy đoán."
)
#: Review round 2 nit 7 — block 4's "history not computed" state (md5/sha1/sha256/domain
#: entities have no structured `alerts` column to count from), a fixed literal like
#: `SENTENCE_OUT_OF_SCOPE` above, safe outside a wrapper: which of the four hash/domain
#: kinds an entity is comes from this module's own regex dispatch, never from alert text.
SENTENCE_HISTORY_NOT_COMPUTED = "history not computed for this entity type"
HEADING_CASE = "## Case"
HEADING_CLUSTERS = "## Clusters"
HEADING_TIMELINE = "## Timeline"
HEADING_ENTITIES = "## Entities"
HEADING_CORRELATION = "## Correlation"
HEADING_TIER1 = "## Tier-1 decisions"
HEADING_PLAYBOOKS = "## Playbooks"
HEADING_NOTES = "## Notes"
HEADING_PREVIOUS_RUN = "## Previous ② run"
HEADING_SCOPE = "## Scope"
#: This module's own template-constant vocabulary, the `llm.builder.TEMPLATE_CONSTANTS`
#: analogue for the headings and the block-9 sentence it adds — combined with the builder's
#: own set by any caller (a test, later P5-T04) that lints a rendered dossier.
DOSSIER_TEMPLATE_CONSTANTS = frozenset(
    {
        HEADING_CASE,
        HEADING_CLUSTERS,
        HEADING_TIMELINE,
        HEADING_ENTITIES,
        HEADING_CORRELATION,
        HEADING_TIER1,
        HEADING_PLAYBOOKS,
        HEADING_NOTES,
        HEADING_PREVIOUS_RUN,
        HEADING_SCOPE,
        HEADING_LEARNED,
        SENTENCE_OUT_OF_SCOPE,
        SENTENCE_HISTORY_NOT_COMPUTED,
    }
)

# ─────────────────────────────────────────────────────── entity regexes (design note 2)
#: Word-bounded so a 31- or 33-hex-character string never matches the 32-length family —
#: hex characters are all `\w`, so `\b` cannot land inside a contiguous run; see the module
#: docstring reference and the task report for the worked-through reasoning.
_IPV4_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4_RE = re.compile(rf"\b{_IPV4_OCTET}(?:\.{_IPV4_OCTET}){{3}}\b")
#: A candidate *finder*, deliberately over-inclusive (it also matches `17:56:55`, a
#: timestamp, and `00:1a:2b:3c:4d:5e`, a MAC address) — `_extract_ipv6` is what actually
#: decides, by handing every candidate to `ipaddress.IPv6Address` (Review round 1 blocker
#: 1): that constructor requires exactly 8 groups unless `::` compresses a run of them, so
#: a 3-group timestamp or a 6-group MAC never validates, while `fe80::1` does.
_IPV6_CANDIDATE_RE = re.compile(r"\b[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){2,7}\b")
#: One combined hex-run scan classified by exact length (32/40/64) rather than three
#: separate regexes — a 33-char run greedily matches once as a run of 33 and is simply not
#: one of the three lengths, so it is never classified as any hash family (the near-miss
#: test the card names).
_HEX_RUN_RE = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
_HASH_KIND_BY_LEN = {32: "md5", 40: "sha1", 64: "sha256"}
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b")

#: A committed snapshot of common IANA TLDs — a module-level frozenset, not a network fetch
#: and not a new data file (design note 2). Not exhaustive: it only has to be a fixed,
#: reviewable list a domain's last label is checked against.
TLD_ALLOWLIST = frozenset(
    {
        "com",
        "net",
        "org",
        "edu",
        "gov",
        "mil",
        "int",
        "info",
        "biz",
        "name",
        "pro",
        "co",
        "io",
        "ai",
        "app",
        "dev",
        "cloud",
        "xyz",
        "top",
        "site",
        "online",
        "tech",
        "me",
        "tv",
        "cc",
        "mobi",
        "asia",
        "club",
        "shop",
        "store",
        "live",
        "world",
        "group",
        "team",
        "agency",
        "solutions",
        "systems",
        "network",
        "media",
        "digital",
        "email",
        "run",
        "page",
        "link",
        "click",
        "work",
        "life",
        "today",
        "news",
        "blog",
        "vn",
        "uk",
        "de",
        "fr",
        "jp",
        "cn",
        "ru",
        "br",
        "in",
        "au",
        "ca",
        "us",
        "kr",
        "sg",
        "hk",
        "tw",
        "nl",
        "es",
        "it",
        "se",
        "no",
        "fi",
        "pl",
        "ch",
        "at",
        "be",
        "id",
        "th",
        "ph",
        "my",
        "nz",
        "za",
        "mx",
        "ar",
        "cl",
        "il",
        "tr",
        "ua",
        "eu",
    }
)

ENTITY_TYPE_ORDER: tuple[str, ...] = (
    "ipv4",
    "ipv6",
    "md5",
    "sha1",
    "sha256",
    "domain",
    "username",
    "host",
)


# ─────────────────────────────────────────────────────────────────────── public types
@dataclass(frozen=True)
class Entity:
    kind: str
    value: str
    count_7d: int
    #: `None` means "not computed" (md5/sha1/sha256/domain — no structured `alerts`
    #: column to count from, should 10); an empty mapping means "computed, found
    #: nothing in the window" — the two render differently (`_block4_entities`).
    history: Mapping[str, int] | None
    lookup: Mapping[str, Any]


@dataclass(frozen=True)
class Snapshot:
    """What P7-2 requires: `{alert_count, total_occurrences, last_seen_at}`, read in the
    same transaction as the blocks (design note 5). `alert_count` is the row count of
    heads + duplicates currently absorbed; `total_occurrences` is `sum(occurrence_count)`
    over the heads alone (a head's own column already counts its merged duplicates
    one-for-one — `web/routers/tier2.py`'s `list_cases` docstring measures the same fact)."""

    alert_count: int
    total_occurrences: int
    last_seen_at: datetime | None


@dataclass(frozen=True)
class Dossier:
    """`blocks` (P5-T04 review round 1, B2) is additive: one `(block_kind, body)` per
    `untrusted_block` in `text`, in render order, of the FINAL render only (the budget
    cascade renders several times; only the last one is `text`). `block_kind` is the
    block's `source` (`wazuh_raw_log`, `rule_description`, `context`, ...); `body` is the
    block's `Block.plain` — the free text as the model sees it (NFKC-normalised, the
    nonce stripped, truncated when bounded) but **not** HTML-escaped and **without** the
    `<untrusted_data ...>` wrapper. That is the shape `security.detector.scan` is
    documented to run over, so a consumer can scan block by block instead of scanning
    `text`, whose own wrapper tags are what `heuristic:delimiter_lookalike` flags.
    Defaults to `()` so a hand-built `Dossier` (a test double) stays valid.

    `learned_used` (P13-T08) is True when block 10 is in `text` - also in its "nothing found" form -
    and False when `build` got no `learned`, or the budget dropped it: the run whose prompt this is
    used the lookup only in the first case. Defaults to False for the same reason."""

    text: str
    nonce: str
    snapshot: Snapshot
    truncations: tuple[dict[str, Any], ...]
    estimated_tokens: int
    blocks: tuple[tuple[str, str], ...] = ()
    learned_used: bool = False


class UnknownCase(Exception):
    """`case_id` matches no row in `cases`. Maps to 404 in whatever router calls this
    (P5-T04, out of scope here)."""

    def __init__(self, case_id: str) -> None:
        super().__init__(f"case_id={case_id!r} does not exist")
        self.case_id = case_id


@dataclass(frozen=True)
class _Head:
    alert_id: str
    rule_id: str
    rule_level: int
    severity: str
    category: str
    occurrence_count: int
    alert_time: datetime
    first_seen_at: datetime
    last_seen_at: datetime
    description: str
    raw_log: str
    agent_name: str
    origin_host: str | None
    alert_user: str | None
    srcip: str
    dstip: str
    raw_payload: Mapping[str, Any]


# ───────────────────────────────────────────────────── queries (design note 3 and 6)
#: Design note 6: heads are `alert_id IN (SELECT alert_id FROM case_alerts WHERE case_id
#: = %s)`; duplicates are `duplicate_of IN` that *same* subquery — never `JOIN case_alerts
#: USING (alert_id)`, which would miss every duplicate (DEC-036).
_CASE_ALERT_IDS = "SELECT alert_id FROM case_alerts WHERE case_id = %s"
#: The same subquery, named-parameter form, for the correlation queries below, which also
#: bind `domain.correlation._WINDOW_PREDICATE`'s `%(...)s` placeholders in the same call —
#: psycopg does not accept mixed `%s`/`%(name)s` placeholders against one params mapping.
_CASE_ALERT_IDS_NAMED = "SELECT alert_id FROM case_alerts WHERE case_id = %(case_id)s"

_HEADS_SQL = f"""
    SELECT alert_id, rule_id, rule_level, severity, category, occurrence_count,
           alert_time, first_seen_at, last_seen_at, description, raw_log,
           agent_name, origin_host, alert_user, srcip, dstip, raw_payload
    FROM alerts
    WHERE alert_id IN ({_CASE_ALERT_IDS})
    ORDER BY alert_time, alert_id
"""

_DUPLICATE_SPANS_SQL = f"""
    SELECT duplicate_of, count(*), min(alert_time), max(alert_time)
    FROM alerts
    WHERE duplicate_of IN ({_CASE_ALERT_IDS})
    GROUP BY duplicate_of
    ORDER BY duplicate_of
"""

#: Should 11: a `UNION ALL` of the PK path and the `ix_alerts_duplicate_of` path, rather
#: than one `OR`ed `WHERE` — the single-column `IN` on each side lets the planner use the
#: index each predicate actually has, where the `OR` form forced a sequential scan.
_TIMELINE_BASE_SQL = f"""
    SELECT alert_time, rule_id, agent_name, alert_user, alert_id FROM alerts
     WHERE alert_id IN ({_CASE_ALERT_IDS})
    UNION ALL
    SELECT alert_time, rule_id, agent_name, alert_user, alert_id FROM alerts
     WHERE duplicate_of IN ({_CASE_ALERT_IDS})
"""
#: Fetches one more row than the structural cap so `_fetch_timeline` can tell "exactly
#: 300" from "more than 300" without a separate `count(*)` round trip. Ordered so the
#: common (uncapped) case needs nothing further — the `ORDER BY alert_time, alert_id`
#: substring is what the Coder's and the Reviewer's determinism tests monkeypatch away.
_TIMELINE_SQL = f"""
    {_TIMELINE_BASE_SQL}
    ORDER BY alert_time, alert_id
    LIMIT {TIMELINE_MAX_LINES + 1}
"""
#: Only reached when `_TIMELINE_SQL` came back with `TIMELINE_MAX_LINES + 1` rows (should
#: 8: keep head *and* tail, never only the earliest 300) — the newest events, DESC then
#: reversed in Python, so the two halves never overlap (`TIMELINE_HEAD_LINES +
#: TIMELINE_TAIL_LINES == TIMELINE_MAX_LINES`, so more than 300 rows always leaves a gap
#: between the two halves for the marker to stand in for).
_TIMELINE_TAIL_SQL = f"""
    {_TIMELINE_BASE_SQL}
    ORDER BY alert_time DESC, alert_id DESC
    LIMIT {TIMELINE_TAIL_LINES}
"""
#: Exact count for the capped case's `truncations` entry (should 7) — not needed, and not
#: run, when `_TIMELINE_SQL` alone already answered the whole case.
_TIMELINE_COUNT_SQL = f"SELECT count(*) FROM ({_TIMELINE_BASE_SQL}) t"

#: Blocker 4: this module's own correlation queries, not `domain.correlation`'s —
#: `domain.correlation.rows_query`/`samples_query` never exclude the case's own heads
#: (deviation 6 flipped: they must), are not a total order, and cap samples' `raw_log` not
#: at all. `_WINDOW_PREDICATE` (the ±2h agent/user/srcip window) is imported, not copied,
#: so this can never drift from what `escalate`'s own correlation reads.
_CORRELATION_ROWS_SQL = f"""
    SELECT rule_id, category, status,
           count(*) AS cluster_count,
           sum(occurrence_count) AS alert_count,
           min(alert_time) AS first_seen,
           max(alert_time) AS last_seen,
           count(DISTINCT srcip) AS src_ip_count
    FROM alerts
    WHERE {_WINDOW_PREDICATE}
      AND {_STATUS_PREDICATE}
      AND alert_id NOT IN ({_CASE_ALERT_IDS_NAMED})
    GROUP BY rule_id, category, status
    ORDER BY sum(occurrence_count) DESC, rule_id, category, status
    LIMIT {MAX_CORRELATION_ROWS}
"""

_CORRELATION_SAMPLES_SQL = f"""
    SELECT alert_id, rule_id, category, severity, status, occurrence_count,
           alert_time, description, raw_log
    FROM alerts
    WHERE {_WINDOW_PREDICATE}
      AND {_STATUS_PREDICATE}
      AND alert_id NOT IN ({_CASE_ALERT_IDS_NAMED})
    ORDER BY occurrence_count DESC, alert_time DESC, alert_id
    LIMIT {MAX_CORRELATION_SAMPLES}
"""

_TIER1_EVENTS_SQL = f"""
    SELECT audit_id, event_type, subject_id, actor_id, actor_role, payload, created_at
    FROM audit_events
    WHERE subject_id IN ({_CASE_ALERT_IDS})
      AND event_type IN ('alert.acknowledged', 'tier1.decided', 'tier1.escalated', 'alert.reopened')
    ORDER BY created_at, audit_id
"""

_TRIGGER_ALERT_SQL = """
    SELECT payload ->> 'trigger_alert_id'
    FROM audit_events
    WHERE subject_id = %s AND event_type = 'case.opened'
    ORDER BY created_at, audit_id
    LIMIT 1
"""

_CASE_SQL = "SELECT case_id, title, severity, created_by, created_at FROM cases WHERE case_id = %s"

_NOTES_SQL = (
    "SELECT author_id, body, created_at FROM case_notes "
    "WHERE case_id = %s ORDER BY created_at, note_id"
)

_PREVIOUS_RUN_SQL = """
    SELECT run_id, result, created_at
    FROM llm_runs
    WHERE pipeline = 'investigate' AND subject_id = %s AND result IS NOT NULL
    ORDER BY created_at DESC, run_id DESC
    LIMIT 1
"""


def _fetch_case(conn: psycopg.Connection, case_id: str) -> dict[str, Any] | None:
    row = conn.execute(_CASE_SQL, (case_id,)).fetchone()
    if row is None:
        return None
    return {"case_id": row[0], "title": row[1], "severity": row[2], "created_by": row[3]}


def _fetch_heads(conn: psycopg.Connection, case_id: str) -> list[_Head]:
    rows = conn.execute(_HEADS_SQL, (case_id,)).fetchall()
    return [_Head(*row) for row in rows]


def _fetch_duplicate_spans(
    conn: psycopg.Connection, case_id: str
) -> dict[str, tuple[int, datetime, datetime]]:
    rows = conn.execute(_DUPLICATE_SPANS_SQL, (case_id,)).fetchall()
    return {row[0]: (row[1], row[2], row[3]) for row in rows}


def _fetch_timeline(
    conn: psycopg.Connection, case_id: str
) -> tuple[list[tuple[Any, ...]], bool, int]:
    """`(rows, capped, total)`. `rows` fetched ascending, `LIMIT 301`: 300 or fewer answers
    the whole case, `capped=False`, `total == len(rows)`. More than that means the case has
    over 300 timeline events — should 8: keep the earliest `TIMELINE_HEAD_LINES` *and* the
    latest `TIMELINE_TAIL_LINES`, never only the earliest 300, so the tail is fetched with
    its own DESC query and reversed; `capped=True`, the two halves are concatenated (a gap
    always separates them — see `_TIMELINE_TAIL_SQL`'s docstring), and `total` is the exact
    count for the `truncations` entry (should 7)."""
    rows = conn.execute(_TIMELINE_SQL, (case_id, case_id)).fetchall()
    if len(rows) <= TIMELINE_MAX_LINES:
        return rows, False, len(rows)
    total = conn.execute(_TIMELINE_COUNT_SQL, (case_id, case_id)).fetchone()[0]
    tail = list(reversed(conn.execute(_TIMELINE_TAIL_SQL, (case_id, case_id)).fetchall()))
    return rows[:TIMELINE_HEAD_LINES] + tail, True, total


def _fetch_tier1_events(conn: psycopg.Connection, case_id: str) -> list[tuple[Any, ...]]:
    return conn.execute(_TIER1_EVENTS_SQL, (case_id,)).fetchall()


def _fetch_correlation(
    conn: psycopg.Connection, case_id: str, head: _Head
) -> tuple[list[tuple[Any, ...]], list[tuple[Any, ...]]]:
    """`(rows, samples)` for one head's ±2h window, this module's own queries (blocker 4):
    the case's own alerts excluded in SQL (deviation 6, flipped), a total order on each
    (tie-breakers `rule_id, category, status` / `alert_id`), samples uncapped in row count
    here — `_block5_correlation` caps and dedupes across heads at render time."""
    params = {**_correlation_params(head), "case_id": case_id}
    rows = conn.execute(_CORRELATION_ROWS_SQL, params).fetchall()
    samples = conn.execute(_CORRELATION_SAMPLES_SQL, params).fetchall()
    return rows, samples


def _fetch_trigger_alert_id(conn: psycopg.Connection, case_id: str) -> str | None:
    row = conn.execute(_TRIGGER_ALERT_SQL, (case_id,)).fetchone()
    return row[0] if row and row[0] else None


def _fetch_notes(conn: psycopg.Connection, case_id: str) -> list[tuple[Any, ...]]:
    return conn.execute(_NOTES_SQL, (case_id,)).fetchall()


def _fetch_previous_run(conn: psycopg.Connection, case_id: str) -> tuple[Any, ...] | None:
    return conn.execute(_PREVIOUS_RUN_SQL, (case_id,)).fetchone()


# ───────────────────────────────────────────────────── entity extraction (design note 2)
def _extract_ipv4(text: str) -> set[str]:
    return {m.group() for m in _IPV4_RE.finditer(text)}


def _extract_ipv6(text: str) -> set[str]:
    found: set[str] = set()
    for m in _IPV6_CANDIDATE_RE.finditer(text):
        candidate = m.group()
        try:
            ipaddress.IPv6Address(candidate)
        except ValueError:
            continue  # `17:56:55` (a timestamp), `00:1a:2b:3c:4d:5e` (a MAC) — rejected
        found.add(candidate.lower())
    return found


def _classify_ip(value: str | None) -> str | None:
    """`"ipv4"` / `"ipv6"` / `None` for a structured `srcip`/`dstip` column value — used to
    add those columns to the entity set directly (Review round 1 blocker 2), not through
    the free-text regexes above: the column is already a parsed, structured address, never
    itself a hostname or free text."""
    if not value:
        return None
    try:
        return "ipv6" if ipaddress.ip_address(value).version == 6 else "ipv4"
    except ValueError:
        return None


def _is_private_ip(value: str) -> bool:
    """The same test `ingest/wazuh_parser.py`'s `_is_private` runs to fill
    `alerts.srcip_is_private`/`dstip_is_private` (phase-1 Khối 7, chốt C4) — mirrored,
    not imported: `tier2` may not import `ingest` (context pack §4). `is_private` alone
    already covers the RFC 5737 documentation ranges (`203.0.113.0/24` and its
    neighbours) on this Python; the other three are named explicitly anyway, so this
    reads correctly on an older stdlib too."""
    try:
        addr = ipaddress.ip_address(value)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return False


def _extract_hashes(text: str) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {"md5": set(), "sha1": set(), "sha256": set()}
    for m in _HEX_RUN_RE.finditer(text):
        kind = _HASH_KIND_BY_LEN.get(len(m.group()))
        if kind is not None:
            found[kind].add(m.group().lower())
    return found


def _extract_domains(text: str) -> set[str]:
    found: set[str] = set()
    for m in _DOMAIN_RE.finditer(text):
        candidate = m.group()
        tld = candidate.rsplit(".", 1)[-1].lower()
        if tld in TLD_ALLOWLIST:
            found.add(candidate.lower())
    return found


def _raw_payload_str(raw_payload: Mapping[str, Any], *path: str) -> str | None:
    node: Any = raw_payload
    for key in path:
        if not isinstance(node, Mapping):
            return None
        node = node.get(key)
    return node if isinstance(node, str) and node else None


def _extract_raw_values(heads: Sequence[_Head]) -> dict[str, set[str]]:
    """Every raw entity string, by type — regex families from `raw_log` + `description`
    (design note 2's *"From the case's raw_logs and descriptions"*); hosts from the
    already-parsed `agent_name`/`origin_host` columns (what `agent.name`/
    `predecoder.hostname` resolve to at ingest — `ingest/wazuh_parser.py` — so no jsonb
    path walk is needed for hosts).

    **Usernames and IPs — Review round 1 blocker 2.** A Windows alert's targeted user
    (`eventdata.targetUserName`) and source address (`eventdata.ipAddress`) never appear
    under `raw_payload["data"]["dstuser"/"srcuser"]` — only a Linux/syslog alert's do
    (DEC-149/152 win over this card's original wording, DEC-151 item 3). `alerts.alert_user`
    is the column every ingest path already resolves onto (`dstuser` preferred, `srcuser`
    fallback, then the Windows `eventdata` chain — `ingest/wazuh_parser.py`), so it is the
    primary username source here; `data.srcuser` is read *in addition*, as a Linux-only
    supplement, for the lateral-movement case where it differs from the resolved user.
    Likewise `srcip`/`dstip` — already-parsed, structured addresses, not free text — are
    entities in their own right alongside whatever the regexes find in `raw_log`/
    `description`."""
    values: dict[str, set[str]] = {t: set() for t in ENTITY_TYPE_ORDER}
    for head in heads:
        text = f"{head.raw_log}\n{head.description}"
        values["ipv4"] |= _extract_ipv4(text)
        values["ipv6"] |= _extract_ipv6(text)
        hashes = _extract_hashes(text)
        values["md5"] |= hashes["md5"]
        values["sha1"] |= hashes["sha1"]
        values["sha256"] |= hashes["sha256"]
        values["domain"] |= _extract_domains(text)
        for column in (head.srcip, head.dstip):
            kind = _classify_ip(column)
            if kind is not None:
                values[kind].add(column)
        if head.alert_user:
            values["username"].add(head.alert_user)
        linux_srcuser = _raw_payload_str(head.raw_payload, "data", "srcuser")
        if linux_srcuser:
            values["username"].add(linux_srcuser)
        if head.agent_name:
            values["host"].add(head.agent_name)
        if head.origin_host and head.origin_host != head.agent_name:
            values["host"].add(head.origin_host)
    return values


def _bulk_asset_lookup(conn: psycopg.Connection, hosts: list[str]) -> dict[str, dict[str, Any]]:
    if not hosts:
        return {}
    rows = conn.execute(
        "SELECT hostname, criticality, owner, role FROM assets "
        "WHERE hostname = ANY(%s) AND active ORDER BY hostname",
        (hosts,),
    ).fetchall()
    return {
        r[0]: {"status": "found", "criticality": r[1], "owner": r[2], "role": r[3]} for r in rows
    }


def _bulk_identity_lookup(conn: psycopg.Connection, users: list[str]) -> dict[str, dict[str, Any]]:
    if not users:
        return {}
    rows = conn.execute(
        "SELECT username, is_privileged FROM identities "
        "WHERE username = ANY(%s) AND active ORDER BY username",
        (users,),
    ).fetchall()
    return {r[0]: {"status": "found", "is_privileged": r[1]} for r in rows}


def _bulk_ioc_lookup(conn: psycopg.Connection, values: list[str]) -> dict[str, dict[str, Any]]:
    """Blocker 3: `iocs`' PK is `(value, source)`, so more than one row can share a
    `value`. Mirrors `enrichment.lookups.lookup_ioc`'s worst-wins rule
    (`malicious > suspicious > clean`) and adds the total order that function's own bare
    `max()` over an unordered query never had: ties broken by `source`, so which row
    "wins" never depends on `iocs`' physical row order. The private-IP "skip, don't even
    look up" rule lives in the caller (`_build_entities`), which is where an entity first
    knows whether its own value is a private address."""
    if not values:
        return {}
    rows = conn.execute(
        "SELECT value, source, reputation FROM iocs "
        "WHERE value = ANY(%s) AND active AND expires_at > now() "
        "ORDER BY value, "
        "CASE reputation WHEN 'malicious' THEN 3 WHEN 'suspicious' THEN 2 "
        "WHEN 'clean' THEN 1 ELSE 0 END DESC, source",
        (values,),
    ).fetchall()
    out: dict[str, dict[str, Any]] = {}
    for value, _source, reputation in rows:
        if value not in out:  # first row per value, by the ORDER BY above, is worst-wins
            out[value] = {"status": "found", "reputation": reputation}
    return out


def _bulk_host_history(
    conn: psycopg.Connection, hosts: list[str], window: tuple[datetime, datetime]
) -> dict[str, dict[str, int]]:
    if not hosts:
        return {}
    rows = conn.execute(
        "SELECT agent_name, category, count(*) FROM alerts "
        "WHERE agent_name = ANY(%s) AND alert_time >= %s AND alert_time < %s "
        "GROUP BY agent_name, category ORDER BY agent_name, category",
        (hosts, *window),
    ).fetchall()
    out: dict[str, dict[str, int]] = {}
    for host, cat, n in rows:
        out.setdefault(host, {})[cat] = n
    return out


def _bulk_username_history(
    conn: psycopg.Connection, users: list[str], window: tuple[datetime, datetime]
) -> dict[str, dict[str, int]]:
    if not users:
        return {}
    rows = conn.execute(
        "SELECT alert_user, category, count(*) FROM alerts "
        "WHERE alert_user = ANY(%s) AND alert_time >= %s AND alert_time < %s "
        "GROUP BY alert_user, category ORDER BY alert_user, category",
        (users, *window),
    ).fetchall()
    out: dict[str, dict[str, int]] = {}
    for user, cat, n in rows:
        out.setdefault(user, {})[cat] = n
    return out


def _bulk_ip_history(
    conn: psycopg.Connection, ips: list[str], window: tuple[datetime, datetime]
) -> dict[str, dict[str, int]]:
    """One SQL for both IPv4 and IPv6 entities: an IP can appear as `srcip` or `dstip`."""
    if not ips:
        return {}
    rows = conn.execute(
        """
        SELECT ip, category, count(*) FROM (
            SELECT srcip AS ip, category FROM alerts
             WHERE srcip = ANY(%s) AND alert_time >= %s AND alert_time < %s
            UNION ALL
            SELECT dstip AS ip, category FROM alerts
             WHERE dstip = ANY(%s) AND alert_time >= %s AND alert_time < %s
        ) x
        GROUP BY ip, category
        ORDER BY ip, category
        """,
        (ips, *window, ips, *window),
    ).fetchall()
    out: dict[str, dict[str, int]] = {}
    for ip, cat, n in rows:
        out.setdefault(ip, {}).setdefault(cat, 0)
        out[ip][cat] += n
    return out


def _history_window(heads: Sequence[_Head]) -> tuple[datetime, datetime] | None:
    """Should 10 (ruling): anchored *before* the case, at `[earliest head alert_time -
    7 days, earliest head alert_time)` — independent of `now()` (so two builds of the same
    case are identical regardless of when either runs) and excluding the case's own
    alerts by construction (the window ends strictly before the case started, so nothing
    the case itself created can fall inside it): "was this entity seen before the
    incident". `None` when there are no heads to anchor on."""
    if not heads:
        return None
    anchor = min(h.alert_time for h in heads)
    return anchor - timedelta(days=ENTITY_HISTORY_DAYS), anchor


def _build_entities(conn: psycopg.Connection, heads: Sequence[_Head]) -> tuple[Entity, ...]:
    """Cap 50, ordered deterministically by (type, -count_7d, value) — a value can appear
    only once per type, so this key is always a strict total order regardless of which
    order the extraction or the bulk queries happen to visit rows in (design note 2, 3)."""
    raw = _extract_raw_values(heads)
    window = _history_window(heads)
    ip_values = sorted(raw["ipv4"] | raw["ipv6"])
    public_ip_values = [v for v in ip_values if not _is_private_ip(v)]
    host_lookup = _bulk_asset_lookup(conn, sorted(raw["host"]))
    user_lookup = _bulk_identity_lookup(conn, sorted(raw["username"]))
    ioc_values = sorted(
        set(public_ip_values) | raw["md5"] | raw["sha1"] | raw["sha256"] | raw["domain"]
    )
    ioc_lookup = _bulk_ioc_lookup(conn, ioc_values)
    if window is None:
        host_history: dict[str, dict[str, int]] = {}
        user_history: dict[str, dict[str, int]] = {}
        ip_history: dict[str, dict[str, int]] = {}
    else:
        host_history = _bulk_host_history(conn, sorted(raw["host"]), window)
        user_history = _bulk_username_history(conn, sorted(raw["username"]), window)
        ip_history = _bulk_ip_history(conn, ip_values, window)

    entities: list[Entity] = []
    for kind in ENTITY_TYPE_ORDER:
        # md5/sha1/sha256/domain have no structured `alerts` column to count history from
        # (Review round 1 deviation 4, kept): "not computed", never "none" (should 10) —
        # `history=None` in the `else` branch below is that state; the other four kinds
        # always set a dict (possibly empty, meaning "computed, found nothing").
        for value in sorted(raw[kind]):
            if kind == "host":
                lookup = host_lookup.get(value, {"status": "not_found"})
                history: dict[str, int] | None = host_history.get(value, {})
            elif kind == "username":
                lookup = user_lookup.get(value, {"status": "not_found"})
                history = user_history.get(value, {})
            elif kind in ("ipv4", "ipv6"):
                if _is_private_ip(value):  # C4 in enrichment/lookups.py: never looked up
                    lookup = {"status": "skipped", "reputation": "skipped"}
                else:
                    lookup = ioc_lookup.get(value, {"status": "not_found"})
                history = ip_history.get(value, {})
            else:
                lookup = ioc_lookup.get(value, {"status": "not_found"})
                history = None
            entities.append(
                Entity(
                    kind=kind,
                    value=value,
                    count_7d=sum(history.values()) if history else 0,
                    history=history,
                    lookup=lookup,
                )
            )

    entities.sort(key=lambda e: (ENTITY_TYPE_ORDER.index(e.kind), -e.count_7d, e.value))
    return tuple(entities)


# ─────────────────────────────────────────────────────────────── rendering (design note 1)
def _utc(value: datetime) -> datetime:
    """Nit 15: render every datetime on a fixed offset, never the session's `TimeZone`
    GUC — two builds under different ambient timezones must produce the same text."""
    return value.astimezone(UTC)


def _iso(value: datetime) -> str:
    return _utc(value).isoformat(timespec="seconds")


#: What `Dossier.blocks` is built from: every block function appends `(source, plain)` here
#: as it wraps, and `build()`'s inner `render()` starts a fresh list per render.
_BlockSink = list[tuple[str, str]]


def _wrapped(
    sink: _BlockSink | None,
    text: str,
    source: str,
    nonce: str,
    *,
    limit_bytes: int | None = None,
) -> str:
    """`wrap.untrusted_block(...).rendered`, recording `(source, block.plain)` in `sink`
    on the way (P5-T04 review round 1, B2). The one place a block is wrapped in this
    module, so `Dossier.blocks` cannot drift from what `Dossier.text` contains."""
    block = wrap.untrusted_block(text, source, nonce=nonce, limit_bytes=limit_bytes)
    if sink is not None:
        sink.append((source, block.plain))
    return block.rendered


def _id_fact(name: str, kind: str, value: str, nonce: str, sink: _BlockSink | None = None) -> str:
    """`fact(name, Id(kind, value))` — or, for a value that fails the id pattern (which
    must never happen for a real ingested `alert_id`/`rule_id` but must never crash the
    build either, nit 15), the raw value inside its own small wrapped block instead of a
    raised `ValueError`."""
    try:
        return fact(name, Id(kind, value))
    except ValueError:
        return _wrapped(sink, f"{name}: {value}", "context", nonce)


def _block1_case(
    case_row: Mapping[str, Any],
    heads: Sequence[_Head],
    dup_spans: Mapping[str, tuple[int, datetime, datetime]],
    trigger_alert_id: str | None,
    nonce: str,
    *,
    representatives_shown: int | None,
    sink: _BlockSink | None = None,
) -> str:
    total_dup = sum(span[0] for span in dup_spans.values())
    total_occurrences = sum(h.occurrence_count for h in heads)
    parts = [HEADING_CASE]
    parts.append(fact("severity", Severity(case_row["severity"])))
    parts.append(fact("clusters", len(heads)))
    parts.append(fact("occurrence_count", int(total_occurrences)))
    parts.append(fact("alerts", int(len(heads) + total_dup)))
    if heads:
        parts.append(fact("first_seen", _utc(min(h.first_seen_at for h in heads))))
        parts.append(fact("last_seen", _utc(max(h.last_seen_at for h in heads))))
    if trigger_alert_id:
        parts.append(_id_fact("alert_id", "alert_id", trigger_alert_id, nonce, sink))
    context_lines = [f"title: {case_row['title']}"]
    if case_row.get("created_by"):
        context_lines.append(f"escalated_by: {case_row['created_by']}")
    # Should 7: block 1's `clusters: N` next to how many block 2 actually lists, inside
    # the block that carries the mark — a bare "clusters: 20" beside 15 listed clusters
    # says nothing on its own about the cut.
    if representatives_shown is not None and representatives_shown < len(heads):
        context_lines.append(
            f"representatives_shown: {representatives_shown} of {len(heads)} "
            f"{wrap.TRUNCATION_MARKER}"
        )
    parts.append(_wrapped(sink, "\n".join(context_lines), "context", nonce))
    return "\n".join(parts)


def _block2_clusters(
    heads: Sequence[_Head],
    dup_spans: Mapping[str, tuple[int, datetime, datetime]],
    nonce: str,
    *,
    raw_log_limit: int,
    sink: _BlockSink | None = None,
) -> str:
    parts = [HEADING_CLUSTERS]
    for head in heads:
        line = [
            _id_fact("alert_id", "alert_id", head.alert_id, nonce, sink),
            _id_fact("rule_id", "rule_id", head.rule_id, nonce, sink),
            fact("severity", Severity(head.severity)),
            fact("category", Category(head.category)),
            fact("occurrence_count", int(head.occurrence_count)),
        ]
        span = dup_spans.get(head.alert_id)
        if span is not None:
            _dup_count, dup_first, dup_last = span
            line.append(fact("first_seen", _utc(dup_first)))
            line.append(fact("last_seen", _utc(dup_last)))
        parts.append(" · ".join(line))
        parts.append(
            _wrapped(sink, head.raw_log, "wazuh_raw_log", nonce, limit_bytes=raw_log_limit)
        )
        # Blocker 5: 249 of 842 real heads carry an empty `raw_log`, and P5-T04's evidence
        # check accepts a quote from `raw_log` *or* `description` — the description was
        # never rendered anywhere before this. Wrapped separately (its own source, so a
        # linter/evidence reader can tell which field a quote came from), with the head's
        # agent/user/IPs alongside it — free text and structured-but-untrusted addresses
        # both, so they go in the same small block rather than bare beside a `fact()`.
        if head.description:
            # Review round 2 nit 9: capped at the tighter of the two raw_log limits,
            # always — unlike `raw_log_limit` above, this never starts at 8 KB, since
            # the description is meant to be a short rule label, not a second log body.
            parts.append(
                _wrapped(
                    sink,
                    head.description,
                    "rule_description",
                    nonce,
                    limit_bytes=RAW_LOG_CUT_BYTES,
                )
            )
        context_lines = [f"agent_name: {head.agent_name}"]
        if head.origin_host and head.origin_host != head.agent_name:
            context_lines.append(f"origin_host: {head.origin_host}")
        if head.alert_user:
            context_lines.append(f"alert_user: {head.alert_user}")
        if head.srcip:
            context_lines.append(f"srcip: {head.srcip}")
        if head.dstip:
            context_lines.append(f"dstip: {head.dstip}")
        parts.append(_wrapped(sink, "\n".join(context_lines), "context", nonce))
    return "\n".join(parts)


def _block3_timeline(
    rows: Sequence[tuple[Any, ...]],
    nonce: str,
    *,
    capped: bool,
    dropped: bool,
    sink: _BlockSink | None = None,
) -> str:
    if dropped:
        # Should 7: the drop must not leave an empty wrapped block — the mark itself is
        # the content.
        body = wrap.TRUNCATION_MARKER
    else:
        lines = [
            f"{_iso(alert_time)} · {rule_id} · {agent_name} · {alert_user or ''}"
            for alert_time, rule_id, agent_name, alert_user, _alert_id in rows
        ]
        if capped:
            lines.insert(TIMELINE_HEAD_LINES, wrap.TRUNCATION_MARKER)
        body = "\n".join(lines) if lines else wrap.TRUNCATION_MARKER
    wrapped = _wrapped(sink, body, "context", nonce)
    return f"{HEADING_TIMELINE}\n{wrapped}"


def _entity_lookup_facts(entity: Entity, nonce: str) -> str:
    """Should 9: the lookup *result* — found/not_found/skipped and, when found, the
    criticality/privilege/reputation — is trusted, closed-set data (it came from our own
    `assets`/`identities`/`iocs`, never from the alert), so it is rendered through
    `fact()` outside any wrap; only the entity *value* itself (§_block4_entities) sits in
    a small wrapped block. Before this, both sat inside the same wrap, where a forged
    username in `raw_log` could fake a "found, privileged" sibling line no reader could
    tell from a real one.

    Review round 2 should 4: `SENTENCE_ABSENT` follows only `not_found` — a `skipped`
    lookup (a private IP, never queried at all) is not "absent from the internal
    database", and saying so would be false. ① makes exactly this distinction
    (`llm/triage.py` renders `SENTENCE_ABSENT` only for `LookupStatus.NOT_FOUND`)."""
    status = entity.lookup.get("status") or "not_found"
    if entity.kind == "host":
        parts = [fact("lookup_asset", LookupStatus(status))]
        if status == "found":
            criticality = entity.lookup.get("criticality") or "unknown"
            parts.append(fact("asset_criticality", AssetCriticality(criticality)))
        elif status == "not_found":
            parts.append(SENTENCE_ABSENT)
    elif entity.kind == "username":
        parts = [fact("lookup_identity", LookupStatus(status))]
        if status == "found":
            privileged = entity.lookup.get("is_privileged")
            priv_value = "true" if privileged else ("false" if privileged is False else "unknown")
            parts.append(fact("identity_privileged", IdentityPrivileged(priv_value)))
        elif status == "not_found":
            parts.append(SENTENCE_ABSENT)
    else:
        parts = [fact("lookup_ioc", LookupStatus(status))]
        if status == "found":
            reputation = entity.lookup.get("reputation") or "not_found"
            parts.append(fact("ioc_reputation", IocReputation(reputation)))
        elif status == "not_found":
            parts.append(SENTENCE_ABSENT)
    return " · ".join(parts)


def _entity_history_facts(entity: Entity) -> list[str]:
    """Review round 2 nit 7 (ruling): the 7-day history — each category a `Category`
    enum value, each count a plain int, both computed by this module from our own
    `alerts` table and never attacker-controlled — moves to trusted `fact()` lines
    outside the wrap, reusing the existing `category`/`alerts` pair (the same two
    `FACT_NAMES` `_block5_correlation`'s rows already use for the same shape: a
    category and a count). No name was added to `FACT_NAMES` — `category` and `alerts`
    already fit.

    Before this, the whole "7d: …" line sat inside the entity value's own wrap, where a
    multi-line value (e.g. a forged username ending in a fake "\\n7d: none") could plant
    a sibling history line no reader could tell from the real one. `None` (not computed
    — md5/sha1/sha256/domain, should 10) renders `SENTENCE_HISTORY_NOT_COMPUTED`, also
    outside the wrap; an empty mapping (computed, nothing found) renders nothing further
    — the absence of both is itself the signal, and it is not attacker-influenced
    either way."""
    if entity.history is None:
        return [SENTENCE_HISTORY_NOT_COMPUTED]
    return [
        " · ".join((fact("category", Category(cat)), fact("alerts", int(n))))
        for cat, n in sorted(entity.history.items())
    ]


def _block4_entities(entities: Sequence[Entity], nonce: str, sink: _BlockSink | None = None) -> str:
    parts = [HEADING_ENTITIES]
    for e in entities:
        value_body = f"{e.kind}: {e.value}"
        parts.append(_wrapped(sink, value_body, "context", nonce))
        parts.append(_entity_lookup_facts(e, nonce))
        parts.extend(_entity_history_facts(e))
    return "\n".join(parts)


def _render_correlation_sample(sample: tuple[Any, ...], nonce: str) -> str:
    (
        alert_id,
        rule_id,
        category,
        _severity,
        _status,
        occurrence_count,
        alert_time,
        description,
        raw_log,
    ) = sample
    raw_log, _truncated = wrap.truncate_block(raw_log or "", SAMPLE_RAW_LOG_LIMIT_BYTES)
    header = (
        f"alert_id={alert_id} rule_id={rule_id} category={category} "
        f"occurrence={occurrence_count} alert_time={_iso(alert_time)}"
    )
    return "\n".join((header, description or "", raw_log))


def _block5_correlation(
    heads: Sequence[_Head],
    correlation_by_head: Mapping[str, tuple[list[tuple[Any, ...]], list[tuple[Any, ...]]]],
    nonce: str,
    sink: _BlockSink | None = None,
) -> str:
    parts = [HEADING_CORRELATION]
    shown_samples: set[str] = set()
    for head in heads:
        parts.append(_id_fact("alert_id", "alert_id", head.alert_id, nonce, sink))
        rows, samples = correlation_by_head.get(head.alert_id, ([], []))
        if not rows:
            parts.append(SENTENCE_NO_CORRELATION)
            continue
        for (
            rule_id,
            category,
            status,
            cluster_count,
            alert_count,
            first_seen,
            last_seen,
            src_ip_count,
        ) in rows:
            parts.append(
                " · ".join(
                    (
                        _id_fact("rule_id", "rule_id", rule_id, nonce, sink),
                        fact("category", Category(category)),
                        fact("status", AlertStatus(status)),
                        fact("clusters", int(cluster_count)),
                        fact("alerts", int(alert_count)),
                        fact("src_ips", int(src_ip_count)),
                        fact("first_seen", _utc(first_seen)),
                        fact("last_seen", _utc(last_seen)),
                    )
                )
            )
        # Deduplicate across heads: the same external alert can fall in more than one
        # head's ±2h window, and design note 1 asks for it as evidence once, not once per
        # head it happens to correlate with.
        new_samples = [s for s in samples if s[0] not in shown_samples]
        for s in new_samples:
            shown_samples.add(s[0])
        if new_samples:
            body = "\n\n".join(_render_correlation_sample(s, nonce) for s in new_samples)
            parts.append(_wrapped(sink, body, "correlation_samples", nonce))
    return "\n".join(parts)


def _block6_tier1(
    rows: Sequence[tuple[Any, ...]], nonce: str, sink: _BlockSink | None = None
) -> str:
    # Nit 13: only event_type/subject_id/actor_role/created_at are ever read here — a
    # `tier1.decided` payload's `llm_suggestion`/`llm_confidence` (or any other payload
    # key) never reaches the dossier; there is no path in this function that touches
    # `payload` at all.
    lines = []
    for _audit_id, event_type, subject_id, _actor_id, actor_role, _payload, created_at in rows:
        lines.append(f"{_iso(created_at)} · {event_type} · {subject_id} · {actor_role}")
    body = "\n".join(lines)
    wrapped = _wrapped(sink, body, "context", nonce)
    return f"{HEADING_TIER1}\n{wrapped}"


def _block7_playbooks(categories: Sequence[str], nonce: str, sink: _BlockSink | None = None) -> str:
    parts = [HEADING_PLAYBOOKS]
    for cat in categories:
        parts.append(fact("category", Category(cat)))
        text = get_playbook(cat)
        if text:
            parts.append(_wrapped(sink, text, "kb_playbook", nonce))
        else:
            parts.append(SENTENCE_NO_PLAYBOOK)
    return "\n".join(parts)


def _block8_notes_and_previous(
    notes: Sequence[tuple[Any, ...]],
    previous_run: tuple[Any, ...] | None,
    nonce: str,
    sink: _BlockSink | None = None,
) -> str:
    parts = [HEADING_NOTES]
    if notes:
        body = "\n\n".join(
            f"{_iso(created_at)} ({author_id}):\n{body_text}"
            for author_id, body_text, created_at in notes
        )
        parts.append(_wrapped(sink, body, "context", nonce))
    parts.append(HEADING_PREVIOUS_RUN)
    if previous_run is not None:
        _run_id, result, created_at = previous_run
        body = f"{_iso(created_at)}\n{json.dumps(result, ensure_ascii=False, sort_keys=True)}"
        # Injection accumulating across rounds (docs/phase-7-tier2.md:250): a previous ②
        # result that was itself injected must not re-enter the next prompt unwrapped.
        parts.append(_wrapped(sink, body, "proposer", nonce))
    return "\n".join(parts)


def _block9_scope() -> str:
    return f"{HEADING_SCOPE}\n{SENTENCE_OUT_OF_SCOPE}"


def _block10_learned(
    history_text: str | None,
    entries: Sequence[tuple[KbLearnedLevel, str]],
    *,
    nothing_found: bool,
    nonce: str,
    sink: _BlockSink | None = None,
) -> str:
    """Block 10 (P13-T08, spec §7.8), ①'s section (`llm.triage._learned_section`) in this module's
    layout. The heading; the history under its own source (its values, such as a SOAR scenario, are not
    id-shaped, so it is a block, not facts); each entry's level as a typed fact, in the entries' order;
    the entries' approved text as the one `kb_learned` block, numbered `[1]`.. in the same order so a level
    and its entry can be matched; then the sentence that says what the section is. When the lookup found
    nothing: the heading and the one sentence that says so. The text is approved content and a history
    the system wrote, and still goes in blocks: the linter accepts no prose outside one."""
    parts = [HEADING_LEARNED]
    if nothing_found:
        parts.append(SENTENCE_NO_LEARNED)
        return "\n".join(parts)
    if history_text:
        parts.append(_wrapped(sink, history_text, "decision_history", nonce))
    parts.extend(fact("kb_learned_level", level) for level, _text in entries)
    if entries:
        body = "\n\n".join(f"[{number}] {text}" for number, (_level, text) in enumerate(entries, 1))
        parts.append(_wrapped(sink, body, "kb_learned", nonce))
    parts.append(SENTENCE_LEARNED_IS_REFERENCE)
    return "\n".join(parts)


def _select_representatives(
    heads: Sequence[_Head], trigger_alert_id: str | None, limit: int
) -> frozenset[str]:
    """Should 8: which heads survive the representatives cut. The escalation trigger
    (`case.opened`'s `trigger_alert_id`, when it is one of this case's own heads) is
    always kept; the rest are ranked worst-first — severity, then `rule_level`, then
    `occurrence_count`, each descending — ties broken by `alert_id` for a total order, so
    the cap cuts the same heads every time (design note 2's rule for the entity cap,
    applied here too)."""
    if len(heads) <= limit:
        return frozenset(h.alert_id for h in heads)
    head_ids = {h.alert_id for h in heads}
    trigger = trigger_alert_id if trigger_alert_id in head_ids else None
    rest = [h for h in heads if h.alert_id != trigger]
    ranked = sorted(
        rest,
        key=lambda h: (
            -_SEVERITY_RANK.get(h.severity, -1),
            -h.rule_level,
            -h.occurrence_count,
            h.alert_id,
        ),
    )
    keep_count = limit - (1 if trigger else 0)
    kept = {h.alert_id for h in ranked[:keep_count]}
    if trigger:
        kept.add(trigger)
    return frozenset(kept)


# ─────────────────────────────────────────────────────────────────────── build()
def build(
    conn: psycopg.Connection,
    case_id: str,
    *,
    nonce: str,
    cfg: config.Config | None = None,
    learned: LearnedLike | None = None,
) -> Dossier:
    """The dossier of `case_id`: nine blocks. `learned` (P13-T08): None - those nine blocks, byte for byte
    what this function returned before the parameter existed. Else ten: block 10, the learned section (see
    the module docstring), follows block 8 and the scope sentence stays last."""
    cfg = cfg or config.load()

    case_row = _fetch_case(conn, case_id)
    if case_row is None:
        raise UnknownCase(case_id)

    heads = _fetch_heads(conn, case_id)
    dup_spans = _fetch_duplicate_spans(conn, case_id)
    timeline_rows, timeline_capped, timeline_total = _fetch_timeline(conn, case_id)
    tier1_rows = _fetch_tier1_events(conn, case_id)
    trigger_alert_id = _fetch_trigger_alert_id(conn, case_id)
    notes = _fetch_notes(conn, case_id)
    previous_run = _fetch_previous_run(conn, case_id)
    categories = sorted({h.category for h in heads})

    truncations: list[dict[str, Any]] = []
    if timeline_capped:
        # Should 7/8: the 300-line structural cap is unconditional, like the entity cap
        # below — recorded regardless of whether the token budget is ever exceeded, and
        # distinct from `STEP_TIMELINE_DROPPED`, the budget-driven cascade step that can
        # remove the block entirely.
        truncations.append(
            {"step": STEP_TIMELINE_CAPPED, "before": timeline_total, "after": TIMELINE_MAX_LINES}
        )

    entities_all = _build_entities(conn, heads)
    if len(entities_all) > MAX_ENTITIES:
        truncations.append(
            {"step": STEP_ENTITIES_CAPPED, "before": len(entities_all), "after": MAX_ENTITIES}
        )
    entities = entities_all[:MAX_ENTITIES]

    correlation_by_head = {h.alert_id: _fetch_correlation(conn, case_id, h) for h in heads}

    total_dup = sum(span[0] for span in dup_spans.values())
    snapshot = Snapshot(
        alert_count=len(heads) + total_dup,
        total_occurrences=sum(h.occurrence_count for h in heads),
        last_seen_at=max((h.last_seen_at for h in heads), default=None),
    )

    raw_log_limit = RAW_LOG_INITIAL_BYTES
    kept_ids: frozenset[str] | None = None
    timeline_dropped = False

    # Block 10's material, checked once, before any render or cut (P13-T08).
    history_text = (learned.history_text or None) if learned is not None else None
    learned_entries = prompt_entries(learned)
    nothing_found = learned is not None and history_text is None and not learned_entries
    learned_dropped = False

    # `Dossier.blocks`: filled by the block functions as they wrap, and emptied at the start
    # of every render — the budget cascade below renders up to four times, and only the
    # last render is `text`.
    blocks: _BlockSink = []

    def render() -> str:
        blocks.clear()
        display_heads = heads if kept_ids is None else [h for h in heads if h.alert_id in kept_ids]
        shown = len(display_heads) if kept_ids is not None else None
        sections = [
            _block1_case(
                case_row,
                heads,
                dup_spans,
                trigger_alert_id,
                nonce,
                representatives_shown=shown,
                sink=blocks,
            ),
            _block2_clusters(
                display_heads, dup_spans, nonce, raw_log_limit=raw_log_limit, sink=blocks
            ),
            _block3_timeline(
                timeline_rows,
                nonce,
                capped=timeline_capped,
                dropped=timeline_dropped,
                sink=blocks,
            ),
            _block4_entities(entities, nonce, blocks),
            _block5_correlation(display_heads, correlation_by_head, nonce, blocks),
            _block6_tier1(tier1_rows, nonce, blocks),
            _block7_playbooks(categories, nonce, blocks),
            _block8_notes_and_previous(notes, previous_run, nonce, blocks),
        ]
        if learned is not None and not learned_dropped:
            sections.append(
                _block10_learned(
                    history_text,
                    learned_entries,
                    nothing_found=nothing_found,
                    nonce=nonce,
                    sink=blocks,
                )
            )
        sections.append(_block9_scope())  # the instruction stays last
        return "\n\n".join(sections)

    text = render()
    estimated = _estimate_tokens(text)
    budget = cfg.CASE_PROMPT_BUDGET_TOKENS

    if estimated > budget and learned is not None and not nothing_found:
        # P13-T08, Review Focus 5: the learned section is a reference, never evidence, so it is the first
        # thing to go - before any step that cuts what the case itself is made of. It goes whole. The
        # two-line "nothing found" form is not cut: it costs a few tokens, says something true, and
        # dropping it would be recorded as a saving it is not.
        before = estimated
        learned_dropped = True
        text = render()
        estimated = _estimate_tokens(text)
        truncations.append({"step": STEP_LEARNED_DROPPED, "before": before, "after": estimated})

    if estimated > budget and raw_log_limit > RAW_LOG_CUT_BYTES:
        before = estimated
        # Nit 14: only worth recording — and only worth re-rendering for — if some
        # cluster's `raw_log` actually exceeds the tighter limit; otherwise the cut is a
        # no-op and the step is skipped (the limit is still tightened, harmlessly, for
        # whatever renders after this point).
        would_cut = any(len(h.raw_log.encode("utf-8")) > RAW_LOG_CUT_BYTES for h in heads)
        raw_log_limit = RAW_LOG_CUT_BYTES
        if would_cut:
            text = render()
            estimated = _estimate_tokens(text)
            truncations.append({"step": STEP_RAW_LOG_CUT, "before": before, "after": estimated})

    if estimated > budget and len(heads) > MAX_REPRESENTATIVE_CLUSTERS:
        before = estimated
        kept_ids = _select_representatives(heads, trigger_alert_id, MAX_REPRESENTATIVE_CLUSTERS)
        text = render()
        estimated = _estimate_tokens(text)
        truncations.append({"step": STEP_REPRESENTATIVES_CUT, "before": before, "after": estimated})

    if estimated > budget and not timeline_dropped and (timeline_rows or timeline_capped):
        before = estimated
        timeline_dropped = True
        text = render()
        estimated = _estimate_tokens(text)
        truncations.append({"step": STEP_TIMELINE_DROPPED, "before": before, "after": estimated})

    if estimated > budget:
        truncations.append(
            {"step": STEP_STILL_OVER_BUDGET, "before": estimated, "after": estimated}
        )

    return Dossier(
        text=text,
        nonce=nonce,
        snapshot=snapshot,
        truncations=tuple(truncations),
        estimated_tokens=estimated,
        blocks=tuple(blocks),
        learned_used=learned is not None and not learned_dropped,
    )
