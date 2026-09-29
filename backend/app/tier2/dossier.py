"""Assemble the nine-block case dossier (facts, logs, timeline, entities, playbooks).

P5-T03 (DEC-151 wave 2). `build(conn, case_id, *, nonce, cfg=None) -> Dossier` reads the
nine blocks of context pack §7.6 / the card's design note 1 from the database only, inside
`cfg.CASE_PROMPT_BUDGET_TOKENS`, and is deterministic: two builds of the same case at the
same instant are byte-identical except the nonce (design note 3). This module sends
nothing to a model and imports nothing from `app.llm.adapter` — P5-T04 does that.

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
carries an explicit `ORDER BY`
ending in a primary key. The one non-deterministic input is `nonce`, a required keyword
parameter — never generated in here.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import psycopg

from app.domain import correlation
from app.infra import config
from app.kb.lookup import get_playbook
from app.llm.builder import (
    SENTENCE_ABSENT,
    SENTENCE_NO_CORRELATION,
    SENTENCE_NO_PLAYBOOK,
    Category,
    Id,
    Severity,
    fact,
)
from app.security import wrap

# ─────────────────────────────────────────────────────── budget / truncation (design note 4)
#: "raw_log up to 8 KB" (design note 1 block 2) is the *baseline*, not itself a recorded
#: truncation; the cut from 8 KB to 4 KB is the first of the three budget-driven steps.
RAW_LOG_INITIAL_BYTES = 8_192
RAW_LOG_CUT_BYTES = 4_096
MAX_REPRESENTATIVE_CLUSTERS = 15
TIMELINE_MAX_LINES = 300
MAX_ENTITIES = 50
ENTITY_HISTORY_DAYS = 7

STEP_RAW_LOG_CUT = "raw_log_8kb_to_4kb"
STEP_REPRESENTATIVES_CUT = "representatives_to_15_clusters"
STEP_TIMELINE_DROPPED = "timeline_dropped"
STEP_STILL_OVER_BUDGET = "budget_exceeded_after_cuts"
STEP_ENTITIES_CAPPED = "entities_cap_50"


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
SENTENCE_OUT_OF_SCOPE = (
    "Không có threat intel ngoài, dữ liệu gói tin, EDR. "
    "Thiếu thì trả need_more_data, không suy đoán."
)
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
        SENTENCE_OUT_OF_SCOPE,
    }
)

# ─────────────────────────────────────────────────────── entity regexes (design note 2)
#: Word-bounded so a 31- or 33-hex-character string never matches the 32-length family —
#: hex characters are all `\w`, so `\b` cannot land inside a contiguous run; see the module
#: docstring reference and the task report for the worked-through reasoning.
_IPV4_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4_RE = re.compile(rf"\b{_IPV4_OCTET}(?:\.{_IPV4_OCTET}){{3}}\b")
_IPV6_RE = re.compile(
    r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b"  # full/partial form, >= 3 groups
    r"|\b(?:[0-9A-Fa-f]{1,4}:)+:(?:[0-9A-Fa-f]{1,4}:?)*[0-9A-Fa-f]{1,4}\b"  # "::" compressed
)
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
    history: Mapping[str, int]
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
    text: str
    nonce: str
    snapshot: Snapshot
    truncations: tuple[dict[str, Any], ...]
    estimated_tokens: int


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
    raw_payload: Mapping[str, Any]


# ───────────────────────────────────────────────────── queries (design note 3 and 6)
#: Design note 6: heads are `alert_id IN (SELECT alert_id FROM case_alerts WHERE case_id
#: = %s)`; duplicates are `duplicate_of IN` that *same* subquery — never `JOIN case_alerts
#: USING (alert_id)`, which would miss every duplicate (DEC-036).
_CASE_ALERT_IDS = "SELECT alert_id FROM case_alerts WHERE case_id = %s"

_HEADS_SQL = f"""
    SELECT alert_id, rule_id, rule_level, severity, category, occurrence_count,
           alert_time, first_seen_at, last_seen_at, description, raw_log,
           agent_name, origin_host, alert_user, srcip, raw_payload
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

_TIMELINE_SQL = f"""
    SELECT alert_time, rule_id, agent_name, alert_user, alert_id
    FROM alerts
    WHERE alert_id IN ({_CASE_ALERT_IDS}) OR duplicate_of IN ({_CASE_ALERT_IDS})
    ORDER BY alert_time, alert_id
    LIMIT {TIMELINE_MAX_LINES}
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


def _fetch_timeline(conn: psycopg.Connection, case_id: str) -> list[tuple[Any, ...]]:
    return conn.execute(_TIMELINE_SQL, (case_id, case_id)).fetchall()


def _fetch_tier1_events(conn: psycopg.Connection, case_id: str) -> list[tuple[Any, ...]]:
    return conn.execute(_TIER1_EVENTS_SQL, (case_id,)).fetchall()


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
    return {m.group().lower() for m in _IPV6_RE.finditer(text) if m.group().count(":") >= 2}


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
    (design note 2's *"From the case's raw_logs and descriptions"*), usernames from the
    two `raw_payload` paths, hosts from the already-parsed `agent_name`/`origin_host`
    columns (which is what `agent.name`/`predecoder.hostname` resolve to at ingest —
    `ingest/wazuh_parser.py` — so no jsonb path walk is needed for hosts)."""
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
        for path in (("data", "dstuser"), ("data", "srcuser")):
            user = _raw_payload_str(head.raw_payload, *path)
            if user:
                values["username"].add(user)
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
    if not values:
        return {}
    rows = conn.execute(
        "SELECT value, reputation FROM iocs "
        "WHERE value = ANY(%s) AND active AND expires_at > now() ORDER BY value",
        (values,),
    ).fetchall()
    return {r[0]: {"status": "found", "reputation": r[1]} for r in rows}


def _bulk_host_history(conn: psycopg.Connection, hosts: list[str]) -> dict[str, dict[str, int]]:
    if not hosts:
        return {}
    rows = conn.execute(
        f"SELECT agent_name, category, count(*) FROM alerts "
        f"WHERE agent_name = ANY(%s) AND alert_time > now() - interval '{ENTITY_HISTORY_DAYS} days' "
        f"GROUP BY agent_name, category ORDER BY agent_name, category",
        (hosts,),
    ).fetchall()
    out: dict[str, dict[str, int]] = {}
    for host, cat, n in rows:
        out.setdefault(host, {})[cat] = n
    return out


def _bulk_username_history(conn: psycopg.Connection, users: list[str]) -> dict[str, dict[str, int]]:
    if not users:
        return {}
    rows = conn.execute(
        f"SELECT alert_user, category, count(*) FROM alerts "
        f"WHERE alert_user = ANY(%s) AND alert_time > now() - interval '{ENTITY_HISTORY_DAYS} days' "
        f"GROUP BY alert_user, category ORDER BY alert_user, category",
        (users,),
    ).fetchall()
    out: dict[str, dict[str, int]] = {}
    for user, cat, n in rows:
        out.setdefault(user, {})[cat] = n
    return out


def _bulk_ip_history(conn: psycopg.Connection, ips: list[str]) -> dict[str, dict[str, int]]:
    """One SQL for both IPv4 and IPv6 entities: an IP can appear as `srcip` or `dstip`."""
    if not ips:
        return {}
    rows = conn.execute(
        f"""
        SELECT ip, category, count(*) FROM (
            SELECT srcip AS ip, category FROM alerts
             WHERE srcip = ANY(%s) AND alert_time > now() - interval '{ENTITY_HISTORY_DAYS} days'
            UNION ALL
            SELECT dstip AS ip, category FROM alerts
             WHERE dstip = ANY(%s) AND alert_time > now() - interval '{ENTITY_HISTORY_DAYS} days'
        ) x
        GROUP BY ip, category
        ORDER BY ip, category
        """,
        (ips, ips),
    ).fetchall()
    out: dict[str, dict[str, int]] = {}
    for ip, cat, n in rows:
        out.setdefault(ip, {}).setdefault(cat, 0)
        out[ip][cat] += n
    return out


def _build_entities(conn: psycopg.Connection, heads: Sequence[_Head]) -> tuple[Entity, ...]:
    """Cap 50, ordered deterministically by (type, -count_7d, value) — a value can appear
    only once per type, so this key is always a strict total order regardless of which
    order the extraction or the bulk queries happen to visit rows in (design note 2, 3)."""
    raw = _extract_raw_values(heads)
    ip_values = sorted(raw["ipv4"] | raw["ipv6"])
    host_lookup = _bulk_asset_lookup(conn, sorted(raw["host"]))
    host_history = _bulk_host_history(conn, sorted(raw["host"]))
    user_lookup = _bulk_identity_lookup(conn, sorted(raw["username"]))
    user_history = _bulk_username_history(conn, sorted(raw["username"]))
    ip_history = _bulk_ip_history(conn, ip_values)
    ioc_values = sorted(
        raw["ipv4"] | raw["ipv6"] | raw["md5"] | raw["sha1"] | raw["sha256"] | raw["domain"]
    )
    ioc_lookup = _bulk_ioc_lookup(conn, ioc_values)

    entities: list[Entity] = []
    for kind in ENTITY_TYPE_ORDER:
        for value in sorted(raw[kind]):
            if kind == "host":
                lookup = host_lookup.get(value, {"status": "not_found"})
                history = host_history.get(value, {})
            elif kind == "username":
                lookup = user_lookup.get(value, {"status": "not_found"})
                history = user_history.get(value, {})
            elif kind in ("ipv4", "ipv6"):
                lookup = ioc_lookup.get(value, {"status": "not_found"})
                history = ip_history.get(value, {})
            else:  # md5 / sha1 / sha256 / domain — no structured alerts column for history
                lookup = ioc_lookup.get(value, {"status": "not_found"})
                history = {}
            entities.append(
                Entity(
                    kind=kind,
                    value=value,
                    count_7d=sum(history.values()),
                    history=history,
                    lookup=lookup,
                )
            )

    entities.sort(key=lambda e: (ENTITY_TYPE_ORDER.index(e.kind), -e.count_7d, e.value))
    return tuple(entities)


# ─────────────────────────────────────────────────────────────── rendering (design note 1)
def _block1_case(
    case_row: Mapping[str, Any],
    heads: Sequence[_Head],
    dup_spans: Mapping[str, tuple[int, datetime, datetime]],
    trigger_alert_id: str | None,
    nonce: str,
) -> str:
    total_dup = sum(span[0] for span in dup_spans.values())
    total_occurrences = sum(h.occurrence_count for h in heads)
    parts = [HEADING_CASE]
    parts.append(fact("severity", Severity(case_row["severity"])))
    parts.append(fact("clusters", len(heads)))
    parts.append(fact("occurrence_count", int(total_occurrences)))
    parts.append(fact("alerts", int(len(heads) + total_dup)))
    if heads:
        parts.append(fact("first_seen", min(h.alert_time for h in heads)))
        parts.append(fact("last_seen", max(h.alert_time for h in heads)))
    if trigger_alert_id:
        try:
            parts.append(fact("alert_id", Id("alert_id", trigger_alert_id)))
        except ValueError:
            pass  # design note: a malformed id from an old audit row is never echoed raw
    context_lines = [f"title: {case_row['title']}"]
    if case_row.get("created_by"):
        context_lines.append(f"escalated_by: {case_row['created_by']}")
    parts.append(wrap.untrusted_block("\n".join(context_lines), "context", nonce=nonce).rendered)
    return "\n".join(parts)


def _block2_clusters(
    heads: Sequence[_Head],
    dup_spans: Mapping[str, tuple[int, datetime, datetime]],
    nonce: str,
    *,
    raw_log_limit: int,
) -> str:
    parts = [HEADING_CLUSTERS]
    for head in heads:
        line = [
            fact("alert_id", Id("alert_id", head.alert_id)),
            fact("rule_id", Id("rule_id", head.rule_id)),
            fact("severity", Severity(head.severity)),
            fact("category", Category(head.category)),
            fact("occurrence_count", int(head.occurrence_count)),
        ]
        span = dup_spans.get(head.alert_id)
        if span is not None:
            dup_count, dup_first, dup_last = span
            line.append(fact("alerts", int(dup_count)))
            line.append(fact("first_seen", dup_first))
            line.append(fact("last_seen", dup_last))
        parts.append(" · ".join(line))
        parts.append(
            wrap.untrusted_block(
                head.raw_log,
                "wazuh_raw_log",
                nonce=nonce,
                limit_bytes=raw_log_limit,
            ).rendered
        )
    return "\n".join(parts)


def _block3_timeline(rows: Sequence[tuple[Any, ...]], nonce: str) -> str:
    lines = [
        f"{alert_time.isoformat(timespec='seconds')} · {rule_id} · {agent_name} · {alert_user or ''}"
        for alert_time, rule_id, agent_name, alert_user, _alert_id in rows
    ]
    body = "\n".join(lines)
    wrapped = wrap.untrusted_block(body, "context", nonce=nonce).rendered
    return f"{HEADING_TIMELINE}\n{wrapped}"


def _entity_detail(entity: Entity) -> str:
    if entity.lookup.get("status") != "found":
        return SENTENCE_ABSENT
    if entity.kind == "host":
        return f"criticality={entity.lookup.get('criticality')}"
    if entity.kind == "username":
        return f"privileged={entity.lookup.get('is_privileged')}"
    return f"reputation={entity.lookup.get('reputation')}"


def _block4_entities(entities: Sequence[Entity], nonce: str) -> str:
    lines = []
    for e in entities:
        history_str = ", ".join(f"{cat}={n}" for cat, n in sorted(e.history.items())) or "none"
        lines.append(
            f"{e.kind}: {e.value} | lookup: {e.lookup.get('status')} | "
            f"{_entity_detail(e)} | {ENTITY_HISTORY_DAYS}d: {history_str}"
        )
    body = "\n".join(lines)
    wrapped = wrap.untrusted_block(body, "context", nonce=nonce).rendered
    return f"{HEADING_ENTITIES}\n{wrapped}"


def _block5_correlation(
    heads: Sequence[_Head],
    correlation_by_head: Mapping[str, correlation.CorrelationSummary],
    case_head_ids: frozenset[str],
    nonce: str,
) -> str:
    parts = [HEADING_CORRELATION]
    for head in heads:
        parts.append(fact("alert_id", Id("alert_id", head.alert_id)))
        summary = correlation_by_head.get(head.alert_id)
        rows = summary.rows if summary is not None else ()
        if not rows:
            parts.append(SENTENCE_NO_CORRELATION)
            continue
        for row in rows:
            parts.append(
                " · ".join(
                    (
                        fact("rule_id", Id("rule_id", row.rule_id)),
                        fact("category", Category(row.category)),
                        fact("clusters", int(row.cluster_count)),
                        fact("alerts", int(row.alert_count)),
                        fact("src_ips", int(row.src_ip_count)),
                        fact("first_seen", row.first_seen),
                        fact("last_seen", row.last_seen),
                    )
                )
            )
        # "clusters not already in the case" (design note 1 block 5): the samples are
        # the only place a concrete alert_id is named, so that is where this is applied.
        samples = [s for s in summary.samples if s.get("alert_id") not in case_head_ids]
        if samples:
            body = "\n\n".join(
                f"alert_id={s.get('alert_id')} rule_id={s.get('rule_id')} "
                f"category={s.get('category')}\n{s.get('description') or ''}\n{s.get('raw_log') or ''}"
                for s in samples
            )
            parts.append(wrap.untrusted_block(body, "correlation_samples", nonce=nonce).rendered)
    return "\n".join(parts)


def _block6_tier1(rows: Sequence[tuple[Any, ...]], nonce: str) -> str:
    lines = []
    for _audit_id, event_type, subject_id, _actor_id, actor_role, _payload, created_at in rows:
        lines.append(
            f"{created_at.isoformat(timespec='seconds')} · {event_type} · {subject_id} · {actor_role}"
        )
    body = "\n".join(lines)
    wrapped = wrap.untrusted_block(body, "context", nonce=nonce).rendered
    return f"{HEADING_TIER1}\n{wrapped}"


def _block7_playbooks(categories: Sequence[str], nonce: str) -> str:
    parts = [HEADING_PLAYBOOKS]
    for cat in categories:
        parts.append(fact("category", Category(cat)))
        text = get_playbook(cat)
        if text:
            parts.append(wrap.untrusted_block(text, "kb_playbook", nonce=nonce).rendered)
        else:
            parts.append(SENTENCE_NO_PLAYBOOK)
    return "\n".join(parts)


def _block8_notes_and_previous(
    notes: Sequence[tuple[Any, ...]],
    previous_run: tuple[Any, ...] | None,
    nonce: str,
) -> str:
    parts = [HEADING_NOTES]
    if notes:
        body = "\n\n".join(
            f"{created_at.isoformat(timespec='seconds')} ({author_id}):\n{body_text}"
            for author_id, body_text, created_at in notes
        )
        parts.append(wrap.untrusted_block(body, "context", nonce=nonce).rendered)
    parts.append(HEADING_PREVIOUS_RUN)
    if previous_run is not None:
        _run_id, result, created_at = previous_run
        body = f"{created_at.isoformat(timespec='seconds')}\n{json.dumps(result, ensure_ascii=False, sort_keys=True)}"
        # Injection accumulating across rounds (docs/phase-7-tier2.md:250): a previous ②
        # result that was itself injected must not re-enter the next prompt unwrapped.
        parts.append(wrap.untrusted_block(body, "proposer", nonce=nonce).rendered)
    return "\n".join(parts)


def _block9_scope() -> str:
    return f"{HEADING_SCOPE}\n{SENTENCE_OUT_OF_SCOPE}"


# ─────────────────────────────────────────────────────────────────────── build()
def build(
    conn: psycopg.Connection,
    case_id: str,
    *,
    nonce: str,
    cfg: config.Config | None = None,
) -> Dossier:
    cfg = cfg or config.load()

    case_row = _fetch_case(conn, case_id)
    if case_row is None:
        raise UnknownCase(case_id)

    heads = _fetch_heads(conn, case_id)
    dup_spans = _fetch_duplicate_spans(conn, case_id)
    timeline_rows = _fetch_timeline(conn, case_id)
    tier1_rows = _fetch_tier1_events(conn, case_id)
    trigger_alert_id = _fetch_trigger_alert_id(conn, case_id)
    notes = _fetch_notes(conn, case_id)
    previous_run = _fetch_previous_run(conn, case_id)
    categories = sorted({h.category for h in heads})

    entities_all = _build_entities(conn, heads)
    truncations: list[dict[str, Any]] = []
    if len(entities_all) > MAX_ENTITIES:
        truncations.append(
            {"step": STEP_ENTITIES_CAPPED, "before": len(entities_all), "after": MAX_ENTITIES}
        )
    entities = entities_all[:MAX_ENTITIES]

    case_head_ids = frozenset(h.alert_id for h in heads)
    correlation_by_head = {h.alert_id: correlation.summarize_for_prompt(conn, h) for h in heads}

    total_dup = sum(span[0] for span in dup_spans.values())
    snapshot = Snapshot(
        alert_count=len(heads) + total_dup,
        total_occurrences=sum(h.occurrence_count for h in heads),
        last_seen_at=max((h.last_seen_at for h in heads), default=None),
    )

    raw_log_limit = RAW_LOG_INITIAL_BYTES
    n_clusters = len(heads)
    timeline_active = list(timeline_rows)

    def render() -> str:
        display_heads = heads[:n_clusters]
        sections = [
            _block1_case(case_row, heads, dup_spans, trigger_alert_id, nonce),
            _block2_clusters(display_heads, dup_spans, nonce, raw_log_limit=raw_log_limit),
            _block3_timeline(timeline_active, nonce),
            _block4_entities(entities, nonce),
            _block5_correlation(display_heads, correlation_by_head, case_head_ids, nonce),
            _block6_tier1(tier1_rows, nonce),
            _block7_playbooks(categories, nonce),
            _block8_notes_and_previous(notes, previous_run, nonce),
            _block9_scope(),
        ]
        return "\n\n".join(sections)

    text = render()
    estimated = _estimate_tokens(text)
    budget = cfg.CASE_PROMPT_BUDGET_TOKENS

    if estimated > budget and raw_log_limit > RAW_LOG_CUT_BYTES:
        before = estimated
        raw_log_limit = RAW_LOG_CUT_BYTES
        text = render()
        estimated = _estimate_tokens(text)
        truncations.append({"step": STEP_RAW_LOG_CUT, "before": before, "after": estimated})

    if estimated > budget and n_clusters > MAX_REPRESENTATIVE_CLUSTERS:
        before = estimated
        n_clusters = MAX_REPRESENTATIVE_CLUSTERS
        text = render()
        estimated = _estimate_tokens(text)
        truncations.append({"step": STEP_REPRESENTATIVES_CUT, "before": before, "after": estimated})

    if estimated > budget and timeline_active:
        before = estimated
        timeline_active = []
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
    )
