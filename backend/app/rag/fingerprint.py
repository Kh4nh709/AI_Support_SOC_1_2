"""The fingerprint of an alert or a case: closed fields and a generalised log (P13-T02, DEC-210).

A lookup searches the approved entries by this, and the ranking agent is shown it. It is built by
code from closed fields only (spec §7.6): the category, the MITRE ids, the rule ids and descriptions,
the SOAR scenario, the decoder, the tags the rule groups stand for, and the log with its addresses,
accounts, hosts, ids and numbers replaced by placeholders (`rag.generalise`). The rule descriptions
go through the same replacement as the log: Wazuh fills `$(field)` of the event into some of them,
and a fixed description has nothing to replace. Each closed value is checked against its own shape
before it is written, so a value the SIEM or the payload filled with text cannot put a line of its
own into the fingerprint.

`soar_scenario` is `alerts.raw_payload -> enrichment.scenario.id` when that is a string of the shape
of an id, else None. The name is `soar_scenario` and never `scenario_id`: that already means the lab's
ground-truth tag (DEC-117).

`text` is lines, in this order, a line left out when it has no value:

    category: …  mitre: …  rules: …  scenario: …  source: …  tags: …
    rule: <description>        one per distinct description, sorted
    log: <generalised log>     one line, at most 2000 characters

A case is the union over its heads (`case_alerts`, never their duplicates): `category` and
`log_source` are the most frequent value among the heads (the first met in head order on a tie),
`soar_scenario` is the first head's that has one, the other fields are the sorted union. Heads are
in the order `case_alerts.added_at`, `alert_time`, `alert_id`.

A subject that is not there is a `PermanentError`: the job cannot succeed by waiting.
"""

from __future__ import annotations

import re
import uuid
from collections import Counter
from collections.abc import Hashable, Sequence
from dataclasses import dataclass
from typing import Any

import psycopg

from app.infra.errors import PermanentError
from app.rag.generalise import placeholderise
from app.rag.tags import tags_from_rule_groups

LOG_LIMIT = 2000  # characters of generalised log in `text`
DESCRIPTION_LIMIT = 200
DESCRIPTION_READ_LIMIT = 1000  # characters of a description read before it is generalised
RAW_LOG_READ_LIMIT = 50_000  # characters of a raw log read; the generalised log is cut to LOG_LIMIT
_LOG_SEPARATOR = " | "

_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,63}")
_SCENARIO = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}")
_MITRE = re.compile(r"T\d{4}(?:\.\d{3})?")
_WHITESPACE = re.compile(r"\s+")
_HALF_PLACEHOLDER = re.compile(r"<[A-Z_]*$")
_LOG_MARKER = "\nlog: "
_RULE_PREFIX = "rule: "

#: `a.raw_payload` is read for two strings only; a value that is not a JSON string is NULL here.
_SELECT = (
    "SELECT a.alert_id, a.rule_id, a.description, a.category, a.decoder, a.mitre_ids,"
    " a.rule_groups, left(a.raw_log, %(read_limit)s), a.agent_name, a.alert_user,"
    " CASE WHEN jsonb_typeof(a.raw_payload #> '{enrichment,scenario,id}') = 'string'"
    "      THEN a.raw_payload #>> '{enrichment,scenario,id}' END,"
    " CASE WHEN jsonb_typeof(a.raw_payload #> '{enrichment,asset,host}') = 'string'"
    "      THEN a.raw_payload #>> '{enrichment,asset,host}' END"
    " FROM alerts a"
)


@dataclass(frozen=True)
class Fingerprint:
    category: str
    mitre_ids: tuple[str, ...]
    rule_ids: tuple[str, ...]
    soar_scenario: str | None
    log_source: str
    tags: tuple[str, ...]
    text: str


@dataclass(frozen=True)
class _Row:
    alert_id: str
    rule_id: str | None
    description: str | None
    category: str | None
    decoder: str | None
    mitre_ids: Sequence[str]
    rule_groups: Sequence[str]
    raw_log: str | None
    agent_name: str | None
    alert_user: str | None
    scenario: str | None
    asset_host: str | None

    @classmethod
    def of(cls, record: Sequence[Any]) -> _Row:
        return cls(*record)


def _token(value: str | None) -> str | None:
    return value if isinstance(value, str) and _TOKEN.fullmatch(value) else None


def _one_line(value: str | None) -> str:
    return _WHITESPACE.sub(" ", value).strip() if isinstance(value, str) else ""


def _most_common[T: Hashable](values: Sequence[T]) -> T:
    """The value met most often; on a tie the first of those met in `values` order."""
    counts = Counter(values)
    top = max(counts.values())
    return next(value for value in values if counts[value] == top)


def _cut(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return _HALF_PLACEHOLDER.sub("", text[:limit]).rstrip()


def _build(rows: Sequence[_Row], inventory: Sequence[str]) -> Fingerprint:
    category = _most_common([_token(row.category) or "unknown" for row in rows])
    mitre_ids = sorted(
        {m.upper() for row in rows for m in row.mitre_ids if _MITRE.fullmatch(m.upper())}
    )
    rule_ids = sorted({token for row in rows if (token := _token(row.rule_id))})
    scenario = next(
        (row.scenario for row in rows if row.scenario and _SCENARIO.fullmatch(row.scenario)), None
    )
    decoders = [token for row in rows if (token := _token(row.decoder))]
    log_source = _most_common(decoders) if decoders else ""
    tags = tags_from_rule_groups([group for row in rows for group in row.rule_groups])

    hosts = {name for row in rows for name in (row.agent_name, row.asset_host) if name}
    hosts.update(inventory)
    users = sorted({row.alert_user for row in rows if row.alert_user})
    # Wazuh fills `$(field)` into some descriptions, so a description can carry the event's own
    # address, account or host: it is generalised like the log. A fixed description has none of
    # those and comes out as it went in.
    descriptions = sorted(
        {
            _cut(
                _one_line(placeholderise(raw[:DESCRIPTION_READ_LIMIT], sorted(hosts), users=users)),
                DESCRIPTION_LIMIT,
            )
            for raw in {row.description for row in rows if row.description}
            if _one_line(raw)
        }
    )
    templates: list[str] = []
    size = 0
    for row in rows:
        if size >= LOG_LIMIT or not row.raw_log:
            continue
        template = _one_line(placeholderise(row.raw_log, sorted(hosts), users=users))
        if template and template not in templates:
            templates.append(template)
            size += len(template) + len(_LOG_SEPARATOR)
    log = _cut(_LOG_SEPARATOR.join(templates), LOG_LIMIT)

    lines = [f"category: {category}"]
    if mitre_ids:
        lines.append("mitre: " + " ".join(mitre_ids))
    if rule_ids:
        lines.append("rules: " + " ".join(rule_ids))
    if scenario:
        lines.append(f"scenario: {scenario}")
    if log_source:
        lines.append(f"source: {log_source}")
    if tags:
        lines.append("tags: " + " ".join(tags))
    lines.extend(_RULE_PREFIX + description for description in descriptions)
    if log:
        lines.append(f"log: {log}")
    return Fingerprint(
        category=category,
        mitre_ids=tuple(mitre_ids),
        rule_ids=tuple(rule_ids),
        soar_scenario=scenario,
        log_source=log_source,
        tags=tuple(tags),
        text="\n".join(lines),
    )


def _inventory_hostnames(conn: psycopg.Connection) -> list[str]:
    return [name for (name,) in conn.execute("SELECT hostname FROM assets LIMIT 10000")]


def alert_fingerprint(conn: psycopg.Connection, alert_id: str) -> Fingerprint:
    """The fingerprint of one alert. `PermanentError` when the alert does not exist."""
    record = conn.execute(
        _SELECT + " WHERE a.alert_id = %(alert_id)s",
        {"alert_id": alert_id, "read_limit": RAW_LOG_READ_LIMIT},
    ).fetchone()
    if record is None:
        raise PermanentError(f"alert_fingerprint: alert {alert_id!r} does not exist")
    return _build([_Row.of(record)], _inventory_hostnames(conn))


def case_fingerprint(conn: psycopg.Connection, case_id: str) -> Fingerprint:
    """The union over the case's heads (module doc). `PermanentError` when the case does not
    exist, is not a UUID, or holds no head."""
    try:
        wanted = str(uuid.UUID(str(case_id)))
    except ValueError as exc:
        raise PermanentError("case_fingerprint: the case id is not a UUID") from exc
    records = conn.execute(
        _SELECT
        + " JOIN case_alerts ca ON ca.alert_id = a.alert_id WHERE ca.case_id = %(case_id)s"
        + " ORDER BY ca.added_at, a.alert_time, a.alert_id",
        {"case_id": wanted, "read_limit": RAW_LOG_READ_LIMIT},
    ).fetchall()
    if not records:
        raise PermanentError(f"case_fingerprint: case {wanted} does not exist or has no alert")
    return _build([_Row.of(record) for record in records], _inventory_hostnames(conn))


def search_phrases(fp: Fingerprint) -> list[str]:
    """The phrases `rag.candidates` searches the entries' full text for: each rule id and each rule
    description of `fp`, never the log (a log carries a date and a month that change every day). A
    fingerprint not built by this module has no `rule:` lines, and is searched by its whole text."""
    head = fp.text.split(_LOG_MARKER, 1)[0]
    descriptions = [
        line[len(_RULE_PREFIX) :] for line in head.split("\n") if line.startswith(_RULE_PREFIX)
    ]
    phrases = [*fp.rule_ids, *descriptions]
    if not phrases and fp.text.strip():
        phrases = [fp.text]
    return list(dict.fromkeys(phrase for phrase in phrases if phrase.strip()))
