"""Rows for the P13 retrieval tests: alerts, cases and learned-knowledge entries (P13-T02).

`scratch_db.insert_alert` fills one fixed alert; the history and candidate tests need to choose the
columns the keys read (rule, addresses, host, user, category, status, first sighting, case, head)
and the SOAR block of `raw_payload`. Each function writes on the connection it is given and leaves
the commit or rollback to the caller; the `db` fixture rolls everything back.

The statuses keep the table's own rules: a closed alert has `closed_at`, one a person closed has
`sealed_at`, an alert in an open case has none (`ck_alerts_*`).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from tests.scratch_db import insert_user

__all__ = ["add_alert", "add_case", "add_entry", "add_user", "soar_payload"]

#: Statuses that end an alert's life (closed_at is mandatory) and those a person set (sealed too).
_CLOSED = {"auto_closed", "closed_fp", "closed_benign", "closed_confirmed", "duplicate"}
_SEALED = {"closed_fp", "closed_benign", "closed_confirmed", "duplicate"}
#: What `transitions.conclude_case` sets on a concluded case's alerts.
ALERT_STATUS_OF_CASE = {
    "concluded_fp": "closed_fp",
    "concluded_policy_violation": "closed_benign",
    "confirmed_incident": "closed_confirmed",
}


def add_user(conn: psycopg.Connection) -> str:
    return insert_user(conn, "tier2")


def soar_payload(
    *, scenario: str | None = None, dedup_key: str | None = None, **extra: Any
) -> dict[str, Any]:
    """The part of a SOAR document the retrieval reads: `enrichment.scenario.id`,
    `enrichment.case.dedup_key`. No `enrichment` at all when neither is given."""
    document: dict[str, Any] = dict(extra)
    enrichment: dict[str, Any] = {}
    if scenario is not None:
        enrichment["scenario"] = {"id": scenario, "name": "scenario " + scenario}
    if dedup_key is not None:
        enrichment["case"] = {"dedup_key": dedup_key}
    if enrichment:
        document["enrichment"] = enrichment
    return document


def add_alert(
    conn: psycopg.Connection,
    alert_id: str,
    *,
    rule_id: str = "5710",
    description: str = "sshd: attempt to login using a non-existent user",
    agent_name: str = "host-a",
    srcip: str = "",
    dstip: str = "",
    alert_user: str | None = None,
    decoder: str | None = "sshd",
    category: str = "ssh_brute_force",
    mitre_ids: Sequence[str] = (),
    rule_groups: Sequence[str] = (),
    status: str = "queued_tier1",
    days_ago: float = 1.0,
    duplicate_of: str | None = None,
    case_id: str | None = None,
    raw_log: str = "",
    raw_payload: Mapping[str, Any] | None = None,
) -> str:
    """One alert first seen `days_ago` days before the transaction began."""
    closed = status in _CLOSED
    sealed = status in _SEALED
    conn.execute(
        "INSERT INTO alerts (alert_id, rule_id, rule_level, severity, description, agent_name,"
        " alert_time, srcip, dstip, alert_user, decoder, mitre_ids, rule_groups, category,"
        " resolved_by, mapping_version, status, event_bucket_hash, duplicate_of, case_id,"
        " first_seen_at, last_seen_at, closed_at, sealed_at, raw_log, raw_payload)"
        " VALUES (%(alert_id)s, %(rule_id)s, 5, 'medium', %(description)s, %(agent_name)s,"
        " now() - %(days_ago)s * interval '1 day', %(srcip)s, %(dstip)s, %(alert_user)s,"
        " %(decoder)s, %(mitre_ids)s, %(rule_groups)s, %(category)s, 'none', 'v1', %(status)s,"
        " %(hash)s, %(duplicate_of)s, %(case_id)s,"
        " now() - %(days_ago)s * interval '1 day', now() - %(days_ago)s * interval '1 day',"
        " CASE WHEN %(closed)s THEN now() END, CASE WHEN %(sealed)s THEN now() END,"
        " %(raw_log)s, %(raw_payload)s)",
        {
            "alert_id": alert_id,
            "rule_id": rule_id,
            "description": description,
            "agent_name": agent_name,
            "days_ago": days_ago,
            "srcip": srcip,
            "dstip": dstip,
            "alert_user": alert_user,
            "decoder": decoder,
            "mitre_ids": list(mitre_ids),
            "rule_groups": list(rule_groups),
            "category": category,
            "status": status,
            "hash": hashlib.sha256(alert_id.encode()).hexdigest(),
            "duplicate_of": duplicate_of,
            "case_id": case_id,
            "closed": closed,
            "sealed": sealed,
            "raw_log": raw_log,
            "raw_payload": Jsonb(dict(raw_payload) if raw_payload is not None else {}),
        },
    )
    return alert_id


def add_case(
    conn: psycopg.Connection,
    user_id: str,
    heads: Iterable[str],
    *,
    status: str = "investigating",
    duplicates: Iterable[str] = (),
) -> str:
    """A case holding `heads` (existing alerts) in `case_alerts`; `duplicates` (existing alerts that
    point at a head) get `case_id` too, as `transitions.escalate` does. The alerts' own status
    follows the case: open -> `escalated_tier2`, concluded -> what `conclude_case` writes."""
    case_id = str(uuid.uuid4())
    concluded = status != "investigating"
    conn.execute(
        "INSERT INTO cases (case_id, title, status, severity, created_by, concluded_at,"
        " concluded_by, conclusion_reason) VALUES (%s, 'p13t02', %s, 'medium', %s,"
        " CASE WHEN %s THEN now() END, CASE WHEN %s THEN %s::uuid END,"
        " CASE WHEN %s THEN 'p13t02 reason' END)",
        (case_id, status, user_id, concluded, concluded, user_id, concluded),
    )
    alert_status = ALERT_STATUS_OF_CASE.get(status, "escalated_tier2")
    for alert_id in heads:
        conn.execute(
            "INSERT INTO case_alerts (case_id, alert_id, added_by) VALUES (%s, %s, %s)",
            (case_id, alert_id, user_id),
        )
        _put_in_case(conn, alert_id, case_id, alert_status)
    for alert_id in duplicates:
        conn.execute("UPDATE alerts SET case_id = %s WHERE alert_id = %s", (case_id, alert_id))
    return case_id


def _put_in_case(conn: psycopg.Connection, alert_id: str, case_id: str, status: str) -> None:
    if status == "escalated_tier2":
        conn.execute(
            "UPDATE alerts SET case_id = %s, status = 'escalated_tier2', closed_at = NULL,"
            " sealed_at = NULL WHERE alert_id = %s",
            (case_id, alert_id),
        )
    else:
        conn.execute(
            "UPDATE alerts SET case_id = %s, status = %s, closed_at = now(), sealed_at = now()"
            " WHERE alert_id = %s",
            (case_id, status, alert_id),
        )


def add_entry(
    conn: psycopg.Connection,
    *,
    entry_id: str | None = None,
    status: str = "active",
    conclusion: str = "closed_fp",
    category: str = "recon",
    mitre_ids: Sequence[str] = (),
    tags: Sequence[str] = (),
    soar_scenario: str | None = None,
    rule_ids: Sequence[str] = (),
    log_source: str | None = None,
    fingerprint: str = "",
    content: str | None = None,
    file_path: str | None = None,
    source_alert_ids: Sequence[str] = (),
    source_case_ids: Sequence[str] = (),
    evidence: Sequence[Mapping[str, Any]] = (),
    approved_days_ago: float = 1.0,
    supersedes_entry: str | None = None,
) -> str:
    """One `knowledge_entries` row. `content_sha256` is the hash of `content`; `file_path` is where
    the published file would be (relative to `kb_learned/`)."""
    entry_id = entry_id or str(uuid.uuid4())
    body = content if content is not None else f"# entry {entry_id}\n"
    conn.execute(
        "INSERT INTO knowledge_entries (entry_id, status, conclusion, category, mitre_ids, tags,"
        " soar_scenario, rule_ids, log_source, fingerprint, content, content_sha256, file_path,"
        " source_alert_ids, source_case_ids, evidence, approved_at, supersedes_entry)"
        " VALUES (%(entry_id)s, %(status)s, %(conclusion)s, %(category)s, %(mitre_ids)s, %(tags)s,"
        " %(soar_scenario)s, %(rule_ids)s, %(log_source)s, %(fingerprint)s, %(content)s,"
        " %(sha)s, %(file_path)s, %(source_alert_ids)s, %(source_case_ids)s::uuid[],"
        " %(evidence)s, now() - %(approved)s * interval '1 day', %(supersedes)s)",
        {
            "entry_id": entry_id,
            "status": status,
            "conclusion": conclusion,
            "category": category,
            "mitre_ids": list(mitre_ids),
            "tags": list(tags),
            "soar_scenario": soar_scenario,
            "rule_ids": list(rule_ids),
            "log_source": log_source,
            "fingerprint": fingerprint,
            "content": body,
            "sha": hashlib.sha256(body.encode("utf-8")).hexdigest(),
            "file_path": file_path or f"entries/{category}/{entry_id}.md",
            "source_alert_ids": list(source_alert_ids),
            "source_case_ids": list(source_case_ids),
            "evidence": Jsonb(json.loads(json.dumps(list(evidence)))),
            "approved": approved_days_ago,
            "supersedes": supersedes_entry,
        },
    )
    return entry_id
