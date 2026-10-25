"""P13-T07 / DEC-210, spec §7.8, §7.9 - the two places that queue ① (`finish_enrichment` and the
`auto_closed` branch of `open_alert`) queue the lookup too, and delay ①, when `RAG_ENABLED`.

* with the switch on: a `rag_lookup` job for `alert:<id>` and a `triage` job whose `scheduled_at` is
  `RAG_TRIAGE_DELAY_S` seconds after the database's `now()` (45 by default), on both paths. ① never
  waits for the lookup: it is simply later, and reads whatever result exists then;
* with the switch off (its default): exactly today's `enqueue(conn, "triage", alert_id)` and nothing
  else, so the rows are what they have always been;
* the jobs live and die with the transition's transaction; a refused transition queues nothing; the
  other two ways in (`received`, `duplicate`) queue nothing either way.

`domain` may import only `infra` and `audit` (`test_import_rules.py`), so the transitions spell the
lookup's subject themselves; the test pins that the spelling is `rag.subject`'s.

Every test runs inside the `db` fixture's transaction and is rolled back.
"""

from __future__ import annotations

import dataclasses
import hashlib
import itertools
import json
import uuid
from pathlib import Path

import pytest
from app.domain import transitions
from app.domain.alert import AlertContext
from app.domain.transitions import (
    AutocloseMatch,
    StaleState,
    finish_enrichment,
    open_alert,
    start_enrichment,
)
from app.ingest.wazuh_parser import parse_wazuh_alert
from app.rag.subject import Subject, parse_subject
from psycopg import sql
from psycopg.types.json import Jsonb

from tests.rag_data import add_user

pytestmark = pytest.mark.db

_DOC = json.loads((Path(__file__).parent / "fixtures" / "alert_40112.json").read_text("utf-8"))
_CANONICAL = parse_wazuh_alert(_DOC).alert
assert _CANONICAL is not None

_CONTEXT = AlertContext(
    asset_present=False,
    asset_criticality="unknown",
    asset_owner=None,
    asset_role=None,
    identity_privileged=None,
    ioc_reputation="skipped",
    lookup_status={"asset": "not_found", "identity": "not_found", "ioc": "skipped"},
)

_counter = itertools.count()


class _Abort(Exception):
    """Raised inside a savepoint to roll it back, as a caller whose later step fails would."""


@pytest.fixture
def switch_on(monkeypatch) -> None:
    monkeypatch.setenv("RAG_ENABLED", "true")


@pytest.fixture
def enqueued(monkeypatch) -> list[tuple[tuple, dict]]:
    """Every `enqueue(...)` the transitions make: the positional arguments after `conn`, and the
    keywords. The real function still runs."""
    calls: list[tuple[tuple, dict]] = []
    real = transitions.enqueue

    def spy(conn, *args, **kwargs):
        calls.append((args, kwargs))
        return real(conn, *args, **kwargs)

    monkeypatch.setattr(transitions, "enqueue", spy)
    return calls


def _alert(alert_id: str | None = None):
    n = next(_counter)
    alert_id = alert_id or f"1786907202.{720_000 + n}"
    return dataclasses.replace(
        _CANONICAL,
        alert_id=alert_id,
        event_bucket_hash=hashlib.sha256(alert_id.encode()).hexdigest(),
    )


def enriching(db) -> str:
    """An alert that is about to finish enrichment (`received` -> `enriching`)."""
    alert = _alert()
    open_alert(db, alert, kind="received", source="wazuh", suggestion_visible=True)
    start_enrichment(db, alert.alert_id)
    return alert.alert_id


def finish(db, alert_id: str) -> None:
    finish_enrichment(db, alert_id, context=_CONTEXT, risk_score=61, risk_components={})


def auto_close(db, alert_id: str | None = None) -> str:
    """An alert that opens straight into `auto_closed` (A3); ① still runs on it (D8)."""
    rule_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO autoclose_rules (autoclose_rule_id, name, match, reason, created_by)"
        " VALUES (%s, 'scanner', %s, 'known scanner', %s)",
        (rule_id, Jsonb({}), add_user(db)),
    )
    alert = _alert(alert_id)
    open_alert(
        db,
        alert,
        kind="auto_closed",
        source="wazuh",
        suggestion_visible=True,
        rule=AutocloseMatch(rule_id=rule_id, name="scanner", reason="known scanner"),
    )
    return alert.alert_id


def jobs(db, alert_id: str) -> list[tuple[str, str, str, int, float]]:
    """`(job_type, subject_id, status, attempts, seconds from now() to scheduled_at)` of the two
    job types, the lookup first."""
    rows = db.execute(
        "SELECT job_type, subject_id, status, attempts,"
        " extract(epoch FROM scheduled_at - now())::float8"
        " FROM jobs WHERE job_type IN ('rag_lookup', 'triage') AND subject_id IN (%s, %s)"
        " ORDER BY job_type",
        (alert_id, f"alert:{alert_id}"),
    ).fetchall()
    return [tuple(row) for row in rows]


def queue_by_enrichment(db) -> str:
    """Path 1: enrichment finished, the alert is `queued_tier1`."""
    alert_id = enriching(db)
    finish(db, alert_id)
    return alert_id


def queue_by_auto_close(db) -> str:
    """Path 2: the alert opened as `auto_closed`; ① runs on it all the same (D8)."""
    return auto_close(db)


both_paths = pytest.mark.parametrize(
    "queue", [queue_by_enrichment, queue_by_auto_close], ids=["finish_enrichment", "auto_closed"]
)


# ── with the switch on ────────────────────────────────────────────────────────────────────────


@both_paths
def test_the_lookup_is_queued_and_the_triage_is_delayed_by_45_seconds(db, switch_on, queue) -> None:
    alert_id = queue(db)
    (lookup_type, lookup_subject, lookup_status, _, lookup_in), triage = jobs(db, alert_id)
    assert (lookup_type, lookup_subject, lookup_status) == (
        "rag_lookup",
        f"alert:{alert_id}",
        "pending",
    )
    assert lookup_in == pytest.approx(0, abs=1)  # the lookup runs at once
    assert triage[:4] == ("triage", alert_id, "pending", 0)
    assert triage[4] == pytest.approx(45, abs=1)  # RAG_TRIAGE_DELAY_S, from the database's clock


@both_paths
def test_the_delay_is_the_configured_one(db, switch_on, monkeypatch, queue) -> None:
    monkeypatch.setenv("RAG_TRIAGE_DELAY_S", "120")
    alert_id = queue(db)
    _, triage = jobs(db, alert_id)
    assert triage[4] == pytest.approx(120, abs=1)


@both_paths
@pytest.mark.parametrize("delay", ["45", "120", "0"])
def test_the_delay_is_the_databases_clock_not_the_applications(
    db, switch_on, enqueued, monkeypatch, queue, delay
) -> None:
    """P13 fix wave, item 3 (T07 M1): the rows above would still read about 45 s if the expression were
    built from the application's clock. The SQL text handed to `enqueue` is the database's `now()`.
    """
    monkeypatch.setenv("RAG_TRIAGE_DELAY_S", delay)
    queue(db)
    (_, _), (args, kwargs) = enqueued
    assert args[0] == "triage"
    scheduled_at = kwargs["scheduled_at"]
    assert isinstance(scheduled_at, sql.Composable)  # an expression, not a timestamp computed here
    assert scheduled_at.as_string(db) == f"now() + {delay} * interval '1 second'"


@both_paths
def test_a_delay_of_zero_runs_the_triage_now(db, switch_on, monkeypatch, queue) -> None:
    monkeypatch.setenv("RAG_TRIAGE_DELAY_S", "0")
    alert_id = queue(db)
    lookup, triage = jobs(db, alert_id)
    assert lookup[0] == "rag_lookup" and triage[0] == "triage"
    assert triage[4] == pytest.approx(0, abs=1)


@both_paths
def test_the_calls_are_the_lookup_then_the_delayed_triage(db, switch_on, enqueued, queue) -> None:
    alert_id = queue(db)
    kinds = [(args, sorted(kwargs)) for args, kwargs in enqueued]
    assert kinds == [
        (("rag_lookup", f"alert:{alert_id}"), []),
        (("triage", alert_id), ["scheduled_at"]),
    ]


@both_paths
def test_the_subject_is_the_one_the_lookup_job_parses(db, switch_on, queue) -> None:
    alert_id = queue(db)
    (_, lookup_subject, *_), _ = jobs(db, alert_id)
    assert lookup_subject == Subject("alert", alert_id).key
    assert parse_subject(lookup_subject) == Subject("alert", alert_id)


@both_paths
def test_a_job_already_queued_is_not_queued_twice(db, switch_on, queue) -> None:
    alert_id = queue(db)
    transitions.enqueue(db, "rag_lookup", f"alert:{alert_id}")
    transitions.enqueue(db, "triage", alert_id)
    assert len(jobs(db, alert_id)) == 2  # single-flight: the live rows are kept


@both_paths
def test_the_jobs_live_and_die_with_the_transitions_transaction(db, switch_on, queue) -> None:
    made: list[str] = []
    with pytest.raises(_Abort), db.transaction():
        made.append(queue(db))
        assert len(jobs(db, made[0])) == 2  # inside the same transaction they are there
        raise _Abort
    assert jobs(db, made[0]) == []


def test_a_refused_finish_queues_nothing(db, switch_on, enqueued) -> None:
    alert = _alert()
    open_alert(db, alert, kind="received", source="wazuh", suggestion_visible=True)
    with pytest.raises(StaleState), db.transaction():
        finish(db, alert.alert_id)  # `received`, not `enriching`
    assert jobs(db, alert.alert_id) == []
    assert enqueued == []


@pytest.mark.parametrize("kind", ["received", "duplicate"])
def test_the_other_ways_into_open_alert_queue_neither_job(db, switch_on, enqueued, kind) -> None:
    parent = _alert()
    open_alert(db, parent, kind="received", source="wazuh", suggestion_visible=True)
    alert = _alert()
    if kind == "duplicate":
        open_alert(
            db,
            alert,
            kind="duplicate",
            source="wazuh",
            suggestion_visible=True,
            duplicate_of=parent.alert_id,
        )
    else:
        open_alert(db, alert, kind="received", source="wazuh", suggestion_visible=True)
    assert jobs(db, alert.alert_id) == []
    assert enqueued == []


# ── with the switch off ───────────────────────────────────────────────────────────────────────


@both_paths
def test_the_switch_off_queues_exactly_todays_triage_and_nothing_else(db, enqueued, queue) -> None:
    alert_id = queue(db)
    assert enqueued == [(("triage", alert_id), {})]  # today's call, argument for argument
    ((job_type, subject_id, status, attempts, in_seconds),) = jobs(db, alert_id)
    assert (job_type, subject_id, status, attempts) == ("triage", alert_id, "pending", 0)
    assert in_seconds == 0  # the column's own DEFAULT now(): not delayed
    assert db.execute("SELECT count(*) FROM jobs WHERE job_type = 'rag_lookup'").fetchone() == (0,)


@pytest.mark.parametrize("value", ["false", "0", "", "no"])
@both_paths
def test_the_switch_is_off_for_any_false_value(db, monkeypatch, enqueued, queue, value) -> None:
    monkeypatch.setenv("RAG_ENABLED", value)
    alert_id = queue(db)
    assert enqueued == [(("triage", alert_id), {})]
    assert len(jobs(db, alert_id)) == 1


@both_paths
def test_the_delay_key_means_nothing_with_the_switch_off(db, monkeypatch, enqueued, queue) -> None:
    monkeypatch.setenv("RAG_TRIAGE_DELAY_S", "300")
    alert_id = queue(db)
    assert enqueued == [(("triage", alert_id), {})]
    ((*_, in_seconds),) = jobs(db, alert_id)
    assert in_seconds == 0
