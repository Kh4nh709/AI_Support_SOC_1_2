"""P13-T08 / DEC-210, spec §7.6, §7.9 - the two places that queue the lookup for ②: `escalate` (a new case)
and `POST /api/tier2/cases/{id}/analyze` (a refresh).

* `escalate`, with `RAG_ENABLED`, queues `rag_lookup` for `case:<uuid>` in its own transaction; without
  the switch it queues exactly what it always has: nothing;
* `api_analyze`, with `RAG_ENABLED`, queues one more `rag_lookup` for the case when the case's newest
  lookup is older than `RAG_CASE_REFRESH_H` hours or there is none, before its commit. It never moves
  the 202 body or the `run_id`, and it does not wait: the `investigate` job is enqueued exactly as before;
* ② never waits for any of it: the lookup is a job like the others and the investigation reads whatever
  `latest_lookup` holds when it runs (`test_investigate_rag.py`).

`domain` may import only `infra` and `audit` (`test_import_rules.py`), so `escalate` spells the lookup's
subject itself; the test pins that the spelling is `rag.subject`'s.

Every test runs inside the `db` fixture's transaction and is rolled back; the route's commits are spied
(`test_investigate.py`'s rule 5).
"""

from __future__ import annotations

import uuid

import psycopg
import pytest
from app.domain import transitions
from app.domain.transitions import StaleState
from app.infra import config
from app.rag.subject import Subject, parse_subject
from app.tier2 import investigate as tier2_investigate
from app.web import deps, main

from tests.rag_data import add_alert, add_user
from tests.test_investigate import _Client, _make_case, _make_user, _spy_commit_and_rollback
from tests.test_triage_rag import put_lookup

pytestmark = pytest.mark.db


class _Abort(Exception):
    """Raised inside a savepoint to roll it back, as a caller whose later step fails would."""


@pytest.fixture
def switch_on(monkeypatch) -> None:
    monkeypatch.setenv("RAG_ENABLED", "true")


@pytest.fixture
def enqueued(monkeypatch) -> list[tuple[tuple, dict]]:
    """Every `enqueue(...)` `escalate` makes: the positional arguments after `conn`, and the keywords.
    The real function still runs."""
    calls: list[tuple[tuple, dict]] = []
    real = transitions.enqueue

    def spy(conn, *args, **kwargs):
        calls.append((args, kwargs))
        return real(conn, *args, **kwargs)

    monkeypatch.setattr(transitions, "enqueue", spy)
    return calls


def lookup_jobs(db, case_id: str) -> list[tuple[str, str, str, int, float]]:
    """`(job_type, subject_id, status, attempts, seconds from now() to scheduled_at)` of the lookups
    queued for the case."""
    rows = db.execute(
        "SELECT job_type, subject_id, status, attempts, extract(epoch FROM scheduled_at - now())::float8"
        " FROM jobs WHERE job_type = 'rag_lookup' AND subject_id = %s ORDER BY job_id",
        (f"case:{case_id}",),
    ).fetchall()
    return [tuple(row) for row in rows]


def job_types(db, case_id: str) -> list[str]:
    """Every job type queued for the case, by either spelling of its subject."""
    rows = db.execute(
        "SELECT job_type FROM jobs WHERE subject_id IN (%s, %s) ORDER BY job_id",
        (case_id, f"case:{case_id}"),
    ).fetchall()
    return [job_type for (job_type,) in rows]


# ═══════════════════════════════════════════════════════════════════════════════ escalate
def escalated(db) -> tuple[str, str]:
    """A case opened by `transitions.escalate` from an alert an analyst holds: `(case_id, trigger id)`."""
    user = add_user(db)
    trigger = add_alert(db, "te-1")
    transitions.acknowledge(db, trigger, user)
    return transitions.escalate(db, trigger, user, title="p13t08", severity="high"), trigger


def test_escalate_queues_the_lookup_for_the_new_case(db, switch_on) -> None:
    case_id, _ = escalated(db)
    ((job_type, subject, status, attempts, in_seconds),) = lookup_jobs(db, case_id)
    assert (job_type, subject, status, attempts) == ("rag_lookup", f"case:{case_id}", "pending", 0)
    assert in_seconds == pytest.approx(0, abs=1)  # at once: nothing waits for it


def test_escalate_makes_exactly_one_call_and_nothing_else(db, switch_on, enqueued) -> None:
    case_id, _ = escalated(db)
    assert enqueued == [(("rag_lookup", f"case:{case_id}"), {})]
    assert job_types(db, case_id) == [
        "rag_lookup"
    ]  # no `investigate` and no delayed job of any kind


def test_escalate_spells_the_subject_the_way_the_lookup_job_reads_it(db, switch_on) -> None:
    case_id, _ = escalated(db)
    ((_, subject, *_),) = lookup_jobs(db, case_id)
    assert subject == Subject("case", case_id).key
    assert parse_subject(subject) == Subject("case", case_id)


def test_escalate_queues_the_lookup_in_the_cases_transaction(db, switch_on) -> None:
    user = add_user(db)
    trigger = add_alert(db, "te-2")
    transitions.acknowledge(db, trigger, user)
    made: list[str] = []
    with pytest.raises(_Abort), db.transaction():
        made.append(transitions.escalate(db, trigger, user, title="t", severity="high"))
        assert len(lookup_jobs(db, made[0])) == 1  # inside the same transaction it is there
        raise _Abort
    assert lookup_jobs(db, made[0]) == []
    assert db.execute("SELECT count(*) FROM cases WHERE case_id = %s", (made[0],)).fetchone() == (
        0,
    )


def test_a_refused_escalate_queues_no_second_lookup(db, switch_on, enqueued) -> None:
    case_id, trigger = escalated(db)
    enqueued.clear()
    with pytest.raises(StaleState), db.transaction():
        transitions.escalate(db, trigger, add_user(db), title="again", severity="high")
    assert len(lookup_jobs(db, case_id)) == 1
    assert db.execute("SELECT count(*) FROM jobs WHERE job_type = 'rag_lookup'").fetchone() == (1,)
    assert enqueued == []  # it failed before it queued anything


def test_escalate_without_the_switch_queues_nothing(db, enqueued) -> None:
    case_id, _ = escalated(db)
    assert enqueued == []  # not one call to `enqueue`: today's behaviour, byte for byte
    assert job_types(db, case_id) == []
    assert db.execute("SELECT count(*) FROM jobs WHERE job_type = 'rag_lookup'").fetchone() == (0,)


@pytest.mark.parametrize("value", ["false", "0", "", "no"])
def test_escalate_is_silent_for_any_false_value_of_the_switch(
    db, monkeypatch, enqueued, value
) -> None:
    monkeypatch.setenv("RAG_ENABLED", value)
    escalated(db)
    assert enqueued == []


def test_the_other_rag_keys_mean_nothing_to_escalate_with_the_switch_off(
    db, monkeypatch, enqueued
) -> None:
    monkeypatch.setenv("RAG_CASE_REFRESH_H", "1")
    monkeypatch.setenv("KNOWLEDGE_DRAFT_ENABLED", "true")  # the draft's switch is not this one
    escalated(db)
    assert enqueued == []


# ═══════════════════════════════════════════════════════════════════════════════ analyze
def make_client(db, user_id: str, **overrides) -> _Client:
    """The `test_investigate.py` client, with the config the test chooses. `RAG_ENABLED` and
    `RAG_CASE_REFRESH_H` come from it, as the route reads them from its `Cfg`."""
    client = _Client(user_id)

    def get_conn():
        try:
            yield db
        except BaseException:
            db.rollback()
            raise

    main.app.dependency_overrides[deps.get_conn] = get_conn
    main.app.dependency_overrides[deps.get_config] = lambda: config.Config(
        ANALYZE_QUOTA_PER_USER_DAY=5, **overrides
    )
    main.app.dependency_overrides[deps.current_user] = client.claims
    return client


@pytest.fixture
def web(db, monkeypatch):
    """`web(**config_overrides)` -> `(client, case_id)`: a signed-in Tier-2 user, one open case of theirs,
    and the commit and rollback spied (nothing here is ever really committed)."""
    _spy_commit_and_rollback(db, monkeypatch)

    def make(**overrides) -> tuple[_Client, str]:
        user_id = _make_user(db)
        return make_client(db, user_id, **overrides), _make_case(db, user_id)

    try:
        yield make
    finally:
        for dep in (deps.get_conn, deps.get_config, deps.current_user):
            main.app.dependency_overrides.pop(dep, None)


def analyze(client: _Client, case_id: str):
    return client.http.post(f"/api/tier2/cases/{case_id}/analyze")


def investigate_jobs(db, case_id: str) -> list[tuple[int, str]]:
    return db.execute(
        "SELECT job_id, status FROM jobs WHERE job_type = 'investigate' AND subject_id = %s",
        (case_id,),
    ).fetchall()


# ── with the switch on ────────────────────────────────────────────────────────────────────────
def test_analyze_queues_a_lookup_when_the_case_has_none(db, web) -> None:
    client, case_id = web(RAG_ENABLED=True)
    assert analyze(client, case_id).status_code == 202
    ((job_type, subject, status, attempts, _),) = lookup_jobs(db, case_id)
    assert (job_type, subject, status, attempts) == ("rag_lookup", f"case:{case_id}", "pending", 0)


def test_analyze_queues_a_lookup_when_the_newest_is_older_than_the_refresh_window(db, web) -> None:
    client, case_id = web(RAG_ENABLED=True)  # RAG_CASE_REFRESH_H defaults to 24
    put_lookup(db, case_id, kind="case", minutes_ago=24 * 60 + 5)
    assert analyze(client, case_id).status_code == 202
    assert len(lookup_jobs(db, case_id)) == 1


def test_analyze_queues_no_lookup_when_the_newest_is_fresher_than_the_window(db, web) -> None:
    client, case_id = web(RAG_ENABLED=True)
    put_lookup(db, case_id, kind="case", minutes_ago=24 * 60 - 5)
    assert analyze(client, case_id).status_code == 202
    assert lookup_jobs(db, case_id) == []


def test_it_is_the_newest_lookup_that_counts(db, web) -> None:
    client, case_id = web(RAG_ENABLED=True)
    put_lookup(db, case_id, kind="case", minutes_ago=3 * 24 * 60)  # old
    put_lookup(db, case_id, kind="case", minutes_ago=10)  # and a fresh one: nothing to refresh
    assert analyze(client, case_id).status_code == 202
    assert lookup_jobs(db, case_id) == []


def test_the_window_is_the_configured_number_of_hours(db, web) -> None:
    client, case_id = web(RAG_ENABLED=True, RAG_CASE_REFRESH_H=2)
    put_lookup(db, case_id, kind="case", minutes_ago=3 * 60)
    assert analyze(client, case_id).status_code == 202
    assert len(lookup_jobs(db, case_id)) == 1

    other_client, other_case = web(RAG_ENABLED=True, RAG_CASE_REFRESH_H=2)
    put_lookup(db, other_case, kind="case", minutes_ago=60)
    assert analyze(other_client, other_case).status_code == 202
    assert lookup_jobs(db, other_case) == []


def test_a_zero_window_always_refreshes(db, web) -> None:
    client, case_id = web(RAG_ENABLED=True, RAG_CASE_REFRESH_H=0)
    put_lookup(db, case_id, kind="case", minutes_ago=1)
    assert analyze(client, case_id).status_code == 202
    assert len(lookup_jobs(db, case_id)) == 1


@pytest.mark.parametrize("status", ["ok", "empty", "failed", "budget"])
def test_it_is_the_age_of_the_newest_lookup_not_its_status(db, web, status) -> None:
    """Spec §7.6: "older than `RAG_CASE_REFRESH_H`, or none". A fresh `failed` row is not retried by a
    click: ② would run on it exactly as it runs on no row, and the queue already retried the job."""
    client, case_id = web(RAG_ENABLED=True)
    put_lookup(db, case_id, kind="case", status=status, minutes_ago=30)
    assert analyze(client, case_id).status_code == 202
    assert lookup_jobs(db, case_id) == []


def test_a_lookup_of_another_subject_is_not_this_cases(db, web) -> None:
    client, case_id = web(RAG_ENABLED=True)
    put_lookup(db, str(uuid.uuid4()), kind="case", minutes_ago=5)  # another case
    put_lookup(
        db, case_id, kind="alert", minutes_ago=5
    )  # an alert whose id happens to be this text
    assert analyze(client, case_id).status_code == 202
    assert len(lookup_jobs(db, case_id)) == 1


def test_a_lookup_already_queued_is_not_queued_twice(db, web) -> None:
    client, case_id = web(RAG_ENABLED=True)
    transitions.enqueue(db, "rag_lookup", f"case:{case_id}")  # e.g. the one `escalate` queued
    assert analyze(client, case_id).status_code == 202
    assert len(lookup_jobs(db, case_id)) == 1  # single-flight keeps the live row


def test_the_lookup_is_queued_before_the_commit(db, web, monkeypatch) -> None:
    """In the request's own transaction: at the route's commit the lookup is already there, so one
    commit makes the investigation and its lookup visible together (and a refused request has neither).
    """
    client, case_id = web(RAG_ENABLED=True)
    seen: list[tuple[int, int]] = []

    def commit() -> None:
        seen.append((len(investigate_jobs(db, case_id)), len(lookup_jobs(db, case_id))))

    monkeypatch.setattr(db, "commit", commit)
    assert analyze(client, case_id).status_code == 202
    assert seen == [(1, 1)]


def test_the_202_body_and_the_run_id_do_not_move(db, web) -> None:
    client, case_id = web(RAG_ENABLED=True)
    response = analyze(client, case_id)
    body = response.json()
    assert response.status_code == 202
    assert set(body) == {"run_id", "job_id"}  # nothing about the lookup is in it
    ((job_id, _),) = investigate_jobs(db, case_id)
    assert body["job_id"] == job_id
    assert uuid.UUID(body["run_id"]) == tier2_investigate.run_id_for_job(job_id)


def test_the_audit_row_is_what_it_was(db, web) -> None:
    client, case_id = web(RAG_ENABLED=True)
    body = analyze(client, case_id).json()
    ((payload,),) = db.execute(
        "SELECT payload FROM audit_events WHERE event_type = 'case.analyzed' AND subject_id = %s",
        (case_id,),
    ).fetchall()
    assert payload == {"run_id": body["run_id"], "job_id": body["job_id"]}


def test_the_investigation_is_queued_to_run_now_not_after_the_lookup(db, web) -> None:
    """② never waits: no delay on the `investigate` job, and the lookup is a separate job."""
    client, case_id = web(RAG_ENABLED=True)
    assert analyze(client, case_id).status_code == 202
    (in_seconds,) = db.execute(
        "SELECT extract(epoch FROM scheduled_at - now())::float8 FROM jobs"
        " WHERE job_type = 'investigate' AND subject_id = %s",
        (case_id,),
    ).fetchone()
    assert in_seconds == pytest.approx(0, abs=1)


@pytest.mark.parametrize("path", ["unknown", "concluded", "already_running", "over_quota"])
def test_a_refused_analyze_queues_no_lookup(db, web, path) -> None:
    client, case_id = web(RAG_ENABLED=True)
    if path == "unknown":
        case_id = str(uuid.uuid4())
        expected = 404
    elif path == "concluded":
        db.execute(
            "UPDATE cases SET status = 'concluded_fp', conclusion_reason = 'done', concluded_by = %s,"
            " concluded_at = now() WHERE case_id = %s",
            (client.user_id, case_id),
        )
        expected = 409
    elif path == "already_running":
        transitions.enqueue(db, "investigate", case_id)
        expected = 409
    else:
        main.app.dependency_overrides[deps.get_config] = lambda: config.Config(
            ANALYZE_QUOTA_PER_USER_DAY=0, RAG_ENABLED=True
        )
        expected = 429
    assert analyze(client, case_id).status_code == expected
    assert lookup_jobs(db, case_id) == []


# ── with the switch off: today's behaviour ────────────────────────────────────────────────────
def test_the_switch_off_queues_only_the_investigation_and_reads_no_lookup(
    db, web, monkeypatch
) -> None:
    client, case_id = web()  # RAG_ENABLED defaults to False
    statements: list[str] = []
    real = psycopg.Cursor.execute

    def spy(self, query, *args, **kwargs):
        statements.append(query if isinstance(query, str) else repr(query))
        return real(self, query, *args, **kwargs)

    monkeypatch.setattr(psycopg.Cursor, "execute", spy)

    response = analyze(client, case_id)

    assert statements, "the recorder saw nothing - it is not recording"
    assert not [s for s in statements if "rag_results" in s or "rag_lookup" in s]
    assert response.status_code == 202 and set(response.json()) == {"run_id", "job_id"}
    assert job_types(db, case_id) == ["investigate"]  # the rows are what they have always been


def test_the_switch_off_ignores_a_stale_or_missing_lookup(db, web) -> None:
    client, case_id = web(RAG_ENABLED=False, RAG_CASE_REFRESH_H=1)
    put_lookup(db, case_id, kind="case", minutes_ago=48 * 60)
    assert analyze(client, case_id).status_code == 202
    assert lookup_jobs(db, case_id) == []
    assert db.execute("SELECT count(*) FROM jobs WHERE job_type = 'rag_lookup'").fetchone() == (0,)


def test_the_body_and_the_run_id_are_the_same_shape_with_and_without_the_switch(db, web) -> None:
    shapes = []
    for on in (False, True):
        client, case_id = web(RAG_ENABLED=on)
        response = analyze(client, case_id)
        body = response.json()
        ((job_id, status),) = investigate_jobs(db, case_id)
        shapes.append(
            (
                response.status_code,
                sorted(body),
                body["job_id"] == job_id,
                uuid.UUID(body["run_id"]) == tier2_investigate.run_id_for_job(job_id),
                status,
            )
        )
    assert shapes[0] == shapes[1] == (202, ["job_id", "run_id"], True, True, "pending")
