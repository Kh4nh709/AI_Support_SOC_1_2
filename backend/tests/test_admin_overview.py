"""P11-T05 — the admin overview and the failed-job retry: `web/routers/admin_overview.py`
(`GET /api/admin/overview`, `POST /api/admin/jobs/{job_id}/retry`, spec §4.1 and §5.4).

Every test runs the real app through `TestClient(main.app)`, with `deps.get_conn` overridden
to this module's own connection and `deps.current_user` to a fixed `Claims` (the shape of
`test_pages_rules.py`'s `client` fixture). The database is a scratch database this module
builds and drops (`tests/scratch_db.py`), not the shared `db` fixture, for two reasons:

- the 403 tests commit for real (`deps.require_role` commits the `authz.denied` row before it
  raises), and that row must not reach the shared database a later test file counts in;
- the overview counts whole tables (`failed_jobs`, `inventory`, `cases_open`), so an exact
  assertion needs a database no other file has written to.

Each test rolls its connection back at the end, so the module's tests do not see each other's
rows. The only committed rows are the two 403 tests' own (see them).

A "section fails" test has to fail with a REAL SQL error, not a Python exception: only a
statement that errors puts the request's transaction into the aborted state a missing
savepoint would leave behind (`SELECT 1/0`, or `pg_sleep` past `statement_timeout`).
"""

from __future__ import annotations

import dataclasses
import hashlib
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

import psycopg
import pytest
from app.infra import config, jobs
from app.infra.auth import Claims
from app.web import deps, main
from app.web.routers import admin_overview
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from tests.scratch_db import insert_user, scratch_database

OVERVIEW = "/api/admin/overview"
SECTIONS = (
    "alerts_by_day",
    "by_source",
    "top_agents",
    "funnel",
    "waiting",
    "cases_open",
    "health",
    "failed_jobs",
    "inventory",
)
HCM = ZoneInfo("Asia/Ho_Chi_Minh")


# ---------------------------------------------------------------------------
# The scratch database and the client
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def scratch_dsn():
    with scratch_database("overview") as dsn:
        yield dsn


@pytest.fixture
def sdb(scratch_dsn):
    conn = psycopg.connect(scratch_dsn)
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


@pytest.fixture(autouse=True)
def _require_db_marker_for_scratch(request):
    uses = {"sdb", "scratch_dsn", "client"} & set(request.fixturenames)
    if uses and request.node.get_closest_marker("db") is None:
        pytest.fail(f"{request.node.nodeid} uses {sorted(uses)} without @pytest.mark.db")


def _override(sdb, claims: Claims, tz: str = "Asia/Ho_Chi_Minh") -> None:
    cfg = dataclasses.replace(config.load(), DISPLAY_TZ=tz)
    main.app.dependency_overrides[deps.get_conn] = lambda: sdb
    main.app.dependency_overrides[deps.current_user] = lambda: claims
    main.app.dependency_overrides[deps.get_config] = lambda: cfg


def _clear_overrides() -> None:
    for dep in (deps.get_conn, deps.current_user, deps.get_config):
        main.app.dependency_overrides.pop(dep, None)


@pytest.fixture
def client(sdb):
    """`(TestClient, connection, admin Claims)`; DISPLAY_TZ is pinned to the default."""
    admin_id = insert_user(sdb, "admin")
    claims = Claims(user_id=admin_id, username="p11t05-admin", role="admin", iat=0.0, exp=0.0)
    _override(sdb, claims)
    try:
        yield TestClient(main.app), sdb, claims
    finally:
        _clear_overrides()


# ---------------------------------------------------------------------------
# Factories — plain SQL, with the CHECKs that bite here satisfied
# ---------------------------------------------------------------------------

_CLOSED = {"duplicate", "auto_closed", "closed_fp", "closed_benign", "closed_confirmed"}
_SEALED = {"duplicate", "closed_fp", "closed_benign", "closed_confirmed"}


def _ago(**kwargs: float) -> datetime:
    return datetime.now(UTC) - timedelta(**kwargs)


def _alert(
    conn: Any,
    alert_id: str,
    *,
    received_at: datetime | None = None,
    agent_name: str = "agent-a",
    source: str = "wazuh",
    status: str = "received",
    duplicate_of: str | None = None,
    is_synthetic: bool = False,
    triage_status: str = "pending",
) -> None:
    """One alert. A `duplicate_of` makes it a `duplicate` (the CHECK wants it closed and sealed)."""
    if duplicate_of is not None:
        status = "duplicate"
    conn.execute(
        """
        INSERT INTO alerts (
            alert_id, rule_id, rule_level, severity, description, agent_name, alert_time,
            category, resolved_by, mapping_version, event_bucket_hash, raw_payload,
            source, is_synthetic, status, duplicate_of, triage_status,
            received_at, closed_at, sealed_at
        ) VALUES (
            %(id)s, '1', 5, 'medium', 'd', %(agent)s, now(),
            'generic', 'none', 'v1', %(hash)s, %(payload)s,
            %(source)s, %(synthetic)s, %(status)s, %(dup)s, %(triage)s,
            COALESCE(%(received)s, now()),
            CASE WHEN %(closed)s THEN now() END,
            CASE WHEN %(sealed)s THEN now() END
        )
        """,
        {
            "id": alert_id,
            "agent": agent_name,
            "hash": hashlib.sha256(alert_id.encode()).hexdigest(),
            "payload": Jsonb({}),
            "source": source,
            "synthetic": is_synthetic,
            "status": status,
            "dup": duplicate_of,
            "triage": triage_status,
            "received": received_at,
            "closed": status in _CLOSED,
            "sealed": status in _SEALED,
        },
    )


def _rejected(conn: Any, received_at: datetime | None = None) -> None:
    conn.execute(
        "INSERT INTO rejected_alerts (raw_payload, reason, received_at) "
        "VALUES (%s, 'bad', COALESCE(%s, now()))",
        (Jsonb({}), received_at),
    )


def _job(
    conn: Any,
    *,
    job_type: str = "triage",
    subject_id: str | None = None,
    status: str = "failed",
    attempts: int = 3,
    last_error: str | None = "boom",
    created_at: datetime | None = None,
    locked_at: datetime | None = None,
) -> int:
    (job_id,) = conn.execute(
        """
        INSERT INTO jobs (job_type, subject_id, status, attempts, last_error, created_at, locked_at)
        VALUES (%s, %s, %s, %s, %s, COALESCE(%s, now()), %s)
        RETURNING job_id
        """,
        (
            job_type,
            subject_id or f"alert-{uuid.uuid4().hex[:8]}",
            status,
            attempts,
            last_error,
            created_at,
            locked_at,
        ),
    ).fetchone()
    return job_id


def _case(conn: Any, creator: str, status: str = "investigating") -> None:
    done = status != "investigating"
    conn.execute(
        """
        INSERT INTO cases (case_id, title, status, severity, created_by,
                           concluded_by, concluded_at, conclusion_reason)
        VALUES (gen_random_uuid(), 't', %s, 'high', %s, %s,
                CASE WHEN %s THEN now() END, CASE WHEN %s THEN 'r' END)
        """,
        (status, creator, creator if done else None, done, done),
    )


def _health(conn: Any, checked_at: datetime, *, ok: bool, checks: list[dict]) -> None:
    conn.execute(
        "INSERT INTO system_health (checked_at, checks, ok) VALUES (%s, %s, %s)",
        (checked_at, Jsonb(checks), ok),
    )


def _get(tc: TestClient, **params: str) -> Any:
    return tc.get(OVERVIEW, params=params)


def _events(conn: Any, event_type: str, subject_id: str | None = None) -> list[tuple]:
    sql = "SELECT actor_role, actor_id, subject_id, payload FROM audit_events WHERE event_type = %s"
    args: list[Any] = [event_type]
    if subject_id is not None:
        sql += " AND subject_id = %s"
        args.append(subject_id)
    return conn.execute(sql + " ORDER BY audit_id", args).fetchall()


def _job_row(conn: Any, job_id: int) -> tuple:
    return conn.execute(
        "SELECT status, attempts, last_error, locked_at, scheduled_at FROM jobs WHERE job_id = %s",
        (job_id,),
    ).fetchone()


# ---------------------------------------------------------------------------
# Shape, defaults, the range parameter
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_empty_database_answers_every_section_with_its_empty_shape(client) -> None:
    tc, _db, _ = client
    resp = _get(tc)
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"range", "errors", *SECTIONS}
    assert body["range"] == "24h"  # the default
    assert body["errors"] == []
    assert body["alerts_by_day"] == []
    assert body["by_source"] == {"rows": [], "rejected": 0}
    assert body["top_agents"] == []
    assert body["funnel"] == {
        "by_status": {},
        "triage": {"ready": 0, "unavailable": 0, "pending": 0, "none": 0},
    }
    assert body["waiting"] == {"count": 0, "oldest_received_at": None}
    assert body["cases_open"] == 0
    assert body["health"] is None
    assert body["failed_jobs"] == []
    assert body["inventory"] == {"assets": 0, "identities": 0, "iocs": 0, "loaded_at": None}
    assert admin_overview.SECTION_TIMEOUT == "3s"


@pytest.mark.db
@pytest.mark.parametrize("value", ["24h", "7d", "30d"])
def test_range_is_echoed(client, value: str) -> None:
    tc, _db, _ = client
    resp = _get(tc, range=value)
    assert resp.status_code == 200
    assert resp.json()["range"] == value


@pytest.mark.db
@pytest.mark.parametrize("value", ["1h", "90d", "24H", "", "month", "7"])
def test_any_other_range_is_422(client, value: str) -> None:
    tc, _db, _ = client
    assert _get(tc, range=value).status_code == 422


# ---------------------------------------------------------------------------
# alerts_by_day
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_alerts_by_day_counts_heads_and_duplicates_and_leaves_out_synthetic(client) -> None:
    tc, db, _ = client
    _alert(db, "head-1")
    _alert(db, "head-2")
    _alert(db, "dup-1", duplicate_of="head-1")
    _alert(db, "dup-2", duplicate_of="head-1")
    _alert(db, "dup-3", duplicate_of="head-2")
    _alert(db, "synthetic-head", is_synthetic=True)
    _alert(db, "synthetic-dup", duplicate_of="synthetic-head", is_synthetic=True)

    days = _get(tc).json()["alerts_by_day"]

    # every row has the same received_at (one transaction's now()), so there is one day
    (today,) = db.execute("SELECT (now() AT TIME ZONE 'Asia/Ho_Chi_Minh')::date").fetchone()
    assert days == [{"day": today.isoformat(), "total": 5, "heads": 2, "duplicates": 3}]


@pytest.mark.db
def test_alerts_by_day_is_ordered_by_day_ascending(client) -> None:
    tc, db, _ = client
    for n in (3, 1, 2):  # 3, 1 and 2 days ago, inserted out of order
        _alert(db, f"day-{n}", received_at=_ago(days=n, hours=1))
        _alert(db, f"day-{n}-b", received_at=_ago(days=n, hours=1))
    days = _get(tc, range="7d").json()["alerts_by_day"]
    assert len(days) == 3
    assert [d["day"] for d in days] == sorted(d["day"] for d in days)
    assert [d["total"] for d in days] == [2, 2, 2]


@pytest.mark.db
def test_alert_day_is_the_day_in_display_tz_at_the_midnight_edge(client) -> None:
    """23:59 and 00:00 local are two days; in UTC they are 16:59 and 17:00, one day."""
    tc, db, _ = client
    day = datetime.now(HCM).date() - timedelta(days=3)
    late = datetime(day.year, day.month, day.day, 23, 59, tzinfo=HCM)
    early = late + timedelta(minutes=1)  # 00:00 of the next local day
    assert early.hour == 0 and early.date() == day + timedelta(days=1)
    _alert(db, "edge-late", received_at=late)
    _alert(db, "edge-early", received_at=early)

    days = _get(tc, range="7d").json()["alerts_by_day"]

    assert days == [
        {"day": day.isoformat(), "total": 1, "heads": 1, "duplicates": 0},
        {"day": (day + timedelta(days=1)).isoformat(), "total": 1, "heads": 1, "duplicates": 0},
    ]


@pytest.mark.db
def test_the_day_follows_the_configured_display_tz(client) -> None:
    """The zone is `cfg.DISPLAY_TZ`, passed as a parameter: with UTC the same two alerts share a day."""
    tc, db, claims = client
    day = datetime.now(HCM).date() - timedelta(days=3)
    late = datetime(day.year, day.month, day.day, 23, 59, tzinfo=HCM)
    _alert(db, "tz-late", received_at=late)
    _alert(db, "tz-early", received_at=late + timedelta(minutes=1))
    _override(db, claims, tz="UTC")

    days = _get(tc, range="7d").json()["alerts_by_day"]

    assert days == [{"day": day.isoformat(), "total": 2, "heads": 2, "duplicates": 0}]


@pytest.mark.db
def test_an_unknown_display_tz_fails_only_that_section(client) -> None:
    """A bad zone name is a database error on one section, not a 500 for the page."""
    tc, db, claims = client
    _alert(db, "tz-bad")
    _override(db, claims, tz="Not/AZone")

    body = _get(tc).json()

    assert body["alerts_by_day"] is None
    assert [e["section"] for e in body["errors"]] == ["alerts_by_day"]
    assert body["by_source"]["rows"] == [{"source": "wazuh", "alerts": 1, "heads": 1}]


# ---------------------------------------------------------------------------
# The range filter
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_the_range_bounds_every_time_filtered_section(client) -> None:
    tc, db, _ = client
    ages = {"a2h": {"hours": 2}, "a3d": {"days": 3}, "a10d": {"days": 10}, "a40d": {"days": 40}}
    agents = {"a2h": "agent-1", "a3d": "agent-2", "a10d": "agent-3", "a40d": "agent-4"}
    for name, age in ages.items():
        _alert(db, name, received_at=_ago(**age), agent_name=agents[name], status="queued_tier1")
        _rejected(db, _ago(**age))

    def view(range_: str) -> tuple[int, int, int, int]:
        body = _get(tc, range=range_).json()
        return (
            sum(d["total"] for d in body["alerts_by_day"]),
            sum(r["alerts"] for r in body["by_source"]["rows"]),
            body["by_source"]["rejected"],
            sum(a["alerts"] for a in body["top_agents"]),
        )

    assert view("24h") == (1, 1, 1, 1)
    assert view("7d") == (2, 2, 2, 2)
    assert view("30d") == (3, 3, 3, 3)  # the 40-day-old alert is in no range
    funnel = _get(tc, range="7d").json()["funnel"]
    assert funnel["by_status"] == {"queued_tier1": 2}


@pytest.mark.db
def test_cases_health_jobs_and_inventory_do_not_depend_on_the_range(client) -> None:
    tc, db, claims = client
    _case(db, claims.user_id)
    _job(db, created_at=_ago(days=90))
    _health(db, _ago(days=90), ok=True, checks=[])
    db.execute(
        "INSERT INTO assets (hostname, criticality, active, loaded_at) VALUES ('h1','low',true,%s)",
        (_ago(days=90),),
    )
    body = _get(tc, range="24h").json()
    assert body["cases_open"] == 1
    assert len(body["failed_jobs"]) == 1
    assert body["health"] is not None
    assert body["inventory"]["assets"] == 1


# ---------------------------------------------------------------------------
# by_source, top_agents, funnel
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_by_source_counts_alerts_heads_and_the_rejected_intake(client) -> None:
    tc, db, _ = client
    _alert(db, "w-1")
    _alert(db, "w-2")
    _alert(db, "w-dup", duplicate_of="w-1")
    _alert(db, "lab-1", source="lab")
    _alert(db, "replay-syn", source="replay", is_synthetic=True)
    _rejected(db)
    _rejected(db)
    _rejected(db, _ago(days=2))  # outside 24h

    by_source = _get(tc).json()["by_source"]

    assert by_source == {
        "rows": [
            {"source": "wazuh", "alerts": 3, "heads": 2},
            {"source": "lab", "alerts": 1, "heads": 1},
        ],
        "rejected": 2,
    }
    assert _get(tc, range="7d").json()["by_source"]["rejected"] == 3


@pytest.mark.db
def test_top_agents_are_five_at_most_most_first_ties_by_name(client) -> None:
    tc, db, _ = client
    plan = {"zed": 5, "alpha": 3, "beta": 3, "gamma": 3, "delta": 2, "epsilon": 2, "zeta": 1}
    for agent, n in plan.items():
        for i in range(n):
            _alert(db, f"{agent}-{i}", agent_name=agent)
    _alert(db, "synthetic", agent_name="zzz-synthetic", is_synthetic=True)

    top = _get(tc).json()["top_agents"]

    assert top == [
        {"agent_name": "zed", "alerts": 5},
        {"agent_name": "alpha", "alerts": 3},
        {"agent_name": "beta", "alerts": 3},
        {"agent_name": "gamma", "alerts": 3},
        {"agent_name": "delta", "alerts": 2},  # delta before epsilon: the tie is by name
    ]


@pytest.mark.db
def test_funnel_counts_heads_by_status_and_by_triage_status(client) -> None:
    tc, db, _ = client
    _alert(db, "q-1", status="queued_tier1", triage_status="ready")
    _alert(db, "q-2", status="queued_tier1", triage_status="ready")
    _alert(db, "q-3", status="queued_tier1", triage_status="unavailable")
    _alert(db, "a-1", status="auto_closed", triage_status="pending")
    _alert(db, "t-1", status="tier1_active", triage_status="pending")
    _alert(db, "d-1", duplicate_of="q-1", triage_status="ready")  # not a head
    _alert(db, "s-1", status="queued_tier1", triage_status="ready", is_synthetic=True)

    funnel = _get(tc).json()["funnel"]

    assert funnel["by_status"] == {"queued_tier1": 3, "auto_closed": 1, "tier1_active": 1}
    assert funnel["triage"] == {"ready": 2, "unavailable": 1, "pending": 2, "none": 0}


# ---------------------------------------------------------------------------
# waiting — the KPI "clusters waiting for Tier 1, with the oldest" (spec §4.1)
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_waiting_counts_queued_tier1_heads_and_the_oldest_received(client) -> None:
    tc, db, _ = client
    oldest = _ago(hours=5)
    _alert(db, "w-old", status="queued_tier1", received_at=oldest)
    _alert(db, "w-mid", status="queued_tier1", received_at=_ago(hours=2))
    _alert(db, "w-new", status="queued_tier1", received_at=_ago(minutes=5))
    _alert(db, "other-1", status="tier1_active", received_at=_ago(days=1))  # not waiting
    _alert(db, "other-2", status="escalated_tier2", received_at=_ago(days=2))
    _alert(db, "other-3", status="auto_closed", received_at=_ago(days=3))
    _alert(db, "syn-q", status="queued_tier1", is_synthetic=True, received_at=_ago(days=4))
    # a row that points at a head is not a cluster, whatever its status says
    _alert(db, "not-a-head", duplicate_of="w-old", received_at=_ago(days=5))
    db.execute(
        "UPDATE alerts SET status = 'queued_tier1', closed_at = NULL, sealed_at = NULL "
        "WHERE alert_id = 'not-a-head'"
    )

    waiting = _get(tc).json()["waiting"]

    assert set(waiting) == {"count", "oldest_received_at"}
    assert waiting["count"] == 3
    assert datetime.fromisoformat(waiting["oldest_received_at"]) == oldest


@pytest.mark.db
def test_nothing_waiting_is_a_zero_count_and_a_null_oldest(client) -> None:
    tc, db, _ = client
    _alert(db, "busy", status="tier1_active")
    body = _get(tc).json()
    assert body["waiting"] == {"count": 0, "oldest_received_at": None}
    assert body["errors"] == []


@pytest.mark.db
def test_waiting_is_what_waits_now_not_what_arrived_in_the_range(client) -> None:
    tc, db, _ = client
    oldest = _ago(days=40)  # outside every range
    _alert(db, "w-ancient", status="queued_tier1", received_at=oldest)
    _alert(db, "w-recent", status="queued_tier1", received_at=_ago(hours=1))

    for range_ in ("24h", "7d", "30d"):
        waiting = _get(tc, range=range_).json()["waiting"]
        assert waiting["count"] == 2, range_
        assert datetime.fromisoformat(waiting["oldest_received_at"]) == oldest, range_
    # the range does bound what the same alerts add to the funnel
    assert _get(tc, range="30d").json()["funnel"]["by_status"] == {"queued_tier1": 1}


# ---------------------------------------------------------------------------
# cases_open, health, failed_jobs, inventory
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_cases_open_counts_only_investigating(client) -> None:
    tc, db, claims = client
    _case(db, claims.user_id)
    _case(db, claims.user_id)
    _case(db, claims.user_id, "concluded_fp")
    _case(db, claims.user_id, "confirmed_incident")

    body = _get(tc).json()

    assert body["cases_open"] == 2
    assert isinstance(body["cases_open"], int)


@pytest.mark.db
def test_health_is_the_newest_row(client) -> None:
    tc, db, _ = client
    old = [{"name": "disk_free", "ok": False}]
    new = [{"name": "disk_free", "ok": True}, {"name": "monthly_cost", "ok": True}]
    newest_at = _ago(minutes=1)
    _health(db, _ago(hours=3), ok=False, checks=old)
    _health(db, newest_at, ok=True, checks=new)
    _health(db, _ago(hours=1), ok=False, checks=old)

    health = _get(tc).json()["health"]

    assert set(health) == {"checked_at", "ok", "checks"}
    assert health["ok"] is True
    assert health["checks"] == new
    assert datetime.fromisoformat(health["checked_at"]) == newest_at


@pytest.mark.db
def test_no_health_row_yet_is_null_not_an_error(client) -> None:
    tc, _db, _ = client
    body = _get(tc).json()
    assert body["health"] is None
    assert body["errors"] == []


@pytest.mark.db
def test_failed_jobs_are_failed_only_newest_first_and_at_most_fifty(client) -> None:
    tc, db, _ = client
    ids = []
    for i in range(51):
        ids.append(_job(db, subject_id=f"s{i:02d}", created_at=_ago(minutes=i + 1)))
    _job(db, subject_id="live-1", status="pending", attempts=0, last_error=None)
    _job(db, subject_id="live-2", status="running", attempts=1, last_error=None)
    _job(db, subject_id="live-3", status="succeeded", attempts=1, last_error=None)

    jobs_out = _get(tc).json()["failed_jobs"]

    assert len(jobs_out) == 50
    assert [j["subject_id"] for j in jobs_out] == [f"s{i:02d}" for i in range(50)]  # s50 is cut
    assert set(jobs_out[0]) == {
        "job_id",
        "job_type",
        "subject_id",
        "attempts",
        "last_error",
        "locked_at",
        "created_at",
    }
    assert jobs_out[0]["job_id"] == ids[0]
    assert jobs_out[0]["job_type"] == "triage"
    assert jobs_out[0]["attempts"] == 3
    assert jobs_out[0]["last_error"] == "boom"
    assert jobs_out[0]["locked_at"] is None


@pytest.mark.db
def test_a_job_that_failed_again_is_listed_by_its_last_attempt_not_its_creation(client) -> None:
    """A retried job keeps its old `created_at`, and `claim_job` stamps `locked_at` on each
    attempt (`finish_job` keeps it): the last attempt is `COALESCE(locked_at, created_at)`. A job
    created ten days ago that failed a minute ago must head the list, not fall off it behind
    fifty newer-created failures."""
    tc, db, _ = client
    for i in range(50):
        _job(db, subject_id=f"newer-{i:02d}", created_at=_ago(hours=i + 1))
    old = _job(
        db,
        subject_id="retried-and-failed-again",
        created_at=_ago(days=10),
        locked_at=_ago(minutes=1),
        last_error="failed again",
    )

    jobs_out = _get(tc).json()["failed_jobs"]

    assert len(jobs_out) == 50
    assert jobs_out[0]["job_id"] == old
    assert jobs_out[0]["subject_id"] == "retried-and-failed-again"
    # the rest follow by their own last attempt (here their creation), newest first
    assert [j["subject_id"] for j in jobs_out[1:4]] == ["newer-00", "newer-01", "newer-02"]
    assert "newer-49" not in {j["subject_id"] for j in jobs_out}  # the oldest last attempt is cut


@pytest.mark.db
def test_failed_job_last_error_is_cut_to_200_characters_and_null_stays_null(client) -> None:
    tc, db, _ = client
    _job(db, subject_id="long", last_error="é" * 450, created_at=_ago(minutes=1))
    _job(db, subject_id="exact", last_error="x" * 200, created_at=_ago(minutes=2))
    _job(db, subject_id="short", last_error="x" * 199, created_at=_ago(minutes=3))
    _job(db, subject_id="none", last_error=None, created_at=_ago(minutes=4))
    locked = _ago(minutes=30)
    _job(db, subject_id="locked", last_error="e", created_at=_ago(minutes=5), locked_at=locked)

    by_subject = {j["subject_id"]: j for j in _get(tc).json()["failed_jobs"]}

    assert by_subject["long"]["last_error"] == "é" * 200  # characters, not bytes
    assert len(by_subject["exact"]["last_error"]) == 200
    assert len(by_subject["short"]["last_error"]) == 199
    assert by_subject["none"]["last_error"] is None
    assert by_subject["locked"]["locked_at"] is not None


@pytest.mark.db
def test_inventory_counts_active_rows_and_reports_the_newest_active_load(client) -> None:
    """`loaded_at` is the newest of the three tables' ACTIVE rows: the inactive asset below
    was loaded later than any of them and must not show."""
    tc, db, _ = client
    assets_at, identities_at, iocs_at = _ago(days=2), _ago(days=1), _ago(hours=5)
    db.execute(
        "INSERT INTO assets (hostname, criticality, active, loaded_at) VALUES "
        "('h-active-1','low',true,%s), ('h-active-2','high',true,%s), ('h-off','low',false,%s)",
        (assets_at, assets_at, _ago(hours=1)),
    )
    db.execute(
        "INSERT INTO identities (username, is_privileged, active, loaded_at) VALUES "
        "('u-active', false, true, %s), ('u-off-1', true, false, %s), ('u-off-2', true, false, %s)",
        (identities_at, identities_at, identities_at),
    )
    db.execute(
        "INSERT INTO iocs (value, source, reputation, expires_at, active, loaded_at) VALUES "
        "('1.2.3.4','feed','malicious', now() + interval '1 day', true, %s), "
        "('5.6.7.8','feed','clean', now() + interval '1 day', true, %s), "
        "('9.9.9.9','feed','clean', now() + interval '1 day', true, %s), "
        "('8.8.8.8','feed','clean', now() + interval '1 day', false, %s)",
        (iocs_at, iocs_at, iocs_at, iocs_at),
    )

    inventory = _get(tc).json()["inventory"]

    assert {k: inventory[k] for k in ("assets", "identities", "iocs")} == {
        "assets": 2,
        "identities": 1,
        "iocs": 3,
    }
    assert datetime.fromisoformat(inventory["loaded_at"]) == iocs_at


@pytest.mark.db
def test_inventory_loaded_at_is_null_when_no_active_row_has_one(client) -> None:
    tc, db, _ = client
    db.execute("INSERT INTO assets (hostname, criticality, active) VALUES ('legacy','low',true)")
    inventory = _get(tc).json()["inventory"]
    assert inventory == {"assets": 1, "identities": 0, "iocs": 0, "loaded_at": None}


# ---------------------------------------------------------------------------
# Each section fails alone
# ---------------------------------------------------------------------------


def _seed_every_section(db: Any, creator: str) -> None:
    _alert(db, "all-1", status="queued_tier1", triage_status="ready")
    _case(db, creator)
    _job(db, subject_id="seed-failed")
    _health(db, _ago(minutes=1), ok=True, checks=[{"name": "disk_free", "ok": True}])
    db.execute("INSERT INTO assets (hostname, criticality, active) VALUES ('seed','low',true)")


def _sql_error(conn: Any) -> None:
    conn.execute("SELECT 1/0")  # a real statement error: the transaction is now aborted


def _driver_error(conn: Any) -> None:
    raise psycopg.OperationalError(
        "connection to server failed: postgresql://app_rw:hunter2@db:5432/soc SELECT secret"
    )


@pytest.mark.db
@pytest.mark.parametrize("fault", [_sql_error, _driver_error], ids=["sql-error", "driver-error"])
@pytest.mark.parametrize("failing", ["top_agents", "waiting", "cases_open"])
def test_a_failing_section_is_null_with_an_error_and_the_others_still_compute(
    client, monkeypatch, failing: str, fault
) -> None:
    tc, db, claims = client
    _seed_every_section(db, claims.user_id)
    monkeypatch.setattr(admin_overview, f"_{failing}", lambda conn, *args: fault(conn))

    resp = _get(tc)

    assert resp.status_code == 200
    body = resp.json()
    assert len(body["errors"]) == 1
    assert body["errors"][0]["section"] == failing
    assert body[failing] is None
    for section in SECTIONS:
        if section != failing:
            assert body[section] is not None, f"{section} was lost with {failing}"
    # the sections AFTER the failing one ran on a usable transaction: real data, not nulls
    assert body["alerts_by_day"][0]["total"] == 1
    assert body["funnel"]["by_status"] == {"queued_tier1": 1}
    if failing != "waiting":
        assert body["waiting"]["count"] == 1
    if failing != "cases_open":
        assert body["cases_open"] == 1
    assert body["failed_jobs"][0]["subject_id"] == "seed-failed"
    assert body["health"]["ok"] is True
    assert body["inventory"]["assets"] == 1
    # the connection is still good for the caller's next statement
    assert db.execute("SELECT 1").fetchone() == (1,)


@pytest.mark.db
def test_the_error_text_is_generic_never_sql_nor_a_dsn(client, monkeypatch) -> None:
    tc, _db, _ = client
    monkeypatch.setattr(admin_overview, "_cases_open", lambda conn, *args: _driver_error(conn))

    body = _get(tc).json()
    text = str(body["errors"])

    for leaked in ("SELECT", "hunter2", "postgresql://", "app_rw", "5432"):
        assert leaked not in text
    assert body["errors"] == [{"section": "cases_open", "error": "query_failed"}]


@pytest.mark.db
def test_a_section_past_its_statement_timeout_is_reported_as_a_timeout(client, monkeypatch) -> None:
    tc, db, claims = client
    _seed_every_section(db, claims.user_id)
    monkeypatch.setattr(admin_overview, "SECTION_TIMEOUT", "50ms")
    monkeypatch.setattr(
        admin_overview, "_cases_open", lambda conn, *args: conn.execute("SELECT pg_sleep(5)")
    )

    body = _get(tc).json()

    assert body["errors"] == [{"section": "cases_open", "error": "timeout"}]
    assert body["cases_open"] is None
    assert body["failed_jobs"][0]["subject_id"] == "seed-failed"
    assert body["inventory"]["assets"] == 1


class _CountingConnection:
    """Forwards `execute` to a real connection and counts the statements."""

    def __init__(self, conn: Any) -> None:
        self._conn = conn
        self.statements = 0

    def execute(self, *args: Any, **kwargs: Any) -> Any:
        self.statements += 1
        return self._conn.execute(*args, **kwargs)


_DAY = timedelta(hours=24)


@pytest.mark.db
@pytest.mark.parametrize(
    "name, args, statements",
    [
        ("_alerts_by_day", ("UTC", _DAY), 1),
        ("_by_source", (_DAY,), 2),  # alerts, then rejected_alerts
        ("_top_agents", (_DAY,), 1),
        ("_funnel", (_DAY,), 1),
        ("_waiting", (), 1),
        ("_cases_open", (), 1),
        ("_health", (), 1),
        ("_failed_jobs", (), 1),
        ("_inventory", (), 1),
    ],
)
def test_a_section_runs_one_statement_except_by_source(sdb, name, args, statements) -> None:
    """`SECTION_TIMEOUT` is a limit per statement, not per section. The module says so and
    names `by_source` as the one section that runs two; this pins both halves of that sentence."""
    counting = _CountingConnection(sdb)
    getattr(admin_overview, name)(counting, *args)
    assert counting.statements == statements


@pytest.mark.db
def test_several_sections_can_fail_in_one_response(client, monkeypatch) -> None:
    tc, _db, _ = client
    for name in ("_by_source", "_funnel", "_failed_jobs"):
        monkeypatch.setattr(admin_overview, name, lambda conn, *args: _sql_error(conn))

    body = _get(tc).json()

    assert [e["section"] for e in body["errors"]] == ["by_source", "funnel", "failed_jobs"]
    assert body["by_source"] is None and body["funnel"] is None and body["failed_jobs"] is None
    assert body["alerts_by_day"] == [] and body["cases_open"] == 0 and body["health"] is None


# ---------------------------------------------------------------------------
# POST /api/admin/jobs/{job_id}/retry
# ---------------------------------------------------------------------------


def _retry(tc: TestClient, job_id: Any) -> Any:
    return tc.post(f"/api/admin/jobs/{job_id}/retry")


@pytest.mark.db
def test_retry_puts_a_failed_job_back_to_pending_and_writes_the_event(client) -> None:
    tc, db, claims = client
    job_id = _job(
        db,
        job_type="triage",
        subject_id="alert-retry",
        attempts=3,
        last_error="x" * 450,
        locked_at=_ago(hours=1),
    )
    db.execute(
        "UPDATE jobs SET scheduled_at = now() + interval '1 day' WHERE job_id = %s", (job_id,)
    )
    (now,) = db.execute("SELECT now()").fetchone()  # one transaction: the route's now() is this

    resp = _retry(tc, job_id)

    assert resp.status_code == 200
    assert resp.json() == {"job_id": job_id, "status": "pending"}
    status, attempts, last_error, locked_at, scheduled_at = _job_row(db, job_id)
    assert (status, attempts, locked_at) == ("pending", 0, None)
    assert last_error == "x" * 450  # kept: it says why the job failed last time
    assert scheduled_at == now  # reset from a day ahead to now: the worker may claim it
    ((actor_role, actor_id, subject_id, payload),) = _events(db, "admin.job_retried", str(job_id))
    assert actor_role == "admin" and str(actor_id) == claims.user_id
    assert subject_id == str(job_id)
    assert payload == {
        "job_id": job_id,
        "job_type": "triage",
        "subject_id": "alert-retry",
        "attempts_before": 3,
        "last_error": "x" * 200,  # the event is cut; the row is not
    }


@pytest.mark.db
def test_a_null_last_error_stays_null_in_the_event(client) -> None:
    tc, db, _ = client
    job_id = _job(db, last_error=None)
    assert _retry(tc, job_id).status_code == 200
    ((_, _, _, payload),) = _events(db, "admin.job_retried", str(job_id))
    assert payload["last_error"] is None


@pytest.mark.db
def test_the_worker_claims_a_retried_job_again(client) -> None:
    """`claim_job` takes `pending AND scheduled_at <= now()` of a matching type: the retry makes both true."""
    tc, db, _ = client
    job_id = _job(db, job_type="investigate", subject_id="case-1", attempts=3, last_error="timeout")
    # a job that was due only in the future would NOT be claimed: the retry must reset it
    db.execute(
        "UPDATE jobs SET scheduled_at = now() + interval '1 day' WHERE job_id = %s", (job_id,)
    )

    assert _retry(tc, job_id).status_code == 200
    claimed = jobs.claim_job(db, ["investigate"])

    assert claimed is not None
    assert (claimed.job_id, claimed.subject_id) == (job_id, "case-1")
    assert claimed.attempts == 1  # attempts started again from 0


@pytest.mark.db
@pytest.mark.parametrize("status", ["pending", "running", "succeeded"])
def test_retry_of_a_job_that_is_not_failed_is_409_not_failed(client, status: str) -> None:
    tc, db, _ = client
    job_id = _job(db, status=status, attempts=1, last_error=None)
    before = _job_row(db, job_id)

    resp = _retry(tc, job_id)

    assert resp.status_code == 409
    assert resp.json() == {"detail": {"reason": "not_failed"}}
    assert _job_row(db, job_id) == before
    assert _events(db, "admin.job_retried", str(job_id)) == []


@pytest.mark.db
@pytest.mark.parametrize("live", ["pending", "running"])
def test_retry_while_a_sibling_is_live_is_409_already_queued_and_changes_nothing(
    client, live: str
) -> None:
    tc, db, _ = client
    failed = _job(db, job_type="triage", subject_id="alert-sib", last_error="old failure")
    _job(db, job_type="triage", subject_id="alert-sib", status=live, attempts=0, last_error=None)
    before = _job_row(db, failed)

    resp = _retry(tc, failed)  # TestClient re-raises a server exception: a 500 would fail here

    assert resp.status_code == 409
    assert resp.json() == {"detail": {"reason": "already_queued"}}
    assert _job_row(db, failed) == before
    assert before[0] == "failed"
    assert _events(db, "admin.job_retried", str(failed)) == []


@pytest.mark.db
def test_a_sibling_of_another_type_or_subject_does_not_block_the_retry(client) -> None:
    tc, db, _ = client
    failed = _job(db, job_type="triage", subject_id="alert-x")
    _job(db, job_type="pipeline", subject_id="alert-x", status="pending", last_error=None)
    _job(db, job_type="triage", subject_id="alert-y", status="running", last_error=None)
    _job(db, job_type="triage", subject_id="alert-x", status="succeeded", last_error=None)
    _job(db, job_type="triage", subject_id="alert-x", status="failed")  # another failed one

    assert _retry(tc, failed).status_code == 200
    assert _job_row(db, failed)[0] == "pending"


@pytest.mark.db
def test_a_sibling_that_appears_after_the_check_is_409_not_a_500(client, monkeypatch) -> None:
    """The race: the sibling is enqueued between the check and the UPDATE. The unique index
    refuses the UPDATE; the route turns that into 409 on a savepoint, so the request's own
    transaction is still usable and the job is unchanged."""
    tc, db, _ = client
    failed = _job(db, job_type="triage", subject_id="alert-race", last_error="old failure")
    _job(db, job_type="triage", subject_id="alert-race", status="pending", last_error=None)
    before = _job_row(db, failed)
    monkeypatch.setattr(admin_overview, "_has_live_sibling", lambda *args: False)

    resp = _retry(tc, failed)

    assert resp.status_code == 409
    assert resp.json() == {"detail": {"reason": "already_queued"}}
    assert _job_row(db, failed) == before  # the same connection reads on: not aborted
    assert _events(db, "admin.job_retried", str(failed)) == []


@pytest.mark.db
def test_retry_of_an_unknown_job_is_404(client) -> None:
    tc, db, _ = client
    for job_id in (987654321, 2**63 - 1):  # the largest bigint is still a plain 404
        resp = _retry(tc, job_id)
        assert resp.status_code == 404
        assert resp.json() == {"detail": {"reason": "not_found"}}
        # by subject: the concurrency tests below commit `admin.job_retried` rows of their own
        assert _events(db, "admin.job_retried", str(job_id)) == []


@pytest.mark.db
@pytest.mark.parametrize("bad", ["abc", "0", "-1", "1.5", "99999999999999999999", "1e3"])
def test_a_malformed_job_id_is_422_before_any_sql(client, bad: str) -> None:
    tc, _db, _ = client
    assert _retry(tc, bad).status_code == 422


@pytest.mark.db
def test_a_second_retry_of_the_same_job_is_409_not_failed(client) -> None:
    tc, db, _ = client
    job_id = _job(db)
    assert _retry(tc, job_id).status_code == 200
    again = _retry(tc, job_id)
    assert again.status_code == 409
    assert again.json() == {"detail": {"reason": "not_failed"}}
    assert len(_events(db, "admin.job_retried", str(job_id))) == 1


# ---------------------------------------------------------------------------
# Retry under concurrency — COMMITTED data, a request on its own connection in a thread,
# and a second connection that holds an uncommitted write the request has to wait for
# ---------------------------------------------------------------------------


def _wait_for_a_backend_blocked_on_a_lock(dsn: Any, timeout: float = 10.0) -> None:
    """Poll `pg_stat_activity` (autocommit: a fresh snapshot each time) until one backend of
    this database waits for a lock: the request is then parked behind the other connection."""
    deadline = time.monotonic() + timeout
    with psycopg.connect(dsn, autocommit=True) as watcher:
        while time.monotonic() < deadline:
            (waiting,) = watcher.execute(
                "SELECT count(*) FROM pg_stat_activity "
                "WHERE wait_event_type = 'Lock' AND datname = current_database()"
            ).fetchone()
            if waiting:
                return
            time.sleep(0.02)
    raise AssertionError("the retry request never blocked on the other connection's lock")


def _retry_in_a_thread(
    dsn: Any, job_id: int, start: threading.Barrier | None = None
) -> tuple[threading.Thread, dict[str, Any]]:
    """`POST .../retry` as an admin on a connection of its own (committed on success, rolled
    back on error, exactly as `deps.get_conn` does it). `out` gets the `response`, or the
    `error` an unhandled server exception raised. With `start`, the thread waits on that
    barrier first, so several of them post at the same moment."""
    claims = Claims(user_id=str(uuid.uuid4()), username="a", role="admin", iat=0.0, exp=0.0)
    cfg = config.load()

    def own_connection():
        conn = psycopg.connect(dsn)
        try:
            yield conn
        except BaseException:
            conn.rollback()
            raise
        else:
            conn.commit()
        finally:
            conn.close()

    main.app.dependency_overrides[deps.get_conn] = own_connection
    main.app.dependency_overrides[deps.current_user] = lambda: claims
    main.app.dependency_overrides[deps.get_config] = lambda: cfg
    out: dict[str, Any] = {}

    def run() -> None:
        try:
            if start is not None:
                start.wait(timeout=10)
            out["response"] = TestClient(main.app).post(f"/api/admin/jobs/{job_id}/retry")
        except Exception as exc:  # noqa: BLE001 - the test reports whatever the app raised
            out["error"] = exc

    thread = threading.Thread(target=run)
    thread.start()
    return thread, out


@pytest.mark.db
def test_two_retries_of_one_job_cannot_both_pass_the_for_update_lock(scratch_dsn) -> None:
    """Another admin's retry is mid-flight (its UPDATE is not committed yet). This request
    must wait on the job row, then see `pending` and answer 409 `not_failed`: without
    `FOR UPDATE` it would read the stale `failed` row, retry it a second time and write a
    second `admin.job_retried`."""
    with psycopg.connect(scratch_dsn, autocommit=True) as setup:
        job_id = _job(setup, subject_id="alert-lock", last_error="old failure")
    holder = psycopg.connect(scratch_dsn)
    try:
        holder.execute(
            "UPDATE jobs SET status = 'pending', attempts = 0 WHERE job_id = %s", (job_id,)
        )
        thread, out = _retry_in_a_thread(scratch_dsn, job_id)
        try:
            _wait_for_a_backend_blocked_on_a_lock(scratch_dsn)
        finally:
            holder.commit()  # the other admin's retry lands; the request may go on
            thread.join(timeout=15)
        assert not thread.is_alive()
        assert "error" not in out, out.get("error")
        assert out["response"].status_code == 409
        assert out["response"].json() == {"detail": {"reason": "not_failed"}}
        with psycopg.connect(scratch_dsn, autocommit=True) as check:
            assert _events(check, "admin.job_retried", str(job_id)) == []
            assert _job_row(check, job_id)[:2] == ("pending", 0)
    finally:
        _clear_overrides()
        holder.close()
        with psycopg.connect(scratch_dsn, autocommit=True) as cleanup:
            cleanup.execute("DELETE FROM jobs WHERE job_id = %s", (job_id,))


@pytest.mark.db
def test_two_simultaneous_retries_give_one_200_and_one_409_and_never_a_deadlock(
    scratch_dsn, monkeypatch
) -> None:
    """Two admins press "Chạy lại" on the same failed job at the same moment, each request on
    its own committed connection and started by a barrier. The lock must be exclusive:
    `FOR UPDATE` parks the second request on the row until the first commits, and it then reads
    `pending` and answers 409 `not_failed`. A weaker lock (`FOR SHARE`) lets both read `failed`;
    both UPDATEs then wait on each other's share lock and PostgreSQL aborts one with
    `DeadlockDetected`, a 500.

    To make the weaker lock fail every time rather than when the scheduler is kind, the sibling
    check, which runs after the read and before the UPDATE, waits (up to 2 s) for the other
    request to arrive. Under `FOR UPDATE` the other request is parked on the row and never
    arrives, so the wait ends by itself and costs two seconds; under `FOR SHARE` both arrive.
    The one `admin.job_retried` row it commits cannot be deleted (`audit_events` is
    append-only): the module's scratch database is dropped at the end."""
    with psycopg.connect(scratch_dsn, autocommit=True) as setup:
        job_id = _job(setup, subject_id="alert-simultaneous", last_error="old failure")
    real_check = admin_overview._has_live_sibling
    meeting = threading.Barrier(2)

    def wait_for_the_other_request_then_check(*args: Any) -> bool:
        try:
            meeting.wait(timeout=2)
        except threading.BrokenBarrierError:
            pass
        return real_check(*args)

    monkeypatch.setattr(admin_overview, "_has_live_sibling", wait_for_the_other_request_then_check)
    start = threading.Barrier(2)
    try:
        first, out_first = _retry_in_a_thread(scratch_dsn, job_id, start)
        second, out_second = _retry_in_a_thread(scratch_dsn, job_id, start)
        first.join(timeout=30)
        second.join(timeout=30)
        assert not first.is_alive() and not second.is_alive()
        outs = [out_first, out_second]
        assert [o["error"] for o in outs if "error" in o] == []  # no DeadlockDetected, no 500
        assert sorted(o["response"].status_code for o in outs) == [200, 409]
        loser = next(o["response"] for o in outs if o["response"].status_code == 409)
        assert loser.json() == {"detail": {"reason": "not_failed"}}
        with psycopg.connect(scratch_dsn, autocommit=True) as check:
            assert len(_events(check, "admin.job_retried", str(job_id))) == 1
            assert _job_row(check, job_id)[:2] == ("pending", 0)
    finally:
        _clear_overrides()
        with psycopg.connect(scratch_dsn, autocommit=True) as cleanup:
            cleanup.execute("DELETE FROM jobs WHERE job_id = %s", (job_id,))


@pytest.mark.db
def test_a_sibling_enqueued_between_the_check_and_the_update_is_409_not_a_500(scratch_dsn) -> None:
    """The real race, not a stub of it: `enqueue` has inserted the sibling but not committed,
    so the sibling check cannot see it; the UPDATE waits on the unique index, and when the
    sibling commits the index refuses it. The route turns that into a 409."""
    with psycopg.connect(scratch_dsn, autocommit=True) as setup:
        failed = _job(setup, job_type="triage", subject_id="alert-race-real", last_error="old")
    holder = psycopg.connect(scratch_dsn)
    sibling = None
    try:
        sibling = _job(holder, job_type="triage", subject_id="alert-race-real", status="pending")
        thread, out = _retry_in_a_thread(scratch_dsn, failed)
        try:
            _wait_for_a_backend_blocked_on_a_lock(scratch_dsn)
        finally:
            holder.commit()  # the sibling is now live; the parked UPDATE is refused
            thread.join(timeout=15)
        assert not thread.is_alive()
        assert "error" not in out, out.get("error")
        assert out["response"].status_code == 409
        assert out["response"].json() == {"detail": {"reason": "already_queued"}}
        with psycopg.connect(scratch_dsn, autocommit=True) as check:
            assert _job_row(check, failed)[:3] == ("failed", 3, "old")
            assert _events(check, "admin.job_retried", str(failed)) == []
    finally:
        _clear_overrides()
        holder.close()
        with psycopg.connect(scratch_dsn, autocommit=True) as cleanup:
            cleanup.execute(
                "DELETE FROM jobs WHERE job_id = ANY(%s)", ([failed, sibling or failed],)
            )


# ---------------------------------------------------------------------------
# Admin only
# ---------------------------------------------------------------------------


def test_the_module_mounts_exactly_two_routes_and_each_carries_the_admin_dependency() -> None:
    paths = main.app.openapi()["paths"]
    assert "get" in paths["/api/admin/overview"]
    assert "post" in paths["/api/admin/jobs/{job_id}/retry"]
    routes = {
        (method, route.path) for route in admin_overview.router.routes for method in route.methods
    }
    assert routes == {("GET", "/api/admin/overview"), ("POST", "/api/admin/jobs/{job_id}/retry")}
    for route in admin_overview.router.routes:
        calls = [d.call for d in route.dependant.dependencies]
        assert admin_overview.require_admin in calls, route.path


def _tier1() -> Claims:
    return Claims(user_id=str(uuid.uuid4()), username="t1", role="tier1", iat=0.0, exp=0.0)


@pytest.mark.db
def test_overview_is_403_for_tier1_and_writes_authz_denied(sdb) -> None:
    tier1 = _tier1()
    _override(sdb, tier1)
    try:
        resp = TestClient(main.app).get(OVERVIEW)
    finally:
        _clear_overrides()
    assert resp.status_code == 403
    ((_, actor_id, subject_id, payload),) = _events(sdb, "authz.denied", OVERVIEW)
    assert str(actor_id) == tier1.user_id and subject_id == OVERVIEW
    assert payload["required"] == ["admin"] and payload["role"] == "tier1"
    assert payload["method"] == "GET"


@pytest.mark.db
def test_retry_is_403_for_tier1_writes_authz_denied_and_touches_no_job(sdb) -> None:
    """`require_role` COMMITS the denial, and that commit takes the job inserted here with it:
    the job is deleted again below so the module's other tests still see an empty `jobs`."""
    tier1 = _tier1()
    job_id = _job(sdb, subject_id="alert-403")
    path = f"/api/admin/jobs/{job_id}/retry"
    _override(sdb, tier1)
    try:
        resp = TestClient(main.app).post(path)
        after = _job_row(sdb, job_id)
    finally:
        _clear_overrides()
        sdb.rollback()
        sdb.execute("DELETE FROM jobs WHERE job_id = %s", (job_id,))
        sdb.commit()
    assert resp.status_code == 403
    assert after[0] == "failed" and after[1] == 3
    ((_, actor_id, subject_id, payload),) = _events(sdb, "authz.denied", path)
    assert str(actor_id) == tier1.user_id and subject_id == path
    assert payload["required"] == ["admin"] and payload["method"] == "POST"
    assert _events(sdb, "admin.job_retried", str(job_id)) == []


@pytest.mark.db
def test_a_tier1_user_with_a_malformed_job_id_is_still_403(sdb) -> None:
    """The role check answers first, whatever the id (`deps.clean_path_id`'s own rule)."""
    _override(sdb, _tier1())
    try:
        resp = TestClient(main.app).post("/api/admin/jobs/not-a-number/retry")
    finally:
        _clear_overrides()
    assert resp.status_code == 403
