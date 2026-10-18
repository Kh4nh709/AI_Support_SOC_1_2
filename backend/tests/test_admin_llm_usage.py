"""P11-T04 — `GET /api/admin/llm/usage?range=24h|7d|30d|month` (`web/routers/admin_llm.py`, spec
§4.3 and §5.3, decisions 4 and 5).

Every test runs the real app through `TestClient(main.app)`, with `deps.get_conn` overridden to
this module's own connection and `deps.current_user` / `deps.get_config` to fixed values (the
shape of `test_admin_overview.py` and `test_admin_llm_limits.py`).

The database is a scratch database this module builds and drops (`tests/scratch_db.py`), not the
shared `db` fixture: the usage page sums whole tables (`llm_runs` is append-only, so a row
another test file had committed would stay and move every total), and an exact assertion needs
a database nobody else has written to. Each test rolls its connection back at the end; nothing a
test seeds, renames or drops reaches the next one. The 403 tests spy on `commit` instead of
committing, so they leave nothing behind either.

`now()` is the TRANSACTION's start, so inside one test it does not move: the request and the
seeds see the same instant. Seeds are `now() - <interval>`; a test that depends on the calendar
month asks the database where the month starts instead of assuming the day it runs.
"""

from __future__ import annotations

import dataclasses
import json
import uuid
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

import psycopg
import pytest
from app.audit import llm_runs
from app.infra import config
from app.infra.auth import Claims
from app.web import deps, main
from app.web.routers import admin_llm, tier2_runs
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from tests.scratch_db import scratch_database

pytestmark = pytest.mark.db

USAGE = "/api/admin/llm/usage"
RANGES = ("24h", "7d", "30d", "month")
_CFG = dataclasses.replace(
    config.Config(), LLM_MONTHLY_USD_CAP=30, ANALYZE_QUOTA_PER_USER_DAY=25, LLM_TIMEOUT_S=120
)

#: Columns and key names that must never leave the server on this route (spec §5.3, §6).
_FORBIDDEN_KEYS = frozenset(
    {
        "system_prompt",
        "user_message",
        "agent_trace",
        "injection_findings",
        "citation_warnings",
        "result",
        "gate_result",
        "verifier_result",
        "evidence_check",
    }
)


# ---------------------------------------------------------------------------
# The scratch database and the client
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def scratch_dsn():
    with scratch_database("llm_usage") as dsn:
        yield dsn


@pytest.fixture
def sdb(scratch_dsn):
    conn = psycopg.connect(scratch_dsn)
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


class _Client:
    def __init__(self, conn: psycopg.Connection, user_id: str, username: str) -> None:
        self.http = TestClient(main.app, follow_redirects=False)
        self.conn = conn
        self.user_id = user_id
        self.username = username
        self.role = "admin"

    def claims(self) -> Claims:
        return Claims(
            user_id=self.user_id, username=self.username, role=self.role, iat=0.0, exp=0.0
        )

    def get(self, range_: str | None = None):
        params = {} if range_ is None else {"range": range_}
        return self.http.get(USAGE, params=params)

    def ok(self, range_: str | None = None) -> dict[str, Any]:
        resp = self.get(range_)
        assert resp.status_code == 200, resp.text
        return resp.json()


def _user(conn: psycopg.Connection, display_name: str, role: str = "tier2") -> tuple[str, str]:
    user_id = str(uuid.uuid4())
    username = f"t04-{user_id[:8]}"
    conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash) "
        "VALUES (%s, %s, %s, %s, 'x')",
        (user_id, username, display_name, role),
    )
    return user_id, username


@pytest.fixture
def client(sdb):
    user_id, username = _user(sdb, "Quản trị viên", role="admin")
    c = _Client(sdb, user_id, username)
    main.app.dependency_overrides[deps.get_conn] = lambda: sdb
    main.app.dependency_overrides[deps.get_config] = lambda: _CFG
    main.app.dependency_overrides[deps.current_user] = c.claims
    try:
        yield c
    finally:
        for dep in (deps.get_conn, deps.get_config, deps.current_user):
            main.app.dependency_overrides.pop(dep, None)


# ---------------------------------------------------------------------------
# Factories — plain SQL
# ---------------------------------------------------------------------------


def _json(value: Any) -> Jsonb | None:
    return None if value is None else Jsonb(value)


def _run(
    conn: psycopg.Connection,
    *,
    pipeline: str = "triage",
    role: str | None = "proposer",
    ago: timedelta = timedelta(0),
    at: str | None = None,
    result: Any = None,
    stopped_by: str | None = None,
    cost: str | None = None,
    tokens: tuple[int | None, int | None] = (None, None),
    latency: int | None = None,
    subject_id: str | None = None,
    system_prompt: str = "system",
    user_message: str = "user",
    agent_trace: Any = None,
    injection_findings: Any = None,
    citation_warnings: Any = None,
    gate_result: Any = None,
    verifier_result: Any = None,
    evidence_check: Any = None,
) -> str:
    """One `llm_runs` row at `now() - ago`, or at the SQL expression `at`. Returns its run_id."""
    run_id = str(uuid.uuid4())
    created_at = at if at is not None else "now() - %(ago)s"
    conn.execute(
        f"""
        INSERT INTO llm_runs (
            run_id, pipeline, subject_type, subject_id, role, system_prompt, user_message,
            agent_trace, result, injection_findings, citation_warnings, gate_result,
            verifier_result, evidence_check, input_tokens, output_tokens, latency_ms,
            cost_usd, stopped_by, created_at)
        VALUES (
            %(run_id)s, %(pipeline)s, %(subject_type)s, %(subject_id)s, %(role)s,
            %(system_prompt)s, %(user_message)s, %(agent_trace)s, %(result)s,
            %(injection_findings)s, %(citation_warnings)s, %(gate_result)s,
            %(verifier_result)s, %(evidence_check)s, %(tin)s, %(tout)s, %(latency)s,
            %(cost)s, %(stopped_by)s, {created_at})
        """,
        {
            "run_id": run_id,
            "pipeline": pipeline,
            "subject_type": "alert" if pipeline == "triage" else "case",
            "subject_id": subject_id or f"s-{run_id[:8]}",
            "role": role,
            "system_prompt": system_prompt,
            "user_message": user_message,
            "agent_trace": _json(agent_trace),
            "result": _json(result),
            "injection_findings": _json(injection_findings),
            "citation_warnings": _json(citation_warnings),
            "gate_result": _json(gate_result),
            "verifier_result": _json(verifier_result),
            "evidence_check": _json(evidence_check),
            "tin": tokens[0],
            "tout": tokens[1],
            "latency": latency,
            "cost": Decimal(cost) if cost is not None else None,
            "stopped_by": stopped_by,
            "ago": ago,
        },
    )
    return run_id


def _analyzed(
    conn: psycopg.Connection, actor_id: str, ago: timedelta, event_type: str = "case.analyzed"
) -> None:
    """One audit row at `now() - ago` (the shared writer cannot backdate `created_at`)."""
    conn.execute(
        "INSERT INTO audit_events (event_type, subject_id, actor_id, actor_role, payload, "
        "created_at) VALUES (%s, %s, %s, 'analyst', '{}'::jsonb, now() - %s)",
        (event_type, str(uuid.uuid4()), actor_id, ago),
    )


def _now_and_month(conn: psycopg.Connection) -> tuple[datetime, datetime, datetime]:
    """The database's `now()`, the start of its calendar month and of the next one."""
    return conn.execute(
        "SELECT now(), date_trunc('month', now()), date_trunc('month', now()) + interval '1 month'"
    ).fetchone()


def _by_key(body: dict[str, Any]) -> dict[tuple[str, str | None], dict[str, Any]]:
    return {(r["pipeline"], r["role"]): r for r in body["by_pipeline_role"]}


def _keys(node: Any) -> set[str]:
    """Every dict key anywhere in a JSON value."""
    if isinstance(node, dict):
        return set(node) | {k for v in node.values() for k in _keys(v)}
    if isinstance(node, list):
        return {k for v in node for k in _keys(v)}
    return set()


# ---------------------------------------------------------------------------
# Admin only, and the parameter
# ---------------------------------------------------------------------------


def test_the_usage_route_is_a_get_of_the_module_and_carries_the_admin_dependency():
    routes = [r for r in admin_llm.router.routes if getattr(r, "path", "") == USAGE]
    assert len(routes) == 1
    (route,) = routes
    assert route.methods == {"GET"}
    assert admin_llm.require_admin in {d.call for d in route.dependant.dependencies}


@pytest.mark.parametrize("role", ["tier1", "tier2"])
def test_a_non_admin_gets_403_and_authz_denied_is_written(client, sdb, monkeypatch, role):
    client.role = role
    seen_at_commit: list[list[str]] = []

    def _spy_commit() -> None:
        rows = sdb.execute(
            "SELECT event_type FROM audit_events WHERE actor_id = %s ORDER BY audit_id",
            (client.user_id,),
        ).fetchall()
        seen_at_commit.append([r[0] for r in rows])

    monkeypatch.setattr(sdb, "commit", _spy_commit)

    resp = client.get()

    assert resp.status_code == 403
    assert seen_at_commit == [["authz.denied"]]
    assert "by_pipeline_role" not in resp.text  # a refusal carries no usage


def test_no_range_means_month(client):
    assert client.ok()["range"] == "month"


@pytest.mark.parametrize("range_", RANGES)
def test_each_range_is_echoed(client, range_):
    assert client.ok(range_)["range"] == range_


@pytest.mark.parametrize("range_", ["1h", "week", "", "MONTH", "24H", "all", "7", "30d "])
def test_any_other_range_is_422(client, range_):
    assert client.get(range_).status_code == 422


# ---------------------------------------------------------------------------
# by_pipeline_role
# ---------------------------------------------------------------------------


def _seed_matrix(conn: psycopg.Connection) -> None:
    """Four `(pipeline, role)` groups, all inside the last 24 hours."""
    # ① proposer: five runs, latencies 100..500 (p50 300, p95 480), the last stopped by `schema`
    # with its usage written, as `triage.py` does
    for i, (latency, cost, stopped) in enumerate(
        [
            (100, "0.10000", None),
            (200, "0.20000", None),
            (300, "0.30000", None),
            (400, "0.40000", None),
            (500, "0.50000", "schema"),
        ]
    ):
        _run(
            conn,
            pipeline="triage",
            role="proposer",
            ago=timedelta(hours=1 + i),
            result=None if stopped else {"suggested_action": "needs_review"},
            stopped_by=stopped,
            cost=cost,
            tokens=(1000 * (i + 1), 100 * (i + 1)),
            latency=latency,
        )
    # ① verifier: four runs (p50 25, p95 47), none stopped
    for i, latency in enumerate([10, 20, 30, 50]):
        _run(
            conn,
            pipeline="triage",
            role="verifier",
            ago=timedelta(hours=1 + i),
            result={"agree": True, "structured_only_verdict": "needs_review", "reason": "r"},
            cost="0.01000",
            tokens=(50, 5),
            latency=latency,
        )
    # ② investigator: three runs; one stopped by the cap, with no tokens, latency or cost
    _run(
        conn,
        pipeline="investigate",
        role="investigator",
        ago=timedelta(hours=2),
        result={"suggested_conclusion": "false_positive"},
        cost="2.00000",
        tokens=(4000, 800),
        latency=1000,
    )
    _run(
        conn,
        pipeline="investigate",
        role="investigator",
        ago=timedelta(hours=3),
        result={"suggested_conclusion": "need_more_data"},
        cost="3.50000",
        tokens=(6000, 900),
        latency=3000,
    )
    _run(
        conn,
        pipeline="investigate",
        role="investigator",
        ago=timedelta(hours=4),
        result=None,
        stopped_by="cap",
    )
    # a v1 row with no role at all, stopped in transit
    _run(
        conn,
        pipeline="triage",
        role=None,
        ago=timedelta(hours=5),
        result=None,
        stopped_by="transient",
    )


def test_the_matrix_counts_with_result_stopped_percentiles_tokens_and_cost(client):
    _seed_matrix(client.conn)

    body = client.ok("24h")

    rows = body["by_pipeline_role"]
    # ordered by pipeline, then role (a NULL role last)
    assert [(r["pipeline"], r["role"]) for r in rows] == [
        ("investigate", "investigator"),
        ("triage", "proposer"),
        ("triage", "verifier"),
        ("triage", None),
    ]
    by = _by_key(body)
    assert by[("triage", "proposer")] == {
        "pipeline": "triage",
        "role": "proposer",
        "calls": 5,
        "with_result": 4,
        "stopped": {"schema": 1},
        "input_tokens": 15000,
        "output_tokens": 1500,
        "latency_p50_ms": 300,
        "latency_p95_ms": 480,
        "cost_usd": 1.5,
    }
    assert by[("triage", "verifier")] == {
        "pipeline": "triage",
        "role": "verifier",
        "calls": 4,
        "with_result": 4,
        "stopped": {},
        "input_tokens": 200,
        "output_tokens": 20,
        "latency_p50_ms": 25,
        "latency_p95_ms": 47,
        "cost_usd": 0.04,
    }
    # the NULL latency of the capped run is skipped by the percentile, not counted as 0
    assert by[("investigate", "investigator")] == {
        "pipeline": "investigate",
        "role": "investigator",
        "calls": 3,
        "with_result": 2,
        "stopped": {"cap": 1},
        "input_tokens": 10000,
        "output_tokens": 1700,
        "latency_p50_ms": 2000,
        "latency_p95_ms": 2900,
        "cost_usd": 5.5,
    }
    assert by[("triage", None)] == {
        "pipeline": "triage",
        "role": None,
        "calls": 1,
        "with_result": 0,
        "stopped": {"transient": 1},
        "input_tokens": 0,
        "output_tokens": 0,
        "latency_p50_ms": None,
        "latency_p95_ms": None,
        "cost_usd": 0.0,
    }


def test_the_percentiles_are_integers(client):
    _seed_matrix(client.conn)

    for row in client.ok("24h")["by_pipeline_role"]:
        for key in ("latency_p50_ms", "latency_p95_ms"):
            assert row[key] is None or type(row[key]) is int, (row["role"], key)


def test_stopped_counts_every_reason_and_leaves_out_the_null_ones(client):
    conn = client.conn
    for reason in ("cap", "cap", "linter", None):
        _run(
            conn,
            role="proposer",
            ago=timedelta(hours=1),
            stopped_by=reason,
            result=None if reason else {"suggested_action": "escalate"},
        )

    row = _by_key(client.ok("24h"))[("triage", "proposer")]

    assert row["calls"] == 4
    assert row["with_result"] == 1
    assert row["stopped"] == {"cap": 2, "linter": 1}


def test_there_is_no_chat_row_and_no_tool_calls(client):
    _seed_matrix(client.conn)

    body = client.ok("24h")

    assert {r["pipeline"] for r in body["by_pipeline_role"]} <= {"triage", "investigate"}
    assert body["tool_calls"] == 0


def test_a_database_with_no_runs_answers_empty_blocks_not_an_error(client):
    body = client.ok("24h")

    assert body["by_pipeline_role"] == []
    assert body["recent"] == []
    assert body["month"]["spent_usd"] == 0.0
    assert body["month"]["projected_usd"] == 0.0
    assert body["quota"]["users"] == []


# ---------------------------------------------------------------------------
# The range
# ---------------------------------------------------------------------------

#: seed offset -> cost; 0 and 2h are inside every window, 40d is outside all rolling ones.
_RANGE_SEEDS = {
    timedelta(0): "0.50000",
    timedelta(hours=2): "1.00000",
    timedelta(days=3): "2.00000",
    timedelta(days=20): "4.00000",
    timedelta(days=40): "8.00000",
}
_WINDOW = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}


def _seed_ranges(conn: psycopg.Connection) -> None:
    for ago, cost in _RANGE_SEEDS.items():
        _run(
            conn,
            role="proposer",
            ago=ago,
            cost=cost,
            subject_id=f"r-{ago.total_seconds():.0f}",
            result={"suggested_action": "needs_review"},
        )


def _expected_calls_and_cost(conn: psycopg.Connection, range_: str) -> tuple[int, float]:
    """The seeds a range holds, decided in Python from the database's own now and month start."""
    now, month_start, _ = _now_and_month(conn)
    since = month_start if range_ == "month" else now - _WINDOW[range_]
    inside = [Decimal(c) for ago, c in _RANGE_SEEDS.items() if now - ago >= since]
    return len(inside), float(sum(inside))


@pytest.mark.parametrize("range_", RANGES)
def test_the_range_filters_by_pipeline_role(client, range_):
    _seed_ranges(client.conn)
    calls, cost = _expected_calls_and_cost(client.conn, range_)

    row = _by_key(client.ok(range_))[("triage", "proposer")]

    assert (row["calls"], row["cost_usd"]) == (calls, cost)


def test_the_windows_hold_different_runs(client):
    """The seeds tell the ranges apart, so the test above is not four copies of one answer."""
    _seed_ranges(client.conn)

    calls = {r: _by_key(client.ok(r))[("triage", "proposer")]["calls"] for r in _WINDOW}

    assert calls == {"24h": 2, "7d": 3, "30d": 4}


def test_the_range_does_not_change_month_quota_or_recent(client):
    conn = client.conn
    _seed_ranges(conn)
    user_id, _ = _user(conn, "Người dùng")
    _analyzed(conn, user_id, timedelta(hours=1))

    bodies = {r: client.ok(r) for r in RANGES}

    for name in ("month", "quota", "recent", "limits", "limits_error", "tool_calls"):
        assert len({json.dumps(bodies[r][name], sort_keys=True) for r in RANGES}) == 1, name
    # and the by_pipeline_role block is the one that DOES move
    assert len({json.dumps(bodies[r]["by_pipeline_role"], sort_keys=True) for r in RANGES}) > 1


def test_recent_shows_a_run_older_than_every_range(client):
    _run(
        client.conn,
        role="proposer",
        ago=timedelta(days=40),
        subject_id="ancient",
        result={"suggested_action": "escalate"},
    )

    body = client.ok("24h")

    assert body["by_pipeline_role"] == []
    assert [r["subject_id"] for r in body["recent"]] == ["ancient"]


# ---------------------------------------------------------------------------
# month
# ---------------------------------------------------------------------------


def test_month_is_the_calendar_month_not_a_rolling_thirty_days(client):
    conn = client.conn
    _run(conn, ago=timedelta(0), cost="12.50000")  # this month, always
    _run(conn, at="date_trunc('month', now()) - interval '1 day'", cost="100.00000")  # last month

    body = client.ok("month")

    assert body["month"]["spent_usd"] == 12.5
    # the answer is exactly what the adapter's cap check reads
    assert body["month"]["spent_usd"] == round(llm_runs.month_spend_usd(conn), 4)
    assert _by_key(body)[("triage", "proposer")]["calls"] == 1  # `month` the range, too


def test_month_spend_is_the_same_whatever_the_range(client):
    conn = client.conn
    _run(conn, ago=timedelta(0), cost="12.50000")
    _run(conn, at="date_trunc('month', now()) - interval '1 day'", cost="100.00000")

    spent = {r: client.ok(r)["month"]["spent_usd"] for r in RANGES}

    assert set(spent.values()) == {12.5}


def test_month_pct_and_projection_on_a_frozen_now(client):
    conn = client.conn
    _run(conn, ago=timedelta(0), cost="12.50000")
    now, month_start, next_month = _now_and_month(conn)
    elapsed = max((now - month_start).total_seconds(), 3600.0)
    month_seconds = (next_month - month_start).total_seconds()
    expected_projection = 12.5 / (elapsed / 86400) * (month_seconds / 86400)

    month = client.ok("month")["month"]

    assert month["cap_usd"] == 30
    assert month["pct"] == 41.7  # 12.5 / 30 * 100 = 41.666...
    assert month["projected_usd"] == pytest.approx(expected_projection, abs=6e-5)
    assert month["projected_usd"] == round(month["projected_usd"], 4)


def test_month_over_the_cap_is_pct_above_100(client):
    _run(client.conn, ago=timedelta(0), cost="45.00000")

    assert client.ok()["month"]["pct"] == 150.0


def test_the_cap_follows_a_value_saved_on_the_web(client):
    conn = client.conn
    conn.execute(
        "INSERT INTO settings (key, value, updated_by) VALUES ('LLM_MONTHLY_USD_CAP', 60, %s)",
        (client.user_id,),
    )
    _run(conn, ago=timedelta(0), cost="12.00000")

    body = client.ok()

    assert body["month"]["cap_usd"] == 60
    assert body["month"]["pct"] == 20.0
    assert body["limits"]["cap_usd"] == 60
    assert body["limits"]["sources"]["LLM_MONTHLY_USD_CAP"]["source"] == "web"
    assert body["limits_error"] is None


@pytest.mark.parametrize(
    ("spent", "elapsed_s", "month_s", "expected"),
    [
        (10.0, 15 * 86400, 30 * 86400, 20.0),  # half the month gone: double
        (10.0, 30 * 86400, 30 * 86400, 10.0),  # the last instant: what was spent
        (1.0, 300, 30 * 86400, 720.0),  # 00:05 on day 1: the floor of one hour, not 5 minutes
        (1.0, 3600, 30 * 86400, 720.0),  # exactly at the floor
        (1.0, 7200, 31 * 86400, 372.0),  # past the floor: the real elapsed time, 31 days
        (0.0, 1, 30 * 86400, 0.0),
    ],
)
def test_the_projection_formula_and_its_one_hour_floor(spent, elapsed_s, month_s, expected):
    assert admin_llm._projected_usd(spent, elapsed_s, month_s) == pytest.approx(expected)


def test_money_is_a_json_number_with_at_most_four_decimals(client):
    conn = client.conn
    # numeric(10,5): five decimals stored, four served; a half rounds up
    _run(conn, ago=timedelta(0), cost="0.12345")
    _run(conn, ago=timedelta(0), cost="0.00001", role="verifier")

    body = client.ok()

    assert body["month"]["spent_usd"] == 0.1235  # 0.12346
    assert _by_key(body)[("triage", "proposer")]["cost_usd"] == 0.1235  # 0.12345, half up
    assert _by_key(body)[("triage", "verifier")]["cost_usd"] == 0.0
    for value in (
        body["month"]["spent_usd"],
        body["month"]["projected_usd"],
        *(r["cost_usd"] for r in body["by_pipeline_role"]),
        *(r["cost_usd"] for r in body["recent"] if r["cost_usd"] is not None),
    ):
        assert isinstance(value, int | float) and not isinstance(value, bool)
        assert round(value, 4) == value


# ---------------------------------------------------------------------------
# quota
# ---------------------------------------------------------------------------


def test_quota_counts_the_last_24_hours_of_case_analyzed_per_user_most_used_first(client):
    conn = client.conn
    alice, alice_name = _user(conn, "Alice")
    bob, bob_name = _user(conn, "Bob")
    carol, _ = _user(conn, "Carol")
    for ago in (timedelta(hours=1), timedelta(hours=12), timedelta(hours=23, minutes=59)):
        _analyzed(conn, alice, ago)
    _analyzed(conn, alice, timedelta(hours=25))  # one day and an hour: out
    _analyzed(conn, alice, timedelta(hours=1), event_type="tier1.decided")  # not an analysis
    _analyzed(conn, bob, timedelta(hours=2))
    _analyzed(conn, carol, timedelta(hours=25))  # only an old one: not listed at all

    quota = client.ok("7d")["quota"]

    assert quota["limit"] == 25
    assert quota["window"] == "24h"
    assert quota["users"] == [
        {"username": alice_name, "display_name": "Alice", "used": 3, "remaining": 22},
        {"username": bob_name, "display_name": "Bob", "used": 1, "remaining": 24},
    ]


def test_quota_gives_the_same_number_as_the_analyze_route_counts(client):
    conn = client.conn
    alice, alice_name = _user(conn, "Alice")
    for ago in (
        timedelta(minutes=1),
        timedelta(hours=10),
        timedelta(hours=23, minutes=59),
        timedelta(hours=24, minutes=1),
        timedelta(days=3),
    ):
        _analyzed(conn, alice, ago)

    used = {u["username"]: u["used"] for u in client.ok()["quota"]["users"]}

    assert tier2_runs._analyze_quota_count(conn, alice) == 3
    assert used[alice_name] == tier2_runs._analyze_quota_count(conn, alice)


def test_quota_and_the_analyze_route_share_one_counting_rule(client):
    """Not two copies that agree today: the route's count is built from the constant the usage
    query is built from, so a change to the window moves both."""
    assert tier2_runs.ANALYZE_QUOTA_WHERE in admin_llm._QUOTA_USED_SQL
    assert "interval '1 day'" in tier2_runs.ANALYZE_QUOTA_WHERE  # the rolling 24 hours


def test_quota_remaining_is_never_negative(client):
    conn = client.conn
    alice, alice_name = _user(conn, "Alice")
    conn.execute(
        "INSERT INTO settings (key, value, updated_by) "
        "VALUES ('ANALYZE_QUOTA_PER_USER_DAY', 2, %s)",
        (client.user_id,),
    )
    for _ in range(4):
        _analyzed(conn, alice, timedelta(hours=1))

    quota = client.ok()["quota"]

    assert quota["limit"] == 2
    assert quota["users"] == [
        {"username": alice_name, "display_name": "Alice", "used": 4, "remaining": 0}
    ]


def test_quota_users_with_the_same_count_are_ordered_by_username(client):
    conn = client.conn
    ids = [_user(conn, name) for name in ("Zed", "Amy", "Mia")]
    for user_id, _ in ids:
        _analyzed(conn, user_id, timedelta(hours=1))

    users = client.ok()["quota"]["users"]

    assert [u["username"] for u in users] == sorted(u for _, u in ids)


# ---------------------------------------------------------------------------
# recent
# ---------------------------------------------------------------------------


def test_recent_holds_at_most_twenty_rows_newest_first(client):
    conn = client.conn
    for minute in range(1, 26):  # 25 runs, `a-1` the newest
        _run(
            conn,
            role="proposer",
            ago=timedelta(minutes=minute),
            subject_id=f"a-{minute}",
            result={"suggested_action": "needs_review"},
        )

    recent = client.ok("24h")["recent"]

    assert len(recent) == 20
    assert [r["subject_id"] for r in recent] == [f"a-{m}" for m in range(1, 21)]
    stamps = [datetime.fromisoformat(r["created_at"]) for r in recent]
    assert stamps == sorted(stamps, reverse=True)


def test_recent_row_has_exactly_the_documented_fields(client):
    run_id = _run(
        client.conn,
        pipeline="investigate",
        role="investigator",
        ago=timedelta(minutes=3),
        subject_id="case-1",
        result={"suggested_conclusion": "confirmed_incident"},
        cost="1.23450",
        tokens=(111, 22),
        latency=3333,
    )

    (row,) = client.ok()["recent"]

    assert set(row) == {
        "run_id",
        "created_at",
        "pipeline",
        "role",
        "subject_type",
        "subject_id",
        "input_tokens",
        "output_tokens",
        "latency_ms",
        "outcome",
        "cost_usd",
    }
    assert row["run_id"] == run_id
    assert (row["pipeline"], row["role"], row["subject_type"], row["subject_id"]) == (
        "investigate",
        "investigator",
        "case",
        "case-1",
    )
    assert (row["input_tokens"], row["output_tokens"], row["latency_ms"]) == (111, 22, 3333)
    assert row["outcome"] == "confirmed_incident"
    assert row["cost_usd"] == 1.2345
    datetime.fromisoformat(row["created_at"])  # an ISO time


def test_a_row_with_no_tokens_latency_or_cost_serves_nulls(client):
    _run(client.conn, role="proposer", result=None, stopped_by="cap")

    (row,) = client.ok()["recent"]

    assert (row["input_tokens"], row["output_tokens"], row["latency_ms"], row["cost_usd"]) == (
        None,
        None,
        None,
        None,
    )


def test_no_prompt_trace_finding_or_result_ever_leaves_the_server(client):
    """Plant a marker in every column that holds text the model saw or wrote, then read the
    whole response as text and as keys."""
    marker = uuid.uuid4().hex
    _run(
        client.conn,
        pipeline="investigate",
        role="investigator",
        ago=timedelta(minutes=1),
        system_prompt=f"SECRET-SYSTEM-{marker}",
        user_message=f"SECRET-USER-{marker}",
        agent_trace={"rounds": [{"tool": f"SECRET-TRACE-{marker}"}]},
        result={
            "suggested_conclusion": "confirmed_incident",
            "summary": f"SECRET-RESULT-{marker}",
            "attack_narrative": f"SECRET-NARRATIVE-{marker}",
        },
        injection_findings=[{"quote": f"SECRET-INJECTION-{marker}"}],
        citation_warnings=[f"SECRET-CITATION-{marker}"],
        gate_result={"note": f"SECRET-GATE-{marker}"},
        verifier_result={"reason": f"SECRET-VERIFIER-{marker}"},
        evidence_check={"rejected": [{"reason": f"SECRET-EVIDENCE-{marker}"}]},
    )
    _run(
        client.conn,
        role="proposer",
        ago=timedelta(minutes=2),
        system_prompt=f"SECRET-SYSTEM2-{marker}",
        user_message=f"SECRET-USER2-{marker}",
        result={"suggested_action": "escalate", "reasons": [{"claim": f"SECRET-CLAIM-{marker}"}]},
    )

    for range_ in RANGES:
        resp = client.get(range_)
        assert resp.status_code == 200
        assert marker not in resp.text
        for word in ("system_prompt", "user_message", "agent_trace", "SECRET"):
            assert word not in resp.text, (range_, word)
        assert not (_keys(resp.json()) & _FORBIDDEN_KEYS), range_
    # and the runs themselves ARE served, by their safe fields only
    assert {r["outcome"] for r in client.ok()["recent"]} == {"confirmed_incident", "escalate"}


# ---------------------------------------------------------------------------
# outcome
# ---------------------------------------------------------------------------


def _drop_verdict_checks(conn: psycopg.Connection) -> None:
    """The database refuses a `suggested_action` / `suggested_conclusion` outside its closed set
    (`ck_llm_runs_suggested_*`), so a hostile one cannot be seeded under them. The route must
    not rely on that: drop the two CHECKs for this test's transaction (rolled back with it)."""
    for name in ("ck_llm_runs_suggested_action", "ck_llm_runs_suggested_conclusion"):
        conn.execute(f"ALTER TABLE llm_runs DROP CONSTRAINT {name}")


def _outcome_of(client: _Client, **run: Any) -> str | None:
    """The `outcome` the page would show for one more seeded run."""
    run_id = _run(client.conn, **run)
    (row,) = [r for r in client.ok()["recent"] if r["run_id"] == run_id]
    return row["outcome"]


@pytest.mark.parametrize(
    ("run", "expected"),
    [
        # the verdict of the proposer (①) and of the investigator (②), by their real keys
        (
            {"pipeline": "triage", "role": "proposer", "result": {"suggested_action": "escalate"}},
            "escalate",
        ),
        (
            {
                "pipeline": "triage",
                "role": "proposer",
                "result": {"suggested_action": "false_positive"},
            },
            "false_positive",
        ),
        (
            {
                "pipeline": "investigate",
                "role": "investigator",
                "result": {"suggested_conclusion": "policy_violation"},
            },
            "policy_violation",
        ),
        (
            {
                "pipeline": "investigate",
                "role": "investigator",
                "result": {"suggested_conclusion": "need_more_data"},
            },
            "need_more_data",
        ),
        # the verifier's own verdict has another key (`llm/templates/output_schemas.json`)
        (
            {
                "pipeline": "triage",
                "role": "verifier",
                "result": {"agree": False, "structured_only_verdict": "escalate", "reason": "x"},
            },
            "escalate",
        ),
        # no result: stopped:<why>, or nothing
        (
            {"pipeline": "triage", "role": "proposer", "result": None, "stopped_by": "schema"},
            "stopped:schema",
        ),
        (
            {"pipeline": "triage", "role": "verifier", "result": None, "stopped_by": "cap"},
            "stopped:cap",
        ),
        (
            {
                "pipeline": "investigate",
                "role": "investigator",
                "result": None,
                "stopped_by": "transient",
            },
            "stopped:transient",
        ),
        ({"pipeline": "triage", "role": "proposer", "result": None, "stopped_by": None}, None),
        # a result without its verdict key: the stop reason when there is one, else nothing
        ({"pipeline": "triage", "role": "proposer", "result": {"confidence": "high"}}, None),
        (
            {
                "pipeline": "investigate",
                "role": "investigator",
                "result": {},
                "stopped_by": "linter",
            },
            "stopped:linter",
        ),
        # the other pipeline's key is not this pipeline's verdict
        (
            {
                "pipeline": "triage",
                "role": "proposer",
                "result": {"suggested_conclusion": "escalate"},
            },
            None,
        ),
        (
            {
                "pipeline": "investigate",
                "role": "investigator",
                "result": {"suggested_action": "escalate"},
            },
            None,
        ),
        # a stop reason longer than a short code is not echoed
        ({"pipeline": "triage", "role": "proposer", "result": None, "stopped_by": "x" * 33}, None),
        (
            {"pipeline": "triage", "role": "proposer", "result": None, "stopped_by": "x" * 32},
            "stopped:" + "x" * 32,
        ),
    ],
)
def test_outcome(client, run, expected):
    assert _outcome_of(client, **run) == expected


@pytest.mark.parametrize(
    ("pipeline", "role", "key"),
    [
        ("triage", "proposer", "suggested_action"),
        ("investigate", "investigator", "suggested_conclusion"),
        ("triage", "verifier", "structured_only_verdict"),
    ],
)
@pytest.mark.parametrize(
    "value",
    [
        "x" * 41,  # model output longer than a verdict code
        "needs_review" + " " * 40,
        "<script>" + "a" * 40 + "</script>",
        5,
        True,
        None,
        ["escalate"],
        {"a": "escalate"},
    ],
    ids=["long", "padded", "markup-long", "number", "bool", "json-null", "list", "object"],
)
def test_a_verdict_that_is_long_or_not_a_string_is_null(client, pipeline, role, key, value):
    _drop_verdict_checks(client.conn)

    # no `stopped_by`: a hostile value must come out null, not as some other text
    assert _outcome_of(client, pipeline=pipeline, role=role, result={key: value}) is None


@pytest.mark.parametrize(
    ("pipeline", "role", "key"),
    [
        ("triage", "proposer", "suggested_action"),
        ("investigate", "investigator", "suggested_conclusion"),
    ],
)
def test_a_verdict_of_exactly_forty_characters_is_served_and_short_markup_stays_text(
    client, pipeline, role, key
):
    _drop_verdict_checks(client.conn)
    forty = "v" * 40

    assert _outcome_of(client, pipeline=pipeline, role=role, result={key: forty}) == forty
    # served as the text it is: the page renders text only, and there is nothing to escape here
    assert _outcome_of(client, pipeline=pipeline, role=role, result={key: "<b>x</b>"}) == "<b>x</b>"


@pytest.mark.parametrize("hostile", [["not", "an", "object"], "just a string", 7, True])
def test_a_result_that_is_not_an_object_has_no_verdict(client, hostile):
    assert _outcome_of(client, role="proposer", result=hostile) is None
    assert _outcome_of(client, role="proposer", result=hostile, stopped_by="schema") == (
        "stopped:schema"
    )


# ---------------------------------------------------------------------------
# limits unreadable, and the savepoint of each block
# ---------------------------------------------------------------------------


def test_unreadable_limits_degrade_the_limits_and_serve_the_rest(client):
    conn = client.conn
    _seed_matrix(conn)
    alice, alice_name = _user(conn, "Alice")
    _analyzed(conn, alice, timedelta(hours=1))
    conn.execute("ALTER TABLE settings RENAME TO settings_t04_away")  # rolled back with the test

    body = client.ok("24h")

    assert body["limits"] is None
    assert body["limits_error"] == "limits_unavailable"
    assert body["month"]["cap_usd"] is None
    assert body["month"]["pct"] is None
    assert body["month"]["spent_usd"] == round(llm_runs.month_spend_usd(conn), 4)
    assert body["quota"]["limit"] is None
    assert body["quota"]["users"] == [
        {"username": alice_name, "display_name": "Alice", "used": 1, "remaining": None}
    ]
    assert len(body["by_pipeline_role"]) == 4
    assert body["recent"]
    assert body["tool_calls"] == 0
    assert conn.execute("SELECT 1").fetchone() == (1,)  # and the transaction is still usable


def test_readable_limits_carry_the_limits_out_object_and_no_error(client):
    body = client.ok()

    assert body["limits_error"] is None
    limits = body["limits"]
    assert (limits["cap_usd"], limits["quota_per_24h"], limits["timeout_s"]) == (30, 25, 120)
    assert set(limits["sources"]) == {
        "LLM_MONTHLY_USD_CAP",
        "ANALYZE_QUOTA_PER_USER_DAY",
        "LLM_TIMEOUT_S",
    }
    assert {s["source"] for s in limits["sources"].values()} == {"env"}
    assert set(limits["bounds"]) == {"cap_usd", "quota_per_24h", "timeout_s"}


def test_the_answer_has_exactly_the_documented_top_level_keys(client):
    body = client.ok()

    assert list(body) == [
        "range",
        "month",
        "by_pipeline_role",
        "quota",
        "recent",
        "limits",
        "limits_error",
        "tool_calls",
    ]
    assert set(body["month"]) == {"spent_usd", "cap_usd", "pct", "projected_usd"}
    assert set(body["quota"]) == {"limit", "window", "users"}


@pytest.mark.parametrize("block", ["_month", "_by_pipeline_role", "_quota_used", "_recent"])
@pytest.mark.parametrize(
    ("statement", "reason"),
    [("SELECT 1/0", "query_failed"), ("SELECT pg_sleep(2)", "timeout")],
)
def test_a_failing_block_is_a_503_for_the_whole_answer_and_the_transaction_survives(
    client, monkeypatch, block, statement, reason
):
    monkeypatch.setattr(admin_llm, "BLOCK_TIMEOUT", "100ms")

    def boom(conn, *args, **kwargs):
        conn.execute(statement)

    monkeypatch.setattr(admin_llm, block, boom)

    resp = client.get("7d")

    assert resp.status_code == 503
    assert resp.json() == {"detail": {"reason": reason}}
    assert client.conn.execute("SELECT 1").fetchone() == (1,)  # the savepoint was rolled back


def test_every_block_goes_through_the_savepoint_helper_in_order(client, monkeypatch):
    seen: list[str] = []
    real = admin_llm._block

    def spy(conn, name, compute):
        seen.append(name)
        return real(conn, name, compute)

    monkeypatch.setattr(admin_llm, "_block", spy)

    client.ok()

    assert seen == ["month", "by_pipeline_role", "quota", "recent"]
