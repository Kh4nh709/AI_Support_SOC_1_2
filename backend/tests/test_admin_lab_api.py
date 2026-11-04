"""P14-T09 — `web/routers/admin_lab.py`: the admin API of the lab runs and labels (spec §6, DEC-213).

    GET    /api/admin/lab/runs                              200 {runs: [... total, labelled]}
    POST   /api/admin/lab/runs                              201; 409 overlap; 422
    GET    /api/admin/lab/runs/{run_id}/alerts?after=&limit=  200 {run, alerts, next_after}; 404
    PUT    /api/admin/lab/labels/{alert_id}   {label}       200; 404; 409 outside_every_run; 422
    DELETE /api/admin/lab/labels/{alert_id}                 204

Every test runs on a scratch database through `deps.get_conn` itself (committed on a 2xx, rolled back on any
raise) and reads the outcome back on a second connection: committed data, not an open transaction. The
refusal of a tier1 or tier2 caller commits its `authz.denied` row for real, which is the other reason
for a scratch database. Each test starts with empty lab tables (the windows may not overlap, so a run
left by one test would refuse the next).
"""

from __future__ import annotations

import dataclasses
import json
import typing
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, NamedTuple

import psycopg
import pytest
from app.infra import config
from app.infra.auth import Claims
from app.web import deps, main
from app.web.routers import admin_lab
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from tests import conftest
from tests.lab_data import at
from tests.scratch_db import insert_user, scratch_database
from tests.test_archive import _put_alert

pytestmark = pytest.mark.db

RUNS = "/api/admin/lab/runs"
LABELS = "/api/admin/lab/labels"
JSON = {"content-type": "application/json"}


@pytest.fixture(scope="module")
def scratch_dsn():
    with scratch_database("labadmin") as dsn:
        yield dsn


class World(NamedTuple):
    dsn: conftest.Dsn  # not str: a plain str prints a password in a failing test's report
    admin_id: str
    tier1_id: str
    tier2_id: str


def _claims(user_id: str, role: str) -> Claims:
    return Claims(user_id=user_id, username=f"p14t09-{role}", role=role, iat=0.0, exp=0.0)


@pytest.fixture
def world(scratch_dsn) -> World:
    with psycopg.connect(scratch_dsn) as setup:
        # the lab tables are emptied, and the alerts earlier tests committed (duplicates first: they
        # point at their head), so one test's alerts never fall in another's window
        setup.execute("TRUNCATE lab_labels, lab_runs")
        setup.execute(
            "DELETE FROM alerts WHERE duplicate_of IS NOT NULL AND alert_id LIKE 'p14t09-%'"
        )
        setup.execute("DELETE FROM alerts WHERE alert_id LIKE 'p14t09-%'")
        return World(
            scratch_dsn,
            insert_user(setup, "admin"),
            insert_user(setup, "tier1"),
            insert_user(setup, "tier2"),
        )


@pytest.fixture
def as_user(world, monkeypatch) -> Callable[[str], TestClient]:
    """`deps.get_conn` itself, unreplaced, handing out a connection to the scratch database; only the
    caller is overridden. `as_user("admin")` is a client signed in as the world's admin."""
    monkeypatch.setattr(
        deps.db, "connect", lambda *args, **kwargs: psycopg.connect(world.dsn, autocommit=False)
    )
    ids = {"admin": world.admin_id, "tier1": world.tier1_id, "tier2": world.tier2_id}

    def client(role: str) -> TestClient:
        main.app.dependency_overrides[deps.current_user] = lambda: _claims(ids[role], role)
        return TestClient(main.app, raise_server_exceptions=False)

    try:
        yield client
    finally:
        main.app.dependency_overrides.pop(deps.current_user, None)


# ── what a second connection sees ───────────────────────────────────────────────────────────


def _rows(world: World, query: str, params: tuple = ()) -> list[tuple]:
    with psycopg.connect(world.dsn) as conn:
        return conn.execute(query, params).fetchall()


def _runs_in_db(world: World) -> list[tuple]:
    return _rows(world, "SELECT name, purpose FROM lab_runs ORDER BY name")


def _label_in_db(world: World, alert_id: str) -> tuple | None:
    found = _rows(
        world,
        "SELECT run_id::text, label, labeled_by::text FROM lab_labels WHERE alert_id = %s",
        (alert_id,),
    )
    return found[0] if found else None


def _events(world: World, event_type: str, subject: str | None = None) -> list[tuple]:
    query = (
        "SELECT subject_id, actor_role, actor_id::text, payload FROM audit_events "
        "WHERE event_type = %s"
    )
    params: tuple = (event_type,)
    if subject is not None:
        query += " AND subject_id = %s"
        params += (subject,)
    return _rows(world, query + " ORDER BY audit_id", params)


def _alert(world: World, hours: float, **over) -> str:
    alert_id = f"p14t09-{uuid.uuid4().hex[:10]}"
    with psycopg.connect(world.dsn) as conn:
        _put_alert(conn, alert_id, received_at=at(hours), **over)
    return alert_id


def _run(client: TestClient, **over) -> dict[str, Any]:
    body = {"name": f"run-{uuid.uuid4().hex[:8]}", "purpose": "test"}
    body.update({"starts_at": at(0).isoformat(), "ends_at": at(4).isoformat()})
    body.update(over)
    resp = client.post(RUNS, json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _when(text: str) -> datetime:
    return datetime.fromisoformat(text)


def test_the_world_keeps_the_redacted_dsn_so_a_failing_test_prints_no_password(world):
    """`World` holds the `conftest.Dsn` itself, not `str(dsn)`: pytest prints a failing test's arguments
    with `repr`, and only a `Dsn` redacts the password there."""
    assert type(world.dsn) is conftest.Dsn
    assert repr(world.dsn) == repr(conftest.redact_dsn(world.dsn))
    assert repr(world.dsn) in repr(world)


# ── the routes, exactly ─────────────────────────────────────────────────────────────────────


def test_the_router_has_exactly_the_five_routes_of_the_brief():
    found = {(method, route.path) for route in admin_lab.router.routes for method in route.methods}
    assert found == {
        ("GET", "/api/admin/lab/runs"),
        ("POST", "/api/admin/lab/runs"),
        ("GET", "/api/admin/lab/runs/{run_id}/alerts"),
        ("PUT", "/api/admin/lab/labels/{alert_id}"),
        ("DELETE", "/api/admin/lab/labels/{alert_id}"),
    }


@pytest.mark.parametrize("name", ["api_put_label", "api_delete_label"])
def test_the_alert_id_takes_the_pattern_of_the_existing_alert_routes(name):
    hints = typing.get_type_hints(getattr(admin_lab, name), include_extras=True)
    assert hints["alert_id"] == deps.AlertId


def test_the_router_is_discovered_and_mounted():
    """FastAPI 0.141 keeps an included router as one node in `app.routes`; the OpenAPI document lists what
    is really served."""
    paths = main.app.openapi()["paths"]
    assert {RUNS, f"{RUNS}/{{run_id}}/alerts", f"{LABELS}/{{alert_id}}"} <= set(paths)
    assert set(paths[f"{LABELS}/{{alert_id}}"]) == {"put", "delete"}


def test_the_audit_page_groups_both_new_events_under_configuration():
    from app.web.routers import admin_audit

    assert {"lab.run_created", "lab.labeled"} <= set(admin_audit.GROUPS["configuration"])


# ── POST /runs ──────────────────────────────────────────────────────────────────────────────


def test_creating_a_run_answers_201_with_the_run_and_commits_it_with_its_event(world, as_user):
    resp = as_user("admin").post(
        RUNS,
        json={
            "name": "Lần 1",
            "purpose": "kb",
            "starts_at": at(0).isoformat(),
            "ends_at": at(4).isoformat(),
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert set(body) == {"run_id", "name", "purpose", "starts_at", "ends_at", "total", "labelled"}
    assert (body["name"], body["purpose"], body["total"], body["labelled"]) == ("Lần 1", "kb", 0, 0)
    assert (_when(body["starts_at"]), _when(body["ends_at"])) == (at(0), at(4))
    assert _runs_in_db(world) == [("Lần 1", "kb")]
    assert _events(world, "lab.run_created", body["run_id"]) == [
        (
            body["run_id"],
            "admin",
            world.admin_id,
            {"run_id": body["run_id"], "name": "Lần 1", "purpose": "kb"},
        )
    ]


def test_a_run_recorded_after_the_fact_counts_the_alerts_already_in_its_window(world, as_user):
    _alert(world, 1)
    _alert(world, 2)
    _alert(world, 9)
    body = _run(as_user("admin"))
    assert (body["total"], body["labelled"]) == (2, 0)


@pytest.mark.parametrize(
    "starts,ends",
    [
        ("2026-11-05T09:00:00Z", "2026-11-05T11:00:00Z"),
        ("2026-11-05T16:00:00+07:00", "2026-11-05T18:00:00+07:00"),
        ("2026-11-05T09:00:00+00:00", "2026-11-05T11:00:00.500000+00:00"),
    ],
)
def test_a_time_with_a_zone_is_taken_in_that_zone(world, as_user, starts, ends):
    body = _run(as_user("admin"), starts_at=starts, ends_at=ends)
    assert _when(body["starts_at"]) == _when(starts)
    assert _when(body["ends_at"]) == _when(ends)


@pytest.mark.parametrize(
    "first,second",
    [((0, 4), (2, 6)), ((2, 6), (0, 4)), ((0, 8), (2, 4)), ((2, 4), (0, 8)), ((0, 4), (0, 4))],
    ids=["starts-inside", "ends-inside", "inside", "holds", "same"],
)
def test_an_overlapping_run_is_409_overlap_and_writes_nothing(world, as_user, first, second):
    client = as_user("admin")
    _run(client, name="first", starts_at=at(first[0]).isoformat(), ends_at=at(first[1]).isoformat())
    events_before = len(_events(world, "lab.run_created"))
    resp = client.post(
        RUNS,
        json={
            "name": "second",
            "purpose": "test",
            "starts_at": at(second[0]).isoformat(),
            "ends_at": at(second[1]).isoformat(),
        },
    )
    assert resp.status_code == 409
    assert resp.json() == {"detail": {"reason": "overlap"}}
    assert _runs_in_db(world) == [("first", "test")]
    assert len(_events(world, "lab.run_created")) == events_before


def test_a_run_that_starts_where_another_ends_is_accepted(world, as_user):
    client = as_user("admin")
    _run(client, name="a", starts_at=at(0).isoformat(), ends_at=at(2).isoformat())
    _run(client, name="b", starts_at=at(2).isoformat(), ends_at=at(4).isoformat())
    assert _runs_in_db(world) == [("a", "test"), ("b", "test")]


def _valid(**over) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": "n",
        "purpose": "test",
        "starts_at": at(0).isoformat(),
        "ends_at": at(4).isoformat(),
    }
    body.update(over)
    return {k: v for k, v in body.items() if v is not ...}


@pytest.mark.parametrize(
    "body,field,reason",
    [
        (_valid(purpose="train"), "purpose", "invalid"),
        (_valid(purpose=...), "purpose", "required"),
        (_valid(purpose=None), "purpose", "required"),
        (_valid(purpose=3), "purpose", "invalid"),
        (_valid(name=...), "name", "required"),
        (_valid(name=""), "name", "empty"),
        (_valid(name="   "), "name", "empty"),
        (_valid(name="x" * 81), "name", "too_long"),
        (_valid(name=5), "name", "invalid"),
        (_valid(name="a\u0000b"), "name", "invalid"),
        (_valid(starts_at=...), "starts_at", "required"),
        (_valid(ends_at=...), "ends_at", "required"),
        (_valid(starts_at="yesterday"), "starts_at", "invalid"),
        (_valid(ends_at="2026-11-05"), "ends_at", "invalid"),
        (_valid(starts_at="2026-11-05T09:00:00"), "starts_at", "invalid"),  # no zone: ambiguous
        (_valid(ends_at="2026-11-05T11:00:00"), "ends_at", "invalid"),
        (_valid(starts_at=1762333200), "starts_at", "invalid"),
        (_valid(ends_at=at(0).isoformat()), "ends_at", "not_after_starts"),
        (_valid(ends_at=at(-1).isoformat()), "ends_at", "not_after_starts"),
    ],
    ids=lambda v: v if isinstance(v, str) and len(v) < 30 else None,
)
def test_a_malformed_run_is_422_with_the_field_and_the_reason_and_writes_nothing(
    world, as_user, body, field, reason
):
    resp = as_user("admin").post(RUNS, json=body)
    assert resp.status_code == 422, resp.text
    assert resp.json() == {"detail": {"field": field, "reason": reason}}
    assert _runs_in_db(world) == []


def test_a_name_already_taken_is_422_name_taken(world, as_user):
    client = as_user("admin")
    _run(client, name="same", starts_at=at(0).isoformat(), ends_at=at(1).isoformat())
    resp = client.post(
        RUNS, json=_valid(name="same", starts_at=at(5).isoformat(), ends_at=at(6).isoformat())
    )
    assert resp.status_code == 422
    assert resp.json() == {"detail": {"field": "name", "reason": "taken"}}
    assert _runs_in_db(world) == [("same", "test")]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"json": [1, 2]},
        {"json": "text"},
        {"json": _valid(extra="x")},
        {"content": b"{not json", "headers": JSON},
        {"content": b"", "headers": JSON},
        {"content": b"\xff\xfe", "headers": JSON},
        {"content": json.dumps(_valid()).encode()},  # no content type: what a no-cors fetch sends
        {"content": json.dumps(_valid()).encode(), "headers": {"content-type": "text/plain"}},
        {"data": _valid(), "headers": {"content-type": "application/x-www-form-urlencoded"}},
    ],
    ids=[
        "array",
        "string",
        "extra-key",
        "broken",
        "empty",
        "bad-utf8",
        "no-type",
        "text-plain",
        "form",
    ],
)
def test_a_body_that_is_not_a_json_object_is_422_body_invalid_and_writes_nothing(
    world, as_user, kwargs
):
    resp = as_user("admin").post(RUNS, **kwargs)
    assert resp.status_code == 422, resp.text
    assert resp.json() == {"detail": {"field": "body", "reason": "invalid"}}
    assert _runs_in_db(world) == []


# ── GET /runs ───────────────────────────────────────────────────────────────────────────────


def test_the_list_is_empty_with_no_run(world, as_user):
    resp = as_user("admin").get(RUNS)
    assert resp.status_code == 200
    assert resp.json() == {"runs": []}


def test_the_list_gives_each_run_with_its_total_and_labelled_counts_newest_first(world, as_user):
    client = as_user("admin")
    old = _run(client, name="old", starts_at=at(0).isoformat(), ends_at=at(4).isoformat())
    new = _run(
        client, name="new", purpose="kb", starts_at=at(10).isoformat(), ends_at=at(14).isoformat()
    )
    first = _alert(world, 1)
    _alert(world, 2)
    _alert(world, 3)
    _alert(world, 11)
    head = _alert(world, 3.5)
    _alert(world, 3.6, status="duplicate", duplicate_of=head)
    assert client.put(f"{LABELS}/{first}", json={"label": "true_positive"}).status_code == 200
    assert client.put(f"{LABELS}/{head}", json={"label": "false_positive"}).status_code == 200

    resp = client.get(RUNS)
    assert resp.status_code == 200
    runs = resp.json()["runs"]
    assert [r["name"] for r in runs] == ["new", "old"]
    assert runs[0] == {
        "run_id": new["run_id"],
        "name": "new",
        "purpose": "kb",
        "starts_at": runs[0]["starts_at"],
        "ends_at": runs[0]["ends_at"],
        "total": 1,
        "labelled": 0,
    }
    assert (runs[1]["run_id"], runs[1]["total"], runs[1]["labelled"]) == (old["run_id"], 4, 2)


# ── GET /runs/{run_id}/alerts ───────────────────────────────────────────────────────────────


def test_a_runs_alerts_are_those_received_in_its_window_with_their_labels(world, as_user):
    client = as_user("admin")
    run = _run(client, starts_at=at(1).isoformat(), ends_at=at(3).isoformat())
    outside = _alert(world, 0.5)
    inside_a = _alert(world, 1)
    inside_b = _alert(world, 2)
    end = _alert(world, 3)
    client.put(f"{LABELS}/{inside_b}", json={"label": "false_positive"})

    resp = client.get(f"{RUNS}/{run['run_id']}/alerts")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [a["alert_id"] for a in body["alerts"]] == [inside_a, inside_b]
    assert [a["label"] for a in body["alerts"]] == [None, "false_positive"]
    assert outside not in json.dumps(body) and end not in json.dumps(body)
    assert body["run"]["run_id"] == run["run_id"]
    assert (body["run"]["total"], body["run"]["labelled"]) == (2, 1)
    assert body["next_after"] is None


@pytest.mark.parametrize("arm", [True, False], ids=["visible-arm", "blind-arm"])
def test_no_alert_carries_a_key_of_one_over_the_wire(world, as_user, arm):
    client = as_user("admin")
    run = _run(client)
    alert_id = _alert(world, 1, suggestion_visible=arm, triaged_count=2)
    with psycopg.connect(world.dsn) as conn:
        conn.execute(
            "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt, "
            "user_message, result, gate_result) VALUES (%s, 'triage', 'alert', %s, 's', 'u', %s, %s)",
            (
                str(uuid.uuid4()),
                alert_id,
                Jsonb({"suggested_action": "needs_review", "marker": "LLM-RESULT-MARKER"}),
                Jsonb({"held_by": ["step2"], "proposed_action": "true_positive"}),
            ),
        )
        conn.execute(
            "UPDATE alerts SET raw_payload = %s WHERE alert_id = %s",
            (Jsonb({"soar": {"marker": "SOAR-MARKER"}}), alert_id),
        )
    text = client.get(f"{RUNS}/{run['run_id']}/alerts").text
    assert alert_id in text
    for forbidden in (
        "suggested_action",
        "proposed_action",
        "held_by",
        '"rag',
        "LLM-RESULT-MARKER",
        "SOAR-MARKER",
        "needs_review",
        "triage_status",
        "suggestion_visible",
        "gate_result",
    ):
        assert forbidden not in text, forbidden


def test_next_after_pages_through_the_alerts(world, as_user):
    client = as_user("admin")
    run = _run(client)
    ids = [_alert(world, 0.1 * i) for i in range(5)]
    seen: list[str] = []
    after = None
    for _ in range(5):
        url = f"{RUNS}/{run['run_id']}/alerts?limit=2" + (f"&after={after}" if after else "")
        body = client.get(url).json()
        seen += [a["alert_id"] for a in body["alerts"]]
        after = body["next_after"]
        if after is None:
            break
    assert seen == ids


def test_an_unknown_run_is_404(world, as_user):
    resp = as_user("admin").get(f"{RUNS}/{uuid.uuid4()}/alerts")
    assert resp.status_code == 404
    assert resp.json() == {"detail": {"reason": "not_found"}}


def test_a_run_id_that_is_not_a_uuid_is_422_and_one_with_a_control_character_is_404(world, as_user):
    client = as_user("admin")
    assert client.get(f"{RUNS}/not-a-uuid/alerts").status_code == 422
    assert client.get(f"{RUNS}/a%00b/alerts").status_code == 404


@pytest.mark.parametrize(
    "query",
    [
        "limit=0",
        "limit=-1",
        f"limit={admin_lab.MAX_LIMIT + 1}",
        "limit=abc",
        "after=a%00b",
        "after=",
    ],
)
def test_a_bad_limit_or_after_is_422(world, as_user, query):
    client = as_user("admin")
    run = _run(client)
    resp = client.get(f"{RUNS}/{run['run_id']}/alerts?{query}")
    assert resp.status_code == 422, resp.text


# ── PUT /labels/{alert_id} ──────────────────────────────────────────────────────────────────


def test_putting_a_label_answers_200_and_commits_the_label_with_its_event(world, as_user):
    client = as_user("admin")
    run = _run(client)
    alert_id = _alert(world, 1)
    resp = client.put(f"{LABELS}/{alert_id}", json={"label": "true_positive"})
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"alert_id": alert_id, "run_id": run["run_id"], "label": "true_positive"}
    assert _label_in_db(world, alert_id) == (run["run_id"], "true_positive", world.admin_id)
    assert _events(world, "lab.labeled", alert_id) == [
        (
            alert_id,
            "admin",
            world.admin_id,
            {"alert_id": alert_id, "run_id": run["run_id"], "label": "true_positive"},
        )
    ]


def test_relabelling_changes_the_label_and_writes_one_more_event(world, as_user):
    client = as_user("admin")
    run = _run(client)
    alert_id = _alert(world, 1)
    client.put(f"{LABELS}/{alert_id}", json={"label": "true_positive"})
    resp = client.put(f"{LABELS}/{alert_id}", json={"label": "false_positive"})
    assert resp.status_code == 200
    assert resp.json()["label"] == "false_positive"
    assert _label_in_db(world, alert_id) == (run["run_id"], "false_positive", world.admin_id)
    assert [e[3]["label"] for e in _events(world, "lab.labeled", alert_id)] == [
        "true_positive",
        "false_positive",
    ]


def test_an_unknown_alert_is_404(world, as_user):
    _run(as_user("admin"))
    resp = as_user("admin").put(f"{LABELS}/no-such-alert", json={"label": "true_positive"})
    assert resp.status_code == 404
    assert resp.json() == {"detail": {"reason": "not_found"}}


def test_an_alert_outside_every_run_is_409_outside_every_run_and_writes_nothing(world, as_user):
    client = as_user("admin")
    _run(client, starts_at=at(0).isoformat(), ends_at=at(4).isoformat())
    alert_id = _alert(world, 6)
    resp = client.put(f"{LABELS}/{alert_id}", json={"label": "true_positive"})
    assert resp.status_code == 409
    assert resp.json() == {"detail": {"reason": "outside_every_run"}}
    assert _label_in_db(world, alert_id) is None
    assert _events(world, "lab.labeled", alert_id) == []


def test_a_duplicate_is_409_not_a_queue_head_and_writes_nothing(world, as_user):
    client = as_user("admin")
    _run(client)
    head = _alert(world, 1)
    duplicate = _alert(world, 1.5, status="duplicate", duplicate_of=head)
    resp = client.put(f"{LABELS}/{duplicate}", json={"label": "true_positive"})
    assert resp.status_code == 409
    assert resp.json() == {"detail": {"reason": "not_a_queue_head"}}
    assert _label_in_db(world, duplicate) is None
    assert _events(world, "lab.labeled", duplicate) == []
    # its head is labelled as before
    assert client.put(f"{LABELS}/{head}", json={"label": "true_positive"}).status_code == 200


def test_a_duplicate_outside_every_run_is_still_not_a_queue_head(world, as_user):
    client = as_user("admin")
    _run(client, starts_at=at(0).isoformat(), ends_at=at(4).isoformat())
    head = _alert(world, 8)
    duplicate = _alert(world, 8.5, status="duplicate", duplicate_of=head)
    resp = client.put(f"{LABELS}/{duplicate}", json={"label": "true_positive"})
    assert resp.status_code == 409
    assert resp.json() == {"detail": {"reason": "not_a_queue_head"}}


def test_with_no_run_at_all_every_alert_is_outside_every_run(world, as_user):
    alert_id = _alert(world, 1)
    resp = as_user("admin").put(f"{LABELS}/{alert_id}", json={"label": "false_positive"})
    assert resp.status_code == 409


@pytest.mark.parametrize(
    "body,field,reason",
    [
        ({"label": "benign"}, "label", "invalid"),
        ({"label": "escalate"}, "label", "invalid"),
        ({"label": "TP"}, "label", "invalid"),
        ({"label": ""}, "label", "invalid"),
        ({"label": 1}, "label", "invalid"),
        ({"label": True}, "label", "invalid"),
        ({"label": None}, "label", "required"),
        ({}, "label", "required"),
        ({"label": "true_positive", "note": "x"}, "body", "invalid"),
    ],
)
def test_a_bad_label_is_422_and_writes_nothing(world, as_user, body, field, reason):
    client = as_user("admin")
    _run(client)
    alert_id = _alert(world, 1)
    resp = client.put(f"{LABELS}/{alert_id}", json=body)
    assert resp.status_code == 422, resp.text
    assert resp.json() == {"detail": {"field": field, "reason": reason}}
    assert _label_in_db(world, alert_id) is None
    assert _events(world, "lab.labeled", alert_id) == []


@pytest.mark.parametrize(
    "kwargs",
    [
        {"content": b'{"label": "true_positive"}'},
        {"content": b'{"label": "true_positive"}', "headers": {"content-type": "text/plain"}},
        {"data": {"label": "true_positive"}},
        {"json": ["true_positive"]},
        {"content": b"{broken", "headers": JSON},
    ],
    ids=["no-type", "text-plain", "form", "array", "broken"],
)
def test_a_put_that_is_not_a_json_object_is_422_body_invalid(world, as_user, kwargs):
    client = as_user("admin")
    _run(client)
    alert_id = _alert(world, 1)
    resp = client.put(f"{LABELS}/{alert_id}", **kwargs)
    assert resp.status_code == 422, resp.text
    assert resp.json() == {"detail": {"field": "body", "reason": "invalid"}}
    assert _label_in_db(world, alert_id) is None


def test_a_control_character_in_the_alert_id_is_404_on_put_and_delete(world, as_user):
    client = as_user("admin")
    assert client.put(f"{LABELS}/a%00b", json={"label": "true_positive"}).status_code == 404
    assert client.delete(f"{LABELS}/a%00b", headers=JSON).status_code == 404
    assert client.put(f"{LABELS}/a%0Ab", json={"label": "true_positive"}).status_code == 404


def test_a_failure_after_the_label_is_written_leaves_neither_label_nor_event(
    world, as_user, monkeypatch
):
    from app.lab import labels as lab_labels

    client = as_user("admin")
    _run(client)
    alert_id = _alert(world, 1)

    def boom(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("injected failure")

    monkeypatch.setattr(lab_labels, "write_event", boom)
    resp = client.put(f"{LABELS}/{alert_id}", json={"label": "true_positive"})
    assert resp.status_code == 500
    assert _label_in_db(world, alert_id) is None
    assert _events(world, "lab.labeled", alert_id) == []


def test_a_failure_after_the_run_is_written_leaves_neither_run_nor_event(
    world, as_user, monkeypatch
):
    """The POST twin of the PUT test above. The signed-in user is overridden here, so the run's INSERT is the
    first statement on an IDLE connection: with the event written after the savepoint closed, the savepoint
    would be the outermost transaction and commit the run before the event failed."""
    from app.lab import runs as lab_runs

    client = as_user("admin")
    events_before = len(_events(world, "lab.run_created"))

    def boom(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("injected failure")

    monkeypatch.setattr(lab_runs, "write_event", boom)
    resp = client.post(RUNS, json=_valid(name="boom"))
    assert resp.status_code == 500
    assert _runs_in_db(world) == []
    assert len(_events(world, "lab.run_created")) == events_before


@pytest.mark.parametrize(
    "field,value",
    [
        ("starts_at", "0001-01-01T00:00:00+14:00"),  # before year 1 once it is UTC
        ("ends_at", "9999-12-31T23:00:00-14:00"),  # after year 9999 once it is UTC
    ],
)
def test_a_time_that_cannot_be_written_in_utc_is_422_invalid_not_a_500(
    world, as_user, field, value
):
    body = _valid(**{field: value})
    if field == "starts_at":
        body["ends_at"] = at(4).isoformat()
    else:
        body["starts_at"] = at(0).isoformat()
    resp = as_user("admin").post(RUNS, json=body)
    assert resp.status_code == 422, resp.text
    assert resp.json() == {"detail": {"field": field, "reason": "invalid"}}
    assert _runs_in_db(world) == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("starts_at", "1999-12-31T23:59:59Z"),
        ("starts_at", "2100-01-01T00:00:00Z"),
        ("ends_at", "1999-12-31T23:59:59Z"),
        ("ends_at", "2100-01-01T00:00:00Z"),
        ("starts_at", "2000-01-01T00:00:00+07:00"),  # 1999-12-31T17:00:00Z
        ("ends_at", "2100-01-01T07:00:00+07:00"),  # 2100-01-01T00:00:00Z
        ("starts_at", "0001-01-01T00:00:00Z"),
        ("ends_at", "9999-12-31T23:59:59Z"),
    ],
)
def test_a_time_outside_the_years_2000_to_2099_in_utc_is_422_invalid(world, as_user, field, value):
    body = _valid(**{field: value})
    if field == "starts_at":
        body["ends_at"] = at(4).isoformat()
    else:
        body["starts_at"] = at(0).isoformat()
    resp = as_user("admin").post(RUNS, json=body)
    assert resp.status_code == 422, resp.text
    assert resp.json() == {"detail": {"field": field, "reason": "invalid"}}
    assert _runs_in_db(world) == []


@pytest.mark.parametrize(
    "starts,ends",
    [
        ("2000-01-01T00:00:00Z", "2000-01-01T01:00:00Z"),
        ("2099-12-31T22:00:00Z", "2099-12-31T23:59:59Z"),
        ("2000-01-01T07:00:00+07:00", "2000-01-01T08:00:00+07:00"),
        ("2100-01-01T05:00:00+07:00", "2100-01-01T06:59:59+07:00"),
    ],
)
def test_the_first_and_last_second_the_years_allow_are_201_and_listed(world, as_user, starts, ends):
    client = as_user("admin")
    run = _run(client, starts_at=starts, ends_at=ends)
    assert (_when(run["starts_at"]), _when(run["ends_at"])) == (_when(starts), _when(ends))
    listed = client.get(RUNS)
    assert listed.status_code == 200
    assert [r["run_id"] for r in listed.json()["runs"]] == [run["run_id"]]


def test_a_time_with_an_offset_is_taken_in_utc():
    moment = admin_lab._instant({"t": "2026-11-05T16:00:00+07:00"}, "t")
    assert moment == datetime(2026, 11, 5, 9, 0, tzinfo=UTC)
    assert moment.utcoffset() == timedelta(0)


# ── DELETE /labels/{alert_id} ───────────────────────────────────────────────────────────────


def test_deleting_a_label_answers_204_clears_it_and_writes_the_event_with_a_null_label(
    world, as_user
):
    client = as_user("admin")
    run = _run(client)
    alert_id = _alert(world, 1)
    client.put(f"{LABELS}/{alert_id}", json={"label": "true_positive"})
    resp = client.delete(f"{LABELS}/{alert_id}", headers=JSON)
    assert resp.status_code == 204
    assert resp.content == b""
    assert _label_in_db(world, alert_id) is None
    events = _events(world, "lab.labeled", alert_id)
    assert events[-1] == (
        alert_id,
        "admin",
        world.admin_id,
        {"alert_id": alert_id, "run_id": run["run_id"], "label": None},
    )
    assert len(events) == 2
    listed = client.get(f"{RUNS}/{run['run_id']}/alerts").json()["alerts"]
    assert [(a["alert_id"], a["label"]) for a in listed] == [(alert_id, None)]


@pytest.mark.parametrize("target", ["unlabelled", "unknown"])
def test_deleting_what_is_not_there_is_204_and_writes_no_event(world, as_user, target):
    client = as_user("admin")
    _run(client)
    alert_id = _alert(world, 1) if target == "unlabelled" else "never-existed"
    resp = client.delete(f"{LABELS}/{alert_id}", headers=JSON)
    assert resp.status_code == 204
    assert _events(world, "lab.labeled", alert_id) == []


def test_a_delete_without_the_json_content_type_is_422_and_changes_nothing(world, as_user):
    """The rule of every route that changes something and reads no body (`deps.require_json_type`)."""
    client = as_user("admin")
    _run(client)
    alert_id = _alert(world, 1)
    client.put(f"{LABELS}/{alert_id}", json={"label": "true_positive"})
    resp = client.delete(f"{LABELS}/{alert_id}")
    assert resp.status_code == 422
    assert resp.json() == {"detail": {"field": "body", "reason": "invalid"}}
    assert _label_in_db(world, alert_id) is not None


# ── who may call ────────────────────────────────────────────────────────────────────────────


def _each_route(alert_id: str, run_id: str):
    return [
        ("get", RUNS, {}),
        ("post", RUNS, {"json": _valid()}),
        ("get", f"{RUNS}/{run_id}/alerts", {}),
        ("put", f"{LABELS}/{alert_id}", {"json": {"label": "true_positive"}}),
        ("delete", f"{LABELS}/{alert_id}", {"headers": JSON}),
    ]


@pytest.mark.parametrize("role", ["tier1", "tier2"])
def test_a_tier1_or_tier2_caller_gets_403_on_every_route_and_changes_nothing(world, as_user, role):
    admin_client = as_user("admin")
    run = _run(admin_client)
    alert_id = _alert(world, 1)
    admin_client.put(f"{LABELS}/{alert_id}", json={"label": "false_positive"})
    before = (_runs_in_db(world), _label_in_db(world, alert_id))
    denied_before = len(_events(world, "authz.denied"))

    client = as_user(role)
    routes = _each_route(alert_id, run["run_id"])
    for method, url, kwargs in routes:
        resp = getattr(client, method)(url, **kwargs)
        assert resp.status_code == 403, (method, url, resp.status_code)
        assert resp.json() == {"detail": "forbidden"}
    assert (_runs_in_db(world), _label_in_db(world, alert_id)) == before
    assert len(_events(world, "authz.denied")) == denied_before + len(routes)
    assert {e[0] for e in _events(world, "authz.denied")[denied_before:]} == {
        url.split("?")[0] for _, url, _ in routes
    }


@pytest.mark.parametrize("role", ["tier1", "tier2"])
def test_the_role_is_checked_before_the_body_and_the_id(world, as_user, role):
    client = as_user(role)
    assert client.post(RUNS, json=["not", "an", "object"]).status_code == 403
    assert client.post(RUNS, content=b"{broken").status_code == 403
    assert client.put(f"{LABELS}/an-alert", json={"nonsense": 1}).status_code == 403
    assert client.get(f"{RUNS}/not-a-uuid/alerts").status_code == 403


def test_no_token_is_401_on_every_route(world, monkeypatch):
    monkeypatch.setattr(
        deps.db, "connect", lambda *args, **kwargs: psycopg.connect(world.dsn, autocommit=False)
    )
    main.app.dependency_overrides.pop(deps.current_user, None)
    main.app.dependency_overrides[deps.get_config] = lambda: dataclasses.replace(
        config.Config(), JWT_SECRET="p14t09-literal-secret-for-a-test"
    )
    try:
        client = TestClient(main.app, raise_server_exceptions=False)
        for method, url, kwargs in _each_route("some-alert", str(uuid.uuid4())):
            resp = getattr(client, method)(url, **kwargs)
            assert resp.status_code == 401, (method, url, resp.status_code)
            assert resp.json() == {"detail": "not authenticated"}
    finally:
        main.app.dependency_overrides.pop(deps.get_config, None)
