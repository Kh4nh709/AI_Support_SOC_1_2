"""P11-T08 — what `test_labels.py`'s rolled-back `db` fixture cannot show about
`POST /api/admin/labels/undo` and `GET /api/admin/labels/next` (`web/routers/labels.py`,
spec §4.6, §5.7, §6): the two things that need a connection which really commits.

- **One transaction.** `undo_last` deletes the label and then writes its `label.created`
  event; the route then reads the progress. All three run on the request's connection, which
  `deps.get_conn` commits on a 2xx and rolls back on any raise. A failure after the DELETE must
  leave the label where it was, with no event. Here the request runs on the REAL `deps.get_conn`,
  pointed at a scratch database through `db.connect`, and the outcome is read back on a second
  connection: committed data, not an open transaction.
- **A tier1 caller.** `deps.require_role` writes `authz.denied` and COMMITS it before it raises
  403, so that row lands for real; it must not reach the shared database a later test file
  counts in (the reason `test_admin_overview.py` has its own scratch database too).

Every test points `labels.CANDIDATES_PATH`, `G1_CLUSTERS_PATH` and `FREEZE_MARKER` at `tmp_path`:
the repository's own `eval/gold_candidates.csv` and `eval/gold_v1.sha256` exist, and a test must
neither read nor touch them. Each test inserts its own uniquely named user and alert, so the
module's tests never see each other's committed rows; the database is dropped at the end.
"""

from __future__ import annotations

import csv
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, NamedTuple

import psycopg
import pytest
from app.infra.auth import Claims
from app.tier1 import labels
from app.web import deps, main
from fastapi.testclient import TestClient

from tests import conftest
from tests.scratch_db import insert_alert, insert_user, scratch_database

UNDO = "/api/admin/labels/undo"
NEXT = "/api/admin/labels/next"
CANDIDATE_COLUMNS = [
    "cluster_id",
    "gold_set",
    "alert_id",
    "category",
    "severity",
    "occurrence_count",
    "first_seen",
    "last_seen",
]


@pytest.fixture(scope="module")
def scratch_dsn():
    with scratch_database("labelsapi") as dsn:
        yield dsn


@pytest.fixture(autouse=True)
def _require_db_marker_for_scratch(request):
    if "scratch_dsn" in request.fixturenames and request.node.get_closest_marker("db") is None:
        pytest.fail(f"{request.node.nodeid} uses `scratch_dsn` without @pytest.mark.db")


class World(NamedTuple):
    dsn: conftest.Dsn  # not str: a plain str prints a password in a failing test's report
    admin_id: str
    tier1_id: str
    alert_id: str


def _claims(user_id: str, role: str) -> Claims:
    return Claims(user_id=user_id, username=f"p11t08-{role}", role=role, iat=0.0, exp=0.0)


@pytest.fixture
def world(scratch_dsn, tmp_path, monkeypatch) -> World:
    """Committed: an admin, a tier1 user, one alert and one gold candidate for it. The three
    paths of `labels` point at `tmp_path` (the freeze marker is absent)."""
    alert_id = f"p11t08-{uuid.uuid4().hex[:10]}"
    with psycopg.connect(scratch_dsn) as setup:
        admin_id = insert_user(setup, "admin")
        tier1_id = insert_user(setup, "tier1")
        insert_alert(setup, alert_id)
    candidates = tmp_path / "gold_candidates.csv"
    with candidates.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CANDIDATE_COLUMNS)
        writer.writeheader()
        writer.writerow(
            {
                "cluster_id": alert_id,
                "gold_set": "G1",
                "alert_id": alert_id,
                "category": "other",
                "severity": "medium",
                "occurrence_count": 1,
                "first_seen": datetime(2026, 9, 1, tzinfo=UTC).isoformat(),
                "last_seen": datetime(2026, 9, 1, tzinfo=UTC).isoformat(),
            }
        )
    monkeypatch.setattr(labels, "CANDIDATES_PATH", candidates)
    monkeypatch.setattr(labels, "G1_CLUSTERS_PATH", tmp_path / "g1_clusters.csv")
    monkeypatch.setattr(labels, "FREEZE_MARKER", tmp_path / "gold_v1.sha256")
    return World(scratch_dsn, admin_id, tier1_id, alert_id)


def _label(world: World, user_id: str) -> None:
    """One committed `gold_offline` label of `user_id` on the world's alert."""
    with psycopg.connect(world.dsn) as conn:
        conn.execute(
            "INSERT INTO triage_labels (alert_id, labeler_id, source, label, confidence) "
            "VALUES (%s, %s, 'gold_offline', 'benign', '2')",
            (world.alert_id, user_id),
        )


def _labels_of(world: World, user_id: str) -> list[str]:
    """What a second connection sees: only committed rows."""
    with psycopg.connect(world.dsn) as conn:
        return [
            row[0]
            for row in conn.execute(
                "SELECT alert_id FROM triage_labels WHERE labeler_id = %s", (user_id,)
            ).fetchall()
        ]


def _events(world: World, event_type: str, actor_id: str) -> list[Any]:
    with psycopg.connect(world.dsn) as conn:
        return conn.execute(
            "SELECT subject_id, actor_role, payload FROM audit_events "
            "WHERE event_type = %s AND actor_id = %s ORDER BY audit_id",
            (event_type, actor_id),
        ).fetchall()


@pytest.fixture
def real_connection(world, monkeypatch) -> Callable[[Claims], TestClient]:
    """`deps.get_conn` itself, unreplaced, handing out a connection to the scratch database:
    committed on a 2xx, rolled back when the route raises. Only the caller is overridden."""
    monkeypatch.setattr(
        deps.db, "connect", lambda *args, **kwargs: psycopg.connect(world.dsn, autocommit=False)
    )

    def client_for(claims: Claims) -> TestClient:
        main.app.dependency_overrides[deps.current_user] = lambda: claims
        # a 500 must come back as a response here, not as the exception it was raised as
        return TestClient(main.app, raise_server_exceptions=False)

    try:
        yield client_for
    finally:
        main.app.dependency_overrides.pop(deps.current_user, None)


@pytest.mark.db
def test_the_world_keeps_the_redacted_dsn_so_a_failing_test_prints_no_password(world) -> None:
    """`World` holds the `conftest.Dsn` itself, not `str(dsn)`: pytest prints a failing test's arguments
    with `repr`, and only a `Dsn` redacts the password there."""
    assert type(world.dsn) is conftest.Dsn
    assert repr(world.dsn) == repr(conftest.redact_dsn(world.dsn))
    assert repr(world.dsn) in repr(world)


# ---------------------------------------------------------------------------
# The caller's connection is the request's one transaction
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_undo_commits_the_delete_and_its_event_together(world, real_connection) -> None:
    """The control for the two tests below: the same request, nothing failing, is visible on a
    second connection, so those tests can see a commit if one happens."""
    _label(world, world.admin_id)
    assert _labels_of(world, world.admin_id) == [world.alert_id]

    resp = real_connection(_claims(world.admin_id, "admin")).post(UNDO, json={})
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"undone_cluster_id": world.alert_id, "done": 0, "total": 1}
    assert _labels_of(world, world.admin_id) == []
    ((subject, role, payload),) = _events(world, "label.created", world.admin_id)
    assert (subject, role) == (world.alert_id, "admin")
    assert payload == {"undo": True, "alert_id": world.alert_id, "labeler_id": world.admin_id}


def _boom(*args: Any, **kwargs: Any) -> None:
    raise RuntimeError("injected failure")


@pytest.mark.db
@pytest.mark.parametrize(
    "failing",
    ["write_event", "next_unlabelled"],
    ids=["the event insert, inside undo_last", "the progress read, after undo_last"],
)
def test_a_failure_after_the_delete_leaves_the_label_and_no_event(
    world, real_connection, monkeypatch, failing
) -> None:
    """`undo_last` has already run its DELETE when the next statement fails: the request's
    rollback must bring the label back, and nothing must say it was undone."""
    _label(world, world.admin_id)
    monkeypatch.setattr(labels, failing, _boom)

    resp = real_connection(_claims(world.admin_id, "admin")).post(UNDO, json={})
    assert resp.status_code == 500
    assert _labels_of(world, world.admin_id) == [world.alert_id]
    assert _events(world, "label.created", world.admin_id) == []


# ---------------------------------------------------------------------------
# tier1 and tier2 are refused, and the refusal is audited
# ---------------------------------------------------------------------------


@pytest.mark.db
@pytest.mark.parametrize("role", ["tier1", "tier2"])
@pytest.mark.parametrize(
    "kwargs",
    [{"json": {}}, {}],
    ids=["with a JSON body", "bare: the role answers before the body is read"],
)
def test_undo_is_403_for_an_analyst_writes_authz_denied_and_deletes_nothing(
    world, real_connection, role, kwargs
) -> None:
    caller = world.tier1_id  # a users row; the caller's role is what the token says
    _label(world, caller)

    resp = real_connection(_claims(caller, role)).post(UNDO, **kwargs)
    assert resp.status_code == 403
    assert resp.json() == {"detail": "forbidden"}
    assert _labels_of(world, caller) == [world.alert_id]
    assert _events(world, "label.created", caller) == []
    ((subject, actor_role, payload),) = _events(world, "authz.denied", caller)
    assert (subject, actor_role) == (UNDO, "analyst")
    assert payload == {"required": ["admin"], "role": role, "method": "POST"}


@pytest.mark.db
@pytest.mark.parametrize("role", ["tier1", "tier2"])
def test_next_is_403_for_an_analyst_writes_authz_denied_and_shows_no_cluster(
    world, real_connection, role
) -> None:
    caller = world.tier1_id

    resp = real_connection(_claims(caller, role)).get(NEXT, params={"labeler": caller})
    assert resp.status_code == 403
    assert resp.json() == {"detail": "forbidden"}  # no cluster, no flag, no progress
    ((subject, actor_role, payload),) = _events(world, "authz.denied", caller)
    assert (subject, actor_role) == (NEXT, "analyst")
    assert payload == {"required": ["admin"], "role": role, "method": "GET"}


@pytest.mark.db
def test_the_same_requests_are_served_to_an_admin(world, real_connection) -> None:
    """Without this the two 403 tests would also pass on a world where nothing is served."""
    client = real_connection(_claims(world.admin_id, "admin"))
    resp = client.get(NEXT, params={"labeler": world.admin_id})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["cluster_id"] == world.alert_id and body["frozen"] is False
    assert body["candidates_present"] is True
    assert client.post(UNDO, json={}).status_code == 404
    assert _events(world, "authz.denied", world.admin_id) == []
