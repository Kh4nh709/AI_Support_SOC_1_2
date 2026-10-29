"""S0 — `POST /webhook/alerts` must stay answerable under concurrent load.

The production hang (27/10, ~12:19): n8n sent about ten concurrent `POST /webhook/alerts`,
the first three got 201, then the app answered nothing at all — not even a wrong key, which
is a 401 that touches no database — until it was restarted.

Mechanism (confirmed by the red step of the first test below): the route
is `async def` but ran `intake.receive` — blocking psycopg I/O — on the event loop. With
`PULL_ENABLED=false` every accepted alert upserts the ONE `source_heartbeat` row, so request A
holds that row's lock until its `Conn` teardown commits, and that commit has to be scheduled by
the very loop request B is blocking inside its own `UPDATE`. A needs the loop to release the
lock, B holds the loop to wait for the lock, and the wait had no bound. The fix runs the
blocking intake in the threadpool and bounds every wait with `lock_timeout`/`statement_timeout`.

Why these tests are built the way they are:
- real concurrency: `httpx.AsyncClient` over `ASGITransport` drives the real ASGI app on one
  real event loop, and `asyncio.gather` puts every request in flight at once. The existing
  `TestClient` tests are sequential and so can never meet the bug.
- a FRESH connection per request (the `Conn` override below delegates to the real
  `deps.get_conn`, with `db.connect` aimed at the scratch database), never one shared
  connection: one shared connection serialises everything and hides the deadlock.
- the burst runs on a worker thread with a watchdog on the test's own thread. A wedged loop is
  blocked inside a C-level wait, so no `asyncio.wait_for` on that loop can ever fire; only a
  clock outside the loop turns "hangs forever" into a failed test.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import traceback
import uuid
from dataclasses import replace
from functools import partial
from pathlib import Path

import httpx
import psycopg
import pytest
from app.infra import config, db
from app.web import deps, main
from app.web.routers import webhook

from tests import conftest

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
ALERT_BARE = json.loads((FIXTURES / "alert_40112.json").read_text(encoding="utf-8"))["_source"]

ALLOWED_HOST = "10.0.0.7"
KEY = "k"
N_ALERTS = 24  # distinct, all valid: the brief asks for at least 20 in flight together
ANSWER_WITHIN_S = 15  # the in-loop bound (`asyncio.wait_for`)
WATCHDOG_S = 30  # the out-of-loop bound: a wedged loop cannot honour the first one


def _uid(_label: str) -> str:
    """A fresh alert id of the Wazuh form `<epoch>.<n>`: the webhook refuses any id off ①'s
    `alert_id` pattern (INT-T02, DEC-211 R6). `_label` only says, at the call site, what it is for.
    """
    return f"{1_790_000_000 + uuid.uuid4().int % 10_000_000}.{uuid.uuid4().int % 10**9}"


def _alert(alert_id: str) -> bytes:
    doc = json.loads(json.dumps(ALERT_BARE))
    doc["id"] = alert_id
    return json.dumps(doc).encode("utf-8")


def _cfg(**overrides) -> config.Config:
    fields = {
        "WEBHOOK_API_KEY": KEY,
        "WEBHOOK_IP_ALLOWLIST": ["10.0.0.0/8"],
        "PULL_ENABLED": False,  # the live config: every accepted alert stamps source_heartbeat
        **overrides,
    }
    return replace(config.Config(), **fields)


# --------------------------------------------------------------------------
# scratch database — its own, because the burst COMMITS (the shared `db`
# fixture's never-commit isolation cannot show a lock held across requests).
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def scratch_dsn():
    if shutil.which("psql") is None or shutil.which("createdb") is None:
        pytest.skip("psql/createdb not on PATH — cannot build the webhook concurrency database")
    session = os.environ.get("TEST_DATABASE_URL", conftest.DEFAULT_TEST_DATABASE_URL)
    dbname = f"{conftest._dbname(session)}_webhook_conc_test"
    subprocess.run(["dropdb", "--if-exists", dbname], check=True, capture_output=True)
    subprocess.run(["createdb", dbname], check=True, capture_output=True)
    dsn = f"postgresql:///{dbname}"
    result = subprocess.run(
        ["bash", "scripts/migrate.sh", dsn],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"scratch migrate failed:\n{result.stderr}"
    try:
        yield dsn
    finally:
        _terminate_backends(dbname)
        subprocess.run(["dropdb", "--if-exists", dbname], check=False, capture_output=True)


def _terminate_backends(dbname: str) -> None:
    """End every other session on `dbname`: un-wedges a loop thread stuck in a lock wait so a
    failed run does not leave it (and its locks) behind, and lets `dropdb` go through."""
    try:
        with psycopg.connect("postgresql:///postgres", autocommit=True) as admin:
            admin.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = %s AND pid <> pg_backend_pid()",
                (dbname,),
            )
    except psycopg.Error:
        pass


def _dbname_of(dsn: str) -> str:
    return dsn.rsplit("/", 1)[1]


def _sessions(dbname: str) -> str:
    """What the other sessions on `dbname` are doing — the evidence for a failure message:
    `idle in transaction` holders whose commit never came, and who waits on a `Lock`."""
    try:
        with psycopg.connect("postgresql:///postgres", autocommit=True) as admin:
            rows = admin.execute(
                "SELECT state, coalesce(wait_event_type, '-'), coalesce(wait_event, '-'), count(*) "
                "FROM pg_stat_activity WHERE datname = %s AND pid <> pg_backend_pid() "
                "GROUP BY 1, 2, 3 ORDER BY 4 DESC",
                (dbname,),
            ).fetchall()
    except psycopg.Error as exc:
        return f"(sessions unavailable: {type(exc).__name__})"
    return "; ".join(f"{n} x {state} [{kind}/{event}]" for state, kind, event, n in rows)


@pytest.fixture
def app_on_scratch(scratch_dsn, monkeypatch):
    """The real app; `Conn` is a per-request factory over the scratch database.

    `fresh_conn` delegates to the real `deps.get_conn` (commit on success, rollback on any
    exception, close always) with `db.connect` aimed at the scratch DSN — so production's
    dependency, teardown ordering and `scope="function"` are what is under test, only the
    DSN differs.
    """
    monkeypatch.setattr(db, "connect", partial(db.connect, scratch_dsn))

    def fresh_conn():
        yield from deps.get_conn()

    main.app.dependency_overrides[deps.get_conn] = fresh_conn
    main.app.dependency_overrides[deps.get_config] = lambda: _cfg()
    try:
        yield main.app
    finally:
        main.app.dependency_overrides.pop(deps.get_conn, None)
        main.app.dependency_overrides.pop(deps.get_config, None)


def _run_on_loop_thread(make_coro, scratch_dsn: str, what: str):
    """`asyncio.run(make_coro())` on a worker thread, bounded by a clock outside the loop."""
    box: dict = {}

    def target() -> None:
        try:
            box["result"] = asyncio.run(make_coro())
        except BaseException as exc:  # noqa: BLE001 — handed back to the test thread
            box["error"] = exc

    thread = threading.Thread(target=target, name="webhook-loop", daemon=True)
    thread.start()
    thread.join(WATCHDOG_S)
    if thread.is_alive():
        frame = sys._current_frames().get(thread.ident)
        where = "".join(traceback.format_stack(frame)[-6:]) if frame is not None else "?"
        sessions = _sessions(_dbname_of(scratch_dsn))
        _terminate_backends(_dbname_of(scratch_dsn))
        thread.join(10)
        pytest.fail(
            f"{what}: no answer in {WATCHDOG_S}s — the event loop is wedged, or a request sits in "
            f"a database wait nothing bounds. Database sessions: {sessions}. "
            f"The loop thread is parked at:\n{where}"
        )
    if "error" in box:
        raise box["error"]
    return box["result"]


def _transport() -> httpx.ASGITransport:
    return httpx.ASGITransport(
        app=main.app, client=(ALLOWED_HOST, 1234), raise_app_exceptions=False
    )


# --------------------------------------------------------------------------
# the acceptance test
# --------------------------------------------------------------------------


@pytest.mark.db
def test_concurrent_webhook_burst_is_answered_and_a_wrong_key_stays_401(
    app_on_scratch, scratch_dsn
) -> None:
    ids = [_uid("burst") for _ in range(N_ALERTS)]
    duplicate_id = _uid("twin")
    posts: list[tuple[str, bytes, str]] = [("alert", _alert(i), KEY) for i in ids]
    # Two copies of ONE alert in flight together: exactly one is 201, the other a genuine 409
    # (the loser waits on the winner's unique-index entry, which is a wait of its own).
    posts += [("twin", _alert(duplicate_id), KEY), ("twin", _alert(duplicate_id), KEY)]
    # Wrong keys in the middle of the batch: a 401 touches no database at all.
    posts.insert(len(posts) // 3, ("wrong-key", _alert(_uid("nokey")), "not-the-key"))
    posts.insert(2 * len(posts) // 3, ("wrong-key", _alert(_uid("nokey")), "also-wrong"))
    # A body with no rule.id: a 400 whose rejected_alerts row must be committed before the raise.
    posts.insert(len(posts) // 2, ("rejected", json.dumps({"id": _uid("norule")}).encode(), KEY))
    assert len(posts) >= 20

    async def burst() -> list[tuple[str, int, float, dict]]:
        async with httpx.AsyncClient(transport=_transport(), base_url="http://webhook") as client:

            async def one(kind: str, body: bytes, key: str):
                started = time.monotonic()
                response = await client.post(
                    "/webhook/alerts", content=body, headers={"X-API-Key": key}
                )
                try:
                    payload = response.json()
                except ValueError:
                    payload = {}
                return kind, response.status_code, time.monotonic() - started, payload

            return await asyncio.wait_for(
                asyncio.gather(*(one(*p) for p in posts)), timeout=ANSWER_WITHIN_S
            )

    with psycopg.connect(scratch_dsn) as check:
        (rejected_before,) = check.execute("SELECT count(*) FROM rejected_alerts").fetchone()

    results = _run_on_loop_thread(burst, scratch_dsn, "20+ concurrent POST /webhook/alerts")

    assert len(results) == len(posts), "every request must be answered"
    by_kind: dict[str, list[tuple[int, float, dict]]] = {}
    for kind, status, elapsed, payload in results:
        by_kind.setdefault(kind, []).append((status, elapsed, payload))

    assert [s for s, _, _ in by_kind["alert"]] == [201] * N_ALERTS
    assert sorted(s for s, _, _ in by_kind["twin"]) == [201, 409]
    assert [s for s, _, _ in by_kind["wrong-key"]] == [401, 401]
    assert all(elapsed < 5 for _, elapsed, _ in by_kind["wrong-key"]), "a 401 must be prompt"
    assert [(s, p) for s, _, p in by_kind["rejected"]] == [
        (400, {"detail": {"missing": "rule.id"}})
    ]

    with psycopg.connect(scratch_dsn) as check:
        (intake_rows,) = check.execute(
            "SELECT count(*) FROM intake WHERE source_alert_id = ANY(%s)", (ids + [duplicate_id],)
        ).fetchone()
        (job_rows,) = check.execute(
            "SELECT count(*) FROM jobs j JOIN intake i ON j.subject_id = i.intake_id::text "
            "WHERE j.job_type = 'pipeline' AND i.source_alert_id = ANY(%s)",
            (ids + [duplicate_id],),
        ).fetchone()
        (rejected_after,) = check.execute("SELECT count(*) FROM rejected_alerts").fetchone()
        (stamped,) = check.execute(
            "SELECT count(*) FROM source_heartbeat WHERE last_alert_at IS NOT NULL"
        ).fetchone()
    assert intake_rows == N_ALERTS + 1
    assert job_rows == N_ALERTS + 1, "one pipeline job per accepted alert, none for the 409"
    assert rejected_after == rejected_before + 1, "the 400's rejected_alerts row was committed"
    assert stamped == 1, "PULL_ENABLED=false: the accepted alerts stamped source_heartbeat"


# --------------------------------------------------------------------------
# defence in depth: a wait that does not end is bounded, and costs one request —
# answered 503 "busy" + Retry-After (Director ruling R1: 500 is outside the frozen set)
# --------------------------------------------------------------------------


def _post_one(scratch_dsn: str, body: bytes, key: str, what: str) -> tuple[int, dict, dict]:
    """One POST on its own loop thread: (status, lower-cased headers, JSON body or {})."""

    async def go() -> tuple[int, dict, dict]:
        async with httpx.AsyncClient(transport=_transport(), base_url="http://webhook") as client:
            response = await client.post(
                "/webhook/alerts", content=body, headers={"X-API-Key": key}
            )
            try:
                payload = response.json()
            except ValueError:
                payload = {}
            return response.status_code, dict(response.headers), payload

    return _run_on_loop_thread(go, scratch_dsn, what)


# Which of the two bounds fires: the other is made too long to matter.
_WHICH_BOUND = [
    pytest.param("400ms", "30s", id="lock_timeout"),
    pytest.param("30s", "400ms", id="statement_timeout"),
]


@pytest.mark.db
@pytest.mark.parametrize(("lock_timeout", "statement_timeout"), _WHICH_BOUND)
def test_a_held_heartbeat_lock_is_a_503_busy_for_one_request_and_the_loop_keeps_answering(
    app_on_scratch, scratch_dsn, monkeypatch, lock_timeout, statement_timeout
) -> None:
    """Someone else holds the `source_heartbeat` row (a long transaction, the worker, a stuck
    session). The accepted-alert UPDATE must give up after `lock_timeout` (or `statement_timeout`)
    instead of waiting for ever, and say so as `503 busy` with a `Retry-After` — not a 500, which
    is outside the webhook's frozen status set. Meanwhile the loop answers a wrong key at once, the
    timed-out request's transaction is gone (the holder is the only open one) and left no intake
    row, and a retry of the same alert once the lock is released is a clean 201."""
    monkeypatch.setattr(webhook, "_LOCK_TIMEOUT", lock_timeout)
    monkeypatch.setattr(webhook, "_STATEMENT_TIMEOUT", statement_timeout)
    stuck_id = _uid("stuck")

    holder = psycopg.connect(scratch_dsn)
    try:
        holder.execute(
            "INSERT INTO source_heartbeat (manager_id, last_seen_at) VALUES ('indexer', now()) "
            "ON CONFLICT (manager_id) DO UPDATE SET last_seen_at = now()"
        )  # an open transaction now holds the row lock

        async def while_held() -> tuple[tuple[int, dict, dict, float], tuple[int, float]]:
            async with httpx.AsyncClient(
                transport=_transport(), base_url="http://webhook"
            ) as client:

                async def post(key: str):
                    started = time.monotonic()
                    response = await client.post(
                        "/webhook/alerts", content=_alert(stuck_id), headers={"X-API-Key": key}
                    )
                    try:
                        payload = response.json()
                    except ValueError:
                        payload = {}
                    elapsed = time.monotonic() - started
                    return response.status_code, dict(response.headers), payload, elapsed

                stuck, wrong = await asyncio.wait_for(
                    asyncio.gather(post(KEY), post("wrong")), timeout=ANSWER_WITHIN_S
                )
                return stuck, (wrong[0], wrong[3])

        (stuck_status, stuck_headers, stuck_body, stuck_s), (wrong_status, wrong_s) = (
            _run_on_loop_thread(
                while_held, scratch_dsn, "POST while the heartbeat row is locked by another session"
            )
        )
        with psycopg.connect(scratch_dsn) as check:
            (open_transactions,) = check.execute(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                "AND state = 'idle in transaction' AND pid <> pg_backend_pid()"
            ).fetchone()
    finally:
        holder.rollback()
        holder.close()

    assert wrong_status == 401 and wrong_s < 2, "the loop stays responsive while a request waits"
    assert stuck_status == 503, "a bounded wait that timed out is 'busy', never a 500"
    assert stuck_body == {"detail": "busy"}, "distinguishable from the disabled 503"
    assert stuck_headers.get("retry-after") == "2"
    assert 0.3 <= stuck_s < 10, f"the wait is bounded by the timeout, took {stuck_s:.1f}s"
    assert open_transactions == 1, "only the holder is still in a transaction; the 503 rolled back"

    with psycopg.connect(scratch_dsn) as check:
        (left_behind,) = check.execute(
            "SELECT count(*) FROM intake WHERE source_alert_id = %s", (stuck_id,)
        ).fetchone()
    assert left_behind == 0, "the timed-out request rolled back; it left no intake row"

    retry_status, _, retry_body = _post_one(
        scratch_dsn, _alert(stuck_id), KEY, "retry after the lock is released"
    )
    assert retry_status == 201 and "intake_id" in retry_body


@pytest.mark.db
@pytest.mark.parametrize(
    ("raised", "expected"),
    [
        pytest.param(psycopg.errors.LockNotAvailable("lock_timeout"), 503, id="LockNotAvailable"),
        pytest.param(psycopg.errors.QueryCanceled("statement_timeout"), 503, id="QueryCanceled"),
        # The catch is exactly those two classes: a real bug, or any other database error, is
        # still a 500.
        pytest.param(psycopg.errors.DeadlockDetected("deadlock"), 500, id="DeadlockDetected"),
        pytest.param(psycopg.OperationalError("connection lost"), 500, id="OperationalError"),
        pytest.param(RuntimeError("a bug"), 500, id="RuntimeError"),
    ],
)
def test_only_the_two_timeout_errors_map_to_503_busy(
    app_on_scratch, scratch_dsn, monkeypatch, raised, expected
) -> None:
    def boom(*_args, **_kwargs):
        raise raised

    monkeypatch.setattr(webhook.intake, "receive", boom)
    status, headers, body = _post_one(scratch_dsn, _alert(_uid("map")), KEY, "mapped error")

    assert status == expected
    if expected == 503:
        assert body == {"detail": "busy"}
        assert headers.get("retry-after") == "2"
    else:
        assert "retry-after" not in headers


@pytest.mark.db
def test_the_disabled_503_stays_distinguishable_from_the_busy_503(
    app_on_scratch, scratch_dsn
) -> None:
    main.app.dependency_overrides[deps.get_config] = lambda: _cfg(WEBHOOK_API_KEY="")
    status, headers, body = _post_one(scratch_dsn, _alert(_uid("off")), KEY, "disabled webhook")

    assert status == 503
    assert body == {"detail": "webhook disabled"}
    assert "retry-after" not in headers
