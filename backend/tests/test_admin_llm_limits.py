"""`PUT /api/admin/llm/limits` (P11-T03, spec §5.2, DEC-200 item 3).

Admin only; any of `cap_usd`, `quota_per_24h`, `timeout_s` as JSON integers inside the bounds
of the Owner's decision 2 (cap 1-1000, quota 1-200, timeout 10-600, the timeout's top
held to what the job lock allows, DEC-202). In the request's own
transaction it reads the effective limits, upserts only the keys that change, and writes ONE
`admin.settings_changed` event `{changes: [{key, old, new}]}` (a change over a clamped timeout also
carries `stored`). An empty or unchanged body
writes nothing. Limits that cannot be read answer `503 {reason: "limits_unavailable"}`.

Every test runs inside the `db` fixture's transaction and is rolled back: the overridden
`get_conn` yields that connection and never commits (the `test_tier2_api.py` pattern).
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import replace

import psycopg
import pytest
from app.infra import config
from app.infra.auth import Claims
from app.infra.settings import KEYS, bounds, effective_limits, from_config
from app.web import deps, main
from app.web.routers import admin_llm
from fastapi.testclient import TestClient

pytestmark = pytest.mark.db

URL = "/api/admin/llm/limits"

_CFG = replace(
    config.Config(), LLM_MONTHLY_USD_CAP=30, ANALYZE_QUOTA_PER_USER_DAY=25, LLM_TIMEOUT_S=120
)
_FIELD = {
    "cap_usd": "LLM_MONTHLY_USD_CAP",
    "quota_per_24h": "ANALYZE_QUOTA_PER_USER_DAY",
    "timeout_s": "LLM_TIMEOUT_S",
}


def _make_user(
    conn: psycopg.Connection, *, role: str = "admin", display_name: str = "Quản trị viên"
) -> tuple[str, str]:
    user_id = str(uuid.uuid4())
    username = f"user-{user_id[:8]}"
    conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash) "
        "VALUES (%s, %s, %s, %s, 'x')",
        (user_id, username, display_name, role),
    )
    return user_id, username


class _Client:
    def __init__(self, user_id: str, username: str) -> None:
        self.http = TestClient(main.app, follow_redirects=False)
        self.user_id = user_id
        self.username = username
        self.role = "admin"

    def claims(self) -> Claims:
        return Claims(
            user_id=self.user_id, username=self.username, role=self.role, iat=0.0, exp=0.0
        )

    def put(self, body=None, **kwargs):
        return self.http.put(URL, json=body, **kwargs) if body is not None else self.http.put(URL)


@pytest.fixture
def client(db):
    user_id, username = _make_user(db)
    c = _Client(user_id, username)

    def get_conn():
        # `deps.get_conn`'s shape minus the commit: this connection is the `db` fixture's, and
        # its own teardown rolls everything back.
        try:
            yield db
        except BaseException:
            db.rollback()
            raise

    main.app.dependency_overrides[deps.get_conn] = get_conn
    main.app.dependency_overrides[deps.get_config] = lambda: _CFG
    main.app.dependency_overrides[deps.current_user] = c.claims
    try:
        yield c
    finally:
        for dep in (deps.get_conn, deps.get_config, deps.current_user):
            main.app.dependency_overrides.pop(dep, None)


def _settings_rows(db) -> dict[str, int]:
    return dict(db.execute("SELECT key, value FROM settings").fetchall())


def _events(db, actor_id: str) -> list[tuple]:
    return db.execute(
        "SELECT event_type, subject_id, actor_role, actor_id::text, payload FROM audit_events "
        "WHERE event_type = 'admin.settings_changed' AND actor_id = %s ORDER BY audit_id",
        (actor_id,),
    ).fetchall()


# ── admin only ────────────────────────────────────────────────────────────────────────────


def test_every_route_of_the_module_carries_the_admin_dependency():
    routes = [r for r in admin_llm.router.routes if getattr(r, "methods", None)]
    assert routes, "the router has no routes"
    for route in routes:
        calls = {d.call for d in route.dependant.dependencies}
        assert admin_llm.require_admin in calls, f"{sorted(route.methods)} {route.path}"
    assert {(m, r.path) for r in routes for m in r.methods} >= {("PUT", URL)}


@pytest.mark.parametrize("role", ["tier1", "tier2"])
def test_a_non_admin_gets_403_writes_authz_denied_and_changes_nothing(
    client, db, monkeypatch, role
):
    client.role = role
    seen_at_commit: list[list[str]] = []

    def _spy_commit() -> None:
        rows = db.execute(
            "SELECT event_type FROM audit_events WHERE actor_id = %s ORDER BY audit_id",
            (client.user_id,),
        ).fetchall()
        seen_at_commit.append([r[0] for r in rows])

    monkeypatch.setattr(db, "commit", _spy_commit)

    resp = client.put({"cap_usd": 99})

    assert resp.status_code == 403
    assert seen_at_commit == [["authz.denied"]]
    assert _settings_rows(db) == {}


# ── nothing to do ─────────────────────────────────────────────────────────────────────────


def test_an_empty_body_writes_nothing_and_answers_the_effective_limits(client, db):
    resp = client.put({})

    assert resp.status_code == 200
    limits = resp.json()["limits"]
    assert (limits["cap_usd"], limits["quota_per_24h"], limits["timeout_s"]) == (30, 25, 120)
    assert set(limits["sources"]) == set(KEYS)
    assert _settings_rows(db) == {}
    assert _events(db, client.user_id) == []


def test_no_body_at_all_is_the_same_as_an_empty_one(client, db):
    resp = client.put()

    assert resp.status_code == 200
    assert resp.json()["limits"]["cap_usd"] == 30
    assert _settings_rows(db) == {}
    assert _events(db, client.user_id) == []


def test_a_value_equal_to_the_effective_one_writes_nothing(client, db):
    resp = client.put({"cap_usd": 30, "quota_per_24h": 25, "timeout_s": 120})

    assert resp.status_code == 200
    assert _settings_rows(db) == {}
    assert _events(db, client.user_id) == []
    assert {s["source"] for s in resp.json()["limits"]["sources"].values()} == {"env"}


def test_saving_the_same_change_twice_writes_one_event(client, db):
    assert client.put({"cap_usd": 50}).status_code == 200
    again = client.put({"cap_usd": 50})

    assert again.status_code == 200
    assert len(_events(db, client.user_id)) == 1


# ── a change ──────────────────────────────────────────────────────────────────────────────


def test_a_change_writes_the_row_one_event_and_answers_the_new_limits(client, db):
    resp = client.put({"cap_usd": 50})

    assert resp.status_code == 200
    assert _settings_rows(db) == {"LLM_MONTHLY_USD_CAP": 50}
    (updated_by,) = db.execute(
        "SELECT updated_by::text FROM settings WHERE key = 'LLM_MONTHLY_USD_CAP'"
    ).fetchone()
    assert updated_by == client.user_id

    events = _events(db, client.user_id)
    assert len(events) == 1
    event_type, subject_id, actor_role, actor_id, payload = events[0]
    assert (event_type, actor_role, actor_id) == (
        "admin.settings_changed",
        "admin",
        client.user_id,
    )
    assert subject_id == "llm_limits"
    assert payload == {"changes": [{"key": "LLM_MONTHLY_USD_CAP", "old": 30, "new": 50}]}

    limits = resp.json()["limits"]
    assert (limits["cap_usd"], limits["quota_per_24h"], limits["timeout_s"]) == (50, 25, 120)
    cap = limits["sources"]["LLM_MONTHLY_USD_CAP"]
    assert cap["source"] == "web"
    assert cap["updated_by_name"] == "Quản trị viên"
    assert cap["updated_at"] is not None
    assert limits["sources"]["LLM_TIMEOUT_S"] == {
        "source": "env",
        "updated_at": None,
        "updated_by_name": None,
        "clamped": False,
    }


def test_several_changes_are_one_event_and_only_the_changed_keys_are_in_it(client, db):
    resp = client.put({"timeout_s": 90, "cap_usd": 30, "quota_per_24h": 10})  # cap is unchanged

    assert resp.status_code == 200
    assert _settings_rows(db) == {"ANALYZE_QUOTA_PER_USER_DAY": 10, "LLM_TIMEOUT_S": 90}
    events = _events(db, client.user_id)
    assert len(events) == 1
    assert events[0][4] == {
        "changes": [
            {"key": "ANALYZE_QUOTA_PER_USER_DAY", "old": 25, "new": 10},
            {"key": "LLM_TIMEOUT_S", "old": 120, "new": 90},
        ]
    }


def test_the_old_value_of_a_second_change_is_the_first_web_value(client, db):
    client.put({"cap_usd": 50})
    resp = client.put({"cap_usd": 70})

    assert resp.status_code == 200
    events = _events(db, client.user_id)
    assert [e[4] for e in events] == [
        {"changes": [{"key": "LLM_MONTHLY_USD_CAP", "old": 30, "new": 50}]},
        {"changes": [{"key": "LLM_MONTHLY_USD_CAP", "old": 50, "new": 70}]},
    ]
    assert _settings_rows(db) == {"LLM_MONTHLY_USD_CAP": 70}


def test_the_row_of_a_second_change_is_stamped_again(client, db):
    other_id, _ = _make_user(db, display_name="Người khác")
    db.execute(
        "INSERT INTO settings (key, value, updated_at, updated_by) VALUES "
        "('LLM_MONTHLY_USD_CAP', 40, now() - interval '1 day', %s)",
        (other_id,),
    )
    before = db.execute(
        "SELECT updated_at FROM settings WHERE key = 'LLM_MONTHLY_USD_CAP'"
    ).fetchone()[0]

    resp = client.put({"cap_usd": 41})

    assert resp.status_code == 200
    updated_at, updated_by = db.execute(
        "SELECT updated_at, updated_by::text FROM settings WHERE key = 'LLM_MONTHLY_USD_CAP'"
    ).fetchone()
    assert updated_at > before and updated_by == client.user_id


def test_updated_by_name_is_the_display_name_or_the_username_and_null_for_env(client, db):
    named_id, _ = _make_user(db, display_name="Chị Lan")
    bare_id, bare_username = _make_user(db, display_name="")
    db.execute(
        "INSERT INTO settings (key, value, updated_by) VALUES "
        "('LLM_MONTHLY_USD_CAP', 40, %s), ('LLM_TIMEOUT_S', 90, %s)",
        (named_id, bare_id),
    )

    resp = client.put({})

    sources = resp.json()["limits"]["sources"]
    assert sources["LLM_MONTHLY_USD_CAP"]["updated_by_name"] == "Chị Lan"
    assert sources["LLM_TIMEOUT_S"]["updated_by_name"] == bare_username
    assert sources["ANALYZE_QUOTA_PER_USER_DAY"]["updated_by_name"] is None


def test_the_answer_is_what_the_accessor_reads_back(client, db):
    resp = client.put({"cap_usd": 12, "quota_per_24h": 3, "timeout_s": 100})

    limits = effective_limits(db, _CFG)
    body = resp.json()["limits"]
    assert (body["cap_usd"], body["quota_per_24h"], body["timeout_s"]) == (12, 3, 100)
    assert (limits.cap_usd, limits.quota_per_24h, limits.timeout_s) == (12, 3, 100)
    assert {s["source"] for s in body["sources"].values()} == {"web"}


def test_limits_out_is_the_shape_the_usage_route_will_embed(db):
    plain = admin_llm.limits_out(db, from_config(_CFG))

    assert plain == {
        "cap_usd": 30,
        "quota_per_24h": 25,
        "timeout_s": 120,
        "sources": {
            key: {"source": "env", "updated_at": None, "updated_by_name": None, "clamped": False}
            for key in KEYS
        },
        # what the page's form may offer: the timeout's top is the derived one (DEC-202)
        "bounds": {
            "cap_usd": {"min": 1, "max": 1000},
            "quota_per_24h": {"min": 1, "max": 200},
            "timeout_s": {"min": 10, "max": 120},
        },
    }


def test_limits_out_reports_a_clamp_and_the_derived_maximum(db):
    admin, _ = _make_user(db)
    db.execute(
        "INSERT INTO settings (key, value, updated_by) VALUES ('LLM_TIMEOUT_S', 600, %s)", (admin,)
    )
    cfg = replace(_CFG, JOB_LOCK_TIMEOUT_S=200)  # ceiling 70

    out = admin_llm.limits_out(db, effective_limits(db, cfg))

    assert out["timeout_s"] == 70
    assert out["sources"]["LLM_TIMEOUT_S"]["source"] == "web"
    assert out["sources"]["LLM_TIMEOUT_S"]["clamped"] is True
    assert out["sources"]["LLM_MONTHLY_USD_CAP"]["clamped"] is False
    assert out["bounds"]["timeout_s"] == {"min": 10, "max": 70}


def test_a_put_over_a_clamped_timeout_answers_the_clamp_and_the_effective_old_value(client, db):
    db.execute(
        "INSERT INTO settings (key, value, updated_by) VALUES ('LLM_TIMEOUT_S', 600, %s)",
        (client.user_id,),
    )

    seen = client.put({})
    changed = client.put({"timeout_s": 90})

    body = seen.json()["limits"]
    assert body["timeout_s"] == 120 and body["sources"]["LLM_TIMEOUT_S"]["clamped"] is True
    assert body["bounds"]["timeout_s"] == {"min": 10, "max": 120}
    assert changed.json()["limits"]["sources"]["LLM_TIMEOUT_S"]["clamped"] is False
    # the audit row names the value the system was really running with (`old`), and the stored
    # 600 that the clamp hid (`stored`), so the drop from 600 to 120 is explained (P11-T20 row 6)
    assert _events(db, client.user_id)[0][4] == {
        "changes": [{"key": "LLM_TIMEOUT_S", "old": 120, "new": 90, "stored": 600}]
    }


def test_only_a_clamped_key_carries_stored_in_the_change_entry(client, db):
    """P11-T20 row 6 (P11-T03 review N3). The stored 600 is above the ceiling of 120, so the
    timeout's effective value is a clamp; the cap's stored 40 is not. A PUT that changes both
    gives each its own entry, and only the clamped one names `stored`. A PUT that leaves the
    clamped key alone writes no `stored` at all."""
    for key, value in (("LLM_TIMEOUT_S", 600), ("LLM_MONTHLY_USD_CAP", 40)):
        db.execute(
            "INSERT INTO settings (key, value, updated_by) VALUES (%s, %s, %s)",
            (key, value, client.user_id),
        )

    both = client.put({"cap_usd": 50, "timeout_s": 90})
    cap_only = client.put({"cap_usd": 60})  # the timeout is no longer clamped: 90 is stored now

    assert both.status_code == 200 and cap_only.status_code == 200
    first, second = (event[4] for event in _events(db, client.user_id))
    assert first == {
        "changes": [
            {"key": "LLM_MONTHLY_USD_CAP", "old": 40, "new": 50},
            {"key": "LLM_TIMEOUT_S", "old": 120, "new": 90, "stored": 600},
        ]
    }
    assert second == {"changes": [{"key": "LLM_MONTHLY_USD_CAP", "old": 50, "new": 60}]}


def test_a_change_that_leaves_the_clamped_timeout_alone_carries_no_stored(client, db):
    db.execute(
        "INSERT INTO settings (key, value, updated_by) VALUES ('LLM_TIMEOUT_S', 600, %s)",
        (client.user_id,),
    )

    resp = client.put({"cap_usd": 55})

    assert resp.status_code == 200
    assert resp.json()["limits"]["sources"]["LLM_TIMEOUT_S"]["clamped"] is True  # still clamped
    assert _events(db, client.user_id)[0][4] == {
        "changes": [{"key": "LLM_MONTHLY_USD_CAP", "old": 30, "new": 55}]
    }


def test_the_put_works_as_the_role_the_app_runs_as(client, db):
    """`app_rw` reaches `settings` through 017's default privileges: the whole route, as that
    role, reads, upserts and writes its event."""
    db.execute("SET LOCAL ROLE app_rw")

    resp = client.put({"cap_usd": 55})

    assert resp.status_code == 200
    assert resp.json()["limits"]["cap_usd"] == 55
    assert len(_events(db, client.user_id)) == 1


def test_the_change_holds_a_lock_until_the_transaction_ends(client, db, _test_database):
    """Two admins saving at once: the second waits for the first, so its `old` values are the
    first one's `new` ones and the audit trail is a chain, not two claims about the same past."""
    assert client.put({"cap_usd": 50}).status_code == 200

    other = psycopg.connect(_test_database)
    try:
        (got,) = other.execute(
            "SELECT pg_try_advisory_xact_lock(hashtext('admin.llm.limits'))"
        ).fetchone()
    finally:
        other.rollback()
        other.close()

    assert got is False


def test_a_second_put_waits_for_the_first_and_reads_the_limits_only_after_it(_test_database):
    """Pins the ORDER of the lock and the read, which the test above (the lock is held at the
    end) cannot: request A holds the lock and has upserted 50 without committing; request B asks
    for 70, and must wait for the lock BEFORE it reads. When A commits, B's one event is
    `{old: 50, new: 70}` — not `old: 30`, the value B would have read with the read first.

    Real connections and real commits, on committed data (the `db` fixture's one open
    transaction cannot show two requests). Request B writes nothing for good: its connection
    is rolled back after its event has been read. Red step: move the lock after the read."""
    dsn = _test_database
    setup = psycopg.connect(dsn)
    a_id, _ = _make_user(setup, display_name="A")
    b_id, b_username = _make_user(setup, display_name="B")
    setup.commit()
    seen: dict = {}

    def get_conn():
        conn = psycopg.connect(dsn)
        try:
            yield conn
            seen["events"] = conn.execute(
                "SELECT payload FROM audit_events WHERE event_type = 'admin.settings_changed' "
                "AND actor_id = %s",
                (b_id,),
            ).fetchall()
        finally:
            conn.rollback()  # B's rows and event are never committed
            conn.close()

    def waiting_on_an_advisory_lock() -> bool:
        (count,) = setup.execute(
            "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted "
            "AND database = (SELECT oid FROM pg_database WHERE datname = current_database())"
        ).fetchone()
        return count > 0

    main.app.dependency_overrides[deps.get_conn] = get_conn
    main.app.dependency_overrides[deps.get_config] = lambda: _CFG
    main.app.dependency_overrides[deps.current_user] = lambda: Claims(
        user_id=b_id, username=b_username, role="admin", iat=0.0, exp=0.0
    )
    a = psycopg.connect(dsn)
    answer: dict = {}
    try:
        a.execute("SELECT pg_advisory_xact_lock(hashtext('admin.llm.limits'))")
        a.execute(
            "INSERT INTO settings (key, value, updated_by) VALUES ('LLM_MONTHLY_USD_CAP', 50, %s)",
            (a_id,),
        )

        def request_b() -> None:
            answer["resp"] = TestClient(main.app).put(URL, json={"cap_usd": 70})

        thread = threading.Thread(target=request_b)
        thread.start()
        deadline = time.monotonic() + 15
        while not waiting_on_an_advisory_lock() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert waiting_on_an_advisory_lock(), "request B never reached the lock"
        a.commit()  # A is done: B may go on
        thread.join(15)
        assert not thread.is_alive()
        setup.rollback()

        assert answer["resp"].status_code == 200, answer["resp"].text
        assert [row[0] for row in seen["events"]] == [
            {"changes": [{"key": "LLM_MONTHLY_USD_CAP", "old": 50, "new": 70}]}
        ]
    finally:
        a.rollback()
        a.close()
        for dep in (deps.get_conn, deps.get_config, deps.current_user):
            main.app.dependency_overrides.pop(dep, None)
        setup.rollback()
        setup.execute("DELETE FROM settings WHERE updated_by IN (%s, %s)", (a_id, b_id))
        setup.execute("DELETE FROM users WHERE user_id IN (%s, %s)", (a_id, b_id))
        setup.commit()
        setup.close()


# ── validation ────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("field", _FIELD)
def test_the_bounds_are_inclusive_at_both_ends(client, db, field):
    low, high = bounds(_CFG)[_FIELD[field]]
    for value in (low, high):
        resp = client.put({field: value})
        assert resp.status_code == 200, (field, value, resp.text)
        assert resp.json()["limits"][field] == value


@pytest.mark.parametrize("field", _FIELD)
def test_a_value_outside_the_bounds_is_422_out_of_range_and_writes_nothing(client, db, field):
    low, high = bounds(_CFG)[_FIELD[field]]
    for value in (low - 1, high + 1, 0, -5, 10**12):
        resp = client.put({field: value})
        assert resp.status_code == 422, (field, value)
        assert resp.json()["detail"] == {
            "field": field,
            "reason": "out_of_range",
            "min": low,
            "max": high,
        }
    assert _settings_rows(db) == {}
    assert _events(db, client.user_id) == []


# DEC-202: the web's timeout tops out where two sends and the margin still fit under the job lock.
# (job lock, derived ceiling): the default 300 gives 120; a configured 200 gives 70; a lock large
# enough reaches the Owner's static 600 and no further. `.env`'s own timeout is set to 60 so that
# every accepted value below is a real change that writes.
_CEILINGS = [(300, 120), (200, 70), (5000, 600)]


def _with_job_lock(job_lock_timeout_s: int) -> None:
    cfg = replace(_CFG, JOB_LOCK_TIMEOUT_S=job_lock_timeout_s, LLM_TIMEOUT_S=60)
    main.app.dependency_overrides[deps.get_config] = lambda: cfg


@pytest.mark.parametrize(("job_lock_timeout_s", "ceiling"), _CEILINGS)
def test_one_second_above_the_ceiling_is_refused_with_the_derived_max(
    client, db, job_lock_timeout_s, ceiling
):
    """At 300 the ceiling is (300 - 60) // 2 = 120, so 121 is refused and the 422 says `max: 120`.
    The Owner's static 600 would let one model call outlive the job's session (review finding
    I1). Red step: put the static 600 back as the ceiling and 121 is accepted."""
    _with_job_lock(job_lock_timeout_s)

    refused = client.put({"timeout_s": ceiling + 1})

    assert refused.status_code == 422
    assert refused.json()["detail"] == {
        "field": "timeout_s",
        "reason": "out_of_range",
        "min": 10,
        "max": ceiling,
    }
    assert _settings_rows(db) == {}


@pytest.mark.parametrize(("job_lock_timeout_s", "ceiling"), _CEILINGS)
def test_the_ceiling_itself_is_accepted_and_the_answer_shows_it_as_the_maximum(
    client, db, job_lock_timeout_s, ceiling
):
    _with_job_lock(job_lock_timeout_s)

    accepted = client.put({"timeout_s": ceiling})

    assert accepted.status_code == 200
    body = accepted.json()["limits"]
    assert body["timeout_s"] == ceiling
    assert body["bounds"]["timeout_s"] == {"min": 10, "max": ceiling}
    assert body["sources"]["LLM_TIMEOUT_S"]["clamped"] is False
    assert _settings_rows(db) == {"LLM_TIMEOUT_S": ceiling}


@pytest.mark.parametrize("field", _FIELD)
@pytest.mark.parametrize(
    "value",
    ["30", "", 30.5, 30.0, True, False, None, [30], {"v": 30}],
    ids=["str", "empty-str", "float", "whole-float", "true", "false", "null", "list", "object"],
)
def test_a_value_that_is_not_a_json_integer_is_422_not_integer(client, db, field, value):
    resp = client.put({field: value})

    assert resp.status_code == 422
    assert resp.json()["detail"] == {"field": field, "reason": "not_integer"}
    assert _settings_rows(db) == {}
    assert _events(db, client.user_id) == []


@pytest.mark.parametrize("name", ["cap", "LLM_MONTHLY_USD_CAP", "currency", ""])
def test_an_unknown_field_is_422_unknown(client, db, name):
    resp = client.put({name: 30})

    assert resp.status_code == 422
    assert resp.json()["detail"] == {"field": name, "reason": "unknown"}
    assert _settings_rows(db) == {}


def test_one_bad_field_makes_the_whole_request_write_nothing(client, db):
    resp = client.put({"cap_usd": 50, "timeout_s": 5})

    assert resp.status_code == 422
    assert resp.json()["detail"]["field"] == "timeout_s"
    assert _settings_rows(db) == {}
    assert _events(db, client.user_id) == []


@pytest.mark.parametrize("body", [[1, 2], "30", 30, True])
def test_a_body_that_is_not_an_object_is_422(client, db, body):
    resp = client.http.put(URL, json=body)

    assert resp.status_code == 422
    assert _settings_rows(db) == {}


# ── fail closed ───────────────────────────────────────────────────────────────────────────


def test_unreadable_limits_are_503_and_nothing_is_written(client, db):
    """The code deployed before `make migrate`: no `settings` table. The route cannot tell what
    it would be changing, so it changes nothing."""
    db.execute("DROP TABLE settings")  # rolled back with the test's transaction

    resp = client.put({"cap_usd": 50})

    assert resp.status_code == 503
    assert resp.json()["detail"] == {"reason": "limits_unavailable"}
    assert _events(db, client.user_id) == []
    assert db.execute("SELECT 1").fetchone() == (1,)  # and the transaction is still usable


def test_unreadable_limits_are_503_for_an_empty_body_too(client, db):
    db.execute("DROP TABLE settings")

    resp = client.put({})

    assert resp.status_code == 503
    assert resp.json()["detail"] == {"reason": "limits_unavailable"}


def test_a_422_is_answered_before_the_limits_are_read(client, db):
    db.execute("DROP TABLE settings")

    resp = client.put({"cap_usd": "x"})

    assert resp.status_code == 422
