"""P11-T09 — the audit API: `web/routers/admin_audit.py` (`GET /api/admin/audit`, spec §4.7 and §5.8).

Two kinds of test live here.

- Plain tests (no database): the `GROUPS` table against `EVENT_TYPES`, and the redaction function.
- `@pytest.mark.db` tests: the real app through `TestClient(main.app)`, with `deps.get_conn`,
  `deps.current_user` and `deps.get_config` overridden (the shape of `test_admin_overview.py`).

The database is a scratch database this module builds and drops (`tests/scratch_db.py`), not the
shared `db` fixture, for two reasons:

- `audit_events` is append-only (017): a committed row can never be deleted again, and
  `deps.require_role` COMMITS the `authz.denied` row before it raises. The 403 tests therefore get
  a scratch database of their own, so that no committed row reaches the database whose exact
  counts (`total`, a group's rows) the other tests assert;
- the lock test below takes `LOCK TABLE audit_events`, which needs a table no other test is using.

Each test of the main scratch database rolls its connection back at the end, so the tests do not
see each other's rows. Ids are never guessed (a rolled-back INSERT still burns an identity value):
every assertion goes through the ids the factories return.

Two kinds of "slow query" are used on purpose. The MAIN query is slowed for real, by a second
connection holding `ACCESS EXCLUSIVE` on the table: the actual statement waits and the actual
`statement_timeout` cancels it. The COUNT is slowed by replacing its inner function with
`pg_sleep`: both queries read the same table, so a lock would stop the page as well and the
"page served, `total` null" case could not be built.
"""

from __future__ import annotations

import contextlib
import json
import threading
import time
import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
import pytest
from app.audit.events import EVENT_TYPES
from app.infra import config
from app.infra.auth import Claims
from app.web import deps, main
from app.web.routers import admin_audit
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from tests.scratch_db import scratch_database

AUDIT = "/api/admin/audit"
PLACEHOLDER = "[đã ẩn]"

# Spec §5.8, spelled out a second time here on purpose: the module's table and this one are two
# independent copies, so a name moved to the wrong group (which still leaves "every name in
# exactly one group" true) is caught too.
SPEC_GROUPS: dict[str, set[str]] = {
    "users": {"admin.user_created", "admin.user_updated", "authz.denied"},
    "configuration": {
        "admin.autoclose_rule_toggled",
        "admin.settings_changed",
        "autoclose.reviewed",
        "rule.suspected_wrong",
        "label.created",
    },
    "alerts_cases": {
        "alert.received",
        "alert.duplicate_merged",
        "alert.auto_closed",
        "alert.autoclose_blocked_critical",
        "alert.enrich_started",
        "alert.enriched",
        "alert.reopened",
        "alert.acknowledged",
        "tier1.decided",
        "tier1.escalated",
        "case.opened",
        "case.truncated",
        "tier2.concluded",
    },
    "model": {"triage.suggested", "case.analyzed", "llm.gate_forced", "llm.builder_violation"},
    "system": {"job.exhausted", "admin.job_retried", "health.alarm"},
}


# ---------------------------------------------------------------------------
# No database: the group table
# ---------------------------------------------------------------------------


def test_every_event_type_is_in_exactly_one_group_and_there_are_no_extras() -> None:
    members = Counter(name for names in admin_audit.GROUPS.values() for name in names)
    twice = sorted(name for name, n in members.items() if n > 1)
    assert twice == [], f"in more than one place: {twice}"
    assert sorted(EVENT_TYPES - set(members)) == [], "an event type no group lists"
    assert (
        sorted(set(members) - EVENT_TYPES) == []
    ), "a group lists a name that is not an event type"
    assert sum(members.values()) == len(EVENT_TYPES) == 28


def test_the_groups_are_exactly_the_spec_table() -> None:
    assert list(admin_audit.GROUPS) == list(SPEC_GROUPS)
    for key, expected in SPEC_GROUPS.items():
        value = admin_audit.GROUPS[key]
        assert isinstance(value, tuple), key
        assert set(value) == expected, key
        assert len(value) == len(expected), f"{key} lists a name twice"


def test_every_alert_and_tier1_name_is_in_alerts_cases() -> None:
    """The spec writes `alert.*` and `tier1.*`; a v-next name with that prefix must have a group."""
    for name in EVENT_TYPES:
        if name.startswith(("alert.", "tier1.")):
            assert name in admin_audit.GROUPS["alerts_cases"], name


# ---------------------------------------------------------------------------
# No database: redaction
# ---------------------------------------------------------------------------


def test_the_redaction_suffixes_and_the_placeholder_are_the_spec_ones() -> None:
    """Spec §5.8 as amended at `b9fe528`: the six normalised names a key must equal or end with."""
    assert set(admin_audit.REDACT_SUFFIXES) == {
        "password",
        "passwordhash",
        "secret",
        "token",
        "dsn",
        "apikey",
    }
    assert len(admin_audit.REDACT_SUFFIXES) == 6
    assert admin_audit.REDACTED == PLACEHOLDER
    assert admin_audit.PAYLOAD_MAX_BYTES == 64 * 1024
    assert admin_audit.MAX_PAYLOAD_DEPTH == 32


def test_redaction_replaces_a_top_level_key() -> None:
    out = admin_audit.redact({"password": "hunter2", "username": "ana"})
    assert out == {"password": PLACEHOLDER, "username": "ana"}


def test_redaction_goes_through_dicts_and_lists_at_any_depth() -> None:
    payload = {
        "outer": [
            {"inner": {"password": "p1", "keep": 1}},
            [{"deeper": [{"dsn": "postgresql://u:pw@h/db"}]}],
        ],
        "token": "t1",
        "list": [[[{"secret": "s1"}]]],
    }
    out = admin_audit.redact(payload)
    assert out == {
        "outer": [
            {"inner": {"password": PLACEHOLDER, "keep": 1}},
            [{"deeper": [{"dsn": PLACEHOLDER}]}],
        ],
        "token": PLACEHOLDER,
        "list": [[[{"secret": PLACEHOLDER}]]],
    }


# Keys the rule must catch: the spec's six, in any case or separator style, and the near-misses the
# Reviewer named (`access_token`, `client_secret`, `apiKey`, `api-key`, `db_password`,
# `refresh_token`).
CAUGHT_KEYS = [
    "password",
    "password_hash",
    "token",
    "secret",
    "dsn",
    "api_key",
    "Password",
    "PASSWORD",
    "API_KEY",
    "Api_Key",
    "Password_Hash",
    "DSN",
    "Token",
    "sEcReT",
    "access_token",
    "client_secret",
    "apiKey",
    "api-key",
    "db_password",
    "refresh_token",
    "passwordHash",
    "Password-Hash",
    "X-Api-Key",
    "x_api_key",
    "accessToken",
    "userPassword",
    "APIKEY",
    "apikey",
    "database.dsn",
]
# Keys it must leave alone: a plain substring rule would hide these (`key` would hide a setting's
# name in `admin.settings_changed`'s `changes[].key`; `token` would hide a counter).
VISIBLE_KEYS = [
    "key",
    "Key",
    "token_count",
    "tokens_in",
    "tokens",
    "passwords",
    "secretary",
    "token_type",
    "dsn_host",
    "apikeys",
    "hash",
    "keys",
    "_",
    "-",
    "",
]


@pytest.mark.parametrize("key", CAUGHT_KEYS)
def test_redaction_catches_a_key_after_normalising_it(key: str) -> None:
    assert admin_audit.is_secret_key(key) is True
    assert admin_audit.redact({"a": [{key: "x"}]}) == {"a": [{key: PLACEHOLDER}]}


def test_the_rule_is_lowercase_drop_underscores_and_hyphens_then_equal_or_end_with() -> None:
    assert admin_audit.normalise_key("apiKey") == "apikey"  # camelCase needs no split of its own
    assert admin_audit.normalise_key("X-Api_KEY") == "xapikey"
    assert admin_audit.normalise_key("a.b c") == "a.b c"  # only `_` and `-` are dropped
    assert admin_audit.is_secret_key("my token") is True  # a suffix, not a whole word
    assert admin_audit.is_secret_key("token in") is False  # not a suffix
    assert admin_audit.is_secret_key(7) is False  # a JSON key is a string; nothing else matches


def test_a_redacted_key_keeps_its_name_and_loses_a_structured_value_whole() -> None:
    out = admin_audit.redact({"secret": {"nested": ["a", {"b": 1}]}, "token": [1, 2, 3]})
    assert out == {"secret": PLACEHOLDER, "token": PLACEHOLDER}


@pytest.mark.parametrize("key", VISIBLE_KEYS)
def test_a_near_miss_key_stays_visible(key: str) -> None:
    assert admin_audit.is_secret_key(key) is False
    assert admin_audit.redact({key: "visible"}) == {key: "visible"}
    assert admin_audit.redact({"a": [{key: [1, {"b": 2}]}]}) == {"a": [{key: [1, {"b": 2}]}]}


def test_a_settings_change_is_returned_whole_with_its_key_names() -> None:
    """`admin.settings_changed` (P11-T03) carries `changes: [{key, old, new}]`: the setting's name is
    the value of a key called `key`, and neither it nor the numbers may be hidden."""
    payload = {
        "changes": [
            {"key": "LLM_TIMEOUT_S", "old": 60, "new": 90},
            {"key": "LLM_MONTHLY_USD_CAP", "old": 50, "new": 80},
        ]
    }
    assert admin_audit.redact(payload) == payload


def test_redaction_returns_everything_else_unchanged_and_unstringified() -> None:
    payload = {
        "int": 7,
        "float": 1.5,
        "none": None,
        "true": True,
        "false": False,
        "text": "<b>x</b> \x07 \u202e",
        "list": [1, "two", None, [3.5, {"k": []}], {}],
        "empty": {},
    }
    out = admin_audit.redact(payload)
    assert out == payload
    assert out["int"] == 7 and type(out["int"]) is int
    assert out["true"] is True and out["none"] is None
    assert isinstance(out["list"], list) and isinstance(out["list"][3], list)


def test_redaction_does_not_touch_the_input() -> None:
    payload = {"a": [{"password": "p"}], "token": "t"}
    snapshot = json.dumps(payload, sort_keys=True)
    admin_audit.redact(payload)
    assert json.dumps(payload, sort_keys=True) == snapshot


@pytest.mark.parametrize("value", [None, 0, 1.5, True, "text", "password", [], {}, ["token"]])
def test_redaction_of_a_payload_that_is_not_a_dict(value: Any) -> None:
    """A jsonb payload may be any JSON value; a bare string is not a key and stays as it is."""
    assert admin_audit.redact(value) == value


def test_redaction_refuses_a_payload_nested_deeper_than_the_cap_and_takes_the_cap_itself() -> None:
    cap = admin_audit.MAX_PAYLOAD_DEPTH

    def nest(levels: int, bottom: Any) -> Any:
        value = bottom
        for i in range(levels - 1):
            value = [value] if i % 2 else {"k": value}
        return value

    ok = admin_audit.redact(nest(cap, {"token": "leak-deep"}))
    dumped = json.dumps(ok, ensure_ascii=False)
    assert "leak-deep" not in dumped and PLACEHOLDER in dumped
    with pytest.raises(admin_audit.PayloadTooDeep):
        admin_audit.redact(nest(cap + 1, {"token": "leak-deep"}))
    with pytest.raises(admin_audit.PayloadTooDeep):
        admin_audit.redact(nest(10_000, 1))  # and not a RecursionError


def test_the_route_is_registered_once_and_is_admin_only() -> None:
    paths = main.app.openapi()["paths"]
    assert "get" in paths[AUDIT]
    assert sorted(path for path in paths if path.startswith("/api/admin/audit")) == [AUDIT]
    routes = {
        (method, route.path) for route in admin_audit.router.routes for method in route.methods
    }
    assert routes == {("GET", AUDIT)}
    for route in admin_audit.router.routes:
        calls = [d.call for d in route.dependant.dependencies]
        assert admin_audit.require_admin in calls, route.path


def test_the_openapi_lists_the_six_parameters_and_the_groups_as_an_enum() -> None:
    operation = main.app.openapi()["paths"][AUDIT]["get"]
    params = {p["name"]: p for p in operation["parameters"]}
    assert set(params) == {"range", "group", "actor", "subject", "cursor", "limit"}
    assert params["range"]["schema"]["enum"] == ["24h", "7d", "30d"]
    group_schema = params["group"]["schema"]
    options = group_schema.get("anyOf") or [group_schema]
    assert [o["enum"] for o in options if "enum" in o] == [list(admin_audit.GROUPS)]
    assert params["limit"]["schema"]["default"] == 50
    assert params["limit"]["schema"]["maximum"] == 100


# ---------------------------------------------------------------------------
# The scratch databases and the client
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def scratch_dsn():
    with scratch_database("audit") as dsn:
        yield dsn


@pytest.fixture(scope="module")
def denied_dsn():
    """The database the 403 tests write their committed `authz.denied` rows into."""
    with scratch_database("audit403") as dsn:
        yield dsn


@pytest.fixture
def sdb(scratch_dsn):
    conn = psycopg.connect(scratch_dsn)
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


@pytest.fixture
def ddb(denied_dsn):
    conn = psycopg.connect(denied_dsn)
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


@pytest.fixture(autouse=True)
def _require_db_marker_for_scratch(request):
    uses = {"sdb", "ddb", "scratch_dsn", "denied_dsn", "client"} & set(request.fixturenames)
    if uses and request.node.get_closest_marker("db") is None:
        pytest.fail(f"{request.node.nodeid} uses {sorted(uses)} without @pytest.mark.db")


def _override(conn, claims: Claims | None) -> None:
    cfg = config.load()
    main.app.dependency_overrides[deps.get_conn] = lambda: conn
    main.app.dependency_overrides[deps.get_config] = lambda: cfg
    if claims is not None:
        main.app.dependency_overrides[deps.current_user] = lambda: claims


def _clear_overrides() -> None:
    for dep in (deps.get_conn, deps.current_user, deps.get_config):
        main.app.dependency_overrides.pop(dep, None)


def _user(conn, username: str, role: str = "tier1") -> str:
    (user_id,) = conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash)"
        " VALUES (gen_random_uuid(), %s, 'p11t09', %s, 'not-a-real-hash') RETURNING user_id",
        (username, role),
    ).fetchone()
    return str(user_id)


@pytest.fixture
def client(sdb):
    """`(TestClient, connection, admin Claims)`; the admin is a real `users` row."""
    admin_id = _user(sdb, "p11t09-admin", "admin")
    claims = Claims(user_id=admin_id, username="p11t09-admin", role="admin", iat=0.0, exp=0.0)
    _override(sdb, claims)
    try:
        yield TestClient(main.app), sdb, claims
    finally:
        _clear_overrides()


# ---------------------------------------------------------------------------
# Factories — plain SQL; the CHECKs that bite here (`ck_audit_actor_id_theo_role`) satisfied
# ---------------------------------------------------------------------------


def _ago(**kwargs: float) -> datetime:
    return datetime.now(UTC) - timedelta(**kwargs)


def _event(
    conn: Any,
    event_type: str = "alert.received",
    subject: str = "subject-1",
    *,
    role: str = "system",
    actor_id: str | None = None,
    payload: Any = None,
    created_at: datetime | None = None,
) -> int:
    """One `audit_events` row; `payload=None` is a SQL NULL (use `Jsonb(None)` for JSON null)."""
    (audit_id,) = conn.execute(
        "INSERT INTO audit_events (event_type, subject_id, actor_role, actor_id, payload, created_at)"
        " VALUES (%s, %s, %s, %s, %s, COALESCE(%s, now())) RETURNING audit_id",
        (
            event_type,
            subject,
            role,
            actor_id,
            Jsonb(payload) if payload is not None else None,
            created_at,
        ),
    ).fetchone()
    return audit_id


def _event_with_json_text(conn: Any, text: str, subject: str = "raw-payload") -> int:
    """An event whose jsonb payload is the given JSON text, byte for byte (no Python encoder)."""
    (audit_id,) = conn.execute(
        "INSERT INTO audit_events (event_type, subject_id, actor_role, payload)"
        " VALUES ('alert.received', %s, 'system', %s::jsonb) RETURNING audit_id",
        (subject, text),
    ).fetchone()
    return audit_id


@contextlib.contextmanager
def _table_locked(dsn: Any, release_after: float = 8.0):
    """Another connection holds `ACCESS EXCLUSIVE` on `audit_events`, so a SELECT on it waits.

    The holder lets go by itself after `release_after` seconds, request or no request: a module
    that sets no `statement_timeout` then fails an assertion (a 200 after 8 s, not a 503) and the
    run never hangs on a lock nobody will release. Take it before the test writes anything of its
    own to `audit_events` (the lock would wait for that transaction)."""
    holder = psycopg.connect(dsn)
    timer = threading.Timer(release_after, holder.rollback)
    try:
        holder.execute("LOCK TABLE audit_events IN ACCESS EXCLUSIVE MODE")
        timer.start()
        yield
    finally:
        timer.cancel()
        holder.rollback()
        holder.close()


def _get(tc: TestClient, **params: Any):
    return tc.get(AUDIT, params=params)


def _ids(resp: Any) -> list[int]:
    assert resp.status_code == 200, resp.text
    return [e["audit_id"] for e in resp.json()["events"]]


# ---------------------------------------------------------------------------
# The answer's shape
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_an_empty_log_answers_an_empty_page(client) -> None:
    tc, _db, _ = client
    resp = _get(tc)
    assert resp.status_code == 200
    assert resp.json() == {"events": [], "next_cursor": None, "total": 0}


@pytest.mark.db
def test_each_event_has_exactly_the_seven_fields(client) -> None:
    tc, db, claims = client
    audit_id = _event(
        db,
        "admin.user_created",
        "user-1",
        role="admin",
        actor_id=claims.user_id,
        payload={"username": "ana", "role": "tier1"},
    )
    body = _get(tc).json()
    (event,) = body["events"]
    assert set(event) == {
        "audit_id",
        "created_at",
        "event_type",
        "actor_role",
        "actor_username",
        "subject_id",
        "payload",
    }
    assert event["audit_id"] == audit_id
    assert event["event_type"] == "admin.user_created"
    assert event["actor_role"] == "admin"
    assert event["actor_username"] == "p11t09-admin"
    assert event["subject_id"] == "user-1"
    assert event["payload"] == {"username": "ana", "role": "tier1"}
    datetime.fromisoformat(event["created_at"])  # an ISO 8601 string
    assert set(body) == {"events", "next_cursor", "total"}


@pytest.mark.db
def test_actor_username_is_null_for_system_and_llm_and_for_an_actor_with_no_user_row(
    client,
) -> None:
    tc, db, _ = client
    sys_id = _event(db, role="system")
    llm_id = _event(db, "triage.suggested", role="llm")
    ghost = str(uuid.uuid4())  # audit_events.actor_id has no FK (a deleted user's rows stay)
    ghost_id = _event(db, "tier1.decided", role="analyst", actor_id=ghost)
    by_id = {e["audit_id"]: e for e in _get(tc).json()["events"]}
    assert by_id[sys_id]["actor_username"] is None and by_id[sys_id]["actor_role"] == "system"
    assert by_id[llm_id]["actor_username"] is None and by_id[llm_id]["actor_role"] == "llm"
    assert by_id[ghost_id]["actor_username"] is None and by_id[ghost_id]["actor_role"] == "analyst"


@pytest.mark.db
def test_a_null_payload_is_null(client) -> None:
    tc, db, _ = client
    _event(db, payload=None)
    assert _get(tc).json()["events"][0]["payload"] is None


@pytest.mark.db
def test_the_order_is_audit_id_descending_not_created_at(client) -> None:
    """Insertion order, which the primary key serves: a row written later with an OLDER
    `created_at` still comes first."""
    tc, db, _ = client
    first = _event(db, subject="o-1", created_at=_ago(hours=1))
    second = _event(db, subject="o-2", created_at=_ago(hours=5))
    third = _event(db, subject="o-3", created_at=_ago(hours=3))
    assert _ids(_get(tc)) == [third, second, first]


@pytest.mark.db
def test_the_read_writes_nothing(client) -> None:
    tc, db, _ = client
    _event(db)
    before = db.execute("SELECT count(*) FROM audit_events").fetchone()
    assert _get(tc, group="system", actor="nobody", subject="x").status_code == 200
    assert _get(tc).status_code == 200
    assert db.execute("SELECT count(*) FROM audit_events").fetchone() == before


# ---------------------------------------------------------------------------
# range
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_the_default_range_is_seven_days(client) -> None:
    tc, db, _ = client
    _event(db, subject="r-8d", created_at=_ago(days=8))
    in_6d = _event(db, subject="r-6d", created_at=_ago(days=6))
    now = _event(db, subject="r-now")
    assert _ids(_get(tc)) == [now, in_6d]
    assert _ids(_get(tc, range="7d")) == [now, in_6d]


@pytest.mark.db
def test_each_range_keeps_only_its_window(client) -> None:
    tc, db, _ = client
    e_1h = _event(db, subject="w-1h", created_at=_ago(hours=1))
    e_2d = _event(db, subject="w-2d", created_at=_ago(days=2))
    e_10d = _event(db, subject="w-10d", created_at=_ago(days=10))
    _event(db, subject="w-40d", created_at=_ago(days=40))
    assert _ids(_get(tc, range="24h")) == [e_1h]
    assert _ids(_get(tc, range="7d")) == [e_2d, e_1h]
    assert _ids(_get(tc, range="30d")) == [e_10d, e_2d, e_1h]


@pytest.mark.db
def test_the_window_edges_are_a_day_a_week_and_thirty_days(client) -> None:
    tc, db, _ = client
    inside = {
        "24h": _event(db, subject="in-24h", created_at=_ago(hours=23, minutes=30)),
        "7d": _event(db, subject="in-7d", created_at=_ago(days=6, hours=23, minutes=30)),
        "30d": _event(db, subject="in-30d", created_at=_ago(days=29, hours=23, minutes=30)),
    }
    outside = {
        "24h": _event(db, subject="out-24h", created_at=_ago(hours=24, minutes=30)),
        "7d": _event(db, subject="out-7d", created_at=_ago(days=7, minutes=30)),
        "30d": _event(db, subject="out-30d", created_at=_ago(days=30, minutes=30)),
    }
    for name in ("24h", "7d", "30d"):
        ids = set(_ids(_get(tc, range=name, limit=100)))
        assert inside[name] in ids, name
        assert outside[name] not in ids, name


@pytest.mark.db
@pytest.mark.parametrize("value", ["1h", "90d", "24H", "", "month", "7", "7d "])
def test_any_other_range_is_422(client, value: str) -> None:
    tc, _db, _ = client
    assert _get(tc, range=value).status_code == 422


# ---------------------------------------------------------------------------
# group
# ---------------------------------------------------------------------------


def _one_event_per_type(db: Any) -> dict[str, int]:
    return {name: _event(db, name, f"g-{name}") for name in sorted(EVENT_TYPES)}


@pytest.mark.db
@pytest.mark.parametrize("group", list(SPEC_GROUPS))
def test_a_group_returns_exactly_its_event_types(client, group: str) -> None:
    tc, db, _ = client
    ids = _one_event_per_type(db)
    resp = _get(tc, group=group, limit=100)
    assert resp.status_code == 200
    assert {e["event_type"] for e in resp.json()["events"]} == SPEC_GROUPS[group]
    assert sorted(_ids(resp)) == sorted(ids[name] for name in SPEC_GROUPS[group])
    assert resp.json()["total"] == len(SPEC_GROUPS[group])


@pytest.mark.db
def test_no_group_returns_every_event_type_and_the_groups_partition_it(client) -> None:
    tc, db, _ = client
    ids = _one_event_per_type(db)
    everything = _ids(_get(tc, limit=100))
    assert sorted(everything) == sorted(ids.values())
    per_group = [i for group in SPEC_GROUPS for i in _ids(_get(tc, group=group, limit=100))]
    assert sorted(per_group) == sorted(everything)  # no row in two groups, none in no group


@pytest.mark.db
@pytest.mark.parametrize(
    "value", ["nope", "USERS", "Users", "", "alert.received", "alerts", " users"]
)
def test_an_unknown_group_is_422(client, value: str) -> None:
    tc, _db, _ = client
    assert _get(tc, group=value).status_code == 422


# ---------------------------------------------------------------------------
# subject
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_subject_is_an_exact_match(client) -> None:
    tc, db, _ = client
    exact = _event(db, subject="ALERT-1")
    again = _event(db, "tier1.decided", "ALERT-1")
    _event(db, subject="ALERT-10")  # a prefix match would take it
    _event(db, subject="alert-1")  # a case-insensitive match would take it
    _event(db, subject="XALERT-1")
    _event(db, subject="ALERT-1 ")
    assert _ids(_get(tc, subject="ALERT-1")) == [again, exact]
    assert _get(tc, subject="ALERT-1").json()["total"] == 2
    assert _ids(_get(tc, subject="ALERT")) == []


@pytest.mark.db
def test_subject_takes_an_alert_a_case_a_user_a_rule_and_a_path(client) -> None:
    tc, db, _ = client
    case_id = str(uuid.uuid4())
    wanted = {
        s: _event(db, subject=s) for s in ("alert-9", case_id, "rule-3", "/api/admin/users", "42")
    }
    for subject, audit_id in wanted.items():
        assert _ids(_get(tc, subject=subject)) == [audit_id], subject


@pytest.mark.db
@pytest.mark.parametrize(
    "value",
    [
        "x' OR '1'='1",
        "'; DROP TABLE audit_events; --",
        "%",
        "_",
        "%s",
        "%(subject)s",
        "\\",
        '"; SELECT 1 --',
        "ALERT-1\n",
        "<script>alert(1)</script>",
    ],
)
def test_a_hostile_filter_value_is_bound_data_never_sql(client, value: str) -> None:
    tc, db, _ = client
    _event(db, subject="ALERT-1")
    for name in ("subject", "actor"):
        resp = _get(tc, **{name: value})
        assert resp.status_code == 200, (name, resp.text)
        assert resp.json() == {"events": [], "next_cursor": None, "total": 0}, name
    assert db.execute("SELECT count(*) FROM audit_events").fetchone() == (1,)  # the table stands


@pytest.mark.db
@pytest.mark.parametrize("name", ["subject", "actor"])
def test_a_nul_byte_or_an_empty_value_in_a_text_filter_is_422_not_a_500(client, name: str) -> None:
    """A NUL cannot be sent to PostgreSQL (the driver raises); no subject or username holds one."""
    tc, _db, _ = client
    assert _get(tc, **{name: "a\x00b"}).status_code == 422
    assert _get(tc, **{name: "\x00"}).status_code == 422
    assert _get(tc, **{name: ""}).status_code == 422


# ---------------------------------------------------------------------------
# actor
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_actor_as_a_username_returns_that_users_events(client) -> None:
    tc, db, claims = client
    ana = _user(db, "ana", "tier1")
    bob = _user(db, "bob", "tier2")
    a1 = _event(db, "tier1.decided", "a-1", role="analyst", actor_id=ana)
    _event(db, "tier1.decided", "a-2", role="analyst", actor_id=bob)
    a3 = _event(db, "tier1.escalated", "a-3", role="analyst", actor_id=ana)
    boss = _event(db, "admin.user_created", "u-1", role="admin", actor_id=claims.user_id)
    _event(db, "alert.received", "s-1", role="system")
    resp = _get(tc, actor="ana")
    assert _ids(resp) == [a3, a1]
    assert {e["actor_username"] for e in resp.json()["events"]} == {"ana"}
    assert resp.json()["total"] == 2
    assert _ids(_get(tc, actor="p11t09-admin")) == [boss]  # an admin actor is a username too


@pytest.mark.db
def test_actor_system_and_llm_are_the_actor_role(client) -> None:
    tc, db, claims = client
    ana = _user(db, "ana", "tier1")
    sys1 = _event(db, "alert.received", "s-1", role="system")
    sys2 = _event(db, "job.exhausted", "s-2", role="system")
    llm1 = _event(db, "triage.suggested", "l-1", role="llm")
    _event(db, "tier1.decided", "a-1", role="analyst", actor_id=ana)
    _event(db, "admin.user_updated", "u-1", role="admin", actor_id=claims.user_id)
    assert _ids(_get(tc, actor="system")) == [sys2, sys1]
    assert _ids(_get(tc, actor="llm")) == [llm1]
    assert _get(tc, actor="system").json()["total"] == 2
    assert {e["actor_role"] for e in _get(tc, actor="llm").json()["events"]} == {"llm"}


@pytest.mark.db
def test_an_unknown_username_is_an_empty_list_not_an_error(client) -> None:
    tc, db, _ = client
    _event(db)
    resp = _get(tc, actor="no-such-user")
    assert resp.status_code == 200
    assert resp.json() == {"events": [], "next_cursor": None, "total": 0}


@pytest.mark.db
def test_actor_matches_the_username_exactly_as_login_does(client) -> None:
    tc, db, _ = client
    ana = _user(db, "Ana.Lee", "tier1")
    wanted = _event(db, "tier1.decided", "a-1", role="analyst", actor_id=ana)
    assert _ids(_get(tc, actor="Ana.Lee")) == [wanted]
    for other in ("ana.lee", "ANA.LEE", "Ana", "Ana.Lee ", "Ana.Le%", "Ana.L_e"):
        assert _ids(_get(tc, actor=other)) == [], other


@pytest.mark.db
def test_the_names_system_and_llm_are_roles_even_when_a_user_has_that_name(client) -> None:
    tc, db, _ = client
    impostor = _user(db, "system", "tier1")
    human = _event(db, "tier1.decided", "a-1", role="analyst", actor_id=impostor)
    machine = _event(db, "alert.received", "s-1", role="system")
    assert _ids(_get(tc, actor="system")) == [machine]
    assert human not in _ids(_get(tc, actor="system"))


@pytest.mark.db
def test_an_actor_without_a_user_row_is_not_matched_by_any_username(client) -> None:
    tc, db, _ = client
    ghost = str(uuid.uuid4())
    _event(db, "tier1.decided", "a-1", role="analyst", actor_id=ghost)
    assert _ids(_get(tc, actor="ghost")) == []
    assert len(_ids(_get(tc))) == 1  # but it is in the unfiltered list


# ---------------------------------------------------------------------------
# filters together
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_filters_combine_with_and(client) -> None:
    tc, db, _ = client
    ana = _user(db, "ana", "tier1")
    bob = _user(db, "bob", "tier1")
    e1 = _event(db, "tier1.decided", "AL-1", role="analyst", actor_id=ana, created_at=_ago(hours=1))
    e2 = _event(db, "tier1.decided", "AL-1", role="analyst", actor_id=bob)  # other actor
    e3 = _event(db, "tier1.decided", "AL-2", role="analyst", actor_id=ana)  # other subject
    e4 = _event(db, "admin.user_updated", "AL-1", role="analyst", actor_id=ana)  # other group
    e5 = _event(db, "tier1.decided", "AL-1", role="analyst", actor_id=ana, created_at=_ago(days=10))
    e6 = _event(db, "alert.received", "AL-1", role="system")  # a machine

    def got(**params: Any) -> list[int]:
        return sorted(_ids(_get(tc, limit=100, **params)))

    assert got(group="alerts_cases") == sorted([e1, e2, e3, e6])  # 7d: e5 is out
    assert got(group="alerts_cases", range="30d") == sorted([e1, e2, e3, e5, e6])
    assert got(group="alerts_cases", actor="ana") == sorted([e1, e3])
    assert got(group="alerts_cases", actor="ana", subject="AL-1") == [e1]
    assert got(group="alerts_cases", actor="ana", subject="AL-1", range="30d") == sorted([e1, e5])
    assert got(group="alerts_cases", actor="ana", subject="AL-1", range="24h") == [e1]
    assert got(group="users", actor="ana", subject="AL-1") == [e4]
    assert got(group="alerts_cases", actor="system", subject="AL-1") == [e6]
    assert got(actor="ana", subject="AL-1") == sorted([e1, e4])
    assert got(group="model", actor="ana", subject="AL-1") == []
    # the total follows the same filter
    body = _get(tc, group="alerts_cases", actor="ana", subject="AL-1", range="30d").json()
    assert body["total"] == 2 and body["next_cursor"] is None


# ---------------------------------------------------------------------------
# limit and cursor
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_limit_defaults_to_fifty_and_goes_up_to_a_hundred(client) -> None:
    tc, db, _ = client
    all_ids = [_event(db, subject=f"lim-{i}") for i in range(120)]
    newest_first = list(reversed(all_ids))
    default = _get(tc).json()
    assert [e["audit_id"] for e in default["events"]] == newest_first[:50]
    assert default["next_cursor"] == newest_first[49]
    assert default["total"] == 120
    hundred = _get(tc, limit=100).json()
    assert [e["audit_id"] for e in hundred["events"]] == newest_first[:100]
    assert hundred["next_cursor"] == newest_first[99]
    one = _get(tc, limit=1).json()
    assert [e["audit_id"] for e in one["events"]] == newest_first[:1]


@pytest.mark.db
@pytest.mark.parametrize("value", ["0", "101", "abc", "-1", "", "1.5", "1000000", "5 5"])
def test_a_limit_outside_1_to_100_or_not_a_number_is_422(client, value: str) -> None:
    tc, _db, _ = client
    assert _get(tc, limit=value).status_code == 422


@pytest.mark.db
def test_cursor_pages_over_three_pages_with_no_overlap_and_no_gap(client) -> None:
    tc, db, _ = client
    all_ids = [_event(db, subject=f"pg-{i}") for i in range(7)]
    expected_pages = [
        list(reversed(all_ids))[0:3],
        list(reversed(all_ids))[3:6],
        list(reversed(all_ids))[6:7],
    ]
    pages: list[list[int]] = []
    cursors: list[int | None] = []
    totals: list[int] = []
    params: dict[str, Any] = {"limit": 3}
    for _ in range(3):
        body = _get(tc, **params).json()
        pages.append([e["audit_id"] for e in body["events"]])
        cursors.append(body["next_cursor"])
        totals.append(body["total"])
        if body["next_cursor"] is None:
            break
        params["cursor"] = body["next_cursor"]
    assert pages == expected_pages
    assert cursors == [expected_pages[0][-1], expected_pages[1][-1], None]
    assert totals == [7, 7, 7]  # the total is the filter's, whatever the page
    seen = [i for page in pages for i in page]
    assert len(seen) == len(set(seen)) == 7  # no overlap
    assert sorted(seen) == sorted(all_ids)  # no gap
    assert seen == sorted(seen, reverse=True)


@pytest.mark.db
def test_a_cursor_is_strictly_less_than_the_last_id_seen(client) -> None:
    tc, db, _ = client
    all_ids = [_event(db, subject=f"c-{i}") for i in range(5)]
    middle = all_ids[2]
    assert _ids(_get(tc, cursor=middle)) == [all_ids[1], all_ids[0]]
    assert _ids(_get(tc, cursor=all_ids[0])) == []
    assert _ids(_get(tc, cursor=all_ids[-1] + 1)) == list(reversed(all_ids))


@pytest.mark.db
def test_paging_with_a_filter_has_no_overlap_and_no_gap(client) -> None:
    tc, db, _ = client
    wanted: list[int] = []
    for i in range(7):
        wanted.append(_event(db, "tier1.decided", "mine", payload={"i": i}))
        _event(db, "alert.received", "other")  # interleaved, so the ids of "mine" have gaps
    seen: list[int] = []
    params: dict[str, Any] = {"subject": "mine", "limit": 2}
    pages = 0
    while True:
        body = _get(tc, **params).json()
        seen += [e["audit_id"] for e in body["events"]]
        pages += 1
        assert body["total"] == 7
        if body["next_cursor"] is None:
            break
        params["cursor"] = body["next_cursor"]
        assert pages < 10
    assert pages == 4  # 2 + 2 + 2 + 1
    assert seen == list(reversed(wanted))


@pytest.mark.db
def test_next_cursor_is_set_when_the_page_is_full_and_null_when_it_is_not(client) -> None:
    """A full last page still carries a cursor (the spec: "when the page is full"); the page after
    it is empty and its cursor is null."""
    tc, db, _ = client
    all_ids = [_event(db, subject=f"f-{i}") for i in range(6)]
    newest_first = list(reversed(all_ids))
    page1 = _get(tc, limit=3).json()
    page2 = _get(tc, limit=3, cursor=page1["next_cursor"]).json()
    assert page1["next_cursor"] == newest_first[2]
    assert page2["next_cursor"] == newest_first[5]  # full, though nothing is left
    page3 = _get(tc, limit=3, cursor=page2["next_cursor"]).json()
    assert page3 == {"events": [], "next_cursor": None, "total": 6}
    partial = _get(tc, limit=4, cursor=newest_first[3]).json()  # 2 rows left, limit 4
    assert len(partial["events"]) == 2 and partial["next_cursor"] is None


@pytest.mark.db
@pytest.mark.parametrize(
    "value", ["abc", "1.5", "-1", "0", "", "99999999999999999999", "9223372036854775808", "1e3"]
)
def test_a_bad_cursor_is_422(client, value: str) -> None:
    tc, _db, _ = client
    assert _get(tc, cursor=value).status_code == 422


@pytest.mark.db
def test_the_largest_bigint_is_an_ordinary_cursor(client) -> None:
    tc, db, _ = client
    only = _event(db)
    assert _ids(_get(tc, cursor=2**63 - 1)) == [only]


# ---------------------------------------------------------------------------
# redaction through the route
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_a_secret_nested_in_a_list_in_a_dict_is_redacted_and_never_leaves(client) -> None:
    tc, db, _ = client
    _event(
        db,
        "admin.settings_changed",
        "settings",
        role="system",
        payload={
            "old": {"LLM_TIMEOUT_S": 60},
            "new": {"LLM_TIMEOUT_S": 90},
            "attempts": [
                {"step": 1, "Password": "leak-one"},
                {
                    "step": 2,
                    "nested": [{"deeper": {"API_KEY": "leak-two", "dsn": "postgres://leak-three"}}],
                },
            ],
            "token": "leak-four",
            "Secret": ["leak-five"],
            "password_hash": "$argon2id$leak-six",
        },
    )
    resp = _get(tc)
    (event,) = resp.json()["events"]
    assert event["payload"] == {
        "old": {"LLM_TIMEOUT_S": 60},
        "new": {"LLM_TIMEOUT_S": 90},
        "attempts": [
            {"step": 1, "Password": PLACEHOLDER},
            {"step": 2, "nested": [{"deeper": {"API_KEY": PLACEHOLDER, "dsn": PLACEHOLDER}}]},
        ],
        "token": PLACEHOLDER,
        "Secret": PLACEHOLDER,
        "password_hash": PLACEHOLDER,
    }
    for leaked in ("leak-one", "leak-two", "leak-three", "leak-four", "leak-five", "leak-six"):
        assert leaked not in resp.text, leaked


@pytest.mark.db
def test_near_miss_secret_names_are_redacted_through_the_route_and_counters_are_not(client) -> None:
    tc, db, _ = client
    _event(
        db,
        "admin.settings_changed",
        "settings",
        payload={
            "changes": [{"key": "LLM_TIMEOUT_S", "old": 60, "new": 90}],
            "auth": [
                {
                    "access_token": "leak-1",
                    "client_secret": "leak-2",
                    "apiKey": "leak-3",
                    "api-key": "leak-4",
                    "db_password": "leak-5",
                    "refresh_token": "leak-6",
                    "nested": {"Password": "leak-7", "API_KEY": "leak-8"},
                }
            ],
            "usage": {"token_count": 12, "tokens_in": 5, "passwords": 3, "key": "visible"},
        },
    )
    resp = _get(tc)
    (event,) = resp.json()["events"]
    assert event["payload"] == {
        "changes": [{"key": "LLM_TIMEOUT_S", "old": 60, "new": 90}],
        "auth": [
            {
                "access_token": PLACEHOLDER,
                "client_secret": PLACEHOLDER,
                "apiKey": PLACEHOLDER,
                "api-key": PLACEHOLDER,
                "db_password": PLACEHOLDER,
                "refresh_token": PLACEHOLDER,
                "nested": {"Password": PLACEHOLDER, "API_KEY": PLACEHOLDER},
            }
        ],
        "usage": {"token_count": 12, "tokens_in": 5, "passwords": 3, "key": "visible"},
    }
    for leaked in (f"leak-{n}" for n in range(1, 9)):
        assert leaked not in resp.text, leaked


@pytest.mark.db
def test_the_rest_of_a_payload_comes_back_as_it_was_stored(client) -> None:
    tc, db, _ = client
    payload = {
        "int": 7,
        "big": 2**62,
        "float": 1.5,
        "none": None,
        "flag": True,
        "text": "tiếng Việt — ok",
        "list": [1, "two", None, [3.5, {"k": []}], {}],
        "obj": {"a": {"b": {"c": "d"}}},
        "empty": {},
    }
    _event(db, payload=payload)
    assert _get(tc).json()["events"][0]["payload"] == payload


@pytest.mark.db
@pytest.mark.parametrize(
    "text, expected",
    [
        ('"just a string"', "just a string"),
        ("[1, 2, 3]", [1, 2, 3]),
        ("42", 42),
        ("true", True),
        ("null", None),
        ('["password", "token"]', ["password", "token"]),
        ('[{"token": "x"}]', [{"token": PLACEHOLDER}]),
    ],
)
def test_a_payload_that_is_not_an_object_is_returned_as_json(client, text: str, expected) -> None:
    tc, db, _ = client
    _event_with_json_text(db, text)
    assert _get(tc).json()["events"][0]["payload"] == expected


# ---------------------------------------------------------------------------
# hostile text is data
# ---------------------------------------------------------------------------

_HOSTILE = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "</pre><iframe src=javascript:alert(1)>",
    "{{7*7}} ${7*7} <%= 7*7 %>",
    "line1\r\nline2\ttab \x07bell \x1b[31mred\x1b[0m \x01\x02\x7f",
    "\u202eRTL override\u202c \u2028 \u2029 \ufeffBOM",
    "'; DROP TABLE audit_events; --",
    "a" * 3000,
]


@pytest.mark.db
def test_hostile_text_in_a_payload_a_subject_and_a_username_is_returned_as_data(client) -> None:
    tc, db, _ = client
    mallory = _user(db, "<b onmouseover=alert(1)>mallory</b>", "tier1")
    for i, text in enumerate(_HOSTILE):
        _event(
            db,
            "tier1.decided",
            f"hostile-{i}",
            role="analyst",
            actor_id=mallory,
            payload={"note": text, "list": [text], text[:40]: {"nested": text}},
        )
    _event(db, "alert.received", "<img src=x onerror=alert(1)>", role="system")
    resp = _get(tc, limit=100)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    events = resp.json()["events"]
    by_subject = {e["subject_id"]: e for e in events}
    for i, text in enumerate(_HOSTILE):
        event = by_subject[f"hostile-{i}"]
        assert event["payload"]["note"] == text  # byte for byte, nothing stripped or escaped
        assert event["payload"]["list"] == [text]
        assert event["payload"][text[:40]] == {"nested": text}
        assert event["actor_username"] == "<b onmouseover=alert(1)>mallory</b>"
    assert "<img src=x onerror=alert(1)>" in by_subject
    # and the same hostile subject and username can be asked for, as plain filter values
    assert len(_ids(_get(tc, subject="<img src=x onerror=alert(1)>"))) == 1
    assert len(_ids(_get(tc, actor="<b onmouseover=alert(1)>mallory</b>", limit=100))) == len(
        _HOSTILE
    )


@pytest.mark.db
def test_a_nested_secret_next_to_hostile_text_is_still_redacted(client) -> None:
    tc, db, _ = client
    _event(
        db,
        payload={"a": [{"b": {"password": "<script>steal()</script>", "c": "<script>x</script>"}}]},
    )
    payload = _get(tc).json()["events"][0]["payload"]
    assert payload == {"a": [{"b": {"password": PLACEHOLDER, "c": "<script>x</script>"}}]}


# ---------------------------------------------------------------------------
# the large payload
# ---------------------------------------------------------------------------


def _text_of_size(total_bytes: int) -> str:
    """JSON text `{"b": "xxx..."}` whose jsonb::text is exactly `total_bytes` bytes (ASCII)."""
    return '{"b": "' + "x" * (total_bytes - 9) + '"}'


@pytest.mark.db
def test_a_payload_over_64_kb_is_replaced_by_a_truncated_marker_with_its_size(client) -> None:
    tc, db, _ = client
    big = _event_with_json_text(db, _text_of_size(70_000), "big")
    small = _event_with_json_text(db, '{"b": "small"}', "small")
    (size,) = db.execute(
        "SELECT octet_length(payload::text) FROM audit_events WHERE audit_id = %s", (big,)
    ).fetchone()
    assert size == 70_000
    resp = _get(tc)
    events = {e["audit_id"]: e for e in resp.json()["events"]}
    assert events[big]["payload"] == {"truncated": True, "size": 70_000}
    assert events[small]["payload"] == {"b": "small"}  # the others are untouched
    assert len(resp.content) < 2_000  # the page did not grow with the payload


@pytest.mark.db
def test_the_cut_is_over_65536_bytes_so_exactly_64_kb_is_returned_whole(client) -> None:
    tc, db, _ = client
    at_limit = _event_with_json_text(db, _text_of_size(65_536), "at-limit")
    over = _event_with_json_text(db, _text_of_size(65_537), "over")
    sizes = dict(
        db.execute(
            "SELECT audit_id, octet_length(payload::text) FROM audit_events"
            " WHERE audit_id = ANY(%s)",
            ([at_limit, over],),
        ).fetchall()
    )
    assert sizes == {at_limit: 65_536, over: 65_537}  # the test's own arithmetic is exact
    events = {e["audit_id"]: e for e in _get(tc).json()["events"]}
    assert events[at_limit]["payload"] == {"b": "x" * (65_536 - 9)}
    assert events[over]["payload"] == {"truncated": True, "size": 65_537}


@pytest.mark.db
def test_a_one_megabyte_string_and_a_secret_inside_it_never_leave_the_database(client) -> None:
    tc, db, _ = client
    text = json.dumps({"password": "hunter2-in-a-big-one", "log": "A" * 1_000_000})
    _event_with_json_text(db, text, "one-mb")
    resp = _get(tc)
    (event,) = resp.json()["events"]
    assert event["payload"]["truncated"] is True
    assert event["payload"]["size"] > 1_000_000
    assert "hunter2" not in resp.text and len(resp.content) < 2_000


@pytest.mark.db
def test_a_multibyte_payload_is_measured_in_bytes_not_characters(client) -> None:
    tc, db, _ = client
    # 25,000 characters of 3 bytes each: 75,000 bytes, though only ~25,000 characters
    _event_with_json_text(db, json.dumps({"b": "€" * 25_000}, ensure_ascii=False), "bytes")
    (event,) = _get(tc).json()["events"]
    assert event["payload"] == {"truncated": True, "size": 75_000 + 9}


def _nested_dicts(levels: int, bottom: Any) -> Any:
    value = bottom
    for _ in range(levels - 1):
        value = {"a": value}
    return value


@pytest.mark.db
def test_the_deepest_payload_that_is_returned_has_32_levels_and_is_redacted_to_the_bottom(
    client,
) -> None:
    tc, db, _ = client
    levels = admin_audit.MAX_PAYLOAD_DEPTH
    assert levels == 32
    bottom = {"keep": 1, "password": "leak-at-the-bottom"}
    text = json.dumps(_nested_dicts(levels, bottom))
    _event_with_json_text(db, text)
    resp = _get(tc)
    (event,) = resp.json()["events"]
    assert event["payload"] == _nested_dicts(levels, {"keep": 1, "password": PLACEHOLDER})
    assert "leak-at-the-bottom" not in resp.text


@pytest.mark.db
def test_one_level_deeper_the_payload_is_cut_whole_never_leaked_never_half_sent(client) -> None:
    tc, db, _ = client
    levels = admin_audit.MAX_PAYLOAD_DEPTH + 1
    text = json.dumps(_nested_dicts(levels, {"password": "leak-too-deep", "keep": 1}))
    _event_with_json_text(db, text)
    resp = _get(tc)
    (event,) = resp.json()["events"]
    (size,) = db.execute("SELECT octet_length(payload::text) FROM audit_events").fetchone()
    assert event["payload"] == {"truncated": True, "size": size}
    assert "leak-too-deep" not in resp.text


@pytest.mark.db
@pytest.mark.parametrize("depth", [100, 400, 1_500, 5_000, 12_000])
def test_a_payload_nested_to_hundreds_or_thousands_of_levels_is_cut_not_a_500(
    client, depth: int
) -> None:
    """Under 64 KB, so the size rule keeps it, yet neither FastAPI's encoder nor (from about
    9,000 levels) the driver's JSON parser can walk it: one such row must not make the audit
    page a 500. (PostgreSQL itself accepts about 15,000 levels, then refuses on stack depth.)"""
    tc, db, _ = client
    deep = _event_with_json_text(db, "[" * depth + "]" * depth, "deep")
    after = _event(db, subject="after-deep", payload={"ok": 1})
    resp = _get(tc)
    assert resp.status_code == 200
    events = {e["audit_id"]: e for e in resp.json()["events"]}
    assert events[deep]["payload"] == {"truncated": True, "size": 2 * depth}
    assert events[after]["payload"] == {"ok": 1}


@pytest.mark.db
@pytest.mark.parametrize(
    "shape", ['{"n": %s}', "[1, %s, 2]", '{"a": [{"b": %s}]}'], ids=["object", "array", "nested"]
)
def test_a_number_of_thousands_of_digits_cuts_that_payload_not_the_page(client, shape: str) -> None:
    """jsonb stores it; Python's `json.loads` refuses an integer of more than 4,300 digits with a
    `ValueError` (the interpreter's int-string limit), which is neither `RecursionError` nor
    `PayloadTooDeep`. The row is cut, the page is 200 and the next row is intact."""
    tc, db, _ = client
    big = _event_with_json_text(db, shape % ("9" * 5000), "big-int")
    after = _event(db, subject="after-big-int", payload={"ok": 1})
    resp = _get(tc)
    assert resp.status_code == 200
    events = {e["audit_id"]: e for e in resp.json()["events"]}
    (size,) = db.execute(
        "SELECT octet_length(payload::text) FROM audit_events WHERE audit_id = %s", (big,)
    ).fetchone()
    assert size > 5000
    assert events[big]["payload"] == {"truncated": True, "size": size}
    assert events[after]["payload"] == {"ok": 1}


@pytest.mark.db
def test_a_number_of_a_few_thousand_digits_under_the_limit_is_returned_whole(client) -> None:
    """The cut starts where the parser refuses (over 4,300 digits), not before."""
    tc, db, _ = client
    _event_with_json_text(db, '{"n": ' + "9" * 4000 + "}", "int-4000")
    (event,) = _get(tc).json()["events"]
    assert event["payload"] == {"n": int("9" * 4000)}


# ---------------------------------------------------------------------------
# the main query's timeout
# ---------------------------------------------------------------------------


def test_the_timeouts_are_three_seconds_and_one_second() -> None:
    assert admin_audit.QUERY_TIMEOUT == "3s"
    assert admin_audit.TOTAL_TIMEOUT == "1s"


@pytest.mark.db
def test_a_main_query_past_its_statement_timeout_is_503_timeout(
    client, scratch_dsn, monkeypatch
) -> None:
    """The real thing: another connection holds `ACCESS EXCLUSIVE` on `audit_events`, so the
    page's SELECT waits on the lock and only the `SET LOCAL statement_timeout` ends the wait."""
    tc, db, _ = client
    monkeypatch.setattr(admin_audit, "QUERY_TIMEOUT", "150ms")
    with _table_locked(scratch_dsn):
        started = time.monotonic()
        resp = _get(tc)
        elapsed = time.monotonic() - started
    assert resp.status_code == 503
    assert resp.json() == {"detail": {"reason": "timeout"}}
    assert 0.1 <= elapsed < 5, elapsed  # it waited its 150 ms: not 0, and not for the lock
    # the SAVEPOINT was rolled back, not the connection: it is still usable
    assert db.execute("SELECT 1").fetchone() == (1,)


@pytest.mark.db
def test_the_503_body_is_the_reason_only_never_sql_nor_a_dsn(
    client, scratch_dsn, monkeypatch
) -> None:
    tc, _db, _ = client
    monkeypatch.setattr(admin_audit, "QUERY_TIMEOUT", "100ms")
    with _table_locked(scratch_dsn):
        resp = _get(tc, group="users", actor="ana", subject="secret-subject")
    assert resp.status_code == 503
    for leaked in ("SELECT", "audit_events", "statement", "postgres", "secret-subject", "57014"):
        assert leaked not in resp.text, leaked


# ---------------------------------------------------------------------------
# the total
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_total_is_the_count_of_the_same_filter_not_of_the_page(client) -> None:
    tc, db, _ = client
    for i in range(5):
        _event(db, "alert.received", "t-in", role="system")
    for i in range(3):
        _event(db, "tier1.decided", "t-other", role="system")
    _event(db, "alert.received", "t-old", role="system", created_at=_ago(days=20))
    assert _get(tc, limit=2).json()["total"] == 8  # 7d
    assert _get(tc, limit=2, range="30d").json()["total"] == 9
    assert _get(tc, limit=2, subject="t-in").json()["total"] == 5
    assert _get(tc, limit=1, group="alerts_cases", subject="t-in").json()["total"] == 5
    assert _get(tc, subject="nope").json()["total"] == 0


@pytest.mark.db
def test_total_is_counted_in_its_own_savepoint_under_its_own_short_timeout(
    client, monkeypatch
) -> None:
    tc, db, _ = client
    _event(db)
    monkeypatch.setattr(admin_audit, "TOTAL_TIMEOUT", "50ms")
    seen: dict[str, Any] = {}

    def spy(conn, where, params):
        seen["timeout"] = conn.execute("SHOW statement_timeout").fetchone()[0]
        return 41

    monkeypatch.setattr(admin_audit, "_count_matching", spy)
    body = _get(tc).json()
    assert body["total"] == 41 and len(body["events"]) == 1
    assert seen == {"timeout": "50ms"}


@pytest.mark.db
def test_total_is_null_when_its_count_times_out_and_the_page_is_still_served(
    client, monkeypatch
) -> None:
    tc, db, _ = client
    older = _event(db, subject="tt-1")
    newer = _event(db, subject="tt-2")
    monkeypatch.setattr(admin_audit, "TOTAL_TIMEOUT", "50ms")
    monkeypatch.setattr(
        admin_audit,
        "_count_matching",
        lambda conn, where, params: conn.execute("SELECT pg_sleep(5)"),
    )
    started = time.monotonic()
    resp = _get(tc, limit=1)
    elapsed = time.monotonic() - started
    assert elapsed < 4  # the count was cancelled at 50 ms, not after its 5 s sleep
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] is None
    assert [e["audit_id"] for e in body["events"]] == [newer]
    assert body["next_cursor"] == newer  # the page itself is intact
    assert older not in [e["audit_id"] for e in body["events"]]
    # the request's transaction is not aborted: the cancelled statement was inside a savepoint
    assert db.execute("SELECT 1").fetchone() == (1,)


def _sql_error(conn: Any) -> None:
    conn.execute("SELECT 1/0")  # a real statement error: it aborts the transaction it runs in


def _driver_error(conn: Any) -> None:
    raise psycopg.OperationalError("server closed the connection")


@pytest.mark.db
@pytest.mark.parametrize("fault", [_sql_error, _driver_error], ids=["sql-error", "driver-error"])
def test_total_is_null_when_its_count_fails_for_any_reason(client, monkeypatch, fault) -> None:
    tc, db, _ = client
    only = _event(db)
    monkeypatch.setattr(admin_audit, "_count_matching", lambda conn, where, params: fault(conn))
    resp = _get(tc)
    assert resp.status_code == 200
    assert resp.json()["total"] is None
    assert [e["audit_id"] for e in resp.json()["events"]] == [only]
    assert db.execute("SELECT 1").fetchone() == (1,)  # not left in a failed transaction


@pytest.mark.db
def test_a_failed_count_rolls_back_its_savepoint_only_and_the_request_commits_nothing(
    client, scratch_dsn, monkeypatch
) -> None:
    """`infra/db.transaction()` issues BEGIN/COMMIT/ROLLBACK on the connection the request
    shares with its caller. Here the caller's own uncommitted row must survive the request (so
    nothing rolled the transaction back) and stay invisible to everyone else (so nothing
    committed it) — on the success path and on the path where the count failed."""
    tc, db, _ = client
    mine = _event(db, subject="uncommitted-row")
    for failing in (False, True):
        if failing:
            monkeypatch.setattr(
                admin_audit,
                "_count_matching",
                lambda conn, where, params: conn.execute("SELECT 1/0"),
            )
        resp = _get(tc, subject="uncommitted-row")
        assert resp.status_code == 200
        assert _ids(resp) == [mine]
        assert db.execute(
            "SELECT count(*) FROM audit_events WHERE audit_id = %s", (mine,)
        ).fetchone() == (1,)
        with psycopg.connect(scratch_dsn) as other:
            assert other.execute(
                "SELECT count(*) FROM audit_events WHERE audit_id = %s", (mine,)
            ).fetchone() == (0,)


@pytest.mark.db
def test_a_main_query_timeout_leaves_the_callers_transaction_alone(
    client, scratch_dsn, monkeypatch
) -> None:
    """Same property for the 503 path: the savepoint is rolled back, the caller's rows stay."""
    tc, db, _ = client
    monkeypatch.setattr(admin_audit, "QUERY_TIMEOUT", "100ms")
    with _table_locked(scratch_dsn):
        user_rows = db.execute("SELECT count(*) FROM users").fetchone()
        assert _get(tc).status_code == 503
    assert db.execute("SELECT count(*) FROM users").fetchone() == user_rows  # the admin row stands
    assert _ids(_get(tc)) == []  # and the lock is gone: the same request now succeeds


# ---------------------------------------------------------------------------
# admin only
# ---------------------------------------------------------------------------


def _tier(role: str) -> Claims:
    return Claims(user_id=str(uuid.uuid4()), username=f"p11t09-{role}", role=role, iat=0.0, exp=0.0)


def _denials(conn: Any, actor_id: str) -> list[tuple[Any, ...]]:
    return conn.execute(
        "SELECT actor_role, subject_id, payload FROM audit_events"
        " WHERE event_type = 'authz.denied' AND actor_id = %s ORDER BY audit_id",
        (actor_id,),
    ).fetchall()


@pytest.mark.db
@pytest.mark.parametrize("role", ["tier1", "tier2"])
def test_a_tier1_or_tier2_user_gets_403_and_authz_denied_is_written(ddb, role: str) -> None:
    """`require_role` COMMITS the denial, which is why this runs in the module's second scratch
    database (an `audit_events` row can never be deleted again)."""
    user = _tier(role)
    _override(ddb, user)
    try:
        resp = TestClient(main.app).get(AUDIT)
    finally:
        _clear_overrides()
    assert resp.status_code == 403
    assert resp.json() == {"detail": "forbidden"}  # no page, no event, nothing about the log
    ((actor_role, subject, payload),) = _denials(ddb, user.user_id)
    assert actor_role == "analyst" and subject == AUDIT
    assert payload == {"required": ["admin"], "role": role, "method": "GET"}


@pytest.mark.db
def test_the_role_check_answers_before_the_query_is_validated(ddb) -> None:
    user = _tier("tier1")
    _override(ddb, user)
    try:
        resp = TestClient(main.app).get(AUDIT, params={"limit": "abc", "range": "x", "cursor": "q"})
    finally:
        _clear_overrides()
    assert resp.status_code == 403
    assert len(_denials(ddb, user.user_id)) == 1


@pytest.mark.db
def test_an_anonymous_request_is_401_and_reads_nothing(ddb) -> None:
    _override(ddb, None)  # no `current_user` override: the real one, with no token
    try:
        resp = TestClient(main.app).get(AUDIT)
    finally:
        _clear_overrides()
    assert resp.status_code == 401


@pytest.mark.db
def test_the_denial_shows_up_in_the_audit_log_for_an_admin(ddb) -> None:
    """The log a tier1 user failed to read records the attempt: `authz.denied`, subject the path,
    in the `users` group, with the analyst role and no username (the id is not a `users` row)."""
    user = _tier("tier1")
    _override(ddb, user)
    try:
        assert TestClient(main.app).get(AUDIT).status_code == 403
        admin = Claims(
            user_id=_user(ddb, "p11t09-reader", "admin"),
            username="p11t09-reader",
            role="admin",
            iat=0.0,
            exp=0.0,
        )
        _override(ddb, admin)
        resp = TestClient(main.app).get(AUDIT, params={"group": "users", "subject": AUDIT})
    finally:
        _clear_overrides()
    assert resp.status_code == 200
    mine = [e for e in resp.json()["events"] if e["payload"]["role"] == "tier1"]
    assert mine
    event = mine[0]
    assert event["event_type"] == "authz.denied" and event["subject_id"] == AUDIT
    assert event["actor_role"] == "analyst" and event["actor_username"] is None
    assert event["payload"] == {"required": ["admin"], "role": "tier1", "method": "GET"}
