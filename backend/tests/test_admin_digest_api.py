"""P11-T07 — the digest JSON API: `GET /api/admin/digest?day=` and
`POST /api/admin/digest/{alert_id}/review` in `web/routers/admin_digest.py` (spec §4.5 and §5.6),
a JSON face over `tier1/digest.py` (`build`, `review`) that the Jinja page already uses.

Every test runs the real app through `TestClient(main.app)`, with `deps.get_conn` overridden to
this module's own connection and `deps.current_user` to a fixed `Claims` (the shape of
`test_admin_overview.py`). The database is a scratch database this module builds and drops
(`tests/scratch_db.py`), not the shared `db` fixture, because some tests need COMMITTED data
(the concurrency tests, and the 403 test, since `deps.require_role` commits `authz.denied`
before it raises). Two rules keep the committed rows from reaching a neighbour:

- an ordinary test rolls its connection back at the end, so it never sees another test's rows;
- a test that commits uses a day of its own (`2026-08-NN`, `2026-07-01`), so its alerts are not
  on `_DAY`, the day every other test reads. `audit_events` is append-only, so those rows stay
  until the module's scratch database is dropped.

A test that needs no row at all (a bad day, a bad verdict) runs on `_NoSql`: a connection that
fails the test if the route touches it, which proves "before any SQL" instead of assuming it.
Those run in `make test` as well as `make test-db`.
"""

from __future__ import annotations

import dataclasses
import hashlib
import itertools
import json
import threading
import time
import typing
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote
from zoneinfo import ZoneInfo

import psycopg
import pytest
from app.domain import transitions
from app.infra import config
from app.infra.auth import Claims
from app.tier1 import digest, queue
from app.web import deps, main
from app.web.routers import admin_digest
from fastapi import Request
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from tests.scratch_db import scratch_database

HCM = ZoneInfo("Asia/Ho_Chi_Minh")  # UTC+7, no DST: cfg.DISPLAY_TZ's default
TZ = "Asia/Ho_Chi_Minh"
_DAY = "2026-09-29"
# Local day 2026-09-29 spans [2026-09-28 17:00 UTC, 2026-09-29 17:00 UTC).
_IN_DAY = datetime(2026, 9, 29, 10, 0, tzinfo=UTC)  # 17:00 local on the 29th
_OTHER_DAY = datetime(2026, 9, 28, 10, 0, tzinfo=UTC)  # 17:00 local on the 28th
_DIGEST = "/api/admin/digest"
_counter = itertools.count()

# What `DigestRowOut` carries: every `DigestRow` field, who reviewed it and when, and whether a
# digest review reopened it (fix round 1, F4).
ROW_KEYS = {f.name for f in dataclasses.fields(digest.DigestRow)} | {
    "reviewed_by_name",
    "reviewed_at",
    "reopened_by_review",
}


# ---------------------------------------------------------------------------
# The scratch database and the client
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def scratch_dsn():
    with scratch_database("digestapi") as dsn:
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


class _NoSql:
    """A connection that fails the test if a route touches it."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"the route reached the connection ({name})")


def _config(tz: str = TZ) -> config.Config:
    return dataclasses.replace(config.Config(), DISPLAY_TZ=tz)


def _override(conn: Any, claims: Claims, tz: str = TZ) -> None:
    cfg = _config(tz)
    main.app.dependency_overrides[deps.get_conn] = lambda: conn
    main.app.dependency_overrides[deps.current_user] = lambda: claims
    main.app.dependency_overrides[deps.get_config] = lambda: cfg


def _clear_overrides() -> None:
    for dep in (deps.get_conn, deps.current_user, deps.get_config):
        main.app.dependency_overrides.pop(dep, None)


def _as(claims: Claims) -> None:
    main.app.dependency_overrides[deps.current_user] = lambda: claims


def _user(conn: Any, role: str = "admin", *, display_name: str = "Alice Admin") -> Claims:
    user_id = str(uuid.uuid4())
    username = f"p11t07-{uuid.uuid4().hex[:10]}"
    conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash)"
        " VALUES (%s, %s, %s, %s, 'not-a-real-hash')",
        (user_id, username, display_name, role),
    )
    return Claims(user_id=user_id, username=username, role=role, iat=0.0, exp=0.0)


@pytest.fixture
def client(sdb):
    """`(TestClient, connection, admin Claims)`; DISPLAY_TZ is pinned to the default."""
    admin = _user(sdb, "admin", display_name="Alice Admin")
    _override(sdb, admin)
    try:
        yield TestClient(main.app), sdb, admin
    finally:
        _clear_overrides()


@pytest.fixture
def no_sql():
    """An admin on a connection that must never be used."""
    admin = Claims(user_id=str(uuid.uuid4()), username="a", role="admin", iat=0.0, exp=0.0)
    _override(_NoSql(), admin)
    try:
        yield TestClient(main.app)
    finally:
        _clear_overrides()


# ---------------------------------------------------------------------------
# Factories — plain SQL, as test_pages_digest.py does it
# ---------------------------------------------------------------------------


def _rule(conn: Any, user_id: str, *, name: str = "known-scanner", enabled: bool = True) -> str:
    """`match = []` is the whitelist's "matches everything" shape."""
    rule_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO autoclose_rules (autoclose_rule_id, name, match, reason, created_by, enabled)"
        " VALUES (%s, %s, %s, 'matched scanner', %s, %s)",
        (rule_id, name, Jsonb([]), user_id, enabled),
    )
    return rule_id


def _alert(
    conn: Any,
    *,
    alert_id: str | None = None,
    status: str = "auto_closed",
    closed_at: datetime | None = _IN_DAY,
    autoclose_rule_id: str | None = None,
    occurrence_count: int = 1,
    severity: str = "high",
    description: str = "SSH brute force",
    is_synthetic: bool = False,
    auto_closed_event: bool = True,
    suggestion_visible: bool = True,
) -> str:
    """One alert (`suggestion_visible` false is the blind arm, DEC-101). An alert created `auto_closed` also gets the `alert.auto_closed` audit event
    `transitions.open_alert` writes in the same transaction as `closed_at = now()`, at
    `closed_at`: it is what dates the closing once a reopen has cleared `closed_at`."""
    alert_id = alert_id or f"p11t07-{next(_counter)}-{uuid.uuid4().hex[:6]}"
    conn.execute(
        """
        INSERT INTO alerts (
            alert_id, rule_id, rule_level, severity, description, agent_name,
            alert_time, category, resolved_by, mapping_version,
            event_bucket_hash, raw_payload, status, occurrence_count,
            closed_at, autoclose_rule_id, close_reason, is_synthetic, suggestion_visible
        ) VALUES (
            %s, '40112', 10, %s, %s, 'host-1', now(), 'brute_force', 'rule_groups', 'v1',
            %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
        """,
        (
            alert_id,
            severity,
            description,
            hashlib.sha256(alert_id.encode()).hexdigest(),
            Jsonb({}),
            status,
            occurrence_count,
            closed_at,
            autoclose_rule_id,
            "matched scanner" if closed_at is not None else None,
            is_synthetic,
            suggestion_visible,
        ),
    )
    if auto_closed_event and status == "auto_closed" and closed_at is not None:
        conn.execute(
            "INSERT INTO audit_events (event_type, subject_id, actor_role, payload, created_at)"
            " VALUES ('alert.auto_closed', %s, 'system', %s, %s)",
            (alert_id, Jsonb({"seeded": True}), closed_at),
        )
    return alert_id


def _reopened(
    conn: Any,
    user_id: str,
    rule_id: str | None,
    *,
    closed_at: datetime = _IN_DAY,
    is_synthetic: bool = False,
) -> str:
    """An alert a rule auto-closed at `closed_at` and that Tier 1 then reopened (A17): status
    `queued_tier1`, `closed_at` cleared, the `alert.auto_closed` event and `autoclose_rule_id`
    kept, as in production."""
    alert_id = _alert(
        conn, autoclose_rule_id=rule_id, closed_at=closed_at, is_synthetic=is_synthetic
    )
    transitions.reopen(conn, alert_id, user_id, reason="tier1 looked again")
    return alert_id


def _run(conn: Any, alert_id: str, suggested_action: str) -> None:
    """One ① (`proposer`) run, in the shape `queue.latest_suggestion` reads."""
    result = {"suggested_action": suggested_action, "confidence": "high", "reasons": []}
    conn.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt,"
        " user_message, result, role, gate_result)"
        " VALUES (gen_random_uuid(), 'triage', 'alert', %s, 's', 'u', %s::jsonb, 'proposer', '{}')",
        (alert_id, json.dumps(result)),
    )


def _events(conn: Any, event_type: str, subject_id: str) -> list[tuple]:
    return conn.execute(
        "SELECT actor_role, actor_id, payload FROM audit_events"
        " WHERE event_type = %s AND subject_id = %s ORDER BY audit_id",
        (event_type, subject_id),
    ).fetchall()


def _all_event_types(conn: Any, alert_id: str) -> list[str]:
    """Every audit event of the alert but the `alert.auto_closed` the factory seeds, so that
    "nothing was written" still reads `[]`."""
    return [
        t
        for (t,) in conn.execute(
            "SELECT event_type FROM audit_events"
            " WHERE subject_id = %s AND event_type <> 'alert.auto_closed' ORDER BY audit_id",
            (alert_id,),
        ).fetchall()
    ]


def _review_rows(conn: Any, alert_id: str) -> list[tuple]:
    return conn.execute(
        "SELECT reviewer_id, verdict, reviewed_at FROM autoclose_reviews WHERE alert_id = %s",
        (alert_id,),
    ).fetchall()


def _labels(conn: Any, alert_id: str) -> list[tuple]:
    return conn.execute(
        "SELECT labeler_id, source, label FROM triage_labels WHERE alert_id = %s", (alert_id,)
    ).fetchall()


def _alert_state(conn: Any, alert_id: str) -> tuple:
    return conn.execute(
        "SELECT status, closed_at IS NULL, close_reason FROM alerts WHERE alert_id = %s",
        (alert_id,),
    ).fetchone()


def _nothing_written(conn: Any, alert_id: str) -> None:
    """No review, no label, and no event for the alert (an alert inserted by this test has none
    of its own: the inserts above write no event)."""
    assert _review_rows(conn, alert_id) == []
    assert _labels(conn, alert_id) == []
    assert _all_event_types(conn, alert_id) == []


def _at_utc(monkeypatch: pytest.MonkeyPatch, instant: datetime) -> None:
    """The clock the route reads, fixed at one instant: `_now_local(tz)` is that instant seen in
    `tz`, so a route that asked for the wrong zone gets another date (a fake that returned the
    same wall-clock time in every zone would not notice)."""
    monkeypatch.setattr(admin_digest, "_now_local", lambda tz: instant.astimezone(ZoneInfo(tz)))


def _get(tc: TestClient, day: str | None = _DAY) -> Any:
    return tc.get(_DIGEST, params={} if day is None else {"day": day})


def _review_url(alert_id: str) -> str:
    return f"{_DIGEST}/{quote(alert_id, safe='')}/review"


def _post(tc: TestClient, alert_id: str, verdict: Any, day: Any = _DAY) -> Any:
    return tc.post(_review_url(alert_id), json={"day": day, "verdict": verdict})


def _no_leak(resp: Any) -> None:
    """No SQL text, driver message or credential in an error body."""
    text = resp.text.lower()
    for needle in ("select ", "insert ", "update ", "postgres", "password", "psycopg", "traceback"):
        assert needle not in text, (needle, resp.text[:200])


BAD_DAYS = [
    "2026-02-30",  # impossible
    "2026-02-29",  # not a leap year
    "2026-13-01",
    "2026-00-10",
    "2026-01-00",
    "2026-09-31",
    "abc",
    "",
    "2026-9-1",  # not zero-padded
    "20260930",  # date.fromisoformat takes it; the contract is YYYY-MM-DD
    "2026-W40-3",  # an ISO week date, taken by date.fromisoformat too
    "2026-09-30T00:00:00",
    " 2026-09-30",
    "2026-09-30 ",
    "2026-09-30\n",
    "2026-09-30\x00",
    "0000-01-01",
    "9999-99-99",
    "٢٠٢٦-٠٩-٣٠",  # Arabic-Indic digits
    "2026/09/30",
]


# ---------------------------------------------------------------------------
# GET — the shape
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_get_answers_the_documented_shape_and_every_row_key(client, monkeypatch) -> None:
    tc, db, admin = client
    _at_utc(monkeypatch, datetime(2026, 9, 29, 17, 30, tzinfo=UTC))  # 00:30 local on the 30th
    rule_id = _rule(db, admin.user_id, name="known-scanner")
    agrees = _alert(db, autoclose_rule_id=rule_id, occurrence_count=9)
    disagrees = _alert(db, autoclose_rule_id=rule_id, occurrence_count=2, severity="low")
    no_run = _alert(db, autoclose_rule_id=rule_id, occurrence_count=5)
    _run(db, agrees, "false_positive")
    _run(db, disagrees, "escalate")

    resp = _get(tc)

    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"day", "today", "rules_enabled", "rows"}
    assert body["day"] == _DAY
    assert body["today"] == "2026-09-30"  # it is still the 29th in UTC
    assert body["rules_enabled"] is True
    # `build`'s order: the disagreement first, then the larger cluster.
    assert [r["alert_id"] for r in body["rows"]] == [disagrees, agrees, no_run]
    for row in body["rows"]:
        assert set(row) == ROW_KEYS
        assert row["reviewed_verdict"] is None
        assert row["reviewed_by_name"] is None and row["reviewed_at"] is None
    first = body["rows"][0]
    assert first["rule_id"] == "40112" and first["severity"] == "low"
    assert first["description"] == "SSH brute force" and first["category"] == "brute_force"
    assert first["agent_name"] == "host-1" and first["occurrence_count"] == 2
    assert first["autoclose_rule_id"] == rule_id and first["autoclose_rule_name"] == "known-scanner"
    assert first["suggested_action"] == "escalate" and first["disagreement"] is True
    assert body["rows"][1]["suggested_action"] == "false_positive"
    assert body["rows"][1]["disagreement"] is False
    assert body["rows"][2]["suggested_action"] is None and body["rows"][2]["disagreement"] is False
    # Datetimes are ISO strings, as FastAPI serialises them, and they are the stored instants.
    expected = db.execute(
        "SELECT first_seen_at, last_seen_at FROM alerts WHERE alert_id = %s", (disagrees,)
    ).fetchone()
    assert datetime.fromisoformat(first["first_seen_at"]) == expected[0]
    assert datetime.fromisoformat(first["last_seen_at"]) == expected[1]


@pytest.mark.db
def test_an_empty_day_is_an_empty_list_and_the_day_is_echoed(client) -> None:
    tc, _db, _ = client
    body = _get(tc, "2026-01-02").json()
    assert body["rows"] == [] and body["day"] == "2026-01-02"


@pytest.mark.db
def test_the_default_day_is_today_in_the_display_zone(client, monkeypatch) -> None:
    """The spec says today (the Jinja page defaults to yesterday: the 08:00 job reviews it). At
    00:30 local on the 30th it is still 17:30 UTC on the 29th: the zone, not UTC, names the day."""
    tc, db, _ = client
    _at_utc(monkeypatch, datetime(2026, 9, 29, 17, 30, tzinfo=UTC))  # 00:30 local on the 30th
    today_alert = _alert(db, closed_at=datetime(2026, 9, 30, 0, 10, tzinfo=HCM))
    yesterday_alert = _alert(db, closed_at=datetime(2026, 9, 29, 23, 50, tzinfo=HCM))

    body = _get(tc, None).json()

    assert body["day"] == "2026-09-30" and body["today"] == "2026-09-30"
    assert [r["alert_id"] for r in body["rows"]] == [today_alert]
    assert yesterday_alert not in {r["alert_id"] for r in body["rows"]}
    # Asking for another day leaves `today` alone.
    other = _get(tc, "2026-09-29").json()
    assert other["day"] == "2026-09-29" and other["today"] == "2026-09-30"
    assert [r["alert_id"] for r in other["rows"]] == [yesterday_alert]


@pytest.mark.db
def test_today_comes_from_the_clock_through_the_display_zone_at_local_midnight(
    client, monkeypatch
) -> None:
    """The real `_now_local` runs, over a frozen `datetime.now`: one second before 17:00 UTC is
    still the 29th at 23:59:59 local, 17:00:00 UTC is the 30th at 00:00:00 local."""
    tc, _db, _ = client
    for instant, today in (
        (datetime(2026, 9, 29, 16, 59, 59, tzinfo=UTC), "2026-09-29"),
        (datetime(2026, 9, 29, 17, 0, 0, tzinfo=UTC), "2026-09-30"),
    ):

        class FrozenDateTime(datetime):
            @classmethod
            def now(cls, tz=None, _instant=instant):
                return _instant.astimezone(tz) if tz else _instant.replace(tzinfo=None)

        monkeypatch.setattr(admin_digest, "datetime", FrozenDateTime)
        body = tc.get(_DIGEST).json()
        assert body["today"] == today and body["day"] == today, instant


@pytest.mark.db
def test_the_day_is_normalised_and_the_two_ends_of_the_calendar_do_not_break_the_query(
    client,
) -> None:
    tc, _db, _ = client
    for day in ("0001-01-01", "9999-12-31"):
        resp = _get(tc, day)
        assert resp.status_code == 200, (day, resp.text[:200])
        assert resp.json()["day"] == day and resp.json()["rows"] == []


# ---------------------------------------------------------------------------
# GET — the day bounds, in DISPLAY_TZ
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_the_day_bounds_are_local_midnights_in_the_display_zone(client) -> None:
    """Asia/Ho_Chi_Minh is UTC+7. 23:59:59 local on the 29th is 16:59:59 UTC on the 29th, so
    a day cut at UTC midnight would put it, and the alerts around it, on the wrong side."""
    tc, db, _ = client
    before_start = _alert(db, closed_at=datetime(2026, 9, 28, 23, 59, 59, 999999, tzinfo=HCM))
    at_start = _alert(db, closed_at=datetime(2026, 9, 29, 0, 0, 0, tzinfo=HCM))
    last_second = _alert(db, closed_at=datetime(2026, 9, 29, 23, 59, 59, tzinfo=HCM))
    last_micro = _alert(db, closed_at=datetime(2026, 9, 29, 23, 59, 59, 999999, tzinfo=HCM))
    next_midnight = _alert(db, closed_at=datetime(2026, 9, 30, 0, 0, 0, tzinfo=HCM))
    # The same instants read as UTC: 00:00 UTC on the 29th is 07:00 local, inside the local day;
    # 17:00 UTC on the 29th is 00:00 local on the 30th, outside it.
    utc_midnight = _alert(db, closed_at=datetime(2026, 9, 29, 0, 0, 0, tzinfo=UTC))
    utc_late = _alert(db, closed_at=datetime(2026, 9, 29, 20, 0, 0, tzinfo=UTC))

    day29 = {r["alert_id"] for r in _get(tc, "2026-09-29").json()["rows"]}
    day30 = {r["alert_id"] for r in _get(tc, "2026-09-30").json()["rows"]}
    day28 = {r["alert_id"] for r in _get(tc, "2026-09-28").json()["rows"]}

    assert day29 == {at_start, last_second, last_micro, utc_midnight}
    assert day30 == {next_midnight, utc_late}
    assert day28 == {before_start}


@pytest.mark.db
def test_the_day_follows_cfg_display_tz_not_a_constant_zone(client) -> None:
    tc, db, admin = client
    _override(db, admin, tz="UTC")
    last_second = _alert(db, closed_at=datetime(2026, 9, 29, 23, 59, 59, tzinfo=UTC))
    midnight = _alert(db, closed_at=datetime(2026, 9, 30, 0, 0, 0, tzinfo=UTC))
    assert {r["alert_id"] for r in _get(tc, "2026-09-29").json()["rows"]} == {last_second}
    assert {r["alert_id"] for r in _get(tc, "2026-09-30").json()["rows"]} == {midnight}


@pytest.mark.db
def test_synthetic_alerts_and_other_statuses_are_not_on_the_digest(client) -> None:
    tc, db, _ = client
    real = _alert(db)
    _alert(db, is_synthetic=True)
    _alert(db, status="queued_tier1", closed_at=None)
    assert [r["alert_id"] for r in _get(tc).json()["rows"]] == [real]


# ---------------------------------------------------------------------------
# GET — a bad day is a 422 before any SQL
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", BAD_DAYS)
def test_get_with_a_bad_day_is_422_bad_day_and_never_reaches_the_database(no_sql, bad) -> None:
    resp = _get(no_sql, bad)
    assert resp.status_code == 422, (bad, resp.status_code, resp.text[:200])
    assert resp.json() == {"detail": {"reason": "bad_day"}}


# ---------------------------------------------------------------------------
# GET — rules_enabled
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_rules_enabled_is_true_only_while_a_rule_is_enabled(client) -> None:
    tc, db, admin = client
    assert _get(tc).json()["rules_enabled"] is False  # no rule at all
    rule_id = _rule(db, admin.user_id, name="off", enabled=False)
    assert _get(tc).json()["rules_enabled"] is False  # only a disabled one
    other = _rule(db, admin.user_id, name="on", enabled=True)
    assert _get(tc).json()["rules_enabled"] is True
    db.execute("UPDATE autoclose_rules SET enabled = false WHERE autoclose_rule_id = %s", (other,))
    assert _get(tc).json()["rules_enabled"] is False
    db.execute("UPDATE autoclose_rules SET enabled = true WHERE autoclose_rule_id = %s", (rule_id,))
    assert _get(tc).json()["rules_enabled"] is True


@pytest.mark.db
def test_a_rule_disabled_after_it_closed_clusters_does_not_hide_them(client) -> None:
    tc, db, admin = client
    rule_id = _rule(db, admin.user_id, enabled=False)
    closed = _alert(db, autoclose_rule_id=rule_id)
    body = _get(tc).json()
    assert body["rules_enabled"] is False
    assert [r["alert_id"] for r in body["rows"]] == [closed]


# ---------------------------------------------------------------------------
# POST — validation, before any SQL
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", BAD_DAYS)
def test_post_with_a_bad_day_is_422_bad_day_and_never_reaches_the_database(no_sql, bad) -> None:
    resp = _post(no_sql, "a-1", "correct", day=bad)
    assert resp.status_code == 422, (bad, resp.status_code, resp.text[:200])
    assert resp.json() == {"detail": {"reason": "bad_day"}}


@pytest.mark.parametrize("bad", [None, 5, True, ["2026-09-29"], {"day": _DAY}])
def test_post_with_a_day_that_is_not_text_is_422_bad_day(no_sql, bad) -> None:
    resp = _post(no_sql, "a-1", "correct", day=bad)
    assert resp.status_code == 422 and resp.json() == {"detail": {"reason": "bad_day"}}


def test_post_with_no_day_at_all_is_422_bad_day(no_sql) -> None:
    resp = no_sql.post(_review_url("a-1"), json={"verdict": "correct"})
    assert resp.status_code == 422 and resp.json() == {"detail": {"reason": "bad_day"}}


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "Correct",
        "right",
        "wrong ",
        " wrong",
        "correct\n",
        "all",
        None,
        1,
        True,
        ["correct"],
        {},
    ],
)
def test_post_with_a_verdict_outside_the_three_is_422_invalid(no_sql, bad) -> None:
    resp = _post(no_sql, "a-1", bad)
    assert resp.status_code == 422, (bad, resp.status_code, resp.text[:200])
    assert resp.json() == {"detail": {"field": "verdict", "reason": "invalid"}}


def test_post_with_no_verdict_at_all_is_422_invalid(no_sql) -> None:
    resp = no_sql.post(_review_url("a-1"), json={"day": _DAY})
    assert resp.status_code == 422
    assert resp.json() == {"detail": {"field": "verdict", "reason": "invalid"}}


def test_the_day_is_judged_before_the_verdict(no_sql) -> None:
    resp = _post(no_sql, "a-1", "nonsense", day="2026-02-30")
    assert resp.status_code == 422 and resp.json() == {"detail": {"reason": "bad_day"}}


@pytest.mark.parametrize("body", ["[]", '"correct"', "5", "null"])
def test_a_json_body_that_is_not_an_object_is_a_422(no_sql, body) -> None:
    resp = no_sql.post(
        _review_url("a-1"), content=body, headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == 422


def test_malformed_json_is_a_422_and_no_sql(no_sql) -> None:
    resp = no_sql.post(
        _review_url("a-1"), content="{not json", headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST — a body that does not say it is JSON is not parsed, and writes nothing
# ---------------------------------------------------------------------------


@pytest.mark.db
@pytest.mark.parametrize(
    "headers",
    [
        {"Content-Type": "text/plain"},
        {"Content-Type": "application/x-www-form-urlencoded"},
        {},  # no Content-Type at all
    ],
    ids=["text-plain", "form", "none"],
)
def test_a_body_without_a_json_content_type_is_a_422_and_writes_nothing(client, headers) -> None:
    """The one cross-site request a browser can send without a preflight is a form or
    `text/plain` post: FastAPI must not read that as JSON."""
    tc, db, _ = client
    alert_id = _alert(db)
    raw = json.dumps({"day": _DAY, "verdict": "correct"})
    resp = tc.post(_review_url(alert_id), content=raw, headers=headers)
    assert resp.status_code == 422, (resp.status_code, resp.text[:200])
    assert _alert_state(db, alert_id) == ("auto_closed", False, "matched scanner")
    _nothing_written(db, alert_id)


@pytest.mark.db
def test_a_form_encoded_body_is_a_422_and_writes_nothing(client) -> None:
    tc, db, _ = client
    alert_id = _alert(db)
    resp = tc.post(_review_url(alert_id), data={"day": _DAY, "verdict": "correct"})
    assert resp.status_code == 422
    _nothing_written(db, alert_id)


# ---------------------------------------------------------------------------
# POST — the review itself
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_correct_is_a_200_the_row_is_reviewed_and_the_gold_label_and_events_are_written(
    client,
) -> None:
    tc, db, admin = client
    rule_id = _rule(db, admin.user_id)
    alert_id = _alert(db, autoclose_rule_id=rule_id)
    _run(db, alert_id, "false_positive")

    resp = _post(tc, alert_id, "correct")

    assert resp.status_code == 200, resp.text[:300]
    body = resp.json()
    assert set(body) == {"row", "reopened"} and body["reopened"] is False
    row = body["row"]
    assert set(row) == ROW_KEYS
    assert row["alert_id"] == alert_id and row["reviewed_verdict"] == "correct"
    assert row["reviewed_by_name"] == "Alice Admin"
    ((reviewer_id, verdict, reviewed_at),) = _review_rows(db, alert_id)
    assert str(reviewer_id) == admin.user_id and verdict == "correct"
    assert datetime.fromisoformat(row["reviewed_at"]) == reviewed_at
    # `digest.review`'s own writes, none of them from this module: the gold label (source
    # digest), `autoclose.reviewed` and `label.created`.
    assert [tuple(map(str, r)) for r in _labels(db, alert_id)] == [
        (admin.user_id, "digest", "false_positive")
    ]
    ((role, actor, payload),) = _events(db, "autoclose.reviewed", alert_id)
    assert role == "admin" and str(actor) == admin.user_id
    assert payload["verdict"] == "correct" and payload["autoclose_rule_id"] == rule_id
    assert payload["suggested_action"] == "false_positive"
    ((_, _, label_payload),) = _events(db, "label.created", alert_id)
    assert label_payload["label"] == "false_positive" and label_payload["source"] == "digest"
    # The alert stays auto-closed, and the page now carries the verdict.
    assert _alert_state(db, alert_id)[0] == "auto_closed"
    listed = _get(tc).json()["rows"]
    assert listed == [row]  # the 200's row is what the list shows


@pytest.mark.db
def test_unsure_is_a_200_and_writes_the_review_and_its_event_but_no_label(client) -> None:
    tc, db, admin = client
    alert_id = _alert(db, autoclose_rule_id=_rule(db, admin.user_id))

    resp = _post(tc, alert_id, "unsure")

    assert resp.status_code == 200, resp.text[:300]
    assert resp.json()["reopened"] is False
    assert resp.json()["row"]["reviewed_verdict"] == "unsure"
    assert resp.json()["row"]["reviewed_by_name"] == "Alice Admin"
    assert [v for (_, v, _) in _review_rows(db, alert_id)] == ["unsure"]
    assert _labels(db, alert_id) == []
    assert _all_event_types(db, alert_id) == ["autoclose.reviewed"]
    assert _alert_state(db, alert_id)[0] == "auto_closed"


@pytest.mark.db
def test_wrong_reopens_the_alert_and_the_row_still_describes_it(client) -> None:
    """`build` lists only auto-closed alerts, so a `wrong` review makes the alert leave the
    digest: the 200's row therefore comes from the snapshot taken before the review, with the
    recorded verdict, reviewer and time read after it."""
    tc, db, admin = client
    rule_id = _rule(db, admin.user_id)
    alert_id = _alert(db, autoclose_rule_id=rule_id, occurrence_count=7, severity="critical")
    _run(db, alert_id, "escalate")

    resp = _post(tc, alert_id, "wrong")

    assert resp.status_code == 200, resp.text[:300]
    body = resp.json()
    assert body["reopened"] is True
    row = body["row"]
    assert set(row) == ROW_KEYS
    assert row["alert_id"] == alert_id and row["occurrence_count"] == 7
    assert row["severity"] == "critical" and row["autoclose_rule_name"] == "known-scanner"
    assert row["suggested_action"] == "escalate" and row["disagreement"] is True
    assert row["reviewed_verdict"] == "wrong" and row["reviewed_by_name"] == "Alice Admin"
    ((_, _, reviewed_at),) = _review_rows(db, alert_id)
    assert datetime.fromisoformat(row["reviewed_at"]) == reviewed_at
    # Back in the Tier 1 queue, `closed_at` cleared, and no gold label: "wrong" says only that
    # auto-closing was wrong, not what the alert is.
    assert _alert_state(db, alert_id) == ("queued_tier1", True, "digest")
    assert _labels(db, alert_id) == []
    assert sorted(_all_event_types(db, alert_id)) == ["alert.reopened", "autoclose.reviewed"]
    # `reopened_by_review`: the page shows the verdict and "đã mở lại về hàng đợi Tier 1" again
    # after a refetch, so the list keeps the row (module docstring; the F4 tests below).
    assert row["reopened_by_review"] is True
    assert _get(tc).json()["rows"] == [row]


@pytest.mark.db
def test_rule_suspected_wrong_fires_once_at_two_wrong_reviews_of_one_rule(client) -> None:
    tc, db, admin = client
    rule_id = _rule(db, admin.user_id)
    first, second, third = (_alert(db, autoclose_rule_id=rule_id) for _ in range(3))

    assert _post(tc, first, "wrong").status_code == 200
    assert _events(db, "rule.suspected_wrong", rule_id) == []  # one wrong is not a pattern

    assert _post(tc, second, "wrong").status_code == 200
    ((role, _, payload),) = _events(db, "rule.suspected_wrong", rule_id)
    assert role == "system" and payload == {"wrong_count": 2, "window": "7 days"}

    assert _post(tc, third, "wrong").status_code == 200
    assert len(_events(db, "rule.suspected_wrong", rule_id)) == 1  # once per window


@pytest.mark.db
def test_a_correct_or_unsure_review_never_counts_toward_suspected_wrong(client) -> None:
    tc, db, admin = client
    rule_id = _rule(db, admin.user_id)
    for verdict in ("correct", "unsure", "correct", "wrong"):
        assert _post(tc, _alert(db, autoclose_rule_id=rule_id), verdict).status_code == 200
    assert _events(db, "rule.suspected_wrong", rule_id) == []


@pytest.mark.db
def test_a_second_review_is_409_already_reviewed_with_the_recorded_verdict_and_reviewer(
    client,
) -> None:
    tc, db, admin = client
    other = _user(db, "admin", display_name="Bob Second")
    alert_id = _alert(db, autoclose_rule_id=_rule(db, admin.user_id))
    assert _post(tc, alert_id, "correct").status_code == 200
    recorded = _review_rows(db, alert_id)
    events_before = _all_event_types(db, alert_id)
    labels_before = _labels(db, alert_id)

    _as(other)
    resp = _post(tc, alert_id, "wrong")  # a different reviewer, a different verdict

    assert resp.status_code == 409, resp.text[:300]
    detail = resp.json()["detail"]
    assert set(detail) == {"reason", "row"} and detail["reason"] == "already_reviewed"
    assert set(detail["row"]) == ROW_KEYS
    assert detail["row"]["reviewed_verdict"] == "correct"  # the first review wins
    assert detail["row"]["reviewed_by_name"] == "Alice Admin"  # and it names who
    assert detail["row"]["alert_id"] == alert_id
    # `digest.review` runs in a savepoint: the refused attempt wrote nothing, and the alert did
    # not reopen although the second verdict was "wrong".
    assert _review_rows(db, alert_id) == recorded
    assert _all_event_types(db, alert_id) == events_before
    assert _labels(db, alert_id) == labels_before
    assert _alert_state(db, alert_id)[0] == "auto_closed"
    _no_leak(resp)


@pytest.mark.db
def test_the_same_verdict_twice_is_still_409_not_an_upsert(client) -> None:
    tc, db, _ = client
    alert_id = _alert(db)
    assert _post(tc, alert_id, "unsure").status_code == 200
    again = _post(tc, alert_id, "unsure")
    assert again.status_code == 409
    assert again.json()["detail"]["reason"] == "already_reviewed"
    assert len(_review_rows(db, alert_id)) == 1
    assert len(_events(db, "autoclose.reviewed", alert_id)) == 1


@pytest.mark.db
def test_an_alert_a_rule_closed_that_day_and_that_is_no_longer_auto_closed_is_409(client) -> None:
    """A stale page: the row was reopened by Tier 1 after this admin loaded it. `build` no
    longer lists it, but the answer is the conflict the page maps to "no longer auto-closed",
    not a 404 that says the alert never was on that day."""
    tc, db, admin = client
    rule_id = _rule(db, admin.user_id)
    alert_id = _reopened(db, admin.user_id, rule_id)
    events_before = _all_event_types(db, alert_id)

    resp = _post(tc, alert_id, "correct")

    assert resp.status_code == 409, resp.text[:300]
    assert resp.json() == {"detail": {"reason": "not_auto_closed"}}
    assert _review_rows(db, alert_id) == [] and _labels(db, alert_id) == []
    assert _all_event_types(db, alert_id) == events_before
    assert _alert_state(db, alert_id)[0] == "queued_tier1"


def _not_on_the_digest(db: Any, admin_id: str, case: str) -> str:
    """Each case breaks exactly one of the four conditions of a 409 (not synthetic; closed by a
    rule; an `alert.auto_closed` event on the posted day; now in another status)."""
    rule_id = _rule(db, admin_id, name=f"rule-{case}")
    if case == "synthetic_reopened":
        return _reopened(db, admin_id, rule_id, is_synthetic=True)
    if case == "never_auto_closed_queued":
        return _alert(db, status="queued_tier1", closed_at=None, autoclose_rule_id=rule_id)
    if case == "never_auto_closed_received":
        return _alert(db, status="received", closed_at=None, autoclose_rule_id=rule_id)
    if case == "other_day_reopened":
        return _reopened(db, admin_id, rule_id, closed_at=_OTHER_DAY)
    if case == "reopened_without_a_rule":
        return _reopened(db, admin_id, None)
    if case == "auto_closed_on_another_day":
        return _alert(db, closed_at=_OTHER_DAY, autoclose_rule_id=rule_id)
    if case == "synthetic_auto_closed":
        return _alert(db, is_synthetic=True, autoclose_rule_id=rule_id)
    assert case == "unknown", case
    return "no-such-alert"


@pytest.mark.db
@pytest.mark.parametrize(
    "case",
    [
        "synthetic_reopened",
        "never_auto_closed_queued",
        "never_auto_closed_received",
        "other_day_reopened",
        "reopened_without_a_rule",
        "auto_closed_on_another_day",
        "synthetic_auto_closed",
        "unknown",
    ],
)
def test_every_other_alert_that_is_not_on_the_days_digest_is_404(client, case) -> None:
    """The 409 is only for an alert a rule auto-closed on the posted day (DISPLAY_TZ) that is
    now in another status; every other alert off the digest is a 404, whatever its status."""
    tc, db, admin = client
    alert_id = _not_on_the_digest(db, admin.user_id, case)
    before = _all_event_types(db, alert_id)

    resp = _post(tc, alert_id, "correct")

    assert resp.status_code == 404, (case, resp.status_code, resp.text[:300])
    assert resp.json() == {"detail": {"reason": "not_in_digest"}}
    assert _review_rows(db, alert_id) == [] and _labels(db, alert_id) == []
    assert _all_event_types(db, alert_id) == before


@pytest.mark.db
def test_the_conflict_follows_the_posted_day_not_the_alert(client) -> None:
    """An alert reopened after a rule closed it on the 28th is a 409 for the 28th and a 404 for
    the 29th; the day bounds are the display zone's, 23:59:59 local included."""
    tc, db, admin = client
    rule_id = _rule(db, admin.user_id)
    late = _reopened(
        db, admin.user_id, rule_id, closed_at=datetime(2026, 9, 28, 23, 59, 59, tzinfo=HCM)
    )
    midnight = _reopened(
        db, admin.user_id, rule_id, closed_at=datetime(2026, 9, 29, 0, 0, 0, tzinfo=HCM)
    )
    assert _post(tc, late, "correct", day="2026-09-28").status_code == 409
    assert _post(tc, late, "correct", day="2026-09-29").status_code == 404
    assert _post(tc, midnight, "correct", day="2026-09-28").status_code == 404
    assert _post(tc, midnight, "correct", day="2026-09-29").status_code == 409


@pytest.mark.db
def test_a_second_review_after_wrong_is_409_not_auto_closed(client) -> None:
    """`wrong` reopened the alert: the page of a second reviewer shows a row that is gone."""
    tc, db, admin = client
    alert_id = _alert(db, autoclose_rule_id=_rule(db, admin.user_id))
    assert _post(tc, alert_id, "wrong").status_code == 200
    events_before = _all_event_types(db, alert_id)

    resp = _post(tc, alert_id, "correct")

    assert resp.status_code == 409
    assert resp.json() == {"detail": {"reason": "not_auto_closed"}}
    assert _all_event_types(db, alert_id) == events_before
    assert [v for (_, v, _) in _review_rows(db, alert_id)] == ["wrong"]
    assert _labels(db, alert_id) == []


@pytest.mark.db
def test_an_alert_of_another_day_is_404_not_in_digest_and_nothing_is_written(client) -> None:
    tc, db, _ = client
    yesterday = _alert(db, closed_at=_OTHER_DAY)
    resp = _post(tc, yesterday, "correct", day=_DAY)
    assert resp.status_code == 404, resp.text[:300]
    assert resp.json() == {"detail": {"reason": "not_in_digest"}}
    assert _alert_state(db, yesterday)[0] == "auto_closed"
    _nothing_written(db, yesterday)
    # The same alert is reviewable on its own day.
    assert _post(tc, yesterday, "correct", day="2026-09-28").status_code == 200


@pytest.mark.db
def test_an_unknown_alert_and_a_synthetic_one_are_404_not_in_digest(client) -> None:
    tc, db, _ = client
    synthetic = _alert(db, is_synthetic=True)
    for alert_id in ("no-such-alert", "9" * 300, synthetic):
        resp = _post(tc, alert_id, "wrong")
        assert resp.status_code == 404, (alert_id[:20], resp.status_code)
        assert resp.json() == {"detail": {"reason": "not_in_digest"}}
    assert _alert_state(db, synthetic)[0] == "auto_closed"
    _nothing_written(db, synthetic)


@pytest.mark.db
@pytest.mark.parametrize("char", ["\x00", "\x01", "\x1b", "\x7f", "\x85"])
def test_a_control_character_in_the_id_is_404_and_the_connection_stays_usable(client, char) -> None:
    """`deps.AlertId`: a NUL used to reach `WHERE alert_id = %s` and come back as a driver
    `DataError`, a 500."""
    tc, db, _ = client
    resp = _post(tc, f"a{char}b", "correct")
    assert resp.status_code == 404, (resp.status_code, resp.text[:200])
    assert db.execute("SELECT 1").fetchone() == (1,)


def test_the_alert_id_parameter_is_the_shared_validated_type() -> None:
    hints = typing.get_type_hints(admin_digest.api_review, include_extras=True)
    assert hints["alert_id"] == deps.AlertId


@pytest.mark.db
def test_every_error_body_is_a_plain_reason_and_nothing_else(client) -> None:
    tc, db, admin = client
    done = _alert(db)
    assert _post(tc, done, "correct").status_code == 200
    answers = [
        _get(tc, "2026-02-30"),
        _post(tc, done, "correct", day="nope"),
        _post(tc, done, "maybe"),
        _post(tc, done, "correct"),  # 409 already_reviewed
        _post(tc, _reopened(db, admin.user_id, _rule(db, admin.user_id)), "correct"),  # 409
        _post(tc, "missing", "correct"),
    ]
    assert [r.status_code for r in answers] == [422, 422, 422, 409, 409, 404]
    for resp in answers:
        _no_leak(resp)


# ---------------------------------------------------------------------------
# An alert a digest review reopened stays on its day's list (fix round 1, F4)
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_after_sai_the_next_get_still_lists_the_row_with_its_verdict_and_reviewer(client) -> None:
    """Spec 4.5: after a review the row shows the verdict, the reviewer and, for "Sai", that it
    was reopened. It must survive a refetch and a reload, which page state would not: the
    alert is no longer `auto_closed`, so `build` has dropped it, and the API lists it again."""
    tc, db, admin = client
    rule_id = _rule(db, admin.user_id)
    sai = _alert(db, autoclose_rule_id=rule_id, occurrence_count=5)
    waiting = _alert(db, autoclose_rule_id=rule_id, occurrence_count=2)
    posted = _post(tc, sai, "wrong")
    assert posted.status_code == 200 and posted.json()["reopened"] is True
    assert _alert_state(db, sai)[0] == "queued_tier1"

    for _refetch in range(2):  # nothing consumes the row
        rows = _get(tc).json()["rows"]
        assert [r["alert_id"] for r in rows] == [sai, waiting]  # `build`'s order, 5 before 2
        listed = rows[0]
        assert listed == posted.json()["row"]  # the 200's row is what the list shows
        assert listed["reviewed_verdict"] == "wrong"
        assert listed["reviewed_by_name"] == "Alice Admin" and listed["reviewed_at"] is not None
        assert listed["reopened_by_review"] is True
        assert rows[1]["reopened_by_review"] is False and rows[1]["reviewed_verdict"] is None
        # The page's summary is computed from the rows: the reopened cluster is still counted.
        reviewed = [r for r in rows if r["reviewed_verdict"] is not None]
        assert (len(rows), len(reviewed), len(rows) - len(reviewed)) == (2, 1, 1)


@pytest.mark.db
def test_a_row_reopened_by_a_digest_review_is_listed_whatever_became_of_it_since(client) -> None:
    tc, db, admin = client
    sai = _alert(db, autoclose_rule_id=_rule(db, admin.user_id))
    assert _post(tc, sai, "wrong").status_code == 200
    transitions.acknowledge(db, sai, admin.user_id)  # Tier 1 picks it up
    assert _alert_state(db, sai)[0] == "tier1_active"

    (row,) = _get(tc).json()["rows"]

    assert row["alert_id"] == sai and row["reopened_by_review"] is True
    assert row["reviewed_verdict"] == "wrong"


# ---------------------------------------------------------------------------
# The blind arm on a reopened row (P11-T20 part 4, finding I1's lesser case; DEC-101, §6.4)
# ---------------------------------------------------------------------------


def _blind_sai(
    db: Any, admin_id: str, *, occurrence_count: int, suggested: str = "escalate"
) -> str:
    """A blind alert a rule auto-closed in `_DAY`, with ① run on it: not yet reviewed."""
    alert_id = _alert(
        db,
        autoclose_rule_id=_rule(db, admin_id, name=f"blind-{next(_counter)}"),
        occurrence_count=occurrence_count,
        suggestion_visible=False,
    )
    _run(db, alert_id, suggested)
    return alert_id


@pytest.mark.db
def test_a_blind_alert_shows_its_suggestion_while_it_is_auto_closed_and_not_after_sai(
    client,
) -> None:
    """Auto-closed is a decided state (D8: the digest reviews it against ①), so the row shows ①.
    "Sai" reopens it, which makes it blind and undecided again (A17): the 200's row and every
    refetch then carry no suggestion and no disagreement flag."""
    tc, db, admin = client
    alert_id = _blind_sai(db, admin.user_id, occurrence_count=4)
    (before,) = _get(tc).json()["rows"]
    assert before["suggested_action"] == "escalate" and before["disagreement"] is True

    posted = _post(tc, alert_id, "wrong")

    assert posted.status_code == 200 and posted.json()["reopened"] is True
    row = posted.json()["row"]
    assert row["suggested_action"] is None and row["disagreement"] is False
    assert row["reopened_by_review"] is True and row["reviewed_verdict"] == "wrong"
    assert "escalate" not in posted.text
    for _refetch in range(2):
        resp = _get(tc)
        assert resp.json()["rows"] == [row] and "escalate" not in resp.text


@pytest.mark.db
def test_a_reopened_row_on_the_visible_arm_keeps_its_suggestion(client) -> None:
    tc, db, admin = client
    alert_id = _alert(db, autoclose_rule_id=_rule(db, admin.user_id), suggestion_visible=True)
    _run(db, alert_id, "escalate")
    assert _post(tc, alert_id, "wrong").json()["row"]["suggested_action"] == "escalate"
    (row,) = _get(tc).json()["rows"]
    assert row["suggested_action"] == "escalate" and row["disagreement"] is True


@pytest.mark.db
@pytest.mark.parametrize(
    "decided", ["closed_fp", "closed_benign", "closed_confirmed", "escalated_tier2"]
)
def test_a_blind_reopened_row_shows_its_suggestion_again_once_it_is_decided(
    client, decided: str
) -> None:
    tc, db, admin = client
    alert_id = _blind_sai(db, admin.user_id, occurrence_count=3)
    assert _post(tc, alert_id, "wrong").status_code == 200
    assert _get(tc).json()["rows"][0]["suggested_action"] is None
    sealed = ", sealed_at = now(), closed_at = now()" if decided != "escalated_tier2" else ""
    db.execute(f"UPDATE alerts SET status = %s{sealed} WHERE alert_id = %s", (decided, alert_id))

    (row,) = _get(tc).json()["rows"]

    assert row["suggested_action"] == "escalate" and row["disagreement"] is True


@pytest.mark.db
@pytest.mark.parametrize("status", ["queued_tier1", "tier1_active"])
def test_a_blind_reopened_row_stays_withheld_while_tier1_works_on_it(client, status: str) -> None:
    tc, db, admin = client
    alert_id = _blind_sai(db, admin.user_id, occurrence_count=3)
    assert _post(tc, alert_id, "wrong").status_code == 200
    if status == "tier1_active":
        transitions.acknowledge(db, alert_id, admin.user_id)
    assert _alert_state(db, alert_id)[0] == status
    (row,) = _get(tc).json()["rows"]
    assert row["suggested_action"] is None and row["disagreement"] is False


@pytest.mark.db
def test_a_withheld_row_does_not_sort_as_a_disagreement(client) -> None:
    """The order is `(not disagreement, -occurrence_count, alert_id)`. Were the withheld row's
    flag set, 50 occurrences would put it ahead of the visible disagreement of 1; withheld, it
    sorts among the rows with none, by its occurrences, ahead of the `false_positive` of 5."""
    tc, db, admin = client
    rule_id = _rule(db, admin.user_id)
    visible = _alert(db, autoclose_rule_id=rule_id, occurrence_count=1)
    _run(db, visible, "escalate")
    agreeing = _alert(db, autoclose_rule_id=rule_id, occurrence_count=5)
    _run(db, agreeing, "false_positive")
    blind = _blind_sai(db, admin.user_id, occurrence_count=50)
    assert _post(tc, blind, "wrong").status_code == 200

    rows = _get(tc).json()["rows"]

    assert [r["alert_id"] for r in rows] == [visible, blind, agreeing]
    assert [r["disagreement"] for r in rows] == [True, False, False]


@pytest.mark.db
def test_the_suggestion_of_a_withheld_row_is_never_read(client, monkeypatch) -> None:
    tc, db, admin = client
    blind = _blind_sai(db, admin.user_id, occurrence_count=2)
    assert _post(tc, blind, "wrong").status_code == 200
    shown = _alert(db, autoclose_rule_id=_rule(db, admin.user_id), suggestion_visible=True)
    _run(db, shown, "escalate")
    assert _post(tc, shown, "wrong").status_code == 200
    asked: list[list[str]] = []
    real = digest.latest_suggestions

    def spy(conn: Any, alert_ids: Any) -> Any:
        asked.append(list(alert_ids))
        return real(conn, alert_ids)

    monkeypatch.setattr(digest, "latest_suggestions", spy)

    rows = digest.reopened_by_review(db, _DAY, tz=TZ)

    assert {r.alert_id for r in rows} == {blind, shown}
    assert asked == [[shown]]  # one read, and the blind alert is not in it


@pytest.mark.db
def test_the_snapshot_row_of_a_post_is_withheld_when_the_alert_went_blind_in_between(
    client, monkeypatch
) -> None:
    """`_row_now` falls back to the snapshot read before the review when neither list has the
    alert any more (a reopen landed between). The snapshot was taken while it was auto-closed;
    the response must not carry ① for an alert that is blind and undecided by now."""
    tc, db, admin = client
    alert_id = _blind_sai(db, admin.user_id, occurrence_count=2)

    def reopened_meanwhile(*_a: Any, **_k: Any) -> list:
        transitions.reopen(db, alert_id, admin.user_id, reason="a Tier 1 analyst, meanwhile")
        return []

    monkeypatch.setattr(admin_digest, "_day_rows", reopened_meanwhile)

    resp = _post(tc, alert_id, "correct")

    assert resp.status_code == 200, resp.text[:300]
    row = resp.json()["row"]
    assert row["suggested_action"] is None and row["disagreement"] is False
    assert "escalate" not in resp.text


@pytest.mark.db
def test_the_snapshot_row_of_a_post_keeps_its_suggestion_on_the_visible_arm(
    client, monkeypatch
) -> None:
    tc, db, admin = client
    alert_id = _alert(db, autoclose_rule_id=_rule(db, admin.user_id), suggestion_visible=True)
    _run(db, alert_id, "escalate")

    def reopened_meanwhile(*_a: Any, **_k: Any) -> list:
        transitions.reopen(db, alert_id, admin.user_id, reason="meanwhile")
        return []

    monkeypatch.setattr(admin_digest, "_day_rows", reopened_meanwhile)

    row = _post(tc, alert_id, "correct").json()["row"]

    assert row["suggested_action"] == "escalate" and row["disagreement"] is True


@pytest.mark.db
def test_an_alert_tier1_reopened_without_a_digest_review_is_not_listed(client) -> None:
    """As before: it left the digest when it left `auto_closed`. So did an alert whose review
    was `correct` or `unsure` and that Tier 1 then reopened: only a `wrong` review keeps it."""
    tc, db, admin = client
    rule_id = _rule(db, admin.user_id)
    kept = _alert(db, autoclose_rule_id=rule_id)
    _reopened(db, admin.user_id, rule_id)
    for verdict in ("correct", "unsure"):
        reviewed = _alert(db, autoclose_rule_id=rule_id)
        assert _post(tc, reviewed, verdict).status_code == 200
        transitions.reopen(db, reviewed, admin.user_id, reason="tier1 looked again")
        assert _alert_state(db, reviewed)[0] == "queued_tier1"

    rows = _get(tc).json()["rows"]

    assert [r["alert_id"] for r in rows] == [kept]
    assert rows[0]["reopened_by_review"] is False


@pytest.mark.db
def test_a_sai_row_is_listed_on_the_day_the_rule_closed_it_and_on_no_other(client) -> None:
    tc, db, admin = client
    rule_id = _rule(db, admin.user_id)
    on_28th = _alert(db, closed_at=_OTHER_DAY, autoclose_rule_id=rule_id)
    last_second = _alert(
        db, closed_at=datetime(2026, 9, 29, 23, 59, 59, tzinfo=HCM), autoclose_rule_id=rule_id
    )
    first_second = _alert(
        db, closed_at=datetime(2026, 9, 30, 0, 0, 0, tzinfo=HCM), autoclose_rule_id=rule_id
    )
    assert _post(tc, on_28th, "wrong", day="2026-09-28").status_code == 200
    assert _post(tc, last_second, "wrong", day="2026-09-29").status_code == 200
    assert _post(tc, first_second, "wrong", day="2026-09-30").status_code == 200

    def listed(day: str) -> list[tuple[str, bool]]:
        return [(r["alert_id"], r["reopened_by_review"]) for r in _get(tc, day).json()["rows"]]

    assert listed("2026-09-28") == [(on_28th, True)]
    assert listed("2026-09-29") == [(last_second, True)]  # not the 28th's, not 00:00:00 on the 30th
    assert listed("2026-09-30") == [(first_second, True)]
    assert listed("2026-10-01") == []


@pytest.mark.db
def test_a_sai_row_follows_the_display_zone_not_utc(client) -> None:
    tc, db, admin = client
    _override(db, admin, tz="UTC")
    rule_id = _rule(db, admin.user_id)
    sai = _alert(
        db, closed_at=datetime(2026, 9, 29, 23, 59, 59, tzinfo=UTC), autoclose_rule_id=rule_id
    )
    assert _post(tc, sai, "wrong", day="2026-09-29").status_code == 200
    assert [r["alert_id"] for r in _get(tc, "2026-09-29").json()["rows"]] == [sai]
    assert _get(tc, "2026-09-30").json()["rows"] == []


@pytest.mark.db
def test_a_reopened_row_with_no_wrong_review_or_a_synthetic_one_is_not_listed(client) -> None:
    """`autoclose_reviews` says `wrong` for the row to be listed: an `alert.auto_closed` event on
    the day and a reopen are not enough, and a synthetic alert is never on the digest."""
    tc, db, admin = client
    rule_id = _rule(db, admin.user_id)
    _reopened(db, admin.user_id, rule_id)
    synthetic = _alert(db, autoclose_rule_id=rule_id, is_synthetic=True)
    digest.review(db, synthetic, "wrong", admin.user_id)  # a review of a synthetic alert
    assert _alert_state(db, synthetic)[0] == "queued_tier1"
    assert _get(tc).json()["rows"] == []


# ---------------------------------------------------------------------------
# A POST costs the same however big the day is (fix round 1, F3)
# ---------------------------------------------------------------------------


class _Counting:
    """The connection the route gets, counting its `execute` calls."""

    def __init__(self, conn: Any) -> None:
        self._conn = conn
        self.n = 0

    def execute(self, *args: Any, **kwargs: Any) -> Any:
        self.n += 1
        return self._conn.execute(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)


@pytest.mark.db
def test_build_with_an_alert_id_reads_only_that_alert_and_without_one_reads_the_day(client) -> None:
    _tc, db, _ = client
    a, b, c = _alert(db), _alert(db), _alert(db, closed_at=_OTHER_DAY)
    for alert_id in (a, b, c):
        _run(db, alert_id, "escalate")
    assert {r.alert_id for r in digest.build(db, _DAY, tz=TZ)} == {a, b}
    assert [r.alert_id for r in digest.build(db, _DAY, tz=TZ, alert_id=a)] == [a]
    assert digest.build(db, _DAY, tz=TZ, alert_id=c) == []  # not closed on that day
    assert digest.build(db, _DAY, tz=TZ, alert_id="no-such-alert") == []
    (one,) = digest.build(db, _DAY, tz=TZ, alert_id=b)
    assert one.suggested_action == "escalate" and one.disagreement is True


@pytest.mark.db
def test_a_post_costs_the_same_statements_for_a_day_of_3_rows_and_of_43(client) -> None:
    """Each POST used to build the whole day twice, with one `latest_suggestion` query per row:
    87 statements at 40 rows and 167 at 80. With `alert_id` given to `build` it is a constant."""
    tc, db, admin = client
    counting = _Counting(db)
    main.app.dependency_overrides[deps.get_conn] = lambda: counting

    def costs(day: str, rows: int) -> dict[str, int]:
        # a rule of its own per day: a second `wrong` review of one rule writes
        # `rule.suspected_wrong`, a few more statements that have nothing to do with the day
        rule_id = _rule(db, admin.user_id, name=f"rule-{day}")
        at = datetime.fromisoformat(f"{day}T12:00:00+07:00")
        ids = [_alert(db, closed_at=at, autoclose_rule_id=rule_id) for _ in range(rows)]
        for alert_id in ids:
            _run(db, alert_id, "false_positive")
        reopened = _reopened(db, admin.user_id, rule_id, closed_at=at)
        out = {}
        for name, alert_id, verdict, expected in (
            ("200 unsure", ids[0], "unsure", 200),
            ("200 wrong", ids[1], "wrong", 200),
            ("409 already_reviewed", ids[0], "unsure", 409),
            ("409 not_auto_closed", reopened, "correct", 409),
            ("404 not_in_digest", "no-such-alert", "correct", 404),
        ):
            counting.n = 0
            resp = _post(tc, alert_id, verdict, day=day)
            assert resp.status_code == expected, (name, resp.status_code, resp.text[:200])
            out[name] = counting.n
        return out

    small = costs("2026-09-20", 3)
    big = costs("2026-09-21", 43)

    assert small == big, (small, big)
    assert max(small.values()) <= 20, small


@pytest.mark.db
def test_build_and_reopened_by_review_cost_two_statements_however_big_the_day(client) -> None:
    """P11-T20 row 20 (P11-T07 round 2, N1). `_rows_from` read ① with one `latest_suggestion`
    query per row: 43 statements for 40 rows, 49 with five "Sai" rows. It now reads the whole
    day's ① in one statement (`queue.latest_suggestions`): the rows, and ① for them, is two
    statements for `build` and two for `reopened_by_review`, at 3 rows and at 43; an empty day
    reads no ① at all. The whole GET is a constant too."""
    tc, db, admin = client
    counting = _Counting(db)

    def seed(day: str, rows: int, sai: int) -> None:
        rule_id = _rule(db, admin.user_id, name=f"rule-{day}")
        at = datetime.fromisoformat(f"{day}T12:00:00+07:00")
        for i in range(rows):
            alert_id = _alert(db, closed_at=at, autoclose_rule_id=rule_id, occurrence_count=i + 1)
            if i % 3 != 2:  # a third of the rows have no ① run yet
                _run(db, alert_id, "false_positive" if i % 3 == 0 else "escalate")
        for _ in range(sai):
            alert_id = _alert(db, closed_at=at, autoclose_rule_id=rule_id)
            digest.review(db, alert_id, "wrong", admin.user_id)

    def costs(day: str) -> dict[str, int]:
        out = {}
        counting.n = 0
        built = digest.build(counting, day, tz=TZ)
        out["build"], rows = counting.n, len(built)
        counting.n = 0
        reopened = digest.reopened_by_review(counting, day, tz=TZ)
        out["reopened_by_review"], sai = counting.n, len(reopened)
        main.app.dependency_overrides[deps.get_conn] = lambda: counting
        counting.n = 0
        listed = tc.get(_DIGEST, params={"day": day})
        assert listed.status_code == 200 and len(listed.json()["rows"]) == rows + sai
        out["GET"] = counting.n
        return out | {"rows": rows, "sai": sai}

    seed("2026-09-22", 3, 1)
    seed("2026-09-23", 43, 5)

    small, big = costs("2026-09-22"), costs("2026-09-23")
    empty = costs("2026-09-24")

    assert (small["rows"], small["sai"], big["rows"], big["sai"]) == (3, 1, 43, 5)
    assert (small["build"], small["reopened_by_review"]) == (2, 2)
    assert (big["build"], big["reopened_by_review"]) == (2, 2)
    assert small["GET"] == big["GET"], (small, big)
    assert (empty["build"], empty["reopened_by_review"]) == (1, 1)  # no row, so no ① read


@pytest.mark.db
def test_the_digest_rows_read_the_suggestion_exactly_as_latest_suggestion_does(client) -> None:
    """The batched read behind `build` and `reopened_by_review` gives each row the verdict the
    one-alert reader gives it, in every state ① can leave an alert in: no run, a failed run, a
    good one, a failed run after a good one (no verdict: the older run does not stand in)."""
    _tc, db, admin = client
    rule_id = _rule(db, admin.user_id)
    day_at = datetime.fromisoformat("2026-09-25T12:00:00+07:00")
    no_run = _alert(db, closed_at=day_at, autoclose_rule_id=rule_id, occurrence_count=1)
    good = _alert(db, closed_at=day_at, autoclose_rule_id=rule_id, occurrence_count=2)
    _run(db, good, "escalate")
    failed_last = _alert(db, closed_at=day_at, autoclose_rule_id=rule_id, occurrence_count=3)
    _run(db, failed_last, "escalate")
    db.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt,"
        " user_message, result, role, gate_result, stopped_by, created_at)"
        " VALUES (gen_random_uuid(), 'triage', 'alert', %s, 's', 'u', NULL, 'proposer', NULL,"
        " 'linter', now() + interval '1 minute')",
        (failed_last,),
    )
    sai = _alert(db, closed_at=day_at, autoclose_rule_id=rule_id, occurrence_count=4)
    _run(db, sai, "needs_review")
    digest.review(db, sai, "wrong", admin.user_id)

    rows = digest.build(db, "2026-09-25", tz=TZ) + digest.reopened_by_review(
        db, "2026-09-25", tz=TZ
    )

    assert {r.alert_id for r in rows} == {no_run, good, failed_last, sai}
    for row in rows:
        reference = queue.latest_suggestion(db, row.alert_id)
        expected = reference.suggested_action if reference else None
        assert row.suggested_action == expected, row.alert_id
        assert row.disagreement == (reference is not None and expected != "false_positive")
    by_id = {r.alert_id: r for r in rows}
    assert by_id[good].suggested_action == "escalate" and by_id[good].disagreement is True
    assert by_id[no_run].suggested_action is None and by_id[no_run].disagreement is False
    assert by_id[failed_last].suggested_action is None  # not the older run's "escalate"
    assert by_id[sai].suggested_action == "needs_review"


# ---------------------------------------------------------------------------
# The 200 after "Sai" is the list's own row (P11-T07 round 2, N2 and N3)
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_two_sai_rows_on_one_day_each_200_names_the_alert_it_reviewed(client) -> None:
    """P11-T20 row 21 (round 2, N2; mutant n9: `reopened_by_review` ignores `alert_id`). Two
    alerts of one day are both reviewed "Sai". The route reads the list's row for the alert it
    just reviewed, so if that read ignored `alert_id` the second 200 would carry the first
    alert's row, the biggest cluster being listed first (9 occurrences against 1)."""
    tc, db, admin = client
    rule_id = _rule(db, admin.user_id)
    big = _alert(db, autoclose_rule_id=rule_id, occurrence_count=9)
    small = _alert(db, autoclose_rule_id=rule_id, occurrence_count=1)

    first = _post(tc, big, "wrong")
    second = _post(tc, small, "wrong")

    assert first.status_code == second.status_code == 200, (first.text[:200], second.text[:200])
    assert first.json()["row"]["alert_id"] == big
    assert second.json()["row"]["alert_id"] == small
    assert second.json()["row"]["occurrence_count"] == 1
    listed = {r["alert_id"]: r for r in _get(tc).json()["rows"]}
    assert set(listed) == {big, small}
    assert listed[big] == first.json()["row"] and listed[small] == second.json()["row"]


@pytest.mark.db
@pytest.mark.parametrize("verdict", ["wrong", "unsure", "correct"])
def test_a_run_that_lands_before_the_review_is_in_the_200s_row_not_only_the_snapshot(
    client, monkeypatch, verdict
) -> None:
    """P11-T20 row 22 (round 2, N3; mutant n7: the 200 always from the snapshot). The route reads
    the alert before the review (`before`) and answers with the row as the list has it after.
    A ① run that lands in between is in the second and not in the first, so the 200 carries it
    and equals the list's row. `digest.review` is wrapped so the run lands right before it."""
    tc, db, admin = client
    alert_id = _alert(db, autoclose_rule_id=_rule(db, admin.user_id))  # no ① run yet
    assert digest.build(db, _DAY, tz=TZ, alert_id=alert_id)[0].suggested_action is None
    real_review = digest.review

    def review_after_a_run(conn, alert, verdict_, reviewer_id):
        _run(conn, alert, "escalate")  # lands after the route's first read, before the review
        return real_review(conn, alert, verdict_, reviewer_id)

    monkeypatch.setattr(digest, "review", review_after_a_run)

    resp = _post(tc, alert_id, verdict)

    assert resp.status_code == 200, resp.text[:300]
    row = resp.json()["row"]
    assert row["suggested_action"] == "escalate" and row["disagreement"] is True
    assert row["reviewed_verdict"] == verdict
    assert _get(tc).json()["rows"] == [row]  # the 200 is the list's row


# ---------------------------------------------------------------------------
# The reviewer's name
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_the_reviewer_name_is_the_display_name_and_falls_back_to_the_username(client) -> None:
    tc, db, admin = client
    blank = _user(db, "admin", display_name="")
    padded = _user(db, "admin", display_name="   ")
    named = _user(db, "admin", display_name="Carol Named")
    expected = {}
    for who, expect in ((blank, blank.username), (padded, padded.username), (named, "Carol Named")):
        alert_id = _alert(db)
        _as(who)
        resp = _post(tc, alert_id, "unsure")
        assert resp.status_code == 200, resp.text[:300]
        assert resp.json()["row"]["reviewed_by_name"] == expect
        expected[alert_id] = expect
    _as(admin)
    listed = {r["alert_id"]: r["reviewed_by_name"] for r in _get(tc).json()["rows"]}
    assert listed == expected


@pytest.mark.db
def test_a_list_mixes_reviewed_and_unreviewed_rows(client) -> None:
    tc, db, _ = client
    a, b = _alert(db, occurrence_count=3), _alert(db, occurrence_count=2)
    assert _post(tc, a, "unsure").status_code == 200
    rows = {r["alert_id"]: r for r in _get(tc).json()["rows"]}
    assert rows[a]["reviewed_verdict"] == "unsure" and rows[a]["reviewed_by_name"] == "Alice Admin"
    assert rows[a]["reviewed_at"] is not None
    assert rows[b]["reviewed_verdict"] is None
    assert rows[b]["reviewed_by_name"] is None and rows[b]["reviewed_at"] is None


@pytest.mark.db
def test_review_details_is_one_query_for_many_alerts_and_empty_for_none(client) -> None:
    _tc, db, admin = client
    a, b, c = _alert(db), _alert(db), _alert(db)
    digest.review(db, a, "correct", admin.user_id)
    digest.review(db, b, "unsure", admin.user_id)
    assert digest.review_details(db, []) == {}
    got = digest.review_details(db, [a, b, c, "missing"])
    assert set(got) == {a, b}
    assert got[a].verdict == "correct" and got[a].reviewer_name == "Alice Admin"
    assert got[b].verdict == "unsure" and got[a].reviewed_at <= got[b].reviewed_at


# ---------------------------------------------------------------------------
# Concurrency — COMMITTED data, each request on a connection of its own
# ---------------------------------------------------------------------------


def _committed_user(dsn: Any, display_name: str, role: str = "admin") -> Claims:
    with psycopg.connect(dsn, autocommit=True) as setup:
        return _user(setup, role, display_name=display_name)


def _committed_alert(dsn: Any, day_instant: datetime) -> str:
    with psycopg.connect(dsn, autocommit=True) as setup:
        return _alert(setup, closed_at=day_instant)


def _threaded_app(dsn: Any, people: dict[str, Claims]) -> None:
    """Every request gets a connection of its own, committed on success and rolled back on
    error exactly as `deps.get_conn` does it, and the caller named by its `X-Test-User` header."""
    cfg = _config()

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

    def current_user(request: Request) -> Claims:
        return people[request.headers["x-test-user"]]

    main.app.dependency_overrides[deps.get_conn] = own_connection
    main.app.dependency_overrides[deps.current_user] = current_user
    main.app.dependency_overrides[deps.get_config] = lambda: cfg


def _post_in_a_thread(
    who: str, alert_id: str, verdict: str, day: str, start: threading.Barrier | None = None
) -> tuple[threading.Thread, dict[str, Any]]:
    out: dict[str, Any] = {}

    def run() -> None:
        try:
            if start is not None:
                start.wait(timeout=10)
            out["response"] = TestClient(main.app).post(
                _review_url(alert_id),
                json={"day": day, "verdict": verdict},
                headers={"X-Test-User": who},
            )
        except Exception as exc:  # noqa: BLE001 - the test reports whatever the app raised
            out["error"] = exc

    thread = threading.Thread(target=run)
    thread.start()
    return thread, out


def _wait_for_a_backend_blocked_on_a_lock(dsn: Any, timeout: float = 10.0) -> None:
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
    raise AssertionError("the review request never blocked on the other connection's lock")


@pytest.mark.db
def test_two_simultaneous_reviews_give_one_200_and_one_409_already_reviewed_never_a_500(
    scratch_dsn, monkeypatch
) -> None:
    """Two admins press a button on the same row at the same moment, each request on its own
    committed connection and started by a barrier. A second barrier inside `digest.review`
    holds both requests until the two have passed the day check, so they reach the review
    together. One review is recorded; the other is `already_reviewed`, and its `row` names the
    winner (the verdict and the reviewer of the review that is on file), whichever one that was."""
    alice = _committed_user(scratch_dsn, "Alice Race")
    bob = _committed_user(scratch_dsn, "Bob Race")
    day = "2026-08-01"
    alert_id = _committed_alert(scratch_dsn, datetime(2026, 8, 1, 12, 0, tzinfo=HCM))
    real_review = digest.review
    meeting = threading.Barrier(2)

    def review_when_both_have_arrived(*args: Any, **kwargs: Any) -> None:
        try:
            meeting.wait(timeout=3)
        except threading.BrokenBarrierError:
            pass
        return real_review(*args, **kwargs)

    monkeypatch.setattr(digest, "review", review_when_both_have_arrived)
    _threaded_app(scratch_dsn, {"alice": alice, "bob": bob})
    start = threading.Barrier(2)
    try:
        t1, out1 = _post_in_a_thread("alice", alert_id, "correct", day, start)
        t2, out2 = _post_in_a_thread("bob", alert_id, "unsure", day, start)
        t1.join(timeout=30)
        t2.join(timeout=30)
        assert not t1.is_alive() and not t2.is_alive()
        outs = [out1, out2]
        assert [o["error"] for o in outs if "error" in o] == []  # never a 500
        assert sorted(o["response"].status_code for o in outs) == [200, 409]
        winner = next(o["response"] for o in outs if o["response"].status_code == 200)
        loser = next(o["response"] for o in outs if o["response"].status_code == 409)
        assert loser.json()["detail"]["reason"] == "already_reviewed"
        won_verdict = winner.json()["row"]["reviewed_verdict"]
        assert won_verdict in {"correct", "unsure"}
        assert loser.json()["detail"]["row"]["reviewed_verdict"] == won_verdict
        won_name = winner.json()["row"]["reviewed_by_name"]
        assert won_name in {"Alice Race", "Bob Race"}
        assert loser.json()["detail"]["row"]["reviewed_by_name"] == won_name
        assert loser.json()["detail"]["row"]["reviewed_at"] == winner.json()["row"]["reviewed_at"]
        with psycopg.connect(scratch_dsn, autocommit=True) as check:
            ((reviewer_id, verdict, _),) = _review_rows(check, alert_id)
            assert verdict == won_verdict
            assert str(reviewer_id) == (alice if won_name == "Alice Race" else bob).user_id
            assert len(_events(check, "autoclose.reviewed", alert_id)) == 1
            assert len(_labels(check, alert_id)) == (1 if won_verdict == "correct" else 0)
    finally:
        _clear_overrides()


@pytest.mark.db
def test_a_review_waits_for_the_row_lock_and_then_sees_that_the_alert_was_reopened(
    scratch_dsn,
) -> None:
    """A Tier 1 analyst reopens the alert (not committed yet) while an admin reviews it as
    `correct`. The request has already seen the alert on the digest. `digest.review`'s
    `SELECT ... FOR UPDATE` must park it on the row; when the reopen commits it reads
    `queued_tier1` and the answer is 409 `not_auto_closed`. Without the lock the review
    would go through beside the reopen: a `correct` verdict and a gold label on an alert that
    is no longer closed."""
    admin = _committed_user(scratch_dsn, "Alice Lock")
    analyst = _committed_user(scratch_dsn, "Tina Tier1", role="tier1")
    day = "2026-08-02"
    alert_id = _committed_alert(scratch_dsn, datetime(2026, 8, 2, 12, 0, tzinfo=HCM))
    holder = psycopg.connect(scratch_dsn)
    try:
        transitions.reopen(holder, alert_id, analyst.user_id, reason="tier1 looked again")
        _threaded_app(scratch_dsn, {"admin": admin})
        thread, out = _post_in_a_thread("admin", alert_id, "correct", day)
        try:
            _wait_for_a_backend_blocked_on_a_lock(scratch_dsn)
        finally:
            holder.commit()  # the reopen lands; the parked review may go on
            thread.join(timeout=15)
        assert not thread.is_alive()
        assert "error" not in out, out.get("error")
        assert out["response"].status_code == 409, out["response"].text[:300]
        assert out["response"].json() == {"detail": {"reason": "not_auto_closed"}}
        with psycopg.connect(scratch_dsn, autocommit=True) as check:
            assert _review_rows(check, alert_id) == []
            assert _labels(check, alert_id) == []
            assert _events(check, "autoclose.reviewed", alert_id) == []
            assert _alert_state(check, alert_id)[0] == "queued_tier1"
    finally:
        _clear_overrides()
        holder.close()


# ---------------------------------------------------------------------------
# Admin only
# ---------------------------------------------------------------------------


def test_the_two_json_routes_are_mounted_and_each_carries_the_admin_dependency() -> None:
    paths = main.app.openapi()["paths"]
    assert "get" in paths[_DIGEST]
    assert "post" in paths[f"{_DIGEST}/{{alert_id}}/review"]
    api_routes = [r for r in admin_digest.router.routes if r.path.startswith("/api/")]
    assert {(m, r.path) for r in api_routes for m in r.methods} == {
        ("GET", _DIGEST),
        ("POST", f"{_DIGEST}/{{alert_id}}/review"),
    }
    for route in api_routes:
        calls = [d.call for d in route.dependant.dependencies]
        assert admin_digest.require_admin in calls, route.path


@pytest.mark.db
def test_a_tier1_user_is_403_on_both_routes_with_authz_denied_and_nothing_reviewed(
    sdb, scratch_dsn
) -> None:
    """`require_role` COMMITS the denial. The alert is committed on a day of its own first, so
    that what the 403 keeps out of the database can be read from another connection."""
    tier1 = _user(sdb, "tier1", display_name="Tina")
    sdb.commit()
    alert_id = _committed_alert(scratch_dsn, datetime(2026, 7, 1, 12, 0, tzinfo=HCM))
    post_path = _review_url(alert_id)
    _override(sdb, tier1)
    try:
        got = TestClient(main.app).get(_DIGEST, params={"day": "2026-07-01"})
        posted = _post(TestClient(main.app), alert_id, "wrong", day="2026-07-01")
    finally:
        _clear_overrides()
    assert got.status_code == 403 and posted.status_code == 403
    assert got.json() == {"detail": "forbidden"} and posted.json() == {"detail": "forbidden"}
    for path, method in ((_DIGEST, "GET"), (post_path, "POST")):
        # by actor: the next test commits a denial of its own on the same path
        ((_, _, payload),) = [
            e for e in _events(sdb, "authz.denied", path) if str(e[1]) == tier1.user_id
        ]
        assert payload["required"] == ["admin"] and payload["role"] == "tier1"
        assert payload["method"] == method
    with psycopg.connect(scratch_dsn, autocommit=True) as check:
        assert _review_rows(check, alert_id) == []
        assert _all_event_types(check, alert_id) == []
        assert _alert_state(check, alert_id)[0] == "auto_closed"


@pytest.mark.db
def test_tier2_is_403_too_and_the_role_check_answers_before_the_day(sdb) -> None:
    tier2 = _user(sdb, "tier2", display_name="Tess")
    _override(sdb, tier2)
    try:
        assert TestClient(main.app).get(_DIGEST, params={"day": "not-a-day"}).status_code == 403
        assert _post(TestClient(main.app), "x", "bad-verdict", day="bad").status_code == 403
    finally:
        _clear_overrides()
        sdb.rollback()
