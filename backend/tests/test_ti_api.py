"""DEC-224 T3 — the Threat Intel API (`web/routers/ti.py` over `app/ti/queries.py`, spec 2026-11-17 §7), over a scratch database:

    GET /api/ti/iocs      the list: filters, `q`, paging, a fixed order, expired rows hidden unless asked
    GET /api/ti/stats     per day and source, top malware, the KPI counts (days of GMT+7)
    GET /api/ti/lookup    the rows whose value equals the input after the importer's normalisation
    GET /api/ti/status    the newest import-log row, the newest successful one, `stale`
    GET /api/ti/export    admin only: the list as CSV (formula-guarded) or as a plain-text blocklist

Every route needs a login; `tier1`, `tier2` and `admin` read, export is `admin`. Every read runs under a statement timeout
(a held lock turns a read into a closed `503 {"detail": {"reason": "timeout"}}`), `q` is at most 128 characters, the CSV starts
with a UTF-8 byte order mark and the blocklist never carries an address or a name a firewall must not block (Ruling TI9). The routes only read: nothing here writes a row
of `ti_ioc`, of `ti_import_log` or an audit event (but the `authz.denied` of a refused role).

The module owns a scratch database (`scratch_database`: built through `scripts/migrate.sh`, dropped when the module ends), so what a
test commits never reaches the shared one. The route runs as in production: `deps.get_conn` itself, on a connection that has
SET ROLE `app_rw` (the app's role: SELECT, INSERT and UPDATE, no DELETE), so a missing grant is a failing test; only the signed-in
user, the configuration and the CLOCK (`ti.get_clock`) are overridden. Every row is made up: documentation address ranges,
`example.*` names, invented hashes.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import re
import socket
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
import pytest
from app.infra.auth import Claims
from app.infra.config import Config
from app.ti import queries
from app.ti.importer import normalise_value
from app.web import deps, main
from app.web.routers import ti as ti_router
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient

from tests.scratch_db import insert_user, scratch_database

pytestmark = pytest.mark.db

NOW = datetime(2026, 11, 17, 9, 0, 0, tzinfo=UTC)  # 16:00 on 17/11/2026 in GMT+7
TODAY = "2026-11-17"
IOCS = "/api/ti/iocs"
STATS = "/api/ti/stats"
LOOKUP = "/api/ti/lookup"
STATUS = "/api/ti/status"
EXPORT = "/api/ti/export"
READ_ROUTES = [IOCS, STATS, f"{LOOKUP}?value=192.0.2.1", STATUS]

IOC_KEYS = [
    "id", "source", "type", "value", "malware", "threat", "confidence", "tags", "reference",
    "first_seen", "last_seen", "imported_at", "expires_at", "expired", "hit_count", "last_hit",
]  # fmt: skip
LOG_KEYS = [
    "id", "file", "started_at", "finished_at", "rows_total", "rows_new", "rows_updated", "rows_error",
    "status", "message",
]  # fmt: skip
#: A row with nothing in it a search could find by accident.
BARE = {"malware": None, "threat": None, "tags": [], "reference": None}


def at(*args: int) -> datetime:
    return datetime(*args, tzinfo=UTC)


def ago(**delta: float) -> datetime:
    return NOW - timedelta(**delta)


@pytest.fixture(scope="module")
def scratch_dsn():
    with scratch_database("tiapi") as dsn:
        yield dsn


@dataclass
class Api:
    """The scratch database `dsn`, one user per role, the clock the routes are given, and what a test puts in."""

    dsn: Any  # a conftest.Dsn, never a plain str: a plain str prints a password in a report
    now: datetime = NOW
    counter: int = 0

    def __post_init__(self) -> None:
        with psycopg.connect(self.dsn) as setup:
            self.users: dict[str, tuple[str, str]] = {}
            for role in ("tier1", "tier2", "admin"):
                user_id = insert_user(setup, role)
                (username,) = setup.execute(
                    "SELECT username FROM users WHERE user_id = %s", (user_id,)
                ).fetchone()
                self.users[role] = (user_id, username)

    # ── clients ─────────────────────────────────────────────────────────────────────────────

    def _wire(self) -> None:
        main.app.dependency_overrides[deps.get_config] = lambda: Config()
        main.app.dependency_overrides[ti_router.get_clock] = lambda: lambda: self.now

    def _signed_in(self, request: Request) -> Claims:
        """The caller, named by the `x-test-role` header of the request."""
        role = request.headers.get("x-test-role")
        if role is None:
            raise HTTPException(status_code=401, detail="not authenticated")
        user_id, username = self.users.get(role, (self.users["tier1"][0], f"x-{role}"))
        return Claims(user_id=user_id, username=username, role=role, iat=0.0, exp=0.0)

    def client(self, role: str = "tier2") -> TestClient:
        self._wire()
        main.app.dependency_overrides[deps.current_user] = self._signed_in
        return TestClient(main.app, raise_server_exceptions=False, headers={"x-test-role": role})

    def anonymous(self) -> TestClient:
        """No token: the real `current_user` answers."""
        self._wire()
        main.app.dependency_overrides.pop(deps.current_user, None)
        return TestClient(main.app, raise_server_exceptions=False)

    def unwire(self) -> None:
        for dependency in (deps.current_user, deps.get_config, ti_router.get_clock):
            main.app.dependency_overrides.pop(dependency, None)

    def get(self, role: str, path: str, **params: Any):
        return self.client(role).get(path, params=params or None)

    # ── what a second connection sees ───────────────────────────────────────────────────────

    def rows(self, query: str, params: tuple = ()) -> list[tuple]:
        with psycopg.connect(self.dsn) as conn:
            return conn.execute(query, params).fetchall()

    def execute(self, query: str, params: tuple = ()) -> None:
        with psycopg.connect(self.dsn) as conn:
            conn.execute(query, params)

    def counts(self) -> tuple[int, int, int]:
        return (
            self.rows("SELECT count(*) FROM ti_ioc")[0][0],
            self.rows("SELECT count(*) FROM ti_import_log")[0][0],
            self.rows("SELECT count(*) FROM audit_events")[0][0],
        )

    def denied(self, role: str) -> list[tuple]:
        return self.rows(
            "SELECT subject_id, payload FROM audit_events WHERE event_type = 'authz.denied' "
            "AND actor_id = %s ORDER BY audit_id",
            (self.users[role][0],),
        )

    # ── what a test puts in ─────────────────────────────────────────────────────────────────

    def put(self, **over: Any) -> int:
        """One `ti_ioc` row, committed; its id. Unique by default (the counter is in the value). Fresh: expires in 29 days."""
        self.counter += 1
        row: dict[str, Any] = {
            "source": "threatfox",
            "type": "ip:port",
            "value": f"192.0.2.{self.counter % 250 + 1}:{10000 + self.counter}",
            "malware": "win.example_rat",
            "threat": "botnet_cc",
            "confidence": 75,
            "tags": ["example_rat", "c2"],
            "reference": "https://threatfox.abuse.ch/ioc/90000001/",
            "first_seen": ago(hours=1),
            "last_seen": ago(hours=1),
            "imported_at": ago(days=1),
            "expires_at": NOW + timedelta(days=29),
            "hit_count": 0,
            "last_hit": None,
        }
        row.update(over)
        names = list(row)
        with psycopg.connect(self.dsn) as conn:
            (new_id,) = conn.execute(
                f"INSERT INTO ti_ioc ({', '.join(names)}) "
                f"VALUES ({', '.join('%s' for _ in names)}) RETURNING id",
                list(row.values()),
            ).fetchone()
        return new_id

    def put_log(
        self,
        finished: datetime,
        *,
        status: str = "ok",
        rows_total: int = 100,
        rows_new: int = 10,
        rows_updated: int = 90,
        rows_error: int = 0,
        file: str = "ioc_2026-11-17.csv",
        message: str | None = None,
    ) -> int:
        with psycopg.connect(self.dsn) as conn:
            (new_id,) = conn.execute(
                "INSERT INTO ti_import_log (file, started_at, finished_at, rows_total, rows_new, rows_updated, "
                "rows_error, status, message) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
                (
                    file,
                    finished - timedelta(seconds=5),
                    finished,
                    rows_total,
                    rows_new,
                    rows_updated,
                    rows_error,
                    status,
                    message,
                ),
            ).fetchone()
        return new_id


@pytest.fixture
def api(scratch_dsn, monkeypatch):
    def connect(*args, **kwargs):
        """What `deps.get_conn` opens: the scratch database, as the app's role."""
        conn = psycopg.connect(scratch_dsn, autocommit=True)
        conn.execute("SET ROLE app_rw")
        conn.autocommit = False
        return conn

    monkeypatch.setattr("app.web.deps.db.connect", connect)
    world = Api(scratch_dsn)
    world.execute("TRUNCATE ti_ioc, ti_import_log RESTART IDENTITY")
    try:
        yield world
    finally:
        world.unwire()


def ids(response) -> list[int]:
    assert response.status_code == 200, response.text
    return [row["id"] for row in response.json()["rows"]]


def read_csv(response) -> list[dict[str, str]]:
    assert response.status_code == 200, response.text
    reader = csv.DictReader(io.StringIO(response.content.decode("utf-8-sig"), newline=""))
    return list(reader)


# ═══════════════════════════ the list ═══════════════════════════════════════════════════════


def test_the_list_answers_rows_total_page_and_page_size(api):
    api.put()
    body = api.get("tier2", IOCS).json()
    assert list(body) == ["rows", "total", "page", "page_size"]
    assert (body["total"], body["page"], body["page_size"]) == (1, 1, 50)
    assert list(body["rows"][0]) == IOC_KEYS


def test_a_row_is_served_field_for_field_with_timestamps_in_utc(api):
    new_id = api.put(
        source="threatfox",
        type="domain",
        value="c2.example.com",
        malware="win.example_rat",
        threat="botnet_cc",
        confidence=90,
        tags=["example_rat", "c2"],
        reference="https://threatfox.abuse.ch/ioc/90000003/",
        first_seen=at(2026, 11, 17, 5, 40, 19),
        last_seen=at(2026, 11, 17, 7, 5),
        imported_at=at(2026, 11, 17, 7, 5),
        expires_at=at(2026, 12, 17, 7, 5),
        hit_count=2,
        last_hit=at(2026, 11, 17, 8, 0),
    )
    (row,) = api.get("tier2", IOCS).json()["rows"]
    assert row == {
        "id": new_id,
        "source": "threatfox",
        "type": "domain",
        "value": "c2.example.com",
        "malware": "win.example_rat",
        "threat": "botnet_cc",
        "confidence": 90,
        "tags": ["example_rat", "c2"],
        "reference": "https://threatfox.abuse.ch/ioc/90000003/",
        "first_seen": "2026-11-17T05:40:19+00:00",
        "last_seen": "2026-11-17T07:05:00+00:00",
        "imported_at": "2026-11-17T07:05:00+00:00",
        "expires_at": "2026-12-17T07:05:00+00:00",
        "expired": False,
        "hit_count": 2,
        "last_hit": "2026-11-17T08:00:00+00:00",
    }


def test_a_row_without_confidence_malware_or_tags_is_served_with_nulls_and_an_empty_list(api):
    api.put(
        source="malwarebazaar",
        type="sha256_hash",
        value="a" * 64,
        confidence=None,
        malware=None,
        threat=None,
        reference=None,
        tags=[],
    )
    (row,) = api.get("tier2", IOCS).json()["rows"]
    assert row["confidence"] is None and row["malware"] is None and row["threat"] is None
    assert row["reference"] is None and row["tags"] == [] and row["last_hit"] is None


def test_the_order_is_newest_first_and_the_highest_id_first_among_equals(api):
    same = ago(hours=1)
    tied = [api.put(first_seen=same) for _ in range(5)]
    older = [api.put(first_seen=ago(hours=2)) for _ in range(3)]
    newest = api.put(first_seen=ago(minutes=10))
    # the physical order of the rows is not the id order: the tie is broken by the id, not by luck
    api.execute("UPDATE ti_ioc SET hit_count = 0 WHERE id = ANY(%s)", (sorted(tied + older),))
    expected = [newest, *sorted(tied, reverse=True), *sorted(older, reverse=True)]
    assert ids(api.get("tier2", IOCS, page_size=200)) == expected


def test_the_pages_of_a_list_with_ties_do_not_overlap_or_skip(api):
    same = ago(hours=1)
    for _ in range(7):
        api.put(first_seen=same)
    for _ in range(4):
        api.put(first_seen=ago(hours=3))
    full = ids(api.get("tier2", IOCS, page_size=200))
    assert len(full) == 11 and len(set(full)) == 11
    for size in (1, 2, 3, 4, 5):
        walked: list[int] = []
        pages = -(-11 // size)
        for number in range(1, pages + 1):
            walked += ids(api.get("tier2", IOCS, page=number, page_size=size))
        assert walked == full, size


def test_the_order_does_not_come_from_the_request(api):
    first = api.put(first_seen=ago(hours=1), value="b.example.com", type="domain")
    second = api.put(first_seen=ago(hours=2), value="a.example.com", type="domain")
    default = ids(api.get("tier2", IOCS))
    assert default == [first, second]
    for params in (
        {"sort": "value"},
        {"order": "asc"},
        {"sort": "value; DROP TABLE ti_ioc", "order": "asc; DROP TABLE ti_ioc"},
        {"sort_by": "first_seen", "dir": "asc", "order_by": "value"},
    ):
        assert ids(api.get("tier2", IOCS, **params)) == default, params
    assert api.counts()[0] == 2


def test_the_default_page_size_is_fifty_and_the_last_page_holds_the_rest(api):
    for _ in range(55):
        api.put()
    first = api.get("tier2", IOCS).json()
    assert (first["total"], len(first["rows"]), first["page_size"]) == (55, 50, 50)
    second = api.get("tier2", IOCS, page=2).json()
    assert (second["total"], len(second["rows"]), second["page"]) == (55, 5, 2)
    assert not set(ids(api.get("tier2", IOCS))) & set(ids(api.get("tier2", IOCS, page=2)))


def test_a_page_size_of_two_hundred_is_served_whole(api):
    for _ in range(205):
        api.put()
    body = api.get("tier2", IOCS, page_size=200).json()
    assert (len(body["rows"]), body["total"], body["page_size"]) == (200, 205, 200)


def test_a_page_past_the_end_is_an_empty_list_with_the_right_total(api):
    for _ in range(3):
        api.put()
    body = api.get("tier2", IOCS, page=2, page_size=2).json()
    assert len(body["rows"]) == 1
    for deep in (3, 50, 1_000_000):
        body = api.get("tier2", IOCS, page=deep, page_size=2).json()
        assert (body["rows"], body["total"], body["page"]) == ([], 3, deep)
    body = api.get("tier2", IOCS, page=7, source="urlhaus").json()
    assert (body["rows"], body["total"]) == ([], 0)


def test_an_empty_table_is_an_empty_list(api):
    body = api.get("tier2", IOCS).json()
    assert (body["rows"], body["total"]) == ([], 0)


# ── the filters ─────────────────────────────────────────────────────────────────────────────


def test_source_filters_alone(api):
    tf = api.put(source="threatfox")
    uh = api.put(source="urlhaus", type="url", value="http://c2.example.com/a")
    mb = api.put(source="malwarebazaar", type="sha256_hash", value="b" * 64)
    assert ids(api.get("tier2", IOCS, source="threatfox")) == [tf]
    assert ids(api.get("tier2", IOCS, source="urlhaus")) == [uh]
    assert ids(api.get("tier2", IOCS, source="malwarebazaar")) == [mb]
    assert sorted(ids(api.get("tier2", IOCS))) == [tf, uh, mb]


def test_type_filters_alone_and_is_read_as_the_importer_stores_it(api):
    ipp = api.put(type="ip:port", value="192.0.2.1:443")
    dom = api.put(type="domain", value="c2.example.com")
    api.put(type="url", value="http://c2.example.com/a")
    assert ids(api.get("tier2", IOCS, type="domain")) == [dom]
    assert ids(api.get("tier2", IOCS, type="DOMAIN")) == [dom]  # stored lower-case, read lower-case
    assert ids(api.get("tier2", IOCS, type=" ip:port ")) == [ipp]
    assert ids(api.get("tier2", IOCS, type="sha256_hash")) == []
    assert ids(api.get("tier2", IOCS, type="dom")) == []  # equality, not a prefix


def test_malware_filters_by_the_exact_name(api):
    alpha = api.put(malware="win.alpha")
    api.put(malware="win.alpha_two")
    api.put(malware=None)
    assert ids(api.get("tier2", IOCS, malware="win.alpha")) == [alpha]
    assert ids(api.get("tier2", IOCS, malware="  win.alpha  ")) == [alpha]
    assert ids(api.get("tier2", IOCS, malware="win")) == []
    assert ids(api.get("tier2", IOCS, malware="WIN.ALPHA")) == []
    assert ids(api.get("tier2", IOCS, malware="win.alpha%")) == []  # no wildcard in an equality
    assert ids(api.get("tier2", IOCS, malware="win.alph_")) == []


def test_blank_text_filters_are_no_filter(api):
    one = api.put()
    two = api.put()
    for params in ({"q": ""}, {"q": "   "}, {"type": ""}, {"malware": " "}):
        assert sorted(ids(api.get("tier2", IOCS, **params))) == [one, two], params


def test_min_confidence_keeps_the_rows_at_or_over_it_and_leaves_out_the_rows_with_none(api):
    unknown = api.put(confidence=None)
    zero = api.put(confidence=0)
    fifty = api.put(confidence=50)
    s75 = api.put(confidence=75)
    full = api.put(confidence=100)
    assert sorted(ids(api.get("tier2", IOCS, min_confidence=100))) == [full]
    assert sorted(ids(api.get("tier2", IOCS, min_confidence=75))) == sorted([s75, full])
    assert sorted(ids(api.get("tier2", IOCS, min_confidence=51))) == sorted([s75, full])
    # even 0 leaves out a row whose confidence is unknown: "at least 0" is a statement about a number
    assert sorted(ids(api.get("tier2", IOCS, min_confidence=0))) == sorted([zero, fifty, s75, full])
    assert unknown not in ids(api.get("tier2", IOCS, min_confidence=0))
    assert unknown in ids(api.get("tier2", IOCS))


def day_rows(api) -> dict[str, int]:
    """Four rows round the GMT+7 midnight of 17/11: the 16th at 23:59:59, the 17th at 00:00:00 and 23:59:59, the 18th at 00:00:00."""
    return {
        "late16": api.put(first_seen=at(2026, 11, 16, 16, 59, 59)),
        "early17": api.put(first_seen=at(2026, 11, 16, 17, 0, 0)),
        "late17": api.put(first_seen=at(2026, 11, 17, 16, 59, 59)),
        "early18": api.put(first_seen=at(2026, 11, 17, 17, 0, 0)),
    }


def test_from_and_to_as_dates_are_the_whole_days_of_gmt_plus_7(api):
    r = day_rows(api)
    both = api.get("tier2", IOCS, **{"from": "2026-11-17", "to": "2026-11-17"})
    assert sorted(ids(both)) == sorted([r["early17"], r["late17"]])
    assert ids(api.get("tier2", IOCS, **{"from": "2026-11-18"})) == [r["early18"]]
    assert sorted(ids(api.get("tier2", IOCS, to="2026-11-16"))) == [r["late16"]]
    wide = api.get("tier2", IOCS, **{"from": "2026-11-16", "to": "2026-11-18"})
    assert len(ids(wide)) == 4


def test_from_and_to_as_times_with_an_offset_are_inclusive_instants(api):
    r = day_rows(api)
    exact = api.get(
        "tier2", IOCS, **{"from": "2026-11-17T00:00:00+07:00", "to": "2026-11-17T23:59:59+07:00"}
    )
    assert sorted(ids(exact)) == sorted([r["early17"], r["late17"]])  # both ends are in
    after = api.get("tier2", IOCS, **{"from": "2026-11-17T00:00:01+07:00"})
    assert r["early17"] not in ids(after) and r["late17"] in ids(after)
    before = api.get("tier2", IOCS, to="2026-11-16T23:59:58+07:00")
    assert r["late16"] not in ids(before)
    utc_form = api.get(
        "tier2", IOCS, **{"from": "2026-11-16T17:00:00Z", "to": "2026-11-17T16:59:59Z"}
    )
    assert sorted(ids(utc_form)) == sorted([r["early17"], r["late17"]])


def test_a_time_with_no_zone_is_read_as_gmt_plus_7(api):
    r = day_rows(api)
    got = api.get("tier2", IOCS, **{"from": "2026-11-17T00:00:00", "to": "2026-11-17T23:59:59"})
    assert sorted(ids(got)) == sorted([r["early17"], r["late17"]])
    got = api.get("tier2", IOCS, **{"from": "2026-11-17 00:00:01"})
    assert r["early17"] not in ids(got)


def test_a_range_that_is_the_wrong_way_round_is_an_empty_list(api):
    day_rows(api)
    got = api.get("tier2", IOCS, **{"from": "2026-11-18", "to": "2026-11-16"}).json()
    assert (got["rows"], got["total"]) == ([], 0)


def test_q_is_a_case_insensitive_substring_of_value_malware_threat_and_a_tag(api):
    by_value = api.put(type="url", value="http://Evil.Example.com/Panel", **BARE)
    by_malware = api.put(**{**BARE, "malware": "win.Needle_Rat"})
    by_threat = api.put(**{**BARE, "threat": "NEEDLE_dropper"})
    by_tag = api.put(**{**BARE, "tags": ["c2", "Needle"]})
    miss = api.put(**{**BARE, "tags": ["haystack"]})
    assert ids(api.get("tier2", IOCS, q="EVIL.example")) == [by_value]
    assert ids(api.get("tier2", IOCS, q="panel")) == [by_value]
    assert ids(api.get("tier2", IOCS, q="needle_rat")) == [by_malware]
    assert ids(api.get("tier2", IOCS, q="Needle_dropper")) == [by_threat]
    assert sorted(ids(api.get("tier2", IOCS, q="needle"))) == sorted(
        [by_malware, by_threat, by_tag]
    )
    assert ids(api.get("tier2", IOCS, q="  needle_dropper  ")) == [by_threat]
    assert ids(api.get("tier2", IOCS, q="hayst")) == [miss]
    assert ids(api.get("tier2", IOCS, q="no such thing")) == []


def test_q_does_not_look_in_the_reference_or_the_source(api):
    api.put(**{**BARE, "reference": "https://threatfox.abuse.ch/ioc/90000001/"})
    assert ids(api.get("tier2", IOCS, q="abuse.ch")) == []
    assert ids(api.get("tier2", IOCS, q="threatfox")) == []


def test_percent_underscore_backslash_and_quote_in_q_are_literal(api):
    plain = {**BARE, "type": "domain"}
    under = api.put(value="a_b.example.com", **plain)
    api.put(value="axb.example.com", **plain)
    percent = api.put(value="100%.example.com", **plain)
    api.put(value="1000.example.com", **plain)
    back = api.put(value="back\\slash.example.com", **plain)
    api.put(value="backslash.example.com", **plain)
    quote = api.put(value="o'neil.example.com", **plain)
    assert ids(api.get("tier2", IOCS, q="a_b")) == [under]
    assert ids(api.get("tier2", IOCS, q="_")) == [under]
    assert ids(api.get("tier2", IOCS, q="%")) == [percent]
    assert ids(api.get("tier2", IOCS, q="100%")) == [percent]
    assert ids(api.get("tier2", IOCS, q="\\")) == [back]
    assert ids(api.get("tier2", IOCS, q="back\\")) == [back]
    assert ids(api.get("tier2", IOCS, q="'")) == [quote]
    assert (
        ids(api.get("tier2", IOCS, q="\\%")) == []
    )  # the two characters, in this order, are nowhere
    assert ids(api.get("tier2", IOCS, q="a%b")) == []
    assert ids(api.get("tier2", IOCS, q="%%")) == []
    assert len(ids(api.get("tier2", IOCS))) == 7


def test_a_hostile_q_is_a_literal_search_and_no_error(api):
    api.put()
    for hostile in (
        "'; DROP TABLE ti_ioc; --",
        "' OR '1'='1",
        '" OR ""="',
        "%s",
        "%(x)s",
        "%(q_like)s",
        "{0}",
        "{}",
        "\\",
        "\\\\",
        "a\\",
        "$1",
        "?",
        ":x",
        "<script>alert(1)</script>",
        "é" * 100,
        "\u202e",
        "\ufffd",
    ):
        response = api.get("tier2", IOCS, q=hostile)
        assert response.status_code == 200, (hostile, response.text)
        assert response.json()["total"] == 0, hostile
    assert api.counts()[0] == 1  # the table is there, and so is its row


def test_a_hostile_filter_value_is_a_literal_value_and_no_error(api):
    api.put()
    for name in ("type", "malware"):
        for hostile in ("'; DROP TABLE ti_ioc; --", "%", "_", "\\", "%s", "x' OR 1=1 --"):
            response = api.get("tier2", IOCS, **{name: hostile})
            assert response.status_code == 200, (name, hostile)
            assert response.json()["total"] == 0, (name, hostile)
    assert api.counts()[0] == 1


def test_every_filter_together_leaves_the_one_row_that_meets_them_all(api):
    target = api.put(
        source="urlhaus",
        type="url",
        value="http://c2.example.com/needle",
        malware="win.alpha",
        confidence=90,
        first_seen=at(2026, 11, 17, 3, 0),
        threat="payload_delivery",
    )
    # one row per filter that fails exactly that filter
    api.put(source="threatfox", type="url", value="http://c2.example.com/needle", malware="win.alpha", confidence=90, first_seen=at(2026, 11, 17, 3, 0))  # fmt: skip
    api.put(source="urlhaus", type="domain", value="needle.example.com", malware="win.alpha", confidence=90, first_seen=at(2026, 11, 17, 3, 0))  # fmt: skip
    api.put(source="urlhaus", type="url", value="http://c2.example.com/needle2", malware="win.beta", confidence=90, first_seen=at(2026, 11, 17, 3, 0))  # fmt: skip
    api.put(source="urlhaus", type="url", value="http://c2.example.com/needle3", malware="win.alpha", confidence=40, first_seen=at(2026, 11, 17, 3, 0))  # fmt: skip
    api.put(source="urlhaus", type="url", value="http://c2.example.com/needle4", malware="win.alpha", confidence=90, first_seen=at(2026, 11, 10, 3, 0))  # fmt: skip
    api.put(source="urlhaus", type="url", value="http://c2.example.com/other", malware="win.alpha", confidence=90, first_seen=at(2026, 11, 17, 3, 0), threat="x", tags=[])  # fmt: skip
    api.put(source="urlhaus", type="url", value="http://c2.example.com/needle5", malware="win.alpha", confidence=90, first_seen=at(2026, 11, 18, 3, 0))  # fmt: skip
    got = api.get(
        "tier2",
        IOCS,
        source="urlhaus",
        type="url",
        malware="win.alpha",
        min_confidence=80,
        q="needle",
        **{"from": "2026-11-16", "to": "2026-11-17"},
    )
    assert ids(got) == [target]


# ── expired rows ────────────────────────────────────────────────────────────────────────────


def test_an_expired_row_is_left_out_unless_asked_for(api):
    live = api.put(expires_at=NOW + timedelta(days=1))
    api.put(expires_at=NOW - timedelta(days=1))
    assert ids(api.get("tier2", IOCS)) == [live]
    assert api.get("tier2", IOCS).json()["total"] == 1
    assert ids(api.get("tier2", IOCS, expired="false")) == [live]


def test_expired_true_serves_the_expired_rows_too_each_marked(api):
    live = api.put(expires_at=NOW + timedelta(days=1), first_seen=ago(hours=1))
    gone = api.put(expires_at=NOW - timedelta(days=1), first_seen=ago(hours=2))
    body = api.get("tier2", IOCS, expired="true").json()
    assert [(r["id"], r["expired"]) for r in body["rows"]] == [(live, False), (gone, True)]
    assert body["total"] == 2


def test_a_row_expires_at_the_instant_in_expires_at(api):
    on_the_instant = api.put(expires_at=NOW)
    a_moment_left = api.put(expires_at=NOW + timedelta(microseconds=1))
    assert ids(api.get("tier2", IOCS)) == [a_moment_left]
    both = api.get("tier2", IOCS, expired="true").json()["rows"]
    assert {r["id"]: r["expired"] for r in both} == {on_the_instant: True, a_moment_left: False}


def test_expiry_is_judged_by_the_routes_clock(api):
    row = api.put(expires_at=NOW + timedelta(days=1))
    assert ids(api.get("tier2", IOCS)) == [row]
    api.now = NOW + timedelta(days=2)
    assert ids(api.get("tier2", IOCS)) == []
    assert api.get("tier2", IOCS, expired="true").json()["rows"][0]["expired"] is True


# ── bounds: a 422 and never a 500 ──────────────────────────────────────────────────────────

BAD_PAGING = [
    {"page": 0},
    {"page": -1},
    {"page": "x"},
    {"page": 1_000_001},
    {"page": 1.5},
    {"page_size": 0},
    {"page_size": -5},
    {"page_size": 201},
    {"page_size": "x"},
]
BAD_FILTERS = [
    {"min_confidence": -1},
    {"min_confidence": 101},
    {"min_confidence": "x"},
    {"min_confidence": 7.5},
    {"source": "other"},
    {"source": "ThreatFox"},
    {"source": ""},
    {"source": "threatfox' OR 1=1"},
    {"q": "x" * 129},
    {"q": "http://" + "a" * 200 + ".example.com/"},
    {"type": "x" * 65},
    {"malware": "x" * 257},
    {"from": "yesterday"},
    {"to": "2026-13-45"},
    {"from": "2026-11-17T25:00:00"},
    {"from": "2026-11-17T00:00:00 07:00"},  # an unencoded `+` is a space
    {"to": "9999-12-31"},
    {"from": "x" * 65},
    {"expired": "maybe"},
    {"q": "a\x00b"},
    {"malware": "\x00"},
    {"type": "ip\x00:port"},
    {"from": "2026-11-17\x00"},
]


@pytest.mark.parametrize("params", BAD_PAGING, ids=lambda p: str(p)[:60])
def test_an_out_of_range_page_is_a_422(api, params):
    api.put()
    assert api.get("tier2", IOCS, **params).status_code == 422


@pytest.mark.parametrize("params", BAD_FILTERS, ids=lambda p: str(p)[:60])
def test_an_out_of_range_filter_is_a_422_on_the_list_and_on_the_export(api, params):
    api.put()
    assert api.get("tier2", IOCS, **params).status_code == 422
    assert api.get("admin", EXPORT, **params).status_code == 422


@pytest.mark.parametrize(
    "path, params",
    [
        (STATS, {"days": 0}),
        (STATS, {"days": 91}),
        (STATS, {"days": -3}),
        (STATS, {"days": "x"}),
        (STATS, {"days": 7.5}),
        (LOOKUP, {}),
        (LOOKUP, {"value": ""}),
        (LOOKUP, {"value": "   "}),
        (LOOKUP, {"value": "x" * 2049}),
        (LOOKUP, {"value": "a\x00b"}),
        (EXPORT, {"format": "xml"}),
        (EXPORT, {"format": ""}),
        (EXPORT, {"format": "CSV"}),
    ],
    ids=lambda p: str(p)[:50],
)
def test_the_other_routes_refuse_their_bad_inputs_with_a_422(api, path, params):
    assert api.get("admin", path, **params).status_code == 422


def test_the_edge_values_of_the_bounds_are_accepted(api):
    api.put()
    for params in (
        {"page": 1},
        {"page": 1_000_000},
        {"page_size": 1},
        {"page_size": 200},
        {"min_confidence": 0},
        {"min_confidence": 100},
        {"q": "x" * 128},
        {"type": "x" * 64},
        {"malware": "x" * 256},
        {"from": "0001-01-02"},
        {"to": "9999-12-30"},
    ):
        assert api.get("tier2", IOCS, **params).status_code == 200, params
    for days in (1, 90):
        assert api.get("tier2", STATS, days=days).status_code == 200
    assert api.get("tier2", LOOKUP, value="x" * 2048).status_code == 200


def test_a_long_or_odd_text_never_reaches_a_500_on_any_route(api):
    api.put()
    odd = ["\u0000", "\ud7ff", "\U0001f600" * 500, "\u202e\u2028\u2029", "\x7f\x9f", "\t\r\n"]
    for text in odd:
        for role, path, name in (
            ("tier2", IOCS, "q"),
            ("tier2", IOCS, "malware"),
            ("tier2", IOCS, "type"),
            ("tier2", LOOKUP, "value"),
            ("admin", EXPORT, "q"),
        ):
            status = api.get(role, path, **{name: text}).status_code
            assert status in (200, 422), (path, name, repr(text[:10]), status)


# ── the values are data ─────────────────────────────────────────────────────────────────────

HOSTILE_VALUES = [
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "=cmd|' /C calc'!A0",
    "http://evil.example.com/a?b=c&d=<script>alert(1)</script>",
    '" onmouseover="alert(1)',
    "'; DROP TABLE ti_ioc; --",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "&lt;b&gt;bold&lt;/b&gt;",
]


def test_a_value_comes_back_exactly_as_it_is_stored(api):
    stored = {
        value: api.put(type="url", value=value, reference=value, threat=value, tags=[value])
        for value in HOSTILE_VALUES
    }
    response = api.get("tier2", IOCS, page_size=200)
    assert response.headers["content-type"].startswith("application/json")
    by_id = {row["id"]: row for row in response.json()["rows"]}
    for value, new_id in stored.items():
        row = by_id[new_id]
        assert row["value"] == value and row["reference"] == value and row["threat"] == value
        assert row["tags"] == [value]
    for value in HOSTILE_VALUES:  # the lookup too
        found = api.get("tier2", LOOKUP, value=value)
        assert found.status_code == 200
        assert [r["id"] for r in found.json()["rows"]] == [stored[value]], value


def test_no_route_resolves_fetches_or_opens_anything(api, monkeypatch):
    """The routes treat a domain and a URL as text: nothing in this process looks a name up or opens a socket of its own (the
    database driver's connection is libpq's, not Python's)."""
    api.put(type="domain", value="c2.example.com")
    api.put(type="url", value="http://c2.example.com/a")

    def refuse(*args, **kwargs):
        raise AssertionError("a route reached the network")

    for name in (
        "getaddrinfo",
        "gethostbyname",
        "gethostbyname_ex",
        "gethostbyaddr",
        "create_connection",
    ):
        monkeypatch.setattr(socket, name, refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "sendto", refuse)
    for role, path in (
        ("admin", f"{IOCS}?q=example.com"),
        ("admin", f"{LOOKUP}?value=c2.example.com"),
        ("admin", f"{LOOKUP}?value=http://c2.example.com/a"),
        ("admin", STATS),
        ("admin", STATUS),
        ("admin", f"{EXPORT}?format=csv"),
        ("admin", f"{EXPORT}?format=blocklist"),
    ):
        assert api.client(role).get(path).status_code == 200, path


# ═══════════════════════════ roles ═══════════════════════════════════════════════════════════


@pytest.mark.parametrize(
    "path", [*READ_ROUTES, f"{EXPORT}?format=csv", f"{EXPORT}?format=blocklist"]
)
def test_every_route_needs_a_login(api, path):
    response = api.anonymous().get(path)
    assert response.status_code == 401
    assert "value" not in response.text and "rows" not in response.text


def test_the_role_and_the_login_are_judged_before_the_inputs(api):
    api.put()
    assert api.get("tier1", EXPORT, q="a\x00b").status_code == 403
    assert api.get("tier2", EXPORT, format="xml").status_code == 403
    assert api.anonymous().get(EXPORT, params={"q": "a\x00b"}).status_code == 401
    assert api.anonymous().get(IOCS, params={"page": 0, "min_confidence": 999}).status_code == 401
    assert api.anonymous().get(LOOKUP).status_code == 401


@pytest.mark.parametrize("path", READ_ROUTES)
@pytest.mark.parametrize("role", ["tier1", "tier2", "admin"])
def test_the_three_roles_read(api, role, path):
    api.put(value="192.0.2.1:443")
    assert api.get(role, path).status_code == 200


@pytest.mark.parametrize("role", ["tier1", "tier2"])
@pytest.mark.parametrize("fmt", ["csv", "blocklist"])
def test_export_is_refused_to_an_analyst_and_the_refusal_is_audited(api, role, fmt):
    api.put(type="domain", value="c2.example.com")
    before = len(api.denied(role))
    response = api.get(role, EXPORT, format=fmt)
    assert response.status_code == 403
    assert "c2.example.com" not in response.text
    assert "content-disposition" not in response.headers
    events = api.denied(role)
    assert len(events) == before + 1
    subject, payload = events[-1]
    assert subject == EXPORT
    assert payload["required"] == ["admin"] and payload["role"] == role


@pytest.mark.parametrize("fmt", ["csv", "blocklist"])
def test_export_is_served_to_an_admin(api, fmt):
    api.put(type="domain", value="c2.example.com")
    assert api.get("admin", EXPORT, format=fmt).status_code == 200
    assert api.denied("admin") == []


def test_the_routes_only_read(api):
    api.put(type="domain", value="c2.example.com")
    api.put_log(ago(hours=1))
    before = api.counts()
    for role in ("tier1", "tier2", "admin"):
        for path in READ_ROUTES:
            assert api.get(role, path).status_code == 200
    for fmt in ("csv", "blocklist"):
        assert api.get("admin", EXPORT, format=fmt).status_code == 200
    assert api.counts() == before


def test_a_post_or_a_delete_on_a_route_is_a_405(api):
    api.put()
    client = api.client("admin")
    for path in (IOCS, STATS, LOOKUP, STATUS, EXPORT):
        for method in ("post", "put", "delete", "patch"):
            assert getattr(client, method)(path).status_code == 405, (method, path)
    assert api.counts()[0] == 1


# ═══════════════════════════ stats ═══════════════════════════════════════════════════════════


# fmt: off
def seed_stats(api) -> None:
    """The set the stats numbers are checked on; each row's comment says what it is for. Today is 17/11 in GMT+7."""
    old = at(2026, 11, 10, 1, 0)  # imported long ago: not today
    # 00:00 on the 17th in GMT+7: today, and imported today
    api.put(first_seen=at(2026, 11, 16, 17, 0, 0), malware="win.alpha", confidence=75, imported_at=at(2026, 11, 16, 17, 0, 0))
    # today; 74 is under the bar; one hit; imported today
    api.put(first_seen=at(2026, 11, 17, 8, 0), malware="win.alpha", confidence=74, hit_count=3, imported_at=at(2026, 11, 17, 1, 0))
    # today; imported at 23:59:59 on the 16th: not today
    api.put(source="malwarebazaar", first_seen=at(2026, 11, 17, 1, 0), malware="win.beta", confidence=None, imported_at=at(2026, 11, 16, 16, 59, 59))
    # 23:59:59 on the 16th
    api.put(source="malwarebazaar", first_seen=at(2026, 11, 16, 16, 59, 59), malware="win.beta", confidence=100, imported_at=old)
    # 00:00 on the 16th, no malware name
    api.put(source="urlhaus", type="url", value="http://c2.example.com/x", first_seen=at(2026, 11, 15, 17, 0, 0), malware=None, confidence=80, imported_at=old)
    # 00:00 on 19/10: the 30th day back, in
    api.put(first_seen=at(2026, 10, 18, 17, 0, 0), malware="win.gamma", confidence=10, imported_at=old)
    # 23:59:59 on 18/10: the 31st day back, out of a 30-day series
    api.put(first_seen=at(2026, 10, 18, 16, 59, 59), malware="win.gamma", confidence=90, imported_at=old)
    # expired: counted nowhere
    api.put(first_seen=at(2026, 11, 17, 2, 0), malware="win.zeta", confidence=99, hit_count=5, imported_at=at(2026, 11, 17, 2, 0), expires_at=NOW)
    # an empty malware name is not a name; imported today
    api.put(first_seen=at(2026, 11, 17, 3, 0), malware="", confidence=None, imported_at=at(2026, 11, 17, 3, 0))
    # 00:00 on the 18th: tomorrow, not a day of the series
    api.put(source="urlhaus", type="url", value="http://c2.example.com/y", first_seen=at(2026, 11, 17, 17, 0, 0), malware=None, confidence=None, imported_at=old)
    # the newest name, with one row
    api.put(first_seen=at(2026, 11, 17, 8, 30), malware="win.delta", confidence=None, imported_at=old)
# fmt: on


def test_stats_answer_exactly_these_keys(api):
    seed_stats(api)
    body = api.get("tier2", STATS).json()
    assert list(body) == [
        "days", "today", "sources", "by_day", "top_malware", "high_confidence", "matched_in_logs",
        "imported_today", "newest_malware",
    ]  # fmt: skip
    assert body["days"] == 30 and body["today"] == TODAY
    assert body["sources"] == ["threatfox", "urlhaus", "malwarebazaar"]


def test_stats_count_per_day_and_source_by_the_day_of_first_seen_in_gmt_plus_7(api):
    seed_stats(api)
    by_day = api.get("tier2", STATS).json()["by_day"]
    assert len(by_day) == 30
    assert by_day[0]["day"] == "2026-10-19"  # the 30th day back, today included
    assert by_day[-1]["day"] == TODAY
    assert all(list(d) == ["day", "threatfox", "urlhaus", "malwarebazaar", "total"] for d in by_day)
    got = {d["day"]: d for d in by_day if d["total"]}
    assert got == {
        "2026-10-19": {
            "day": "2026-10-19",
            "threatfox": 1,
            "urlhaus": 0,
            "malwarebazaar": 0,
            "total": 1,
        },
        "2026-11-16": {
            "day": "2026-11-16",
            "threatfox": 0,
            "urlhaus": 1,
            "malwarebazaar": 1,
            "total": 2,
        },
        # 00:00 (utc 16/11 17:00), 08:00 and 08:30 UTC and the empty-malware row: four threatfox; the expired row is not counted
        "2026-11-17": {
            "day": "2026-11-17",
            "threatfox": 4,
            "urlhaus": 0,
            "malwarebazaar": 1,
            "total": 5,
        },
    }


def test_the_days_without_an_ioc_are_in_the_series_as_zeros_oldest_first(api):
    seed_stats(api)
    by_day = api.get("tier2", STATS).json()["by_day"]
    days = [d["day"] for d in by_day]
    assert days == sorted(days) and len(set(days)) == 30
    empty = next(d for d in by_day if d["day"] == "2026-11-05")
    assert empty == {
        "day": "2026-11-05",
        "threatfox": 0,
        "urlhaus": 0,
        "malwarebazaar": 0,
        "total": 0,
    }


def test_days_sets_the_length_of_the_series_and_nothing_else(api):
    seed_stats(api)
    one = api.get("tier2", STATS, days=1).json()
    assert [d["day"] for d in one["by_day"]] == [TODAY]
    assert one["by_day"][0]["total"] == 5
    assert len(api.get("tier2", STATS, days=7).json()["by_day"]) == 7
    wide = api.get("tier2", STATS, days=31).json()
    assert len(wide["by_day"]) == 31 and wide["by_day"][0]["day"] == "2026-10-18"
    assert wide["by_day"][0]["threatfox"] == 1  # the 23:59:59 row of 18/10 is in the 31st day
    assert len(api.get("tier2", STATS, days=90).json()["by_day"]) == 90
    assert len(api.get("tier2", STATS).json()["by_day"]) == 30
    for key in (
        "top_malware",
        "high_confidence",
        "matched_in_logs",
        "imported_today",
        "newest_malware",
    ):
        assert one[key] == wide[key] == api.get("tier2", STATS).json()[key], key


def test_the_series_follows_the_routes_clock_in_gmt_plus_7(api):
    seed_stats(api)
    api.now = at(2026, 11, 17, 16, 59, 59)  # 23:59:59 on the 17th in GMT+7
    assert api.get("tier2", STATS).json()["today"] == TODAY
    api.now = at(2026, 11, 17, 17, 0, 0)  # 00:00 on the 18th
    body = api.get("tier2", STATS).json()
    assert body["today"] == "2026-11-18"
    assert body["by_day"][-1]["day"] == "2026-11-18"
    assert body["by_day"][-1]["urlhaus"] == 1  # the row that was "tomorrow" is today's now


def test_the_top_malware_counts_the_names_and_breaks_a_tie_by_name(api):
    seed_stats(api)
    top = api.get("tier2", STATS).json()["top_malware"]
    # win.alpha 2, win.beta 2, win.gamma 2 (31st day row included: the count is not windowed), win.delta 1;
    # NULL and '' are no name; win.zeta is expired
    assert top == [
        {"malware": "win.alpha", "count": 2},
        {"malware": "win.beta", "count": 2},
        {"malware": "win.gamma", "count": 2},
        {"malware": "win.delta", "count": 1},
    ]


def test_the_top_malware_is_the_ten_most_frequent(api):
    for rank in range(12):
        for _ in range(12 - rank):
            api.put(malware=f"win.family{rank:02d}")
    api.put(malware=None)
    api.put(malware="")
    top = api.get("tier2", STATS).json()["top_malware"]
    assert [t["malware"] for t in top] == [f"win.family{rank:02d}" for rank in range(10)]
    assert [t["count"] for t in top] == list(range(12, 2, -1))


def test_high_confidence_is_the_rows_at_75_or_more_and_leaves_out_none(api):
    seed_stats(api)
    # 75 (yes), 74 (no), 100, 80, 90 (the 31st day row), 99 but expired (no), None (no)
    assert api.get("tier2", STATS).json()["high_confidence"] == 4


def test_matched_in_logs_is_the_rows_with_a_hit(api):
    seed_stats(api)
    assert api.get("tier2", STATS).json()["matched_in_logs"] == 1  # the 5-hit row is expired


def test_imported_today_counts_by_the_day_of_imported_at_in_gmt_plus_7(api):
    seed_stats(api)
    # imported at 00:00 on the 17th (yes), at 08:00 UTC (yes), at 03:00 UTC (yes); 23:59:59 on the 16th (no); the expired one (no)
    assert api.get("tier2", STATS).json()["imported_today"] == 3


def test_the_newest_malware_is_three_distinct_names_by_how_new_their_newest_row_is(api):
    seed_stats(api)
    # delta (08:30 UTC on the 17th), alpha (08:00), beta (01:00); gamma is older, NULL and '' are no name
    assert api.get("tier2", STATS).json()["newest_malware"] == [
        "win.delta",
        "win.alpha",
        "win.beta",
    ]


def test_fewer_than_three_names_is_a_shorter_list(api):
    api.put(malware="win.only")
    api.put(malware=None)
    assert api.get("tier2", STATS).json()["newest_malware"] == ["win.only"]


def test_expired_rows_are_counted_nowhere_in_the_stats(api):
    api.put(
        malware="win.old",
        confidence=100,
        hit_count=4,
        imported_at=ago(hours=2),
        first_seen=ago(hours=2),
        expires_at=NOW - timedelta(seconds=1),
    )
    body = api.get("tier2", STATS).json()
    assert body["top_malware"] == [] and body["newest_malware"] == []
    assert (body["high_confidence"], body["matched_in_logs"], body["imported_today"]) == (0, 0, 0)
    assert sum(d["total"] for d in body["by_day"]) == 0


def test_the_kpis_are_the_totals_the_list_gives_for_the_same_question(api):
    seed_stats(api)
    stats = api.get("tier2", STATS).json()
    assert stats["high_confidence"] == api.get("tier2", IOCS, min_confidence=75).json()["total"]
    for entry in stats["top_malware"]:
        assert entry["count"] == api.get("tier2", IOCS, malware=entry["malware"]).json()["total"]
    window = api.get("tier2", IOCS, **{"from": "2026-10-19", "to": TODAY}).json()["total"]
    # the row at 00:00 on the 18th is outside both
    assert window == sum(d["total"] for d in stats["by_day"])


def test_empty_stats_are_zeros_and_empty_lists(api):
    body = api.get("tier2", STATS).json()
    assert len(body["by_day"]) == 30 and all(d["total"] == 0 for d in body["by_day"])
    assert body["top_malware"] == [] and body["newest_malware"] == []
    assert (body["high_confidence"], body["matched_in_logs"], body["imported_today"]) == (0, 0, 0)


# ═══════════════════════════ lookup ══════════════════════════════════════════════════════════


def test_lookup_answers_value_rows_and_total(api):
    api.put(type="domain", value="c2.example.com")
    body = api.get("tier2", LOOKUP, value="c2.example.com").json()
    assert list(body) == ["value", "rows", "total"]
    assert body["value"] == "c2.example.com" and body["total"] == 1
    assert list(body["rows"][0]) == IOC_KEYS


def test_lookup_finds_a_value_by_equality(api):
    url = api.put(type="url", value="http://c2.example.com/Panel/a.php")
    api.put(type="url", value="http://c2.example.com/Panel/a.php?x=1")
    assert [
        r["id"]
        for r in api.get("tier2", LOOKUP, value="http://c2.example.com/Panel/a.php").json()["rows"]
    ] == [url]
    assert api.get("tier2", LOOKUP, value="http://c2.example.com/Panel").json() == {
        "value": "http://c2.example.com/Panel",
        "rows": [],
        "total": 0,
    }


def test_lookup_reads_the_input_the_way_the_importer_stored_it(api):
    domain = api.put(type="domain", value="c2.example.com")
    sha = api.put(source="malwarebazaar", type="sha256_hash", value="ab" * 32, **BARE)
    md5 = api.put(type="md5_hash", value="0123456789abcdef0123456789abcdef", **BARE)
    url = api.put(type="url", value="http://c2.example.com/Panel")
    ipp = api.put(type="ip:port", value="192.0.2.10:443")

    def found(value: str) -> list[int]:
        response = api.get("tier2", LOOKUP, value=value)
        assert response.status_code == 200, response.text
        return [r["id"] for r in response.json()["rows"]]

    assert found("C2.Example.COM") == [domain]  # a domain is lower-cased
    assert found("  c2.example.com  ") == [domain]  # trimmed
    assert found("AB" * 32) == [sha]  # a hash is lower-cased
    assert found("0123456789ABCDEF0123456789ABCDEF") == [md5]
    assert found("http://c2.example.com/Panel") == [url]  # a URL keeps its case
    assert found("http://C2.example.com/Panel") == []
    assert found("http://c2.example.com/panel") == []
    assert found("192.0.2.10:443") == [ipp]
    assert found("192.0.2.10:444") == []


def test_the_rule_of_the_lookup_is_the_importers_for_every_type(api):
    """The SQL tests a row's type for "stored lower-case" itself; this ties it to `normalise_value` over a spread of types, with
    a row of each spelling under each type (a row the importer would never write is a row the database can still hold).
    """
    types = [
        "domain", "sha256_hash", "sha1_hash", "md5_hash", "imphash_hash", "_hash", "url", "ip:port", "ip",
        "hash", "x_hash_y", "domains", "email",
    ]  # fmt: skip
    stored: dict[int, tuple[str, str]] = {}
    for kind in types:
        for spelling in ("Ab.Example", "ab.example"):
            stored[api.put(type=kind, value=spelling, **BARE)] = (kind, spelling)
    for probe in ("Ab.Example", "ab.example", "AB.EXAMPLE", "  Ab.Example  ", "aB.example"):
        expected = {
            row_id
            for row_id, (kind, value) in stored.items()
            if normalise_value(kind, probe) == value
        }
        body = api.get("tier2", LOOKUP, value=probe).json()
        assert {row["id"] for row in body["rows"]} == expected, probe
        assert body["total"] == len(expected)
    # the rule is not vacuous: the two spellings are told apart by the type
    only_lower = {
        row["type"] for row in api.get("tier2", LOOKUP, value="AB.EXAMPLE").json()["rows"]
    }
    assert only_lower == {"domain", "sha256_hash", "sha1_hash", "md5_hash", "imphash_hash", "_hash"}


def test_the_value_echoed_is_the_input_trimmed_in_the_case_it_came(api):
    assert (
        api.get("tier2", LOOKUP, value="  C2.Example.COM ").json()["value"]
        == "  C2.Example.COM ".strip()
    )


def test_lookup_of_an_ipv4_address_finds_the_ip_port_rows_of_that_address(api):
    a = api.put(type="ip:port", value="192.0.2.1:443", first_seen=ago(hours=1))
    b = api.put(type="ip:port", value="192.0.2.1:8080", first_seen=ago(hours=2))
    api.put(
        type="ip:port", value="192.0.2.10:443"
    )  # another address that begins with the same text
    api.put(type="ip:port", value="192.0.2.100:443")
    api.put(type="ip:port", value="192.0.2.11:1")
    api.put(type="url", value="http://192.0.2.1:443/a")  # not an ip:port row
    api.put(type="domain", value="192.0.2.1.example.com")
    api.put(source="urlhaus", type="ip:port", value="198.51.100.1:80")
    body = api.get("tier2", LOOKUP, value="192.0.2.1").json()
    assert [r["id"] for r in body["rows"]] == [a, b] and body["total"] == 2
    assert [r["id"] for r in api.get("tier2", LOOKUP, value=" 192.0.2.1 ").json()["rows"]] == [a, b]


def test_an_ipv4_lookup_also_finds_a_row_that_holds_the_bare_address(api):
    bare = api.put(type="ip", value="192.0.2.1")
    ipp = api.put(type="ip:port", value="192.0.2.1:443")
    got = [r["id"] for r in api.get("tier2", LOOKUP, value="192.0.2.1").json()["rows"]]
    assert sorted(got) == sorted([bare, ipp])


def test_a_lookup_with_a_port_is_equality_only(api):
    ipp = api.put(type="ip:port", value="192.0.2.1:443")
    api.put(type="ip:port", value="192.0.2.1:4430")
    assert [r["id"] for r in api.get("tier2", LOOKUP, value="192.0.2.1:443").json()["rows"]] == [
        ipp
    ]


def test_text_that_looks_like_an_address_but_is_not_one_is_plain_equality(api):
    api.put(type="ip:port", value="192.0.2.1:443")
    for value in (
        "192.0.2.",
        "192.0.2",
        "192.0.2.256",
        "192.0.02.1",
        "192.0.2.%",
        "192.0.2._",
        "%",
        "_",
        "192.0.2.1%",
    ):
        body = api.get("tier2", LOOKUP, value=value).json()
        assert (body["rows"], body["total"]) == ([], 0), value


def test_a_lookup_with_a_wildcard_matches_nothing_by_pattern(api):
    api.put(type="domain", value="c2.example.com")
    api.put(type="url", value="http://100%.example.com/")
    for value in ("%", "_", "c2.example.%", "%.example.com", "c_.example.com", "\\"):
        assert api.get("tier2", LOOKUP, value=value).json()["rows"] == [], value
    assert len(api.get("tier2", LOOKUP, value="http://100%.example.com/").json()["rows"]) == 1


def test_a_lookup_finds_an_expired_row_and_says_so(api):
    gone = api.put(type="domain", value="c2.example.com", expires_at=NOW - timedelta(days=3))
    (row,) = api.get("tier2", LOOKUP, value="c2.example.com").json()["rows"]
    assert row["id"] == gone and row["expired"] is True


def test_a_lookup_serves_a_value_under_each_source_newest_first(api):
    older = api.put(
        source="urlhaus", type="url", value="http://c2.example.com/a", first_seen=ago(hours=5)
    )
    newer = api.put(
        source="threatfox", type="url", value="http://c2.example.com/a", first_seen=ago(hours=1)
    )
    got = api.get("tier2", LOOKUP, value="http://c2.example.com/a").json()
    assert [r["id"] for r in got["rows"]] == [newer, older] and got["total"] == 2


def test_a_lookup_serves_at_most_its_cap_and_the_total_says_how_many_there_are(api, monkeypatch):
    monkeypatch.setattr(queries, "LOOKUP_MAX_ROWS", 2)
    made = [
        api.put(type="ip:port", value=f"192.0.2.1:{4000 + n}", first_seen=ago(minutes=n))
        for n in range(5)
    ]
    body = api.get("tier2", LOOKUP, value="192.0.2.1").json()
    assert [r["id"] for r in body["rows"]] == made[:2] and body["total"] == 5


def test_a_lookup_that_finds_nothing_is_an_empty_list(api):
    api.put(type="domain", value="c2.example.com")
    assert api.get("tier2", LOOKUP, value="nothing.example.org").json() == {
        "value": "nothing.example.org",
        "rows": [],
        "total": 0,
    }


# ═══════════════════════════ status ══════════════════════════════════════════════════════════


def test_status_with_no_import_is_stale_and_empty(api):
    assert api.get("tier2", STATUS).json() == {
        "latest": None,
        "latest_success": None,
        "stale": True,
        "stale_after_hours": 26,
    }


def test_status_serves_the_log_row_field_for_field(api):
    log_id = api.put_log(
        at(2026, 11, 17, 0, 5, 3),
        rows_total=200,
        rows_new=180,
        rows_updated=15,
        rows_error=5,
        status="partial",
        message="skipped: value_control_char=5",
        file="ioc_2026-11-17.csv",
    )
    body = api.get("tier2", STATUS).json()
    expected = {
        "id": log_id,
        "file": "ioc_2026-11-17.csv",
        "started_at": "2026-11-17T00:04:58+00:00",
        "finished_at": "2026-11-17T00:05:03+00:00",
        "rows_total": 200,
        "rows_new": 180,
        "rows_updated": 15,
        "rows_error": 5,
        "status": "partial",
        "message": "skipped: value_control_char=5",
    }
    assert list(body) == ["latest", "latest_success", "stale", "stale_after_hours"]
    assert list(body["latest"]) == LOG_KEYS
    assert body["latest"] == expected and body["latest_success"] == expected


@pytest.mark.parametrize(
    "age, stale",
    [
        (timedelta(hours=1), False),
        (timedelta(hours=25), False),
        (timedelta(hours=26), False),  # within the last 26 hours, the edge included
        (timedelta(hours=26, microseconds=1), True),
        (timedelta(hours=26, seconds=1), True),
        (timedelta(hours=27), True),
        (timedelta(days=9), True),
        (timedelta(hours=-3), False),  # a finish ahead of the web's clock is not stale
    ],
    ids=lambda v: str(v),
)
def test_status_is_stale_when_no_successful_import_finished_in_the_last_26_hours(api, age, stale):
    api.put_log(NOW - age)
    body = api.get("tier2", STATUS).json()
    assert body["stale"] is stale
    assert body["latest_success"] is not None


def test_status_judges_staleness_by_the_routes_clock(api):
    api.put_log(NOW - timedelta(hours=25))
    assert api.get("tier2", STATUS).json()["stale"] is False
    api.now = NOW + timedelta(hours=2)  # the same row is now 27 hours old
    assert api.get("tier2", STATUS).json()["stale"] is True


def test_a_partial_run_is_a_success_and_a_failed_one_is_not(api):
    api.put_log(ago(hours=2), status="partial", rows_error=3)
    assert api.get("tier2", STATUS).json()["stale"] is False
    api.execute("TRUNCATE ti_import_log")
    api.put_log(
        ago(hours=2), status="failed", rows_total=0, rows_new=0, rows_updated=0, message="no_file"
    )
    body = api.get("tier2", STATUS).json()
    assert body["stale"] is True and body["latest_success"] is None
    assert body["latest"]["status"] == "failed" and body["latest"]["message"] == "no_file"


def test_a_failed_run_after_a_good_one_is_the_latest_and_the_good_one_decides_staleness(api):
    ok = api.put_log(ago(hours=20), status="ok")
    failed = api.put_log(
        ago(hours=1), status="failed", rows_new=0, rows_updated=0, message="no_file"
    )
    body = api.get("tier2", STATUS).json()
    assert (body["latest"]["id"], body["latest_success"]["id"]) == (failed, ok)
    assert body["stale"] is False
    api.now = NOW + timedelta(
        hours=10
    )  # the good run is now 30 hours old, the failed one is not a success
    body = api.get("tier2", STATUS).json()
    assert (body["latest"]["id"], body["latest_success"]["id"], body["stale"]) == (failed, ok, True)


def test_the_newest_run_is_the_one_that_finished_last_not_the_one_with_the_highest_id(api):
    later_finish = api.put_log(ago(hours=1))  # inserted first: the lower id
    earlier_finish = api.put_log(ago(hours=5))
    body = api.get("tier2", STATUS).json()
    assert later_finish < earlier_finish
    assert body["latest"]["id"] == later_finish and body["latest_success"]["id"] == later_finish


def test_two_runs_that_finished_together_are_ordered_by_id(api):
    first = api.put_log(ago(hours=1))
    second = api.put_log(ago(hours=1))
    assert api.get("tier2", STATUS).json()["latest"]["id"] == second > first


# ═══════════════════════════ export ══════════════════════════════════════════════════════════


def test_the_csv_is_a_download_with_a_fixed_name_and_the_right_type(api):
    api.put()
    response = api.get("admin", EXPORT, format="csv")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/csv; charset=utf-8"
    assert response.headers["content-disposition"] == 'attachment; filename="threat-intel-iocs.csv"'
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"


def test_the_default_format_is_csv(api):
    api.put()
    response = api.get("admin", EXPORT)
    assert response.headers["content-type"] == "text/csv; charset=utf-8"


def test_the_csv_holds_the_lists_columns_and_a_row_per_ioc_newest_first(api):
    old = api.put(first_seen=ago(hours=5), value="192.0.2.1:1")
    new = api.put(first_seen=ago(hours=1), value="192.0.2.2:2", tags=["a", "b"], confidence=None)
    response = api.get("admin", EXPORT, format="csv")
    rows = read_csv(response)
    assert list(rows[0]) == IOC_KEYS
    assert [r["id"] for r in rows] == [str(new), str(old)]
    assert rows[0]["tags"] == "a,b" and rows[0]["confidence"] == ""
    assert rows[0]["first_seen"] == (NOW - timedelta(hours=1)).isoformat()
    assert response.content.decode("utf-8-sig").splitlines()[0] == ",".join(IOC_KEYS)


def test_the_csv_guards_every_cell_that_a_spreadsheet_would_run(api):
    api.put(
        type="url",
        value="=cmd|' /C calc'!A0",
        malware="+SUM(1+1)",
        threat="-2+3+cmd|' /C calc'!A0",
        reference="@SUM(A1)",
        tags=["=x", "fine"],
    )
    api.put(type="url", value="\t=tab", malware="\r=cr", threat="plain", reference=None, tags=[])
    api.put(
        type="url",
        value=" =1+1",
        malware="\u00a0=1+1",
        threat="\u2003@SUM(1)",
        reference="  -2+3",
        tags=[],
    )
    response = api.get("admin", EXPORT, format="csv")
    rows = {r["value"]: r for r in read_csv(response)}
    one = rows["'=cmd|' /C calc'!A0"]
    assert one["malware"] == "'+SUM(1+1)" and one["threat"] == "'-2+3+cmd|' /C calc'!A0"
    assert one["reference"] == "'@SUM(A1)" and one["tags"] == "'=x,fine"
    two = rows["'\t=tab"]
    assert two["malware"] == "'\r=cr" and two["threat"] == "plain"
    spaced = rows[
        "' =1+1"
    ]  # white space before the formula character: guarded, the original cell kept behind the `'`
    assert spaced["malware"] == "'\u00a0=1+1" and spaced["threat"] == "'\u2003@SUM(1)"
    assert spaced["reference"] == "'  -2+3"
    for record in read_csv(response):  # no cell of the file reads as a formula, white space or not
        for name, cell in record.items():
            assert not cell.startswith(("\t", "\r")), (name, cell)
            assert not cell.lstrip().startswith(("=", "+", "-", "@")), (name, cell)


def test_the_csv_quotes_what_needs_quoting_and_one_row_stays_one_record(api):
    api.put(type="url", value='say "hi", then\nleave', malware="a\r\nb", threat="x,y")
    api.put(type="url", value="second")
    rows = read_csv(api.get("admin", EXPORT, format="csv"))
    assert len(rows) == 2
    got = {r["value"]: r for r in rows}
    assert got['say "hi", then\nleave']["malware"] == "a\r\nb"
    assert got['say "hi", then\nleave']["threat"] == "x,y"


def test_the_csv_carries_the_same_filters_as_the_list(api):
    keep = api.put(source="urlhaus", type="url", value="http://c2.example.com/needle", confidence=90, first_seen=at(2026, 11, 17, 3, 0), malware="win.alpha")  # fmt: skip
    api.put(source="threatfox", type="url", value="http://c2.example.com/needle", confidence=90, first_seen=at(2026, 11, 17, 3, 0), malware="win.alpha")  # fmt: skip
    api.put(source="urlhaus", type="url", value="http://c2.example.com/other", confidence=90, first_seen=at(2026, 11, 17, 3, 0), malware="win.alpha", threat=None, tags=[])  # fmt: skip
    api.put(source="urlhaus", type="url", value="http://c2.example.com/needle2", confidence=20, first_seen=at(2026, 11, 17, 3, 0), malware="win.alpha")  # fmt: skip
    api.put(source="urlhaus", type="url", value="http://c2.example.com/needle3", confidence=90, first_seen=at(2026, 11, 1, 3, 0), malware="win.alpha")  # fmt: skip
    api.put(source="urlhaus", type="url", value="http://c2.example.com/needle4", confidence=90, first_seen=at(2026, 11, 17, 3, 0), malware="win.beta")  # fmt: skip
    gone = api.put(source="urlhaus", type="url", value="http://c2.example.com/needle5", confidence=90, first_seen=at(2026, 11, 17, 3, 0), malware="win.alpha", expires_at=NOW - timedelta(days=1))  # fmt: skip
    params = {
        "source": "urlhaus",
        "type": "url",
        "malware": "win.alpha",
        "min_confidence": 80,
        "q": "needle",
        "from": "2026-11-16",
        "to": "2026-11-17",
    }
    listed = ids(api.get("tier2", IOCS, **params))
    exported = [int(r["id"]) for r in read_csv(api.get("admin", EXPORT, format="csv", **params))]
    assert listed == exported == [keep]
    with_expired = api.get("admin", EXPORT, format="csv", expired="true", **params)
    assert sorted(int(r["id"]) for r in read_csv(with_expired)) == sorted([keep, gone])


def test_the_export_serves_every_row_of_the_filter_not_a_page(api):
    for _ in range(120):
        api.put()
    rows = read_csv(api.get("admin", EXPORT, format="csv"))
    assert len(rows) == 120
    assert len(read_csv(api.get("admin", EXPORT, format="csv", page=2, page_size=10))) == 120


@pytest.mark.parametrize("fmt", ["csv", "blocklist"])
def test_the_export_refuses_more_rows_than_its_cap_and_says_so(api, monkeypatch, fmt):
    monkeypatch.setattr(queries, "EXPORT_MAX_ROWS", 3)
    for n in range(4):
        api.put(
            type="domain", value=f"c{n}.example.com", source="threatfox" if n < 3 else "urlhaus"
        )
    refused = api.get("admin", EXPORT, format=fmt)
    assert refused.status_code == 422
    assert refused.json() == {"detail": {"field": "filters", "reason": "too_many_rows", "limit": 3}}
    assert "content-disposition" not in refused.headers
    assert "c0.example.com" not in refused.text  # no partial file
    # at the cap exactly, the whole file
    assert api.get("admin", EXPORT, format=fmt, source="threatfox").status_code == 200
    # a filter that brings it under the cap is the way out
    narrowed = api.get("admin", EXPORT, format=fmt, source="urlhaus")
    assert narrowed.status_code == 200 and "c3.example.com" in narrowed.text


def test_the_blocklist_is_plain_text_a_download_with_a_fixed_name(api):
    api.put(type="domain", value="c2.example.com")
    response = api.get("admin", EXPORT, format="blocklist")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/plain; charset=utf-8"
    assert (
        response.headers["content-disposition"]
        == 'attachment; filename="threat-intel-blocklist.txt"'
    )
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert response.text == "c2.example.com\n"


def test_the_blocklist_holds_domains_and_addresses_once_each_the_port_dropped(api):
    api.put(type="ip:port", value="192.0.2.10:443", first_seen=ago(minutes=1))
    api.put(type="domain", value="c2.example.com", first_seen=ago(minutes=2))
    api.put(type="ip:port", value="192.0.2.10:8080", first_seen=ago(minutes=3))  # the same address
    api.put(
        source="urlhaus", type="domain", value="c2.example.com", first_seen=ago(minutes=4)
    )  # the same name
    api.put(type="url", value="http://c2.example.com/x", first_seen=ago(minutes=5))
    api.put(source="malwarebazaar", type="sha256_hash", value="c" * 64, first_seen=ago(minutes=6))
    api.put(type="ip:port", value="[2001:db8::1]:443", first_seen=ago(minutes=7))
    api.put(type="domain", value="payload.example.net", first_seen=ago(minutes=8))
    response = api.get("admin", EXPORT, format="blocklist")
    assert response.text == "192.0.2.10\nc2.example.com\n2001:db8::1\npayload.example.net\n"


def test_a_line_break_in_a_stored_value_never_makes_a_second_line(api):
    """The importer refuses control characters; the export does not rely on it (a row written by anything else)."""
    api.put(type="domain", value="good.example.com", first_seen=ago(minutes=1))
    for hostile in (
        "evil.example.net\nbad.example.org",
        "evil.example.net\r\nbad.example.org",
        "evil.example.net\n",
        "\nevil.example.net",
        "evil.example.net\u2028bad.example.org",
        "evil.example.net;calc",
        "evil.example.net bad.example.org",
    ):
        api.put(type="domain", value=hostile, first_seen=ago(minutes=2))
    for hostile in ("192.0.2.1:443\n198.51.100.1:80", "192.0.2.2:443\r", "198.51.100.2:80 "):
        api.put(type="ip:port", value=hostile, first_seen=ago(minutes=3))
    response = api.get("admin", EXPORT, format="blocklist")
    assert response.text == "good.example.com\n"


def test_every_line_of_a_blocklist_is_a_hostname_or_an_address(api):
    for n in range(20):
        api.put(type="domain", value=f"host-{n}.example.com", first_seen=ago(minutes=n))
        api.put(
            type="ip:port", value=f"203.0.113.{n}:{8000 + n}", first_seen=ago(minutes=n, seconds=30)
        )
    for hostile in HOSTILE_VALUES:
        api.put(type="domain", value=hostile)
        api.put(type="ip:port", value=hostile)
    lines = api.get("admin", EXPORT, format="blocklist").text.splitlines()
    assert len(lines) == 40 and len(set(lines)) == 40
    hostname = re.compile(
        r"[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*"
    )
    for line in lines:
        try:
            ipaddress.ip_address(line)
        except ValueError:
            assert hostname.fullmatch(line), line


def test_the_blocklist_carries_the_same_filters_and_hides_expired_rows_by_default(api):
    api.put(type="domain", value="live.example.com", source="threatfox")
    api.put(type="domain", value="other.example.com", source="urlhaus")
    api.put(
        type="domain",
        value="gone.example.com",
        source="threatfox",
        expires_at=NOW - timedelta(days=1),
    )
    assert set(api.get("admin", EXPORT, format="blocklist").text.split()) == {
        "live.example.com",
        "other.example.com",
    }
    assert (
        api.get("admin", EXPORT, format="blocklist", source="urlhaus").text == "other.example.com\n"
    )
    both = api.get("admin", EXPORT, format="blocklist", source="threatfox", expired="true")
    assert set(both.text.split()) == {"live.example.com", "gone.example.com"}


def test_an_empty_blocklist_is_an_empty_file(api):
    api.put(type="url", value="http://c2.example.com/x")
    response = api.get("admin", EXPORT, format="blocklist")
    assert response.status_code == 200 and response.text == ""
    assert api.get("admin", EXPORT, format="csv", source="urlhaus").text == (
        "\ufeff" + ",".join(IOC_KEYS) + "\r\n"
    )


def test_the_csv_starts_with_a_byte_order_mark_so_excel_reads_it_as_utf_8(api):
    api.put(type="url", value="http://b\u00fccher.example.com/\u00e4", malware="win.\u00e9tude")
    response = api.get("admin", EXPORT, format="csv")
    assert response.headers["content-type"] == "text/csv; charset=utf-8"
    assert response.content.startswith(b"\xef\xbb\xbfid,source,")
    assert response.content.count(b"\xef\xbb\xbf") == 1
    (record,) = read_csv(response)  # `utf-8-sig`: the first header cell is `id`
    assert next(iter(record)) == "id"
    assert (
        record["value"] == "http://b\u00fccher.example.com/\u00e4"
        and record["malware"] == "win.\u00e9tude"
    )
    # the blocklist is not a spreadsheet: no mark
    assert not api.get("admin", EXPORT, format="blocklist").content.startswith(b"\xef\xbb\xbf")


def test_the_blocklist_never_carries_what_a_firewall_or_a_sinkhole_must_not_block(api):
    api.put(type="ip:port", value="192.0.2.1:80", first_seen=ago(minutes=1))
    never = [
        ("ip:port", "127.0.0.1:80"), ("ip:port", "0.0.0.0:80"), ("ip:port", "10.0.0.1:80"),
        ("ip:port", "172.16.0.5:80"), ("ip:port", "192.168.1.1:80"), ("ip:port", "169.254.1.1:80"),
        ("ip:port", "100.64.0.1:80"), ("ip:port", "224.0.0.1:80"), ("ip:port", "255.255.255.255:80"),
        ("ip:port", "[::1]:80"), ("ip:port", "[fe80::1]:80"), ("ip:port", "[fd00::1]:80"),
        ("ip:port", "[ff02::1]:80"), ("ip:port", "[::ffff:10.0.0.1]:80"), ("ip:port", "[::ffff:127.0.0.1]:80"),
        ("ip:port", "2001:db8::1:443"), ("ip:port", "::1"),
        ("domain", "localhost"), ("domain", "127.0.0.1"), ("domain", "10.1.2.3"), ("domain", "0.0.0.0"),
        ("domain", "x.local"), ("domain", "1.0.0.127.in-addr.arpa"), ("domain", "com"), ("domain", "lan"),
        ("domain", "printer.lan"), ("domain", "foo.example"),
        # a number spelt in hex is an address to getaddrinfo, with no DNS query: not a name to block
        ("domain", "127.0.0.0x1"), ("domain", "0x7f.0x0.0x0.0x1"), ("domain", "0xa.0x1"),
        ("domain", "192.168.1.0x1"), ("domain", "169.254.169.0xfe"), ("domain", "0.0.0.0x0"),
        ("domain", "2130706433"), ("domain", "0177.0.0.1"), ("domain", "127.1"), ("domain", "example.c0m"),
        # IANA special-purpose ranges that are not globally reachable
        ("ip:port", "192.0.0.1:80"), ("ip:port", "192.0.0.170:80"), ("ip:port", "198.18.0.1:80"),
        ("ip:port", "198.19.255.255:80"), ("ip:port", "[::ffff:198.18.0.1]:80"), ("ip:port", "[2001:2::1]:80"),
    ]  # fmt: skip
    for number, (kind, value) in enumerate(never, start=2):
        api.put(type=kind, value=value, first_seen=ago(minutes=number))
    api.put(type="domain", value="c2.example.com", first_seen=ago(minutes=60))
    api.put(type="ip:port", value="[2001:db8::1]:443", first_seen=ago(minutes=61))
    api.put(type="domain", value="c2.example.xn--p1ai", first_seen=ago(minutes=62))
    response = api.get("admin", EXPORT, format="blocklist")
    assert response.text == "192.0.2.1\nc2.example.com\n2001:db8::1\nc2.example.xn--p1ai\n"
    # the CSV is the list, never-block values included: it is a record, not a blocklist
    assert len(read_csv(api.get("admin", EXPORT, format="csv"))) == len(never) + 4


# ═══════════════════════════ the statement timeout ═══════════════════════════════════════════


@contextmanager
def tables_locked(api, *tables: str, release_after: float = 20.0):
    """Another session holds ACCESS EXCLUSIVE on `tables`: a read of them waits. A watchdog lets go after `release_after`
    seconds, so a read that has NO timeout ends (as a 200, which the test then refuses) instead of hanging the suite.
    """
    holder = psycopg.connect(api.dsn)
    holder.execute(f"LOCK TABLE {', '.join(tables)} IN ACCESS EXCLUSIVE MODE")
    watchdog = threading.Timer(release_after, holder.rollback)
    watchdog.start()
    try:
        yield
    finally:
        watchdog.cancel()
        holder.rollback()
        holder.close()


TIMEOUT_ROUTES = [
    ("tier2", IOCS, {}),
    ("tier2", IOCS, {"q": "needle", "min_confidence": 1}),
    ("tier1", STATS, {}),
    ("tier2", LOOKUP, {"value": "c2.example.com"}),
    ("tier2", LOOKUP, {"value": "192.0.2.1"}),
    ("admin", STATUS, {}),
    ("admin", EXPORT, {"format": "csv"}),
    ("admin", EXPORT, {"format": "blocklist"}),
]


@pytest.mark.parametrize(
    ("role", "path", "params"),
    TIMEOUT_ROUTES,
    ids=[f"{r}-{p}-{len(q)}" for r, p, q in TIMEOUT_ROUTES],
)
def test_a_read_that_waits_on_a_lock_is_cut_by_the_statement_timeout_and_answers_a_closed_503(
    api, monkeypatch, role, path, params
):
    api.put(type="domain", value="c2.example.com")
    api.put_log(ago(hours=1))
    monkeypatch.setattr(queries, "STATEMENT_TIMEOUT", "300ms")
    with tables_locked(api, "ti_ioc", "ti_import_log"):
        started = time.monotonic()
        response = api.get(role, path, **params)
        waited = time.monotonic() - started
    assert response.status_code == 503, response.text
    assert response.json() == {"detail": {"reason": "timeout"}}
    assert waited < 10  # the 300 ms limit, not the watchdog
    shown = response.text.lower()
    for leaked in (
        "select",
        "ti_ioc",
        "ti_import_log",
        "statement",
        "cancel",
        "psycopg",
        "postgres",
        "traceback",
    ):
        assert leaked not in shown, leaked
    # the lock is gone, and so is the cut: the same read is served
    assert api.get(role, path, **params).status_code == 200


def test_the_timeout_is_set_for_the_transaction_of_the_read_and_no_longer(api, monkeypatch):
    monkeypatch.setattr(queries, "STATEMENT_TIMEOUT", "1234ms")
    with psycopg.connect(api.dsn) as conn:
        before = conn.execute("SHOW statement_timeout").fetchone()[0]
        queries.set_statement_timeout(conn)
        assert conn.execute("SHOW statement_timeout").fetchone()[0] == "1234ms"
        conn.rollback()
        assert conn.execute("SHOW statement_timeout").fetchone()[0] == before != "1234ms"


def test_a_read_that_is_not_blocked_is_not_affected_by_the_timeout(api):
    for number in range(30):
        api.put(value=f"192.0.2.{number + 1}:{4000 + number}")
    for role, path, params in TIMEOUT_ROUTES:
        assert api.get(role, path, **params).status_code == 200, path


def test_a_timeout_writes_nothing_and_leaves_no_event(api, monkeypatch):
    api.put(type="domain", value="c2.example.com")
    before = api.counts()
    monkeypatch.setattr(queries, "STATEMENT_TIMEOUT", "200ms")
    with tables_locked(api, "ti_ioc"):
        assert api.get("tier2", IOCS).status_code == 503
    assert api.counts() == before
