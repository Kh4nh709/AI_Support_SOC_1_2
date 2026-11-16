"""SR-T1 — the read half of the SOAR review API (`web/routers/soar_reviews.py`, spec 2026-11-16 §4 and §5):

    GET /api/soar/reviews            the list: filters, `q`, pagination
    GET /api/soar/reviews/count      the badge: how many reviews are in these states, and the newest one's time
    GET /api/soar/reviews/{id}       the ticket plus `raw`, `history` and `related_alerts`

All three admit the three roles (as every `/api` route of the analysts' pages), take the Bearer token, and WRITE NOTHING: a
lock older than two minutes is only served as the state the row had, never released by a read. Every test runs on a scratch
database of this module (`soar_review_world.py`), committed data read back on a connection of its own.
"""

from __future__ import annotations

import json
import random
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import psycopg
import pytest
from app.web import main

from tests import soar_review_data as data
from tests.scratch_db import scratch_database
from tests.soar_review_data import MISSING
from tests.soar_review_world import REVIEWS, World

pytestmark = pytest.mark.db

#: The served review object, key by key, in the spec's order (§4), then what the detail adds.
SERVED_KEYS = [
    "id", "kind", "status", "severity", "title", "simulated", "case_id", "case_number",
    "action_type", "action_text", "action_target", "action_via", "action_agent",
    "host", "agent_id", "user_name", "src_ip", "domain", "scenario_id", "scenario_name", "score", "note",
    "buttons", "created_at", "auto_expire_at", "remind_every_minutes", "next_remind_at",
    "decided_by", "decided_at", "result", "last_error", "locked_by", "locked_at", "last_sent_at", "received_at", "updated_at",
    "allowed_decisions", "strong_warning",
]  # fmt: skip
DETAIL_KEYS = [*SERVED_KEYS, "raw", "history", "related_alerts", "related_total"]
ALERT_KEYS = [
    "alert_id", "alert_time", "agent_name", "description", "severity", "status", "occurrence_count",
]  # fmt: skip
HISTORY_KEYS = ["at", "event", "actor", "actor_role", "payload"]


@pytest.fixture(scope="module")
def scratch_dsn():
    with scratch_database("soarread") as dsn:
        yield dsn


@pytest.fixture
def world(scratch_dsn, monkeypatch):
    monkeypatch.setattr(
        "app.web.deps.db.connect", lambda *a, **k: psycopg.connect(scratch_dsn, autocommit=False)
    )
    w = World(scratch_dsn)
    w.execute("TRUNCATE soar_reviews")
    try:
        yield w
    finally:
        w.unwire()


def _case_number() -> int:
    """A case number no other test of this module uses, so the alerts one test puts in are never another's."""
    return random.SystemRandom().randrange(10**6, 10**9)


def _ids(response) -> list[str]:
    assert response.status_code == 200, response.text
    return [row["id"] for row in response.json()["rows"]]


def _at(seconds: float) -> datetime:
    return data.T0 + timedelta(seconds=seconds)


# ── the served object ───────────────────────────────────────────────────────────────────────


def test_a_ticket_is_served_with_exactly_the_spec_keys_in_the_spec_order(world):
    review_id = world.put()
    body = world.get("tier2", f"{REVIEWS}/{review_id}").json()
    assert list(body) == DETAIL_KEYS
    listed = world.get("tier2", REVIEWS).json()["rows"]
    assert list(listed[0]) == SERVED_KEYS
    assert "raw" not in listed[0] and "prev_status" not in listed[0]


def test_the_example_ticket_is_served_field_for_field(world):
    review_id = world.put()
    body = world.get("tier2", f"{REVIEWS}/{review_id}").json()
    expected = {
        "id": review_id,
        "kind": "review",
        "status": "open",
        "severity": "info",
        "title": "ĐÃ TỰ XỬ LÝ",
        "simulated": False,
        "case_id": "~4096",
        "case_number": 65,
        "action_type": "block_ip",
        "action_text": "Chặn IP 79.79.78.202 trên pfSense",
        "action_target": "79.79.78.202",
        "action_via": "pfsense",
        "action_agent": None,
        "host": "pfSense.home.arpa",
        "agent_id": "003",
        "user_name": None,
        "src_ip": "79.79.78.202",
        "domain": None,
        "scenario_id": "SC03",
        "scenario_name": "Quét cổng từ bên ngoài",
        "score": 50,
        "note": "Đã chặn 79.79.78.202 trên pfSense, tự gỡ 22:40",
        "buttons": [
            {"decision": "keep", "label": "✅ Giữ chặn"},
            {"decision": "undo", "label": "↩️ Gỡ chặn IP"},
        ],
        "remind_every_minutes": 0,
        "next_remind_at": None,
        "decided_by": None,
        "decided_at": None,
        "result": None,
        "last_error": None,
        "locked_by": None,
        "locked_at": None,
        "allowed_decisions": ["keep", "undo"],
        "strong_warning": False,
    }
    for key, value in expected.items():
        assert body[key] == value, key


def test_every_timestamp_is_iso_8601_with_the_offset_plus_00_00(world):
    review_id = world.put(
        decided_at=_at(10), next_remind_at=_at(20), status="kept", decided_by="alice"
    )
    body = world.get("tier2", f"{REVIEWS}/{review_id}").json()
    for key in (
        "created_at",
        "auto_expire_at",
        "next_remind_at",
        "decided_at",
        "last_sent_at",
        "updated_at",
    ):
        assert body[key].endswith("+00:00"), key
        datetime.fromisoformat(body[key])
    assert datetime.fromisoformat(body["created_at"]) == _at(-2)
    assert datetime.fromisoformat(body["last_sent_at"]) == _at(0)
    assert body["created_at"] == "2026-11-13T14:40:03.123000+00:00"


def test_the_offset_is_plus_00_00_whatever_zone_the_database_session_is_in(world):
    """The route, not the session, decides how a time is written."""
    review_id = world.put()
    name = _dbname(world)
    world.execute(f"ALTER DATABASE \"{name}\" SET timezone = 'Asia/Ho_Chi_Minh'")
    try:
        body = world.get("tier2", f"{REVIEWS}/{review_id}").json()
    finally:
        world.execute(f'ALTER DATABASE "{name}" RESET timezone')
    assert body["created_at"].endswith("+00:00")
    assert body["created_at"] == "2026-11-13T14:40:03.123000+00:00"


def _dbname(world: World) -> str:
    return world.rows("SELECT current_database()")[0][0]


# ── allowed_decisions: valid for the state AND allowed for the role ─────────────────────────


@pytest.mark.parametrize(
    "role,expected",
    [("tier1", ["keep"]), ("tier2", ["keep", "undo"]), ("admin", ["keep", "undo"])],
)
def test_an_open_block_ip_review_allows_its_buttons_the_role_may_press(world, role, expected):
    review_id = world.put()
    assert world.get(role, f"{REVIEWS}/{review_id}").json()["allowed_decisions"] == expected


@pytest.mark.parametrize("role", ["tier1", "tier2", "admin"])
def test_an_open_kill_process_review_allows_keep_and_fp_to_every_role(world, role):
    buttons = [{"decision": "keep", "label": "Giữ"}, {"decision": "fp", "label": "Báo nhầm"}]
    review_id = world.put(action_type="kill_process", buttons=buttons)
    assert world.get(role, f"{REVIEWS}/{review_id}").json()["allowed_decisions"] == ["keep", "fp"]


@pytest.mark.parametrize("role,expected", [("tier1", []), ("tier2", ["undo"]), ("admin", ["undo"])])
def test_a_kept_review_allows_undo_only(world, role, expected):
    review_id = world.put(status="kept")
    assert world.get(role, f"{REVIEWS}/{review_id}").json()["allowed_decisions"] == expected


def test_a_kept_review_allows_undo_even_when_its_buttons_no_longer_list_it(world):
    review_id = world.put(status="kept", buttons=[{"decision": "keep", "label": "Giữ"}])
    assert world.get("tier2", f"{REVIEWS}/{review_id}").json()["allowed_decisions"] == ["undo"]


@pytest.mark.parametrize("role", ["tier1", "tier2", "admin"])
def test_a_kept_kill_process_review_is_never_undone(world, role):
    review_id = world.put(
        status="kept",
        action_type="kill_process",
        buttons=[{"decision": "keep", "label": "Giữ"}, {"decision": "fp", "label": "Báo nhầm"}],
    )
    assert world.get(role, f"{REVIEWS}/{review_id}").json()["allowed_decisions"] == []


@pytest.mark.parametrize("status", ["undone", "false_positive", "expired"])
def test_a_terminal_review_allows_nothing(world, status):
    review_id = world.put(status=status)
    assert world.get("admin", f"{REVIEWS}/{review_id}").json()["allowed_decisions"] == []


def test_a_notice_allows_nothing_whatever_its_buttons(world):
    review_id = world.put(
        kind="notice", status="info", buttons=[{"decision": "keep", "label": "x"}]
    )
    assert world.get("admin", f"{REVIEWS}/{review_id}").json()["allowed_decisions"] == []


def test_a_review_with_no_buttons_allows_nothing_while_open(world):
    review_id = world.put(buttons=[])
    assert world.get("admin", f"{REVIEWS}/{review_id}").json()["allowed_decisions"] == []


def test_the_role_lists_of_the_configuration_decide_who_is_allowed(world):
    review_id = world.put()
    world.cfg = replace(world.cfg, SOAR_ROLES_KEEP=["admin"], SOAR_ROLES_UNDO=["tier1"])
    assert world.get("tier1", f"{REVIEWS}/{review_id}").json()["allowed_decisions"] == ["undo"]
    assert world.get("tier2", f"{REVIEWS}/{review_id}").json()["allowed_decisions"] == []
    assert world.get("admin", f"{REVIEWS}/{review_id}").json()["allowed_decisions"] == ["keep"]


def test_the_list_gives_each_row_its_allowed_decisions_for_the_caller(world):
    review_id = world.put()
    assert world.get("tier1", REVIEWS).json()["rows"][0]["allowed_decisions"] == ["keep"]
    assert world.get("tier2", REVIEWS).json()["rows"][0]["allowed_decisions"] == ["keep", "undo"]
    assert review_id in _ids(world.get("tier1", REVIEWS))


# ── strong_warning ──────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "fields,expected",
    [
        ({"action_type": "isolate_host", "host": "PC-17"}, True),
        ({"action_type": "block_ip", "host": "AD-server"}, True),
        ({"action_type": "block_ip", "host": "ad-SERVER"}, True),
        ({"action_type": "kill_process", "host": "Ad-Server"}, True),
        ({"action_type": "block_ip", "host": "AD-server2"}, False),
        ({"action_type": "block_ip", "host": "xAD-server"}, False),
        ({"action_type": "block_ip", "host": None}, False),
        ({"action_type": None, "host": "AD-server", "kind": "notice", "status": "info"}, True),
        ({"action_type": "disable_user", "host": "WIN-01"}, False),
        ({"action_type": "block_ip", "host": "ad-SERVER."}, True),
        ({"action_type": "block_ip", "host": "AD-server.home.arpa"}, True),
        ({"action_type": "block_ip", "host": "AD\u200b-server"}, True),
        ({"action_type": "block_ip", "host": "notAD-server"}, False),
    ],
)
def test_strong_warning_is_isolate_host_or_the_domain_controller(world, fields, expected):
    review_id = world.put(**fields)
    assert world.get("tier2", f"{REVIEWS}/{review_id}").json()["strong_warning"] is expected


def test_the_domain_controllers_are_the_ad_hosts_of_the_configuration(world):
    review_id = world.put(host="DC01.lab")
    other = world.put(host="AD-server")
    world.cfg = replace(world.cfg, SOAR_AD_HOSTS=["dc01.LAB", "dc02"])
    assert world.get("tier2", f"{REVIEWS}/{review_id}").json()["strong_warning"] is True
    assert world.get("tier2", f"{REVIEWS}/{other}").json()["strong_warning"] is False


# ── the effective status of a lock: reads write nothing ─────────────────────────────────────


@pytest.mark.parametrize("prev", ["open", "kept"])
@pytest.mark.parametrize("role", ["tier1", "tier2", "admin"])
def test_a_live_lock_is_served_as_processing_with_no_allowed_decision_for_any_caller(
    world, role, prev
):
    """The UI relies on it: a ticket someone is acting on offers nobody a button, whatever the role and whatever it was."""
    review_id = world.put_locked(by="alice", age_s=5, prev=prev)
    body = world.get(role, f"{REVIEWS}/{review_id}").json()
    assert body["status"] == "processing"
    assert body["locked_by"] == "alice"
    assert datetime.fromisoformat(body["locked_at"]) > datetime.now(UTC) - timedelta(seconds=60)
    assert body["allowed_decisions"] == []
    listed = next(r for r in world.get(role, REVIEWS).json()["rows"] if r["id"] == review_id)
    assert (listed["status"], listed["locked_by"], listed["allowed_decisions"]) == (
        "processing",
        "alice",
        [],
    )


@pytest.mark.parametrize(
    "prev,role,expected",
    [
        ("open", "tier1", ["keep"]),
        ("open", "tier2", ["keep", "undo"]),
        ("open", "admin", ["keep", "undo"]),
        ("kept", "tier1", []),
        ("kept", "tier2", ["undo"]),
        ("kept", "admin", ["undo"]),
    ],
)
def test_a_lock_older_than_two_minutes_is_served_with_the_status_and_the_decisions_the_row_had(
    world, prev, role, expected
):
    review_id = world.put_locked(by="alice", age_s=121, prev=prev)
    for body in (
        world.get(role, f"{REVIEWS}/{review_id}").json(),
        next(r for r in world.get(role, REVIEWS).json()["rows"] if r["id"] == review_id),
    ):
        assert body["status"] == prev
        assert body["locked_by"] is None and body["locked_at"] is None
        assert body["allowed_decisions"] == expected


def test_the_two_minute_boundary(world):
    held = world.put_locked(age_s=110)
    abandoned = world.put_locked(age_s=130)
    assert world.get("tier2", f"{REVIEWS}/{held}").json()["status"] == "processing"
    assert world.get("tier2", f"{REVIEWS}/{abandoned}").json()["status"] == "open"


def test_a_read_writes_nothing_a_stale_lock_is_not_released_by_looking_at_it(world):
    review_id = world.put_locked(by="alice", age_s=300, prev="open")
    before = world.row(review_id)
    audit_before = world.rows("SELECT count(*) FROM audit_events")[0][0]
    for role in ("tier1", "tier2", "admin"):
        world.get(role, f"{REVIEWS}/{review_id}")
        world.get(role, REVIEWS)
        world.get(role, f"{REVIEWS}/count")
    assert world.row(review_id) == before
    assert before["status"] == "processing" and before["locked_by"] == "alice"
    assert world.rows("SELECT count(*) FROM audit_events")[0][0] == audit_before


# ── the list ────────────────────────────────────────────────────────────────────────────────


def test_the_list_is_rows_total_page_and_page_size_newest_first_then_by_id(world):
    a = world.put(id="AAAAAAA2", created_at=_at(10))
    b = world.put(id="BBBBBBB2", created_at=_at(30))
    c = world.put(id="CCCCCCC2", created_at=_at(30))
    d = world.put(id="DDDDDDD2", created_at=_at(20))
    body = world.get("tier2", REVIEWS).json()
    assert list(body) == ["rows", "total", "page", "page_size"]
    assert (body["total"], body["page"], body["page_size"]) == (4, 1, 50)
    assert [r["id"] for r in body["rows"]] == [b, c, d, a]  # 30, 30 (by id), 20, 10


def test_the_order_is_newest_created_at_then_id_also_with_kind_notice(world):
    notices = {
        name: world.put(id=name, kind="notice", status="info", created_at=_at(seconds), buttons=[], action_type=None)
        for name, seconds in (("NAAAAAAAAAAAA", 10), ("NCCCCCCCCCCCC", 30), ("NBBBBBBBBBBBB", 30), ("NDDDDDDDDDDDD", 20))
    }  # fmt: skip
    world.put(id="RVWAAAA2", created_at=_at(25))  # a review in between, left out by `kind`
    for params in ({"kind": "notice"}, {"kind": "notice", "status": "info"}):
        body = world.get("tier2", REVIEWS, **params).json()
        assert [r["id"] for r in body["rows"]] == [
            notices["NBBBBBBBBBBBB"], notices["NCCCCCCCCCCCC"], notices["NDDDDDDDDDDDD"], notices["NAAAAAAAAAAAA"],
        ]  # fmt: skip
        assert body["total"] == 4
    everything = [r["id"] for r in world.get("tier2", REVIEWS).json()["rows"]]
    assert everything == [
        "NBBBBBBBBBBBB",
        "NCCCCCCCCCCCC",
        "RVWAAAA2",
        "NDDDDDDDDDDDD",
        "NAAAAAAAAAAAA",
    ]


def test_an_empty_list(world):
    assert world.get("tier2", REVIEWS).json() == {
        "rows": [],
        "total": 0,
        "page": 1,
        "page_size": 50,
    }


def test_pagination(world):
    ids = [world.put(id=f"PAGE000{i}", created_at=_at(i)) for i in range(2, 7)]  # 5 rows
    newest_first = list(reversed(ids))
    page1 = world.get("tier2", REVIEWS, page_size=2, page=1).json()
    page2 = world.get("tier2", REVIEWS, page_size=2, page=2).json()
    page3 = world.get("tier2", REVIEWS, page_size=2, page=3).json()
    page4 = world.get("tier2", REVIEWS, page_size=2, page=4).json()
    assert [r["id"] for r in page1["rows"]] == newest_first[0:2]
    assert [r["id"] for r in page2["rows"]] == newest_first[2:4]
    assert [r["id"] for r in page3["rows"]] == newest_first[4:5]
    assert page4["rows"] == []
    assert {p["total"] for p in (page1, page2, page3, page4)} == {5}
    assert (page2["page"], page2["page_size"]) == (2, 2)


def test_a_page_size_over_the_ceiling_is_clamped_to_200_like_the_queue(world):
    body = world.get("tier2", REVIEWS, page_size=500).json()
    assert body["page_size"] == 200


@pytest.mark.parametrize(
    "params",
    [
        {"page": 0},
        {"page": -1},
        {"page_size": 0},
        {"page": "x"},
        {"page_size": "x"},
        {"page": 10**7},
    ],
)
def test_a_page_or_page_size_out_of_range_is_422(world, params):
    assert world.get("tier2", REVIEWS, **params).status_code == 422


@pytest.fixture
def mixed(world) -> dict[str, str]:
    """Eight tickets that differ in every field the list filters on."""
    return {
        "a": world.put(id="MIXAAAA2", status="open", case_number=1, created_at=_at(10), src_ip="10.0.0.1", host="alpha"),
        "b": world.put(id="MIXBBBB2", status="kept", case_number=1, created_at=_at(20), src_ip="10.0.0.2", host="beta"),
        "c": world.put(
            id="MIXCCCC2", status="open", case_number=2, created_at=_at(30), action_type="kill_process",
            action_target="mimikatz.exe", host="WIN-DC01", user_name="jdoe", src_ip=None,
            buttons=[{"decision": "keep", "label": "Giữ"}, {"decision": "fp", "label": "Nhầm"}],
        ),
        "d": world.put(
            id="MIXDDDD2", status="expired", case_number=3, created_at=_at(40), action_type="isolate_host",
            host="PC-9", domain="evil.example", src_ip=None, action_target="PC-9",
        ),
        "e": world.put(
            id="MIXEEEE2", kind="notice", status="info", severity="warning", case_number=None, created_at=_at(50),
            action_type=None, host=None, src_ip=None, action_target=None, buttons=[],
        ),
        "f": world.put_locked(id="MIXFFFF2", prev="open", age_s=5, case_number=4, created_at=_at(60)),
        "g": world.put_locked(id="MIXGGGG2", prev="kept", age_s=500, case_number=5, created_at=_at(70)),
        "h": world.put(id="MIXHHHH2", status="undone", case_number=6, created_at=_at(80), action_type="sinkhole_domain", domain="bad.test", host=None),
    }  # fmt: skip


def _pick(mixed: dict[str, str], letters: str) -> list[str]:
    """The ids of `letters`, newest created first (the order of the list)."""
    return [mixed[letter] for letter in sorted(letters, reverse=True)]


def test_no_filter_lists_everything_newest_first(world, mixed):
    assert _ids(world.get("tier2", REVIEWS)) == _pick(mixed, "abcdefgh")


def test_status_is_the_effective_status(world, mixed):
    assert _ids(world.get("tier2", REVIEWS, status="open")) == _pick(mixed, "ac")
    assert _ids(world.get("tier2", REVIEWS, status="processing")) == _pick(
        mixed, "f"
    )  # not g: its lock is stale
    assert _ids(world.get("tier2", REVIEWS, status="kept")) == _pick(
        mixed, "bg"
    )  # g is served as kept
    assert _ids(world.get("tier2", REVIEWS, status="expired")) == _pick(mixed, "d")
    assert _ids(world.get("tier2", REVIEWS, status="info")) == _pick(mixed, "e")


def test_status_is_repeatable(world, mixed):
    response = world.client("tier2").get(f"{REVIEWS}?status=open&status=processing&status=kept")
    assert _ids(response) == _pick(mixed, "abcfg")
    assert response.json()["total"] == 5


def test_kind_action_type_and_case_number(world, mixed):
    assert _ids(world.get("tier2", REVIEWS, kind="notice")) == _pick(mixed, "e")
    assert _ids(world.get("tier2", REVIEWS, kind="review")) == _pick(mixed, "abcdfgh")
    assert _ids(world.get("tier2", REVIEWS, action_type="kill_process")) == _pick(mixed, "c")
    assert _ids(world.get("tier2", REVIEWS, action_type="block_ip")) == _pick(mixed, "abfg")
    assert _ids(world.get("tier2", REVIEWS, case_number=1)) == _pick(mixed, "ab")
    assert _ids(world.get("tier2", REVIEWS, case_number=999)) == []


def test_from_is_inclusive_and_to_is_exclusive_on_created_at(world, mixed):
    window = {"from": _at(20).isoformat(), "to": _at(50).isoformat()}
    assert _ids(world.get("tier2", REVIEWS, **window)) == _pick(mixed, "bcd")  # 20 in, 50 out
    assert _ids(world.get("tier2", REVIEWS, **{"from": _at(80).isoformat()})) == _pick(mixed, "h")
    assert _ids(world.get("tier2", REVIEWS, to=_at(10).isoformat())) == []
    assert (
        _ids(
            world.get("tier2", REVIEWS, **{"from": _at(50).isoformat(), "to": _at(20).isoformat()})
        )
        == []
    )


def test_from_and_to_take_any_offset(world, mixed):
    plus7 = _at(20).astimezone(timezone(timedelta(hours=7))).isoformat()
    assert plus7.endswith("+07:00")
    assert _ids(
        world.get("tier2", REVIEWS, **{"from": plus7, "to": "2026-11-13T14:40:50.123Z"})
    ) == _pick(mixed, "bcd")


@pytest.mark.parametrize("value", ["2026-11-13T14:40:05", "2026-11-13", "yesterday", "", "1e9"])
def test_a_time_with_no_offset_or_not_a_time_is_422(world, value):
    assert world.get("tier2", REVIEWS, **{"from": value}).status_code == 422
    assert world.get("tier2", REVIEWS, to=value).status_code == 422


@pytest.mark.parametrize(
    "params",
    [
        {"status": "closed"},
        {"status": "open", "kind": "ticket"},
        {"action_type": "rm_rf"},
        {"case_number": "abc"},
        {"case_number": -1},
        {"case_number": 2**63},
    ],
)
def test_a_value_outside_a_closed_set_or_a_range_is_422(world, params):
    assert world.get("tier2", REVIEWS, **params).status_code == 422


def test_filters_are_anded(world, mixed):
    assert _ids(world.get("tier2", REVIEWS, status="open", case_number=2)) == _pick(mixed, "c")
    assert (
        _ids(world.get("tier2", REVIEWS, status="open", case_number=1, action_type="kill_process"))
        == []
    )


# ── q ───────────────────────────────────────────────────────────────────────────────────────


def test_a_numeric_q_is_a_case_number_and_nothing_else(world, mixed):
    assert _ids(world.get("tier2", REVIEWS, q="1")) == _pick(
        mixed, "ab"
    )  # not the 10.0.0.1 of a text match
    assert _ids(world.get("tier2", REVIEWS, q=" 2 ")) == _pick(mixed, "c")
    assert _ids(world.get("tier2", REVIEWS, q="3")) == _pick(mixed, "d")
    assert _ids(world.get("tier2", REVIEWS, q="0")) == []


@pytest.mark.parametrize("q", ["#1", " #1", "#1 ", "  #  1  ", "# 1", "#001"])
def test_a_leading_hash_and_the_whitespace_around_it_are_ignored_so_65_can_be_written_65(
    world, mixed, q
):
    """Case numbers are written `#65` on the SOAR's tickets: `#65` finds case 65 as `65` does."""
    assert _ids(world.get("tier2", REVIEWS, q=q)) == _pick(mixed, "ab")  # case 1 (`#001` is 1)


def test_a_hash_before_a_text_is_ignored_too_and_only_the_leading_one(world, mixed):
    assert _ids(world.get("tier2", REVIEWS, q="#alpha")) == _pick(mixed, "a")
    assert _ids(world.get("tier2", REVIEWS, q=" # WIN-dc")) == _pick(mixed, "c")
    assert (
        _ids(world.get("tier2", REVIEWS, q="##1")) == []
    )  # one hash goes; `#1` is then a text nobody has
    assert (
        _ids(world.get("tier2", REVIEWS, q="al#pha")) == []
    )  # a hash inside is a character like another


@pytest.mark.parametrize("q", ["#", " # ", "#   "])
def test_a_hash_alone_filters_nothing(world, mixed, q):
    assert _ids(world.get("tier2", REVIEWS, q=q)) == _pick(mixed, "abcdefgh")


def test_a_host_with_a_hash_in_it_is_found_with_or_without_a_leading_one(world):
    plain = world.put(id="HASH0001", host="build#7", src_ip=None)
    assert _ids(world.get("tier2", REVIEWS, q="build#7")) == [plain]
    assert _ids(world.get("tier2", REVIEWS, q="#build#7")) == [plain]


def test_a_number_too_large_for_a_case_number_is_searched_as_text(world, mixed):
    assert _ids(world.get("tier2", REVIEWS, q="9" * 25)) == []


@pytest.mark.parametrize(
    "q,letters",
    [
        ("10.0.0", "ab"),  # src_ip, a substring
        ("10.0.0.2", "b"),
        ("win-dc", "c"),  # host, case-insensitive
        ("ALPHA", "a"),
        ("jdoe", "c"),  # user_name
        ("mimikatz", "c"),  # action_target
        ("evil.EXAMPLE", "d"),  # domain
        ("bad.test", "h"),
        ("pfsense", "fg"),  # the host the default ticket has
        ("block_ip", ""),  # action_type is not searched
        ("Giữ chặn", ""),  # neither is the text of a button
    ],
)
def test_a_text_q_is_a_case_insensitive_substring_of_the_address_host_target_user_or_domain(
    world, mixed, q, letters
):
    assert _ids(world.get("tier2", REVIEWS, q=q)) == _pick(mixed, letters)


def test_q_is_anded_with_the_other_filters(world, mixed):
    assert _ids(world.get("tier2", REVIEWS, q="10.0.0", status="open")) == _pick(mixed, "a")


def test_a_blank_q_filters_nothing(world, mixed):
    assert _ids(world.get("tier2", REVIEWS, q="   ")) == _pick(mixed, "abcdefgh")
    assert _ids(world.get("tier2", REVIEWS, q="")) == _pick(mixed, "abcdefgh")


@pytest.mark.parametrize(
    "wild",
    [
        "%",
        "_",
        "\\",
        "%%",
        "a%",
        "_lpha",
        "al_ha",
        "%lpha",
        "'",
        "' OR '1'='1",
        '"; DROP TABLE soar_reviews;--',
    ],
)
def test_the_wildcards_of_like_and_sql_in_q_match_only_themselves(world, wild):
    """`%` and `_` are escaped: a `q` of `%` is the character, not "everything", and nothing in it is SQL."""
    world.put(id="WILD0001", host="alpha", src_ip="10.0.0.1")
    plain = world.put(id="WILD0002", host="a%b_c\\d", src_ip=None)
    found = _ids(world.get("tier2", REVIEWS, q=wild))
    expected = (
        [plain] if wild in {"%", "_", "\\", "a%"} else []
    )  # `a%` is in the host `a%b_c\\d`, as text
    assert found == expected
    assert world.rows("SELECT count(*) FROM soar_reviews")[0][0] == 2  # the table is still there


def test_q_of_100_characters_is_the_longest_and_101_is_422(world):
    assert world.get("tier2", REVIEWS, q="x" * 100).status_code == 200
    assert world.get("tier2", REVIEWS, q="x" * 101).status_code == 422


def test_q_with_a_nul_character_is_422_not_a_500(world):
    assert world.get("tier2", REVIEWS, q="a\x00b").status_code == 422


# ── the count ───────────────────────────────────────────────────────────────────────────────


def test_the_count_defaults_to_open_reviews_and_gives_the_newest_ones_time(world, mixed):
    body = world.get("tier2", f"{REVIEWS}/count").json()
    assert list(body) == ["count", "latest_received_at"]
    assert body["count"] == 2  # a and c: open reviews
    assert datetime.fromisoformat(body["latest_received_at"]) == _at(30)
    assert body["latest_received_at"].endswith("+00:00")


def test_the_count_is_over_the_effective_status_and_status_is_repeatable(world, mixed):
    client = world.client("tier1")
    both = client.get(f"{REVIEWS}/count?status=open&status=processing").json()
    assert both["count"] == 3  # a, c, f
    assert datetime.fromisoformat(both["latest_received_at"]) == _at(60)
    kept = client.get(f"{REVIEWS}/count?status=kept").json()
    assert kept["count"] == 2  # b, and g whose lock is stale
    assert datetime.fromisoformat(kept["latest_received_at"]) == _at(70)


def test_the_count_is_over_reviews_never_notices(world, mixed):
    assert world.get("tier2", f"{REVIEWS}/count", status="info").json() == {
        "count": 0,
        "latest_received_at": None,
    }


def test_the_count_of_nothing_is_zero_and_null(world):
    assert world.get("tier2", f"{REVIEWS}/count").json() == {"count": 0, "latest_received_at": None}


def test_a_new_ticket_moves_latest_received_at_and_a_late_delivery_of_an_older_ticket_does_too(
    world,
):
    world.put(created_at=_at(10), received_at=_at(10))
    first = world.get("tier2", f"{REVIEWS}/count").json()
    world.put(created_at=_at(99), received_at=_at(99))
    second = world.get("tier2", f"{REVIEWS}/count").json()
    assert (first["count"], second["count"]) == (1, 2)
    assert datetime.fromisoformat(second["latest_received_at"]) > datetime.fromisoformat(
        first["latest_received_at"]
    )
    # a ticket n8n created BEFORE the newest one, but that reached the web only now: n8n's `created_at` would hide it
    world.put(created_at=_at(5), received_at=_at(200))
    third = world.get("tier2", f"{REVIEWS}/count").json()
    assert third["count"] == 3
    assert datetime.fromisoformat(third["latest_received_at"]) == _at(200)
    assert datetime.fromisoformat(third["latest_received_at"]) > datetime.fromisoformat(
        second["latest_received_at"]
    )
    assert "latest_created_at" not in third and list(third) == ["count", "latest_received_at"]


def test_the_count_looks_at_received_at_not_created_at(world):
    world.put(created_at=_at(500), received_at=_at(10))
    body = world.get("tier2", f"{REVIEWS}/count").json()
    assert datetime.fromisoformat(body["latest_received_at"]) == _at(10)


def test_received_at_is_served_on_the_review_after_last_sent_at(world):
    review_id = world.put(created_at=_at(1), received_at=_at(77))
    body = world.get("tier2", f"{REVIEWS}/{review_id}").json()
    assert datetime.fromisoformat(body["received_at"]) == _at(77)
    assert body["received_at"].endswith("+00:00")
    keys = list(body)
    assert (
        keys.index("last_sent_at") + 1 == keys.index("received_at") == keys.index("updated_at") - 1
    )
    row = world.get("tier2", REVIEWS).json()["rows"][0]
    assert row["received_at"] == body["received_at"]


def test_count_is_a_route_not_an_id(world):
    assert world.get("tier2", f"{REVIEWS}/count").status_code == 200
    assert "count" in world.get("tier2", f"{REVIEWS}/count").json()


def test_an_unknown_status_in_the_count_is_422(world):
    assert world.get("tier2", f"{REVIEWS}/count", status="closed").status_code == 422


# ── the detail ──────────────────────────────────────────────────────────────────────────────


def test_the_detail_carries_the_body_n8n_last_sent(world):
    raw = data.review(future_field={"a": [1, {"b": None}]})
    review_id = world.put(raw=raw)
    assert world.get("tier2", f"{REVIEWS}/{review_id}").json()["raw"] == raw


def test_an_unknown_id_is_404(world):
    response = world.get("tier2", f"{REVIEWS}/ZZZZZZZ9")
    assert response.status_code == 404
    assert response.json() == {"detail": "review not found"}


@pytest.mark.parametrize("raw_id", ["a%00b", "%00", "a%1fb", "a%7fb", "a%c2%85b"])
def test_an_id_with_a_control_character_names_nothing_it_is_404_not_a_500(world, raw_id):
    assert world.client("tier2").get(f"{REVIEWS}/{raw_id}").status_code == 404


def _event(
    world: World,
    review_id: str,
    event_type: str,
    *,
    role: str,
    actor: str | None,
    payload: Any,
    at: datetime | None = None,
) -> None:
    world.execute(
        "INSERT INTO audit_events (event_type, subject_id, actor_role, actor_id, payload, created_at) "
        "VALUES (%s, %s, %s, %s, %s::jsonb, COALESCE(%s, now()))",
        (event_type, review_id, role, actor, json.dumps(payload), at),
    )


def test_the_history_is_the_events_of_this_ticket_oldest_first_with_who_did_it(world):
    review_id = world.put()
    tier2_id, tier2_name = world.users["tier2"]
    admin_id, admin_name = world.users["admin"]
    _event(
        world,
        review_id,
        "soar.review_received",
        role="system",
        actor=None,
        payload={"outcome": "created"},
        at=_at(1),
    )
    _event(
        world,
        review_id,
        "soar.review_decided",
        role="analyst",
        actor=tier2_id,
        payload={"decision": "keep", "outcome": "ok"},
        at=_at(2),
    )
    _event(
        world,
        review_id,
        "soar.review_decided",
        role="admin",
        actor=admin_id,
        payload={"decision": "undo", "outcome": "ok"},
        at=_at(3),
    )
    _event(
        world,
        review_id,
        "soar.review_received",
        role="system",
        actor=None,
        payload={"outcome": "updated"},
        at=_at(4),
    )
    # not this ticket's: another subject, and an event of another kind with this subject
    other = world.put()
    _event(
        world,
        other,
        "soar.review_received",
        role="system",
        actor=None,
        payload={"outcome": "created"},
        at=_at(0),
    )
    _event(
        world, review_id, "alert.received", role="system", actor=None, payload={"x": 1}, at=_at(5)
    )
    history = world.get("tier1", f"{REVIEWS}/{review_id}").json()["history"]
    assert [list(h) for h in history] == [HISTORY_KEYS] * 4
    assert [(h["event"], h["actor"], h["actor_role"]) for h in history] == [
        ("soar.review_received", None, "system"),
        ("soar.review_decided", tier2_name, "tier2"),  # the user's role, not the audit's `analyst`
        ("soar.review_decided", admin_name, "admin"),
        ("soar.review_received", None, "system"),
    ]
    assert [h["payload"]["outcome"] for h in history] == ["created", "ok", "ok", "updated"]
    assert [datetime.fromisoformat(h["at"]) for h in history] == [_at(1), _at(2), _at(3), _at(4)]
    assert all(h["at"].endswith("+00:00") for h in history)


def test_the_history_of_a_ticket_with_no_event_is_empty(world):
    assert world.get("tier2", f"{REVIEWS}/{world.put()}").json()["history"] == []


def test_the_history_is_at_most_200_events_the_oldest_ones(world):
    review_id = world.put()
    for i in range(205):
        _event(
            world,
            review_id,
            "soar.review_received",
            role="system",
            actor=None,
            payload={"i": i},
            at=_at(i),
        )
    history = world.get("tier2", f"{REVIEWS}/{review_id}").json()["history"]
    assert [h["payload"]["i"] for h in history] == list(range(200))


def test_a_ticket_without_a_case_number_has_no_related_alerts(world):
    review_id = world.put(case_number=None, case_id=None)
    world.put_alert(f"rel-{uuid.uuid4().hex[:8]}", _case_number())
    body = world.get("tier2", f"{REVIEWS}/{review_id}").json()
    assert body["related_alerts"] == [] and body["related_total"] == 0


def test_the_related_alerts_are_those_of_the_same_case_newest_first(world):
    number = _case_number()
    review_id = world.put(case_number=number)
    t = datetime(2026, 11, 13, 10, 0, tzinfo=UTC)
    world.put_alert(
        "rel-old", number, alert_time=t, description="cũ", agent_name="a1", occurrence_count=3
    )
    world.put_alert(
        "rel-new",
        number,
        alert_time=t + timedelta(hours=2),
        description="mới",
        agent_name="a2",
        occurrence_count=1,
    )
    world.put_alert(
        "rel-mid",
        number,
        alert_time=t + timedelta(hours=1),
        description="giữa",
        agent_name="a3",
        occurrence_count=7,
    )
    world.put_alert("rel-other-case", number + 1, alert_time=t)
    world.put_alert("rel-no-case", MISSING, alert_time=t)
    world.put_alert("rel-null-case", None, alert_time=t)
    body = world.get("tier2", f"{REVIEWS}/{review_id}").json()
    assert [a["alert_id"] for a in body["related_alerts"]] == ["rel-new", "rel-mid", "rel-old"]
    assert body["related_total"] == 3
    first = body["related_alerts"][0]
    assert list(first) == ALERT_KEYS
    assert (first["agent_name"], first["description"], first["occurrence_count"]) == (
        "a2",
        "mới",
        1,
    )
    assert first["severity"] == "medium" and first["status"] == "received"
    assert datetime.fromisoformat(first["alert_time"]) == t + timedelta(hours=2)
    assert first["alert_time"].endswith("+00:00")


def test_related_alerts_carry_no_field_of_the_ai(world):
    number = _case_number()
    review_id = world.put(case_number=number)
    world.put_alert("rel-blind", number)
    alert = world.get("tier1", f"{REVIEWS}/{review_id}").json()["related_alerts"][0]
    assert set(alert) == set(ALERT_KEYS)


def test_at_most_50_related_alerts_and_the_total_says_how_many_there_are(world):
    number = _case_number()
    review_id = world.put(case_number=number)
    t = datetime(2026, 11, 13, 10, 0, tzinfo=UTC)
    for i in range(55):
        world.put_alert(f"rel-m{i:02d}", number, alert_time=t + timedelta(minutes=i))
    body = world.get("tier2", f"{REVIEWS}/{review_id}").json()
    assert len(body["related_alerts"]) == 50 and body["related_total"] == 55
    assert body["related_alerts"][0]["alert_id"] == "rel-m54"
    assert body["related_alerts"][-1]["alert_id"] == "rel-m05"


def test_the_case_number_is_matched_as_the_number_whether_n8n_wrote_it_as_a_number_or_a_text(world):
    number = _case_number()
    review_id = world.put(case_number=number)
    world.put_alert("rel-int", number)
    world.put_alert("rel-str", str(number))
    ids = [
        a["alert_id"] for a in world.get("tier2", f"{REVIEWS}/{review_id}").json()["related_alerts"]
    ]
    assert sorted(ids) == ["rel-int", "rel-str"]


def test_the_detail_of_a_notice_and_of_a_locked_ticket(world):
    notice = world.put(kind="notice", status="info", case_number=None, action_type=None, buttons=[])
    locked = world.put_locked(by="alice", age_s=3)
    assert world.get("tier2", f"{REVIEWS}/{notice}").json()["allowed_decisions"] == []
    assert world.get("tier2", f"{REVIEWS}/{locked}").json()["status"] == "processing"


# ── who may read ────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("role", ["tier1", "tier2", "admin"])
def test_all_three_roles_read_all_three_routes(world, role):
    review_id = world.put()
    for path in (REVIEWS, f"{REVIEWS}/count", f"{REVIEWS}/{review_id}"):
        assert world.get(role, path).status_code == 200, (role, path)


def test_no_token_is_401_on_every_route(world):
    review_id = world.put()
    client = world.anonymous()
    for path in (REVIEWS, f"{REVIEWS}/count", f"{REVIEWS}/{review_id}"):
        assert client.get(path).status_code == 401, path
    assert (
        client.post(f"{REVIEWS}/{review_id}/decision", json={"decision": "keep"}).status_code == 401
    )


def test_a_role_no_page_has_is_403_and_the_refusal_is_audited(world):
    review_id = world.put()
    before = len(world.denied("tier1"))
    for path in (REVIEWS, f"{REVIEWS}/count", f"{REVIEWS}/{review_id}"):
        assert world.get("viewer", path).status_code == 403, path
    denied = world.denied("tier1")[
        before:
    ]  # a role that is no user's: the fixture signs it in as tier1's user
    assert [d["subject_id"] for d in denied] == [
        REVIEWS,
        f"{REVIEWS}/count",
        f"{REVIEWS}/{review_id}",
    ]
    assert denied[0]["payload"] == {
        "required": ["tier1", "tier2", "admin"],
        "role": "viewer",
        "method": "GET",
    }


def test_the_routes_are_in_the_app_under_api_soar(world):
    paths = {
        route.path for router in main.app.routes if hasattr(router, "path") for route in [router]
    }
    paths |= set(main.app.openapi()["paths"])
    assert {
        "/api/soar/reviews",
        "/api/soar/reviews/count",
        "/api/soar/reviews/{review_id}",
        "/api/soar/reviews/{review_id}/decision",
    } <= paths
