"""SR-T1 — `POST /webhook/soar-notices` (`web/routers/webhook_soar_notices.py`, spec 2026-11-16 §2, "Contract A").

n8n pushes the review tickets (and the plain notices) to this route. Every test runs on a scratch database through
`deps.get_conn` itself (committed on a 2xx, rolled back on any raise) and reads the outcome back on a second connection:
committed data, not an open transaction. The scratch database is this module's own (`scratch_database("soarnotice")`),
dropped when the module ends, so no row of `soar_reviews` or `audit_events` reaches the shared session database.

The order of the checks (spec §2), exactly: an empty `SOAR_NOTICE_API_KEY` is `503`; a missing or wrong `X-API-Key` is `401`,
written before the body is even read; a source address outside `SOAR_NOTICE_IP_ALLOWLIST` is `403`; a body over
`MAX_PAYLOAD_BYTES` is `413`; then the body is read (`400` with every fault, or the upsert table of §2). One audit event per
request that parsed; none for any other.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import psycopg
import pytest
from app.infra.config import Config
from app.web import deps, main
from app.web.routers import webhook_soar_notices
from fastapi.testclient import TestClient

from tests import conftest
from tests import soar_review_data as data
from tests.scratch_db import scratch_database
from tests.soar_review_data import MISSING

pytestmark = pytest.mark.db

PATH = "/webhook/soar-notices"
KEY = "notice-key-123"
ALLOWED_HOST = "10.0.0.7"
OUTSIDE_HOST = "192.0.2.9"


@pytest.fixture(scope="module")
def scratch_dsn():
    with scratch_database("soarnotice") as dsn:
        yield dsn


def _cfg(**over) -> Config:
    fields = {"SOAR_NOTICE_API_KEY": KEY, "SOAR_NOTICE_IP_ALLOWLIST": ["10.0.0.0/8"], **over}
    return replace(Config(), **fields)


class World:
    """The scratch database, a client for it, and what a second connection sees."""

    def __init__(
        self, dsn: conftest.Dsn
    ) -> None:  # not str: a plain str prints a password in a report
        self.dsn = dsn
        self.cfg = _cfg()

    def client(self, host: str = ALLOWED_HOST) -> TestClient:
        main.app.dependency_overrides[deps.get_config] = lambda: self.cfg
        return TestClient(main.app, client=(host, 1234), raise_server_exceptions=False)

    def post(
        self, doc: Any, *, key: str | None = KEY, host: str = ALLOWED_HOST, headers=None
    ) -> httpx.Response:
        body = doc if isinstance(doc, bytes) else json.dumps(doc).encode("utf-8")
        sent = {"content-type": "application/json", **(headers or {})}
        if key is not None:
            sent["x-api-key"] = key
        return self.client(host).post(PATH, content=body, headers=sent)

    def rows(self, query: str, params: tuple = ()) -> list[tuple]:
        with psycopg.connect(self.dsn) as conn:
            return conn.execute(query, params).fetchall()

    def row(self, review_id: str) -> dict[str, Any] | None:
        found = self.rows("SELECT to_jsonb(t) FROM soar_reviews t WHERE id = %s", (review_id,))
        return found[0][0] if found else None

    def events(self, review_id: str) -> list[dict[str, Any]]:
        found = self.rows(
            "SELECT event_type, actor_role, actor_id, payload FROM audit_events "
            "WHERE subject_id = %s ORDER BY audit_id",
            (review_id,),
        )
        return [
            {"event_type": t, "actor_role": r, "actor_id": a, "payload": p} for t, r, a, p in found
        ]

    def count(self) -> int:
        return self.rows("SELECT count(*) FROM soar_reviews")[0][0]

    def audit_count(self) -> int:
        return self.rows("SELECT count(*) FROM audit_events WHERE event_type LIKE 'soar.%%'")[0][0]

    def execute(self, query: str, params: tuple = ()) -> None:
        with psycopg.connect(self.dsn) as conn:
            conn.execute(query, params)


@pytest.fixture
def world(scratch_dsn, monkeypatch) -> World:
    monkeypatch.setattr(
        deps.db, "connect", lambda *args, **kwargs: psycopg.connect(scratch_dsn, autocommit=False)
    )
    w = World(scratch_dsn)
    try:
        yield w
    finally:
        main.app.dependency_overrides.pop(deps.get_config, None)


def _at(seconds: float) -> str:
    """A `sent_at` `seconds` after the example's, as n8n writes it."""
    return data.iso(data.T0 + timedelta(seconds=seconds))


def _errors(response: httpx.Response) -> list[dict[str, str]]:
    return response.json()["detail"]["errors"]


# ── 503 / 401 / 403: before the body is read ────────────────────────────────────────────────


def test_an_empty_key_is_503_and_writes_nothing(world):
    world.cfg = _cfg(SOAR_NOTICE_API_KEY="")
    doc = data.review()
    for key in (None, "", KEY, "anything"):
        response = world.post(doc, key=key)
        assert response.status_code == 503
        assert response.json() == {"detail": "soar notices disabled"}
    assert world.row(doc["id"]) is None


@pytest.mark.parametrize("key", [None, "", "wrong", KEY.upper(), KEY + " ", " " + KEY, KEY[:-1]])
def test_a_missing_or_wrong_key_is_401_and_writes_nothing(world, key):
    doc = data.review()
    response = world.post(doc, key=key)
    assert response.status_code == 401
    assert response.json() == {"detail": "unauthorized"}
    assert world.row(doc["id"]) is None
    assert world.events(doc["id"]) == []


def test_the_key_is_checked_before_the_body_is_read(world):
    """A body that would be a 400, a 413 or not even JSON still meets the 401 first: an attacker without the key
    learns nothing about the body and grows nothing."""
    for body in (b"not json", b"{}", b"x" * 100_000):
        world.cfg = _cfg(MAX_PAYLOAD_BYTES=50)
        assert world.post(body, key="wrong").status_code == 401


def test_the_key_is_compared_in_constant_time(world, monkeypatch):
    seen: list[tuple[bytes, bytes]] = []
    real = hmac.compare_digest

    def spy(a, b):
        seen.append((a, b))
        return real(a, b)

    monkeypatch.setattr(webhook_soar_notices.hmac, "compare_digest", spy)
    assert world.post(data.review(), key="wrong").status_code == 401
    assert seen == [(b"wrong", KEY.encode())]


def test_a_key_that_is_not_ascii_is_a_401_not_a_500(world):
    """`hmac.compare_digest` on two `str` raises for a non-ASCII one; the route compares bytes."""
    headers = {"x-api-key": "khóa-sai".encode(), "content-type": "application/json"}
    response = world.client().post(
        PATH, content=json.dumps(data.review()).encode(), headers=headers
    )
    assert response.status_code == 401


def test_the_key_wins_over_the_address_a_wrong_key_from_outside_is_401(world):
    assert world.post(data.review(), key="wrong", host=OUTSIDE_HOST).status_code == 401


def test_an_address_outside_the_allowlist_is_403_and_logged_without_the_key(world, caplog):
    doc = data.review()
    response = world.post(doc, host=OUTSIDE_HOST)
    assert response.status_code == 403
    assert response.json() == {"detail": "forbidden"}
    assert world.row(doc["id"]) is None
    text = " ".join(r.getMessage() for r in caplog.records)
    assert OUTSIDE_HOST in text
    assert KEY not in text


@pytest.mark.parametrize(
    "allowlist,host,status",
    [
        ([], ALLOWED_HOST, 403),  # empty denies all
        (["10.0.0.0/8"], "10.255.255.254", 201),
        (["10.0.0.7"], "10.0.0.7", 201),  # a bare address is a /32
        (["10.0.0.7"], "10.0.0.8", 403),
        (["192.0.2.0/24", "10.0.0.0/8"], "192.0.2.9", 201),
        (["fd00::/8"], "fd00::5", 201),
        (["10.0.0.0/8"], "fd00::5", 403),
        (["10.0.0.0/8"], "testclient", 403),  # a peer that is no address at all
    ],
)
def test_the_source_address_is_matched_against_the_allowlist(world, allowlist, host, status):
    world.cfg = _cfg(SOAR_NOTICE_IP_ALLOWLIST=allowlist)
    assert world.post(data.review(), host=host).status_code == status


# ── 413 ─────────────────────────────────────────────────────────────────────────────────────


def test_a_body_over_max_payload_bytes_is_413_and_one_of_exactly_the_limit_is_read(world):
    doc = data.review()
    size = len(json.dumps(doc).encode("utf-8"))
    world.cfg = _cfg(MAX_PAYLOAD_BYTES=size - 1)
    assert world.post(doc).status_code == 413
    assert world.row(doc["id"]) is None
    world.cfg = _cfg(MAX_PAYLOAD_BYTES=size)
    assert world.post(doc).status_code == 201


def test_a_body_with_no_content_length_is_counted_as_it_arrives(world):
    """A chunked upload names no length: the cap is on what is read, not on what was declared."""
    doc = data.review()
    world.cfg = _cfg(MAX_PAYLOAD_BYTES=100)
    payload = json.dumps(doc).encode("utf-8")

    def chunks():
        for i in range(0, len(payload), 50):
            yield payload[i : i + 50]

    response = world.client().post(
        PATH, content=chunks(), headers={"x-api-key": KEY, "content-type": "application/json"}
    )
    assert response.status_code == 413
    assert world.row(doc["id"]) is None


def test_413_is_not_a_400_and_writes_no_event(world):
    world.cfg = _cfg(MAX_PAYLOAD_BYTES=10)
    before = world.audit_count()
    assert world.post(data.review()).status_code == 413
    assert world.audit_count() == before


# ── 400 ─────────────────────────────────────────────────────────────────────────────────────


def test_a_wrong_body_is_400_listing_every_fault_and_writes_nothing(world):
    doc = data.review(event="gone", severity="bad", score="x", sent_at="2026-11-13T21:40:05")
    before = world.audit_count()
    response = world.post(doc)
    assert response.status_code == 400
    assert response.json() == {
        "detail": {
            "errors": [
                {"field": "event", "reason": "invalid_value"},
                {"field": "sent_at", "reason": "no_offset"},
                {"field": "severity", "reason": "invalid_value"},
                {"field": "score", "reason": "invalid_type"},
            ]
        }
    }
    assert world.row(doc["id"]) is None
    assert world.audit_count() == before


@pytest.mark.parametrize("body", [b"", b"nope", b"[]", b'{"a": NaN}', b"\xff\xfe"])
def test_a_body_that_is_not_a_json_object_is_one_body_fault(world, body):
    response = world.post(body)
    assert response.status_code == 400
    assert _errors(response) == [{"field": "body", "reason": "invalid"}]


def test_an_error_answer_repeats_nothing_the_sender_wrote(world):
    hostile = "<script>alert(1)</script>'; DROP TABLE soar_reviews;--"
    response = world.post(data.review(severity=hostile, title=hostile * 10))
    assert response.status_code == 400
    assert "script" not in response.text and "DROP" not in response.text


def test_a_review_without_its_action_type_and_buttons_is_400(world):
    doc = data.review(action=MISSING, buttons=MISSING)
    assert _errors(world.post(doc)) == [
        {"field": "action.type", "reason": "required"},
        {"field": "buttons", "reason": "required"},
    ]


def test_processing_from_n8n_is_400_reserved(world):
    assert _errors(world.post(data.review(status="processing"))) == [
        {"field": "status", "reason": "reserved"}
    ]


def test_another_major_version_is_400_and_a_later_minor_is_accepted(world):
    assert _errors(world.post(data.review(schema_version="2.0"))) == [
        {"field": "schema_version", "reason": "unsupported_version"}
    ]
    assert world.post(data.review(schema_version="1.9")).status_code == 201


# ── 201: a ticket that is new ───────────────────────────────────────────────────────────────


def test_a_new_review_is_201_and_stored_with_every_field(world):
    doc = data.review()
    response = world.post(doc)
    assert response.status_code == 201
    assert response.json() == {"id": doc["id"], "created": True}
    row = world.row(doc["id"])
    assert row["id"] == doc["id"]
    assert (row["kind"], row["status"], row["severity"]) == ("review", "open", "info")
    assert row["title"] == "ĐÃ TỰ XỬ LÝ" and row["simulated"] is False
    assert (row["case_id"], row["case_number"]) == ("~4096", 65)
    assert row["action_type"] == "block_ip" and row["action_via"] == "pfsense"
    assert row["action_text"] == "Chặn IP 79.79.78.202 trên pfSense"
    assert row["action_target"] == "79.79.78.202" and row["action_agent"] is None
    assert (row["host"], row["agent_id"], row["src_ip"]) == (
        "pfSense.home.arpa",
        "003",
        "79.79.78.202",
    )
    assert (row["user_name"], row["domain"]) == (None, None)
    assert (row["scenario_id"], row["scenario_name"]) == ("SC03", "Quét cổng từ bên ngoài")
    assert row["score"] == 50 and row["note"].startswith("Đã chặn")
    assert row["buttons"] == doc["buttons"]
    assert row["remind_every_minutes"] == 0 and row["next_remind_at"] is None
    assert (row["decided_by"], row["decided_at"], row["result"]) == (None, None, None)
    assert (row["last_error"], row["locked_by"], row["locked_at"], row["prev_status"]) == (
        None,
    ) * 4
    created = datetime.fromisoformat(row["created_at"])
    assert created == datetime(2026, 11, 13, 14, 40, 3, 123000, tzinfo=UTC)
    assert datetime.fromisoformat(row["last_sent_at"]) == datetime(
        2026, 11, 13, 14, 40, 5, 123000, tzinfo=UTC
    )
    assert datetime.fromisoformat(row["auto_expire_at"]) == datetime(
        2026, 11, 13, 15, 40, 5, 123000, tzinfo=UTC
    )
    assert row["updated_at"] is not None


def test_the_body_is_stored_as_sent_unknown_fields_included(world):
    doc = data.review(future_field={"a": [1, 2, {"b": None}]}, extra="giữ nguyên")
    assert world.post(doc).status_code == 201
    assert world.row(doc["id"])["raw"] == doc


def test_a_kill_process_review_and_a_notice_are_stored(world):
    killed = data.kill_process()
    info = data.notice()
    assert world.post(killed).status_code == 201
    assert world.post(info).status_code == 201
    row = world.row(killed["id"])
    assert row["action_type"] == "kill_process" and row["action_agent"] == "WIN-DC01"
    assert [b["decision"] for b in row["buttons"]] == ["keep", "fp"]
    row = world.row(info["id"])
    assert (row["kind"], row["status"], row["severity"]) == ("notice", "info", "warning")
    assert row["buttons"] == [] and row["action_type"] is None and row["case_number"] is None


def test_a_missing_created_at_is_the_first_sent_at(world):
    doc = data.review(created_at=MISSING)
    world.post(doc)
    row = world.row(doc["id"])
    assert row["created_at"] == row["last_sent_at"]


def test_a_missing_severity_is_stored_as_info_and_a_missing_simulated_as_false(world):
    doc = data.review(severity=MISSING, simulated=MISSING, remind_every_minutes=MISSING)
    world.post(doc)
    row = world.row(doc["id"])
    assert (row["severity"], row["simulated"], row["remind_every_minutes"]) == ("info", False, 0)


def test_a_score_is_stored_rounded(world):
    doc = data.review(score=49.5)
    world.post(doc)
    assert world.row(doc["id"])["score"] == 50


def test_a_text_is_stored_as_text_markup_and_sql_included(world):
    hostile = "<img src=x onerror=alert(1)> '; DROP TABLE soar_reviews;-- %s %(x)s \\"
    doc = data.review(note=hostile, host=hostile, title=hostile[:150])
    assert world.post(doc).status_code == 201
    row = world.row(doc["id"])
    assert row["note"] == hostile and row["host"] == hostile
    assert world.count() >= 1


def test_an_update_or_a_reminder_for_an_id_not_known_creates_it(world):
    for event in ("updated", "reminder"):
        doc = data.review(event=event)
        response = world.post(doc)
        assert response.status_code == 201, event
        assert response.json() == {"id": doc["id"], "created": True}


# ── 200: a ticket that is there ─────────────────────────────────────────────────────────────


def test_an_update_replaces_every_field_of_the_stored_ticket(world):
    first = data.review()
    world.post(first)
    update = data.review(
        id=first["id"],
        event="updated",
        sent_at=_at(60),
        status="kept",
        severity="warning",
        title="ĐÃ GIỮ",
        simulated=True,
        case={"id": "~9999", "number": 99},
        host="other-host",
        score=75,
        note=None,
        decided_by="alice",
        decided_at=_at(55),
        result="giữ chặn",
        buttons=[{"decision": "undo", "label": "Gỡ"}],
        remind_every_minutes=30,
        next_remind_at=_at(1800),
    )
    update["action"]["target"] = "1.2.3.4"
    update["action"]["agent"] = "agent-7"
    response = world.post(update)
    assert response.status_code == 200
    assert response.json() == {"id": first["id"], "created": False}
    row = world.row(first["id"])
    assert (row["status"], row["severity"], row["title"], row["simulated"]) == (
        "kept", "warning", "ĐÃ GIỮ", True,
    )  # fmt: skip
    assert (row["case_id"], row["case_number"], row["host"], row["score"]) == (
        "~9999",
        99,
        "other-host",
        75,
    )
    assert row["note"] is None  # absent or null in the body: replaced by null
    assert (row["decided_by"], row["result"]) == ("alice", "giữ chặn")
    assert row["buttons"] == [{"decision": "undo", "label": "Gỡ"}]
    assert (row["action_target"], row["action_agent"]) == ("1.2.3.4", "agent-7")
    assert row["remind_every_minutes"] == 30
    assert row["raw"] == update
    assert datetime.fromisoformat(row["last_sent_at"]) == data.T0 + timedelta(seconds=60)


def test_an_update_that_leaves_created_at_out_keeps_the_stored_one(world):
    first = data.review()
    world.post(first)
    before = world.row(first["id"])["created_at"]
    world.post(data.review(id=first["id"], event="updated", sent_at=_at(30), created_at=MISSING))
    assert world.row(first["id"])["created_at"] == before


def test_an_update_leaves_the_webs_own_last_error_alone(world):
    first = data.review()
    world.post(first)
    world.execute(
        "UPDATE soar_reviews SET last_error = 'GỠ THẤT BẠI' WHERE id = %s", (first["id"],)
    )
    world.post(data.review(id=first["id"], event="reminder", sent_at=_at(30)))
    assert world.row(first["id"])["last_error"] == "GỠ THẤT BẠI"


def test_a_resend_with_the_same_sent_at_is_applied_not_stale(world):
    first = data.review()
    world.post(first)
    again = data.review(id=first["id"], sent_at=first["sent_at"], note="gửi lại")
    response = world.post(again)
    assert (response.status_code, response.json()) == (200, {"id": first["id"], "created": False})
    assert world.row(first["id"])["note"] == "gửi lại"


def test_a_body_older_than_the_last_applied_is_ignored_as_stale(world):
    first = data.review(sent_at=_at(100))
    world.post(first)
    before = world.row(first["id"])
    stale = data.review(id=first["id"], event="updated", sent_at=_at(50), status="kept", note="cũ")
    response = world.post(stale)
    assert response.status_code == 200
    assert response.json() == {
        "id": first["id"],
        "created": False,
        "ignored": True,
        "reason": "stale",
    }
    assert world.row(first["id"]) == before  # not one column moved, `updated_at` included


def test_a_stale_body_does_not_move_last_sent_at_back(world):
    first = data.review(sent_at=_at(100))
    world.post(first)
    world.post(data.review(id=first["id"], sent_at=_at(50)))
    assert datetime.fromisoformat(world.row(first["id"])["last_sent_at"]) == data.T0 + timedelta(
        seconds=100
    )


@pytest.mark.parametrize("terminal", ["undone", "false_positive", "expired"])
def test_a_body_saying_open_does_not_reopen_a_terminal_ticket(world, terminal):
    first = data.review(status=terminal, sent_at=_at(10))
    world.post(first)
    before = world.row(first["id"])
    reopen = data.review(id=first["id"], event="updated", sent_at=_at(20), status="open")
    response = world.post(reopen)
    assert response.status_code == 200
    assert response.json() == {
        "id": first["id"],
        "created": False,
        "ignored": True,
        "reason": "terminal",
    }
    assert world.row(first["id"]) == before


@pytest.mark.parametrize("terminal", ["undone", "false_positive", "expired"])
def test_any_other_change_to_a_terminal_ticket_is_applied(world, terminal):
    """The protection is against `open` only (the Owner's rule as written): n8n's other changes go through."""
    first = data.review(status=terminal, sent_at=_at(10))
    world.post(first)
    update = data.review(
        id=first["id"], event="updated", sent_at=_at(20), status="kept", note="sửa"
    )
    assert world.post(update).json() == {"id": first["id"], "created": False}
    assert world.row(first["id"])["status"] == "kept"


def test_open_is_applied_to_a_ticket_that_is_kept_or_open(world):
    for stored in ("kept", "open"):
        first = data.review(status=stored, sent_at=_at(10))
        world.post(first)
        update = data.review(id=first["id"], sent_at=_at(20), status="open", note="mở")
        assert world.post(update).json() == {"id": first["id"], "created": False}
        assert world.row(first["id"])["note"] == "mở"


def test_stale_wins_over_terminal(world):
    first = data.review(status="expired", sent_at=_at(100))
    world.post(first)
    response = world.post(data.review(id=first["id"], sent_at=_at(10), status="open"))
    assert response.json()["reason"] == "stale"


# ── a ticket the web holds ──────────────────────────────────────────────────────────────────


def _lock(world: World, review_id: str, by: str = "alice") -> None:
    world.execute(
        "UPDATE soar_reviews SET prev_status = status, status = 'processing', locked_by = %s, "
        "locked_at = now() WHERE id = %s",
        (by, review_id),
    )


def test_an_update_that_lands_on_a_processing_row_is_applied_and_clears_the_lock(world):
    first = data.review()
    world.post(first)
    _lock(world, first["id"])
    assert world.row(first["id"])["status"] == "processing"
    update = data.review(id=first["id"], event="updated", sent_at=_at(30), status="kept")
    response = world.post(update)
    assert response.status_code == 200
    assert response.json() == {"id": first["id"], "created": False}
    row = world.row(first["id"])
    assert row["status"] == "kept"
    assert (row["locked_by"], row["locked_at"], row["prev_status"]) == (None, None, None)


def test_an_open_body_on_a_row_in_processing_is_applied_too(world):
    """`processing` is not terminal: the row that was `open` before the lock goes back to `open`, unlocked."""
    first = data.review()
    world.post(first)
    _lock(world, first["id"])
    world.post(data.review(id=first["id"], event="reminder", sent_at=_at(30), status="open"))
    row = world.row(first["id"])
    assert row["status"] == "open" and row["locked_by"] is None


def test_a_stale_body_leaves_a_processing_row_as_it_was(world):
    first = data.review(sent_at=_at(100))
    world.post(first)
    _lock(world, first["id"])
    world.post(data.review(id=first["id"], sent_at=_at(5), status="kept"))
    row = world.row(first["id"])
    assert (row["status"], row["locked_by"], row["prev_status"]) == ("processing", "alice", "open")


# ── the audit event ─────────────────────────────────────────────────────────────────────────

PAYLOAD_KEYS = {"event", "kind", "outcome", "reason", "status", "sent_at"}


def test_a_created_ticket_writes_one_system_event(world):
    doc = data.review()
    world.post(doc)
    [event] = world.events(doc["id"])
    assert event["event_type"] == "soar.review_received"
    assert (event["actor_role"], event["actor_id"]) == ("system", None)
    assert set(event["payload"]) == PAYLOAD_KEYS
    assert event["payload"] == {
        "event": "created",
        "kind": "review",
        "outcome": "created",
        "reason": None,
        "status": "open",
        "sent_at": "2026-11-13T14:40:05.123000+00:00",
    }


def test_each_outcome_is_one_event_with_its_own_outcome_and_reason(world):
    first = data.review(status="expired", sent_at=_at(100))
    world.post(first)  # created
    world.post(
        data.review(id=first["id"], sent_at=_at(100), status="kept", event="updated")
    )  # updated
    world.post(data.review(id=first["id"], sent_at=_at(1), event="reminder"))  # ignored: stale
    world.post(
        data.review(id=first["id"], sent_at=_at(200), status="expired")
    )  # updated: back to expired
    world.post(
        data.review(id=first["id"], sent_at=_at(300), status="open", event="updated")
    )  # terminal
    events = world.events(first["id"])
    assert [e["event_type"] for e in events] == ["soar.review_received"] * 5
    assert [(e["payload"]["outcome"], e["payload"]["reason"]) for e in events] == [
        ("created", None),
        ("updated", None),
        ("ignored", "stale"),
        ("updated", None),
        ("ignored", "terminal"),
    ]
    assert [e["payload"]["event"] for e in events] == [
        "created", "updated", "reminder", "created", "updated",
    ]  # fmt: skip


def test_no_event_for_a_request_that_did_not_parse_or_did_not_pass_the_three_checks(world):
    doc = data.review()
    before = world.audit_count()
    world.post(doc, key="wrong")  # 401
    world.post(doc, host=OUTSIDE_HOST)  # 403
    world.post(b"junk")  # 400
    world.post(data.review(status="processing"))  # 400
    world.cfg = _cfg(SOAR_NOTICE_API_KEY="")
    world.post(doc)  # 503
    assert world.audit_count() == before


def test_a_failure_after_the_row_was_written_leaves_neither_row_nor_event(world, monkeypatch):
    """One transaction: the ticket and its event land together or not at all."""
    doc = data.review()

    def boom(*args, **kwargs):
        raise RuntimeError("audit write failed")

    monkeypatch.setattr(webhook_soar_notices.review_notice, "write_event", boom)
    assert world.post(doc).status_code == 500
    assert world.row(doc["id"]) is None


# ── concurrency ─────────────────────────────────────────────────────────────────────────────


def _threads(calls: list[Callable[[], httpx.Response]]) -> list[httpx.Response]:
    barrier = threading.Barrier(len(calls))

    def run(call: Callable[[], httpx.Response]) -> httpx.Response:
        barrier.wait(timeout=10)
        return call()

    with ThreadPoolExecutor(max_workers=len(calls)) as pool:
        return list(pool.map(run, calls))


def test_six_requests_for_one_new_id_make_it_once_and_the_newest_body_wins(world):
    """The row is locked for the upsert, and a request that lost the insert race falls back to the update path."""
    review_id = data.new_id()
    docs = [data.review(id=review_id, sent_at=_at(i * 10), note=f"lần {i}") for i in range(6)]
    responses = _threads([lambda d=d: world.post(d) for d in docs])
    assert sorted(r.status_code for r in responses) == [200] * 5 + [201]
    assert world.count() >= 1
    row = world.row(review_id)
    assert row["note"] == "lần 5"  # the newest `sent_at`, whatever the arrival order
    assert datetime.fromisoformat(row["last_sent_at"]) == data.T0 + timedelta(seconds=50)
    events = world.events(review_id)
    assert len(events) == 6
    assert sorted(e["payload"]["outcome"] for e in events).count("created") == 1


# ── the event loop ──────────────────────────────────────────────────────────────────────────


def test_a_request_waiting_on_a_locked_row_does_not_block_the_event_loop_and_ends_in_503_busy(
    world, monkeypatch
):
    """The database half of the route runs in a worker thread (S0, 27/10: a blocking call on the loop wedged the whole
    app). A request for a row another session holds waits; while it waits the loop keeps turning (a ticker on the same
    loop is never late, and a second request is answered at once); and the wait is cut by `lock_timeout` into
    `503 busy` with `Retry-After`."""
    monkeypatch.setattr(webhook_soar_notices, "_LOCK_TIMEOUT", "1s")
    first = data.review()
    world.post(first)
    holder = psycopg.connect(world.dsn)
    holder.execute("SELECT 1 FROM soar_reviews WHERE id = %s FOR UPDATE", (first["id"],))
    main.app.dependency_overrides[deps.get_config] = lambda: world.cfg
    update = json.dumps(data.review(id=first["id"], sent_at=_at(30))).encode()
    good = {"x-api-key": KEY, "content-type": "application/json"}

    async def scenario() -> tuple[httpx.Response, httpx.Response, float]:
        gaps: list[float] = []
        stop = asyncio.Event()

        async def ticker() -> None:
            last = time.monotonic()
            while not stop.is_set():
                await asyncio.sleep(0.02)
                now = time.monotonic()
                gaps.append(now - last)
                last = now

        transport = httpx.ASGITransport(app=main.app, client=(ALLOWED_HOST, 1234))
        async with httpx.AsyncClient(transport=transport, base_url="http://app") as client:
            tick = asyncio.create_task(ticker())
            slow, quick = await asyncio.gather(
                client.post(PATH, content=update, headers=good),
                client.post(PATH, content=update, headers={"x-api-key": "wrong"}),
            )
            stop.set()
            await tick
        return slow, quick, max(gaps)

    try:
        slow, quick, worst_gap = asyncio.run(scenario())
    finally:
        holder.rollback()
        holder.close()
    assert (
        worst_gap < 0.4
    ), f"the event loop stood still for {worst_gap:.2f} s: a blocking call on the loop"
    assert quick.status_code == 401
    assert slow.status_code == 503
    assert slow.json() == {"detail": "busy"}
    assert slow.headers["retry-after"] == "2"
    assert datetime.fromisoformat(world.row(first["id"])["last_sent_at"]) == data.T0
