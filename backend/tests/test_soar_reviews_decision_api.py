"""SR-T1 — `POST /api/soar/reviews/{id}/decision` (`web/routers/soar_reviews.py`, spec 2026-11-16 §3 and §4): a person presses a
button, the backend asks n8n (the fake of `tests/fakes/n8n.py`, through the real client), n8n acts.

The route, in order: the caller (401) and a role that is in none of the three lists (403); the JSON type and the body (422);
the role for THE decision asked (403, with the `authz.denied` event); the ticket (404); a ticket someone holds (409 `locked`) or one
in a state the decision does not fit (409 `invalid_state`); the address of n8n and the secret (503 before anything is locked); the
lock, ONE statement, committed so that it is visible and no transaction stays open during the call; the call, off the event loop;
the compare-and-set that finishes; the answer `200 {outcome, message, review}`; and one `soar.review_decided` event per press that
reached the ticket (the six outcomes `ok`, `failed`, `unavailable`, `conflict`, `invalid_state`, `locked`).

THE DATABASE. A decision COMMITS in the middle of a request, by design, and writes audit rows; `audit_events` is append-only. So
every test here runs on a scratch database of this module (`soar_review_world.py`: built through `scripts/migrate.sh`, dropped
when the module ends): nothing a test commits reaches the shared session database. The webhook half of a race is made with
`review_notice.apply` on a connection of its own, committed, in the same scratch database.
"""

from __future__ import annotations

import asyncio
import json
import logging
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
from app.infra import n8n_approval
from app.soar import review_notice, reviews
from app.web import main

from tests import soar_review_data as data
from tests.fakes.n8n import FakeN8n, Reply
from tests.scratch_db import scratch_database
from tests.soar_review_world import JSON, N8N_URL, REVIEWS, SECRET, World

pytestmark = pytest.mark.db

DECIDED = "soar.review_decided"
KEEP_FP = [{"decision": "keep", "label": "✅ Giữ"}, {"decision": "fp", "label": "🚫 Báo nhầm"}]
PAYLOAD_KEYS = {"decision", "note", "outcome", "status_before", "status_after", "message"}


@pytest.fixture(scope="module")
def scratch_dsn():
    with scratch_database("soardecide") as dsn:
        yield dsn


@pytest.fixture
def world(scratch_dsn, monkeypatch):
    monkeypatch.setattr(
        "app.web.deps.db.connect", lambda *a, **k: psycopg.connect(scratch_dsn, autocommit=False)
    )
    w = World(scratch_dsn)
    try:
        yield w
    finally:
        w.unwire()


def _url(review_id: str) -> str:
    return f"{REVIEWS}/{review_id}/decision"


def _decide(world: World, role: str, review_id: str, decision: str, **body: Any) -> httpx.Response:
    return world.post_decision(role, review_id, {"decision": decision, **body})


def _decided(world: World, review_id: str) -> list[dict[str, Any]]:
    return world.events(review_id, DECIDED)


def _untouched(world: World, review_id: str, before: dict[str, Any]) -> None:
    assert world.row(review_id) == before, "the ticket was changed"
    assert world.fake.calls == [], "n8n was called"


# ── who may press which button ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "role,decision,allowed",
    [
        ("tier1", "keep", True),
        ("tier1", "undo", False),
        ("tier1", "fp", True),
        ("tier2", "keep", True),
        ("tier2", "undo", True),
        ("tier2", "fp", True),
        ("admin", "keep", True),
        ("admin", "undo", True),
        ("admin", "fp", True),
    ],
)
def test_the_default_role_lists(world, role, decision, allowed):
    buttons = [{"decision": d, "label": d} for d in ("keep", "undo", "fp")]
    review_id = world.put(buttons=buttons)
    response = _decide(world, role, review_id, decision)
    assert response.status_code == (200 if allowed else 403)
    assert len(world.fake.calls) == (1 if allowed else 0)


def test_a_role_not_allowed_the_decision_is_403_audited_and_changes_nothing(world):
    review_id = world.put()
    before = world.row(review_id)
    response = _decide(world, "tier1", review_id, "undo", note="x")
    assert response.status_code == 403
    assert response.json() == {"detail": "forbidden"}
    _untouched(world, review_id, before)
    assert (
        _decided(world, review_id) == []
    )  # a refusal of the role is `authz.denied`, not a decision
    [denied] = world.denied("tier1")
    assert denied["subject_id"] == _url(review_id)
    assert denied["payload"] == {"required": ["tier2", "admin"], "role": "tier1", "method": "POST"}


def test_the_role_lists_of_the_configuration_decide(world):
    world.cfg = replace(world.cfg, SOAR_ROLES_KEEP=["admin"], SOAR_ROLES_FP=["admin"])
    review_id = world.put()
    assert _decide(world, "tier2", review_id, "keep").status_code == 403
    assert _decide(world, "tier1", review_id, "keep").status_code == 403
    assert world.denied("tier2")[0]["payload"]["required"] == ["admin"]
    assert _decide(world, "admin", review_id, "keep").status_code == 200


def test_a_role_in_none_of_the_lists_is_403_before_the_body_is_even_read(world):
    review_id = world.put()
    before = world.row(review_id)
    for body in (b"not json", b"{}", json.dumps({"decision": "keep"}).encode()):
        response = world.post_decision(
            "viewer", review_id, body, headers={"content-type": "text/plain"}
        )
        assert response.status_code == 403
    _untouched(world, review_id, before)
    assert world.denied("tier1")[0]["payload"] == {
        "required": ["tier1", "tier2", "admin"],
        "role": "viewer",
        "method": "POST",
    }


def test_the_role_check_answers_before_the_json_type_and_the_ticket(world):
    unknown = "ZZZZZZZ9"
    assert world.post_decision("viewer", unknown, {"decision": "keep"}).status_code == 403
    response = world.post_decision("tier1", unknown, b"x", headers={"content-type": "text/plain"})
    assert response.status_code == 422  # signed in and allowed something: now the type


# ── the body ────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "content_type", ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data", ""]
)
def test_a_body_that_is_not_json_by_its_type_is_422_whatever_it_holds(world, content_type):
    review_id = world.put()
    before = world.row(review_id)
    headers = {"content-type": content_type} if content_type else {}
    response = world.post_decision("tier2", review_id, {"decision": "keep"}, headers=headers)
    assert response.status_code == 422
    assert response.json() == {"detail": {"field": "body", "reason": "invalid"}}
    _untouched(world, review_id, before)


@pytest.mark.parametrize(
    "content_type",
    ["application/json", "application/json; charset=utf-8", "application/merge-patch+json"],
)
def test_the_json_types_are_accepted(world, content_type):
    review_id = world.put()
    response = world.post_decision(
        "tier2", review_id, {"decision": "keep"}, headers={"content-type": content_type}
    )
    assert response.status_code == 200


@pytest.mark.parametrize(
    "body,fault",
    [
        (b"", {"field": "body", "reason": "invalid"}),
        (b"not json", {"field": "body", "reason": "invalid"}),
        (b"[]", {"field": "body", "reason": "invalid"}),
        (b'"keep"', {"field": "body", "reason": "invalid"}),
        (b"\xff", {"field": "body", "reason": "invalid"}),
        (b"{}", {"field": "decision", "reason": "required"}),
        (b'{"decision": null}', {"field": "decision", "reason": "required"}),
        (b'{"decision": "delete"}', {"field": "decision", "reason": "invalid"}),
        (b'{"decision": "KEEP"}', {"field": "decision", "reason": "invalid"}),
        (b'{"decision": ""}', {"field": "decision", "reason": "invalid"}),
        (b'{"decision": 5}', {"field": "decision", "reason": "invalid"}),
        (b'{"decision": ["keep"]}', {"field": "decision", "reason": "invalid"}),
        (b'{"decision": "kept"}', {"field": "decision", "reason": "invalid"}),
        (b'{"decision": "keep", "note": 5}', {"field": "note", "reason": "invalid"}),
        (b'{"decision": "keep", "note": {"a": 1}}', {"field": "note", "reason": "invalid"}),
        (b'{"decision": "keep", "note": "a\\u0000b"}', {"field": "note", "reason": "invalid"}),
        (
            json.dumps({"decision": "keep", "note": "x" * 501}).encode(),
            {"field": "note", "reason": "too_long"},
        ),
        (b'{"decision": "keep", "extra": 1}', {"field": "body", "reason": "invalid"}),
        (b'{"decision": "keep", "user": "admin"}', {"field": "body", "reason": "invalid"}),
    ],
    ids=lambda v: v[:30] if isinstance(v, bytes) else None,
)
def test_a_wrong_body_is_422_naming_the_field_and_changes_nothing(world, body, fault):
    review_id = world.put()
    before = world.row(review_id)
    response = world.post_decision("tier2", review_id, body)
    assert response.status_code == 422
    assert response.json() == {"detail": fault}
    _untouched(world, review_id, before)
    assert _decided(world, review_id) == []


def test_a_422_repeats_nothing_the_client_sent(world):
    hostile = "<script>alert(1)</script>"
    response = world.post_decision(
        "tier2", world.put(), {"decision": hostile, "note": hostile * 100}
    )
    assert response.status_code == 422
    assert "script" not in response.text


@pytest.mark.parametrize("note", [None, "", "gỡ vì máy in", "x" * 500])
def test_a_note_of_up_to_500_characters_or_none_is_accepted(world, note):
    review_id = world.put()
    body: dict[str, Any] = {"decision": "keep"}
    if note is not None:
        body["note"] = note
    assert world.post_decision("tier2", review_id, body).status_code == 200


# ── the ticket ──────────────────────────────────────────────────────────────────────────────


def test_an_unknown_id_is_404_and_writes_nothing(world):
    response = _decide(world, "tier2", "ZZZZZZZ9", "keep")
    assert response.status_code == 404
    assert response.json() == {"detail": "review not found"}
    assert world.fake.calls == []
    assert _decided(world, "ZZZZZZZ9") == []


@pytest.mark.parametrize("raw_id", ["a%00b", "%00", "a%1fb", "a%7fb"])
def test_an_id_with_a_control_character_is_404_not_a_500(world, raw_id):
    response = world.client("tier2").post(f"{REVIEWS}/{raw_id}/decision", json={"decision": "keep"})
    assert response.status_code == 404


@pytest.mark.parametrize(
    "fields,decision",
    [
        ({"status": "kept"}, "keep"),
        ({"status": "kept"}, "fp"),
        ({"status": "undone"}, "undo"),
        ({"status": "undone"}, "keep"),
        ({"status": "false_positive"}, "fp"),
        ({"status": "expired"}, "keep"),
        ({"status": "kept", "action_type": "kill_process", "buttons": KEEP_FP}, "undo"),
        (
            {"action_type": "kill_process", "buttons": KEEP_FP},
            "undo",
        ),  # open, but undo is not one of its buttons
        ({}, "fp"),  # open block_ip: keep and undo only
        ({"kind": "notice", "status": "info", "buttons": []}, "keep"),
        (
            {"kind": "notice", "status": "info", "buttons": [{"decision": "keep", "label": "x"}]},
            "keep",
        ),
        ({"buttons": []}, "keep"),
    ],
    ids=[
        "kept-keep",
        "kept-fp",
        "undone-undo",
        "undone-keep",
        "fp-fp",
        "expired-keep",
        "kept-kill-undo",
        "open-kill-undo",
        "open-ip-fp",
        "notice",
        "notice-with-buttons",
        "open-no-buttons",
    ],
)
def test_a_decision_that_does_not_fit_the_state_is_409_invalid_state(world, fields, decision):
    review_id = world.put(**fields)
    before = world.row(review_id)
    response = _decide(world, "admin", review_id, decision, note="ghi chú")
    assert response.status_code == 409
    detail = response.json()["detail"]
    assert list(detail) == ["reason", "review"]
    assert detail["reason"] == "invalid_state"
    review = detail["review"]
    assert review["id"] == review_id and review["status"] == before["status"]
    assert decision not in review["allowed_decisions"]
    assert world.row(review_id) == before and world.fake.calls == []
    [event] = _decided(world, review_id)
    assert event["payload"] == {
        "decision": decision,
        "note": "ghi chú",
        "outcome": "invalid_state",
        "status_before": before["status"],
        "status_after": before["status"],
        "message": None,
    }


def test_a_ticket_someone_holds_is_409_locked_and_shows_who(world):
    review_id = world.put_locked(by="alice", age_s=5, prev="open")
    before = world.row(review_id)
    response = _decide(world, "tier2", review_id, "keep")
    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["reason"] == "locked"
    assert detail["review"]["status"] == "processing" and detail["review"]["locked_by"] == "alice"
    assert detail["review"]["allowed_decisions"] == []
    assert world.row(review_id) == before and world.fake.calls == []
    [event] = _decided(world, review_id)
    assert event["payload"]["outcome"] == "locked"
    assert (event["payload"]["status_before"], event["payload"]["status_after"]) == (
        "processing",
        "processing",
    )


def test_a_409_carries_the_ticket_as_the_get_serves_it_for_this_caller(world):
    review_id = world.put(status="kept")
    detail = _decide(world, "tier1", review_id, "keep").json()["detail"]
    served = world.get("tier1", f"{REVIEWS}/{review_id}").json()
    assert detail["review"] == {k: served[k] for k in detail["review"]}
    assert list(detail["review"]) == [
        k for k in served if k not in ("raw", "history", "related_alerts", "related_total")
    ]


# ── not configured: 503 before anything is locked ───────────────────────────────────────────


@pytest.mark.parametrize("field", ["N8N_APPROVAL_URL", "N8N_APPROVAL_SECRET"])
def test_without_the_address_or_the_secret_the_route_is_503_before_it_locks_anything(world, field):
    world.cfg = replace(world.cfg, **{field: ""})
    review_id = world.put()
    before = world.row(review_id)
    response = _decide(world, "tier2", review_id, "keep")
    assert response.status_code == 503
    assert response.json() == {"detail": "soar approval not configured"}
    _untouched(world, review_id, before)
    assert _decided(world, review_id) == []


def test_a_ticket_that_is_closed_is_still_told_so_when_n8n_is_not_configured(world):
    world.cfg = replace(world.cfg, N8N_APPROVAL_SECRET="")
    review_id = world.put(status="expired")
    assert _decide(world, "tier2", review_id, "keep").status_code == 409


# ── the answers, one outcome at a time ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "fields,role,decision,status",
    [
        ({}, "tier1", "keep", "kept"),
        ({}, "tier2", "undo", "undone"),
        ({}, "admin", "keep", "kept"),
        ({"status": "kept"}, "tier2", "undo", "undone"),
        ({"action_type": "kill_process", "buttons": KEEP_FP}, "tier1", "fp", "false_positive"),
        ({"action_type": "kill_process", "buttons": KEEP_FP}, "tier2", "keep", "kept"),
        ({"action_type": "isolate_host", "host": "PC-17"}, "tier2", "undo", "undone"),
    ],
    ids=[
        "ip-keep",
        "ip-undo",
        "ip-keep-admin",
        "kept-undo",
        "kill-fp",
        "kill-keep",
        "isolate-undo",
    ],
)
def test_ok_n8n_did_it_the_ticket_takes_the_status_n8n_gave(world, fields, role, decision, status):
    review_id = world.put(**fields)
    world.fake = FakeN8n(Reply.ok(status, result="đã xử lý bởi n8n", message="Đã xử lý xong"))
    response = _decide(world, role, review_id, decision)
    assert response.status_code == 200
    body = response.json()
    assert list(body) == ["outcome", "message", "review"]
    assert body["outcome"] == "ok" and body["message"] == "Đã xử lý xong"
    user_id, username = world.users[role]
    row = world.row(review_id)
    assert row["status"] == status
    assert row["result"] == "đã xử lý bởi n8n"
    assert row["decided_by"] == username
    assert datetime.fromisoformat(row["decided_at"]) > datetime.now(UTC) - timedelta(seconds=60)
    assert row["last_error"] is None
    assert (row["locked_by"], row["locked_at"], row["prev_status"]) == (None, None, None)
    assert body["review"]["status"] == status and body["review"]["decided_by"] == username
    assert body["review"]["result"] == "đã xử lý bởi n8n"
    assert body["review"]["locked_by"] is None
    [event] = _decided(world, review_id)
    assert event["actor_role"] == ("admin" if role == "admin" else "analyst")
    assert event["actor_id"] == user_id
    assert event["payload"] == {
        "decision": decision,
        "note": None,
        "outcome": "ok",
        "status_before": fields.get("status", "open"),
        "status_after": status,
        "message": "Đã xử lý xong",
    }


def test_the_answers_ticket_is_the_row_as_it_now_is_with_the_callers_allowed_decisions(world):
    review_id = world.put()
    body = _decide(world, "tier2", review_id, "keep").json()
    assert body["review"]["status"] == "kept"
    assert body["review"]["allowed_decisions"] == ["undo"]  # kept: undo only
    served = world.get("tier2", f"{REVIEWS}/{review_id}").json()
    assert body["review"] == {k: served[k] for k in body["review"]}
    tier1 = _decide(world, "tier1", world.put(), "keep").json()
    assert tier1["review"]["allowed_decisions"] == []  # kept, and tier1 may not undo


def test_a_second_press_after_a_success_is_refused_as_invalid_state(world):
    review_id = world.put()
    assert _decide(world, "tier2", review_id, "keep").status_code == 200
    assert _decide(world, "tier2", review_id, "keep").status_code == 409
    assert _decide(world, "tier2", review_id, "undo").status_code == 200
    assert _decide(world, "tier2", review_id, "undo").status_code == 409
    assert len(world.fake.calls) == 2
    assert world.row(review_id)["status"] == "undone"


def test_what_n8n_is_asked(world):
    review_id = world.put()
    _decide(world, "tier2", review_id, "undo", note="  gỡ vì là máy in  ")
    [call] = world.fake.calls
    assert call.url == N8N_URL
    assert call.secret == SECRET
    assert call.content_type == "application/json"
    _, username = world.users["tier2"]
    assert {k: v for k, v in call.body.items() if k != "requested_at"} == {
        "source": "web",
        "review_id": review_id,
        "decision": "undo",
        "callback": f"undo:{review_id}",
        "user": username,
        "user_role": "tier2",
        "note": "  gỡ vì là máy in  ",
    }
    moment = datetime.fromisoformat(call.body["requested_at"])
    assert moment.utcoffset() == timedelta(0)
    assert call.timeout["read"] == 45.0  # N8N_APPROVAL_TIMEOUT_SECONDS


def test_the_configured_timeout_is_the_one_the_call_gets(world):
    world.cfg = replace(world.cfg, N8N_APPROVAL_TIMEOUT_SECONDS=20)
    _decide(world, "tier2", world.put(), "keep")
    assert world.fake.calls[0].timeout["read"] == 20.0


def test_the_note_goes_to_n8n_and_to_the_audit_event_and_is_empty_for_n8n_when_there_is_none(world):
    with_note, without = world.put(), world.put()
    _decide(world, "tier2", with_note, "keep", note="đã kiểm tra log")
    _decide(world, "tier2", without, "keep")
    assert world.fake.calls[0].body["note"] == "đã kiểm tra log"
    assert world.fake.calls[1].body["note"] == ""
    assert _decided(world, with_note)[0]["payload"]["note"] == "đã kiểm tra log"
    assert _decided(world, without)[0]["payload"]["note"] is None


def test_one_audit_event_per_press_that_reached_the_ticket(world):
    review_id = world.put()
    _decide(world, "tier1", review_id, "undo")  # 403: authz.denied, not a decision
    _decide(world, "tier2", review_id, "fp")  # 409 invalid_state
    _decide(world, "tier2", review_id, "keep")  # ok
    _decide(world, "tier2", review_id, "keep")  # 409 invalid_state
    outcomes = [e["payload"]["outcome"] for e in _decided(world, review_id)]
    assert outcomes == ["invalid_state", "ok", "invalid_state"]
    assert all(set(e["payload"]) == PAYLOAD_KEYS for e in _decided(world, review_id))


def test_the_history_serves_the_events_this_code_wrote_with_the_keys_of_the_spec(world):
    """The page reads `history[].payload` by the keys of spec §6, `actor` as the username (null for the system) and `actor_role`
    as `tier1|tier2|admin|system`. The events here are written by the real webhook code and the real route, then read back through
    the detail."""
    review_id = world.put()
    received = data.review(
        id=review_id, event="updated", sent_at=data.iso(data.T0 + timedelta(minutes=1))
    )
    with psycopg.connect(world.dsn) as conn:
        review_notice.apply(conn, review_notice.parse(json.dumps(received).encode()))
    assert _decide(world, "tier1", review_id, "keep", note="đã xem").status_code == 200
    assert _decide(world, "admin", review_id, "keep").status_code == 409
    assert _decide(world, "tier2", review_id, "undo", note="gỡ").status_code == 200
    history = world.get("tier1", f"{REVIEWS}/{review_id}").json()["history"]
    names = {role: world.users[role][1] for role in ("tier1", "tier2", "admin")}
    assert [(h["event"], h["actor"], h["actor_role"]) for h in history] == [
        ("soar.review_received", None, "system"),
        ("soar.review_decided", names["tier1"], "tier1"),
        ("soar.review_decided", names["admin"], "admin"),
        ("soar.review_decided", names["tier2"], "tier2"),
    ]
    assert set(history[0]["payload"]) == {"event", "kind", "outcome", "reason", "status", "sent_at"}
    assert history[0]["payload"]["outcome"] == "updated"
    for entry in history[1:]:
        assert set(entry["payload"]) == PAYLOAD_KEYS
    assert [h["payload"]["outcome"] for h in history[1:]] == ["ok", "invalid_state", "ok"]
    assert history[1]["payload"]["note"] == "đã xem" and history[3]["payload"]["note"] == "gỡ"
    assert [h["payload"]["status_after"] for h in history[1:]] == ["kept", "kept", "undone"]


# ── failed: n8n could not do it ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "fields,decision,back", [({}, "undo", "open"), ({"status": "kept"}, "undo", "kept")]
)
def test_failed_the_ticket_keeps_its_state_and_remembers_the_message(world, fields, decision, back):
    review_id = world.put(**fields, result="kết quả cũ")
    world.fake = FakeN8n(Reply.failed("GỠ THẤT BẠI: pfSense không trả lời", result="timeout"))
    response = _decide(world, "tier2", review_id, decision)
    assert response.status_code == 200
    body = response.json()
    assert body["outcome"] == "failed"
    assert body["message"] == "GỠ THẤT BẠI: pfSense không trả lời"
    row = world.row(review_id)
    assert row["status"] == back
    assert row["last_error"] == "GỠ THẤT BẠI: pfSense không trả lời"
    assert (row["decided_by"], row["decided_at"]) == (None, None)
    assert row["result"] == "kết quả cũ"  # a failed press changes no decision
    assert (row["locked_by"], row["locked_at"], row["prev_status"]) == (None, None, None)
    assert body["review"]["status"] == back and body["review"]["last_error"] == row["last_error"]
    assert decision in body["review"]["allowed_decisions"]  # and the buttons are there again
    [event] = _decided(world, review_id)
    assert event["payload"] == {
        "decision": decision,
        "note": None,
        "outcome": "failed",
        "status_before": back,
        "status_after": back,
        "message": "GỠ THẤT BẠI: pfSense không trả lời",
    }


def test_failed_without_a_message_falls_back_to_the_result_then_to_a_fixed_sentence(world):
    first, second = world.put(), world.put()
    world.fake = FakeN8n(Reply.json_body({"ok": False, "result": "pfsense: rule not found"}))
    body = _decide(world, "tier2", first, "undo").json()
    assert body["message"] == "pfsense: rule not found"
    assert world.row(first)["last_error"] == "pfsense: rule not found"
    world.fake = FakeN8n(Reply.json_body({"ok": False}))
    body = _decide(world, "tier2", second, "undo").json()
    assert body["outcome"] == "failed" and body["message"]
    assert world.row(second)["last_error"] == body["message"]


def test_a_later_success_clears_the_last_error(world):
    review_id = world.put()
    world.fake = FakeN8n(Reply.failed("lỗi"), Reply.ok("kept"))
    assert _decide(world, "tier2", review_id, "keep").json()["outcome"] == "failed"
    assert world.row(review_id)["last_error"] == "lỗi"
    assert _decide(world, "tier2", review_id, "keep").json()["outcome"] == "ok"
    row = world.row(review_id)
    assert row["last_error"] is None and row["status"] == "kept"


# ── unavailable: n8n could not be asked, or did not answer properly ─────────────────────────

UNAVAILABLE = [
    ("timeout", Reply.timeout()),
    ("network", Reply.network_error()),
    ("http", Reply.http(503)),
    ("http", Reply.http(401, b'{"ok": false}')),
    ("http", Reply.http(404)),
    ("bad_answer", Reply.text("<html>proxy error</html>")),
    ("bad_answer", Reply.json_body({"ok": True, "status": "open"})),
]


@pytest.mark.parametrize(
    "kind,reply", UNAVAILABLE, ids=[f"{k}-{r.status_code}" for k, r in UNAVAILABLE]
)
def test_unavailable_the_ticket_goes_back_and_says_what_kind_of_failure(world, kind, reply):
    review_id = world.put()
    world.fake = FakeN8n(reply)
    response = _decide(world, "tier2", review_id, "keep")
    assert response.status_code == 200
    body = response.json()
    assert body["outcome"] == "unavailable"
    assert body["message"] and body["message"].startswith(n8n_approval._UNAVAILABLE_TEXT[kind][:20])
    row = world.row(review_id)
    assert row["status"] == "open"
    assert row["last_error"] == body["message"]
    assert (row["decided_by"], row["locked_by"], row["locked_at"], row["prev_status"]) == (
        None,
    ) * 4
    assert body["review"]["status"] == "open" and body["review"]["allowed_decisions"] == [
        "keep",
        "undo",
    ]
    [event] = _decided(world, review_id)
    assert (
        event["payload"]["outcome"] == "unavailable" and event["payload"]["status_after"] == "open"
    )


def test_unavailable_the_person_may_press_again(world):
    review_id = world.put()
    world.fake = FakeN8n(Reply.timeout(), Reply.ok("kept"))
    assert _decide(world, "tier2", review_id, "keep").json()["outcome"] == "unavailable"
    assert _decide(world, "tier2", review_id, "keep").json()["outcome"] == "ok"
    assert len(world.fake.calls) == 2


# ── conflict: n8n says it was already handled ───────────────────────────────────────────────


@pytest.mark.parametrize("status", ["open", "kept", "undone", "false_positive", "expired"])
def test_conflict_the_status_n8n_gave_is_taken(world, status):
    review_id = world.put(result="kết quả cũ")
    world.fake = FakeN8n(Reply.conflict(status, "Phiếu đã được xử lý ở nơi khác"))
    response = _decide(world, "tier2", review_id, "keep")
    assert response.status_code == 200
    body = response.json()
    assert body["outcome"] == "conflict" and body["message"] == "Phiếu đã được xử lý ở nơi khác"
    row = world.row(review_id)
    assert row["status"] == status
    assert (row["decided_by"], row["decided_at"]) == (None, None)  # not this person's decision
    assert row["last_error"] is None
    assert row["result"] == "kết quả cũ"
    assert (row["locked_by"], row["locked_at"], row["prev_status"]) == (None, None, None)
    assert body["review"]["status"] == status
    [event] = _decided(world, review_id)
    assert event["payload"]["outcome"] == "conflict"
    assert (event["payload"]["status_before"], event["payload"]["status_after"]) == ("open", status)


@pytest.mark.parametrize("status", ["processing", "info", "weird", "", None])
def test_conflict_with_a_status_that_is_not_one_of_the_five_goes_back_to_the_previous_state(
    world, status
):
    review_id = world.put()
    body = {"ok": False, "message": "đã xử lý"}
    if status is not None:
        body["status"] = status
    world.fake = FakeN8n(Reply.json_body(body, 409))
    response = _decide(world, "tier2", review_id, "keep")
    assert response.json()["outcome"] == "conflict"
    assert world.row(review_id)["status"] == "open"
    assert world.row(review_id)["locked_by"] is None


def test_conflict_keeps_the_result_n8n_gave(world):
    review_id = world.put(result="cũ")
    world.fake = FakeN8n(
        Reply.json_body({"ok": False, "status": "kept", "result": "đã giữ", "message": "m"}, 409)
    )
    _decide(world, "tier2", review_id, "undo")
    assert world.row(review_id)["result"] == "đã giữ"


# ── the lock ────────────────────────────────────────────────────────────────────────────────


def test_the_lock_is_committed_and_no_transaction_is_open_while_n8n_is_being_asked(world):
    """The lock is visible to everyone, with who holds it and the state to go back to; and the request's connection is idle
    (not `idle in transaction`) during the call, so the call may be as long as it likes."""
    review_id = world.put()
    seen: list[dict[str, Any]] = []

    def during_the_call(call) -> None:
        row = world.row(review_id)
        idle = world.rows(
            "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
            "AND state LIKE 'idle in transaction%%' AND pid <> pg_backend_pid()"
        )[0][0]
        seen.append({"row": row, "idle_in_transaction": idle})

    world.fake.on_request = during_the_call
    assert _decide(world, "tier2", review_id, "keep").status_code == 200
    [during] = seen
    _, username = world.users["tier2"]
    assert during["row"]["status"] == "processing"
    assert (during["row"]["locked_by"], during["row"]["prev_status"]) == (username, "open")
    assert datetime.fromisoformat(during["row"]["locked_at"]) > datetime.now(UTC) - timedelta(
        seconds=60
    )
    assert during["idle_in_transaction"] == 0


def test_the_lock_is_one_statement_and_nothing_else_is_written_before_the_call(world, monkeypatch):
    """What reaches the database before n8n is asked: the read of the ticket and ONE `UPDATE` (the lock). The audit event and
    the finish come after the call."""
    seen: list[tuple[str, bool]] = (
        []
    )  # (first word of the statement, whether n8n had been asked by then)
    asked = threading.Event()

    class Spy(psycopg.Connection):
        def execute(self, query, params=None, **kwargs):
            seen.append((str(query).strip().split()[0].upper(), asked.is_set()))
            return super().execute(query, params, **kwargs)

    monkeypatch.setattr(
        "app.web.deps.db.connect", lambda *a, **k: Spy.connect(world.dsn, autocommit=False)
    )
    review_id = world.put()
    world.fake.on_request = lambda call: asked.set()
    assert _decide(world, "tier2", review_id, "keep").status_code == 200
    before = [word for word, after in seen if not after]
    after = [word for word, after in seen if after]
    assert before == ["SELECT", "UPDATE"], seen
    assert after == [
        "UPDATE",
        "SELECT",
        "INSERT",
    ], seen  # the compare-and-set, the ticket as it is, the audit event


def test_a_lock_older_than_two_minutes_is_released_by_the_next_press(world):
    review_id = world.put_locked(by="alice", age_s=200, prev="open")
    seen: list[dict[str, Any]] = []
    world.fake.on_request = lambda call: seen.append(world.row(review_id))
    response = _decide(world, "tier2", review_id, "keep")
    assert response.status_code == 200 and response.json()["outcome"] == "ok"
    [during] = seen
    # the new lock is the new person's, on the state the row had before the old lock: never `processing`
    assert during["locked_by"] == world.users["tier2"][1] and during["prev_status"] == "open"
    assert world.row(review_id)["status"] == "kept"
    [event] = _decided(world, review_id)
    assert event["payload"]["status_before"] == "open"


def test_a_stale_lock_on_a_kept_ticket_goes_back_to_kept_when_the_press_fails(world):
    review_id = world.put_locked(by="alice", age_s=200, prev="kept")
    world.fake = FakeN8n(Reply.timeout())
    body = _decide(world, "tier2", review_id, "undo").json()
    assert body["outcome"] == "unavailable"
    assert world.row(review_id)["status"] == "kept"


def test_a_lock_at_the_edge_is_still_held_and_one_past_it_is_released(world):
    held = world.put_locked(age_s=100)
    released = world.put_locked(age_s=125)
    assert _decide(world, "tier2", held, "keep").status_code == 409
    assert _decide(world, "tier2", released, "keep").status_code == 200


def test_a_press_that_loses_the_lock_race_is_409_and_the_other_changes_state_is_untouched(
    world, monkeypatch
):
    """The ticket changes between the look and the lock (the one statement's WHERE no longer matches): 409 with the ticket as
    it now is, nothing written by this press but its event, n8n not asked."""
    review_id = world.put()
    original = reviews._fetch_row
    changed = threading.Event()

    def fetch_then_change(conn, rid):
        row = original(conn, rid)
        if not changed.is_set():
            changed.set()
            world.execute("UPDATE soar_reviews SET status = 'kept' WHERE id = %s", (rid,))
        return row

    monkeypatch.setattr(reviews, "_fetch_row", fetch_then_change)
    response = _decide(world, "tier2", review_id, "keep")
    assert response.status_code == 409
    assert response.json()["detail"]["reason"] == "invalid_state"
    assert response.json()["detail"]["review"]["status"] == "kept"
    assert world.fake.calls == []
    assert world.row(review_id)["status"] == "kept"
    [event] = _decided(world, review_id)
    assert (event["payload"]["outcome"], event["payload"]["status_after"]) == (
        "invalid_state",
        "kept",
    )


# ── two presses at once: one call to n8n ────────────────────────────────────────────────────


def _press(
    world: World, role: str, review_id: str, decision: str = "keep"
) -> Callable[[], httpx.Response]:
    return lambda: _decide(world, role, review_id, decision)


def _together(calls: list[Callable[[], httpx.Response]]) -> list[httpx.Response]:
    barrier = threading.Barrier(len(calls))

    def run(call: Callable[[], httpx.Response]) -> httpx.Response:
        barrier.wait(timeout=10)
        return call()

    with ThreadPoolExecutor(max_workers=len(calls)) as pool:
        return list(pool.map(run, calls))


def test_a_second_press_while_the_first_is_in_flight_is_409_locked_and_n8n_is_called_once(world):
    review_id = world.put()
    world.fake = FakeN8n(hold=True)
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(_press(world, "tier2", review_id))
        assert world.fake.entered.wait(10), "the first press never reached n8n"
        second = _decide(world, "tier1", review_id, "keep")
        mid_flight = world.get("tier1", f"{REVIEWS}/{review_id}").json()
        world.fake.release()
        answer = first.result(timeout=20)
    assert second.status_code == 409
    assert second.json()["detail"]["reason"] == "locked"
    assert second.json()["detail"]["review"]["locked_by"] == world.users["tier2"][1]
    assert (mid_flight["status"], mid_flight["locked_by"]) == (
        "processing",
        world.users["tier2"][1],
    )
    assert answer.status_code == 200 and answer.json()["outcome"] == "ok"
    assert len(world.fake.calls) == 1
    assert world.row(review_id)["status"] == "kept"
    outcomes = sorted(e["payload"]["outcome"] for e in _decided(world, review_id))
    assert outcomes == ["locked", "ok"]


@pytest.mark.parametrize("round_", range(4))
def test_two_presses_at_the_same_instant_one_wins_and_n8n_is_called_once(world, round_):
    review_id = world.put()
    answers = _together([_press(world, "tier2", review_id), _press(world, "tier1", review_id)])
    assert sorted(a.status_code for a in answers) == [200, 409]
    loser = next(a for a in answers if a.status_code == 409)
    assert loser.json()["detail"]["reason"] in ("locked", "invalid_state")
    assert len(world.fake.calls) == 1
    assert world.row(review_id)["status"] == "kept"


def test_six_presses_at_once_one_call(world):
    review_id = world.put()
    answers = _together([_press(world, "tier2", review_id) for _ in range(6)])
    assert sorted(a.status_code for a in answers) == [200] + [409] * 5
    assert len(world.fake.calls) == 1
    assert len(_decided(world, review_id)) == 6


# ── the webhook wins the race ───────────────────────────────────────────────────────────────


def _webhook_update(world: World, review_id: str, **over: Any) -> None:
    """n8n's own `updated` push for `review_id`, applied the way the route does it, on a connection of its own."""
    body = data.review(
        id=review_id, event="updated", sent_at=data.iso(data.T0 + timedelta(minutes=5)), **over
    )
    with psycopg.connect(world.dsn) as conn:
        review_notice.apply(conn, review_notice.parse(json.dumps(body).encode()))


def test_n8ns_own_update_arriving_during_the_call_wins_and_the_press_writes_nothing(world):
    review_id = world.put()
    world.fake = FakeN8n(Reply.ok("undone"))
    world.fake.on_request = lambda call: _webhook_update(
        world, review_id, status="kept", decided_by="telegram:bob", result="giữ từ Telegram"
    )
    response = _decide(world, "tier2", review_id, "undo")
    assert response.status_code == 200
    body = response.json()
    assert body["outcome"] == "ok"  # what n8n answered to this press
    assert body["review"]["status"] == "kept"  # and the row as it now is
    row = world.row(review_id)
    assert row["status"] == "kept" and row["decided_by"] == "telegram:bob"
    assert row["result"] == "giữ từ Telegram"
    assert (row["locked_by"], row["locked_at"], row["prev_status"]) == (None, None, None)
    [event] = _decided(world, review_id)
    assert event["payload"]["outcome"] == "ok"
    assert (event["payload"]["status_before"], event["payload"]["status_after"]) == ("open", "kept")


def test_n8ns_next_push_does_not_erase_who_decided_when_it_carries_no_decision(world):
    """After a press, n8n's own `updated` push may not know who decided (decided_by, decided_at, result null): the web's record
    of the decision stays."""
    review_id = world.put()
    world.fake = FakeN8n(Reply.ok("kept", result="giữ chặn", message="ok"))
    assert _decide(world, "tier2", review_id, "keep").status_code == 200
    decided = world.row(review_id)
    _webhook_update(world, review_id, status="kept", decided_by=None, decided_at=None, result=None)
    row = world.row(review_id)
    assert row["decided_by"] == world.users["tier2"][1] == decided["decided_by"]
    assert row["result"] == "giữ chặn" and row["decided_at"] == decided["decided_at"]
    assert row["status"] == "kept"
    assert (
        row["last_sent_at"] != decided["last_sent_at"]
    )  # the push was applied: only the three fields are kept


OLD_UPDATED_AT = datetime(2026, 1, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    "reply,outcome",
    [
        (Reply.ok("kept"), "ok"),
        (Reply.failed("lỗi"), "failed"),
        (Reply.timeout(), "unavailable"),
        (Reply.conflict("undone"), "conflict"),
    ],
    ids=["ok", "failed", "unavailable", "conflict"],
)
def test_updated_at_moves_on_the_lock_and_again_on_each_kind_of_finish(world, reply, outcome):
    review_id = world.put()
    world.execute(
        "UPDATE soar_reviews SET updated_at = %s WHERE id = %s", (OLD_UPDATED_AT, review_id)
    )
    during: list[str] = []
    world.fake = FakeN8n(reply)
    world.fake.on_request = lambda call: during.append(world.row(review_id)["updated_at"])
    response = _decide(world, "tier2", review_id, "keep")
    assert response.json()["outcome"] == outcome
    locked = datetime.fromisoformat(during[0])
    finished = datetime.fromisoformat(world.row(review_id)["updated_at"])
    assert locked > OLD_UPDATED_AT + timedelta(days=100)  # the lock is a write of the row
    assert finished > locked  # and so is the finish
    assert response.json()["review"]["updated_at"] == finished.astimezone(UTC).isoformat()


def test_a_refused_press_does_not_touch_the_row_so_updated_at_stays(world):
    held = world.put_locked(by="alice", age_s=5)
    closed = world.put(status="expired")
    for review_id in (held, closed):
        world.execute(
            "UPDATE soar_reviews SET updated_at = %s WHERE id = %s", (OLD_UPDATED_AT, review_id)
        )
        assert _decide(world, "tier2", review_id, "keep").status_code == 409
        assert datetime.fromisoformat(world.row(review_id)["updated_at"]) == OLD_UPDATED_AT


@pytest.mark.parametrize(
    "reply",
    [Reply.failed("lỗi"), Reply.timeout(), Reply.conflict("undone")],
    ids=["failed", "timeout", "conflict"],
)
def test_the_same_race_when_n8n_then_says_failed_timeout_or_conflict(world, reply):
    review_id = world.put()
    world.fake = FakeN8n(reply)
    world.fake.on_request = lambda call: _webhook_update(world, review_id, status="expired")
    response = _decide(world, "tier2", review_id, "undo")
    assert response.status_code == 200
    row = world.row(review_id)
    assert (
        row["status"] == "expired"
    )  # the webhook's: the press does not put the old state back over it
    assert row["last_error"] is None
    assert response.json()["review"]["status"] == "expired"


# ── the call is made off the event loop ─────────────────────────────────────────────────────


def test_the_call_to_n8n_does_not_block_the_event_loop(world):
    """The route is a plain `def`, which FastAPI runs in a worker thread; the call to n8n (up to 100 s) must never stand on the
    loop (the S0 wedge of 27/10). While n8n is being waited for, a ticker on the same loop is never late, and another request is
    answered at once."""
    review_id = world.put()
    world.fake = FakeN8n(hold=True)
    world.client("tier2")  # wires the overrides
    threading.Timer(0.8, world.fake.release).start()

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

        transport = httpx.ASGITransport(app=main.app)
        headers = {"x-test-role": "tier2", **JSON}
        async with httpx.AsyncClient(
            transport=transport, base_url="http://app", headers=headers
        ) as client:
            tick = asyncio.create_task(ticker())
            slow = asyncio.create_task(client.post(_url(review_id), json={"decision": "keep"}))
            await asyncio.sleep(0.3)  # n8n is being waited for now
            quick = await client.get(f"{REVIEWS}/count")
            answered = await slow
            stop.set()
            await tick
        return answered, quick, max(gaps)

    answered, quick, worst_gap = asyncio.run(scenario())
    assert worst_gap < 0.4, f"the event loop stood still for {worst_gap:.2f} s"
    assert quick.status_code == 200
    assert answered.status_code == 200 and answered.json()["outcome"] == "ok"


# ── what n8n says is data ───────────────────────────────────────────────────────────────────


def test_n8ns_texts_are_stored_and_served_as_text_and_cut_at_2000_characters(world):
    hostile = "<img src=x onerror=alert(1)> '; DROP TABLE soar_reviews;-- %s ${x} " + "x" * 3000
    review_id = world.put()
    world.fake = FakeN8n(Reply.json_body({"ok": False, "message": hostile, "result": hostile}))
    body = _decide(world, "tier2", review_id, "undo").json()
    assert body["message"] == hostile[:2000]
    assert body["review"]["last_error"] == hostile[:2000]
    assert world.row(review_id)["last_error"] == hostile[:2000]
    assert world.rows("SELECT count(*) FROM soar_reviews WHERE id = %s", (review_id,))[0][0] == 1


# ── nothing secret ──────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "reply",
    [
        Reply.ok("kept"),
        Reply.failed("x"),
        Reply.conflict(),
        Reply.http(500, SECRET.encode()),
        Reply.network_error(f"refused {SECRET}"),
        Reply.timeout(),
    ],
    ids=["ok", "failed", "conflict", "500", "network", "timeout"],
)
def test_the_secret_is_in_no_answer_no_event_no_row_and_no_log_line(world, caplog, reply):
    caplog.set_level(logging.DEBUG)
    review_id = world.put()
    world.fake = FakeN8n(reply)
    response = _decide(world, "tier2", review_id, "keep")
    everything = [
        response.text,
        json.dumps(world.row(review_id)),
        json.dumps(_decided(world, review_id)),
        "\n".join(f"{r.name} {r.getMessage()}" for r in caplog.records),
    ]
    for text in everything:
        assert SECRET not in text
    assert world.fake.secrets_seen == [SECRET]  # n8n alone got it, in the header
