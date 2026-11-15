"""P11-T20 part 4, finding I1 (whole-branch review) — the blind arm on the admin console.

Context pack §6.4: the suggestion of ① is removed from ANY response, for every role, while
`suggestion_visible = false` and the alert is not yet decided. `tier1/visibility.py` holds the
rule (`SHOW_STATES`, `ANALYST_HIDE`) and applies it to the queue and the alert page; two admin
reads carried ① around it, and this module holds both to it, through the real routes:

- `GET /api/admin/audit`: the rows of `triage.suggested`, `llm.gate_forced` and
  `llm.builder_violation` about a blind, undecided alert are left out of the page and of its
  total (DEC-206 as amended, round 2 N1: the gate only forces `needs_review`, so the bare
  presence of a `llm.gate_forced` row tells the verdict, and a `llm.builder_violation` row tells
  that ① produced none); a person's `autoclose.reviewed` stays listed with its suggestion keys
  masked;
- `GET /api/admin/llm/usage`: `recent[].outcome` and `recent[].subject_id` of a run on an alert.

For each, the four heads the review names: a blind undecided one (hidden), a blind decided one
(shown), a visible one (shown) and a reopened blind one (hidden); and then every `(status,
suggestion_visible)` pair against `visibility.strip` itself, so the routes cannot drift into a
second rule. The audit adds paging: rows are dropped before the `LIMIT`, so pages stay full and
the cursor chain whole. The database is a scratch one (`tests/scratch_db.py`); each test rolls
back.
"""

from __future__ import annotations

import dataclasses
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import psycopg
import pytest
from app.domain import transitions
from app.infra import config
from app.infra.auth import Claims
from app.tier1 import visibility
from app.web import deps, main
from app.web.routers import admin_audit, admin_llm
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from tests.scratch_db import insert_alert, scratch_database

AUDIT = "/api/admin/audit"
USAGE = "/api/admin/llm/usage"
HIDDEN = "[đã ẩn]"
_CFG = dataclasses.replace(config.Config(), LLM_MONTHLY_USD_CAP=30, LLM_TIMEOUT_S=120)

#: Every value `alerts.status` can hold (`ck_alerts_status`).
ALL_STATUSES = (
    "received",
    "duplicate",
    "auto_closed",
    "enriching",
    "queued_tier1",
    "tier1_active",
    "escalated_tier2",
    "closed_fp",
    "closed_benign",
    "closed_confirmed",
)

# What the writers put there (`tier1/triage.py:957-980` and `:812`, `tier1/digest.py` review).
# DEC-217: `triage.suggested` keeps `forced` (always false for a new run) and gains `flagged_by`, the steps whose
# check raised a warning; the blind arm must not see either, or which checks fired tells what ① concluded.
RUN_ID = "5d1f0c2e-8f7b-4c43-9f43-0d2b0d1e9a11"
SUGGESTED = {
    "suggested_action": "true_positive",
    "confidence": "high",
    "forced": False,
    "flagged_by": ["step4"],
    "run_id": RUN_ID,
}
#: `llm.gate_forced` is no longer written (nothing is forced); the rows of old runs are still there.
GATE_FORCED = {
    "proposed": "false_positive",
    "final": "needs_review",
    "forced_by": ["step4"],
    "missing": ["asset_context"],
}
REVIEWED = {
    "verdict": "wrong",
    "autoclose_rule_id": "rule-7",
    "suggested_action": "true_positive",
    "run_id": RUN_ID,
}
BUILDER = {"violations_count": 2}
#: The events left out of the audit while their alert is blind and undecided (DEC-206, amended).
OMITTED = ("triage.suggested", "llm.gate_forced", "llm.builder_violation")
PAYLOADS = {
    "triage.suggested": SUGGESTED,
    "llm.gate_forced": GATE_FORCED,
    "autoclose.reviewed": REVIEWED,
    "llm.builder_violation": BUILDER,
}
#: The keys of each payload that are the suggestion, masked when the alert is told to be blind.
MASK_KEYS = {
    "triage.suggested": set(SUGGESTED),
    "llm.gate_forced": set(GATE_FORCED),
    "autoclose.reviewed": {"suggested_action", "run_id"},
}


# ---------------------------------------------------------------------------
# The scratch database, the client and the factories
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def scratch_dsn():
    with scratch_database("blind_arm") as dsn:
        yield dsn


@pytest.fixture
def sdb(scratch_dsn):
    conn = psycopg.connect(scratch_dsn)
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


def _user(conn: psycopg.Connection, username: str, role: str) -> str:
    (user_id,) = conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash)"
        " VALUES (gen_random_uuid(), %s, 'p11t20', %s, 'not-a-real-hash') RETURNING user_id",
        (username, role),
    ).fetchone()
    return str(user_id)


@pytest.fixture
def client(sdb):
    """`(TestClient, connection)`; the caller is an admin, as both of the pilot's analysts are."""
    admin_id = _user(sdb, "p11t20-admin", "admin")
    claims = Claims(user_id=admin_id, username="p11t20-admin", role="admin", iat=0.0, exp=0.0)
    main.app.dependency_overrides[deps.get_conn] = lambda: sdb
    main.app.dependency_overrides[deps.get_config] = lambda: _CFG
    main.app.dependency_overrides[deps.current_user] = lambda: claims
    try:
        yield TestClient(main.app), sdb
    finally:
        for dep in (deps.get_conn, deps.get_config, deps.current_user):
            main.app.dependency_overrides.pop(dep, None)


def _alert(conn: psycopg.Connection, alert_id: str, *, status: str, visible: bool) -> None:
    """One alert in `status`, with the columns that status's CHECKs want."""
    insert_alert(conn, alert_id, suggestion_visible=visible)
    if status == "received":
        return
    sets, params = "status = %s", [status]
    if status in {"duplicate", "auto_closed", "closed_fp", "closed_benign", "closed_confirmed"}:
        sets += ", closed_at = now()"
    if status in {"duplicate", "closed_fp", "closed_benign", "closed_confirmed"}:
        sets += ", sealed_at = now()"
    if status == "duplicate":
        parent = f"{alert_id}.parent"
        insert_alert(conn, parent)
        sets += ", duplicate_of = %s"
        params.append(parent)
    conn.execute(f"UPDATE alerts SET {sets} WHERE alert_id = %s", [*params, alert_id])


def _event(conn: psycopg.Connection, event_type: str, subject: str, payload: Any) -> int:
    (audit_id,) = conn.execute(
        "INSERT INTO audit_events (event_type, subject_id, actor_role, payload)"
        " VALUES (%s, %s, 'system', %s) RETURNING audit_id",
        (event_type, subject, Jsonb(payload)),
    ).fetchone()
    return audit_id


def _suggestion_events(conn: psycopg.Connection, alert_id: str) -> dict[str, int]:
    """One event of each of the four types the route treats, on `alert_id`; `{type: audit_id}`."""
    return {kind: _event(conn, kind, alert_id, payload) for kind, payload in PAYLOADS.items()}


def _audit(tc: TestClient, subject: str) -> dict[str, dict[str, Any]]:
    """`{event_type: event}` of one subject through the real route, the whole default window."""
    resp = tc.get(AUDIT, params={"subject": subject})
    assert resp.status_code == 200, resp.text
    events = resp.json()["events"]
    assert len({e["event_type"] for e in events}) == len(events), "one event per type here"
    return {e["event_type"]: e for e in events}


def _aid() -> str:
    return f"{uuid.uuid4().int % 10**10}.{uuid.uuid4().int % 10**6}"


def _expect_masked(event: dict[str, Any], kind: str = "autoclose.reviewed") -> None:
    """The event is listed, its suggestion keys are the marker, and nothing else changed."""
    payload = event["payload"]
    assert isinstance(payload, dict), payload
    for key in MASK_KEYS[kind]:
        assert payload[key] == HIDDEN, (kind, key, payload)
    for key, value in PAYLOADS[kind].items():
        if key not in MASK_KEYS[kind]:
            assert payload[key] == value, (kind, key, payload)
    assert set(payload) == set(PAYLOADS[kind])  # same keys, only their values are gone
    text = json.dumps(event)
    for secret in ("true_positive", "false_positive", "needs_review", RUN_ID, "high"):
        assert secret not in text, (kind, secret)


def _expect_shown(event: dict[str, Any], kind: str) -> None:
    assert event["payload"] == PAYLOADS[kind], kind


# ---------------------------------------------------------------------------
# The audit route
# ---------------------------------------------------------------------------


def _body(tc: TestClient, **params: Any) -> dict[str, Any]:
    resp = tc.get(AUDIT, params=params)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _types_of(body: dict[str, Any], alert: str) -> list[str]:
    return [e["event_type"] for e in body["events"] if e["subject_id"] == alert]


@pytest.mark.db
def test_audit_leaves_out_the_events_of_a_blind_undecided_head_and_masks_the_review(client) -> None:
    """DEC-206 as amended: the bare presence of `llm.gate_forced` (the gate only forces
    `needs_review`) or `llm.builder_violation` (① produced none) under a blind, undecided
    alert tells the verdict, so those rows, and `triage.suggested`, are not listed at all. A
    person's `autoclose.reviewed` is listed with its suggestion keys masked."""
    tc, db = client
    alert = _aid()
    _alert(db, alert, status="queued_tier1", visible=False)
    ids = _suggestion_events(db, alert)

    events = _audit(tc, alert)

    assert set(events) == {"autoclose.reviewed"}
    assert events["autoclose.reviewed"]["audit_id"] == ids["autoclose.reviewed"]
    assert events["autoclose.reviewed"]["subject_id"] == alert
    _expect_masked(events["autoclose.reviewed"])
    # and from every other way of asking: the default view, the group, the total
    default = _body(tc, limit=100)
    assert _types_of(default, alert) == ["autoclose.reviewed"]
    assert default["total"] == 1
    model = _body(tc, group="model", limit=100)
    assert model["events"] == [] and model["total"] == 0
    both = _body(tc, group="model", subject=alert)
    assert both["events"] == [] and both["total"] == 0
    only = _body(tc, subject=alert)
    assert [e["event_type"] for e in only["events"]] == ["autoclose.reviewed"]
    assert only["total"] == 1
    listed = [e["audit_id"] for e in default["events"]]
    for kind in OMITTED:
        assert ids[kind] not in listed, kind


@pytest.mark.db
@pytest.mark.parametrize("status", sorted(visibility.SHOW_STATES))
def test_audit_lists_the_events_of_a_blind_decided_head_in_full(client, status: str) -> None:
    """They come back once the alert is decided."""
    tc, db = client
    alert = _aid()
    _alert(db, alert, status=status, visible=False)
    _suggestion_events(db, alert)
    events = _audit(tc, alert)
    assert set(events) == set(PAYLOADS)
    for kind, event in events.items():
        _expect_shown(event, kind)
    assert _body(tc, subject=alert)["total"] == len(PAYLOADS)
    assert _body(tc, group="model", subject=alert)["total"] == 3  # gate, suggested, violation


@pytest.mark.db
@pytest.mark.parametrize("status", ["queued_tier1", "tier1_active", "enriching", "received"])
def test_audit_lists_the_events_of_a_visible_head_in_full(client, status: str) -> None:
    tc, db = client
    alert = _aid()
    _alert(db, alert, status=status, visible=True)
    _suggestion_events(db, alert)
    events = _audit(tc, alert)
    assert set(events) == set(PAYLOADS)
    for kind, event in events.items():
        _expect_shown(event, kind)


@pytest.mark.db
def test_audit_leaves_the_events_out_again_when_a_blind_head_is_reopened(client) -> None:
    """A17: `auto_closed` (decided, so ① is shown) -> `queued_tier1` (undecided, blind again):
    the events go; decided again, they come back."""
    tc, db = client
    alert = _aid()
    analyst = _user(db, "p11t20-analyst", "tier1")
    _alert(db, alert, status="auto_closed", visible=False)
    _suggestion_events(db, alert)
    shown = _audit(tc, alert)
    assert set(shown) == set(PAYLOADS)  # while it is auto-closed the suggestion is shown
    for kind, event in shown.items():
        _expect_shown(event, kind)

    transitions.reopen(db, alert, analyst, reason="the digest said wrong")

    events = _audit(tc, alert)
    assert set(events) == {"autoclose.reviewed", "alert.reopened"}
    _expect_masked(events["autoclose.reviewed"])
    assert _body(tc, subject=alert)["total"] == 2
    assert _body(tc, group="model", subject=alert)["total"] == 0

    db.execute(
        "UPDATE alerts SET status = 'closed_fp', closed_at = now(), sealed_at = now()"
        " WHERE alert_id = %s",
        (alert,),
    )
    again = _audit(tc, alert)
    assert set(again) == set(PAYLOADS) | {"alert.reopened"}
    for kind in PAYLOADS:
        _expect_shown(again[kind], kind)


@pytest.mark.db
def test_audit_a_visible_head_stays_listed_after_a_reopen(client) -> None:
    tc, db = client
    alert = _aid()
    analyst = _user(db, "p11t20-analyst", "tier1")
    _alert(db, alert, status="auto_closed", visible=True)
    _suggestion_events(db, alert)
    transitions.reopen(db, alert, analyst, reason="x")
    events = _audit(tc, alert)
    assert set(events) == set(PAYLOADS) | {"alert.reopened"}
    for kind in PAYLOADS:
        _expect_shown(events[kind], kind)


@pytest.mark.db
def test_audit_follows_visibility_strip_for_every_status_and_arm(client) -> None:
    """The routes hold no rule of their own: for each `(status, suggestion_visible)` pair the
    events are listed in full exactly when `visibility.strip` (analyst mode) returns a dict whole,
    and left out exactly when it takes the `ANALYST_HIDE` keys off it."""
    tc, db = client
    probe = {key: "x" for key in visibility.ANALYST_HIDE}
    seen = set()
    for status in ALL_STATUSES:
        for visible in (True, False):
            alert = _aid()
            _alert(db, alert, status=status, visible=visible)
            for kind in OMITTED:
                _event(db, kind, alert, PAYLOADS[kind])
            stripped = visibility.strip(
                probe, status=status, suggestion_visible=visible, mode="analyst"
            )
            hides = stripped != probe
            seen.add(hides)
            events = _audit(tc, alert)
            assert (set(events) == set(OMITTED)) is (not hides), (status, visible, set(events))
            assert (events == {}) is hides, (status, visible)
            for kind, event in events.items():
                _expect_shown(event, kind)
    assert seen == {True, False}  # the sweep covered both outcomes


@pytest.mark.db
def test_audit_leaves_every_other_event_type_of_a_blind_head_alone(client) -> None:
    tc, db = client
    alert = _aid()
    _alert(db, alert, status="queued_tier1", visible=False)
    kept = {
        "alert.received": {"note": "x"},
        "alert.enriched": {"risk_score": 61},
        "case.analyzed": {"suggested_conclusion": "need_more_data", "job_id": 4},
    }
    for kind, payload in kept.items():
        _event(db, kind, alert, payload)
    _event(db, "llm.builder_violation", alert, BUILDER)
    events = _audit(tc, alert)
    assert set(events) == set(kept)  # the violation is the one that is not there
    for kind, payload in kept.items():
        assert events[kind]["payload"] == payload, kind


@pytest.mark.db
def test_audit_an_event_whose_subject_is_no_alert_is_listed(client) -> None:
    """Nothing says a subject is blind when there is no alert row to say it."""
    tc, db = client
    subject = f"no-such-alert-{uuid.uuid4().hex[:8]}"
    for kind in OMITTED:
        _event(db, kind, subject, PAYLOADS[kind])
    events = _audit(tc, subject)
    assert set(events) == set(OMITTED)
    for kind, event in events.items():
        _expect_shown(event, kind)


@pytest.mark.db
def test_audit_leaves_a_blind_head_out_of_a_page_of_mixed_subjects_and_of_its_total(
    client,
) -> None:
    """Each row follows its OWN alert: one page, three heads, and the total counts two."""
    tc, db = client
    heads = {
        "blind": ("queued_tier1", False),
        "decided": ("closed_fp", False),
        "visible": ("queued_tier1", True),
    }
    ids = {}
    for name, (status, visible) in heads.items():
        ids[name] = _aid()
        _alert(db, ids[name], status=status, visible=visible)
        _event(db, "triage.suggested", ids[name], SUGGESTED)
    body = _body(tc, group="model", limit=100)
    by_subject = {e["subject_id"]: e["payload"] for e in body["events"]}
    assert set(by_subject) == {ids["decided"], ids["visible"]}
    assert by_subject[ids["decided"]] == SUGGESTED
    assert by_subject[ids["visible"]] == SUGGESTED
    assert body["total"] == 2 and body["next_cursor"] is None


def _seed_run(db: psycopg.Connection, pattern: str) -> list[str]:
    """One alert and one `triage.suggested` event each, oldest first: `V` visible, `B` blind and
    undecided. Returns the alert ids, in the same order."""
    ids = []
    for letter in pattern:
        alert = _aid()
        _alert(db, alert, status="queued_tier1", visible=letter == "V")
        _event(db, "triage.suggested", alert, SUGGESTED)
        ids.append(alert)
    return ids


def _chain(tc: TestClient, limit: int, **params: Any) -> tuple[list[list[str]], list[int | None]]:
    """The subjects of each page, newest first, following `next_cursor` to the end; and the
    `total` each page answered."""
    pages, totals, cursor = [], [], None
    for _ in range(50):
        query = {**params, "limit": limit, **({} if cursor is None else {"cursor": cursor})}
        body = _body(tc, **query)
        pages.append([e["subject_id"] for e in body["events"]])
        totals.append(body["total"])
        cursor = body["next_cursor"]
        if cursor is None:
            return pages, totals
    raise AssertionError("the cursor chain does not end")


@pytest.mark.db
def test_audit_pages_are_full_when_a_run_of_dropped_rows_sits_at_a_page_boundary(client) -> None:
    """The join is inside the page selection: rows are dropped BEFORE the `LIMIT`, so a page is
    never short because blind rows were taken out of it afterwards. Oldest first: 5 visible, 10
    blind, 5 visible; at limit 5 the second page is the five older visible rows, not an empty
    page and not a short one."""
    tc, db = client
    ids = _seed_run(db, "V" * 5 + "B" * 10 + "V" * 5)
    visible_newest_first = [ids[i] for i in reversed(range(20)) if i < 5 or i >= 15]

    pages, totals = _chain(tc, 5, group="model")

    assert [len(p) for p in pages] == [5, 5, 0]  # the last page is the empty one a full page owes
    assert [s for page in pages for s in page] == visible_newest_first
    assert totals == [10, 10, 10]


@pytest.mark.db
@pytest.mark.parametrize("limit", [1, 3, 4, 7])
def test_audit_a_cursor_chain_over_a_mix_lists_each_visible_row_once_in_full_pages(
    client, limit: int
) -> None:
    tc, db = client
    pattern = "VBVVBBBVBVVVBBVBVV"
    ids = _seed_run(db, pattern)
    expected = [alert for alert, letter in zip(ids, pattern, strict=True) if letter == "V"][::-1]

    pages, totals = _chain(tc, limit, group="model")

    flat = [s for page in pages for s in page]
    assert flat == expected  # every visible row once, newest first, no blind one
    assert all(len(page) == limit for page in pages[:-1]), [len(p) for p in pages]
    assert len(pages[-1]) <= limit
    assert set(totals) == {len(expected)}


@pytest.mark.db
def test_audit_the_two_spellings_of_the_omission_count_the_same_rows(client) -> None:
    """The page tests the alert with a scalar subquery, the total with an anti join (measured:
    the anti join is the cheap one for a count). One predicate, two spellings: over a mix of
    blind, visible, decided and unknown alerts, with every type, both count the rows the page
    lists, and each equals what the route's own cursor chain lists."""
    tc, db = client
    for i, (status, visible) in enumerate(
        [
            ("queued_tier1", False),
            ("closed_fp", False),
            ("queued_tier1", True),
            ("auto_closed", False),
        ]
    ):
        alert = _aid()
        _alert(db, alert, status=status, visible=visible)
        for kind in (*OMITTED, "autoclose.reviewed", "alert.received"):
            _event(db, kind, alert, PAYLOADS.get(kind, {"i": i}))
    for kind in OMITTED:
        _event(db, kind, "no-such-alert", PAYLOADS[kind])  # no `alerts` row: listed
    clauses, params = admin_audit._filters(admin_audit._WINDOWS["7d"], None, None, None)
    scalar = admin_audit._where(clauses)
    anti = admin_audit._where(
        [admin_audit._BLIND_OMIT_COUNT if c is admin_audit._BLIND_OMIT else c for c in clauses]
    )
    counts = [
        db.execute(admin_audit._COUNT.format(where=where), params).fetchone()[0]
        for where in (scalar, anti)
    ]
    listed = sum(len(page) for page in _chain(tc, 7)[0])
    assert counts[0] == counts[1] == listed == _body(tc)["total"]
    # 4 alerts x 5 types, minus the 3 omitted types of the blind undecided one, plus the 3 of no alert
    assert listed == 4 * 5 - 3 + 3


@pytest.mark.db
def test_audit_the_default_view_lists_no_blind_row_either(client) -> None:
    """No `?group` and no `?subject`: the page the audit opens on."""
    tc, db = client
    ids = _seed_run(db, "BVBV")
    pages, totals = _chain(tc, 100)
    assert pages == [[ids[3], ids[1]]]
    assert totals == [2]


@pytest.mark.db
def test_audit_masks_a_null_value_under_a_suggestion_key_of_a_listed_review(client) -> None:
    """The rule is on the key, not the value."""
    tc, db = client
    alert = _aid()
    _alert(db, alert, status="queued_tier1", visible=False)
    _event(db, "autoclose.reviewed", alert, {"verdict": "wrong", "suggested_action": None})
    payload = _audit(tc, alert)["autoclose.reviewed"]["payload"]
    assert payload == {"verdict": "wrong", "suggested_action": HIDDEN}


@pytest.mark.db
def test_audit_masks_a_suggestion_key_at_any_depth_of_a_listed_review(client) -> None:
    tc, db = client
    alert = _aid()
    _alert(db, alert, status="queued_tier1", visible=False)
    _event(db, "autoclose.reviewed", alert, {"wrapped": [{"suggested_action": "true_positive"}]})
    payload = _audit(tc, alert)["autoclose.reviewed"]["payload"]
    assert payload == {"wrapped": [{"suggested_action": HIDDEN}]}


@pytest.mark.db
def test_audit_still_cuts_an_oversize_payload_of_a_listed_review(client) -> None:
    tc, db = client
    alert = _aid()
    _alert(db, alert, status="queued_tier1", visible=False)
    _event(
        db,
        "autoclose.reviewed",
        alert,
        {**REVIEWED, "pad": "x" * (admin_audit.PAYLOAD_MAX_BYTES + 10)},
    )
    payload = _audit(tc, alert)["autoclose.reviewed"]["payload"]
    assert payload["truncated"] is True and "true_positive" not in json.dumps(payload)


@pytest.mark.parametrize("kind", ["triage.suggested", "llm.gate_forced", "autoclose.reviewed"])
def test_the_payload_function_masks_a_suggestion_when_told_the_alert_is_blind(kind: str) -> None:
    """Defence in depth: the three events whose payload carries a suggestion are masked by
    `_payload(..., blind=True)` whatever the page query did, and shown whole when not told."""
    text = json.dumps(PAYLOADS[kind])
    masked = admin_audit._payload(text, len(text), kind, blind=True)
    assert set(masked) == set(PAYLOADS[kind])
    for key in MASK_KEYS[kind]:
        assert masked[key] == HIDDEN, (kind, key)
    assert admin_audit._payload(text, len(text), kind) == PAYLOADS[kind]


def test_audit_the_suggestion_keys_are_the_visibility_keys_and_the_events_own() -> None:
    """`ANALYST_HIDE` (normalised) is inside what the route masks, so a key `visibility` adds
    is masked here with no second edit; the events' own keys are the ones `triage.py` writes."""
    assert {admin_audit.normalise_key(k) for k in visibility.ANALYST_HIDE} <= set(
        admin_audit.SUGGESTION_HIDE
    )
    for key in ("forced", "flagged_by", "proposed", "final", "forced_by", "missing"):
        assert admin_audit.normalise_key(key) in admin_audit.SUGGESTION_HIDE, key
    assert admin_audit.SUGGESTION_EVENT_TYPES == {
        "triage.suggested",
        "llm.gate_forced",
        "autoclose.reviewed",
    }


def test_audit_the_events_left_out_are_the_three_of_dec_206() -> None:
    assert admin_audit.BLIND_OMITTED_EVENT_TYPES == frozenset(OMITTED)
    assert set(OMITTED) <= {
        name for names in admin_audit.GROUPS.values() for name in names
    }  # each one is a listed event
    assert "autoclose.reviewed" not in admin_audit.BLIND_OMITTED_EVENT_TYPES  # a person's event


# ---------------------------------------------------------------------------
# The LLM usage route: `recent`
# ---------------------------------------------------------------------------


def _run(
    conn: psycopg.Connection,
    subject_id: str,
    *,
    pipeline: str = "triage",
    role: str = "proposer",
    result: Any = None,
    stopped_by: str | None = None,
    created_at: datetime | None = None,
) -> str:
    """One `llm_runs` row on `subject_id` (`llm_runs` is append-only: the result goes in whole)."""
    run_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, role, system_prompt,"
        " user_message, result, stopped_by, created_at)"
        " VALUES (%s, %s, %s, %s, %s, 's', 'u', %s, %s, COALESCE(%s, now()))",
        (
            run_id,
            pipeline,
            "alert" if pipeline == "triage" else "case",
            subject_id,
            role,
            Jsonb(result) if result is not None else None,
            stopped_by,
            created_at,
        ),
    )
    return run_id


def _recent(tc: TestClient) -> dict[str, dict[str, Any]]:
    resp = tc.get(USAGE)
    assert resp.status_code == 200, resp.text
    return {row["run_id"]: row for row in resp.json()["recent"]}


PROPOSED = {"suggested_action": "true_positive"}


@pytest.mark.db
def test_usage_hides_outcome_and_subject_of_a_run_on_a_blind_undecided_head(client) -> None:
    tc, db = client
    alert = _aid()
    _alert(db, alert, status="queued_tier1", visible=False)
    proposer = _run(db, alert, result=PROPOSED)
    verifier = _run(
        db,
        alert,
        role="verifier",
        result={"agree": False, "structured_only_verdict": "true_positive"},
    )
    stopped = _run(db, alert, stopped_by="cap")
    recent = _recent(tc)
    for run_id in (proposer, verifier, stopped):
        row = recent[run_id]  # the run stays listed
        assert row["outcome"] is None and row["subject_id"] is None, row
        assert row["subject_type"] == "alert" and row["pipeline"] == "triage"
    assert alert not in json.dumps(recent) and "true_positive" not in json.dumps(recent)


@pytest.mark.db
@pytest.mark.parametrize("status", sorted(visibility.SHOW_STATES))
def test_usage_shows_a_run_on_a_blind_decided_head(client, status: str) -> None:
    tc, db = client
    alert = _aid()
    _alert(db, alert, status=status, visible=False)
    run = _run(db, alert, result=PROPOSED)
    row = _recent(tc)[run]
    assert row["outcome"] == "true_positive" and row["subject_id"] == alert


@pytest.mark.db
def test_usage_shows_a_run_on_a_visible_head(client) -> None:
    tc, db = client
    alert = _aid()
    _alert(db, alert, status="queued_tier1", visible=True)
    run = _run(db, alert, result=PROPOSED)
    stopped = _run(db, alert, stopped_by="schema")
    recent = _recent(tc)
    assert recent[run]["outcome"] == "true_positive" and recent[run]["subject_id"] == alert
    assert recent[stopped]["outcome"] == "stopped:schema"


@pytest.mark.db
def test_usage_hides_a_run_again_when_a_blind_head_is_reopened(client) -> None:
    tc, db = client
    alert = _aid()
    analyst = _user(db, "p11t20-analyst", "tier1")
    _alert(db, alert, status="auto_closed", visible=False)
    run = _run(db, alert, result=PROPOSED)
    assert _recent(tc)[run]["outcome"] == "true_positive"  # decided: shown
    transitions.reopen(db, alert, analyst, reason="the digest said wrong")
    row = _recent(tc)[run]
    assert row["outcome"] is None and row["subject_id"] is None


@pytest.mark.db
def test_usage_follows_visibility_strip_for_every_status_and_arm(client) -> None:
    tc, db = client
    probe = {key: "x" for key in visibility.ANALYST_HIDE}
    runs = {}
    for status in ALL_STATUSES:
        for visible in (True, False):
            alert = _aid()
            _alert(db, alert, status=status, visible=visible)
            hides = (
                visibility.strip(probe, status=status, suggestion_visible=visible, mode="analyst")
                != probe
            )
            runs[_run(db, alert, result=PROPOSED)] = (alert, hides, status, visible)
    # `recent` holds the last 20 rows: 20 runs here, all of them
    assert len(runs) == 20
    recent = _recent(tc)
    for run_id, (alert, hides, status, visible) in runs.items():
        row = recent[run_id]
        if hides:
            assert row["outcome"] is None and row["subject_id"] is None, (status, visible)
        else:
            assert row["outcome"] == "true_positive" and row["subject_id"] == alert, (
                status,
                visible,
            )


@pytest.mark.db
def test_usage_a_run_on_a_case_and_a_run_on_an_unknown_alert_are_unchanged(client) -> None:
    tc, db = client
    case = _run(
        db,
        "CASE-1",
        pipeline="investigate",
        role="investigator",
        result={"suggested_conclusion": "need_more_data"},
    )
    orphan = _run(db, "9999.1", result=PROPOSED)
    recent = _recent(tc)
    assert recent[case]["subject_id"] == "CASE-1" and recent[case]["outcome"] == "need_more_data"
    assert recent[orphan]["subject_id"] == "9999.1" and recent[orphan]["outcome"] == "true_positive"


@pytest.mark.db
def test_usage_a_case_run_whose_id_equals_a_blind_alerts_id_is_not_hidden(client) -> None:
    """The join is on `subject_type = 'alert'`: a case that happens to carry the same text is
    not the alert."""
    tc, db = client
    alert = _aid()
    _alert(db, alert, status="queued_tier1", visible=False)
    case = _run(db, alert, pipeline="investigate", role="investigator")
    assert _recent(tc)[case]["subject_id"] == alert


@pytest.mark.db
def test_usage_other_blocks_are_unchanged_by_the_blind_arm(client) -> None:
    """The matrix counts calls, tokens and cost, not verdicts; a blind head's run is counted."""
    tc, db = client
    alert = _aid()
    _alert(db, alert, status="queued_tier1", visible=False)
    _run(db, alert, result=PROPOSED)
    body = tc.get(USAGE).json()
    row = [
        r for r in body["by_pipeline_role"] if (r["pipeline"], r["role"]) == ("triage", "proposer")
    ]
    assert row and row[0]["calls"] == 1 and row[0]["with_result"] == 1


def test_neither_statement_holds_a_decided_state_of_its_own() -> None:
    """The decided states reach both statements as a parameter, from `visibility.SHOW_STATES`:
    the router holds no second list of them."""
    recent, page = admin_llm._RECENT_SQL, admin_audit._PAGE.as_string()
    clauses, params = admin_audit._filters(admin_audit._WINDOWS["7d"], None, None, None)
    where = admin_audit._where(clauses).as_string()
    assert "%(show_states)s" in recent and "%(show_states)s" in page
    assert "%(show_states)s" in where  # the rows left out are chosen in the WHERE, with the total
    assert params["show_states"] == sorted(visibility.SHOW_STATES)
    for state in visibility.SHOW_STATES:
        assert f"'{state}'" not in recent, state
        assert f"'{state}'" not in page, state
        assert f"'{state}'" not in where, state


@pytest.mark.db
def test_usage_a_hidden_run_keeps_its_place_in_the_newest_first_order(client) -> None:
    tc, db = client
    alert = _aid()
    _alert(db, alert, status="queued_tier1", visible=False)
    old = _run(db, alert, result=PROPOSED, created_at=datetime(2026, 1, 1, tzinfo=UTC))
    new = _run(db, _aid(), result=PROPOSED)
    order = [r["run_id"] for r in tc.get(USAGE).json()["recent"]]
    assert order.index(new) < order.index(old)
